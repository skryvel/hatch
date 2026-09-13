//! Spawn, capture, output cap, exec timeout, kill.
//!
//! Everything upstream of this module decides *whether* an operation happens.
//! This one decides how, and it has exactly one entry point, [`run`]. By the
//! time control arrives here a human has already read the command and said
//! yes, so nothing in this module second-guesses that: it does not inspect the
//! command, it does not refuse it, and the two ways a run can be cut short —
//! the execution deadline and the user's Kill button — are reported as
//! *results*, not as errors. A truncated result is a result. The only errors
//! are the two ways a run never started at all.
//!
//! # The process group is the unit, not the process
//!
//! The child is put in a session of its own with `setsid`, and every kill is a
//! `killpg` on that group. This is the single most load-bearing decision in
//! the module. A command as ordinary as `make -j8` or `something &` leaves
//! descendants, and signalling only the pid hatch happens to hold reaches the
//! shell and nothing it started: the user presses Kill, the button reports
//! success, and the work carries on. A Kill button that silently does nothing
//! is worse than no Kill button, because the user stops watching.
//!
//! The group is also what makes reading terminate. A backgrounded grandchild
//! inherits the pipes, so those pipes do not reach end of file when the shell
//! exits — they reach it when the last holder does. Ending the group is what
//! closes them. See "When a run is over" below.
//!
//! # What is deliberately not here
//!
//! Elevation. A `root: true` operation goes through `run0`, whose failure
//! modes are not this module's: a cancelled password dialog is an *elevation*
//! failure and must not be reported as the command failing, and the two end
//! with the same exit status, so telling them apart takes more than a number.
//! All of that -- the argv wrapper, the environment the elevated child gets,
//! and the classifier -- lives in [`elevate`], behind a trait, so that this
//! module keeps taking an argv and knowing nothing about privilege. The daemon
//! builds an elevated argv there and hands it here like any other, so
//! everything below this line -- the process group, the deadline, the Kill
//! button, the output cap -- is the same code for both paths.
//!
//! One consequence of that sameness is worth naming, because it is a
//! difference this module cannot see. A root command's deadline and Kill
//! button act on the *elevation program*, and the password dialog lives
//! inside that program's lifetime: a run ended here may be a command that was
//! stopped or a dialog nobody answered, and the two are indistinguishable
//! from what [`run`] returns. Reading that distinction -- or admitting it
//! cannot be read -- belongs to the caller, which is why [`Output`] says what
//! happened to the process and claims nothing about what it means.

pub mod elevate;
pub mod env;
pub mod interactive;
pub mod lookup;

use std::collections::BTreeMap;
use std::fmt;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use nix::sys::signal::{self, Signal};
use serde::{Deserialize, Serialize};
use nix::unistd::{Pid, setsid};
use tokio::io::AsyncReadExt as _;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// The complete environment for a child, as [`env::build_child_env`] builds
/// it. Named here because [`run`] takes it and never constructs one: the map
/// is the config's, not the spawner's.
pub type Env = BTreeMap<String, String>;

// ---- an argv, and the line that stands for it ------------------------------

/// The argv for running `command` through a shell.
///
/// Three arguments and never a string: `bash -c <command>` hands the shell one
/// script, so every quote, space and newline in it is data the shell reads
/// rather than structure another layer already acted on. Written once and
/// shared, because the alternative is two call sites that build the same
/// wrapper and one of them eventually building `format!("bash -c {command}")`
/// instead — which would re-parse the command at a level the reader was never
/// shown, and the whole argument for this window is that what is displayed is
/// what runs.
pub fn shell_argv(command: &str) -> Vec<String> {
    vec!["bash".to_string(), "-c".to_string(), command.to_string()]
}

/// Render an argv as the shell line that would produce it.
///
/// This direction is the only safe one. hatch holds an argv — a list of
/// arguments that are already separate — and needs one line to put on screen;
/// producing that line by joining with spaces would draw `rm 'my file'` as
/// `rm my file`, two arguments where one runs, which is a display saying
/// something other than what happens. So every argument that is not plainly
/// safe is single-quoted, and a single quote inside one is closed, escaped and
/// reopened (`'\''`) — the one form that needs no escape table, because
/// nothing but `'` has any meaning inside single quotes.
///
/// An argument is left bare only if it is non-empty and every byte of it is
/// alphanumeric or one of `_@%+=:,./-`. None of those can start a word, end a
/// word, open a quote, or mean anything to a shell in argument position, so a
/// bare word here re-reads as exactly itself. That keeps the common line
/// readable: `run0 --pipe --setenv=PATH=/usr/bin -- bash -c '…'` quotes the
/// script and nothing else.
///
/// The result is for a human and for a fidelity check, never for execution:
/// nothing in hatch feeds this string back to a shell.
pub fn shell_line(argv: &[String]) -> String {
    argv.iter().map(|arg| shell_quote(arg)).collect::<Vec<_>>().join(" ")
}

/// One argument, quoted if it needs it. See [`shell_line`].
fn shell_quote(arg: &str) -> String {
    fn bare(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&byte)
    }
    if !arg.is_empty() && arg.bytes().all(bare) {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// How much is read from a pipe at a time.
///
/// Well under the 64 KiB pipe buffer on purpose. The read size is the
/// granularity of the live view, so a large one would make a slow trickle of
/// output arrive in visible lumps; it is not a throughput knob, because the
/// loop reads whatever is there and comes straight back.
const READ_CHUNK: usize = 8192;

// ---- what a caller asks for ------------------------------------------------

/// The knobs on a single run.
///
/// One struct rather than five parameters so that the call shape does not
/// change as the daemon and the interactive path land: a signature that grows
/// a parameter per feature makes every existing call site churn, and every
/// churned call site is a chance to pass the new argument wrong.
pub struct RunOpts {
    /// How long the command may run before hatch kills it. `None` is
    /// unbounded, which is what an interactive run under a terminal wants:
    /// there a human is watching and can end it themselves.
    pub timeout: Option<Duration>,
    /// The user's Kill button. Cancelling it ends the run at the next poll.
    pub cancel: CancellationToken,
    /// Cap on what is *kept*, per stream. See [`Output::stdout`].
    pub cap_bytes: usize,
    /// Where to send output as it arrives, for a window that shows a running
    /// command. `None` captures without streaming.
    ///
    /// **The receiver must be drained by a task other than the one awaiting
    /// [`run`].** The channel is bounded and [`run`] sends into it with
    /// backpressure, so a receiver that is only read after `run` returns
    /// deadlocks once the channel fills.
    pub chunks: Option<mpsc::Sender<Chunk>>,
}

/// Which pipe a [`Chunk`] came from.
///
/// Kept apart all the way to the sink rather than interleaved into one text:
/// the window colours them differently, and a diagnostic that a command wrote
/// to stderr must not be read as part of its answer. That separation has to
/// survive the trip to the prompt window, so this is also a wire type — see
/// [`crate::protocol::DaemonMsg::Output`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Bytes as they came off a pipe, plus hatch's own markers.
///
/// Bytes and not a `String`: a chunk boundary falls wherever the kernel
/// happened to split the output, which is very often mid-character, and
/// decoding each chunk on its own would turn every such split into a
/// replacement character in the live view. The consumer reassembles and
/// decodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Which pipe it came from.
    pub stream: Stream,
    /// The bytes.
    pub bytes: Vec<u8>,
}

// ---- what a caller gets back -----------------------------------------------

/// Everything an approved command produced, and how it ended.
///
/// There is no "it worked" flag, because there is no single answer to that
/// question here: a command that exits 1 did what it was asked to do, and a
/// command hatch killed at the deadline may have done most of its work. The
/// fields state what happened and let the daemon and the window say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// Captured standard output, at most [`RunOpts::cap_bytes`] plus hatch's
    /// own markers, decoded lossily.
    ///
    /// Lossy because this text is going into a window and into a tool result,
    /// and neither can render a byte string; a command that emits binary gets
    /// replacement characters rather than a failure. The cap counts *bytes off
    /// the pipe*, so a stream of invalid bytes can make this `String` longer
    /// than the cap once each one becomes a three-byte U+FFFD.
    pub stdout: String,
    /// Captured standard error, under the same cap and the same rules.
    pub stderr: String,
    /// Everything that appeared in the terminal, for a run that had one.
    ///
    /// `None` for every run [`run`] itself performed, and `Some` for every one
    /// [`interactive::run`] performed — the two are exclusive, and the
    /// difference is not cosmetic. A pty is one stream: what a command wrote
    /// to standard output and what it wrote to standard error arrive
    /// interleaved with no mark saying which was which, and so does what the
    /// person typed. Reporting that as `stdout` would be hatch claiming a
    /// separation the run did not have, so an interactive run leaves both of
    /// those empty and puts the one text here, with the escape sequences the
    /// terminal needed and a reader does not taken out.
    pub transcript: Option<String>,
    /// The exit status, if the command exited on its own. `None` when a signal
    /// ended it, and also when the wait itself failed — in both cases the
    /// honest answer is that there is no exit code to report.
    pub exit_code: Option<i32>,
    /// The signal that ended it, if one did. Set for hatch's own kill and for
    /// a command that died of something else, such as a segmentation fault.
    pub signal: Option<i32>,
    /// hatch ended it at [`RunOpts::timeout`].
    pub timed_out: bool,
    /// hatch ended it because [`RunOpts::cancel`] fired — the Kill button.
    pub killed_by_user: bool,
    /// Standard output reached the cap and the rest was dropped.
    pub stdout_truncated: bool,
    /// Standard error reached the cap and the rest was dropped.
    pub stderr_truncated: bool,
    /// The transcript reached the cap and the rest was dropped.
    pub transcript_truncated: bool,
}

/// Why a command never ran.
///
/// Every variant carries the same fact: **nothing was executed.** That is what
/// separates these from every other bad outcome in this module. A command that
/// ran and failed, ran and was truncated, or ran and was killed is an
/// [`Output`] — the approval was honoured and this is what came of it. An
/// `ExecError` means the approval was honoured by nobody, so the agent can
/// retry without wondering what already happened.
///
/// Owned strings rather than an [`std::io::Error`], for the same reason
/// [`crate::swap::ApplyError`] does it: the value is compared in tests and
/// written to the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// The argv was empty, so there is no program to run.
    NoProgram,
    /// The working directory is not a directory hatch can run in.
    ///
    /// Checked before the spawn, because afterwards it is not distinguishable:
    /// a missing cwd and a missing program both come back from `execve` as
    /// `ENOENT` on the same `spawn` call, and "No such file or directory" with
    /// no subject is the least useful thing hatch could tell either the user
    /// or the agent.
    BadCwd {
        /// The directory that was asked for.
        cwd: PathBuf,
        /// Why it is not usable, as text.
        error: String,
    },
    /// hatch could not lay out the private directory an interactive run needs.
    ///
    /// Its own variant rather than a [`ExecError::Spawn`], because nothing was
    /// spawned and there is no program to name: the failure is hatch's own
    /// preparation — a parent directory another user could reach into, a disk
    /// with nothing left on it — and saying "`konsole` could not be started"
    /// would send the reader after the wrong thing.
    Setup {
        /// What could not be done, as text, beginning with the path.
        error: String,
    },
    /// The program could not be started: not on the child's `PATH`, not
    /// executable, or the system refused the fork.
    Spawn {
        /// The program name from `argv[0]`, as spelled.
        program: String,
        /// The operating system's reason, as text.
        error: String,
    },
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecError::NoProgram => {
                f.write_str("there is no program to run; nothing was executed")
            }
            ExecError::BadCwd { cwd, error } => write!(
                f,
                "the working directory {} cannot be used: {error}; nothing was executed",
                cwd.display()
            ),
            ExecError::Setup { error } => write!(
                f,
                "hatch could not prepare a terminal for it: {error}; nothing was executed"
            ),
            ExecError::Spawn { program, error } => write!(
                f,
                "{program} could not be started: {error}; nothing was executed"
            ),
        }
    }
}

impl std::error::Error for ExecError {}

// ---- running ---------------------------------------------------------------

/// Run `argv` to completion, or until the deadline or the user ends it.
///
/// The child gets `env` and nothing else, starts in `cwd`, and leads a session
/// of its own. Standard input is `/dev/null`; standard output and error are
/// pipes, read concurrently, captured up to [`RunOpts::cap_bytes`] each and
/// streamed to [`RunOpts::chunks`] if a sink was given.
///
/// # When a run is over
///
/// Three things can happen and they are not the same thing:
///
/// * **The child exits.** This is the authoritative end of the command, and it
///   is what `run` waits for. End of file on both pipes is *not* the end: a
///   command that closes its own descriptors and keeps working
///   (`exec 1>&- 2>&-; …`) would otherwise be reported as finished while it
///   was still writing files.
/// * **The deadline passes**, if there was one. `timed_out` is set, the group
///   is killed, and a line saying so is appended to stdout — in band, because
///   stdout is what ends up in the audit log and in the agent's tool result,
///   and neither may read as a complete successful run.
/// * **The token is cancelled.** `killed_by_user` is set, the group is killed,
///   and a line saying so is appended for the same reason.
///
/// In all three cases the group is then ended and both pipes are read to end
/// of file before returning, so nothing the command already wrote is lost:
/// `SIGKILL` stops writers, it does not discard what is already in the pipe.
///
/// Ending the group on a *normal* exit is deliberate, and it is the answer to
/// the backgrounded grandchild. Something the command left running holds the
/// pipes open, so waiting for end of file would hang for as long as it lives;
/// and leaving it alive would put a process outside hatch's supervision, one
/// the window can no longer show and the Kill button can no longer reach. The
/// group hatch creates does not outlive the request that created it.
///
/// # Errors
///
/// Only [`ExecError`], and only for a command that never started.
pub async fn run(
    argv: &[String],
    env: &Env,
    cwd: &Path,
    opts: RunOpts,
) -> Result<Output, ExecError> {
    let Some((program, args)) = argv.split_first() else {
        return Err(ExecError::NoProgram);
    };

    // Before the spawn: see `ExecError::BadCwd`.
    match std::fs::metadata(cwd) {
        Ok(md) if md.is_dir() => {}
        Ok(_) => {
            return Err(ExecError::BadCwd {
                cwd: cwd.to_path_buf(),
                error: "not a directory".to_string(),
            });
        }
        Err(e) => {
            return Err(ExecError::BadCwd { cwd: cwd.to_path_buf(), error: e.to_string() });
        }
    }

    let RunOpts { timeout, cancel, cap_bytes, chunks } = opts;
    let mut sink = chunks;

    let mut cmd = Command::new(program);
    cmd.args(args)
        // The constructed environment and only it. `env_clear` first, because
        // `envs` adds to whatever is there and what is there by default is
        // everything the daemon was started with.
        .env_clear()
        .envs(env)
        .current_dir(cwd)
        // Not inherited. A command that reads standard input must see end of
        // file: handing it the daemon's would hang the request on a terminal
        // nobody is watching, and would let an agent-chosen command read what
        // is typed there.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A backstop, not the mechanism: if this future is dropped without
        // reaching the kill below -- a panic, a cancelled task -- tokio at
        // least signals the pid.
        .kill_on_drop(true);

    // SAFETY: `pre_exec` runs in the child between `fork` and `execve`. In that
    // window the child has one thread and a copy of every lock the parent held,
    // some of them held by threads that do not exist here, so only
    // async-signal-safe work is legal: anything that allocates or takes a lock
    // can deadlock outright.
    //
    // `lead_new_session` is one `setsid` syscall, plus on failure an
    // `io::Error::from_raw_os_error`, which stores an integer. No allocation,
    // no lock, no reentrancy. It captures nothing, so there is no shared state
    // to observe and no destructor to run.
    //
    // This is the only `unsafe` in the crate -- the child environment module
    // gave up its own rather than reason about `set_var` under a parallel test
    // harness -- and it is kept because the safe alternative is not equivalent.
    // `Command::process_group(0)` would give the child its own process group
    // with no `pre_exec` at all, and `killpg` would work the same; but it
    // leaves the child in hatch's *session*, sharing hatch's controlling
    // terminal. An approved command could then read and write the terminal the
    // daemon was started from, which is a terminal the agent never had.
    // `setsid` detaches it.
    unsafe {
        cmd.pre_exec(lead_new_session);
    }

    let started = Instant::now();
    let mut child = cmd.spawn().map_err(|e| ExecError::Spawn {
        program: program.clone(),
        error: e.to_string(),
    })?;

    // `setsid` makes the child a session and group leader, so its pid *is* the
    // process group id -- and the group already exists by now, because `spawn`
    // does not return until the child has reached `execve`, which is after
    // `pre_exec` ran. A kill arriving in the first instant therefore has a
    // group to reach.
    //
    // Read here rather than at the kill: after `wait` reaps the child, `id()`
    // is `None`.
    let pgid = child.id().map(|id| Pid::from_raw(id as i32));

    let (Some(mut child_out), Some(mut child_err)) = (child.stdout.take(), child.stderr.take())
    else {
        // Unreachable while both are configured as pipes above. Reported as a
        // spawn failure rather than asserted: a panic here would take down the
        // daemon, and "nothing was executed" is very nearly true -- the child
        // exists, but `kill_on_drop` ends it as this function returns.
        return Err(ExecError::Spawn {
            program: program.clone(),
            error: "the child was started without pipes".to_string(),
        });
    };

    let mut stdout = Capture::new(cap_bytes);
    let mut stderr = Capture::new(cap_bytes);
    let mut out_buf = [0u8; READ_CHUNK];
    let mut err_buf = [0u8; READ_CHUNK];
    let mut out_open = true;
    let mut err_open = true;
    let mut reaped = false;
    let mut status: Option<ExitStatus> = None;
    let mut timed_out = false;
    let mut killed_by_user = false;

    // Absolute, so that re-polling it costs nothing and cannot drift. `pending`
    // for the unbounded case: a branch that never completes is how `select!`
    // spells "this arm is not in play".
    let deadline = timeout.map(|t| started + t);
    let expiry = async move {
        match deadline {
            Some(at) => tokio::time::sleep_until(at).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(expiry);
    let cancelled = cancel.cancelled();
    tokio::pin!(cancelled);

    while !reaped || out_open || err_open {
        tokio::select! {
            // Both pipes in the same `select!`, which is the whole point: a
            // loop that drained one to end of file before touching the other
            // deadlocks on any command that fills the second, because the
            // child cannot finish writing the stream nobody is reading. Both
            // `read` and `wait` are cancellation-safe, so the arms that lose a
            // round lose nothing.
            read = child_out.read(&mut out_buf), if out_open => match read {
                Ok(0) => out_open = false,
                Ok(n) => absorb(&mut stdout, Stream::Stdout, &out_buf[..n], &mut sink).await,
                // A pipe that errors is a pipe nothing more will come out of.
                // There is nobody to report it to who is not already being
                // told how the command ended.
                Err(_) => out_open = false,
            },
            read = child_err.read(&mut err_buf), if err_open => match read {
                Ok(0) => err_open = false,
                Ok(n) => absorb(&mut stderr, Stream::Stderr, &err_buf[..n], &mut sink).await,
                Err(_) => err_open = false,
            },
            waited = child.wait(), if !reaped => {
                reaped = true;
                // `Err` leaves `status` as `None`, which reports no exit code
                // and no signal -- true, and better than inventing one.
                status = waited.ok();
                // See "When a run is over": this is what closes pipes a
                // grandchild is still holding.
                end_group(pgid);
            }
            _ = &mut expiry, if !timed_out && !reaped => {
                timed_out = true;
                end_group(pgid);
            }
            _ = &mut cancelled, if !killed_by_user && !reaped => {
                killed_by_user = true;
                end_group(pgid);
            }
        }
    }

    // In band as well as in the struct. `Output` says `timed_out`, but stdout
    // travels further than `Output` does -- into the audit log, into the tool
    // result the agent reads -- and on its own it would look like a command
    // that simply stopped early.
    if timed_out {
        let note = format!("\n[hatch] killed after {}\n", secs(timeout.unwrap_or_default()));
        stdout.note(&note);
        send(&mut sink, Stream::Stdout, note.as_bytes()).await;
    } else if killed_by_user {
        let note = format!("\n[hatch] killed by the user after {}\n", secs(started.elapsed()));
        stdout.note(&note);
        send(&mut sink, Stream::Stdout, note.as_bytes()).await;
    }

    Ok(Output {
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
        stdout: stdout.into_string(),
        stderr: stderr.into_string(),
        // Two pipes, kept apart. See `Output::transcript` for the path where
        // they cannot be.
        transcript: None,
        transcript_truncated: false,
        exit_code: status.and_then(|s| s.code()),
        signal: status.and_then(|s| s.signal()),
        timed_out,
        killed_by_user,
    })
}

/// Make the calling process a session and process-group leader.
///
/// Runs in the child between `fork` and `execve`; see the safety note at the
/// only call site for why this and nothing else is in here.
fn lead_new_session() -> std::io::Result<()> {
    setsid()?;
    Ok(())
}

/// Signal every process in the group, once, with `SIGKILL`.
///
/// # Why `SIGKILL`, and why there is no grace period
///
/// The usual shape is `SIGTERM`, wait, then `SIGKILL`, so that a well-behaved
/// program can clean up. It is not the right shape here, for three reasons
/// that point the same way.
///
/// `SIGTERM` can be ignored, and a command that ignores it is exactly the
/// command a user is trying to stop. hatch cannot tell "cleaning up carefully"
/// from "trapped it and carried on" without waiting out the grace period every
/// single time, so the polite signal makes *every* kill slow in order to be
/// gentle to the runs that did not need killing.
///
/// The user pressed Kill because they want it to stop. A button that takes a
/// visible pause to do anything is a button people press twice and then stop
/// trusting, and this one is the last line of defence in a design whose whole
/// premise is that the agent may be wrong about what it asked for.
///
/// And the same call ends the group after a normal exit, where a grace period
/// would be pure latency added to every command hatch runs.
///
/// The cost is real and accepted: a command killed here does not get to unlink
/// its temporary files or flush a partial write. It is bounded by hatch's own
/// design — a file hatch writes is staged and renamed, so a killed run
/// leaves the original file untouched — and it is the trade the interactive
/// path may want to revisit, where the human is at a terminal watching.
///
/// Errors are dropped. `ESRCH` means the group is already gone, which is the
/// outcome this function exists to produce.
///
/// A note on the pid the group is named by: after a normal exit `wait` has
/// already reaped the leader, so between that and this call the kernel could
/// in principle hand the same number to a brand new group leader, which this
/// would then kill. That needs the pid space to wrap — some four million
/// spawns by default — inside the microsecond between the two, so it is
/// recorded rather than defended against.
fn end_group(pgid: Option<Pid>) {
    // Zero is not a pid. To `killpg` it means "my own process group", which is
    // hatch's own -- the daemon, the window, and whatever started them. The
    // value here comes from the kernel by way of `child.id()` and is never
    // zero; the guard is here so that if that ever stops being true the kill
    // reaches nothing rather than everything.
    let Some(pgid) = pgid.filter(|p| p.as_raw() != 0) else { return };
    let _ = signal::killpg(pgid, Signal::SIGKILL);
}

/// A duration as a human reads it: `30s`, `0.3s`.
fn secs(d: Duration) -> String {
    if d.subsec_nanos() == 0 {
        format!("{}s", d.as_secs())
    } else {
        format!("{:.1}s", d.as_secs_f64())
    }
}

// ---- capture and streaming -------------------------------------------------

/// The moment one stream crossed its cap.
struct Truncation {
    /// How many bytes of the chunk that crossed it were kept. The marker
    /// belongs immediately after these, in the capture and in the live stream
    /// alike -- a read boundary falls wherever the kernel put it, and letting
    /// the two views place the marker differently is exactly the silent
    /// disagreement the marker exists to prevent.
    kept: usize,
    /// The words, so both views say the same ones.
    marker: String,
}

/// What is kept from one stream, bounded.
struct Capture {
    bytes: Vec<u8>,
    cap: usize,
    truncated: bool,
}

impl Capture {
    fn new(cap: usize) -> Self {
        Self { bytes: Vec::new(), cap, truncated: false }
    }

    /// Keep as much of `chunk` as fits.
    ///
    /// Returns a [`Truncation`] if *this* call is the one that crossed the
    /// cap, so the caller can put the same words into the live stream at the
    /// same byte. Later calls return `None`: it is said once, not per chunk.
    fn push(&mut self, chunk: &[u8]) -> Option<Truncation> {
        if self.truncated {
            return None;
        }
        let room = self.cap.saturating_sub(self.bytes.len());
        if chunk.len() <= room {
            self.bytes.extend_from_slice(chunk);
            return None;
        }
        self.bytes.extend_from_slice(&chunk[..room]);
        let marker = format!("\n[hatch] output truncated at {} bytes\n", self.cap);
        self.bytes.extend_from_slice(marker.as_bytes());
        self.truncated = true;
        Some(Truncation { kept: room, marker })
    }

    /// Append hatch's own words past the cap.
    ///
    /// Deliberately not subject to it. The cap exists to bound how much of the
    /// *command's* output is carried around; a reader who is told nothing
    /// about why the output stops has been told the least useful version of
    /// what happened, and the note is tens of bytes against a cap of hundreds
    /// of kilobytes.
    fn note(&mut self, note: &str) {
        self.bytes.extend_from_slice(note.as_bytes());
    }

    fn into_string(self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

/// Keep what fits, stream everything.
///
/// # Why the two views differ, and why that is not a lie
///
/// The cap bounds what the agent receives; the sink is the live view in the
/// window, and it is not capped. Capping it too would freeze the window at
/// the cap while the command ran on, which takes away precisely what the user
/// needs in order to decide whether to press Kill — and the window is the
/// reason this project exists. Capping neither would let an agent-chosen
/// command decide how much of hatch's memory to use.
///
/// So the two genuinely differ, and the marker is what keeps the difference
/// from being silent: at the moment the capture crosses the cap, the same
/// sentence goes into the stream, at the same byte. A reader of the window can
/// see exactly where the agent's copy stops, and the agent is told that its
/// copy stopped. Neither can mistake one view for the other.
///
/// Reading never stops at the cap, only keeping does. A loop that stopped
/// reading would leave the pipe to fill and the command to block on it, and
/// the cap would have become a hang.
///
/// The chunk that crosses the cap is split so that the marker goes into the
/// stream at that byte rather than after the rest of the read. Otherwise the
/// two views would place it up to [`READ_CHUNK`] apart, and "the window shows
/// where your copy stops" would be true only to within a read.
async fn absorb(
    capture: &mut Capture,
    stream: Stream,
    chunk: &[u8],
    sink: &mut Option<mpsc::Sender<Chunk>>,
) {
    match capture.push(chunk) {
        None => send(sink, stream, chunk).await,
        Some(Truncation { kept, marker }) => {
            send(sink, stream, &chunk[..kept]).await;
            send(sink, stream, marker.as_bytes()).await;
            send(sink, stream, &chunk[kept..]).await;
        }
    }
}

/// Hand bytes to the live view, if anybody is still watching.
///
/// Backpressure rather than dropping: a sink that quietly discarded chunks
/// under load would show a window that is missing lines it cannot know are
/// missing, which is the failure this whole module is written to avoid. A slow
/// consumer therefore slows the command, bounded by the execution deadline.
///
/// A closed channel is a viewer that went away, not a failure of the run;
/// the sink is dropped and the command carries on.
async fn send(sink: &mut Option<mpsc::Sender<Chunk>>, stream: Stream, bytes: &[u8]) {
    // An empty chunk says nothing and would arrive whenever a read landed
    // exactly on the cap.
    if bytes.is_empty() {
        return;
    }
    let Some(tx) = sink.as_ref() else { return };
    if tx.send(Chunk { stream, bytes: bytes.to_vec() }).await.is_err() {
        *sink = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::exec::env::build_child_env;
    use std::time::Duration;
    use tempfile::TempDir;

    /// A cwd nothing else writes to, and the constructed child environment the
    /// daemon will really use, tagged so a test can find the processes it
    /// spawned without asking the whole machine.
    fn fixture() -> (TempDir, Env, String) {
        let dir = tempfile::tempdir().unwrap();
        let tag = uuid::Uuid::new_v4().to_string();
        let mut env = build_child_env(&Config::default());
        env.insert(TAG_VAR.to_string(), tag.clone());
        (dir, env, tag)
    }

    /// A hard ceiling on a test that waits for hatch to kill something.
    ///
    /// Every one of these finishes in well under a second when the kill works.
    /// When it does not -- which is what several of the mutants in this
    /// module's matrix do -- the command is `sleep 30` or `yes`, and the
    /// second of those never ends on its own. A test that can hang forever
    /// stops being a test: it takes the whole run with it.
    async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(20), fut)
            .await
            .expect("hatch did not end the command, so this would have hung forever")
    }

    fn argv(command: &str) -> Vec<String> {
        shell_argv(command)
    }

    /// The two knobs the plan names, as one call shape: everything else in
    /// [`RunOpts`] stays at the "no limit, nobody watching" end.
    async fn run_capped(command: &str, env: &Env, cwd: &Path, cap_bytes: usize) -> Output {
        run(
            &argv(command),
            env,
            cwd,
            RunOpts { timeout: None, cancel: CancellationToken::new(), cap_bytes, chunks: None },
        )
        .await
        .expect("the command must spawn")
    }

    async fn run_streaming(
        command: &str,
        env: &Env,
        cwd: &Path,
        chunks: mpsc::Sender<Chunk>,
    ) -> Output {
        run(
            &argv(command),
            env,
            cwd,
            RunOpts {
                timeout: None,
                cancel: CancellationToken::new(),
                cap_bytes: 1 << 20,
                chunks: Some(chunks),
            },
        )
        .await
        .expect("the command must spawn")
    }

    /// The environment variable a test tags its process group with. Read back
    /// out of `/proc/<pid>/environ`, which every descendant inherits.
    const TAG_VAR: &str = "HATCH_TEST_GROUP";

    /// Every live process on this machine carrying `tag` in its environment,
    /// as `(pid, pgid)`.
    ///
    /// Zombies are excluded: a backgrounded grandchild is reparented when its
    /// shell dies and reaped by whatever `init` this box runs, and that
    /// handover is not instant. A zombie holds no pipe open and cannot run
    /// code, so it is not what the assertions are about — a *live* member is.
    fn tagged(tag: &str) -> Vec<(i32, i32)> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else { return found };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Ok(pid) = name.to_string_lossy().parse::<i32>() else { continue };
            // Both reads race process exit; a vanished process is simply not a
            // member.
            let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ")) else { continue };
            if !environ
                .split(|b| *b == 0)
                .any(|kv| kv == format!("{TAG_VAR}={tag}").as_bytes())
            {
                continue;
            }
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
            // `comm` is parenthesised and may itself contain spaces and
            // parentheses, so the fields are counted from the last `)`:
            // state, ppid, pgrp.
            let Some(close) = stat.rfind(')') else { continue };
            let mut fields = stat[close + 1..].split_whitespace();
            let state = fields.next();
            let _ppid = fields.next();
            let Some(Ok(pgrp)) = fields.next().map(str::parse::<i32>) else { continue };
            if state != Some("Z") {
                found.push((pid, pgrp));
            }
        }
        found
    }

    /// Poll until nothing live carries `tag` any more, or give up.
    async fn wait_until_gone(tag: &str) -> Vec<(i32, i32)> {
        for _ in 0..200 {
            let left = tagged(tag);
            if left.is_empty() {
                return left;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tagged(tag)
    }

    #[test]
    fn a_duration_is_spelled_the_way_a_person_reads_it() {
        // This is the number in "killed after <n>", and hatch's note is the
        // only thing that tells a reader whether the command was given the
        // 300 seconds the config promised or was cut off at once. A whole
        // number of seconds is printed as one; anything else keeps a decimal,
        // because "0s" for a 300 ms deadline would read as an instant kill.
        assert_eq!(secs(Duration::from_secs(300)), "300s");
        assert_eq!(secs(Duration::from_secs(0)), "0s");
        assert_eq!(secs(Duration::from_millis(300)), "0.3s");
        assert_eq!(secs(Duration::from_millis(1500)), "1.5s");
    }

    #[tokio::test]
    async fn captures_stdout_stderr_and_exit_code() {
        let (dir, env, _tag) = fixture();
        let out = run_capped("echo out; echo err >&2; exit 3", &env, dir.path(), 1 << 20).await;

        assert_eq!(out.exit_code, Some(3));
        assert_eq!(out.signal, None);
        assert_eq!(out.stdout, "out\n");
        assert_eq!(out.stderr, "err\n");
        assert!(!out.timed_out);
        assert!(!out.killed_by_user);
        assert!(!out.stdout_truncated);
    }

    #[tokio::test]
    async fn output_is_capped_with_an_explicit_marker() {
        let (dir, env, _tag) = fixture();
        let out = run_capped("yes hello | head -100000", &env, dir.path(), 1024).await;

        assert!(
            out.stdout.len() <= 1024 + 128,
            "the cap bounds what is kept, plus room for the marker; got {}",
            out.stdout.len()
        );
        assert!(out.stdout.contains("output truncated"), "got {:?}", out.stdout);
        assert!(out.stdout_truncated);
        // The command itself succeeded. Truncation is hatch's limit, not a
        // failure of the thing that was approved, and reporting it as one
        // would tell the agent to retry something that worked.
        assert_eq!(out.exit_code, Some(0));
    }

    #[tokio::test]
    async fn execution_timeout_kills_and_reports() {
        let (dir, env, tag) = fixture();
        let started = std::time::Instant::now();
        let out = within(run(
            &argv("sleep 30"),
            &env,
            dir.path(),
            RunOpts {
                timeout: Some(Duration::from_millis(300)),
                cancel: CancellationToken::new(),
                cap_bytes: 1 << 20,
                chunks: None,
            },
        ))
        .await
        .unwrap();

        // The deadline is a deadline, not a signal to kill at once. Every
        // assertion below is just as true of a run that was killed the
        // instant it started, which is the shape of the arithmetic slip that
        // would turn `exec_timeout_secs = 300` into "nothing may run".
        assert!(
            started.elapsed() >= Duration::from_millis(300),
            "killed after {:?}, which is not the deadline it was given",
            started.elapsed()
        );
        assert!(out.timed_out);
        assert!(!out.killed_by_user, "a deadline is not a person");
        // The number, not just the words: it is the only place the reader
        // learns whether the command got its deadline or a fraction of it.
        assert!(out.stdout.contains("killed after 0.3s"), "got {:?}", out.stdout);
        assert!(out.signal.is_some(), "it was killed, not exited");
        assert!(wait_until_gone(&tag).await.is_empty(), "the timeout must actually kill");
    }

    #[tokio::test]
    async fn kill_terminates_the_whole_process_group() {
        let (dir, env, tag) = fixture();
        let cancel = CancellationToken::new();
        let handle = {
            let (env, cwd, cancel) = (env.clone(), dir.path().to_path_buf(), cancel.clone());
            tokio::spawn(async move {
                run(
                    &argv("sleep 30 & sleep 30"),
                    &env,
                    &cwd,
                    RunOpts { timeout: None, cancel, cap_bytes: 1 << 20, chunks: None },
                )
                .await
            })
        };

        tokio::time::sleep(Duration::from_millis(200)).await;
        let running = tagged(&tag);
        // Without this the rest of the test would pass against a group that
        // never had anything in it.
        assert!(
            running.len() >= 2,
            "the shell and its backgrounded child must both be up; saw {running:?}"
        );
        let groups: std::collections::BTreeSet<i32> = running.iter().map(|(_, g)| *g).collect();
        assert_eq!(groups.len(), 1, "setsid must put them all in one new group: {running:?}");
        let group = *groups.iter().next().unwrap();
        assert!(
            running.iter().any(|(pid, _)| *pid == group),
            "the group's leader must be the command hatch spawned, not hatch's own group"
        );

        cancel.cancel();
        let out = within(handle).await.unwrap().unwrap();

        assert!(out.killed_by_user);
        assert!(!out.timed_out, "a person is not a deadline");
        assert!(out.signal.is_some(), "it was killed, not exited");
        // Scoped to the group hatch created. Asking whether any `sleep` is
        // running would be a question about the machine.
        assert!(
            wait_until_gone(&tag).await.is_empty(),
            "the backgrounded child must die with the group, or the Kill button lied"
        );
    }

    #[tokio::test]
    async fn streams_chunks_to_the_sink_as_they_arrive() {
        let (dir, env, _tag) = fixture();
        let (tx, mut rx) = mpsc::channel(64);
        let handle = {
            let (env, cwd) = (env.clone(), dir.path().to_path_buf());
            tokio::spawn(async move {
                run_streaming("echo one; sleep 0.4; echo two", &env, &cwd, tx).await
            })
        };

        let first = rx.recv().await.expect("the first line must arrive on its own");
        assert_eq!(first.stream, Stream::Stdout);
        assert_eq!(String::from_utf8_lossy(&first.bytes), "one\n");
        assert!(
            !handle.is_finished(),
            "`one` has to reach the sink while the command is still running, or this is not \
             streaming, it is a report"
        );

        let out = within(handle).await.unwrap();
        let mut streamed = String::new();
        while let Some(chunk) = rx.recv().await {
            streamed.push_str(&String::from_utf8_lossy(&chunk.bytes));
        }
        assert!(streamed.contains("two"), "got {streamed:?}");
        assert_eq!(out.stdout, "one\ntwo\n", "and the buffer got the whole thing too");
    }

    #[tokio::test]
    async fn nonexistent_cwd_is_refused_before_spawn() {
        let (dir, env, tag) = fixture();
        let missing = dir.path().join("no-such-directory");
        let err = run(
            &argv("echo ran"),
            &env,
            &missing,
            RunOpts {
                timeout: None,
                cancel: CancellationToken::new(),
                cap_bytes: 1 << 20,
                chunks: None,
            },
        )
        .await
        .expect_err("a directory that is not there cannot be a working directory");

        assert!(matches!(err, ExecError::BadCwd { .. }), "got {err:?}");
        assert!(err.to_string().contains("no-such-directory"), "the message must name it");
        // "Before spawn" is the claim, and this is what makes it one: nothing
        // carrying the tag ever existed.
        assert!(tagged(&tag).is_empty(), "nothing may be spawned for a cwd hatch already refused");
    }

    // ---- the design questions, pinned ------------------------------------

    #[tokio::test]
    async fn a_file_is_refused_as_a_working_directory() {
        let (dir, env, _tag) = fixture();
        let file = dir.path().join("not-a-directory");
        std::fs::write(&file, b"x").unwrap();

        let err = run(
            &argv("echo ran"),
            &env,
            &file,
            RunOpts {
                timeout: None,
                cancel: CancellationToken::new(),
                cap_bytes: 1 << 20,
                chunks: None,
            },
        )
        .await
        .expect_err("a regular file is not a working directory");
        assert!(matches!(err, ExecError::BadCwd { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn both_streams_are_read_concurrently_so_a_full_pipe_cannot_deadlock() {
        // Both writers run at once and both write far past the 64 KiB pipe
        // buffer, so a reader that drains either stream to completion before
        // touching the other blocks forever: the child cannot finish stdout
        // until somebody empties stderr, and cannot finish stderr until
        // somebody empties stdout.
        let (dir, env, _tag) = fixture();
        let out = tokio::time::timeout(
            Duration::from_secs(20),
            run_capped(
                "yes o | head -c 200000 & yes e | head -c 200000 >&2 & wait",
                &env,
                dir.path(),
                1 << 20,
            ),
        )
        .await
        .expect("reading one stream to EOF before the other deadlocks here");

        assert_eq!(out.stdout.len(), 200_000);
        assert_eq!(out.stderr.len(), 200_000);
        assert_eq!(out.exit_code, Some(0));
    }

    #[tokio::test]
    async fn a_child_that_closes_its_pipes_early_is_still_waited_for() {
        // EOF on both pipes is not the end of the command. A loop that
        // finished here would report a result while the approved command was
        // still running -- and, for a command that ends by writing a file,
        // report it before the file existed.
        let (dir, env, _tag) = fixture();
        let started = std::time::Instant::now();
        let out = run_capped("exec 1>&- 2>&-; sleep 0.5", &env, dir.path(), 1 << 20).await;

        assert!(
            started.elapsed() >= Duration::from_millis(400),
            "run returned after {:?}, so it answered on EOF rather than on exit",
            started.elapsed()
        );
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.stdout, "");
    }

    #[tokio::test]
    async fn output_still_in_the_pipe_when_the_child_exits_is_not_lost() {
        // Exit and end of file are separate events, and the loop has to wait
        // for the later of the two on *every* stream. Here stderr closes at
        // once and stdout is written in one burst at the very end, so when the
        // shell exits its whole answer is still sitting in the pipe. A loop
        // that stopped as soon as the child was reaped and one stream had
        // ended would hand back a truncated answer for a command that
        // succeeded, and say nothing about it.
        //
        // The throttled sink is what makes that reachable rather than
        // theoretical. Reading is normally so much faster than tokio noticing
        // a child exit that the pipe is empty by the time `wait` is ready; a
        // window that is slow to consume -- a repaint, a scroll, a machine
        // under load -- puts real time between reads, and then the exit lands
        // in the middle of them. It is exactly the case the daemon will be in.
        let (dir, env, _tag) = fixture();
        for attempt in 0..5 {
            let (tx, mut rx) = mpsc::channel::<Chunk>(1);
            let drain = tokio::spawn(async move {
                let mut total: usize = 0;
                while let Some(chunk) = rx.recv().await {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    total += chunk.bytes.len();
                }
                total
            });
            let out = run(
                &argv("exec 2>&-; body=$(yes hello | head -c 60000); printf '%s' \"$body\"; printf END"),
                &env,
                dir.path(),
                RunOpts {
                    timeout: None,
                    cancel: CancellationToken::new(),
                    cap_bytes: 1 << 20,
                    chunks: Some(tx),
                },
            )
            .await
            .unwrap();
            let streamed = drain.await.unwrap();

            assert!(
                out.stdout.ends_with("END"),
                "attempt {attempt}: the tail of a finished command was dropped; kept {} bytes",
                out.stdout.len()
            );
            assert_eq!(streamed, out.stdout.len(), "and the live view saw all of it too");
            assert_eq!(out.exit_code, Some(0));
        }
    }

    #[tokio::test]
    async fn the_process_group_does_not_outlive_a_normal_exit() {
        // The shell exits immediately and leaves a child holding both pipes.
        // Waiting for EOF here would hang for 30 seconds on a command that
        // finished at once; leaving the child alive would put a process the
        // window can no longer show and the Kill button can no longer reach
        // outside hatch's supervision.
        let (dir, env, tag) = fixture();
        let out = tokio::time::timeout(
            Duration::from_secs(10),
            run_capped("sleep 30 & echo done", &env, dir.path(), 1 << 20),
        )
        .await
        .expect("a backgrounded child must not keep run waiting");

        assert_eq!(out.stdout, "done\n");
        assert_eq!(out.exit_code, Some(0));
        assert!(!out.timed_out);
        assert!(!out.killed_by_user);
        assert!(wait_until_gone(&tag).await.is_empty(), "the group must not outlive the request");
    }

    #[tokio::test]
    async fn the_sink_and_the_capture_agree_on_where_truncation_happened() {
        // The live view is not capped -- a window that froze at the cap would
        // stop showing the user what they are deciding whether to kill. So the
        // two views genuinely differ, and the marker is what keeps the
        // difference from being silent: it reaches the sink at exactly the
        // point the agent's copy stops.
        let (dir, env, _tag) = fixture();
        let (tx, mut rx) = mpsc::channel(1024);
        let drain = tokio::spawn(async move {
            let mut seen = Vec::new();
            while let Some(chunk) = rx.recv().await {
                seen.push(chunk);
            }
            seen
        });

        let out = run(
            &argv("yes hello | head -100000"),
            &env,
            dir.path(),
            RunOpts {
                timeout: None,
                cancel: CancellationToken::new(),
                cap_bytes: 1024,
                chunks: Some(tx),
            },
        )
        .await
        .unwrap();

        let seen = drain.await.unwrap();
        let streamed: Vec<u8> = seen.iter().flat_map(|c| c.bytes.clone()).collect();
        let streamed = String::from_utf8_lossy(&streamed).into_owned();

        assert!(out.stdout_truncated);
        assert_eq!(streamed.matches("output truncated").count(), 1, "said once, not per chunk");

        let marker = "\n[hatch] output truncated at 1024 bytes\n";
        let at = streamed.find(marker).unwrap();
        assert_eq!(
            at, 1024,
            "the marker must sit in the stream at the exact byte the agent's copy stops at"
        );

        // `yes hello | head -100000` is exactly 100000 lines of six bytes. The
        // live view is the whole of it: not capped at all, not capped from the
        // marker onwards, not capped a read behind.
        let command_output = format!("{}{}", &streamed[..at], &streamed[at + marker.len()..]);
        assert_eq!(command_output.len(), 600_000, "the live view is the command's whole output");
        assert_eq!(
            &command_output[..1024],
            &out.stdout[..1024],
            "and the two views agree byte for byte up to the point the marker names"
        );
    }

    #[tokio::test]
    async fn a_run_that_is_both_truncated_and_killed_says_both() {
        // The case with the most to explain and the least room to explain it
        // in. Whichever note is written second must not be the one the cap
        // eats: "killed after" is hatch's, it is tens of bytes, and without it
        // a reader of a capped stdout is told the output stopped and not that
        // the command did.
        let (dir, env, tag) = fixture();
        let out = within(run(
            &argv("yes hello"),
            &env,
            dir.path(),
            RunOpts {
                timeout: Some(Duration::from_millis(300)),
                cancel: CancellationToken::new(),
                cap_bytes: 1024,
                chunks: None,
            },
        ))
        .await
        .unwrap();

        assert!(out.stdout_truncated);
        assert!(out.timed_out);
        assert!(out.stdout.contains("output truncated"), "got {:?}", out.stdout);
        assert!(
            out.stdout.contains("killed after 0.3s"),
            "hatch's own note must survive the cap, in full; got {:?}",
            out.stdout
        );
        assert!(wait_until_gone(&tag).await.is_empty());
    }

    #[tokio::test]
    async fn stdin_is_dev_null_and_not_whatever_the_daemon_had() {
        // An approved command that reads standard input must see end of file.
        // Inheriting the daemon's would hang the request on a terminal nobody
        // is watching, and would let an agent-chosen command read what is
        // typed there.
        //
        // Asserted as "fd 0 is /dev/null" rather than "`cat` returned
        // nothing", because the second is not a test of anything when the
        // harness itself was started with its own standard input on
        // /dev/null: inheriting then produces end of file too. This states
        // what the spawn is supposed to do, and it fails whenever the run has
        // a standard input of its own to leak.
        let (dir, env, _tag) = fixture();
        let out = within(run_capped("readlink /proc/self/fd/0", &env, dir.path(), 1 << 20)).await;
        assert_eq!(out.stdout.trim(), "/dev/null", "the child's standard input must be /dev/null");
        assert_eq!(out.exit_code, Some(0));

        // And it really does read as empty, which is what a command that reads
        // stdin depends on.
        let out = within(run_capped("cat", &env, dir.path(), 1 << 20)).await;
        assert_eq!(out.stdout, "");
        assert_eq!(out.exit_code, Some(0));
    }

    #[tokio::test]
    async fn the_command_runs_in_the_directory_it_was_given() {
        let (dir, env, _tag) = fixture();
        let out = run_capped("pwd", &env, dir.path(), 1 << 20).await;
        // The tempdir may live under a symlinked prefix (`/tmp` -> `/private`
        // and friends), so compare what the child reports against what the
        // child's own kernel view canonicalises to.
        assert_eq!(
            out.stdout.trim(),
            std::fs::canonicalize(dir.path()).unwrap().to_string_lossy()
        );
    }

    #[tokio::test]
    async fn the_child_gets_the_environment_it_was_handed_and_nothing_else() {
        // `build_child_env` refuses to read `std::env`; that is only worth
        // anything if the spawn refuses to inherit it too.
        let (dir, env, _tag) = fixture();
        let out = run_capped("env", &env, dir.path(), 1 << 20).await;
        let child: Vec<&str> = out.stdout.lines().collect();

        // Names the shell itself defines, which say nothing about inheritance.
        let shell_made = ["PWD", "SHLVL", "OLDPWD", "_"];
        let leaked: Vec<String> = std::env::vars()
            .map(|(key, _)| key)
            .filter(|key| !env.contains_key(key) && !shell_made.contains(&key.as_str()))
            .filter(|key| child.iter().any(|line| line.starts_with(&format!("{key}="))))
            .collect();
        assert!(leaked.is_empty(), "these came from hatch's own environment: {leaked:?}");
        assert!(
            child.iter().any(|line| *line == format!("PATH={}", env["PATH"])),
            "and the configured PATH did reach the child"
        );
    }

    #[tokio::test]
    async fn a_cancel_arriving_after_the_command_finished_is_not_a_kill() {
        // The token outlives the run in the daemon (one request, one token),
        // so a cancel that lands in the gap between exit and return must not
        // rewrite a completed command's result into a killed one.
        let (dir, env, _tag) = fixture();
        let cancel = CancellationToken::new();
        let out = run(
            &argv("echo done"),
            &env,
            dir.path(),
            RunOpts {
                timeout: None,
                cancel: cancel.clone(),
                cap_bytes: 1 << 20,
                chunks: None,
            },
        )
        .await
        .unwrap();
        cancel.cancel();

        assert!(!out.killed_by_user);
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.stdout, "done\n");
    }

    #[tokio::test]
    async fn a_command_that_cannot_be_spawned_is_an_error_not_an_exit_code() {
        let (dir, env, _tag) = fixture();
        let err = run(
            &["no-such-program-anywhere".to_string()],
            &env,
            dir.path(),
            RunOpts {
                timeout: None,
                cancel: CancellationToken::new(),
                cap_bytes: 1 << 20,
                chunks: None,
            },
        )
        .await
        .expect_err("nothing ran, so there is no exit code to report");
        assert!(matches!(err, ExecError::Spawn { .. }), "got {err:?}");
        assert!(err.to_string().contains("no-such-program-anywhere"));
    }

    #[tokio::test]
    async fn an_empty_argv_names_no_program() {
        let (dir, env, _tag) = fixture();
        let err = run(
            &[],
            &env,
            dir.path(),
            RunOpts {
                timeout: None,
                cancel: CancellationToken::new(),
                cap_bytes: 1 << 20,
                chunks: None,
            },
        )
        .await
        .expect_err("an empty argv has nothing to run");
        assert!(matches!(err, ExecError::NoProgram), "got {err:?}");
    }

    // ---- rendering an argv -------------------------------------------------

    #[test]
    fn a_command_reaches_the_shell_as_one_argument() {
        // The mutant this is here for replaces the three-element argv with a
        // single formatted string. Under it `bash` is handed one word, the
        // rest of the line becomes arguments to the script, and a command
        // with a space in it stops meaning what the window showed.
        let argv = shell_argv("echo 'a; b'");
        assert_eq!(argv, vec!["bash", "-c", "echo 'a; b'"], "three arguments, the last one whole");
    }

    #[test]
    fn a_quoted_argument_is_drawn_quoted_rather_than_joined() {
        assert_eq!(
            shell_line(&shell_argv("rm 'my file'")),
            r#"bash -c 'rm '\''my file'\'''"#,
            "the script is one quoted word and its inner quotes survive"
        );
    }

    #[test]
    fn plain_words_are_left_alone() {
        // Not cosmetic: the root line is mostly `--setenv=KEY=/some/path`, and
        // quoting every one of those would bury the one argument that is
        // genuinely quoted -- the command -- in a line of identical quotes.
        assert_eq!(
            shell_line(&[
                "run0".to_string(),
                "--pipe".to_string(),
                "--setenv=PATH=/usr/local/bin:/usr/bin".to_string(),
                "--".to_string(),
            ]),
            "run0 --pipe --setenv=PATH=/usr/local/bin:/usr/bin --"
        );
    }

    #[test]
    fn an_empty_argument_is_still_visible() {
        // `--setenv=SYSTEMD_PAGER=` is the reason: an empty value is a real
        // argument, and rendering it as nothing would lose a word from the
        // line without losing it from the run.
        assert_eq!(shell_line(&["a".to_string(), String::new(), "b".to_string()]), "a '' b");
    }

    #[test]
    fn every_shell_metacharacter_is_quoted() {
        for hostile in [
            "a b", "a;b", "a&&b", "a|b", "a>b", "a$b", "a`b`", "a*b", "a~b", "a#b", "a(b)",
            "a\nb", "a'b", "a\"b", "a\\b", "a!b", "a{b}", "a[b]", "a?b",
        ] {
            let line = shell_line(&[hostile.to_string()]);
            assert!(line.starts_with('\''), "{hostile:?} was left bare as {line:?}");
        }
    }

    #[test]
    fn the_rendered_line_re_splits_into_the_argv_it_came_from() {
        // The fidelity claim, checked against a real shell rather than
        // against this module's own idea of quoting. `printf` is the vehicle
        // only because it writes its arguments back out; what is under test
        // is that `shell_line` produced a line a shell reads as exactly the
        // arguments hatch holds. Nothing elevated runs here -- the argv is
        // built for this test, not taken from the root path.
        let args = [
            "it's".to_string(),
            "two words".to_string(),
            "$HOME".to_string(),
            "`id`".to_string(),
            "a\\b".to_string(),
            "*".to_string(),
            String::new(),
            "-n".to_string(),
        ];
        let mut argv = vec!["printf".to_string(), "%s\\n".to_string()];
        argv.extend(args.iter().cloned());

        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(shell_line(&argv))
            .output()
            .expect("bash must run");
        assert!(out.status.success(), "{:?}", String::from_utf8_lossy(&out.stderr));
        let seen: Vec<String> =
            String::from_utf8(out.stdout).unwrap().lines().map(str::to_string).collect();
        assert_eq!(seen, args.to_vec(), "the shell saw different arguments than hatch holds");
    }
}
