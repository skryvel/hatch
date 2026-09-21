//! A terminal of the person's own, and the transcript that comes back out.
//!
//! [`super::run`] gives an approved command two pipes and no terminal, which
//! is right for almost everything and wrong for the rest: a `pacman`
//! confirmation, an editor, a pager, anything that reads standard input. Those
//! commands do not fail on pipes, they *hang* on them, and the person watching
//! the window cannot do anything about it because there is nowhere to type.
//! This module is the other shape. It starts the terminal the config names,
//! runs the approved argv inside it under `script(1)`, and hands back one
//! interleaved transcript instead of two streams.
//!
//! # The status file is the answer; the terminal exiting is only a hint
//!
//! Nothing here reads the exit status of the terminal process, and that is the
//! single most load-bearing decision in the module. Two independent reasons,
//! both measured rather than assumed:
//!
//! * **A terminal may not wait for what it started.** Konsole can be
//!   configured to run every window in one process, in which case a second
//!   `konsole` hands its arguments to the first over D-Bus and returns at
//!   once. hatch would then report a command that finished instantly and
//!   succeeded, for a command still running in front of the person.
//! * **A terminal that does wait may still not report.** `kitty` blocks until
//!   its program exits and then exits `0` whatever the program did. Reading
//!   the exit status off the terminal would turn every failure into a success.
//!
//! So the runner below writes the command's status into a file when the
//! command is over, and that file is what [`run`] waits for. The terminal
//! exiting is treated as one signal among several — alongside the `started`
//! marker and a transcript that is still growing — and all it does is start a
//! short grace period, after which hatch says it could not tell how the run
//! ended rather than inventing a number.
//!
//! # Nothing agent-written is ever put through a shell
//!
//! The obvious way to write this is `script -c "<the approved command>"`, and
//! it is wrong. `script`'s `-c` runs its argument through `$SHELL -c`, so the
//! command would be parsed twice: once by the shell the window's rendering
//! describes, and once more by the shell in front of it. A command that
//! survives one round of quoting and not two is a command the window rendered
//! and did not run.
//!
//! `script`'s other form looks like it avoids that and does not. `script --
//! bash -c '…'` reads like an `execvp` of an argv; util-linux 2.42 joins that
//! argv back into one string with spaces and runs *it* through `$SHELL -c`, so
//! `script -- bash -c 'echo a; echo b'` really executes
//! `bash -c "bash -c echo a; echo b"`. It is the same trap wearing the
//! costume of the safe answer.
//!
//! What this module does instead: the argv hatch would have executed —
//! byte for byte the one the window rendered — is written to a file,
//! NUL-separated, and an inner runner reads it with `mapfile -d ''` and
//! `exec`s it. A NUL-separated file cannot be misparsed, because the one byte
//! that separates its fields is the one byte an argument cannot contain, and a
//! quoted array expansion is not re-split. The only string any shell parses
//! here is the one constant `script` is handed, which is hatch's own eleven
//! words and contains no part of the request. The approved bytes meet exactly
//! one shell, the same one they would have met on the ordinary path.
//!
//! # What the person pays for it
//!
//! Everything that appears in that terminal goes into the transcript, and the
//! transcript goes to the agent. That includes what the person types, because
//! the terminal echoes it. A password typed at a prompt inside that terminal
//! is in the agent's context afterwards. The window says so next to the
//! control — see [`crate::prompt_ui`] — because a cost the reader is not told
//! about before they choose is not a cost they agreed to.
//!
//! # What this module cannot promise
//!
//! The terminal is another program with settings of its own, and two of them
//! reach through:
//!
//! * **The environment** is hatch's constructed one *plus whatever the
//!   terminal adds*. A profile that exports variables exports them into the
//!   command too. The ordinary path's "constructed, never inherited" is
//!   weakened to "constructed, and then added to" here.
//! * **The working directory** would be the terminal's to choose — konsole
//!   profiles have an initial directory — so the inner runner `cd`s to the
//!   directory the window stated before it execs anything. That one is taken
//!   back rather than conceded, because the window states it as a fact.

use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::unistd::Pid;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::{Env, ExecError, Output, RunOpts, end_group, secs};

/// How often the status file, the `started` marker and the transcript's size
/// are looked at.
///
/// A tenth of a second is imperceptible against a command a person is sitting
/// in front of, and three `stat`s at that rate cost nothing. It is not a
/// latency budget: the poll only decides how quickly hatch notices a run that
/// has already ended.
const POLL: Duration = Duration::from_millis(100);

/// How long hatch keeps waiting after the terminal has gone and the transcript
/// has stopped growing.
///
/// The normal case never reaches this: the runner writes the status before it
/// exits, which is before the terminal exits, so the file is already there.
/// This bounds the two abnormal ones — a terminal that handed the work to
/// another process and returned, and a terminal somebody closed out from under
/// the command — and the transcript's size is what tells them apart from a run
/// that is simply slow. Long enough that a machine under load is not mistaken
/// for a run that vanished; short enough that a person waiting on a tool call
/// is not left there.
const AFTER_TERMINAL: Duration = Duration::from_secs(5);

/// How long the terminal is given to leave on its own once the command's
/// status is in hand.
///
/// It is already on its way out by then — the runner returned, so the terminal
/// has nothing left to run — and this is the difference between letting it
/// close and killing it. Everything hatch started is ended when the request
/// ends either way; this only decides whether that ending is a `SIGKILL`.
const TERMINAL_EXIT_GRACE: Duration = Duration::from_secs(2);

/// How long the command's process group is given to die before hatch stops
/// waiting for the status its death should produce.
///
/// Pressing Kill signals the command; the runner is still what writes the
/// status, and it writes `137` a moment later. If that does not happen the
/// command was not where hatch thought it was, and the terminal itself is
/// ended instead.
const AFTER_KILL: Duration = Duration::from_secs(3);

/// Cap on the terminal program's *own* diagnostics.
///
/// Not the transcript's cap, and much smaller. What this bounds is what a
/// terminal writes to the pipes hatch gave it before it takes over a window of
/// its own — `Error: no such option`, an X or Wayland complaint, a line about
/// a missing font. A few kilobytes is more than any of those, and none of it
/// is the command's output.
const DIAGNOSTIC_CAP: usize = 8 * 1024;

// ---- the files one run keeps -----------------------------------------------

/// The argv to execute, NUL-separated. See the module docs.
const ARGV: &str = "argv";
/// The directory the command must start in, as bytes with no trailing newline.
const CWD: &str = "cwd";
/// The outer runner, which the terminal starts.
const RUNNER: &str = "run";
/// The inner runner, which `script` starts and which becomes the command.
const INNER: &str = "inner";
/// Touched by the outer runner before it starts `script`.
const STARTED: &str = "started";
/// The command's own pid, written by the inner runner before it `exec`s.
const PID: &str = "pid";
/// Everything that appeared in the terminal.
const TRANSCRIPT: &str = "transcript";
/// The command's exit status, written when it is over.
const STATUS: &str = "status";

/// Why this machine cannot give a command a terminal of its own.
///
/// Two ways for it to be true and they are worth telling apart, because they
/// send the reader to different places: nothing is configured — which is the
/// default anywhere [`crate::config::default_terminal`] has no tested
/// terminal for — or something is configured and is not installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoTerminal {
    /// [`crate::config::Config::terminal`] is empty.
    NotConfigured,
    /// The program it names was not found on the child's `PATH`, as spelled.
    NotInstalled(String),
}

impl NoTerminal {
    /// The sentence the approval window puts under the dead control.
    ///
    /// It names the config key because the reader of this sentence is the one
    /// person who can change the answer, and a dead control with no way
    /// forward is a dead end.
    pub fn sentence(&self) -> String {
        let cause = match self {
            NoTerminal::NotConfigured => "No terminal is configured here".to_string(),
            NoTerminal::NotInstalled(program) => format!("{program} is not installed here"),
        };
        format!(
            "{cause}, so this cannot be given a terminal of its own. \
             The \"terminal\" key in hatch's config file names one."
        )
    }

    /// The same fact as a clause for [`crate::server`]'s refusal text, which
    /// reads *"hatch refused this before showing it to anyone: …"*.
    ///
    /// Addressed to the agent rather than the person, so it says what to do
    /// instead — asking again without a terminal is a request that can be
    /// answered, and the agent is the only party that can make it.
    pub fn clause(&self) -> String {
        let cause = match self {
            NoTerminal::NotConfigured => "no terminal is configured on this machine".to_string(),
            NoTerminal::NotInstalled(program) => {
                format!("the terminal this machine is configured for, {program}, is not installed")
            }
        };
        format!("{cause}, so a command cannot be given one; ask again without a terminal")
    }
}

/// Whether [`run`] could start a terminal at all, asked before anybody is.
///
/// Against the child's `PATH`, through the one shared lookup, because the
/// terminal is spawned with the child's environment and a check against any
/// other one would answer about a file the spawn will never reach. See
/// [`super::lookup`], which makes this argument at length.
///
/// It is a fact about this instant, like every other lookup: a terminal can be
/// uninstalled between this answer and the spawn. That is why the spawn still
/// reports its own failure and this is not treated as a guarantee — what it
/// buys is that the ordinary case, a machine that simply has no such program,
/// costs the reader nothing and is explained before they choose.
pub fn unavailable(terminal: &[String], env: &Env) -> Option<NoTerminal> {
    let Some(program) = terminal.first() else {
        return Some(NoTerminal::NotConfigured);
    };
    match super::lookup::lookup(program, env) {
        Some(_) => None,
        None => Some(NoTerminal::NotInstalled(program.clone())),
    }
}

/// The outer runner: start the recording, then record how it ended.
///
/// Every path in it is a quoted expansion of a variable this script sets
/// itself, never text hatch interpolated, so there is no round of quoting for
/// a directory name to escape from. `HATCH_RUN_DIR` comes from `$0` rather
/// than from the environment because `$0` is the one thing that reaches this
/// script however the terminal was started — an environment can be replaced by
/// a terminal that hands the work to another process, and an argument cannot.
///
/// `SHELL` is forced for the one line that needs it: `script` runs its
/// `--command` through `$SHELL`, and `$SHELL` on this machine is whatever the
/// person's login shell is. The constant below is bash, so bash is what reads
/// it.
///
/// The status is written after `script` returns and `script` is asked for
/// `--return`, so the number in the file is the command's own. It is a number
/// as a shell reports one: a command killed by signal 9 is `137`, not a signal
/// hatch could name, because the shell is all there is between here and it.
const RUNNER_SCRIPT: &str = r#"#!/bin/bash
# Written by hatch for one approved command; removed when that command ends.
# Nothing in this file came from the request -- see src/exec/interactive.rs.
export HATCH_RUN_DIR=${0%/*}
: > "$HATCH_RUN_DIR/started"
SHELL=/bin/bash script --quiet --return --log-out "$HATCH_RUN_DIR/transcript" \
	--command 'exec bash "$HATCH_RUN_DIR/inner"'
printf '%s\n' "$?" > "$HATCH_RUN_DIR/status"
"#;

/// The inner runner: the command, and nothing standing between it and the
/// terminal.
///
/// It records its own pid first. `script` puts its child in a session of its
/// own — that is what a pty needs — so this process is a process-group leader
/// and its pid *is* the group the command and everything it starts will be in.
/// That number is the only thing that makes the Kill button work: killing the
/// terminal's process group does not reach in here, because the terminal
/// detached this side of it on purpose.
///
/// Then the working directory the window stated, then `exec`. `exec` matters:
/// the pid that was recorded has to become the command, not the parent of it.
const INNER_SCRIPT: &str = r#"#!/bin/bash
# Written by hatch for one approved command -- see src/exec/interactive.rs.
printf '%s\n' "$$" > "$HATCH_RUN_DIR/pid"
cd -- "$(< "$HATCH_RUN_DIR/cwd")" || {
	printf 'hatch: the working directory this was approved for cannot be entered\n' >&2
	exit 125
}
mapfile -d '' -t argv < "$HATCH_RUN_DIR/argv"
exec "${argv[@]}"
"#;

// ---- what a caller asks for ------------------------------------------------

/// The knobs on one interactive run.
///
/// Deliberately not [`RunOpts`], though it shares three of its fields: there
/// is no `timeout` here and no `chunks`, and both absences are decisions
/// rather than omissions. The deadline is a runaway-process guard, and in a
/// terminal the person sitting at it is the guard — applying one would end
/// their session mid-keystroke. The live view has nothing to show, because the
/// terminal *is* the live view.
pub struct TerminalOpts<'a> {
    /// The terminal, as argv with the program first. The runner's path is
    /// appended to it. See [`crate::config::Config::terminal`].
    pub terminal: &'a [String],
    /// A directory only this user can read, to make this run's own directory
    /// inside. Checked before anything is written to it.
    pub parent: &'a Path,
    /// The user's Kill button.
    pub cancel: CancellationToken,
    /// Cap on the transcript that is kept. See [`Output::transcript`].
    pub cap_bytes: usize,
}

// ---- running ---------------------------------------------------------------

/// Run `argv` in a terminal and return everything that appeared in it.
///
/// `argv` is the argv the window rendered, unchanged — `bash -c <command>` for
/// an ordinary request, and the whole `run0 … -- bash -c <command>` for a root
/// one. A root command therefore runs `run0` *inside* the terminal rather than
/// the terminal inside `run0`, which is the way round that leaves the polkit
/// dialog behaving as it does everywhere else.
///
/// The [`Output`] that comes back carries the transcript and nothing in
/// `stdout` or `stderr`: a pty is one stream, and dividing it in two after the
/// fact would be hatch inventing a distinction the run did not have.
///
/// # Errors
///
/// [`ExecError`], and only for a run that never started: a private directory
/// hatch could not make, a terminal that is not installed, a terminal that
/// exited without ever starting the runner.
pub async fn run(
    argv: &[String],
    env: &Env,
    cwd: &Path,
    opts: TerminalOpts<'_>,
) -> Result<Output, ExecError> {
    let TerminalOpts { terminal, parent, cancel, cap_bytes } = opts;
    let Some((program, _)) = terminal.split_first() else {
        return Err(ExecError::NoProgram);
    };
    let program = program.clone();

    // Before the spawn, for the reason `super::run` checks it before the
    // spawn: the inner runner refuses to start the command in a directory it
    // cannot enter, and finding that out from inside a terminal that then
    // closes is the least useful place to find it out.
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

    let session = Session::create(parent, argv, cwd)?;
    let mut term_argv = terminal.to_vec();
    term_argv.push(session.path(RUNNER).display().to_string());

    // A token of hatch's own rather than the user's. Cancelling the user's
    // means "stop the command", and the command is not in this process group:
    // see `Session::command_group`. This one means "take the terminal away",
    // which is a different act and happens later or not at all.
    let closing = CancellationToken::new();
    let terminal_env = env.clone();
    let terminal_cwd = cwd.to_path_buf();
    let running = {
        let closing = closing.clone();
        tokio::spawn(async move {
            super::run(
                &term_argv,
                &terminal_env,
                &terminal_cwd,
                RunOpts {
                    // No deadline: see `TerminalOpts`.
                    timeout: None,
                    cancel: closing,
                    cap_bytes: DIAGNOSTIC_CAP,
                    chunks: None,
                },
            )
            .await
        })
    };
    tokio::pin!(running);

    let began = Instant::now();
    let mut killed_by_user = false;
    let mut killed_at: Option<Instant> = None;
    let mut terminal_output: Option<Result<Output, ExecError>> = None;
    // The moment the last sign of life was seen, once there is nothing left to
    // wait for except the file. `None` while the terminal is still up, which
    // is a sign of life in itself.
    let mut quiet_since: Option<Instant> = None;
    let mut transcript_len = 0;

    let status = loop {
        tokio::select! {
            // Biased so that a status file that is already there is read
            // before a timer is allowed to conclude there is not one.
            biased;
            joined = &mut running, if terminal_output.is_none() => {
                terminal_output = Some(match joined {
                    Ok(ran) => ran,
                    // The task cannot panic on its own; a cancelled runtime
                    // can still take it, and "hatch could not start it" is the
                    // honest reading of a spawn whose result never arrived.
                    Err(join) => Err(ExecError::Spawn {
                        program: program.clone(),
                        error: join.to_string(),
                    }),
                });
                quiet_since = Some(Instant::now());
            }
            () = cancel.cancelled(), if !killed_by_user => {
                killed_by_user = true;
                killed_at = Some(Instant::now());
                // The command first, because it is the thing the person wants
                // stopped and because killing it is what makes the runner
                // write a status at all. Only if there is no command to reach
                // does the terminal itself get ended.
                if !session.kill_command() {
                    closing.cancel();
                }
            }
            _ = tokio::time::sleep(POLL) => {}
        }

        if let Some(code) = session.status() {
            break Some(code);
        }

        // A transcript that is still growing is a run that is still going,
        // whatever the terminal process did. This is what stops a terminal
        // that handed the work to another process and returned from being read
        // as a command that finished.
        let seen = session.transcript_len();
        if seen > transcript_len {
            transcript_len = seen;
            if terminal_output.is_some() {
                quiet_since = Some(Instant::now());
            }
        }
        if quiet_since.is_some_and(|at| at.elapsed() >= AFTER_TERMINAL) {
            break None;
        }
        // A kill that did not produce a status within a few seconds did not
        // reach what hatch aimed it at. Take the terminal instead, which ends
        // the wait one way or the other.
        if killed_at.is_some_and(|at| at.elapsed() >= AFTER_KILL) {
            closing.cancel();
            killed_at = None;
        }
    };

    // The command is over, so the terminal has nothing left to run. It is
    // given a moment to notice before it is ended, so that the ordinary case
    // does not involve a signal at all.
    //
    // The result of the grace period is kept rather than thrown away and asked
    // for again. A `tokio::time::timeout` that returns `Ok` has already taken
    // the task's value out of the handle, and a `JoinHandle` polled after that
    // panics — so a second wait here would turn the ordinary ending, a
    // terminal that left inside its grace, into a request that died with
    // "JoinHandle polled after completion". Only the branch that timed out has
    // a handle left to wait on.
    if terminal_output.is_none() {
        let joined = match tokio::time::timeout(TERMINAL_EXIT_GRACE, &mut running).await {
            Ok(joined) => joined,
            Err(_) => {
                closing.cancel();
                (&mut running).await
            }
        };
        terminal_output = Some(match joined {
            Ok(ran) => ran,
            Err(join) => {
                Err(ExecError::Spawn { program: program.clone(), error: join.to_string() })
            }
        });
    }
    let terminal_output = terminal_output.expect("filled immediately above");

    // A terminal that could not be started is the one failure here that is
    // certainly not a command that ran.
    let terminal_output = match terminal_output {
        Ok(output) => output,
        Err(error) => return Err(error),
    };

    // Neither did a terminal that started and never reached the runner. The
    // marker is the runner's own first act, so its absence is evidence about
    // the runner rather than about the command.
    if status.is_none() && !session.started() {
        return Err(ExecError::Spawn {
            program,
            error: match first_line(&terminal_output.stderr) {
                "" => "the terminal exited without starting the command".to_string(),
                said => format!("the terminal exited without starting the command: {said}"),
            },
        });
    }

    let (mut transcript, truncated) = session.transcript(cap_bytes);
    if killed_by_user {
        transcript.push_str(&format!(
            "\n[hatch] killed by the user after {}\n",
            secs(began.elapsed())
        ));
    }
    if status.is_none() {
        transcript.push_str(
            "\n[hatch] the terminal ended without recording how the command finished, so there \
             is no exit status to report\n",
        );
    }

    Ok(Output {
        stdout: String::new(),
        stderr: String::new(),
        transcript: Some(transcript),
        exit_code: status,
        // A shell reports a signalled command as 128 plus the number and hatch
        // has nothing else to read, so claiming a signal here would be hatch
        // guessing which of the two a 137 was.
        signal: None,
        timed_out: false,
        killed_by_user,
        stdout_truncated: false,
        stderr_truncated: false,
        transcript_truncated: truncated,
    })
}

/// The first line of some text, trimmed, or `""`.
fn first_line(text: &str) -> &str {
    text.lines().map(str::trim).find(|line| !line.is_empty()).unwrap_or("")
}

// ---- one run's private directory -------------------------------------------

/// The directory one interactive run keeps its files in, removed when this
/// value is dropped.
///
/// Everything in it is readable by this user and nobody else, because two of
/// the files are the approved command: `argv` is what will be executed and
/// `run` is what will execute it, so another local user who could write either
/// one could choose what the terminal runs after the person had already said
/// yes.
struct Session {
    dir: tempfile::TempDir,
}

impl Session {
    /// Make the directory and write everything one run needs into it.
    ///
    /// `parent` is checked first, on the same terms
    /// `crate::paths::runtime_is_private` uses: a directory this process owns,
    /// at exactly 0700. A world-writable parent — `/tmp` is the one everybody
    /// reaches for — would leave the name of this directory a thing another
    /// local user could race, and `tempfile` creating the directory at 0700
    /// does not help with a parent somebody else can rearrange around it.
    fn create(parent: &Path, argv: &[String], cwd: &Path) -> Result<Session, ExecError> {
        if let Err(why) = private(parent) {
            return Err(ExecError::Setup {
                error: format!("{} {why}", parent.display()),
            });
        }
        let setup = |error: String| ExecError::Setup { error };
        let dir = tempfile::Builder::new()
            .prefix("terminal-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)
            .map_err(|e| setup(format!("creating a directory in {}: {e}", parent.display())))?;
        let session = Session { dir };

        // NUL-separated and NUL-terminated. An argument cannot contain a NUL —
        // `execve` would not carry it — so this is the one framing that cannot
        // be confused by the contents of what it frames.
        let mut packed = Vec::new();
        for arg in argv {
            packed.extend_from_slice(arg.as_bytes());
            packed.push(0);
        }
        session.write(ARGV, &packed, 0o600)?;
        // No trailing newline: the inner runner reads this with `$(<file)`,
        // which strips trailing newlines, and a path that ends in one would
        // come back as a different path.
        session.write(CWD, cwd.as_os_str().as_encoded_bytes(), 0o600)?;
        session.write(RUNNER, RUNNER_SCRIPT.as_bytes(), 0o700)?;
        session.write(INNER, INNER_SCRIPT.as_bytes(), 0o700)?;
        Ok(session)
    }

    /// One file in the directory, created at `mode` and never over an existing
    /// name.
    fn write(&self, name: &str, bytes: &[u8], mode: u32) -> Result<(), ExecError> {
        use std::io::Write as _;
        let path = self.path(name);
        let fail = |e: std::io::Error| ExecError::Setup {
            error: format!("writing {}: {e}", path.display()),
        };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)
            .map_err(fail)?;
        file.write_all(bytes).map_err(fail)?;
        // The terminal is about to read these from another process, and on a
        // file of this size the flush costs less than the failure mode it
        // rules out.
        file.sync_all().map_err(fail)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The command's exit status, if the runner has finished writing one.
    ///
    /// A file that exists but does not parse is a file still being written —
    /// `printf` creates it and fills it in two steps — so this says "not yet"
    /// rather than "no status", and the caller polls again. Nothing else can
    /// put an unparsable value there: the runner writes one `printf` of `$?`.
    fn status(&self) -> Option<i32> {
        let text = std::fs::read_to_string(self.path(STATUS)).ok()?;
        text.trim().parse().ok()
    }

    /// Whether the runner got as far as starting the recording.
    fn started(&self) -> bool {
        self.path(STARTED).exists()
    }

    /// How much has been recorded so far, as a sign of life.
    fn transcript_len(&self) -> u64 {
        std::fs::metadata(self.path(TRANSCRIPT)).map(|md| md.len()).unwrap_or(0)
    }

    /// The command's process group, once the inner runner has named it.
    fn command_group(&self) -> Option<Pid> {
        let text = std::fs::read_to_string(self.path(PID)).ok()?;
        let pid: i32 = text.trim().parse().ok()?;
        (pid > 0).then(|| Pid::from_raw(pid))
    }

    /// End the command and everything it started. Returns whether there was a
    /// group to end.
    ///
    /// The group, not the process, for the reason [`super::run`] kills a
    /// group: a command that left descendants would otherwise carry on with
    /// the Kill button reporting success. The group here is the one `script`
    /// made when it gave the command a terminal of its own, which is why it
    /// has to be read out of a file — it is not a descendant of anything hatch
    /// can see.
    fn kill_command(&self) -> bool {
        match self.command_group() {
            Some(pgid) => {
                end_group(Some(pgid));
                true
            }
            None => false,
        }
    }

    /// Everything that appeared in the terminal, as text an agent can read.
    ///
    /// Four things happen to it, in this order, and each of them is removing
    /// something the terminal put there rather than something the command
    /// said:
    ///
    /// 1. **The cap**, applied to the bytes on disk. A command that fills a
    ///    terminal for an hour is bounded here the way a command that fills a
    ///    pipe is bounded in [`super::Capture`], and by the same number.
    /// 2. **Escape sequences**, because a transcript is the output of a pty
    ///    and is full of cursor movement, colour and window titles. They are
    ///    noise to a reader and a way to lie to one — see
    ///    [`crate::render::unicode`] on why hatch does not pass control
    ///    sequences on.
    /// 3. **Carriage returns before newlines**, which a pty adds to every line
    ///    and no command wrote. A lone carriage return is left alone: that one
    ///    is a progress bar overwriting itself, which is the command's doing.
    /// 4. **`script`'s own two frame lines**, matched on the untranslated
    ///    `[COMMAND=` and `[COMMAND_EXIT_CODE=` they carry rather than on the
    ///    English around them. The first of them contains the command with its
    ///    quoting flattened out, which is a line that looks like a command and
    ///    is not one — exactly the kind of thing this project exists not to
    ///    show anybody. The blank line `script` writes in front of the second
    ///    of them goes with it.
    fn transcript(&self, cap: usize) -> (String, bool) {
        let path = self.path(TRANSCRIPT);
        let Ok(raw) = std::fs::read(&path) else { return (String::new(), false) };
        let truncated = raw.len() > cap;
        let kept = &raw[..raw.len().min(cap)];
        let stripped = strip_ansi_escapes::strip(kept);
        let text = String::from_utf8_lossy(&stripped).replace("\r\n", "\n");

        let mut lines: Vec<&str> = text.lines().collect();
        if lines.first().is_some_and(|line| frame(line, "[COMMAND=")) {
            lines.remove(0);
        }
        if lines.last().is_some_and(|line| frame(line, "[COMMAND_EXIT_CODE=")) {
            lines.pop();
            // The newline in front of it is the footer's too: `script` writes
            // "\nScript done on …" so that its own line starts at a column
            // whatever the command left the cursor at. Dropped with the line
            // it belongs to, and only then — a blank line at the end of a
            // transcript that has no footer is the command's own.
            if lines.last().is_some_and(|line| line.is_empty()) {
                lines.pop();
            }
        }
        let mut text = lines.join("\n");
        if !text.is_empty() {
            text.push('\n');
        }
        if truncated {
            text.push_str(&format!("\n[hatch] output truncated at {cap} bytes\n"));
        }
        (text, truncated)
    }
}

/// Whether `line` is one of `script`'s frame lines.
fn frame(line: &str, marker: &str) -> bool {
    line.starts_with("Script ") && line.contains(marker) && line.ends_with(']')
}

/// Whether approved bytes may be written under `path`.
///
/// The same rule `crate::paths::runtime_is_private` applies to the runtime
/// directory, restated here because this module is handed a directory rather
/// than choosing one and the check has to happen where the writing does. The
/// error is the middle of a sentence beginning with the directory's name.
fn private(path: &Path) -> Result<(), String> {
    let md = std::fs::metadata(path).map_err(|e| format!("cannot be read ({e})"))?;
    if !md.is_dir() {
        return Err("is not a directory".to_string());
    }
    let me = nix::unistd::geteuid().as_raw();
    if md.uid() != me {
        return Err(format!("belongs to uid {} rather than to hatch (uid {me})", md.uid()));
    }
    if md.mode() & 0o777 != 0o700 {
        return Err(format!("is mode {:04o} rather than the 0700 it must be", md.mode() & 0o777));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::exec::env::build_child_env;
    use crate::exec::shell_argv;
    use tempfile::TempDir;

    /// A private parent directory and the child environment the daemon really
    /// builds.
    ///
    /// Tightened to 0700 here, which is what [`crate::config`] does to the
    /// staging directory the daemon really passes: `tempfile` creates a
    /// directory at the umask's mode, and the umask of a test runner is not a
    /// promise about anybody's privacy.
    fn fixture() -> (TempDir, Env) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, build_child_env(&Config::default()))
    }

    #[test]
    fn a_machine_with_no_terminal_configured_says_so_rather_than_naming_one() {
        let (_dir, env) = fixture();
        assert_eq!(unavailable(&[], &env), Some(NoTerminal::NotConfigured));

        // The sentence has to carry the way out of it. A reader who is told
        // only that a control is dead has been told the half that does not
        // help them.
        let said = NoTerminal::NotConfigured.sentence();
        assert!(said.contains("terminal"), "{said}");
        assert!(said.contains("config file"), "{said}");
        assert!(!said.contains("konsole"), "it named a program that was never configured: {said}");
    }

    #[test]
    fn a_terminal_that_is_not_installed_is_named_as_spelled() {
        let (_dir, env) = fixture();
        let configured = ["a-terminal-nobody-has".to_string(), "-e".to_string()];
        let why = unavailable(&configured, &env).expect("it is not installed");
        assert_eq!(why, NoTerminal::NotInstalled("a-terminal-nobody-has".to_string()));

        // As spelled, because the name in the sentence is the name the reader
        // will go and look for in their config file.
        assert!(why.sentence().contains("a-terminal-nobody-has"), "{}", why.sentence());
        assert!(why.clause().contains("a-terminal-nobody-has"), "{}", why.clause());
    }

    #[test]
    fn a_terminal_that_is_installed_is_no_obstacle() {
        let (_dir, env) = fixture();
        // `bash` rather than a real terminal, for the reason the test
        // terminal below is bash: what is being checked is the lookup, and
        // the lookup's whole subject is whether a name resolves on the
        // child's PATH.
        assert_eq!(unavailable(&["bash".to_string()], &env), None);
    }

    #[test]
    fn the_lookup_is_against_the_path_the_terminal_will_be_spawned_with() {
        // Not the daemon's own. A terminal found on a PATH the spawn will
        // never use is a control this window would offer and the spawn would
        // then fail on -- which is the whole failure this check exists to
        // move before the question rather than after it.
        let (_dir, mut env) = fixture();
        assert_eq!(unavailable(&["bash".to_string()], &env), None);
        env.insert("PATH".to_string(), "/nowhere".to_string());
        assert_eq!(
            unavailable(&["bash".to_string()], &env),
            Some(NoTerminal::NotInstalled("bash".to_string()))
        );
    }

    /// The terminal a test uses: `bash`, which runs the runner and waits for
    /// it.
    ///
    /// A real terminal cannot open a window in a test suite, and a fake that
    /// reimplemented the runner would be testing the fake. This one is a
    /// terminal in the only sense this module depends on — a program that is
    /// handed the runner's path and starts it — so everything downstream of it
    /// is the code that will really run: the two runner scripts, `script`, the
    /// NUL-separated argv, the status file.
    fn terminal() -> Vec<String> {
        vec!["bash".to_string()]
    }

    fn opts<'a>(terminal: &'a [String], parent: &'a Path) -> TerminalOpts<'a> {
        TerminalOpts {
            terminal,
            parent,
            cancel: CancellationToken::new(),
            cap_bytes: 1 << 20,
        }
    }

    /// A hard ceiling, for the same reason [`super::super`]'s tests have one:
    /// several of these are about hatch ending something, and a test that can
    /// hang forever takes the whole run with it.
    async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(60), fut)
            .await
            .expect("the interactive run never ended, so this would have hung forever")
    }

    #[tokio::test]
    async fn the_bytes_that_were_approved_are_the_bytes_that_run() {
        // The whole point of the NUL-separated argv. Every one of these
        // survives a single shell and none of them survives two: under
        // `script -c "<command>"`, or under the `script -- <argv>` form that
        // looks like an exec and is not, the quotes are eaten by the second
        // parse and what runs is not what the window drew.
        let (dir, env) = fixture();
        let command = r#"printf '%s\n' 'a; b' "two  spaces" '$HOME' '`id`' "it's""#;
        let term = terminal();
        let out = within(run(&shell_argv(command), &env, dir.path(), opts(&term, dir.path())))
            .await
            .expect("the terminal must start");

        let seen = out.transcript.expect("an interactive run always has one");
        for literal in ["a; b", "two  spaces", "$HOME", "`id`", "it's"] {
            assert!(
                seen.contains(literal),
                "{literal:?} did not survive; a second shell read the command. Got {seen:?}"
            );
        }
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.stdout, "", "a pty is one stream and hatch does not pretend otherwise");
        assert_eq!(out.stderr, "");
    }

    #[tokio::test]
    async fn the_exit_status_comes_from_the_file_and_not_from_the_terminal() {
        // `kitty` exits 0 whatever its program did, and konsole can return
        // before its program has even started. Neither number is the
        // command's, so neither is read. This terminal reports success for a
        // command that failed, which is the shape of both.
        let (dir, env) = fixture();
        let term = vec!["bash".to_string(), "-c".to_string(), r#"bash "$0"; exit 0"#.to_string()];
        let out = within(run(&shell_argv("exit 42"), &env, dir.path(), opts(&term, dir.path())))
            .await
            .expect("the terminal must start");

        assert_eq!(out.exit_code, Some(42), "the terminal said 0; the command said 42");
        assert!(!out.killed_by_user);
        assert!(!out.timed_out, "there is no deadline on this path to have expired");
    }

    #[tokio::test]
    async fn the_transcript_is_stripped_of_what_the_terminal_put_in_it() {
        // Three things the command did not write: the colour it asked for,
        // the carriage return the pty adds to every line, and the two frame
        // lines `script` wraps the recording in. The first of those frame
        // lines carries the command with its quoting flattened, which is a
        // line that looks like a command and is not one.
        let (dir, env) = fixture();
        let term = terminal();
        let out = within(run(
            &shell_argv(r#"printf '\033[31mred\033[0m\n'; printf 'plain\n'"#),
            &env,
            dir.path(),
            opts(&term, dir.path()),
        ))
        .await
        .expect("the terminal must start");

        let seen = out.transcript.unwrap();
        assert_eq!(seen, "red\nplain\n", "got {seen:?}");
        assert!(!out.transcript_truncated);
    }

    #[tokio::test]
    async fn a_transcript_over_the_cap_is_cut_and_says_so() {
        let (dir, env) = fixture();
        let term = terminal();
        let out = within(run(
            &shell_argv("yes hello | head -20000"),
            &env,
            dir.path(),
            TerminalOpts { cap_bytes: 1024, ..opts(&term, dir.path()) },
        ))
        .await
        .expect("the terminal must start");

        let seen = out.transcript.unwrap();
        assert!(out.transcript_truncated);
        assert!(seen.contains("output truncated at 1024 bytes"), "got {seen:?}");
        assert!(seen.len() <= 1024 + 128, "the cap bounds it, plus room for the marker");
        assert_eq!(out.exit_code, Some(0), "the cap is hatch's limit, not the command failing");
    }

    #[tokio::test]
    async fn the_command_starts_in_the_directory_the_window_stated() {
        // A terminal is entitled to choose its own initial directory, and
        // konsole profiles do. The window states this one as a fact, so the
        // runner takes it back rather than trusting whatever the terminal
        // thought.
        let (dir, env) = fixture();
        let elsewhere = tempfile::tempdir().unwrap();
        // A terminal that deliberately starts somewhere else first.
        let term = vec![
            "bash".to_string(),
            "-c".to_string(),
            format!(r#"cd {} && bash "$0""#, elsewhere.path().display()),
        ];
        let out = within(run(&shell_argv("pwd"), &env, dir.path(), opts(&term, dir.path())))
            .await
            .expect("the terminal must start");

        let seen = out.transcript.unwrap();
        assert_eq!(
            seen.trim(),
            std::fs::canonicalize(dir.path()).unwrap().to_string_lossy(),
            "the command ran where the terminal wanted rather than where the window said"
        );
    }

    #[tokio::test]
    async fn kill_ends_the_command_and_everything_it_started() {
        // The terminal's own process group does not contain the command:
        // `script` gives it a session of its own, which is what a pty needs.
        // So the Kill button reaches it through the pid the inner runner
        // records, and this is the test that it does — without it the button
        // would report success and stop nothing.
        let (dir, env) = fixture();
        let cancel = CancellationToken::new();
        let term = terminal();
        let running = {
            let (env, cwd, cancel, term) =
                (env.clone(), dir.path().to_path_buf(), cancel.clone(), term.clone());
            let parent = dir.path().to_path_buf();
            tokio::spawn(async move {
                run(
                    &shell_argv("sleep 300 & sleep 300"),
                    &env,
                    &cwd,
                    TerminalOpts {
                        terminal: &term,
                        parent: &parent,
                        cancel,
                        cap_bytes: 1 << 20,
                    },
                )
                .await
            })
        };

        // The group, once the inner runner has named it. Read from the
        // filesystem because there is no other way to it.
        let group = within(async {
            loop {
                if let Some(found) = find_group(dir.path()) {
                    return found;
                }
                tokio::time::sleep(POLL).await;
            }
        })
        .await;
        // Without this the rest would pass against a group that never had
        // anything in it.
        assert!(
            members(group).len() >= 3,
            "the shell, its backgrounded child and the one it waits on must all be up; saw {:?}",
            members(group)
        );

        cancel.cancel();
        let out = within(running).await.unwrap().expect("the terminal started, so this is a result");

        assert!(out.killed_by_user);
        assert!(out.transcript.unwrap().contains("killed by the user"), "and it says so in band");
        assert!(
            within(async {
                loop {
                    if members(group).is_empty() {
                        return true;
                    }
                    tokio::time::sleep(POLL).await;
                }
            })
            .await,
            "the backgrounded child must die with the group, or the Kill button lied"
        );
    }

    /// The command's process group, once some run under `parent` has recorded
    /// one.
    fn find_group(parent: &Path) -> Option<i32> {
        for entry in std::fs::read_dir(parent).ok()?.flatten() {
            let pid = entry.path().join(PID);
            if let Ok(text) = std::fs::read_to_string(&pid)
                && let Ok(found) = text.trim().parse::<i32>()
            {
                return Some(found);
            }
        }
        None
    }

    /// Every live process in `group`, as pids. Zombies are not members: they
    /// hold nothing open and can run no code.
    fn members(group: i32) -> Vec<i32> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else { return found };
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
            // `comm` is parenthesised and may contain spaces and parentheses,
            // so the fields are counted from the last `)`: state, ppid, pgrp.
            let Some(close) = stat.rfind(')') else { continue };
            let mut fields = stat[close + 1..].split_whitespace();
            let state = fields.next();
            let _ppid = fields.next();
            let Some(Ok(pgrp)) = fields.next().map(str::parse::<i32>) else { continue };
            if pgrp == group && state != Some("Z") {
                found.push(pid);
            }
        }
        found
    }

    #[tokio::test]
    async fn a_terminal_that_is_not_installed_is_an_error_and_not_a_result() {
        let (dir, env) = fixture();
        let term = vec!["no-such-terminal-anywhere".to_string()];
        let err = within(run(&shell_argv("echo ran"), &env, dir.path(), opts(&term, dir.path())))
            .await
            .expect_err("nothing ran, so there is no exit status to report");
        assert!(matches!(err, ExecError::Spawn { .. }), "got {err:?}");
        assert!(err.to_string().contains("no-such-terminal-anywhere"));
    }

    #[tokio::test]
    async fn a_terminal_that_never_starts_the_command_is_an_error_and_not_a_success() {
        // `kitty` exits 0 for a program it could not run, so "the terminal
        // exited 0" and "the command ran" are not the same claim. The marker
        // the runner writes before it does anything else is what separates
        // them: no marker, no command.
        let (dir, env) = fixture();
        let term = vec!["true".to_string()];
        let err = within(run(&shell_argv("echo ran"), &env, dir.path(), opts(&term, dir.path())))
            .await
            .expect_err("the terminal ignored the runner, so nothing ran");
        assert!(matches!(err, ExecError::Spawn { .. }), "got {err:?}");
        assert!(
            err.to_string().contains("without starting the command"),
            "the message must say what did not happen; got {err}"
        );
    }

    #[tokio::test]
    async fn a_terminal_that_returns_early_does_not_make_the_command_finished() {
        // Konsole in single-process mode hands its arguments to a konsole that
        // is already running and returns at once. Reading that as the end of
        // the command would report an instant success for a command still in
        // front of the person. `setsid --fork` is the same shape: it starts
        // the runner and returns before it has done anything.
        let (dir, env) = fixture();
        let term = vec!["setsid".to_string(), "--fork".to_string(), "bash".to_string()];
        let started = std::time::Instant::now();
        let out = within(run(
            &shell_argv("sleep 2; echo the end"),
            &env,
            dir.path(),
            opts(&term, dir.path()),
        ))
        .await
        .expect("the terminal started");

        assert!(
            started.elapsed() >= Duration::from_secs(2),
            "hatch answered after {:?}, so it read the terminal's exit as the command's",
            started.elapsed()
        );
        assert_eq!(out.exit_code, Some(0));
        assert!(out.transcript.unwrap().contains("the end"));
    }

    #[tokio::test]
    async fn a_terminal_still_on_its_way_out_is_waited_for_exactly_once() {
        // The ordinary ending, slowed down enough to see. The runner writes
        // the status and returns, and the terminal is still up for a moment
        // afterwards -- a window redrawing, a shell running its exit trap,
        // konsole saving its scrollback. `run` leaves its loop the instant
        // the status file appears, so the terminal's result is not in hand
        // yet, and the grace period below the loop is the only thing that
        // waits for it. Half a second is well inside that grace, and long
        // enough that no poll of the loop can collect the terminal first.
        //
        // The failure this pins is not a wrong answer but a panic: a grace
        // period that polls the terminal's join handle, gets the result, and
        // then polls the same handle again takes the whole request down with
        // "JoinHandle polled after completion". Every interactive run ends
        // this way, so the window here is only ever as wide as the gap
        // between the status file and the terminal leaving.
        let (dir, env) = fixture();
        let term =
            vec!["bash".to_string(), "-c".to_string(), r#"bash "$0"; sleep 0.5"#.to_string()];
        let out = within(run(&shell_argv("echo done"), &env, dir.path(), opts(&term, dir.path())))
            .await
            .expect("the terminal started");

        assert_eq!(out.exit_code, Some(0), "the command's own status, read off the file");
        let seen = out.transcript.expect("an interactive run always has one");
        assert!(seen.contains("done"), "got {seen:?}");
        assert!(
            !seen.contains("without recording how the command finished"),
            "the status was there all along; got {seen:?}"
        );
    }

    #[tokio::test]
    async fn a_parent_directory_other_people_can_write_to_is_refused() {
        // `/tmp` is the directory everybody reaches for and it is 1777. The
        // files here are the approved command and the script that runs it, so
        // a parent another local user can rearrange is a parent where what
        // runs is no longer what was approved.
        let (dir, env) = fixture();
        let loose = dir.path().join("loose");
        std::fs::create_dir(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();

        let term = terminal();
        let err = within(run(&shell_argv("echo ran"), &env, dir.path(), opts(&term, &loose)))
            .await
            .expect_err("a world-writable parent is not private");
        assert!(matches!(err, ExecError::Setup { .. }), "got {err:?}");
        assert!(err.to_string().contains("0700"), "the message must say what was wrong; got {err}");
    }

    #[tokio::test]
    async fn an_empty_terminal_names_no_program() {
        let (dir, env) = fixture();
        let err = within(run(&shell_argv("echo ran"), &env, dir.path(), opts(&[], dir.path())))
            .await
            .expect_err("a terminal with no program in it cannot be started");
        assert!(matches!(err, ExecError::NoProgram), "got {err:?}");
    }

    #[tokio::test]
    async fn a_working_directory_that_is_not_one_is_refused_before_the_terminal_opens() {
        let (dir, env) = fixture();
        let missing = dir.path().join("no-such-directory");
        let term = terminal();
        let err = within(run(&shell_argv("echo ran"), &env, &missing, opts(&term, dir.path())))
            .await
            .expect_err("a directory that is not there cannot be a working directory");
        assert!(matches!(err, ExecError::BadCwd { .. }), "got {err:?}");
    }

    #[test]
    fn only_script_s_own_frame_lines_are_taken_for_frame_lines() {
        // Matched on the untranslated `[COMMAND=` rather than on the English
        // around it, because the rest of the line is localised. A line of the
        // command's own output that merely mentions one of them is not a
        // frame: it does not begin the way `script`'s does.
        assert!(frame(r#"Script started on 2026-01-01 [COMMAND="bash -c ls"]"#, "[COMMAND="));
        assert!(frame(r#"Script done on 2026-01-01 [COMMAND_EXIT_CODE="0"]"#, "[COMMAND_EXIT_CODE="));
        assert!(!frame(r#"grep: [COMMAND="x"]"#, "[COMMAND="));
        assert!(!frame("Script started on 2026-01-01", "[COMMAND="));
    }
}
