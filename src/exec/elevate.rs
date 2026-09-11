//! Running an approved command as root: the argv, the verdict, the platform.
//!
//! This module is the whole of hatch's knowledge about elevation. Everything
//! it knows about `run0`, about systemd and about polkit is behind
//! [`Elevation`], and the rest of the codebase is meant to hold a
//! `Box<dyn Elevation>` and never learn which one it has. That is not
//! portability theatre: the alternative is a `run0` string in the spawner, a
//! polkit exit status in the daemon and a systemd assumption in the window,
//! and three places is where a platform assumption stops being reviewable.
//!
//! # The two gates
//!
//! hatch's approval window is one gate and the polkit password dialog is a
//! second, independent one. Both must fire for every root operation, and the
//! second one only fires if polkit is asked afresh each time: the action
//! `run0` uses, `org.freedesktop.systemd1.manage-units`, ships
//! `auth_admin_keep`, which caches an authorisation for the session. Under the
//! shipped policy a second root command inside the cache window runs with no
//! password prompt at all, and hatch's window is then the only gate — which is
//! precisely the arrangement the security argument says does not exist. A
//! drop-in under `/etc/polkit-1/rules.d/` returning `polkit.Result.AUTH_ADMIN`
//! for that action restores the second factor, and was checked the only way
//! worth checking it: two root commands five seconds apart, two password
//! prompts.
//!
//! **That drop-in is a deployment requirement, not a nicety,** and nothing in
//! this module can verify it. hatch cannot ask polkit "would you cache this",
//! and a check that ran a probe command to find out would itself pop a
//! password dialog. So it is documented here and in the install notes, and it
//! is the one part of the root path that rests on the operator.
//!
//! # Refusing is not the same as not elevating
//!
//! The failure this module is shaped to make unrepresentable is the quiet one:
//! a platform that cannot elevate returning the *unelevated* argv, so that a
//! command the user approved as root runs as the user instead, does something
//! different, and reports success. [`Elevation::argv`] therefore returns a
//! [`Result`] whose success type is [`ElevatedArgv`], which cannot be built
//! from a plain argv — the only constructor puts the elevation program in
//! front of it. An implementation with nothing to put in front has no way to
//! return `Ok`.
//!
//! The same rule at the other end: [`NoElevation::classify`] cannot report an
//! exit status, because a command that was never elevated was never run.
//!
//! # Two environments, and why they differ
//!
//! A root run involves two processes and they do not get the same
//! environment. [`Elevation::spawner_env`] is what the *elevation program*
//! runs with; [`Elevation::child_env`] is what the *approved command* runs
//! with, passed explicitly as `--setenv` arguments that the window draws. They
//! differ on purpose and in both directions — the command gets hatch's pager
//! defaults, `run0` gets hatch's forced locale — and keeping the two apart is
//! what stops either difference from leaking into the other. See each method
//! for the argument.
//!
//! # One gate on the platform
//!
//! [`platform`] is the only place in the crate that asks what operating system
//! this is, and it asks with `cfg!` rather than `#[cfg]` so that both
//! implementations compile, and are tested, on every platform. A refusing
//! implementation that only compiles where it is selected is a refusing
//! implementation nobody has ever run.
//!
//! # What a second implementation owes
//!
//! [`Elevation`] is seven methods and none of them mention systemd. A macOS
//! implementation over `sudo` with a GUI askpass would supply: the askpass
//! argv; a [`Elevation::child_env`] naming whatever that platform's tools read
//! for paging; a [`Elevation::spawner_env`] that pins `sudo`'s own diagnostics
//! to a known language, because `sudo` translates them too; a
//! [`Elevation::classify`] that knows what a cancelled askpass looks like
//! (status 1, `sudo: a password is required` on standard error — the same
//! collision `run0` has, for the same reason); and a [`Elevation::caveat`]
//! saying whether its elevated child gets a terminal.

use std::collections::BTreeMap;
use std::fmt;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use super::{Env, shell_argv, shell_line};

// ---- what every platform must answer ---------------------------------------

/// One way of running an approved command as root.
///
/// Two responsibilities, and they are the two halves of a root run: build the
/// argv that elevates, and say what a finished elevated run actually means.
/// Everything else — spawning, capture, the timeout, the Kill button — is
/// [`super::run`]'s and is the same whether or not the command is elevated.
pub trait Elevation: Send + Sync {
    /// What this elevates with, for the window and for messages: `run0`.
    fn mechanism(&self) -> &'static str;

    /// Whether an elevated run can be attempted at all.
    ///
    /// Resolved against the `PATH` in `env` — the one the child will be given
    /// — and not against the daemon's own. The daemon's `PATH` came from
    /// wherever it happened to be started; the child's is the config's, and
    /// the child's is the one the spawn will search. Answering from the wrong
    /// one would report a mechanism as present that the run cannot find.
    ///
    /// # Errors
    ///
    /// [`Unavailable`], whose message names what is missing.
    fn available(&self, env: &Env) -> Result<(), Unavailable>;

    /// The environment the **approved command** receives.
    ///
    /// Not the same map as the unelevated child's, and the difference is on
    /// screen: every pair here becomes a visible `--setenv` in the approved
    /// line. See [`Run0::child_env`] for why hatch adds anything at all.
    fn child_env(&self, env: &Env) -> Env;

    /// The environment the **elevation program itself** is spawned with.
    ///
    /// A separate question from [`Self::child_env`], and the separation is the
    /// point: hatch needs `run0` to speak a language hatch can read, and needs
    /// the command not to be affected by that. See [`Run0::spawner_env`].
    fn spawner_env(&self, env: &Env) -> Env;

    /// The argv that runs `inner` as root with [`Self::child_env`] applied.
    ///
    /// `inner` is an argv and not a command string, because the two callers
    /// want different things in front of the elevation wrapper and only one
    /// of them wants a shell. A `run_command` request is a script and gets
    /// `bash -c`; a root `swap_file` is `install` with four options and two
    /// paths, and putting a shell under it would re-parse a path the window
    /// already committed to for no gain at all. This is the primitive and
    /// [`Self::argv`] is the shell-shaped case of it.
    ///
    /// # Errors
    ///
    /// [`Unavailable`], on exactly the terms [`Self::available`] uses. There
    /// is no third answer: an implementation that cannot elevate returns an
    /// error, never an argv that runs the command some other way.
    fn elevate(&self, inner: Vec<String>, env: &Env) -> Result<ElevatedArgv, Unavailable>;

    /// The argv that runs the shell script `command` as root.
    ///
    /// [`shell_argv`] and then [`Self::elevate`], so the wrapper an elevated
    /// command gets is the same one the unelevated path uses and the command
    /// travels as a single `execve` argument either way.
    fn argv(&self, command: &str, env: &Env) -> Result<ElevatedArgv, Unavailable> {
        self.elevate(shell_argv(command), env)
    }

    /// What a finished elevated run means.
    ///
    /// `spawned_with` is the environment the elevation program was actually
    /// given — [`Self::spawner_env`]'s result, as the spawner used it, not as
    /// this module assumes it. An implementation whose diagnostics are
    /// translated can only read them if it knows which language they were
    /// written in, and the only honest source for that is the environment the
    /// run really had. Passing anything else here is how a caller gets a
    /// confident answer out of evidence that does not support one.
    ///
    /// A pure function of how the process ended, so it is testable without a
    /// password dialog — which is the point, because the dialog cannot be
    /// driven from a test and a classifier nobody can test is a classifier
    /// nobody can trust.
    fn classify(&self, exit: Option<i32>, stderr: &str, spawned_with: &Env) -> RootOutcome;

    /// What the window must tell a reader about how a root command differs
    /// from an ordinary one, or `None` when it does not differ.
    ///
    /// A difference in behaviour between the two paths that the window does
    /// not mention is the same failure as a command line the window renders
    /// wrong, only smaller: in both cases the reader approves one thing and a
    /// different one happens.
    fn caveat(&self) -> Option<&'static str>;
}

/// The implementation for the platform this build runs on.
///
/// The one place in the crate that asks. `cfg!` and not `#[cfg]`: both arms
/// are compiled and type-checked everywhere, so the refusing implementation is
/// covered by this crate's tests on the platform where it is *not* selected,
/// which is the only platform its tests will ever run on.
pub fn platform() -> Box<dyn Elevation> {
    if cfg!(target_os = "linux") {
        Box::new(Run0::new())
    } else {
        Box::new(NoElevation::for_os(std::env::consts::OS))
    }
}

// ---- the values it trades in -----------------------------------------------

/// An argv that elevates, and the only kind [`Elevation::argv`] can return.
///
/// The invariant is structural rather than checked: [`ElevatedArgv::wrapping`]
/// is the sole constructor, it is private to this module, and it puts the
/// elevation program at `argv[0]` itself. There is no way to hand the spawner
/// a plain `bash -c …` through this type, which is the one mistake on the root
/// path that would be silent — the command runs, produces output, exits zero,
/// and was never root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevatedArgv(Vec<String>);

impl ElevatedArgv {
    /// `program`, then `wrapper`, then `inner`.
    ///
    /// Taking the three parts rather than a finished vector is what makes the
    /// invariant hold by construction: a caller cannot pass an argv that has
    /// no program in front of it, because the program is a separate argument
    /// and this function is what joins them.
    fn wrapping(program: &str, wrapper: Vec<String>, inner: Vec<String>) -> ElevatedArgv {
        let mut argv = Vec::with_capacity(1 + wrapper.len() + inner.len());
        argv.push(program.to_string());
        argv.extend(wrapper);
        argv.extend(inner);
        ElevatedArgv(argv)
    }

    /// The elevation program — `argv[0]`, which this type guarantees exists.
    pub fn program(&self) -> &str {
        &self.0[0]
    }

    /// The argv, for the spawner.
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// The argv, consumed.
    pub fn into_vec(self) -> Vec<String> {
        self.0
    }

    /// The line the window shows, shell-quoted from the argv above.
    ///
    /// Rendered from the arguments rather than assembled alongside them, so
    /// the line and the run cannot describe different things: see
    /// [`shell_line`]. The reader sees the whole of it — the `bash -c`
    /// wrapper, every `--setenv`, the `--` — because the parts of a root
    /// command line a reader would most want hidden are exactly the parts that
    /// decide what it does.
    pub fn display_line(&self) -> String {
        shell_line(self.as_slice())
    }
}

/// Elevation cannot be attempted here, and why.
///
/// Separate from [`RootOutcome`] because it is answered *before* anything is
/// spawned. Every value of this type means nothing ran, and the message says
/// so in words, because it is shown to a person and written to the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable {
    /// What is missing, as a sentence.
    pub message: String,
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Unavailable {}

/// How an elevated run ended.
///
/// The distinction that matters is the first one: did the command run. An
/// elevation that was refused and a command that exited non-zero are
/// **the same exit status** — both 1, measured — so a classifier that keeps
/// only the number cannot tell them apart, and reporting a refused elevation
/// as "the command exited 1" sends the agent off to fix a command that never
/// ran.
///
/// [`RootOutcome::Unclear`] is here because the alternative to it is a guess.
/// A wrong `Denied` is annoying; a wrong `Ran` hides that nothing happened at
/// all, and that is the direction this project refuses to fail in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootOutcome {
    /// The command ran as root. `exit` is the command's own status, `None`
    /// when a signal ended it — the same meaning [`super::Output::exit_code`]
    /// has, because it is the same number.
    Ran {
        /// The command's exit status.
        exit: Option<i32>,
    },
    /// Nothing ran: the person dismissed the password dialog, or polkit
    /// refused.
    Denied,
    /// Nothing ran, for a reason that is not a refusal — no bus, no
    /// authentication agent, a transient unit that would not start.
    Failed {
        /// What to tell the user.
        message: String,
    },
    /// The command exited non-zero and hatch cannot say whether that status is
    /// the command's or a refusal it could not read.
    ///
    /// Reachable only when the elevation program was spawned without the
    /// forced locale that makes its diagnostics legible — see
    /// [`Run0::spawner_env`]. The status is carried so the caller can still
    /// report it, but it must be reported *as uncertain*: the one thing that
    /// must not happen here is the number being passed off as the command's.
    Unclear {
        /// The status the run ended with.
        exit: Option<i32>,
        /// What to tell the user about why hatch cannot interpret it.
        message: String,
    },
}

impl RootOutcome {
    /// The text for [`crate::protocol::Outcome::ElevationFailed`], or `None`
    /// when this is not a case of nothing having run.
    ///
    /// `None` for [`RootOutcome::Unclear`] too, and deliberately: that variant
    /// is not a claim that nothing ran, so reporting it as an elevation
    /// failure would be the same overstatement in the other direction. A
    /// caller has to handle it as its own case, which is the point of it
    /// being its own case.
    pub fn elevation_failure(&self) -> Option<String> {
        match self {
            RootOutcome::Ran { .. } | RootOutcome::Unclear { .. } => None,
            RootOutcome::Denied => Some(DENIED_MESSAGE.to_string()),
            RootOutcome::Failed { message } => Some(message.clone()),
        }
    }
}

impl From<Unavailable> for RootOutcome {
    fn from(unavailable: Unavailable) -> RootOutcome {
        RootOutcome::Failed { message: unavailable.message }
    }
}

/// What a refused elevation says. One sentence, and the last clause is the
/// load-bearing one: after a denial the agent must not retry as if the command
/// had failed, and the user must not go looking for what it changed.
const DENIED_MESSAGE: &str =
    "the password dialog was dismissed or the authentication failed, so nothing ran";

// ---- Linux: systemd's run0 -------------------------------------------------

/// Elevation through `run0`, systemd's polkit-mediated `sudo` replacement.
///
/// `run0` rather than `sudo` or `pkexec`: no setuid binary is involved, the
/// request travels over the system bus, and the desktop's own authentication
/// agent draws the password dialog — on Wayland, natively, which a terminal
/// `sudo` prompt cannot do from a daemon with no terminal.
pub struct Run0;

impl Run0 {
    /// The program.
    pub const PROGRAM: &'static str = "run0";

    /// The polkit action `run0` authenticates against.
    ///
    /// Nothing passes this to anything: `run0` picks the action itself and
    /// hatch never names it on a command line. It is a constant because it is
    /// the subject of a deployment requirement — the drop-in that restores
    /// the second gate has to name this exact action or it restores nothing,
    /// and `hatch setup polkit` prints that drop-in. A string written out a
    /// second time over there is a string that can drift from the one the
    /// elevation path actually meets, and the failure mode of a drifted
    /// action id is a rule that matches nothing and a user who believes they
    /// have two gates. See the module docs, "The two gates".
    pub const POLKIT_ACTION: &'static str = "org.freedesktop.systemd1.manage-units";

    /// The status `run0` exits with when polkit refuses. **Measured, and
    /// deliberately not used as a signal.**
    ///
    /// The measurement, taken with the `AUTH_ADMIN` drop-in installed so that
    /// a dialog was guaranteed to appear: `run0 true` exits 0, `run0 false`
    /// exits 1, and `run0 true` with the dialog cancelled *also* exits 1. The
    /// number a refusal produces is the number every failing command in the
    /// world produces, so there is nothing here to branch on. It is recorded
    /// as a constant so that nobody measures it a third time, and
    /// `the_denial_status_is_not_a_signal_because_it_collides` is what stops a
    /// later reader from deciding that 1 must mean something after all.
    pub const DENIAL_EXIT: i32 = 1;

    /// The default.
    pub fn new() -> Run0 {
        Run0
    }
}

impl Default for Run0 {
    fn default() -> Run0 {
        Run0::new()
    }
}

/// Environment hatch puts *underneath* the configured one for an elevated
/// command. See [`Run0::child_env`].
const PAGER_DEFEAT: [(&str, &str); 2] = [("PAGER", "cat"), ("SYSTEMD_PAGER", "")];

/// Environment hatch forces *on top of* the configured one for `run0` itself,
/// and only for `run0` itself. See [`Run0::spawner_env`].
///
/// `LANGUAGE` is emptied as well as `LC_ALL` being set, because in glibc
/// `LANGUAGE` overrides `LC_ALL` for message translation specifically: setting
/// `LC_ALL=C` alone still leaves a user with `LANGUAGE=de` reading German
/// diagnostics.
const FORCED_LOCALE: [(&str, &str); 2] = [("LANGUAGE", ""), ("LC_ALL", "C")];

/// What the window says about a root command, because it is not the same
/// command the unelevated path would run.
const RUN0_CAVEAT: &str = "A root command may be given a terminal where an ordinary one gets a \
                           pipe, so it can colour its output or stop to ask something. hatch \
                           sets PAGER and SYSTEMD_PAGER so it cannot wait forever on a pager, \
                           and leaves the rest of its output exactly as it was written.";

/// Text in `run0`'s own first line of standard error that means polkit
/// refused.
///
/// The first entry is the measured one, in full:
/// `Failed to start transient service unit: Access denied`. The rest are the
/// other wordings systemd and polkit use for the same thing, because a
/// refusal that arrives with no authentication agent running says
/// `Interactive authentication required` instead and is equally a refusal.
///
/// Matched case-insensitively, only against the *first* line, and only when
/// the run0 process was given [`FORCED_LOCALE`] — see [`Run0::classify`] for
/// what each of those three restrictions is holding back.
const DENIAL_MARKERS: [&str; 4] = [
    "access denied",
    "interactive authentication required",
    "authentication failed",
    "not authorized",
];

/// Text meaning `run0` could not elevate for a reason that is not a refusal.
/// Checked after [`DENIAL_MARKERS`], because the refusal message names the
/// unit too and a refusal is the more specific answer.
const FAILURE_MARKERS: [&str; 2] =
    ["failed to start transient service", "failed to connect to bus"];

impl Elevation for Run0 {
    fn mechanism(&self) -> &'static str {
        Run0::PROGRAM
    }

    fn available(&self, env: &Env) -> Result<(), Unavailable> {
        if lookup(Run0::PROGRAM, env).is_some() {
            return Ok(());
        }
        Err(Unavailable {
            message: format!(
                "{} was not found on the command's PATH ({}), so hatch cannot run anything as \
                 root here; nothing was run",
                Run0::PROGRAM,
                env.get("PATH").map_or("unset", String::as_str),
            ),
        })
    }

    /// The configured environment, over hatch's pager defaults.
    ///
    /// # Why hatch adds anything
    ///
    /// Everywhere else the child environment is a total function of the config
    /// — nothing inherited, nothing added — because the window resolves
    /// variables against it and a window that resolves against a map the child
    /// does not get is a window stating something untrue. Two keys are added
    /// here anyway, and the reason is that the root path has a failure the
    /// unelevated path does not.
    ///
    /// Under `run0` a command can find itself on a terminal. A terminal is
    /// what `systemctl status`, `journalctl` and `git log` check before
    /// starting a pager, and a pager with nothing to read from waits — not for
    /// a second, but until hatch kills it at the execution deadline, five
    /// minutes later, having shown the reader nothing. `systemctl status` is
    /// not a hypothetical command on this path; it is one of the first things
    /// anyone asks a root shell for.
    ///
    /// So `PAGER=cat` and an empty `SYSTEMD_PAGER`, which is the documented
    /// way to tell systemd's tools not to page. They go *underneath* the
    /// configured pairs, exactly as `PATH` does in
    /// [`super::env::build_child_env`]: a user who spells `PAGER` out in
    /// `exec_env` means it, and hatch's default is a default.
    ///
    /// The honesty cost is paid in the open. Every pair in this map becomes a
    /// `--setenv` in the argv, and the argv is what the window draws, so the
    /// reader sees both keys and can see that hatch put them there. An
    /// invisible environment difference between the two paths would be the
    /// thing to refuse; a visible one is a stated fact.
    ///
    /// Note what is *not* here: [`FORCED_LOCALE`]. That belongs to `run0` and
    /// stops there — see [`Run0::spawner_env`].
    fn child_env(&self, env: &Env) -> Env {
        let mut child: Env = PAGER_DEFEAT
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect::<BTreeMap<_, _>>();
        child.extend(env.iter().map(|(key, value)| (key.clone(), value.clone())));
        child
    }

    /// The configured environment, plus a forced C locale — for `run0` and
    /// nothing downstream of it.
    ///
    /// # Why the locale is forced
    ///
    /// A cancelled password dialog and a command that ran and returned 1 exit
    /// with the same status; see [`Run0::DENIAL_EXIT`]. The only thing that
    /// tells them apart is `run0`'s own message on standard error — and
    /// systemd translates its diagnostics. Matching
    /// `Failed to start transient service unit: Access denied` works for an
    /// English session and silently stops working for everyone else, in the
    /// worst direction available: hatch would report "your command failed,
    /// exit 1" when the truth is "you cancelled the password and nothing ran".
    /// A confident wrong answer, produced only for users who are not reading
    /// the project's own language.
    ///
    /// So `run0` is spawned with `LC_ALL=C` and an empty `LANGUAGE`, and its
    /// diagnostics are then in the one language [`DENIAL_MARKERS`] is written
    /// in. This is forced over the config rather than under it, unlike the
    /// pager defaults: the config's locale is a statement about the command's
    /// output, and this is not about the command.
    ///
    /// # Why it must stop here
    ///
    /// The approved command's environment is [`Self::child_env`], passed
    /// explicitly through `--setenv` — `run0` resets the environment for the
    /// transient unit it creates, so what it was itself spawned with is not
    /// what the command receives. If the forcing did reach the command, then a
    /// root command would see a different locale than the same command run
    /// unprivileged: sort order, number formatting and every message the
    /// command itself emits would change between the two paths, unremarked.
    /// That is the same class of failure as the terminal difference in
    /// [`RUN0_CAVEAT`] and would deserve the same treatment — except that here
    /// it is avoidable, so it is avoided.
    ///
    /// `locale_is_forced_for_run0_and_not_for_the_command` pins hatch's half
    /// of that: the two maps do not agree on these keys. The other half —
    /// whether `run0` propagates anything of its own into the unit — is
    /// systemd's behaviour, not hatch's, and no test here can see it. The
    /// request flow is wired now, so the check is one `run_command` with
    /// `root: true` and the command `env`, read off the window. It is named
    /// here because it is the last unmeasured assumption on this path.
    fn spawner_env(&self, env: &Env) -> Env {
        let mut spawner = env.clone();
        spawner.extend(
            FORCED_LOCALE.iter().map(|(key, value)| ((*key).to_string(), (*value).to_string())),
        );
        spawner
    }

    /// `run0 --pipe --setenv=… -- <inner>`, and for a `run_command` request
    /// that tail is `bash -c '<command>'`.
    ///
    /// In that order, and every part of it earns its place:
    ///
    /// * `--pipe` asks for the command's output on hatch's pipes rather than
    ///   on a terminal of `run0`'s own.
    /// * One `--setenv` per pair, in key order — `run0` resets the environment
    ///   for the transient unit it creates, so anything the child is to have
    ///   must be named here. Key order because a [`BTreeMap`] has one, and a
    ///   line a reader re-reads must not shuffle between two runs of the same
    ///   request.
    /// * `--` before the command, so that a command beginning with a dash is
    ///   the command and not another option to `run0`.
    /// * `inner` last and untouched. For [`Elevation::argv`] that is
    ///   [`shell_argv`]'s `bash -c` and the command as one argument — the same
    ///   wrapper the unelevated path uses, so the command is never
    ///   concatenated into the line but travels as a single `execve` argument
    ///   from here to the shell that reads it. For a root `swap_file` it is
    ///   `install` and its arguments, with no shell under them at all.
    fn elevate(&self, inner: Vec<String>, env: &Env) -> Result<ElevatedArgv, Unavailable> {
        self.available(env)?;
        let mut wrapper = vec!["--pipe".to_string()];
        wrapper.extend(
            self.child_env(env).iter().map(|(key, value)| format!("--setenv={key}={value}")),
        );
        wrapper.push("--".to_string());
        Ok(ElevatedArgv::wrapping(Run0::PROGRAM, wrapper, inner))
    }

    /// Did the command run, and if not, was it refused.
    ///
    /// Four rules, in this order:
    ///
    /// 1. A zero status is the command's. A refusal means nothing ran, and
    ///    nothing running does not succeed.
    /// 2. Otherwise, a refusal must be spelled out on the **first line** of
    ///    standard error.
    /// 3. Otherwise, if `run0` was not given [`FORCED_LOCALE`], hatch cannot
    ///    read a message it may not be able to recognise, and the answer is
    ///    [`RootOutcome::Unclear`].
    /// 4. Otherwise the command ran, and the status is the command's own.
    ///
    /// # Why the first line, and what is still open
    ///
    /// A refusal means the command never started, so `run0`'s message is the
    /// only thing on standard error and is therefore line one. When the
    /// command *does* run, line one is the command's first diagnostic — and
    /// the command's text is chosen by the agent. Matching anywhere in the
    /// stream would let a command write `Access denied` to standard error, run
    /// to completion as root, and be recorded as never having run: a lie in
    /// the audit log, written by the party the log exists to keep honest.
    ///
    /// Restricting the match to line one narrows that to a command whose
    /// *first* diagnostic is the marker, and rule 1 narrows it again by taking
    /// every successful run out of reach. It does not close it, and there is
    /// no exit status to close it with — the measurement says 1 either way.
    /// What remains is: an agent-chosen command that runs as root, exits
    /// non-zero, and whose first line of standard error is one of four
    /// phrases, is recorded as having been refused. The consequence of that
    /// misreading is a *more* alarming log entry than the truth, not a less
    /// alarming one, which is the direction to fail in if one must be chosen.
    ///
    /// # Why rule 3 is not paranoia
    ///
    /// It is the only thing making [`Self::spawner_env`] load-bearing rather
    /// than advisory. A caller that spawns `run0` with the plain child
    /// environment gets `Unclear` on every non-zero run instead of a
    /// plausible-looking `Ran`, which is a bug that announces itself on the
    /// first failing command rather than one that waits for a German-speaking
    /// user to cancel a dialog.
    fn classify(&self, exit: Option<i32>, stderr: &str, spawned_with: &Env) -> RootOutcome {
        if exit == Some(0) {
            return RootOutcome::Ran { exit };
        }
        let first = stderr.lines().next().unwrap_or("").to_lowercase();
        if DENIAL_MARKERS.iter().any(|marker| first.contains(marker)) {
            return RootOutcome::Denied;
        }
        if FAILURE_MARKERS.iter().any(|marker| first.contains(marker)) {
            return RootOutcome::Failed {
                message: format!(
                    "{} could not elevate, so nothing ran: {}",
                    Run0::PROGRAM,
                    stderr.lines().next().unwrap_or("").trim()
                ),
            };
        }
        if !locale_is_forced(spawned_with) {
            return RootOutcome::Unclear {
                exit,
                message: format!(
                    "{} was run without a forced locale, so hatch cannot tell a cancelled \
                     password dialog from the command's own failure: both end with status {}",
                    Run0::PROGRAM,
                    Run0::DENIAL_EXIT,
                ),
            };
        }
        RootOutcome::Ran { exit }
    }

    fn caveat(&self) -> Option<&'static str> {
        Some(RUN0_CAVEAT)
    }
}

/// Whether `env` pins message translation to the language [`DENIAL_MARKERS`]
/// is written in. Every pair of [`FORCED_LOCALE`], because `LC_ALL=C` with
/// `LANGUAGE` still set is not forced at all.
fn locale_is_forced(env: &Env) -> bool {
    FORCED_LOCALE.iter().all(|(key, value)| env.get(*key).map(String::as_str) == Some(*value))
}

/// Find `program` on the `PATH` the child will be given.
///
/// Empty entries are skipped rather than read as `.`, which is what a shell
/// would do with them: resolving an elevation program out of whatever
/// directory a request happens to name is the one lookup nobody wants
/// relative.
fn lookup(program: &str, env: &Env) -> Option<PathBuf> {
    env.get("PATH")?
        .split(':')
        .filter(|dir| !dir.is_empty())
        .map(|dir| Path::new(dir).join(program))
        .find(|candidate| is_executable(candidate))
}

/// A file that could be executed: a regular file with an execute bit set.
fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|md| md.is_file() && md.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

// ---- everywhere else: refuse, and say what is missing ----------------------

/// The implementation for a platform hatch has no elevation mechanism for.
///
/// It refuses, it names the operating system and the mechanism it would need,
/// and it has no way to do anything else — see the module docs. Compiled and
/// tested on every platform including the one where it is never selected,
/// because a refusal path that only exists where it is chosen is a refusal
/// path nobody has ever exercised.
pub struct NoElevation {
    /// The operating system, for the message.
    os: String,
}

impl NoElevation {
    /// Refuse on behalf of `os`, named in every message this produces.
    pub fn for_os(os: &str) -> NoElevation {
        NoElevation { os: os.to_string() }
    }

    /// The refusal, as one sentence ending in the fact that matters.
    fn refusal(&self) -> Unavailable {
        Unavailable {
            message: format!(
                "hatch cannot run a command as root on {}: that needs systemd's {}, which exists \
                 only on Linux, and hatch will not run an approved root command without it; \
                 nothing was run",
                self.os,
                Run0::PROGRAM,
            ),
        }
    }
}

impl Elevation for NoElevation {
    fn mechanism(&self) -> &'static str {
        "none"
    }

    fn available(&self, _env: &Env) -> Result<(), Unavailable> {
        Err(self.refusal())
    }

    /// The environment unchanged, which is the only honest answer: nothing
    /// will receive it.
    fn child_env(&self, env: &Env) -> Env {
        env.clone()
    }

    /// The environment unchanged. Nothing is spawned, so there are no
    /// diagnostics to pin to a language.
    fn spawner_env(&self, env: &Env) -> Env {
        env.clone()
    }

    /// Always an error. There is no argv, and in particular there is no
    /// unelevated one: running the command as the user is not a degraded form
    /// of running it as root, it is a different operation than the one that
    /// was approved.
    fn elevate(&self, _inner: Vec<String>, _env: &Env) -> Result<ElevatedArgv, Unavailable> {
        Err(self.refusal())
    }

    /// Never an exit status.
    ///
    /// Reachable only if a caller ignored [`NoElevation::argv`]'s error and
    /// ran something anyway, and in that case whatever it ran was not this.
    /// Returning `Ran` with the status would put a number in the log under a
    /// root request this platform cannot honour.
    fn classify(&self, _exit: Option<i32>, _stderr: &str, _spawned_with: &Env) -> RootOutcome {
        RootOutcome::Failed { message: self.refusal().message }
    }

    /// Nothing to warn about: nothing runs.
    fn caveat(&self) -> Option<&'static str> {
        None
    }
}

// ---- a rehearsed elevation, for the tests a password dialog makes impossible

/// An [`Elevation`] that answers with an outcome a test chose, and elevates
/// by running the argv it was given without any privilege at all.
///
/// # Why this lives here rather than in a test module
///
/// [`ElevatedArgv`]'s only constructor is private to this module, on purpose:
/// it is what makes "an implementation that cannot elevate cannot return an
/// argv" hold by construction rather than by review. A double built outside
/// this file could not produce one, so the double belongs inside it. That is
/// the invariant working — it constrains hatch's own tests exactly as it
/// constrains a second platform.
///
/// # Why it runs the command
///
/// The four things a password dialog can do cannot be produced on demand: a
/// dialog cannot be driven from a test, and this project's rule is that no
/// test invokes `run0`. But the *mapping* from those four outcomes onto a
/// tool result, a log verdict and a closing frame is the part most worth
/// testing, and testing it needs a run that really happens — otherwise every
/// case reaches the daemon as "hatch could not start it" and the mapping is
/// never exercised.
///
/// So this elevates with a program that runs its arguments and nothing else,
/// resolved off the same `PATH` the child is given. The command genuinely
/// runs, as whoever runs the test; [`Elevation::classify`] then returns
/// whatever the test asked for, which is precisely the seam a real dialog
/// would sit behind.
///
/// Behind the test feature and not `cfg(test)`, for the reason
/// [`crate::prompter::StubPrompter`] is: the integration tests link the
/// library compiled without `cfg(test)`.
#[cfg(any(test, feature = "test-stub-prompter"))]
pub struct Rehearsed {
    /// The program put in front of the argv. Either one that runs what
    /// follows it, or one that ignores it.
    program: &'static str,
    /// What [`Elevation::classify`] answers, whatever actually happened.
    outcome: RootOutcome,
    /// The refusal [`Elevation::available`] gives, when it refuses.
    unavailable: Option<String>,
    /// Every argv this was asked to elevate, in order.
    seen: std::sync::Mutex<Vec<Vec<String>>>,
}

#[cfg(any(test, feature = "test-stub-prompter"))]
impl Rehearsed {
    /// Elevate by running the argv, and report `outcome` afterwards.
    ///
    /// `env` runs its arguments as a command with the environment it was
    /// given, which for an argv that is already `["bash", "-c", …]` or
    /// `["install", …]` means the argv runs unchanged. It is in every POSIX
    /// system's base install and it takes no options hatch needs to avoid.
    pub fn running(outcome: RootOutcome) -> Rehearsed {
        Rehearsed::new("env", outcome)
    }

    /// Elevate by running a program that ignores the argv, and report
    /// `outcome`.
    ///
    /// For the tests that are about the argv hatch *builds* rather than about
    /// what running it does: `true` exits 0 having done nothing, so the argv
    /// can be asserted on through [`Rehearsed::seen`] with nothing on disk
    /// touched.
    pub fn recording(outcome: RootOutcome) -> Rehearsed {
        Rehearsed::new("true", outcome)
    }

    /// An elevation that refuses before anything is spawned.
    pub fn unavailable(message: &str) -> Rehearsed {
        Rehearsed {
            unavailable: Some(message.to_string()),
            ..Rehearsed::new("true", RootOutcome::Ran { exit: Some(0) })
        }
    }

    fn new(program: &'static str, outcome: RootOutcome) -> Rehearsed {
        Rehearsed {
            program,
            outcome,
            unavailable: None,
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Every argv this was asked to elevate, in order.
    pub fn seen(&self) -> Vec<Vec<String>> {
        self.seen.lock().expect("the recording lock").clone()
    }
}

#[cfg(any(test, feature = "test-stub-prompter"))]
impl Elevation for Rehearsed {
    fn mechanism(&self) -> &'static str {
        self.program
    }

    fn available(&self, _env: &Env) -> Result<(), Unavailable> {
        match &self.unavailable {
            Some(message) => Err(Unavailable { message: message.clone() }),
            None => Ok(()),
        }
    }

    /// [`Run0`]'s, so that what the window resolves variables against has the
    /// same shape in a test as in production.
    fn child_env(&self, env: &Env) -> Env {
        Run0::new().child_env(env)
    }

    /// [`Run0`]'s, including the forced locale. A double that quietly dropped
    /// it would make every test pass over the one condition
    /// [`Run0::classify`]'s third rule exists to enforce.
    fn spawner_env(&self, env: &Env) -> Env {
        Run0::new().spawner_env(env)
    }

    /// The program, then the argv unchanged. No wrapper of its own: `run0`'s
    /// `--pipe` and `--setenv` are `run0`'s, and a double that invented
    /// options for a program that does not take them would not run.
    fn elevate(&self, inner: Vec<String>, env: &Env) -> Result<ElevatedArgv, Unavailable> {
        self.available(env)?;
        self.seen.lock().expect("the recording lock").push(inner.clone());
        // Resolved off the child's `PATH` for the reason `available` is: the
        // spawn searches that one, not the daemon's.
        let program = lookup(self.program, env)
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| self.program.to_string());
        Ok(ElevatedArgv::wrapping(&program, Vec::new(), inner))
    }

    fn classify(&self, _exit: Option<i32>, _stderr: &str, _spawned_with: &Env) -> RootOutcome {
        self.outcome.clone()
    }

    fn caveat(&self) -> Option<&'static str> {
        Some(RUN0_CAVEAT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `PATH` with a real executable `run0` on it, so [`Run0::available`]
    /// answers yes without anything being elevated. The directory is the whole
    /// fixture: nothing in this file ever spawns what it finds.
    fn with_run0() -> (tempfile::TempDir, Env) {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join(Run0::PROGRAM);
        std::fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut env = Env::new();
        env.insert("PATH".to_string(), dir.path().display().to_string());
        env.insert("HOME".to_string(), "/home/someone".to_string());
        (dir, env)
    }

    fn argv_of(command: &str) -> Vec<String> {
        let (_dir, env) = with_run0();
        Run0::new().argv(command, &env).expect("run0 is on this PATH").into_vec()
    }

    /// An environment that satisfies [`locale_is_forced`], for the
    /// classification tests that are not about the locale.
    fn forced() -> Env {
        Run0::new().spawner_env(&Env::new())
    }

    // ---- the argv ----------------------------------------------------------

    #[test]
    fn a_direct_argv_is_elevated_without_a_shell_under_it() {
        let (_dir, env) = with_run0();
        let install = vec![
            "install".to_string(),
            "-m".to_string(),
            "0644".to_string(),
            "--".to_string(),
            "/stage/a".to_string(),
            "/etc/hosts".to_string(),
        ];
        let argv = Run0::new().elevate(install.clone(), &env).expect("run0 is on this PATH");

        assert_eq!(argv.program(), Run0::PROGRAM);
        // The tail is the argv it was handed, untouched and unwrapped. A
        // `bash -c` under `install` would re-parse two paths the window has
        // already committed to, and `swap_file` never displays a command line
        // for a reader to notice it in.
        assert_eq!(&argv.as_slice()[argv.as_slice().len() - install.len()..], &install[..]);
        assert!(
            !argv.as_slice().contains(&"bash".to_string()),
            "a shell was put under a direct argv: {:?}",
            argv.as_slice()
        );
        // Everything else about the wrapper is the same as a command's.
        assert_eq!(argv.as_slice()[1], "--pipe");
        assert!(argv.as_slice().contains(&"--".to_string()));
    }

    #[test]
    fn a_command_is_the_shell_shaped_case_of_the_same_primitive() {
        let (_dir, env) = with_run0();
        let run0 = Run0::new();
        assert_eq!(
            run0.argv("echo hi", &env).unwrap(),
            run0.elevate(shell_argv("echo hi"), &env).unwrap(),
            "the two entry points built different argvs for the same command"
        );
    }

    #[test]
    fn a_platform_that_cannot_elevate_refuses_a_direct_argv_too() {
        let refusing = NoElevation::for_os("plan9");
        assert!(refusing.elevate(vec!["install".to_string()], &Env::new()).is_err());
        assert!(refusing.argv("true", &Env::new()).is_err());
    }


    #[test]
    fn the_root_argv_is_the_line_the_spec_names() {
        let (dir, env) = with_run0();
        let argv = Run0::new().argv("systemctl status zram0", &env).unwrap().into_vec();
        assert_eq!(
            argv,
            vec![
                "run0".to_string(),
                "--pipe".to_string(),
                "--setenv=HOME=/home/someone".to_string(),
                "--setenv=PAGER=cat".to_string(),
                format!("--setenv=PATH={}", dir.path().display()),
                "--setenv=SYSTEMD_PAGER=".to_string(),
                "--".to_string(),
                "bash".to_string(),
                "-c".to_string(),
                "systemctl status zram0".to_string(),
            ],
            "program, --pipe, every --setenv in key order, --, then the shell"
        );
    }

    #[test]
    fn every_variable_the_child_gets_is_on_the_line() {
        // The mutant: the `--setenv` list dropped, or built from an empty
        // iterator. `run0` resets the environment, so the command would then
        // run with no PATH and no HOME while the window had shown neither
        // missing -- a command failing for a reason the reader was never told.
        let (_dir, mut env) = with_run0();
        env.insert("TERM".to_string(), "xterm-256color".to_string());

        let argv = Run0::new().argv("true", &env).unwrap();
        let child = Run0::new().child_env(&env);
        assert!(!child.is_empty(), "there is an environment to pass");
        for (key, value) in &child {
            assert!(
                argv.as_slice().contains(&format!("--setenv={key}={value}")),
                "{key} reaches the child unannounced: {:?}",
                argv.as_slice()
            );
        }
        assert_eq!(
            argv.as_slice().iter().filter(|a| a.starts_with("--setenv=")).count(),
            child.len(),
            "one --setenv per variable and no others"
        );
    }

    #[test]
    fn the_command_is_one_argument_after_bash_minus_c() {
        // The mutant: `bash -c` collapsed into a concatenated string. Under it
        // the argv ends with one word, `run0` reads the rest of the command as
        // its own arguments, and a command with a space in it does not run at
        // all -- or worse, runs in part.
        let argv = argv_of("echo 'one two'; rm -rf /tmp/x");
        assert_eq!(
            &argv[argv.len() - 3..],
            &[
                "bash".to_string(),
                "-c".to_string(),
                "echo 'one two'; rm -rf /tmp/x".to_string()
            ],
            "the command is the single last argument"
        );
    }

    #[test]
    fn a_command_that_starts_with_a_dash_is_still_the_command() {
        // What `--` is for. Without it `run0` would read `--version` as its own
        // option and print its version instead of running anything, under a
        // window that said something else entirely.
        let argv = argv_of("--version");
        let separator = argv.iter().position(|a| a == "--").expect("the separator is on the line");
        let bash = argv.iter().position(|a| a == "bash").expect("the shell is on the line");
        assert!(separator < bash, "-- comes before the shell: {argv:?}");
        assert_eq!(argv.last().map(String::as_str), Some("--version"));
    }

    #[test]
    fn the_setenv_order_does_not_move_between_runs() {
        // A line a person re-reads must be the same line.
        let (_dir, env) = with_run0();
        let run0 = Run0::new();
        assert_eq!(run0.argv("true", &env).unwrap(), run0.argv("true", &env).unwrap());
    }

    // ---- the line the window draws -----------------------------------------

    #[test]
    fn the_display_line_shows_the_wrapper_and_every_setenv() {
        let (_dir, env) = with_run0();
        let line = Run0::new().argv("systemctl status zram0", &env).unwrap().display_line();

        assert!(line.starts_with("run0 --pipe "), "{line}");
        assert!(line.contains("--setenv=HOME=/home/someone"), "{line}");
        assert!(line.contains("--setenv=PAGER=cat"), "{line}");
        // Bare, not quoted: the whole argument is one shell word and the
        // empty value is its last character, so it reads as it would be typed.
        assert!(line.contains("--setenv=SYSTEMD_PAGER= "), "{line}");
        assert!(line.contains(" -- bash -c "), "{line}");
        assert!(line.ends_with("'systemctl status zram0'"), "{line}");
    }

    #[test]
    fn the_display_line_is_rendered_from_the_argv_not_built_beside_it() {
        // The mutant: a display line assembled by concatenation. It shows up
        // the moment the command contains a quote, which is exactly when the
        // reader most needs the line to mean what it says.
        let (_dir, env) = with_run0();
        let argv = Run0::new().argv("echo 'it is'", &env).unwrap();
        assert_eq!(argv.display_line(), shell_line(argv.as_slice()));
        assert!(
            argv.display_line().ends_with(r#"'echo '\''it is'\'''"#),
            "{}",
            argv.display_line()
        );
    }

    // ---- classification ----------------------------------------------------

    #[test]
    fn a_denial_is_not_an_ordinary_non_zero_exit() {
        // The measured case, verbatim: the dialog was cancelled, run0 exited 1
        // and wrote this line. The mutant is a classifier that looks only at
        // the status -- under it the agent is told the command exited 1 and
        // goes off to debug a command that never ran.
        let outcome = Run0::new().classify(
            Some(Run0::DENIAL_EXIT),
            "Failed to start transient service unit: Access denied\n",
            &forced(),
        );
        assert_eq!(outcome, RootOutcome::Denied);
        assert_eq!(outcome.elevation_failure().as_deref(), Some(DENIED_MESSAGE));
    }

    #[test]
    fn the_denial_status_is_not_a_signal_because_it_collides() {
        // `run0 false` exits 1 and so does a cancelled dialog. Nothing may be
        // concluded from the number, and this is what stops a later reader
        // from deciding otherwise.
        assert_eq!(Run0::DENIAL_EXIT, 1);
        assert_eq!(
            Run0::new().classify(Some(Run0::DENIAL_EXIT), "", &forced()),
            RootOutcome::Ran { exit: Some(1) },
            "a bare 1 says nothing about elevation"
        );
    }

    #[test]
    fn an_ordinary_failure_is_not_a_denial() {
        let stderr = "grep: /etc/nope: No such file or directory\n";
        let outcome = Run0::new().classify(Some(1), stderr, &forced());
        assert_eq!(outcome, RootOutcome::Ran { exit: Some(1) });
        assert_eq!(outcome.elevation_failure(), None, "the command ran; the status is its own");
    }

    #[test]
    fn a_command_that_succeeded_is_never_a_denial() {
        // A refusal means nothing ran, so a zero status cannot be one. This is
        // also the cheapest half of the defence against a command that writes
        // the marker itself.
        assert_eq!(
            Run0::new().classify(Some(0), "access denied\n", &forced()),
            RootOutcome::Ran { exit: Some(0) }
        );
    }

    #[test]
    fn the_marker_is_only_believed_on_the_first_line() {
        // The command's own output cannot promote itself into a verdict. The
        // agent chooses the command text, so a match anywhere in the stream
        // would let it have hatch record a root command that ran as one that
        // never did.
        assert_eq!(
            Run0::new().classify(Some(2), "checking...\nremote said: Access denied\n", &forced()),
            RootOutcome::Ran { exit: Some(2) },
            "line two is the command talking, not run0"
        );
    }

    #[test]
    fn a_signal_leaves_the_outcome_a_run_with_no_status() {
        assert_eq!(Run0::new().classify(None, "", &forced()), RootOutcome::Ran { exit: None });
    }

    #[test]
    fn every_denial_wording_is_recognised_whatever_the_case() {
        for stderr in [
            "Failed to start transient service unit: Access denied",
            "Interactive authentication required.",
            "Authentication failed.",
            "Request to manage units was not authorized",
            "ACCESS DENIED",
        ] {
            assert_eq!(
                Run0::new().classify(Some(1), stderr, &forced()),
                RootOutcome::Denied,
                "{stderr}"
            );
        }
    }

    #[test]
    fn a_bus_failure_is_an_elevation_failure_and_not_the_commands() {
        let outcome =
            Run0::new().classify(Some(1), "Failed to connect to bus: No such file\n", &forced());
        let RootOutcome::Failed { message } = &outcome else { panic!("got {outcome:?}") };
        assert!(message.contains("nothing ran"), "{message}");
        assert!(message.contains("Failed to connect to bus"), "{message}");
        assert!(outcome.elevation_failure().is_some());
    }

    // ---- the forced locale, and what happens without it --------------------

    #[test]
    fn locale_is_forced_for_run0_and_not_for_the_command() {
        // The whole point of there being two environments. `run0` must speak a
        // language hatch can read; the command must not be moved into it,
        // because a root command that sorts and formats differently than the
        // same command run unprivileged is one more difference between the two
        // paths that nobody told the reader about.
        let (_dir, env) = with_run0();
        let run0 = Run0::new();
        let spawner = run0.spawner_env(&env);
        let child = run0.child_env(&env);

        assert_eq!(spawner.get("LC_ALL").map(String::as_str), Some("C"));
        assert_eq!(spawner.get("LANGUAGE").map(String::as_str), Some(""));
        for (key, _) in FORCED_LOCALE {
            assert!(!child.contains_key(key), "{key} leaked into the command's environment");
        }
        let argv = run0.argv("true", &env).unwrap();
        for (key, _) in FORCED_LOCALE {
            assert!(
                !argv.as_slice().iter().any(|a| a.starts_with(&format!("--setenv={key}="))),
                "{key} is on the line that sets the command's environment: {:?}",
                argv.as_slice()
            );
        }
    }

    #[test]
    fn language_is_emptied_as_well_as_lc_all() {
        // glibc lets `LANGUAGE` override `LC_ALL` for message translation, so
        // setting `LC_ALL=C` alone leaves a user with `LANGUAGE=de` reading
        // German diagnostics -- and hatch reading none of them.
        let mut session = Env::new();
        session.insert("LANGUAGE".to_string(), "de:en".to_string());
        session.insert("LC_ALL".to_string(), "de_DE.UTF-8".to_string());

        let spawner = Run0::new().spawner_env(&session);
        assert_eq!(spawner.get("LANGUAGE").map(String::as_str), Some(""));
        assert_eq!(spawner.get("LC_ALL").map(String::as_str), Some("C"));
        assert!(locale_is_forced(&spawner));
    }

    #[test]
    fn a_configured_locale_still_reaches_the_command() {
        // The forcing is about run0's diagnostics, not about the command's
        // output. A user who sets a locale in `exec_env` gets it.
        let mut env = Env::new();
        env.insert("LC_ALL".to_string(), "de_DE.UTF-8".to_string());
        assert_eq!(
            Run0::new().child_env(&env).get("LC_ALL").map(String::as_str),
            Some("de_DE.UTF-8")
        );
    }

    #[test]
    fn without_the_forced_locale_an_unreadable_failure_is_unclear_not_a_failed_command() {
        // Rule 3, and the reason `spawner_env` is load-bearing rather than
        // advisory. Reporting `Ran { exit: 1 }` here would be the confident
        // wrong answer: in an unforced locale the refusal message is
        // translated, hatch cannot see it, and "your command failed" hides
        // that nothing ran.
        let german = "Fehlgeschlagen: Zugriff verweigert";
        let outcome = Run0::new().classify(Some(1), german, &Env::new());
        let RootOutcome::Unclear { exit, message } = &outcome else { panic!("got {outcome:?}") };
        assert_eq!(*exit, Some(1));
        assert!(message.contains("cannot tell"), "{message}");
        assert_eq!(outcome.elevation_failure(), None, "it is not a claim that nothing ran either");
    }

    #[test]
    fn half_a_forced_locale_is_not_a_forced_locale() {
        let mut half = Env::new();
        half.insert("LC_ALL".to_string(), "C".to_string());
        assert!(!locale_is_forced(&half), "LANGUAGE still overrides it");
        assert!(matches!(
            Run0::new().classify(Some(1), "something", &half),
            RootOutcome::Unclear { .. }
        ));
    }

    #[test]
    fn a_recognised_refusal_is_believed_whatever_the_locale() {
        // Uncertainty about the language does not make a legible message
        // illegible: an English refusal read out of an unforced session is
        // still a refusal.
        assert_eq!(
            Run0::new().classify(Some(1), "Access denied", &Env::new()),
            RootOutcome::Denied
        );
    }

    #[test]
    fn an_unforced_locale_does_not_make_a_successful_run_uncertain() {
        assert_eq!(
            Run0::new().classify(Some(0), "", &Env::new()),
            RootOutcome::Ran { exit: Some(0) }
        );
    }

    // ---- availability ------------------------------------------------------

    #[test]
    fn run0_is_looked_for_on_the_childs_path() {
        let (_dir, env) = with_run0();
        assert!(Run0::new().available(&env).is_ok());
    }

    #[test]
    fn a_path_without_run0_refuses_and_names_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = Env::new();
        env.insert("PATH".to_string(), dir.path().display().to_string());

        let err = Run0::new().available(&env).expect_err("nothing named run0 is there");
        assert!(err.message.contains("run0"), "{err}");
        assert!(err.message.contains("nothing was run"), "{err}");
        assert!(Run0::new().argv("true", &env).is_err(), "and no argv comes out of it either");
    }

    #[test]
    fn a_file_named_run0_that_cannot_be_executed_is_not_run0() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("run0");
        std::fs::write(&bin, "not a program").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o644)).unwrap();

        let mut env = Env::new();
        env.insert("PATH".to_string(), dir.path().display().to_string());
        assert!(Run0::new().available(&env).is_err());
    }

    #[test]
    fn an_empty_path_entry_is_not_the_working_directory() {
        // A shell would read the empty entry as `.`. Doing the same here would
        // let whatever directory a request runs in supply the elevation
        // program.
        let (dir, _env) = with_run0();
        let mut env = Env::new();
        env.insert("PATH".to_string(), "::".to_string());
        assert!(Run0::new().available(&env).is_err());
        // ...and the directory really did hold one, so this is about the empty
        // entries and not about an empty directory.
        env.insert("PATH".to_string(), dir.path().display().to_string());
        assert!(Run0::new().available(&env).is_ok());
    }

    #[test]
    fn a_path_that_is_not_there_at_all_refuses() {
        let err = Run0::new().available(&Env::new()).expect_err("no PATH, no lookup");
        assert!(err.message.contains("unset"), "{err}");
    }

    // ---- the environment an elevated command gets --------------------------

    #[test]
    fn the_pager_is_defeated_in_an_elevated_child() {
        // Without this a `systemctl status` under a terminal waits on a pager
        // for the whole execution timeout and shows the reader nothing.
        let child = Run0::new().child_env(&Env::new());
        assert_eq!(child.get("PAGER").map(String::as_str), Some("cat"));
        assert_eq!(child.get("SYSTEMD_PAGER").map(String::as_str), Some(""));
    }

    #[test]
    fn the_configured_environment_wins_over_hatchs_defaults() {
        // Same precedence as `exec_env` over `exec_path`: a user who spells a
        // variable out in the config means it.
        let mut env = Env::new();
        env.insert("PAGER".to_string(), "less".to_string());
        assert_eq!(Run0::new().child_env(&env).get("PAGER").map(String::as_str), Some("less"));
    }

    #[test]
    fn nothing_beyond_the_pager_keys_is_added() {
        // The count is the point, as it is in `build_child_env`: an
        // implementation that helpfully added `TERM` or `SUDO_USER` would pass
        // every other test here while the window drew an environment nobody
        // configured.
        let mut env = Env::new();
        env.insert("HOME".to_string(), "/home/someone".to_string());
        assert_eq!(
            Run0::new().child_env(&env).keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["HOME", "PAGER", "SYSTEMD_PAGER"]
        );
    }

    #[test]
    fn the_window_is_told_that_a_root_command_may_get_a_terminal() {
        let caveat = Run0::new().caveat().expect("the two paths differ, so the window says so");
        assert!(caveat.contains("terminal"), "{caveat}");
        assert!(caveat.contains("PAGER"), "{caveat}");
    }

    // ---- refusing, everywhere else -----------------------------------------

    #[test]
    fn an_unsupported_platform_refuses_instead_of_running_unprivileged() {
        // The mutation this file exists to make impossible: a platform with no
        // elevation returning the plain argv. The command would run as the
        // user, do something other than what was approved, and report success.
        let (_dir, env) = with_run0();
        let mac = NoElevation::for_os("macos");

        let err = mac.argv("systemctl status zram0", &env).expect_err("nothing to elevate with");
        assert!(err.message.contains("macos"), "{err}");
        assert!(err.message.contains("run0"), "{err}");
        assert!(err.message.contains("nothing was run"), "{err}");
        assert!(mac.available(&env).is_err(), "and it does not claim to be available");
    }

    #[test]
    fn a_refusing_platform_reports_no_exit_status() {
        // Even reached out of order, it cannot put a number in the log under a
        // root request it never honoured.
        let outcome = NoElevation::for_os("macos").classify(Some(0), "", &forced());
        assert!(
            matches!(outcome, RootOutcome::Failed { .. }),
            "a platform that cannot elevate has no exit status to report, got {outcome:?}"
        );
        assert!(outcome.elevation_failure().is_some());
    }

    #[test]
    fn a_refusing_platform_has_nothing_to_caveat() {
        assert_eq!(NoElevation::for_os("macos").caveat(), None);
    }

    #[test]
    fn no_implementation_can_return_an_argv_that_does_not_elevate() {
        // Across every implementation there is: if an argv comes back at all,
        // the elevation program is in front of it. This is the property
        // `ElevatedArgv` exists to make structural, checked here so a third
        // implementation added later inherits the check.
        let (_dir, env) = with_run0();
        let all: Vec<Box<dyn Elevation>> =
            vec![Box::new(Run0::new()), Box::new(NoElevation::for_os("macos"))];
        for elevation in all {
            if let Ok(argv) = elevation.argv("true", &env) {
                assert_eq!(argv.program(), elevation.mechanism());
                assert_ne!(argv.as_slice(), shell_argv("true"), "that is the unelevated argv");
                assert!(argv.as_slice().len() > 3);
            }
        }
    }

    #[test]
    fn the_platform_this_build_runs_on_is_the_one_it_selects() {
        let (_dir, env) = with_run0();
        let platform = platform();
        if cfg!(target_os = "linux") {
            assert_eq!(platform.mechanism(), "run0");
            assert!(platform.argv("true", &env).is_ok());
        } else {
            assert_eq!(platform.mechanism(), "none");
            assert!(platform.argv("true", &env).is_err());
        }
    }
}
