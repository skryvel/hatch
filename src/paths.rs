//! Where hatch keeps its three directories.
//!
//! | what | variable | default |
//! |---|---|---|
//! | `config.toml` | `$XDG_CONFIG_HOME/hatch` | `~/.config/hatch` |
//! | `log/`, `prefs.toml` | `$XDG_STATE_HOME/hatch` | `~/.local/state/hatch` |
//! | `stage/` | `$XDG_RUNTIME_DIR/hatch` | the state directory |
//!
//! # Why `prefs.toml` is in the state directory and not beside the config
//!
//! Because of who writes it. `config.toml` is what the user wrote and hatch
//! reads; `prefs.toml` is what the window wrote down because the user ticked
//! something in it, which is what the spec means by state that persists
//! between restarts. Putting the two side by side would be two files of the
//! same shape in the same place, one of which silently loses hand edits. See
//! [`crate::prefs`].
//!
//! # Why the staging directory is the one worth placing carefully
//!
//! `stage/` holds file content a human has approved but that has not been
//! written yet. `log/` records what was asked for and `config.toml` holds the
//! bearer token, so all three are 0700 and none of them may be readable by
//! another local user — but the runtime directory buys `stage/` one thing the
//! other two cannot have. `$XDG_RUNTIME_DIR` is per-user, already 0700, and
//! **emptied when the user logs out**, so a run that dies between approval and
//! the write cannot leave approved bytes sitting readable after the session
//! that approved them has ended. It is usually tmpfs, which is fine: content
//! is capped at `output_cap_bytes` and the stage is swept at every startup.
//!
//! When the variable is unset the fallback is the state directory rather than
//! an invented path under `/run` or `/tmp`: a guessed runtime directory is one
//! nothing clears and nothing else owns, which is the worst of both.
//!
//! # A variable that is set but unusable
//!
//! `$XDG_RUNTIME_DIR` is created by the login stack, not by us, and a value
//! that names something else — a stale path, a directory belonging to another
//! user, a plain file — must not be written into. [`runtime_is_private`]
//! checks that it is a directory, that this process owns it, and that it is
//! exactly 0700, which is what the spec requires of it anyway.
//!
//! Failing the check **falls back to the state directory and says so**, rather
//! than refusing to start. The fallback is not weaker in permissions — it is
//! created and re-tightened to 0700 on every load, exactly like the runtime
//! directory would be — it is only weaker in lifetime, and the check itself is
//! what stops the genuinely dangerous case of staging into somebody else's
//! directory. Refusing instead would turn a misconfigured environment variable
//! into a daemon that will not start, and a user whose approval tool is down
//! does the privileged thing by hand, with no window and no audit record at
//! all. That is a worse outcome than a stage that survives logout.
//!
//! What the check cannot see is a read-only mount or an ACL, which pass the
//! ownership and mode test and then fail at the first write. That surfaces as
//! a startup error naming the directory, not as a silent fallback.
//!
//! # A relative path in one of the variables
//!
//! The spec is explicit: a relative path in any `XDG_*` variable is invalid
//! and must be ignored. It is ignored here too — the default is used — and a
//! note is printed, because a variable that is set and silently disregarded is
//! how a user ends up looking for their audit log in the wrong place.
//!
//! An empty value counts as unset, again per the spec.
//!
//! # Why this does not call [`dirs`]
//!
//! `dirs::config_dir` and friends answer the same question. They answer it by
//! reading the process environment, which a test cannot vary without mutating
//! shared global state — `unsafe` since Rust 2024, and unsound under a
//! multi-threaded test runner whatever the edition. [`Paths::resolve`] takes
//! the three values and the home directory as arguments, so every case below
//! is an ordinary pure-function test. [`dirs::home_dir`] is still used, once,
//! for the one input that has no `XDG_*` variable of its own.
//!
//! # No home directory, no daemon
//!
//! [`dirs::home_dir`] can fail. Two things need the answer: the defaults
//! above, and the denylist, which protects `~/.claude.json`, `~/.claude` and
//! `~/.config/firejail` and now takes home as an argument rather than deriving
//! it. A hatch started without a home could still serve — with `XDG_CONFIG_HOME`
//! and `XDG_STATE_HOME` set, every directory it needs is known — but its
//! denylist would quietly protect three fewer things than its documentation
//! claims. A self-protection list that is wrong in the safe-looking direction
//! is the failure this whole module exists to avoid, so [`Paths::from_env`]
//! fails instead, and says which variable to set.

use std::ffi::OsString;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use anyhow::Context;

/// The directory hatch takes inside each base directory.
const APP: &str = "hatch";

/// The base directory for `config.toml`.
const CONFIG_VAR: &str = "XDG_CONFIG_HOME";
/// The base directory for the audit log.
const STATE_VAR: &str = "XDG_STATE_HOME";
/// The base directory for approved-but-unwritten file content.
const RUNTIME_VAR: &str = "XDG_RUNTIME_DIR";

/// The three directories hatch uses, the home directory they and the denylist
/// are anchored on, and anything the user should be told about how they were
/// arrived at.
///
/// Resolved once at startup and passed down, rather than re-read per call: the
/// environment can change under a running process, and a daemon that wrote its
/// log to one place and swept a stage in another would be worse than one that
/// is merely out of date.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// Holds `config.toml`.
    config_dir: PathBuf,
    /// Holds `log/`.
    state_dir: PathBuf,
    /// Holds `stage/`. Equal to `state_dir` when there is no usable runtime
    /// directory.
    runtime_dir: PathBuf,
    /// The user's home directory, for the denylist and for the leftover
    /// `~/.hatch` check. Never derived from the directories above.
    home: PathBuf,
    /// Sentences to print at startup: an environment variable that could not
    /// be used, and why.
    notes: Vec<String>,
}

impl Paths {
    /// Resolve the directories from this process's environment.
    ///
    /// Fails only when there is no home directory to anchor on — see the
    /// module docs for why that is fatal rather than partial.
    pub fn from_env() -> anyhow::Result<Paths> {
        let home = dirs::home_dir().context(
            "no home directory. hatch needs one to find its configuration and to know which \
             files to protect from being rewritten; set HOME",
        )?;
        Ok(Paths::resolve(
            &home,
            std::env::var_os(CONFIG_VAR),
            std::env::var_os(STATE_VAR),
            std::env::var_os(RUNTIME_VAR),
            &runtime_is_private,
        ))
    }

    /// The whole of [`Paths::from_env`] except for reading the environment and
    /// looking at the disk, so every case is testable without either.
    ///
    /// `usable` is asked whether `$XDG_RUNTIME_DIR` may be staged into, and
    /// returns the reason it may not.
    fn resolve(
        home: &Path,
        config: Option<OsString>,
        state: Option<OsString>,
        runtime: Option<OsString>,
        usable: &dyn Fn(&Path) -> Result<(), String>,
    ) -> Paths {
        let mut notes = Vec::new();

        let config_dir =
            base(CONFIG_VAR, config, &mut notes).unwrap_or_else(|| home.join(".config")).join(APP);
        let state_dir = base(STATE_VAR, state, &mut notes)
            .unwrap_or_else(|| home.join(".local/state"))
            .join(APP);

        // Unset is the documented default and says nothing. Set but unusable
        // is a surprise, and lands in the same place with a note.
        let runtime_dir = match base(RUNTIME_VAR, runtime, &mut notes) {
            None => state_dir.clone(),
            Some(dir) => match usable(&dir) {
                Ok(()) => dir.join(APP),
                Err(why) => {
                    notes.push(format!(
                        "{RUNTIME_VAR} is {}, which {why}. Approved file content will be staged \
                         under the state directory instead, which is 0700 like the runtime one \
                         but is not emptied when you log out.",
                        dir.display()
                    ));
                    state_dir.clone()
                }
            },
        };

        Paths { config_dir, state_dir, runtime_dir, home: home.to_path_buf(), notes }
    }

    /// The directory holding `config.toml`.
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// The config file itself.
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// The audit log directory.
    pub fn log_dir(&self) -> PathBuf {
        self.state_dir.join("log")
    }

    /// The file the window writes its display preferences to.
    ///
    /// In the state directory rather than the config one — see the module
    /// docs — and at the top of it rather than inside `log/`, which is an
    /// append-only history and not a place anything is replaced.
    pub fn prefs_file(&self) -> PathBuf {
        self.state_dir.join("prefs.toml")
    }

    /// The directory approved file content is staged in.
    pub fn stage_dir(&self) -> PathBuf {
        self.runtime_dir.join("stage")
    }

    /// The user's home directory, as the denylist needs it.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Where hatch kept everything before it followed the XDG spec.
    ///
    /// Nothing reads it. It is named so that a leftover one can be reported
    /// and protected: until the user deletes it, it still holds the audit
    /// history of every operation they ever approved.
    pub fn legacy_dir(&self) -> PathBuf {
        self.home.join(".hatch")
    }

    /// Every directory the denylist must protect, deduplicated.
    ///
    /// Deduplicated because two of them are the same directory whenever the
    /// runtime fallback is taken, and a protected set that lists one root
    /// twice invites the reader to wonder which of the two is the real one.
    pub fn protected(&self) -> Vec<PathBuf> {
        let mut roots = vec![
            self.config_dir.clone(),
            self.state_dir.clone(),
            self.runtime_dir.clone(),
            self.legacy_dir(),
        ];
        roots.sort();
        roots.dedup();
        roots
    }

    /// What the user needs to be told about where things are, if anything.
    ///
    /// Empty in the ordinary case: a daemon that explains its own layout on
    /// every start is a daemon whose startup output stops being read.
    pub fn notices(&self) -> Vec<String> {
        let mut lines = self.notes.clone();

        // `symlink_metadata`, not `exists`: a dangling `~/.hatch` symlink is
        // still something the user left behind and still worth naming.
        let legacy = self.legacy_dir();
        if std::fs::symlink_metadata(&legacy).is_ok() {
            lines.push(format!(
                "{} is left over from an older hatch and is no longer read. Any token in it is \
                 dead: register your client with the line `hatch token` prints now, then remove \
                 the directory.",
                legacy.display()
            ));
        }

        if !lines.is_empty() {
            lines.push(format!(
                "config {}, audit log {}, staging {}",
                self.config_file().display(),
                self.log_dir().display(),
                self.stage_dir().display()
            ));
        }
        lines
    }

    /// Print [`Paths::notices`] on stderr.
    ///
    /// stderr, not stdout, because stdout carries the client registration line
    /// and that is something the user copies.
    pub fn report(&self) {
        for line in self.notices() {
            eprintln!("hatch: {line}");
        }
    }

    /// The three directories under one root, for tests: distinct, so a test
    /// cannot pass by writing into the wrong one.
    #[cfg(test)]
    pub fn scratch(root: &Path) -> Paths {
        Paths {
            config_dir: root.join("config"),
            state_dir: root.join("state"),
            runtime_dir: root.join("run"),
            home: root.join("home"),
            notes: Vec::new(),
        }
    }
}

/// The base directory `var` holds, or `None` when it is unset, empty or
/// relative — the three cases that all mean "use the default".
fn base(var: &str, value: Option<OsString>, notes: &mut Vec<String>) -> Option<PathBuf> {
    let path = PathBuf::from(value.filter(|v| !v.is_empty())?);
    if path.is_absolute() {
        return Some(path);
    }
    notes.push(format!(
        "{var} is {}, which is not an absolute path. The XDG spec calls that invalid, so it is \
         ignored and the default is used.",
        path.display()
    ));
    None
}

/// May approved file content be staged under `path`?
///
/// Yes only if it is a directory this process owns at exactly 0700 — which is
/// what `$XDG_RUNTIME_DIR` is specified to be, so a value failing this is a
/// value naming something that is not a runtime directory. The error is the
/// middle of a sentence beginning "XDG_RUNTIME_DIR is /some/path, which ".
fn runtime_is_private(path: &Path) -> Result<(), String> {
    // Follows symlinks deliberately: a link to a directory this user owns at
    // 0700 is as good as the directory, and it is the target's ownership and
    // mode that decide who can read what is staged there.
    let md = std::fs::metadata(path).map_err(|e| format!("cannot be read ({e})"))?;
    if !md.is_dir() {
        return Err("is not a directory".to_string());
    }
    let me = nix::unistd::geteuid().as_raw();
    if md.uid() != me {
        return Err(format!("belongs to uid {} rather than to you (uid {me})", md.uid()));
    }
    if md.mode() & 0o777 != 0o700 {
        return Err(format!("is mode {:04o} rather than the 0700 it must be", md.mode() & 0o777));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::denylist::Denylist;
    use std::os::unix::fs::PermissionsExt as _;

    /// A runtime directory check that always says yes, for the cases that are
    /// about resolution rather than about the check.
    fn always(_: &Path) -> Result<(), String> {
        Ok(())
    }

    /// A check that always refuses, with the wording a real refusal has.
    fn never(_: &Path) -> Result<(), String> {
        Err("is not a directory".to_string())
    }

    fn var(s: &str) -> Option<OsString> {
        Some(OsString::from(s))
    }

    /// Resolution with nothing set: the spec's defaults, spelled out in full
    /// rather than rebuilt from the code under test.
    fn defaults() -> Paths {
        Paths::resolve(Path::new("/home/user"), None, None, None, &always)
    }

    #[test]
    fn with_nothing_set_everything_falls_where_the_spec_says() {
        let p = defaults();
        assert_eq!(p.config_file(), Path::new("/home/user/.config/hatch/config.toml"));
        assert_eq!(p.log_dir(), Path::new("/home/user/.local/state/hatch/log"));
        assert_eq!(p.prefs_file(), Path::new("/home/user/.local/state/hatch/prefs.toml"));
        assert_eq!(p.home(), Path::new("/home/user"));
        assert!(p.notes.is_empty(), "the ordinary case says nothing: {:?}", p.notes);
    }

    #[test]
    fn with_no_runtime_directory_staging_falls_back_to_the_state_directory() {
        let p = defaults();
        assert_eq!(p.stage_dir(), Path::new("/home/user/.local/state/hatch/stage"));
        assert!(p.notes.is_empty(), "the documented default is not a warning: {:?}", p.notes);
    }

    #[test]
    fn each_variable_is_honoured_when_it_is_set() {
        let p = Paths::resolve(
            Path::new("/home/user"),
            var("/cfg"),
            var("/state"),
            var("/run/user/1000"),
            &always,
        );
        assert_eq!(p.config_file(), Path::new("/cfg/hatch/config.toml"));
        assert_eq!(p.log_dir(), Path::new("/state/hatch/log"));
        assert_eq!(p.stage_dir(), Path::new("/run/user/1000/hatch/stage"));
        assert!(p.notes.is_empty(), "{:?}", p.notes);
    }

    #[test]
    fn one_variable_being_set_does_not_move_the_others() {
        // Each of the three is read from its own variable. Sharing one base
        // between two of them would put the audit log inside the config
        // directory, or the stage inside the log's.
        let only_state = Paths::resolve(Path::new("/home/user"), None, var("/state"), None, &always);
        assert_eq!(only_state.config_file(), Path::new("/home/user/.config/hatch/config.toml"));
        assert_eq!(only_state.log_dir(), Path::new("/state/hatch/log"));

        let only_config = Paths::resolve(Path::new("/home/user"), var("/cfg"), None, None, &always);
        assert_eq!(only_config.config_file(), Path::new("/cfg/hatch/config.toml"));
        assert_eq!(only_config.log_dir(), Path::new("/home/user/.local/state/hatch/log"));
    }

    #[test]
    fn an_empty_variable_counts_as_unset() {
        let p = Paths::resolve(Path::new("/home/user"), var(""), var(""), var(""), &always);
        assert_eq!(p.config_file(), Path::new("/home/user/.config/hatch/config.toml"));
        assert_eq!(p.log_dir(), Path::new("/home/user/.local/state/hatch/log"));
        assert_eq!(p.stage_dir(), Path::new("/home/user/.local/state/hatch/stage"));
        assert!(p.notes.is_empty(), "the spec calls empty unset, not invalid: {:?}", p.notes);
    }

    #[test]
    fn a_relative_variable_is_ignored_and_said_out_loud() {
        let p = Paths::resolve(
            Path::new("/home/user"),
            var("cfg"),
            var("../state"),
            var("run"),
            &always,
        );
        assert_eq!(p.config_file(), Path::new("/home/user/.config/hatch/config.toml"));
        assert_eq!(p.log_dir(), Path::new("/home/user/.local/state/hatch/log"));
        assert_eq!(p.stage_dir(), Path::new("/home/user/.local/state/hatch/stage"));

        let said = p.notes.join("\n");
        for var in [CONFIG_VAR, STATE_VAR, RUNTIME_VAR] {
            assert!(said.contains(var), "{var} was ignored without a word: {said}");
        }
    }

    #[test]
    fn an_unusable_runtime_directory_falls_back_and_names_itself() {
        let p =
            Paths::resolve(Path::new("/home/user"), None, None, var("/run/user/1000"), &never);
        assert_eq!(
            p.stage_dir(),
            Path::new("/home/user/.local/state/hatch/stage"),
            "staging must not go into a directory that failed the check"
        );
        let said = p.notes.join("\n");
        assert!(said.contains(RUNTIME_VAR), "a silent fallback is the one thing not allowed");
        assert!(said.contains("/run/user/1000"), "{said}");
        assert!(said.contains("is not a directory"), "the reason must survive: {said}");
    }

    #[test]
    fn a_usable_runtime_directory_is_used_rather_than_the_fallback() {
        // The pair to the test above: the fallback must be reachable only
        // through a refusal, never taken with the variable set and fine.
        let p =
            Paths::resolve(Path::new("/home/user"), None, None, var("/run/user/1000"), &always);
        assert_eq!(p.stage_dir(), Path::new("/run/user/1000/hatch/stage"));
        assert_ne!(p.stage_dir(), p.log_dir().parent().unwrap().join("stage"));
    }

    // ---- the real runtime-directory check --------------------------------

    #[test]
    fn a_private_directory_of_ours_passes_the_check() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(runtime_is_private(dir.path()), Ok(()));
    }

    #[test]
    fn a_directory_others_can_reach_fails_the_check() {
        // The one that matters: staging approved file content somewhere group
        // or world readable would leak it before it is ever written.
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o755, 0o750, 0o707, 0o701] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            let why = runtime_is_private(dir.path())
                .expect_err("a directory others can reach must be refused");
            assert!(why.contains("0700"), "mode {mode:o}: {why}");
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn a_file_or_a_missing_path_fails_the_check() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-directory");
        std::fs::write(&file, b"").unwrap();
        assert!(runtime_is_private(&file).unwrap_err().contains("not a directory"));
        assert!(runtime_is_private(&dir.path().join("absent")).unwrap_err().contains("read"));
    }

    #[test]
    fn a_directory_belonging_to_someone_else_fails_the_check() {
        // Nothing in the test suite can chown, so this pins the comparison
        // rather than the syscall: /root exists on every Linux host, is not
        // ours, and is not something a test could be tricked into staging in.
        if nix::unistd::geteuid().is_root() {
            eprintln!("skipped: running as root, which owns everything");
            return;
        }
        let why = runtime_is_private(Path::new("/root"))
            .expect_err("/root is not this user's runtime directory");
        assert!(
            why.contains("uid") || why.contains("read"),
            "it must fail on ownership or on being unreadable, not silently pass: {why}"
        );
    }

    // ---- what the denylist is handed -------------------------------------

    #[test]
    fn every_directory_hatch_writes_to_is_handed_to_the_denylist() {
        // The list the daemon actually builds. A directory missing from here
        // is a directory `swap_file` would agree to rewrite.
        let p = Paths::resolve(
            Path::new("/home/user"),
            var("/cfg"),
            var("/state"),
            var("/run/user/1000"),
            &always,
        );
        let d = Denylist::new(&p.protected(), p.home(), &[]);

        assert!(d.is_denied(&p.config_file()), "the token must be protected");
        assert!(d.is_denied(&p.log_dir().join("hatch-2026-09.jsonl")), "so must the history");
        assert!(d.is_denied(&p.stage_dir().join("pending")), "so must approved bytes");
        assert!(d.is_denied(&p.prefs_file()), "and the file the window writes itself");
        assert!(d.is_denied(&p.legacy_dir().join("log/hatch-2026-01.jsonl")), "and the old one");
        // Home-derived entries come from `home`, which is none of the above.
        assert!(d.is_denied(Path::new("/home/user/.claude.json")));
        assert!(d.is_denied(Path::new("/home/user/.config/firejail/x.profile")));
    }

    #[test]
    fn the_runtime_fallback_still_leaves_all_three_protected() {
        let p = Paths::resolve(Path::new("/home/user"), None, None, None, &always);
        let d = Denylist::new(&p.protected(), p.home(), &[]);
        assert!(d.is_denied(&p.config_file()));
        assert!(d.is_denied(&p.log_dir()));
        assert!(d.is_denied(&p.stage_dir()));
        assert_eq!(
            p.protected().len(),
            3,
            "the state and runtime directories are one directory here: {:?}",
            p.protected()
        );
    }

    // ---- what the user is told -------------------------------------------

    #[test]
    fn a_layout_with_nothing_to_report_reports_nothing() {
        let home = tempfile::tempdir().unwrap();
        let p = Paths::resolve(home.path(), None, None, None, &always);
        assert!(p.notices().is_empty(), "{:?}", p.notices());
    }

    #[test]
    fn a_leftover_hatch_directory_is_named_along_with_where_things_went() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".hatch")).unwrap();
        let p = Paths::resolve(home.path(), None, None, None, &always);

        let said = p.notices().join("\n");
        assert!(said.contains(".hatch"), "the old directory must be named: {said}");
        assert!(said.contains("remove"), "and saying it can go is the point: {said}");
        assert!(said.contains("token"), "and that its token is dead: {said}");
        assert!(
            said.contains(&p.config_file().display().to_string()),
            "and where the config is now: {said}"
        );
        assert!(said.contains(&p.log_dir().display().to_string()), "{said}");
        assert!(said.contains(&p.stage_dir().display().to_string()), "{said}");
    }

    #[test]
    fn a_dangling_leftover_symlink_is_reported_too() {
        let home = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/nowhere-at-all", home.path().join(".hatch")).unwrap();
        let p = Paths::resolve(home.path(), None, None, None, &always);
        assert!(p.notices().join("\n").contains(".hatch"), "{:?}", p.notices());
    }

    #[test]
    fn a_warning_always_comes_with_the_paths_it_is_about() {
        // A user told that XDG_STATE_HOME was ignored still has to be told
        // where the log went, or the warning is a puzzle rather than an
        // answer.
        let home = tempfile::tempdir().unwrap();
        let p = Paths::resolve(home.path(), None, var("relative"), None, &always);
        let said = p.notices().join("\n");
        assert!(said.contains(STATE_VAR), "{said}");
        assert!(said.contains(&p.log_dir().display().to_string()), "{said}");
    }
}
