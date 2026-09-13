//! Finding a program on the `PATH` a child will be given.
//!
//! One lookup, shared. [`crate::exec::elevate`] asks it whether this machine
//! has an elevation program on it, and [`crate::render::roster`] asks it where
//! each name in a command will be found — and the two have to agree, because
//! the window that says `run0` is at `/usr/bin/run0` is the same window that
//! is about to spawn it. A second implementation is how the two come to
//! answer differently about the same name on the same machine, which is the
//! argument [`crate::render::command::Scan`](crate::render::command) makes at
//! length one layer up.
//!
//! # Against which `PATH`
//!
//! The child's, never the daemon's. [`crate::exec::env::build_child_env`]
//! constructs the environment an approved command receives, and the `PATH` in
//! it is the only one either caller may resolve against: hatch's own came
//! from wherever the daemon was started, and a window that named a binary out
//! of *that* would be naming a file the command will never reach. So `env` is
//! a parameter here and there is no default, for the reason there is none in
//! [`crate::render::command::annotate_variables`](crate::render::command).
//!
//! # What a lookup is worth
//!
//! It is a fact about this instant and not a promise about the next one.
//! Nothing here holds a file open, takes a lock or records an inode: the
//! answer is what `stat` said, and the binary can be replaced between the
//! answer and the `execve`. [`crate::swap`] has the same gap about a file's
//! hash and closes it by re-checking before it applies; this one cannot be
//! closed the same way, because the lookup that decides what runs is done by
//! the shell at exec time and hatch is not in that path. So every caller that
//! shows a result to a person has to say *when* it was true — see
//! [`crate::render::roster`], which does.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use super::Env;

/// Find `program` on the `PATH` in `env`.
///
/// Empty entries are skipped rather than read as `.`, which is what a shell
/// would do with them: resolving a program out of whatever directory a
/// request happens to name is the one lookup nobody wants relative.
///
/// The first executable match wins, exactly as the shell's own search does,
/// so the answer is the file that would actually run and not merely a file of
/// that name somewhere on the list.
pub fn lookup(program: &str, env: &Env) -> Option<PathBuf> {
    env.get("PATH")?
        .split(':')
        .filter(|dir| !dir.is_empty())
        .map(|dir| Path::new(dir).join(program))
        .find(|candidate| is_executable(candidate))
}

/// A file that could be executed: a regular file with an execute bit set.
pub fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|md| md.is_file() && md.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Whether somebody other than the owner may write `path`: the group-write or
/// other-write bit is set.
///
/// A mode bit and nothing more. This deliberately does not work out whether
/// *the user hatch will run as* can write there — that would mean resolving
/// group membership, ownership and, for a `root: true` request, the fact that
/// root can write anywhere, and the answer would then differ between the
/// window and the run. The mode is one bit, it is the same bit for every
/// reader, and it is what a person checking this by hand would look at.
///
/// It is a fact, and stating it is all this does. Whether a particular
/// writable location should alarm a reader is a verdict, and verdicts belong
/// to [`crate::render::danger`] — see the note there.
///
/// A path that cannot be stat'ed is reported as not writable rather than as
/// writable: the caller only ever asks about a file it has already found, so
/// a failure here is a race with something removing it, and inventing an
/// alarm out of a race is how a list comes to cry wolf.
pub fn anyone_can_write(path: &Path) -> bool {
    std::fs::metadata(path).map(|md| md.permissions().mode() & 0o022 != 0).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// A directory with `program` in it, at `mode`.
    fn planted(dir: &Path, program: &str, mode: u32) -> PathBuf {
        let path = dir.join(program);
        fs::write(&path, "#!/bin/sh\n").expect("writes");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmods");
        path
    }

    fn path_env(dirs: &[&Path]) -> Env {
        let joined =
            dirs.iter().map(|d| d.display().to_string()).collect::<Vec<_>>().join(":");
        Env::from([("PATH".to_string(), joined)])
    }

    #[test]
    fn the_first_executable_match_on_the_path_is_the_one_that_would_run() {
        let first = tempfile::tempdir().expect("a directory");
        let second = tempfile::tempdir().expect("a directory");
        let wanted = planted(first.path(), "tool", 0o755);
        planted(second.path(), "tool", 0o755);

        let env = path_env(&[first.path(), second.path()]);
        assert_eq!(lookup("tool", &env), Some(wanted));
    }

    #[test]
    fn a_file_with_no_execute_bit_is_not_what_the_shell_would_find() {
        // The shell walks past it and keeps looking, so this has to as well:
        // a window that named the unexecutable one would name a file that
        // cannot run.
        let first = tempfile::tempdir().expect("a directory");
        let second = tempfile::tempdir().expect("a directory");
        planted(first.path(), "tool", 0o644);
        let wanted = planted(second.path(), "tool", 0o755);

        let env = path_env(&[first.path(), second.path()]);
        assert_eq!(lookup("tool", &env), Some(wanted));
    }

    #[test]
    fn a_directory_is_not_a_program_however_its_bits_are_set() {
        let dir = tempfile::tempdir().expect("a directory");
        fs::create_dir(dir.path().join("tool")).expect("makes a directory");
        assert!(!is_executable(&dir.path().join("tool")));
        assert_eq!(lookup("tool", &path_env(&[dir.path()])), None);
    }

    #[test]
    fn an_empty_path_entry_is_skipped_rather_than_read_as_the_current_directory() {
        // The one lookup nobody wants relative. `::` and a trailing `:` are
        // both the shell's spelling of "the current directory", and hatch
        // declines to honour it.
        let dir = tempfile::tempdir().expect("a directory");
        let wanted = planted(dir.path(), "tool", 0o755);
        let env = Env::from([("PATH".to_string(), format!("::{}:", dir.path().display()))]);
        assert_eq!(lookup("tool", &env), Some(wanted));
    }

    #[test]
    fn an_environment_with_no_path_resolves_nothing() {
        assert_eq!(lookup("tool", &Env::new()), None);
    }

    #[test]
    fn writability_is_the_group_and_other_bits_and_not_a_question_about_the_reader() {
        let dir = tempfile::tempdir().expect("a directory");
        let tight = planted(dir.path(), "tight", 0o755);
        let group = planted(dir.path(), "group", 0o775);
        let world = planted(dir.path(), "world", 0o757);

        assert!(!anyone_can_write(&tight));
        assert!(anyone_can_write(&group), "group-writable is somebody other than the owner");
        assert!(anyone_can_write(&world));
    }

    #[test]
    fn a_path_that_is_not_there_is_not_reported_as_writable() {
        // A race with something removing the file, not an alarm. See the
        // function's own note: a list that invents one is a list nobody
        // reads.
        let dir = tempfile::tempdir().expect("a directory");
        assert!(!anyone_can_write(&dir.path().join("never-existed")));
    }
}
