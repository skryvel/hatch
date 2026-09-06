//! Self-protection path matching: the targets `swap_file` refuses before it
//! ever draws a prompt.
//!
//! # What this defends, and what it does not
//!
//! `run_command` can reach every path on this list. A command that rewrites
//! `~/.hatch/config.toml` appears in the approval window like any other
//! command, and a human who reads it and approves it gets exactly what it
//! says. So the denylist is **not a containment boundary**, and nothing here
//! should be read as one.
//!
//! What it closes is narrower, and worth closing anyway: the *file* route.
//! `swap_file` replaces a file wholesale behind a diff, and a diff is read by
//! skimming. Burying a changed token, a new firejail exception or an added
//! MCP server in forty otherwise plausible lines is a far easier sell than
//! typing the command that does the same thing, because the command has to
//! survive being read as a command. Refusing these targets outright — before
//! a prompt exists — means there is nothing to skim past.
//!
//! Claiming more than that would be the same failure as a display that
//! overstates what it shows.
//!
//! # Precondition: an absolute path that is already resolved
//!
//! [`Denylist::is_denied`] judges a path *lexically*. It never touches the
//! filesystem, so it cannot see through a symlink: if `~/link` points at
//! `~/.hatch/config.toml` the two name one file, and only the second spelling
//! is denied here. Resolution belongs to the caller, and [`crate::swap`]
//! answers it by refusing a symlinked target outright, which is a stronger
//! answer than following one would be.
//!
//! The precondition is therefore: **`path` is absolute and already resolved.**
//! A caller who does not know that will hand over a path this module cannot
//! judge, so anything failing the precondition is denied rather than allowed:
//!
//! * A relative path is denied. It means whatever the working directory says
//!   it means, and a denylist that guesses at that would be worse than one
//!   that refuses.
//! * A `..` component is denied, not resolved. Resolving it lexically is
//!   wrong in exactly the case that matters — with a symlink anywhere in the
//!   path, `a/b/..` is not `a` — so `/home/user/.hatch/../.hatch/config.toml`
//!   is refused rather than judged.
//! * A `.` component is dropped, because it is a no-op whatever the path
//!   points at. `Path::components` does this, and repeated separators, for
//!   free: `/etc/./hosts` and `/etc//hosts` both judge as `/etc/hosts`.
//!
//! Failing closed is a backstop, not a message. The refusal it produces would
//! read "this target is protected", which for a relative path is untrue, so
//! the caller must reject a non-absolute target itself with its own wording
//! rather than leaning on this.
//!
//! # Matching compares components, never characters
//!
//! `~/.hatchet/notes` is not inside `~/.hatch`, though one string is a prefix
//! of the other. Every comparison here goes through [`Path::starts_with`],
//! which matches whole components and so cannot make that mistake.
//!
//! Components compare as bytes: no case folding, no Unicode normalisation.
//! Linux paths are byte strings, and that is the right default. On a
//! case-insensitive or normalising filesystem two spellings can name one file
//! while only one of them is denied here — a real gap, but engineering
//! against it would buy little given the first section.
//!
//! # Where "home" comes from
//!
//! The `~/.claude*` and `~/.config/firejail` entries need the user's home
//! directory, and it is taken as the **parent of `hatch_dir`** rather than
//! from `$HOME` or [`dirs::home_dir`]. Two reasons: the constructor stays a
//! pure function of its arguments, so a test can pass `/home/user/.hatch` and
//! get the whole set without a real home directory to point at; and the two
//! halves cannot drift apart at runtime, because the state directory *is*
//! `~/.hatch` ([`crate::config::default_dir`]).
//!
//! The coupling that buys is worth stating: move the state directory
//! somewhere other than the home directory and the home-derived entries
//! follow it to the wrong place. If that day comes, home becomes a second
//! parameter. A `hatch_dir` with no parent at all — `/` — drops those entries
//! rather than guessing at a replacement.

use std::path::{Component, Path, PathBuf};

/// The paths `swap_file` will not write, whatever a human answers.
///
/// Cheap to build and self-contained, so a caller may keep one for the process
/// or rebuild it per request from the live config — the latter being what makes
/// an added `denylist_extra` entry take effect without a restart. Order within
/// the list carries no meaning: a path is denied if it is under *any* root.
#[derive(Debug, Clone)]
pub struct Denylist {
    /// Protected roots, each a directory whose subtree is denied or a single
    /// denied file. Owned rather than borrowed because most entries are
    /// constructed here — joined onto the home directory, or parsed out of the
    /// config — and so exist nowhere for a borrow to point at.
    roots: Vec<PathBuf>,
}

impl Denylist {
    /// Build the protected set: `hatch_dir` and its subtree, the sandbox
    /// profiles and MCP client configuration under its parent, `/etc/firejail`,
    /// this binary, and every entry of `extra`.
    ///
    /// `extra` comes from `Config::denylist_extra` and is taken literally:
    /// each entry is a path prefix, not a glob, and no `~` expansion happens.
    /// An entry that is not absolute can never match a judgeable path, so it
    /// protects nothing — silently, since there is no channel to complain on
    /// from here.
    pub fn new(hatch_dir: &Path, extra: &[String]) -> Self {
        Self::with_exe(hatch_dir, extra, std::env::current_exe().ok())
    }

    /// The whole of [`Denylist::new`] except for asking the OS where this
    /// binary lives, so a test can pin that answer either way.
    ///
    /// `exe` is `None` when the path cannot be determined. That entry is then
    /// dropped and the rest of the list still stands. Refusing to build a
    /// denylist at all would be the worse trade: `current_exe` is fallible by
    /// design and, on Linux, reads `/proc/self/exe`, which is already resolved
    /// and can be stale after the binary is replaced or deleted. Losing one
    /// entry of a list that was never a containment boundary beats losing all
    /// of them.
    fn with_exe(hatch_dir: &Path, extra: &[String], exe: Option<PathBuf>) -> Self {
        let mut roots = vec![hatch_dir.to_path_buf(), PathBuf::from("/etc/firejail")];

        if let Some(home) = hatch_dir.parent() {
            roots.push(home.join(".config/firejail"));
            roots.push(home.join(".claude.json"));
            roots.push(home.join(".claude"));
        }
        if let Some(exe) = exe {
            roots.push(exe);
        }
        roots.extend(extra.iter().map(PathBuf::from));

        Self { roots }
    }

    /// Is `path` protected, or too ambiguous to judge?
    ///
    /// True means `swap_file` must refuse without prompting. The two reasons
    /// are deliberately collapsed into one answer — see the module docs on the
    /// precondition — so a caller that wants to tell a user *why* has to check
    /// absoluteness itself first.
    pub fn is_denied(&self, path: &Path) -> bool {
        if !is_judgeable(path) {
            return true;
        }
        self.roots.iter().any(|root| path.starts_with(root))
    }
}

/// Can this path be compared against the protected roots at all?
///
/// Only if it is anchored at the root and contains no `..` to climb with. A
/// path failing either test has no single meaning to judge, and the caller
/// treats that as a denial.
fn is_judgeable(path: &Path) -> bool {
    path.has_root() && !path.components().any(|c| c == Component::ParentDir)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every path below is spelled out in full rather than derived from the
    // list under test. A test that reads the table it checks can only catch
    // the table disagreeing with itself, never an entry going missing — which
    // in a module this small is the whole risk.

    #[test]
    fn refuses_hatch_own_state() {
        let d = Denylist::new(Path::new("/home/user/.hatch"), &[]);
        assert!(d.is_denied(Path::new("/home/user/.hatch/config.toml")));
        assert!(d.is_denied(Path::new("/home/user/.hatch/log/hatch-2026-09.jsonl")));
    }

    #[test]
    fn refuses_client_and_sandbox_config() {
        let d = Denylist::new(Path::new("/home/user/.hatch"), &[]);
        assert!(d.is_denied(Path::new("/home/user/.claude.json")));
        assert!(d.is_denied(Path::new("/home/user/.claude/settings.json")));
        assert!(d.is_denied(Path::new("/home/user/.config/firejail/x.profile")));
        assert!(d.is_denied(Path::new("/etc/firejail/x.profile")));
    }

    #[test]
    fn honours_denylist_extra() {
        let d = Denylist::new(Path::new("/home/user/.hatch"), &["/srv/sacred".into()]);
        assert!(d.is_denied(Path::new("/srv/sacred/file")));
    }

    #[test]
    fn allows_ordinary_targets() {
        let d = Denylist::new(Path::new("/home/user/.hatch"), &[]);
        assert!(!d.is_denied(Path::new("/etc/hosts")));
    }

    #[test]
    fn prefix_match_respects_path_components() {
        let d = Denylist::new(Path::new("/home/user/.hatch"), &[]);
        assert!(!d.is_denied(Path::new("/home/user/.hatchet/notes")));
    }

    #[test]
    fn refuses_every_protected_root_itself_not_only_its_children() {
        let d = Denylist::new(Path::new("/home/user/.hatch"), &[]);
        assert!(d.is_denied(Path::new("/home/user/.hatch")));
        assert!(d.is_denied(Path::new("/home/user/.claude.json")));
        assert!(d.is_denied(Path::new("/home/user/.claude")));
        assert!(d.is_denied(Path::new("/home/user/.config/firejail")));
        assert!(d.is_denied(Path::new("/etc/firejail")));
    }

    #[test]
    fn refuses_deep_children_of_every_protected_root() {
        let d = Denylist::new(Path::new("/home/user/.hatch"), &[]);
        assert!(d.is_denied(Path::new("/home/user/.hatch/stage/pending/x")));
        assert!(d.is_denied(Path::new("/home/user/.claude/plugins/p/settings.json")));
        assert!(d.is_denied(Path::new("/home/user/.config/firejail/nested/x.profile")));
        assert!(d.is_denied(Path::new("/etc/firejail/nested/x.profile")));
    }

    #[test]
    fn allows_the_neighbours_of_every_protected_root() {
        let d = Denylist::new(Path::new("/home/user/.hatch"), &[]);
        assert!(!d.is_denied(Path::new("/home/user/.hatchet/notes")));
        assert!(!d.is_denied(Path::new("/home/user/.claude.json.bak")));
        assert!(!d.is_denied(Path::new("/home/user/.claudex/settings.json")));
        assert!(!d.is_denied(Path::new("/home/user/.config/firejail-old/x.profile")));
        assert!(!d.is_denied(Path::new("/etc/firejail-old/x.profile")));
    }

    #[test]
    fn an_ancestor_of_a_protected_root_is_not_itself_protected() {
        // The prefix test runs one way only. `~/.config` holds far more than
        // firejail profiles, and denying it would refuse ordinary edits.
        let d = Denylist::new(Path::new("/home/user/.hatch"), &[]);
        assert!(!d.is_denied(Path::new("/home/user/.config/nvim/init.lua")));
        assert!(!d.is_denied(Path::new("/home/user/.config")));
        assert!(!d.is_denied(Path::new("/home/user")));
        assert!(!d.is_denied(Path::new("/home")));
        assert!(!d.is_denied(Path::new("/etc")));
        assert!(!d.is_denied(Path::new("/")));
    }

    #[test]
    fn home_comes_from_the_hatch_directory_not_from_the_environment() {
        let d = Denylist::new(Path::new("/srv/elsewhere/.hatch"), &[]);
        assert!(d.is_denied(Path::new("/srv/elsewhere/.claude.json")));
        assert!(d.is_denied(Path::new("/srv/elsewhere/.claude/settings.json")));
        assert!(d.is_denied(Path::new("/srv/elsewhere/.config/firejail/x.profile")));
        // The real home directory is not consulted, so its files are ordinary
        // targets when the state directory lives somewhere else.
        assert!(!d.is_denied(Path::new("/home/user/.claude.json")));
    }

    #[test]
    fn refuses_the_hatch_binary_itself() {
        let d = Denylist::with_exe(
            Path::new("/home/user/.hatch"),
            &[],
            Some(PathBuf::from("/usr/local/bin/hatch")),
        );
        assert!(d.is_denied(Path::new("/usr/local/bin/hatch")));
        assert!(!d.is_denied(Path::new("/usr/local/bin/hatchet")));
    }

    #[test]
    fn the_running_binary_is_protected_without_being_told_where_it_is() {
        // `with_exe` above pins what the entry does; this pins that the public
        // constructor goes and finds it. The expectation comes from the same
        // question the caller would ask — where am I running from — and not
        // from the list under test.
        let exe = std::env::current_exe().unwrap();
        let d = Denylist::new(Path::new("/home/user/.hatch"), &[]);
        assert!(d.is_denied(&exe));
    }

    #[test]
    fn an_unknown_binary_path_drops_only_that_entry() {
        let d = Denylist::with_exe(Path::new("/home/user/.hatch"), &[], None);
        assert!(!d.is_denied(Path::new("/usr/local/bin/hatch")));
        assert!(d.is_denied(Path::new("/home/user/.hatch/config.toml")));
        assert!(d.is_denied(Path::new("/home/user/.claude.json")));
        assert!(d.is_denied(Path::new("/etc/firejail/x.profile")));
    }

    #[test]
    fn an_extra_entry_matches_by_component_like_the_built_in_ones() {
        let d = Denylist::new(Path::new("/home/user/.hatch"), &["/srv/sacred".into()]);
        assert!(d.is_denied(Path::new("/srv/sacred")));
        assert!(d.is_denied(Path::new("/srv/sacred/deep/file")));
        assert!(!d.is_denied(Path::new("/srv/sacredx/file")));
        assert!(!d.is_denied(Path::new("/srv")));
    }

    #[test]
    fn every_extra_entry_is_honoured_not_just_the_first() {
        let d = Denylist::new(
            Path::new("/home/user/.hatch"),
            &["/srv/a".into(), "/srv/b".into(), "/srv/c".into()],
        );
        assert!(d.is_denied(Path::new("/srv/a/file")));
        assert!(d.is_denied(Path::new("/srv/b/file")));
        assert!(d.is_denied(Path::new("/srv/c/file")));
        assert!(!d.is_denied(Path::new("/srv/d/file")));
    }

    #[test]
    fn an_extra_entry_that_is_not_absolute_protects_nothing() {
        // Documented, not desired: a relative entry has no anchor to compare
        // against, so it silently covers nothing. The sharp edge belongs in
        // the config documentation, not in a guess made here.
        let d = Denylist::new(Path::new("/home/user/.hatch"), &["srv/sacred".into()]);
        assert!(!d.is_denied(Path::new("/srv/sacred/file")));
    }

    #[test]
    fn a_filename_that_is_not_utf8_is_judged_by_its_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let d = Denylist::new(Path::new("/home/user/.hatch"), &[]);
        let inside = Path::new(OsStr::from_bytes(b"/home/user/.hatch/\xff\xfe"));
        let outside = Path::new(OsStr::from_bytes(b"/home/user/.hatch\xff/config.toml"));
        assert!(d.is_denied(inside));
        // `.hatch\xff` is a different directory from `.hatch`, and would stop
        // being one if the comparison went through a lossy string conversion.
        assert!(!d.is_denied(outside));
    }

    #[test]
    fn a_relative_path_is_denied_because_it_cannot_be_judged() {
        let d = Denylist::new(Path::new("/home/user/.hatch"), &[]);
        assert!(d.is_denied(Path::new("etc/hosts")));
        assert!(d.is_denied(Path::new("./etc/hosts")));
        assert!(d.is_denied(Path::new("hosts")));
        assert!(d.is_denied(Path::new("")));
    }

    #[test]
    fn a_parent_component_is_denied_rather_than_resolved() {
        let d = Denylist::new(Path::new("/home/user/.hatch"), &[]);
        // Both of these name an ordinary file once resolved. Resolving them
        // here would be a lexical guess that a symlink can falsify, so the
        // answer is a refusal instead.
        assert!(d.is_denied(Path::new("/etc/../etc/hosts")));
        assert!(d.is_denied(Path::new("/home/user/.hatch/../.hatchet/notes")));
        assert!(d.is_denied(Path::new("/home/user/..")));
    }

    #[test]
    fn a_current_dir_component_and_repeated_separators_do_not_change_the_answer() {
        let d = Denylist::new(Path::new("/home/user/.hatch"), &[]);
        assert!(!d.is_denied(Path::new("/etc/./hosts")));
        assert!(!d.is_denied(Path::new("/etc//hosts")));
        assert!(d.is_denied(Path::new("/home/user/./.hatch/config.toml")));
        assert!(d.is_denied(Path::new("/home/user//.hatch//config.toml")));
        assert!(d.is_denied(Path::new("/home/user/.hatch/")));
    }
}
