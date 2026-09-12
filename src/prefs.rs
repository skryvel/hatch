//! `prefs.toml`: the display choices the window itself writes down.
//!
//! # Why this is not in `config.toml`
//!
//! `config.toml` is settings a person writes and hatch reads. It carries
//! comments, the order the person put their keys in, and a bearer token, and
//! the only thing that has ever written it is [`crate::config::Config::load_or_create`]
//! — once, on a first run, to put a generated token where the user can find
//! it.
//!
//! `prefs.toml` is the other direction: state the window writes down because
//! somebody changed it in the UI. A checkbox that persists has to be written
//! every time it is clicked, and writing a preference into `config.toml`
//! would mean re-serializing a file a person hand-edits — which eventually
//! eats a comment or reorders their keys. Two files, two owners, and neither
//! one rewrites the other.
//!
//! That split is the whole point of this module and it is worth keeping even
//! when a preference looks like it would be at home in either file. The test
//! is not what the value *is*, it is **who last touched it**.
//!
//! # Why it lives in the state directory
//!
//! `$XDG_STATE_HOME/hatch/prefs.toml`, beside `log/` rather than beside
//! `config.toml`. The spec puts "state that should persist between restarts"
//! — it names view and layout settings in as many words — under the state
//! directory, and the placement says out loud what the paragraph above says:
//! the config directory holds what the user wrote, the state directory holds
//! what hatch wrote down. A `prefs.toml` sitting next to `config.toml` would
//! be two files with the same shape in the same place, one of which quietly
//! loses hand edits.
//!
//! The directory is created at 0700 by [`crate::config::Config::load_or_create`]
//! and is already on the denylist, so nothing here creates or protects
//! anything of its own.
//!
//! # Nothing here is allowed to fail
//!
//! The process that reads and writes this file is `hatch prompt`, which draws
//! a window and owns nothing. A missing, unreadable or malformed `prefs.toml`
//! is a window with the preference at its default, exactly as
//! [`crate::config::display_style`] treats a config it cannot parse — and
//! with more force, because the alternative here is a request that never
//! opens a window, which the daemon resolves as a denial. So every read
//! returns a value and every write returns nothing: there is no error type in
//! this module and no caller that could do anything with one.
//!
//! A malformed file is repaired by the next write rather than reported. It is
//! hatch's own file; there is nothing in it for a person to have meant.
//!
//! # Two windows writing at once
//!
//! The queue lets several windows be open together, so two of them saving a
//! preference in the same instant is an ordinary event and not a hypothetical.
//! It is made harmless the way [`crate::config`] makes the token write
//! harmless: the new file is built alongside the old one and renamed over it,
//! so a reader sees either the whole of the old file or the whole of the new
//! one and never a truncated one.
//!
//! What the rename does not do is merge. The later of two writes wins the
//! file, and today that costs nothing at all: there is one preference in it,
//! each window writes the value its own reader just clicked, and "the last
//! click wins" is the same answer two clicks in one window would get.
//!
//! **A second preference changes that**, and this is the note for whoever
//! adds one: window A saving its checkbox would then also write back its own
//! stale copy of B's, undoing a change B made a moment earlier. Re-reading
//! the file immediately before writing narrows that to the width of a rename
//! and does not close it. Closing it properly means a lock, and a lock means
//! a stale one can leave a window unable to save — which is why there is not
//! one here for a single boolean.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths::Paths;

/// The display choices a window remembers between requests.
///
/// Every field has a default and the struct carries `#[serde(default)]`, so a
/// file written by an older build keeps loading unchanged after a new
/// preference is added — and, just as importantly, a file written by a *newer*
/// build loads here without its unknown keys stopping anything.
///
/// What may go in here is narrow: a preference the window writes down because
/// a person ticked it, which changes what the window does with itself and
/// nothing about what runs. `stream` is deliberately absent — watching a
/// command is a choice about one command, and a standing "always stream"
/// would be a window that starts every request already committed to a view of
/// it. `terminal` is absent for a much harder reason: it decides what runs,
/// and a remembered one would be a standing grant nobody re-reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Whether the window should close as soon as a verdict is given, rather
    /// than staying to show the run and the result.
    ///
    /// See [`crate::prompt_ui::CLOSE_LABEL`] for what the control says and
    /// what ticking it gives up.
    pub close_on_decide: bool,
}

/// The file [`Prefs`] are kept in, and the only thing that writes it.
///
/// A type rather than a pair of free functions taking a path, because there
/// are three things a window can be doing with this file and the difference
/// between them is not a flag a caller should be passing about: a real prompt
/// reads and writes it, `hatch preview` reads it and must not write it — a
/// documentation tool that changed a user's settings would be a surprising
/// thing for a screenshot to do — and a test has no file at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefsFile {
    /// Where the preferences are. `None` when there is nowhere to keep them,
    /// which is a test and a process with no home directory.
    path: Option<PathBuf>,
    /// Whether a change may be written back. False for `hatch preview`.
    writable: bool,
}

impl PrefsFile {
    /// The real file under `paths`, read and written.
    pub fn at(paths: &Paths) -> PrefsFile {
        PrefsFile { path: Some(paths.prefs_file()), writable: true }
    }

    /// The real file for this process's environment.
    ///
    /// A process with no home directory gets [`PrefsFile::none`] rather than
    /// an error: it is the same answer as an unreadable file, and this module
    /// does not have a louder one.
    pub fn from_env() -> PrefsFile {
        match Paths::from_env() {
            Ok(paths) => PrefsFile::at(&paths),
            Err(_) => PrefsFile::none(),
        }
    }

    /// The real file, read but never written.
    ///
    /// What `hatch preview` gets. The window it draws is the window a request
    /// would get, preference included — that is what makes a preview evidence
    /// — but nothing a person clicks in a sample outlives it.
    pub fn read_only(paths: &Paths) -> PrefsFile {
        PrefsFile { path: Some(paths.prefs_file()), writable: false }
    }

    /// No file: defaults on every read, and a write that goes nowhere.
    pub fn none() -> PrefsFile {
        PrefsFile { path: None, writable: false }
    }

    /// The preferences as they are on disk, or the defaults.
    ///
    /// Infallible by construction. See the module docs: there is no caller of
    /// this that could do anything useful with a failure, and the one thing
    /// they could all do instead — not open the window — is a denial of a
    /// request nobody was shown.
    pub fn read(&self) -> Prefs {
        self.path
            .as_deref()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .and_then(|text| toml::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Write `prefs`, replacing whatever was there. Best effort, and silent.
    ///
    /// Silent because of where it is called from: the frame in which somebody
    /// ticked a checkbox, in the window they are about to approve a command
    /// in. A preference that did not stick is worth none of that window's
    /// room, and a reader who sees the box ticked has been told the truth
    /// about this request whatever the disk did.
    pub fn write(&self, prefs: &Prefs) {
        if !self.writable {
            return;
        }
        let Some(path) = self.path.as_deref() else { return };
        let _ = replace(path, prefs);
    }
}

/// Serialize `prefs` into a 0600 file beside `path` and rename it over.
///
/// 0600 because that is the mode everything hatch creates has, not because
/// there is a secret in it: the file sits in a 0700 directory and holds one
/// boolean. What the mode is really for is that it is the same discipline as
/// `config.toml`'s, applied by the same means — a permissioned temporary file
/// rather than whatever the umask happens to be.
///
/// Unlike `config.toml` this is **not** re-tightened on read. The process that
/// reads it draws a window and owns nothing, and a window that chmods a file
/// on its way to asking a question is a window doing something nobody asked
/// it to.
fn replace(path: &Path, prefs: &Prefs) -> std::io::Result<()> {
    let text = toml::to_string(prefs).map_err(std::io::Error::other)?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o600))
        .tempfile_in(dir)?;
    tmp.write_all(text.as_bytes())?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A state directory that exists, as the daemon would have left it.
    fn a_layout() -> (tempfile::TempDir, Paths) {
        let root = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::scratch(root.path());
        std::fs::create_dir_all(paths.prefs_file().parent().unwrap())
            .expect("the state directory");
        (root, paths)
    }

    #[test]
    fn a_preference_survives_the_window_that_set_it() {
        // The whole feature, in one claim: one window writes, the next one
        // opens with what it wrote.
        let (_root, paths) = a_layout();
        let file = PrefsFile::at(&paths);
        assert!(!file.read().close_on_decide, "the default is to stay");

        file.write(&Prefs { close_on_decide: true });
        assert!(PrefsFile::at(&paths).read().close_on_decide, "a fresh window read the default");
    }

    #[test]
    fn a_preference_turned_off_again_is_written_off_rather_than_forgotten() {
        // The other direction, which a file that is only ever written when a
        // box is ticked would get wrong.
        let (_root, paths) = a_layout();
        let file = PrefsFile::at(&paths);
        file.write(&Prefs { close_on_decide: true });
        file.write(&Prefs { close_on_decide: false });
        assert!(!PrefsFile::at(&paths).read().close_on_decide);
    }

    #[test]
    fn a_missing_file_is_the_default_and_not_a_failure() {
        let (_root, paths) = a_layout();
        assert_eq!(PrefsFile::at(&paths).read(), Prefs::default());
    }

    #[test]
    fn a_missing_directory_costs_a_preference_and_nothing_else() {
        // The one case where the window is running somewhere the daemon has
        // never been. It must not panic, and it must still draw.
        let root = tempfile::tempdir().unwrap();
        let paths = Paths::scratch(&root.path().join("never-created"));
        let file = PrefsFile::at(&paths);
        file.write(&Prefs { close_on_decide: true });
        assert_eq!(file.read(), Prefs::default());
    }

    #[test]
    fn a_malformed_file_is_the_default_and_is_repaired_by_the_next_write() {
        // A window that refused to open over a typo in a preference would
        // resolve as a denial of a request nobody was ever shown.
        let (_root, paths) = a_layout();
        for rubbish in ["not toml at all {{{", "close_on_decide = \"yes\"", "", "\u{0}\u{1}"] {
            std::fs::write(paths.prefs_file(), rubbish).unwrap();
            assert_eq!(
                PrefsFile::at(&paths).read(),
                Prefs::default(),
                "{rubbish:?} was not shrugged off"
            );
        }
        PrefsFile::at(&paths).write(&Prefs { close_on_decide: true });
        assert!(PrefsFile::at(&paths).read().close_on_decide, "the rubbish outlived a write");
    }

    #[test]
    fn a_file_from_another_build_keeps_the_keys_this_one_knows() {
        // Both directions of the same tolerance: a key this build has never
        // heard of must not stop the ones it has from loading.
        let (_root, paths) = a_layout();
        std::fs::write(
            paths.prefs_file(),
            "close_on_decide = true\nsomething_from_next_year = 12\n",
        )
        .unwrap();
        assert!(PrefsFile::at(&paths).read().close_on_decide);
    }

    #[test]
    fn a_preview_reads_the_real_preference_and_writes_nothing() {
        // A screenshot tool that changed a user's settings would be a
        // surprising thing for a screenshot to do.
        let (_root, paths) = a_layout();
        PrefsFile::at(&paths).write(&Prefs { close_on_decide: true });

        let preview = PrefsFile::read_only(&paths);
        assert!(preview.read().close_on_decide, "a preview must show the window as it is");
        preview.write(&Prefs { close_on_decide: false });
        assert!(
            PrefsFile::at(&paths).read().close_on_decide,
            "the preview wrote to the user's file"
        );
    }

    #[test]
    fn a_window_with_no_file_behind_it_defaults_and_never_writes() {
        let file = PrefsFile::none();
        assert_eq!(file.read(), Prefs::default());
        file.write(&Prefs { close_on_decide: true });
        assert_eq!(file.read(), Prefs::default());
    }

    #[test]
    fn the_file_is_written_at_0600() {
        let (_root, paths) = a_layout();
        PrefsFile::at(&paths).write(&Prefs { close_on_decide: true });
        let mode = std::fs::metadata(paths.prefs_file()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "written at {mode:04o}");
    }

    #[test]
    fn two_windows_writing_at_once_leave_one_whole_file_and_not_a_torn_one() {
        // The interleaving the queue makes ordinary. The claim is not that
        // one of them wins — it is that whatever is on disk afterwards parses
        // and is something somebody clicked, which is what the rename buys.
        let (root, paths) = a_layout();
        let mut windows = Vec::new();
        for window in 0..8 {
            let paths = Paths::scratch(root.path());
            windows.push(std::thread::spawn(move || {
                let file = PrefsFile::at(&paths);
                for round in 0..40 {
                    file.write(&Prefs { close_on_decide: (window + round) % 2 == 0 });
                    // Reading in the middle of everyone else's writes is the
                    // half of this that a torn file would break.
                    let _ = file.read();
                }
            }));
        }
        for window in windows {
            window.join().expect("a window writing a preference panicked");
        }
        let text = std::fs::read_to_string(paths.prefs_file()).expect("a file is there");
        toml::from_str::<Prefs>(&text).expect("what survived eight writers is not parseable");
    }

    #[test]
    fn nothing_is_left_beside_the_file_once_a_write_is_over() {
        // The temporary file is the mechanism, not a leftover: a window that
        // dropped one per click would fill the state directory with them.
        let (_root, paths) = a_layout();
        let file = PrefsFile::at(&paths);
        for _ in 0..5 {
            file.write(&Prefs { close_on_decide: true });
        }
        let dir = paths.prefs_file().parent().unwrap().to_path_buf();
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != "prefs.toml")
            .collect();
        assert!(left.is_empty(), "{left:?} was left beside prefs.toml");
    }
}
