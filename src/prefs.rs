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
//! What the rename does not do is merge, and there are several preferences in
//! the file now rather than one — which is the case an earlier version of
//! this paragraph left a note about. A window that serialized its own struct
//! would write back its own stale copy of the other two, undoing a change the
//! window beside it made a moment earlier: a reader who ticks Stream in one
//! window and Close in another would end with whichever they ticked second
//! and no record of the first.
//!
//! So nothing writes the whole struct. [`PrefsFile::update`] is the only way
//! in: it reads the file, changes the one field that was clicked, and renames
//! the result over. That narrows the race to the width of a rename — two
//! windows whose read-modify-write overlap *exactly* still lose one change —
//! and it is where this stops. Closing it properly means a lock, and a stale
//! lock leaves a window unable to save a checkbox, which is a worse failure
//! than the one it prevents: three booleans are not worth a window that
//! cannot be ticked.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths::Paths;

/// The choices a window remembers between requests.
///
/// Every field has a default and the struct carries `#[serde(default)]`, so a
/// file written by an older build keeps loading unchanged after a new
/// preference is added — and, just as importantly, a file written by a *newer*
/// build loads here without its unknown keys stopping anything. Every default
/// is `false`, which is not an accident of the derive: the file's absence and
/// the file saying "no to every one of them" have to be the same window, because a
/// first run and an unreadable file both produce the absence.
///
/// # What may go in here, and the one that nearly may not
///
/// Two of these are display choices — they change what the person *sees* — and
/// they are the easy case: a remembered one costs a glance to notice and a
/// click to undo, and the worst a wrong one does is show too much or too
/// little of something that was going to happen anyway.
///
/// `terminal` is not that, and an earlier version of this struct refused it on
/// exactly that ground. It decides how the command *executes*: the command
/// gets a real tty, and everything in that terminal — including what the
/// person types into it — is captured and returned to the agent. A tick made
/// today is therefore a standing decision that a request next week runs that
/// way, and the person answering that request did not make it for that
/// request.
///
/// It is here anyway, and the reasons it is are narrow enough to be worth
/// naming rather than assuming:
///
/// * The box is **on screen, ticked, in the window**, every time. This is not
///   a hidden grant; it is a visible default, and undoing it is one click in
///   the window that is already asking.
/// * The warning that everything in the terminal goes to the agent is drawn
///   **whether or not the box is ticked** — `PromptApp::terminal_row` draws
///   it beside the control and not in a tooltip — so a remembered tick never
///   arrives without the sentence that says what it costs.
/// * It cannot take a terminal away. An agent that asked for one gets one,
///   and a remembered `false` changes nothing about that.
///
/// What it still is, and what nothing here makes it stop being: the one
/// preference in this file that a person can set once and then be surprised
/// by. Treat any change to how it is drawn as a change to a security control,
/// not to a checkbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Whether the window should close as soon as a verdict is given, rather
    /// than staying to show the run and the result.
    ///
    /// Written by the "Close when I decide" checkbox in the window's
    /// decision row, which is also where what ticking it gives up is said.
    pub close_on_decide: bool,
    /// Whether the window should show the command's output as it arrives.
    ///
    /// Written by the "Stream output to this window" checkbox. A display
    /// choice and nothing more: the daemon captures the output either way and
    /// returns it either way, and this decides only whether the person
    /// watching gets to see it happen.
    ///
    /// It is the one of the three that can leave the window in a state that
    /// reads like a fault: streaming beats closing, so a remembered `true`
    /// here greys the close box on every window from now on. The window says
    /// so out loud, and in words that are true of a standing choice rather
    /// than of a tick made in front of this command — see
    /// `CLOSE_WATCHING_ALWAYS` in `crate::prompt_ui`.
    pub stream: bool,
    /// Whether the command panes show the exact text rather than the
    /// annotated rendering.
    ///
    /// Written by the "Show the original text" checkbox. A view choice and
    /// nothing else: both panes draw every byte of the command, so this
    /// decides which of the two renderings is on screen and never what is in
    /// it. See `crate::prompt_ui::panes` for why the two are alternatives now
    /// rather than neighbours.
    ///
    /// Remembered, unlike the review box, because it is a statement about how
    /// a person reads rather than about one command: somebody who wants the
    /// bytes unannotated wants them on every window, and having to say so
    /// again each time is the kind of friction that ends in nobody checking
    /// anything.
    pub show_original: bool,
    /// Whether a finished command's output waits on the reader's screen
    /// before it reaches the agent.
    ///
    /// Written by the "Show me the output before it is sent" checkbox. An
    /// earlier version of this struct refused it, on the ground that whether
    /// *this* command's output might carry something that must not leave the
    /// machine is a judgement about this command, read on the screen -- `cat`
    /// on a file with a key in it, and not `ls` on the directory it is in.
    ///
    /// It is here because that argument turned out to describe a use nobody
    /// has. In practice a person who wants to read what goes back wants to
    /// read it, and having to say so again on every window is the friction
    /// that ends in nobody reading anything -- the same argument
    /// `show_original` makes.
    ///
    /// What a remembered tick costs, and it is real: every approved run now
    /// waits for a second answer before the agent hears anything, so every
    /// call blocks for however long the reader takes to come back to it, up
    /// to [`crate::config::Config::review_timeout_secs`].
    ///
    /// What it cannot do is let anything *out*. A remembered `true` only ever
    /// puts more output in front of a person, and every ending that is not an
    /// answer -- the deadline included -- withholds. That is the opposite
    /// direction from `terminal`, which is why this one does not need
    /// `terminal`'s paragraph of hedging: the way this preference fails is
    /// that an agent is told less than it could have been.
    pub review: bool,
    /// Whether the command should be given a terminal of its own.
    ///
    /// Written by the "Run it in a terminal" checkbox. **Not a display
    /// choice** — see this struct's own documentation, which is where the
    /// difference is set out and where anyone changing this should start.
    pub terminal: bool,
    /// Whether a sound is played when a window opens.
    ///
    /// Written by the "Play a sound when a window opens" checkbox. The one
    /// preference here that does nothing to the window it is ticked on: the
    /// sound belongs to a window *appearing*, and by the time this box is on
    /// screen its window has appeared. So it is read at the next one, which
    /// is the whole of what it is for -- somebody who is not looking at the
    /// screen cannot be told to look at it by anything drawn on it.
    ///
    /// Remembered for `show_original`'s reason and more plainly: whether a
    /// person is at their desk is not a fact about one command.
    ///
    /// It decides nothing about the request. A sound that fails to play, or a
    /// machine with nothing to play it with, costs the reader the prompt and
    /// nothing else -- the window is drawn either way, and the deadline runs
    /// either way.
    pub sound: bool,
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

    /// The same file, read but never written.
    ///
    /// What `hatch preview` asks for. The window it draws is the window a
    /// request would get, preference included — that is what makes a preview
    /// evidence about the real one — but nothing a person clicks in a sample
    /// outlives the sample. A method rather than a fourth constructor, so
    /// that giving up the right to write is visible at the call site as a
    /// thing that was decided.
    #[must_use]
    pub fn read_only(self) -> PrefsFile {
        PrefsFile { writable: false, ..self }
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

    /// Change one thing in the file and put it back. Best effort, and silent.
    ///
    /// Read-modify-write rather than a plain write, and that is the whole
    /// reason this is a closure and not a value: several windows are open at
    /// once by design, and a window that serialized its own struct would
    /// write back its stale copy of everything it did not touch. See the
    /// module documentation for what that leaves and why it stops there.
    ///
    /// The closure is handed what is on disk *now*, not what the window was
    /// opened with, so it must change only the field it was called for and
    /// leave the rest alone.
    ///
    /// Silent because of where it is called from: the frame in which somebody
    /// ticked a checkbox, in the window they are about to approve a command
    /// in. A preference that did not stick is worth none of that window's
    /// room, and a reader who sees the box ticked has been told the truth
    /// about this request whatever the disk did.
    pub fn update(&self, change: impl FnOnce(&mut Prefs)) {
        if !self.writable {
            return;
        }
        let Some(path) = self.path.as_deref() else { return };
        let mut prefs = self.read();
        change(&mut prefs);
        let _ = replace(path, &prefs);
    }

    /// Write `prefs` whole, replacing whatever was there.
    ///
    /// For a caller that owns the whole file — which is a test setting up a
    /// state, and nothing in the window. Every write a window does goes
    /// through [`PrefsFile::update`], because a window only ever knows about
    /// the one box that was clicked in it.
    #[cfg(test)]
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
/// there is a secret in it: the file sits in a 0700 directory and holds three
/// booleans. What the mode is really for is that it is the same discipline as
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

        file.write(&Prefs { close_on_decide: true, ..Prefs::default() });
        assert!(PrefsFile::at(&paths).read().close_on_decide, "a fresh window read the default");
    }

    #[test]
    fn a_preference_turned_off_again_is_written_off_rather_than_forgotten() {
        // The other direction, which a file that is only ever written when a
        // box is ticked would get wrong.
        let (_root, paths) = a_layout();
        let file = PrefsFile::at(&paths);
        file.write(&Prefs { close_on_decide: true, ..Prefs::default() });
        file.write(&Prefs { close_on_decide: false, ..Prefs::default() });
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
        file.write(&Prefs { close_on_decide: true, ..Prefs::default() });
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
        PrefsFile::at(&paths).write(&Prefs { close_on_decide: true, ..Prefs::default() });
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
        PrefsFile::at(&paths).write(&Prefs { close_on_decide: true, ..Prefs::default() });

        let preview = PrefsFile::at(&paths).read_only();
        assert!(preview.read().close_on_decide, "a preview must show the window as it is");
        preview.write(&Prefs { close_on_decide: false, ..Prefs::default() });
        assert!(
            PrefsFile::at(&paths).read().close_on_decide,
            "the preview wrote to the user's file"
        );
    }

    #[test]
    fn a_window_with_no_file_behind_it_defaults_and_never_writes() {
        let file = PrefsFile::none();
        assert_eq!(file.read(), Prefs::default());
        file.write(&Prefs { close_on_decide: true, ..Prefs::default() });
        assert_eq!(file.read(), Prefs::default());
    }

    #[test]
    fn the_file_is_written_at_0600() {
        let (_root, paths) = a_layout();
        PrefsFile::at(&paths).write(&Prefs { close_on_decide: true, ..Prefs::default() });
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
                    file.write(&Prefs {
                        close_on_decide: (window + round) % 2 == 0,
                        ..Prefs::default()
                    });
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
    fn every_box_is_remembered_on_its_own_and_none_of_them_is_the_default() {
        // One key per box, and a default of `false` for each: the file's
        // absence and the file saying no to all of them have to be the same
        // window, because a first run produces the absence. Every field is
        // written out rather than spread from a default, so a box added
        // later cannot join the file without a test saying what it does when
        // nobody has ever ticked it.
        let (_root, paths) = a_layout();
        let file = PrefsFile::at(&paths);
        assert_eq!(file.read(), Prefs::default());
        assert_eq!(
            Prefs::default(),
            Prefs {
                close_on_decide: false,
                stream: false,
                terminal: false,
                show_original: false,
                review: false,
                sound: false,
            }
        );

        let every = Prefs {
            close_on_decide: true,
            stream: true,
            terminal: true,
            show_original: true,
            review: true,
            sound: true,
        };
        file.write(&every);
        assert_eq!(
            PrefsFile::at(&paths).read(),
            every,
            "a fresh window did not read back every box"
        );
    }

    #[test]
    fn a_window_changing_one_box_leaves_the_two_it_did_not_touch_alone() {
        // The whole reason writes go through `update`. A window that
        // serialized its own struct would write back its stale copy of the
        // other two, and the reader who ticked Stream in the window beside
        // this one would find it unticked again.
        let (_root, paths) = a_layout();
        PrefsFile::at(&paths).write(&Prefs {
            close_on_decide: true,
            stream: true,
            terminal: false,
            show_original: false,
            review: true,
            sound: false,
        });

        // A second window that opened before any of that and knows nothing
        // about it, ticking the one box its reader clicked.
        PrefsFile::at(&paths).update(|prefs| prefs.terminal = true);

        assert_eq!(
            PrefsFile::at(&paths).read(),
            Prefs {
                close_on_decide: true,
                stream: true,
                terminal: true,
                show_original: false,
                review: true,
                sound: false,
            },
            "a window writing one box trampled the others"
        );
    }

    #[test]
    fn an_update_on_a_file_that_cannot_be_read_still_writes_what_it_was_given() {
        // `update` reads first, and a read that fails is the defaults — which
        // is the same answer a window opening on that file would get. The
        // click must still stick.
        let (_root, paths) = a_layout();
        std::fs::write(paths.prefs_file(), "not toml at all {{{").unwrap();
        PrefsFile::at(&paths).update(|prefs| prefs.stream = true);
        assert_eq!(
            PrefsFile::at(&paths).read(),
            Prefs {
                close_on_decide: false,
                stream: true,
                terminal: false,
                show_original: false,
                review: false,
                sound: false,
            }
        );
    }

    #[test]
    fn a_preview_updates_nothing_either() {
        // `read_only` has to cover every way in, not only the one it was
        // written against.
        let (_root, paths) = a_layout();
        PrefsFile::at(&paths).write(&Prefs { close_on_decide: true, ..Prefs::default() });
        PrefsFile::at(&paths).read_only().update(|prefs| prefs.close_on_decide = false);
        assert!(
            PrefsFile::at(&paths).read().close_on_decide,
            "a preview updated the user's file"
        );
    }

    #[test]
    fn nothing_is_left_beside_the_file_once_a_write_is_over() {
        // The temporary file is the mechanism, not a leftover: a window that
        // dropped one per click would fill the state directory with them.
        let (_root, paths) = a_layout();
        let file = PrefsFile::at(&paths);
        for _ in 0..5 {
            file.write(&Prefs { close_on_decide: true, ..Prefs::default() });
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
