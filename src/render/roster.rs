//! What a command will run, in one place: the roster.
//!
//! Reading a command to find out what it runs means reading all of it. Ten
//! `grep`s in a pipeline are ten words to check; a `sudo` in front of
//! something is two programs, not one; and a name that is not on the `PATH`
//! the command will be given looks exactly like a name that is, right up
//! until it does not run. So the window says it once, above the panes, before
//! the reader starts on the command itself: every distinct thing this command
//! puts in command position, how many times, and where each one resolves.
//!
//! [`crate::render::command::invoked`] finds the names — which word of a
//! segment is the command, which wrappers can be seen past and which cannot —
//! and this module answers the other half: *where does that name lead*. The
//! split is the same one the rest of this crate keeps. `command` is a pure
//! reading of the text and has no idea what is on the machine; this module
//! touches the filesystem and has no opinion about shell grammar.
//!
//! # It is a snapshot, and it says so
//!
//! Every entry here is what a `stat` said at the moment the window was drawn.
//! Nothing is held open, nothing is locked, and the binary behind a name can
//! be replaced between this list and the `execve` that follows the reader's
//! approval. That is the same class of gap [`crate::swap`] has about a file's
//! hash — and the difference worth stating is that swap *closes* its gap, by
//! re-reading and re-hashing before it applies, and this one cannot be closed
//! that way. The lookup that decides what actually runs is done by bash at
//! exec time; hatch is not in that path and cannot pin a name to an inode.
//!
//! So the window does not imply otherwise. The line it draws is labelled with
//! *when* it was true — see [`crate::prompt_ui::panes::roster_summary`] — and
//! the label is the honest part of the claim rather than a hedge bolted onto
//! it. A reader who is told "this is where `grep` was a moment ago" has been
//! told something true and useful; a reader who is told "this is what will
//! run" has been told something hatch cannot know.
//!
//! # Against the environment the command will receive
//!
//! The `PATH` is the child's, out of
//! [`crate::exec::env::build_child_env`] — and for a `root: true` request the
//! one that travels through `run0 --setenv=`, because that is the environment
//! the command is handed. It is the same rule, and the same reason, as the
//! `$HOME` in the annotated pane: hatch's own environment came from wherever
//! the daemon was started, and a window that resolved against it would name a
//! file the command will never look at. The environment is therefore a
//! parameter and there is no default.
//!
//! # Facts, not verdicts
//!
//! This module states **where** a name resolves and whether the file or the
//! directory holding it carries a group- or other-write bit. All of those are
//! things a person could check by hand and get the same answer to. None of
//! them is a judgement.
//!
//! Deciding that a particular location is *alarming* is a verdict, and
//! verdicts belong to [`super::danger`], which is still unwritten and now
//! carries a second note waiting for it. This is the same boundary the
//! redirection work drew: `> /dev/null` and `> /etc/passwd` get the same
//! colour here, because two passes with an opinion about the same thing is
//! how a window comes to shout at `/dev/null`.
//!
//! What the window does do with a writable location is say it out loud in its
//! warning colour, which is [`crate::prompt_ui::panes`]'s decision about
//! emphasis rather than a claim about danger — and the words it uses are the
//! fact and nothing else.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::exec::lookup::{anyone_can_write, is_executable, lookup};
use crate::render::command::{Invocation, invoked, is_builtin, is_keyword};

/// One name a command puts in command position, and what it leads to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The name as the command writes it, quoting removed:
    /// [`crate::render::command::invoked`] reads `'ls'` as `ls`. Agent-chosen
    /// text, so it is defanged where it is drawn.
    pub name: String,
    /// How many times this name is in command position. `grep` three times in
    /// a pipeline is one entry with a count of three, which is the whole
    /// reason the list is shorter than the command.
    pub count: usize,
    /// Where the name leads.
    pub found: Resolution,
    /// Whether this is a wrapper whose own command hatch could not read.
    ///
    /// Separate from [`Resolution`] because it is a claim about a *different*
    /// thing: `sudo` itself resolved perfectly well, and what is missing is
    /// the program behind it. A reader told only that `sudo` is at
    /// `/usr/bin/sudo` would reasonably conclude the list was complete.
    pub hides: bool,
}

/// Where a name leads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "found", rename_all = "snake_case")]
pub enum Resolution {
    /// The shell runs it itself and never looks at the `PATH`. See
    /// [`crate::render::command::is_builtin`] for why this distinction is the
    /// difference between a list that is read and one that is not.
    Builtin,
    /// A function this very command defines. It resolves to nothing on disk
    /// and nothing is wrong: `deploy() { … }; deploy` is an ordinary script.
    Function,
    /// A file, where the lookup found it.
    Found {
        /// The file that would run.
        path: PathBuf,
        /// Who else may write it. See [`Writable`].
        writable: Writable,
    },
    /// No file of that name that the shell would execute. A signal, and the
    /// reason it is a variant of its own rather than an absent entry: a name
    /// that resolves to nothing is the most interesting thing this list can
    /// say, and an absence says nothing at all.
    Missing,
    /// A command word hatch will not read a name out of — `$TOOL`, `*.sh` —
    /// so `name` is the word rather than a name. The shell works out what it
    /// stands for and hatch expands nothing.
    Unread,
}

/// Who besides the owner may write a resolved binary, in mode bits.
///
/// Two answers rather than one, because they are two different facts and a
/// reader wants to know which. A writable *file* can be rewritten in place; a
/// writable *directory* can have the file replaced under the same name. Both
/// mean the name could lead somewhere else by the time it runs, and neither
/// is a verdict — see the module docs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Writable {
    /// The file itself carries a group- or other-write bit.
    pub file: bool,
    /// The directory it was found in does.
    pub directory: bool,
}

impl Writable {
    /// Whether either of them is true, which is when there is anything to
    /// say.
    pub fn any(self) -> bool {
        self.file || self.directory
    }
}

impl Entry {
    /// Whether this entry is worth saying something extra about: it leads
    /// nowhere, it could not be read, it hides a command, or it resolves
    /// somewhere anyone can write.
    ///
    /// The four of them together are what turns the compact one-line roster
    /// into the fuller form. An ordinary request has none, and pays one row
    /// rather than several.
    pub fn remarkable(&self) -> bool {
        match &self.found {
            Resolution::Missing | Resolution::Unread => true,
            Resolution::Found { writable, .. } => self.hides || writable.any(),
            Resolution::Builtin | Resolution::Function => self.hides,
        }
    }
}

/// Every distinct thing `command` puts in command position, in the order it
/// first appears, resolved against the environment the command will receive.
///
/// `cwd` is the working directory the command will run in, and it is here for
/// one case: a name with a `/` in it is not looked up on the `PATH` at all —
/// the shell treats it as a path — so `./configure` resolves against the
/// directory the command runs in or against nothing sensible at all.
///
/// # Why first-appearance order
///
/// Because the list is read beside the command, and the command is read top
/// to bottom. Sorting by name would be tidier and would make the reader
/// search the list for the word they just read in the pane; sorting by how
/// remarkable an entry is would be this module deciding what matters, which is
/// the verdict it does not get to make.
pub fn roster(command: &str, env: &BTreeMap<String, String>, cwd: &Path) -> Vec<Entry> {
    let invoked = invoked(command);
    let mut out: Vec<Entry> = Vec::new();

    for invocation in &invoked.runs {
        // A wrapper hatch could not see past is a second remark about the
        // occurrence just recorded, never an occurrence of its own: `sudo -X
        // ls` runs one `sudo`, and counting the remark would draw `sudo x2`
        // over a line with one of them in it.
        if let Invocation::Behind(name) = invocation {
            match out.iter_mut().find(|entry| &entry.name == name) {
                Some(seen) => seen.hides = true,
                // A wrapper that is also a reserved word -- `time -x ls` --
                // was never listed as a name, because reserved words are
                // structure. It still has to appear here: the alternative is
                // a roster that silently says nothing at all about a command
                // it could not read, which is the one thing this list must
                // never do.
                None => out.push(Entry {
                    name: name.clone(),
                    count: 1,
                    found: resolve(name, env, cwd, &invoked),
                    hides: true,
                }),
            }
            continue;
        }
        let (name, word) = match invocation {
            Invocation::Named(name) => (name, false),
            Invocation::Unread(word) => (word, true),
            Invocation::Behind(_) => unreachable!("answered above"),
        };
        // A repeat is a count, not a row. That is the whole reason the list
        // is shorter than the command it describes.
        if let Some(seen) = out.iter_mut().find(|entry| &entry.name == name) {
            seen.count += 1;
            continue;
        }
        let found = match word {
            true => Resolution::Unread,
            false => resolve(name, env, cwd, &invoked),
        };
        out.push(Entry { name: name.clone(), count: 1, found, hides: false });
    }

    out
}

/// Where one name leads, in the order bash would ask.
///
/// A name with a `/` in it is a path and is never looked up on the `PATH`; a
/// reserved word and a builtin are run by the shell itself and never looked
/// up either; a function the command defines shadows a builtin of the same
/// name; and everything left is a `PATH` search. Getting that order wrong is
/// how `cd` comes to be reported as missing.
fn resolve(
    name: &str,
    env: &BTreeMap<String, String>,
    cwd: &Path,
    invoked: &crate::render::command::Invoked,
) -> Resolution {
    if name.contains('/') {
        // Relative to the directory the command runs in, which is the
        // directory the window states in its own header. A leading `./` is
        // dropped so the path reads as a path rather than as a path with the
        // shell's punctuation still in it; nothing else is normalised,
        // because `..` through a symlink is not a lexical question.
        let path = cwd.join(name.trim_start_matches("./"));
        return found_at(path);
    }
    if is_keyword(name) || is_builtin(name) {
        return Resolution::Builtin;
    }
    if invoked.defines.contains(name) {
        return Resolution::Function;
    }
    match lookup(name, env) {
        Some(path) => found_at(path),
        None => Resolution::Missing,
    }
}

/// A path the shell would reach, stat'ed once for whether it runs and once
/// for who may write it.
fn found_at(path: PathBuf) -> Resolution {
    if !is_executable(&path) {
        return Resolution::Missing;
    }
    let writable = Writable {
        file: anyone_can_write(&path),
        directory: path.parent().is_some_and(anyone_can_write),
    };
    Resolution::Found { path, writable }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// A `PATH` of one directory, with the named programs in it at `mode`.
    fn bin(dir: &Path, programs: &[&str], mode: u32) {
        for program in programs {
            let path = dir.join(program);
            fs::write(&path, "#!/bin/sh\n").expect("writes");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmods");
        }
    }

    fn env_of(dirs: &[&Path]) -> BTreeMap<String, String> {
        let joined = dirs.iter().map(|d| d.display().to_string()).collect::<Vec<_>>().join(":");
        BTreeMap::from([("PATH".to_string(), joined)])
    }

    /// The roster of `command` against a `PATH` holding exactly `programs`.
    fn against(command: &str, programs: &[&str]) -> (tempfile::TempDir, Vec<Entry>) {
        let dir = tempfile::tempdir().expect("a directory");
        bin(dir.path(), programs, 0o755);
        let entries = roster(command, &env_of(&[dir.path()]), Path::new("/"));
        (dir, entries)
    }

    fn names(entries: &[Entry]) -> Vec<(&str, usize)> {
        entries.iter().map(|entry| (entry.name.as_str(), entry.count)).collect()
    }

    #[test]
    fn a_name_repeated_is_one_row_with_a_count_on_it() {
        // The case the whole list exists for. Ten greps are ten words to
        // check in the command and one line here.
        let command = "grep a f | grep b | grep c | grep d";
        let (_dir, entries) = against(command, &["grep"]);
        assert_eq!(names(&entries), vec![("grep", 4)]);
    }

    #[test]
    fn a_builtin_resolves_to_the_shell_and_not_to_nothing() {
        // The trap this module is shaped around: `cd` is on no PATH
        // anywhere, and a list that called it missing would put a warning on
        // the most ordinary command there is.
        let (_dir, entries) = against("cd /tmp && ls", &["ls"]);
        assert_eq!(names(&entries), vec![("cd", 1), ("ls", 1)]);
        assert_eq!(entries[0].found, Resolution::Builtin);
        assert!(!entries[0].remarkable(), "a builtin is not a finding");
    }

    #[test]
    fn a_name_that_is_both_a_builtin_and_a_binary_is_reported_as_the_builtin() {
        // bash looks for a builtin before it looks at PATH, and commands
        // reach it as `bash -c`. Naming the file would name something that
        // will not be executed.
        let (_dir, entries) = against("echo hi", &["echo"]);
        assert_eq!(entries[0].found, Resolution::Builtin);
    }

    #[test]
    fn naming_the_file_instead_of_the_builtin_reaches_the_file() {
        // The other half of the rule above, and the reason it needs no
        // special case: `/usr/bin/echo` is a different word in command
        // position, so it takes the path arm.
        let dir = tempfile::tempdir().expect("a directory");
        bin(dir.path(), &["echo"], 0o755);
        let command = format!("{}/echo hi", dir.path().display());
        let entries = roster(&command, &env_of(&[dir.path()]), Path::new("/"));
        assert!(
            matches!(&entries[0].found, Resolution::Found { path, .. } if path.ends_with("echo")),
            "{:?}",
            entries[0]
        );
    }

    #[test]
    fn a_name_nothing_answers_to_is_missing_rather_than_absent() {
        let (_dir, entries) = against("frobnicate --now", &[]);
        assert_eq!(names(&entries), vec![("frobnicate", 1)]);
        assert_eq!(entries[0].found, Resolution::Missing);
        assert!(entries[0].remarkable());
    }

    #[test]
    fn a_file_with_no_execute_bit_is_missing_because_the_shell_would_not_run_it() {
        let dir = tempfile::tempdir().expect("a directory");
        bin(dir.path(), &["tool"], 0o644);
        let entries = roster("tool", &env_of(&[dir.path()]), Path::new("/"));
        assert_eq!(entries[0].found, Resolution::Missing);
    }

    #[test]
    fn a_function_the_command_defines_resolves_to_the_command_itself() {
        // The second way a name can lead nowhere on disk and be perfectly
        // ordinary. Without this the commonest shape of shell script would
        // draw a warning.
        let (_dir, entries) = against("deploy() { rm -rf build; }; deploy", &["rm"]);
        assert_eq!(names(&entries), vec![("rm", 1), ("deploy", 1)]);
        assert_eq!(entries[1].found, Resolution::Function);
        assert!(!entries[1].remarkable());
    }

    #[test]
    fn a_wrapper_is_listed_with_what_it_runs_and_not_instead_of_it() {
        // "Ask what does this run of `sudo foo` and hatch answers `sudo`" is
        // the bug. Both of them run.
        let (_dir, entries) = against("sudo -u root systemctl restart x", &["sudo", "systemctl"]);
        assert_eq!(names(&entries), vec![("sudo", 1), ("systemctl", 1)]);
        assert!(entries.iter().all(|entry| !entry.hides));
    }

    #[test]
    fn a_wrapper_whose_arguments_cannot_be_read_says_so_rather_than_guessing() {
        // `-X` is not in sudo's grammar here, and an unknown option might
        // take a value: skipping one word where two were wanted would report
        // `systemctl` as an argument or an argument as a program.
        let (_dir, entries) = against("sudo -X systemctl restart x", &["sudo", "systemctl"]);
        assert_eq!(names(&entries), vec![("sudo", 1)]);
        assert!(entries[0].hides, "and the window has to say what is behind it");
        assert!(entries[0].remarkable());
    }

    #[test]
    fn the_shell_a_root_request_wraps_is_read_through_to_the_command_in_it() {
        // What `Daemon::prepare_run` draws for `root: true`: the whole run0
        // line, with the approved command as one quoted argument to
        // `bash -c`. Without the shell wrapper the roster for every root
        // request would be `run0` and `bash`.
        let (_dir, entries) = against(
            "run0 --pipe --setenv=PAGER=cat -- bash -c 'systemctl restart x && journalctl -u x'",
            &["run0", "bash", "systemctl", "journalctl"],
        );
        assert_eq!(
            names(&entries),
            vec![("run0", 1), ("bash", 1), ("systemctl", 1), ("journalctl", 1)]
        );
    }

    #[test]
    fn a_reserved_word_that_hides_a_command_is_listed_even_though_it_is_structure() {
        // `time` is a reserved word, so it is not a name and is not listed --
        // until it is the thing hiding the command. A roster that said
        // nothing at all about a command it could not read would be the one
        // failure this list must never have.
        let (_dir, entries) = against("time -x make", &["make"]);
        assert_eq!(names(&entries), vec![("time", 1)]);
        assert!(entries[0].hides);
        assert_eq!(entries[0].found, Resolution::Builtin, "the shell runs it, not a file");
    }

    #[test]
    fn a_word_that_stands_for_something_else_is_kept_as_the_word_it_is() {
        let (_dir, entries) = against("$TOOL --version", &[]);
        assert_eq!(names(&entries), vec![("$TOOL", 1)]);
        assert_eq!(entries[0].found, Resolution::Unread);
        assert!(entries[0].remarkable());
    }

    #[test]
    fn a_binary_anyone_can_rewrite_is_reported_as_a_fact_about_its_bits() {
        let dir = tempfile::tempdir().expect("a directory");
        bin(dir.path(), &["tool"], 0o757);
        let entries = roster("tool", &env_of(&[dir.path()]), Path::new("/"));
        let Resolution::Found { writable, .. } = &entries[0].found else {
            panic!("{:?}", entries[0]);
        };
        assert!(writable.file);
        assert!(!writable.directory, "the temporary directory is the owner's alone");
        assert!(entries[0].remarkable());
    }

    #[test]
    fn a_binary_in_a_directory_anyone_can_replace_it_in_is_the_other_half() {
        // A tight file in a loose directory is the case a file-mode check
        // alone would miss, and it is the more useful of the two: nothing has
        // to be rewritten, only replaced.
        let dir = tempfile::tempdir().expect("a directory");
        let loose = dir.path().join("bin");
        fs::create_dir(&loose).expect("makes a directory");
        bin(&loose, &["tool"], 0o755);
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o777)).expect("chmods");

        let entries = roster("tool", &env_of(&[&loose]), Path::new("/"));
        let Resolution::Found { writable, .. } = &entries[0].found else {
            panic!("{:?}", entries[0]);
        };
        assert!(!writable.file);
        assert!(writable.directory);
    }

    #[test]
    fn a_relative_name_resolves_against_the_directory_the_command_runs_in() {
        // The shell does not search the PATH for a name with a slash in it,
        // so neither does this -- and the directory it is relative to is the
        // one the window's own header states.
        let dir = tempfile::tempdir().expect("a directory");
        bin(dir.path(), &["configure"], 0o755);
        let entries = roster("./configure --prefix=/usr", &BTreeMap::new(), dir.path());
        assert_eq!(
            entries[0].found,
            Resolution::Found {
                path: dir.path().join("configure"),
                writable: Writable::default()
            }
        );
    }

    #[test]
    fn an_ordinary_command_has_nothing_remarkable_in_its_roster() {
        // The case that has to stay quiet, because a list that says something
        // about every request is a list nobody reads.
        let (_dir, entries) = against("cd /tmp && tar -xzf x.tgz && ls -la", &["tar", "ls"]);
        assert!(entries.iter().all(|entry| !entry.remarkable()), "{entries:?}");
    }

    #[test]
    fn an_empty_command_has_nothing_to_say_about_what_it_runs() {
        let (_dir, entries) = against("", &[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn resolution_is_against_the_given_environment_and_never_this_process_s() {
        // The same rule the annotated pane's `$HOME` follows. hatch's own
        // PATH almost certainly has `ls` on it; the child's, here, has
        // nothing at all, and the window must speak for the child.
        let entries = roster("ls -la", &BTreeMap::new(), Path::new("/"));
        assert_eq!(entries[0].found, Resolution::Missing);
    }
}
