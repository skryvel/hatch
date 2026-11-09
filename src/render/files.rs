//! The files a command names, for the window to offer to show.
//!
//! [`crate::render::command::named_paths`] finds the words whose values
//! hatch can state; this keeps the ones that are regular files where the
//! command will look for them. Like the roster, it touches the filesystem,
//! so the daemon builds it against the request's working directory and
//! environment, and the window is handed the result.
//!
//! The list is what was there when the request was prepared. The window
//! reads a file again when someone asks to see it (see [`crate::peek`]), and
//! the command reads it again when it runs; nothing here holds either of
//! those to what was found.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::render::command::named_paths;
use crate::render::language::{Evidence, Language, shebang};
use crate::render::unicode::classify;
use crate::render::{SpanBuilder, Spans, grammar, render_command};

/// The most files one request offers. A command that names more than this
/// is moving files around rather than running one, and the rest are counted
/// rather than listed: see [`Named::more`].
pub const MAX_NAMED_FILES: usize = 12;

/// One file a command names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedFile {
    /// The value as the program receives it: `script.py`, or `/srv/x.py`
    /// for a `"$F"` that holds it. Agent-chosen text, defanged where drawn.
    pub named: String,
    /// Where that is: `named` against the directory the command will be in
    /// when it gets there, when relative -- the working directory, or where a
    /// `cd` before it moved to. What the window reads.
    pub path: PathBuf,
    /// Its size when the request was prepared.
    pub size: u64,
}

/// The files a command names, and whether it names more than were listed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Named {
    pub files: Vec<NamedFile>,
    /// How many more regular files it names past [`MAX_NAMED_FILES`].
    pub more: usize,
}

/// The regular files `command` names, resolved against `cwd` and any `cd`
/// before them that [`named_paths`] can follow.
///
/// `metadata` follows a link, as the program will, and does not open what it
/// looks at, so a named pipe is answered without anyone writing to it.
pub fn named_files(command: &str, env: &BTreeMap<String, String>, cwd: &Path) -> Named {
    let mut named = Named::default();
    for found in named_paths(command, env) {
        let path = cwd.join(found.from_cwd());
        let Ok(metadata) = std::fs::metadata(&path) else { continue };
        if !metadata.is_file() {
            continue;
        }
        match named.files.len() < MAX_NAMED_FILES {
            true => {
                named.files.push(NamedFile { named: found.value, path, size: metadata.len() })
            }
            false => named.more += 1,
        }
    }
    named
}

/// The longest shell file that is read as shell: the longest command hatch
/// accepts. A longer one is drawn plain, as every file was before it was read
/// at all.
///
/// The passes that read shell were written for a command, and some of their
/// cost grows faster than the text does: each here-document is spliced into
/// the whole rendering, so a file that is nothing but short ones costs the
/// square of its length. Sixteen kilobytes of those take about half a second
/// to read; sixty-four took eight. At this size a file costs no more than a
/// command already can, and the reading is on a thread of its own.
pub const SHELL_LIMIT: usize = crate::server::MAX_COMMAND_BYTES;

/// What a file the window shows was read as, and what said so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    pub language: Language,
    /// [`Evidence::Shebang`] or [`Evidence::Filename`], the only two a file
    /// has: its own first line, or its name.
    pub evidence: Evidence,
}

/// `text`, the contents of the file at `path`, drawn byte for byte, and read
/// as its language when this build has a reader for it.
///
/// The language is the file's own word for it. The `#!` line comes first,
/// because it names the program that will run the file; the name's extension
/// second, because it is what somebody meant the file to be. Not the program
/// the command hands the file to: [`NamedFile`] does not carry it, and a
/// script nearly always says the same thing about itself.
///
/// Shell is read by the passes that read the command: command words,
/// separators, strings, comments, and a here-document's body as the program
/// it is given to. A language with a grammar has its strings and comments
/// marked where the grammar is sure of them, as a program in a command does.
/// Anything else, and a shell file past [`SHELL_LIMIT`], is drawn plain.
///
/// The [`Reading`] comes back only when there are marks to account for. A
/// grammar that was not sure of anything in the file -- a Python file cut
/// short at [`crate::peek::LIMIT`] does not parse -- leaves it plain, and a
/// sentence saying it was marked would be the one wrong thing on screen.
///
/// Lines start where the file starts them and nowhere else. The command pane
/// opens a line at every separator, which is how a reader sees the structure
/// of one long line; a file already has its lines, and they are what a reader
/// is going to compare against an editor.
///
/// A reader that panics leaves the file plain. Nothing here should, and the
/// file is the agent's choice of bytes: a plain file is a drawing the window
/// has always had, and a panic on the reading thread is a file that never
/// arrives.
pub fn read_file(text: &str, path: &Path) -> (Spans, Option<Reading>) {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let named = path.file_name().and_then(|name| name.to_str()).and_then(Language::of_filename);
    let reading = match (shebang(text), named) {
        (Some(language), _) => Reading { language, evidence: Evidence::Shebang },
        (None, Some(language)) => Reading { language, evidence: Evidence::Filename },
        (None, None) => return (classify(text), None),
    };
    let read = match reading.language {
        Language::Shell if text.len() <= SHELL_LIMIT => {
            catch_unwind(AssertUnwindSafe(|| relined(&render_command(text, &BTreeMap::new()))))
        }
        Language::Shell => return (classify(text), None),
        other if grammar::reads(other) => {
            catch_unwind(AssertUnwindSafe(|| grammar::read(text, other)))
        }
        _ => return (classify(text), None),
    };
    let plain = classify(text);
    match read {
        Ok(spans) if spans != plain => (spans, Some(reading)),
        _ => (plain, None),
    }
}

/// `spans` with a line started after each newline in the text, and nowhere
/// else. Every span keeps its bytes and its kind.
fn relined(spans: &Spans) -> Spans {
    let source = spans.source();
    let mut builder = SpanBuilder::new(source);
    for span in spans.iter() {
        let range = span.range();
        if source[..range.start].ends_with('\n') {
            builder.break_next();
        }
        builder.push_to(range.end, span.kind().clone());
    }
    builder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("script.py"), "print(1)\n").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/inner.py"), "pass\n").unwrap();
        dir
    }

    fn named(command: &str, env: &BTreeMap<String, String>, cwd: &Path) -> Vec<String> {
        named_files(command, env, cwd).files.into_iter().map(|file| file.named).collect()
    }

    #[test]
    fn a_script_handed_to_an_interpreter_is_named() {
        let dir = a_tree();
        let files = named_files("python3 script.py --fast", &BTreeMap::new(), dir.path());
        assert_eq!(
            files.files,
            vec![NamedFile {
                named: "script.py".to_string(),
                path: dir.path().join("script.py"),
                size: 9,
            }]
        );
    }

    #[test]
    fn a_variable_holding_a_full_path_names_the_file_it_holds() {
        let dir = a_tree();
        let full = dir.path().join("script.py").display().to_string();
        let set = format!("F={full}; python3 \"$F\"");
        assert_eq!(named(&set, &BTreeMap::new(), Path::new("/")), vec![full.clone()]);
        let env = BTreeMap::from([("SCRIPT".to_string(), full.clone())]);
        assert_eq!(named("python3 ${SCRIPT}", &env, Path::new("/")), vec![full]);
    }

    #[test]
    fn a_file_after_a_cd_is_read_where_the_cd_went() {
        let dir = a_tree();
        let sub = dir.path().join("sub");
        let command = format!("cd {} || exit 1; python3 inner.py", sub.display());
        let files = named_files(&command, &BTreeMap::new(), Path::new("/"));
        assert_eq!(
            files.files,
            vec![NamedFile {
                named: "inner.py".to_string(),
                path: dir.path().join("sub/inner.py"),
                size: 5,
            }]
        );
    }

    #[test]
    fn directories_and_missing_names_are_not_files() {
        let dir = a_tree();
        assert!(named("ls sub nothing.py", &BTreeMap::new(), dir.path()).is_empty());
    }

    #[test]
    fn a_command_naming_many_files_lists_some_and_counts_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let names: Vec<String> = (0..MAX_NAMED_FILES + 3).map(|n| format!("f{n}")).collect();
        for name in &names {
            std::fs::write(dir.path().join(name), "").unwrap();
        }
        let files = named_files(&format!("rm {}", names.join(" ")), &BTreeMap::new(), dir.path());
        assert_eq!(files.files.len(), MAX_NAMED_FILES);
        assert_eq!(files.more, 3);
    }

    // ---- reading a file that is shown ---------------------------------------

    use crate::render::{SpanKind, unrender};

    fn read(text: &str, name: &str) -> (Spans, Option<Reading>) {
        read_file(text, Path::new("/srv/app").join(name).as_path())
    }

    /// The text of every span of this kind.
    fn kinds(spans: &Spans, kind: &SpanKind) -> Vec<String> {
        let of_kind = spans.iter().filter(|span| span.kind() == kind);
        of_kind.map(|span| span.text().to_string()).collect()
    }

    /// Every byte as itself, and a line started after each newline and
    /// nowhere else.
    fn assert_the_files_own_lines(spans: &Spans, text: &str) {
        assert_eq!(unrender(spans), text);
        for span in spans.iter() {
            let after_newline = text[..span.range().start].ends_with('\n');
            assert_eq!(span.break_before(), after_newline, "{span:?} in {text:?}");
        }
    }

    #[test]
    fn a_shell_script_is_read_as_the_command_is_on_the_lines_it_has() {
        let text = "#!/bin/bash\nset -e; cd sub && make # build it\necho \"a; b\" >out\n";
        let (spans, reading) = read(text, "install");
        assert_eq!(
            reading,
            Some(Reading { language: Language::Shell, evidence: Evidence::Shebang })
        );
        assert_eq!(kinds(&spans, &SpanKind::Command), ["set", "cd", "make", "echo"]);
        assert_eq!(kinds(&spans, &SpanKind::Comment), ["#!/bin/bash", "# build it"]);
        assert_eq!(kinds(&spans, &SpanKind::Quoted), ["\"a; b\""]);
        assert_eq!(kinds(&spans, &SpanKind::Separator), [";", "&&"]);
        assert_the_files_own_lines(&spans, text);
    }

    #[test]
    fn a_program_inside_a_shell_file_keeps_the_files_lines_as_well() {
        // The command pane starts a `bash -c` program and a here-document body
        // on lines of their own. A file already has its lines.
        let text = "bash -c 'a; b'\ncat <<'EOF' >x.sh\nc && d\nEOF\nls\n";
        let (spans, reading) = read(text, "x.sh");
        assert_eq!(
            reading,
            Some(Reading { language: Language::Shell, evidence: Evidence::Filename })
        );
        assert!(kinds(&spans, &SpanKind::Command).contains(&"ls".to_string()), "{spans:?}");
        assert_the_files_own_lines(&spans, text);
    }

    #[test]
    fn a_files_own_shebang_is_believed_over_its_name() {
        let (spans, reading) = read("#!/usr/bin/env python3\ns = 'x'  # c\n", "run.sh");
        assert!(kinds(&spans, &SpanKind::Command).is_empty(), "read as shell: {spans:?}");
        match cfg!(feature = "highlight") {
            true => {
                assert_eq!(
                    reading,
                    Some(Reading { language: Language::Python, evidence: Evidence::Shebang })
                );
                assert_eq!(kinds(&spans, &SpanKind::Quoted), ["'x'"]);
                assert_eq!(kinds(&spans, &SpanKind::Comment), ["#!/usr/bin/env python3", "# c"]);
            }
            false => assert_eq!(reading, None),
        }
    }

    #[test]
    fn a_file_nothing_here_reads_is_drawn_plain_and_says_nothing() {
        for (text, name) in [
            ("echo hi; ls\n", "notes.txt"),
            ("echo hi; ls\n", "Makefile"),
            ("let s = 'x'; // c\n", "x.js"),
            // A grammar that is sure of nothing marks nothing, and so is not
            // said to have marked anything.
            ("def (:\n  'x'\n", "broken.py"),
        ] {
            let (spans, reading) = read(text, name);
            assert_eq!(reading, None, "{name}");
            assert_eq!(spans, classify(text), "{name}");
        }
    }

    #[test]
    fn a_shell_file_longer_than_a_command_may_be_is_drawn_plain() {
        let at_the_limit = "echo a;\n".repeat(SHELL_LIMIT / 8);
        assert_eq!(at_the_limit.len(), SHELL_LIMIT);
        assert!(read(&at_the_limit, "x.sh").1.is_some());

        let past_it = format!("{at_the_limit}#");
        let (spans, reading) = read(&past_it, "x.sh");
        assert_eq!(reading, None);
        assert_eq!(spans, classify(&past_it));
    }
}
