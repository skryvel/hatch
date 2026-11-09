//! What language an embedded snippet is in, read off the command rather than
//! guessed from the text.
//!
//! Agents write commands that carry programs: `python3 - <<'PY'`, a config
//! file written with `cat <<'EOF' > nginx.conf`, a script piped into `sh`.
//! [`super::command`] already knows those bodies are not shell -- that is
//! what stops a `;` in one from being drawn as a separator -- but it had
//! nothing to say about what they *are*.
//!
//! # Why there is no classifier here
//!
//! The obvious shape is a detector: take the body, look at the text, decide.
//! Every option costs something this program will not pay. The accurate ones
//! carry a model and a C++ runtime; the cheap ones are built for files, lean
//! on a filename this has none of, and still bring a C regex engine. And a
//! classifier that is right nineteen times in twenty is wrong on one window
//! in twenty, which is the same class of mistake as a box drawn around the
//! wrong lines: the reader takes a label as a fact about what will run.
//!
//! The command does not need guessing at. It already says:
//!
//! * the body starts with `#!`, which names its interpreter exactly;
//! * the line that opens the body runs `python3`, `node`, `psql`;
//! * the file it is being written to is called `deploy.py`.
//!
//! All three are facts about what was written, not inferences about what it
//! resembles, and each is a handful of string comparisons. Where none of them
//! is there, this says nothing at all -- an unlabelled body is the same
//! rendering bodies had before this module existed, and costs a reader
//! nothing.
//!
//! # What a reading is worth
//!
//! It is a reading of the *wrapper's* convention, not a claim about the
//! bytes: `python3 - <<'PY'` says a person meant that body as Python, and it
//! would say so just as loudly about a body that is not valid Python at all.
//! So the window says where the reading came from -- see [`Evidence`] -- and
//! a reader who disagrees can see in one clause what to disbelieve.

use std::ops::Range;

/// A language hatch can name.
///
/// Short on purpose. Each entry has to be worth a reader's attention in a
/// window about to run something, and a list that tried to be exhaustive
/// would be a list nobody had checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Python,
    JavaScript,
    Ruby,
    Perl,
    Lua,
    Php,
    Shell,
    Sql,
    R,
    Clojure,
}

impl Language {
    /// What it is called, as the window says it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Python => "Python",
            Self::JavaScript => "JavaScript",
            Self::Ruby => "Ruby",
            Self::Perl => "Perl",
            Self::Lua => "Lua",
            Self::Php => "PHP",
            Self::Shell => "shell",
            Self::Sql => "SQL",
            Self::R => "R",
            Self::Clojure => "Clojure",
        }
    }

    /// The language a program of this name runs, if it is one this knows.
    ///
    /// The name is taken as written after its directory: `python3`,
    /// `/usr/bin/env python3.12` and `python3.12` are one answer. A version
    /// suffix is cut because an interpreter's name carries one and the
    /// language does not.
    pub(crate) fn of_program(word: &str) -> Option<Language> {
        let name = word.rsplit('/').next()?;
        let stem = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
        Some(match stem {
            "python" => Language::Python,
            "node" | "nodejs" => Language::JavaScript,
            "ruby" => Language::Ruby,
            "perl" => Language::Perl,
            "lua" => Language::Lua,
            "php" => Language::Php,
            "sh" | "bash" | "zsh" | "dash" | "ksh" => Language::Shell,
            "psql" | "sqlite" | "mysql" => Language::Sql,
            "Rscript" => Language::R,
            // `bb` is babashka and `clj` is the `clojure` launcher's own
            // wrapper; all three read the same language.
            "bb" | "clojure" | "clj" => Language::Clojure,
            _ => return None,
        })
    }

    /// The language a file of this name holds, if the extension says so.
    pub(crate) fn of_filename(word: &str) -> Option<Language> {
        let name = word.rsplit('/').next()?;
        let extension = name.rsplit_once('.')?.1;
        Some(match extension {
            "py" => Language::Python,
            "js" | "mjs" | "cjs" => Language::JavaScript,
            "rb" => Language::Ruby,
            "pl" => Language::Perl,
            "lua" => Language::Lua,
            "php" => Language::Php,
            "sh" | "bash" => Language::Shell,
            "sql" => Language::Sql,
            "R" => Language::R,
            "clj" | "cljs" | "cljc" | "bb" => Language::Clojure,
            _ => return None,
        })
    }
}

/// Where a reading came from, so a reader knows what to disbelieve.
///
/// Ordered by how exact it is, and that order is the one [`snippets`] tries
/// them in. A request that *named* the interpreter is not a reading at all --
/// hatch built the argv from it and is about to spawn exactly that program,
/// so there is nothing here to disbelieve. A `#!` line is the body naming its
/// own interpreter and cannot be argued with. A command running `python3` is
/// the convention of the program being invoked. A filename is the weakest --
/// a `.py` says what somebody intends to call the file, which is usually but
/// not always what is in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// The request named the interpreter, and hatch put it in the argv.
    Declared,
    /// The body's own `#!` line.
    Shebang,
    /// The program the line above it runs.
    Interpreter,
    /// The name of the file it is written to.
    Filename,
    /// The option it follows: the `-c` of `python3 -c '…'`. The program is
    /// an argument rather than a here-document, which is the one thing the
    /// window says differently about it.
    Flag,
}

impl Evidence {
    /// The clause the window uses to say where a reading came from.
    pub fn because(self) -> &'static str {
        match self {
            // No clause at all. The other three name something a reader could
            // go and check; this one is the argv on the line above, which
            // they are already looking at.
            Self::Declared => "the request named it",
            Self::Shebang => "from its own `#!` line",
            Self::Interpreter => "from the program it is given to",
            Self::Filename => "from the name of the file it is written to",
            Self::Flag => "from the option in front of it",
        }
    }
}

/// One embedded program: where it is, what it reads as, and on what evidence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Snippet {
    range: Range<usize>,
    language: Language,
    evidence: Evidence,
}

impl Snippet {
    /// The program a request named an interpreter for.
    ///
    /// The only constructor outside this module, and the only one that takes
    /// its language rather than reading it: [`snippets`] finds embedded
    /// programs by looking at a command, and this one is not found -- hatch
    /// was told, built the argv, and knows the bytes because it put them
    /// there. See [`crate::exec::interpreter`].
    pub fn declared(range: Range<usize>, language: Language) -> Snippet {
        Snippet { range, language, evidence: Evidence::Declared }
    }

    /// The bytes of the command this covers.
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    /// What it reads as.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Why hatch says so.
    pub fn evidence(&self) -> Evidence {
        self.evidence
    }
}

/// Every embedded program this command carries, in source order.
///
/// Here-documents, which are where an agent puts a program most often, and
/// an interpreter's single-quoted `-c` or `-e` argument. Those are found by
/// [`super::command::script_arguments`], which says which ones and why only
/// those.
pub fn snippets(command: &str) -> Vec<Snippet> {
    let mut out = Vec::new();
    for range in super::command::here_bodies(command) {
        let Some(found) = read(command, &range) else { continue };
        let (language, evidence) = found;
        out.push(Snippet { range, language, evidence });
    }
    for (range, language) in super::command::script_arguments(command) {
        out.push(Snippet { range, language, evidence: Evidence::Flag });
    }
    out.sort_by_key(|found| found.range.start);
    out
}

/// What one body reads as, by the most exact evidence available for it.
fn read(command: &str, body: &Range<usize>) -> Option<(Language, Evidence)> {
    if let Some(language) = shebang(&command[body.clone()]) {
        return Some((language, Evidence::Shebang));
    }
    // The command the here-document operator belongs to, and the rest of its
    // pipeline, on the line the body follows. Not the whole line: the body
    // of `python3 -c 'a'; bash <<'SH'` is bash's.
    let line = &command[super::command::here_reader(command, body)?];

    // The program before the filename, because a command that runs `python3`
    // has said what the body is more directly than a file it happens to also
    // name. `sudo python3 - <<PY` is why this looks past the first word.
    if let Some(language) = line.split_ascii_whitespace().find_map(Language::of_program) {
        return Some((language, Evidence::Interpreter));
    }
    let language = line.split_ascii_whitespace().find_map(Language::of_filename)?;
    Some((language, Evidence::Filename))
}

/// The language a body's own `#!` line names, if it has one.
///
/// `#!/usr/bin/env python3` names `python3` and not `env`, which is the whole
/// reason this is not one lookup.
pub(crate) fn shebang(body: &str) -> Option<Language> {
    let line = body.lines().next()?.strip_prefix("#!")?;
    let mut words = line.split_ascii_whitespace();
    let first = words.next()?;
    if first.rsplit('/').next() == Some("env") {
        return words.next().and_then(Language::of_program);
    }
    Language::of_program(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a command's bodies read as, as `(language, why)`.
    fn read_as(command: &str) -> Vec<(&'static str, &'static str)> {
        snippets(command)
            .iter()
            .map(|found| (found.language().name(), found.evidence().because()))
            .collect()
    }

    #[test]
    fn a_body_given_to_an_interpreter_reads_as_its_language() {
        assert_eq!(
            read_as("python3 - <<'PY'\nprint(1)\nPY"),
            vec![("Python", "from the program it is given to")]
        );
        assert_eq!(
            read_as("node -e x <<'JS'\nlet a = 1\nJS"),
            vec![("JavaScript", "from the program it is given to")]
        );
    }

    #[test]
    fn a_body_is_read_by_the_command_that_owns_it_and_the_pipe_after_it() {
        // Before the fix each of the first three read the first interpreter
        // anywhere on the line.
        let given = "from the program it is given to";
        assert_eq!(
            read_as("python3 -c 'a'; bash <<'SH'\nls\nSH"),
            vec![("Python", "from the option in front of it"), ("shell", given)]
        );
        assert_eq!(read_as("python3 gen.py | bash <<'SH'\nls\nSH"), vec![("shell", given)]);
        assert_eq!(read_as("cat <<'EOF' > config.json && python3 deploy.py\n{}\nEOF"), vec![]);
        // What the owner writes goes on down the pipe.
        assert_eq!(read_as("cat <<'EOF' | python3 -\nprint(1)\nEOF"), vec![("Python", given)]);
        // And a body after another one's terminator has no line of its own
        // to be read from; before, it was read from that terminator.
        assert_eq!(read_as("cat <<'python3' <<'B'\nx\npython3\ny\nB"), vec![]);
    }

    #[test]
    fn a_version_in_the_name_is_not_part_of_the_language() {
        for word in ["python3", "python3.12", "/usr/bin/python3", "python"] {
            assert_eq!(Language::of_program(word), Some(Language::Python), "{word}");
        }
    }

    #[test]
    fn a_shebang_beats_the_program_the_body_is_given_to() {
        // `cat` says nothing and the file name says shell; the body says
        // Python about itself, and it is the one that wrote it.
        let command = "cat <<'EOF' > /tmp/run.sh\n#!/usr/bin/env python3\nprint(1)\nEOF";
        assert_eq!(read_as(command), vec![("Python", "from its own `#!` line")]);
    }

    #[test]
    fn a_file_name_is_read_when_nothing_else_says_anything() {
        assert_eq!(
            read_as("cat <<'EOF' > /srv/app/deploy.py\nprint(1)\nEOF"),
            vec![("Python", "from the name of the file it is written to")]
        );
    }

    #[test]
    fn an_interpreter_further_along_the_line_is_still_found() {
        assert_eq!(
            read_as("sudo -u app python3 - <<'PY'\nprint(1)\nPY"),
            vec![("Python", "from the program it is given to")]
        );
    }

    #[test]
    fn a_body_nothing_names_is_left_unnamed() {
        // The ordinary config file, and the answer is silence. An unlabelled
        // body is exactly the rendering bodies had before this existed.
        assert_eq!(read_as("cat <<'EOF' > /etc/hosts\n127.0.0.1 local\nEOF"), vec![]);
        assert_eq!(read_as("wc -l <<'EOF'\na\nEOF"), vec![]);
    }

    #[test]
    fn a_command_with_no_body_at_all_reads_as_nothing() {
        assert_eq!(read_as("ls -l /tmp"), vec![]);
        assert_eq!(read_as(""), vec![]);
    }

    #[test]
    fn two_bodies_are_read_one_at_a_time() {
        let command = "python3 - <<'PY'\nprint(1)\nPY\npsql -f - <<'SQL'\nselect 1;\nSQL";
        assert_eq!(
            read_as(command),
            vec![
                ("Python", "from the program it is given to"),
                ("SQL", "from the program it is given to"),
            ]
        );
    }

    #[test]
    fn a_reading_covers_the_body_and_not_its_delimiter() {
        let command = "python3 - <<'PY'\nprint(1)\nPY";
        let found = snippets(command);
        assert_eq!(found.len(), 1);
        let text = &command[found[0].range()];
        assert!(text.contains("print(1)"), "{text:?}");
        assert!(!text.contains("PY"), "the delimiter is not data: {text:?}");
    }

    /// Each program found in `command`, as its text and what it reads as.
    fn programs_in(command: &str) -> Vec<(&str, &'static str)> {
        snippets(command)
            .iter()
            .map(|found| (&command[found.range()], found.language().name()))
            .collect()
    }

    #[test]
    fn a_single_quoted_argument_to_an_interpreters_option_reads_as_its_language() {
        assert_eq!(programs_in("python3 -c 'print(1)'"), vec![("print(1)", "Python")]);
        assert_eq!(
            read_as("python3 -c 'print(1)'"),
            vec![("Python", "from the option in front of it")]
        );
        assert_eq!(programs_in("bb -e '(println 1)'"), vec![("(println 1)", "Clojure")]);
        assert_eq!(programs_in("clojure -M -e '(println 1)'"), vec![("(println 1)", "Clojure")]);
        assert_eq!(programs_in("bash -c 'cd /tmp; ls'"), vec![("cd /tmp; ls", "shell")]);
        // The shells' own options are known, for the list of what runs.
        assert_eq!(programs_in("bash -e -u -c 'ls'"), vec![("ls", "shell")]);
        // Past assignments and wrappers, as that list is.
        assert_eq!(
            programs_in("A=1 env B=2 timeout 60 sudo /usr/bin/python3.12 -c 'x'"),
            vec![("x", "Python")]
        );
        // One per segment, in source order, among here-documents.
        assert_eq!(
            programs_in("cd /tmp && python3 -c 'a'; bash <<'SH'\nb\nSH\nbash -c 'c'"),
            vec![("a", "Python"), ("b\n", "shell"), ("c", "shell")]
        );
    }

    #[test]
    fn a_newline_straight_after_the_quote_ends_the_line_above_and_is_not_the_programs() {
        // So the program starts at the start of a line, where its box does.
        assert_eq!(programs_in("python3 -c '\nprint(1)\n'"), vec![("print(1)\n", "Python")]);
        // And a program that was nothing else is no program.
        assert_eq!(programs_in("python3 -c '\n'"), vec![]);
    }

    #[test]
    fn an_argument_whose_bytes_are_not_the_programs_or_whose_place_is_a_guess_is_not_read() {
        for command in [
            // The shell expands it first.
            "python3 -c \"print(1)\"",
            // Several strings joined, the usual way to put a quote in one.
            "python3 -c 'print('\\''x'\\'')'",
            "python3 -c print",
            // An option in front of `-c` might take a value, and `-W` does.
            "python3 -u -c 'print(1)'",
            "python3 -W ignore -c 'print(1)'",
            "python3 script.py 'print(1)'",
            "python3 -c",
            "python3 -c ''",
            "python3 -c 'print(1)",
            // Not what the segment runs.
            "echo python3 -c 'x'",
            // Not looked inside, not shell, not in the table.
            "x=$(python3 -c 'x')",
            "# python3 -c 'x'",
            "cat <<'EOF'\npython3 -c 'x'\nEOF",
            "php -r 'echo 1;'",
        ] {
            assert_eq!(programs_in(command), vec![], "{command}");
        }
    }

#[cfg(test)]
mod clojure_tests {
    use super::*;

    #[test]
    fn a_clojure_runner_names_its_language() {
        // `bb` is babashka, `clj` is the `clojure` launcher's wrapper, and
        // all three read the same language -- so a here-document given to any
        // of them is named the same way.
        for name in ["bb", "clojure", "clj", "/usr/bin/bb"] {
            assert_eq!(Language::of_program(name), Some(Language::Clojure), "{name}");
        }
        assert_eq!(Language::Clojure.name(), "Clojure");
    }

    #[test]
    fn a_clojure_file_is_named_by_its_extension() {
        for path in ["/tmp/x.clj", "deps.cljs", "a/b.cljc", "task.bb"] {
            assert_eq!(Language::of_filename(path), Some(Language::Clojure), "{path}");
        }
    }
}
}
