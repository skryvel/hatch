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
            _ => return None,
        })
    }

    /// The language a file of this name holds, if the extension says so.
    fn of_filename(word: &str) -> Option<Language> {
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
/// Here-documents only, for now. They are where an agent puts a program most
/// often and they are the region already known not to be shell, so a reading
/// here changes nothing else about how the body is drawn. An interpreter's
/// `-c` argument is the obvious next one and is not done: the body is the
/// common case and this says nothing rather than half a thing.
pub fn snippets(command: &str) -> Vec<Snippet> {
    let mut out = Vec::new();
    for range in super::command::here_bodies(command) {
        let Some(found) = read(command, &range) else { continue };
        let (language, evidence) = found;
        out.push(Snippet { range, language, evidence });
    }
    out
}

/// What one body reads as, by the most exact evidence available for it.
fn read(command: &str, body: &Range<usize>) -> Option<(Language, Evidence)> {
    if let Some(language) = shebang(&command[body.clone()]) {
        return Some((language, Evidence::Shebang));
    }
    // The line the here-document operator is on: the body starts after the
    // newline that ends it.
    let head = command[..body.start].trim_end_matches('\n');
    let line = &head[head.rfind('\n').map_or(0, |at| at + 1)..];

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
fn shebang(body: &str) -> Option<Language> {
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
}
