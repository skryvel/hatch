//! Which program a request's text is a program *for*, and how that program is
//! handed one.
//!
//! # Why a request may name an interpreter at all
//!
//! Because agents were doing it anyway, through the shell, and the shell is
//! the wrong place for a reader to meet it. A request to run twenty lines of
//! Python arrives as `bash -c` wrapping `python3 - <<'PY' … PY`: two layers
//! of quoting over a program that is not shell, in a window whose whole job
//! is to show a person what will run. The heredoc's bounds are the scanner's
//! guess, the language is [`crate::render::language`]'s reading of a
//! convention, and the Python is one long string to everything in between.
//!
//! Naming the interpreter turns all three into facts. hatch builds the argv,
//! so it knows exactly which bytes are the program and what they are a
//! program for -- the same move [`super::elevate::ElevatedArgv::script_at`]
//! makes about a root command, for the same reason.
//!
//! # Why a table and not any program the request names
//!
//! Not for safety: `run_command` already runs anything, so this adds no
//! capability and takes none away. It is because hatch has to know *how* to
//! hand a program to an interpreter, and there is no convention -- `-c` for
//! Python and the shells, `-e` for Node, Ruby, Perl and Lua. A request naming
//! something not here is refused with the list, which is a sentence a reader
//! and an agent can both act on; guessing a flag would produce an argv that
//! fails at the far end with the reader having approved something that never
//! ran.
//!
//! Every flag here was run before it was written down -- spawned as the argv
//! hatch builds, with no shell in between and stdin closed, and checked for a
//! clean exit *and* an empty standard error. That second half is why
//! `clojure` carries `-M -e` rather than the `-e` it also accepts: the short
//! form works and warns that it is deprecated, onto the stream the command's
//! own diagnostics come back on. `php -r` is absent because php is not
//! installed on the machine this was written on -- plausible, and not
//! checked.

use crate::render::language::Language;

/// An interpreter a request may name, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interpreter {
    program: String,
    /// What goes between the program and the program text. Usually one
    /// option; `clojure` takes two, because the one-option form it also
    /// accepts prints a deprecation warning onto the command's own stderr --
    /// which a reader would read as the command's.
    flags: &'static [&'static str],
    language: Language,
}

/// The interpreters hatch knows how to hand a program to.
///
/// Keyed by the *stem* of the name -- what is left after a directory, a
/// version suffix and the `.exe` nobody writes here -- so `python3`,
/// `python3.12` and `/usr/bin/python3` are one entry and none of them is
/// rewritten into another. See [`Interpreter::named`].
const KNOWN: &[(&str, &[&str], Language)] = &[
    ("bash", &["-c"], Language::Shell),
    ("sh", &["-c"], Language::Shell),
    ("zsh", &["-c"], Language::Shell),
    ("python", &["-c"], Language::Python),
    ("node", &["-e"], Language::JavaScript),
    ("ruby", &["-e"], Language::Ruby),
    ("perl", &["-e"], Language::Perl),
    ("lua", &["-e"], Language::Lua),
    ("bb", &["-e"], Language::Clojure),
    // `-M -e` and not the `-e` this also accepts: the short form works and
    // warns that it is deprecated, and the warning lands on the command's own
    // standard error, where a reader has every reason to read it as the
    // command's. `bb` needs no such thing.
    ("clojure", &["-M", "-e"], Language::Clojure),
    ("clj", &["-M", "-e"], Language::Clojure),
];

impl Interpreter {
    /// The interpreter a request means by `name`, or nothing.
    ///
    /// The program is kept **as the request wrote it** and only the flag and
    /// the language are looked up. A request naming `python3.12` gets
    /// `python3.12`, not whatever `python` resolves to today: substituting a
    /// neighbouring binary for the one that was named is the one thing a
    /// window about to run something must not do quietly, and the reader
    /// would have no way to see it, because the line is rendered from the
    /// argv hatch is about to spawn.
    pub fn named(name: &str) -> Option<Interpreter> {
        let stem = name
            .rsplit('/')
            .next()?
            .trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
        let (_, flags, language) = KNOWN.iter().find(|(known, _, _)| *known == stem)?;
        Some(Interpreter { program: name.to_string(), flags, language: *language })
    }

    /// The shell every request gets when it names no interpreter.
    ///
    /// The same `bash -c` [`super::shell_argv`] has always produced, spelled
    /// here so that the default and the named case are one code path and
    /// cannot come to build different argvs.
    pub fn shell() -> Interpreter {
        Interpreter { program: "bash".to_string(), flags: &["-c"], language: Language::Shell }
    }

    /// What the program is written in.
    pub fn language(&self) -> Language {
        self.language
    }

    /// The program name, as the request wrote it.
    pub fn program(&self) -> &str {
        &self.program
    }

    /// `<program> <flags…> <source>` -- the argv that runs `source`.
    ///
    /// Separate arguments, never a concatenation: the program travels as a
    /// single `execve` argument from here to the interpreter that reads it,
    /// so every quote, space and newline in it is data rather than structure
    /// some layer in between already acted on. [`super::shell_argv`]'s note,
    /// generalised.
    pub fn argv(&self, source: &str) -> Vec<String> {
        let mut argv = Vec::with_capacity(self.flags.len() + 2);
        argv.push(self.program.clone());
        argv.extend(self.flags.iter().map(|flag| (*flag).to_string()));
        argv.push(source.to_string());
        argv
    }

    /// Where `source` sits in the argv this produces.
    ///
    /// Always last, which is what [`super::last_argument_at`] relies on, and
    /// said here rather than left as `len() - 1` at each of the places that
    /// have to agree about it.
    pub fn source_at(&self) -> usize {
        self.flags.len() + 1
    }

    /// Every name a request may use, for the sentence that refuses the
    /// others.
    pub fn known() -> Vec<&'static str> {
        KNOWN.iter().map(|(name, _, _)| *name).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_named_interpreter_runs_the_program_that_was_named() {
        // Not the stem, and not a neighbour of it. The stem is how the flag
        // is found; it is never what gets spawned.
        for name in ["python3", "python3.12", "/usr/bin/python3"] {
            let found = Interpreter::named(name).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(found.program(), name);
            assert_eq!(found.language(), Language::Python);
            assert_eq!(found.argv("print(1)"), vec![name, "-c", "print(1)"]);
        }
    }

    #[test]
    fn each_interpreter_is_handed_a_program_the_way_that_program_takes_one() {
        // There is no convention, which is the whole reason this is a table.
        // Every one of these was run before it was written down.
        assert_eq!(Interpreter::named("node").unwrap().argv("x")[1], "-e");
        assert_eq!(Interpreter::named("ruby").unwrap().argv("x")[1], "-e");
        assert_eq!(Interpreter::named("perl").unwrap().argv("x")[1], "-e");
        assert_eq!(Interpreter::named("lua").unwrap().argv("x")[1], "-e");
        assert_eq!(Interpreter::named("bash").unwrap().argv("x")[1], "-c");
        assert_eq!(Interpreter::named("sh").unwrap().argv("x")[1], "-c");
        assert_eq!(Interpreter::named("bb").unwrap().argv("x")[1], "-e");
        // Two options, and the reason is not style: `clojure -e` runs and
        // warns that it is deprecated, onto the command's own stderr.
        assert_eq!(Interpreter::named("clojure").unwrap().argv("x"), vec!["clojure", "-M", "-e", "x"]);
        assert_eq!(Interpreter::named("clj").unwrap().argv("x"), vec!["clj", "-M", "-e", "x"]);
    }

    #[test]
    fn the_program_is_the_last_argument_however_many_options_precede_it() {
        // `last_argument_at` rests on this, and it is the one thing a
        // multi-option entry could quietly break.
        for name in ["bash", "python3", "node", "bb", "clojure", "clj"] {
            let found = Interpreter::named(name).unwrap_or_else(|| panic!("{name}"));
            let argv = found.argv("<the program>");
            assert_eq!(argv.last().map(String::as_str), Some("<the program>"), "{name}");
            assert_eq!(argv[found.source_at()], "<the program>", "{name}");
            assert_eq!(argv.len(), found.source_at() + 1, "{name}");
        }
    }

    #[test]
    fn a_name_that_is_not_here_is_not_guessed_at() {
        // A flag nobody checked builds an argv that fails at the far end,
        // with the reader having approved something that never ran.
        for name in ["php", "Rscript", "psql", "rm", "", "/", "env python3"] {
            assert_eq!(Interpreter::named(name), None, "{name} was guessed at");
        }
    }

    #[test]
    fn the_default_is_the_shell_every_request_already_got() {
        let shell = Interpreter::shell();
        assert_eq!(shell.argv("ls -l"), crate::exec::shell_argv("ls -l"));
        assert_eq!(shell.language(), Language::Shell);
    }

    #[test]
    fn the_source_is_where_both_halves_say_it_is() {
        let node = Interpreter::named("node").unwrap();
        let argv = node.argv("console.log(1)");
        assert_eq!(argv[node.source_at()], "console.log(1)");
        assert_eq!(argv.len(), node.source_at() + 1);
    }
}
