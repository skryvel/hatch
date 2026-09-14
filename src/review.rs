//! Reviewing a command's output before the agent receives it: what the person
//! may do to it, and what the agent is told about what they did.
//!
//! # Why this exists
//!
//! Approving a command used to mean its whole output reached the agent, and
//! through the agent the model provider behind it. There was no way to
//! approve `cat` on a file with one secret in it. A person who ticks "Show me
//! the output before it is sent" gets the output on their own screen first,
//! shapes it, and sends what they are willing to send. It is a privacy
//! control, and every rule below is shaped by that rather than by convenience.
//!
//! # The person approves a result, never a transformation
//!
//! The same principle the patch form of a write follows. A filter is a way of
//! producing the text, and what is on the screen when Send is pressed is the
//! text itself — the lines that will go, drawn as they will go. Nobody is
//! asked to predict what `error` will match across five hundred lines.
//!
//! # Plain text, not a pattern language
//!
//! A pattern is a substring, matched without regard to case. It is not a
//! regular expression, and that is decided for the person typing it: a
//! reader under time pressure who types `a.b` means the three characters,
//! and a `.` that matched anything would keep or drop lines they never
//! meant. For a drop filter that is harmless in one direction and useless in
//! the other; for a keep filter it is a line they wanted hidden kept. Plain
//! text has no such surprise, and the result is on screen before anything is
//! sent in either case.
//!
//! Case is ignored because the thing being hidden is spelled every way there
//! is: `password`, `Password:` and `PASSWORD=` are one secret to the person
//! typing the filter.
//!
//! Matching goes through the `regex` crate anyway, on the escaped pattern.
//! Its matching is linear in the text, so no pattern and no output can hang
//! the window, and it knows Unicode's simple case folding where a hand-rolled
//! lower-casing would not.
//!
//! # What the agent is told
//!
//! [`Trimmed`] is how one section of the released output relates to what was
//! captured, and it is worked out by the daemon from the two texts — never
//! taken from the window's word for it. So trimmed output is labelled as
//! trimmed whatever the window claims, and the one claim the window makes that
//! reaches the agent, the keep patterns, is named only when the released text
//! really is limited to lines containing them. See [`Trimmed::of`].
//!
//! The labels themselves are [`heading`], and their rule is the brief of the
//! whole feature: say how the agent's view differs from the output in a way
//! it can act on, and never in a way that reconstructs what was taken. A keep
//! pattern may be named — "lines containing `error`" says nothing about what
//! else there was. A drop pattern must not be: "lines containing `password`
//! were removed" announces the very lines the person removed them to hide. So
//! a removal is said to have happened and nothing more, and a hand edit is
//! said to be an edit and nothing more.

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

/// The longest pattern a person may type, in bytes.
///
/// A filter is a word or a phrase. The bound exists because the pattern is
/// compiled, case-insensitively, into an automaton whose size grows with it,
/// and a pattern too large to compile would be a filter that silently matched
/// nothing — in a drop filter, a secret left in.
pub const MAX_PATTERN_BYTES: usize = 200;

/// The most patterns one filter may hold.
///
/// Generous for a person and bounded for a frame: the keep patterns cross the
/// pipe back to the daemon, and a list with no end is a frame with no end.
pub const MAX_PATTERNS: usize = 32;

/// The parts a command's output comes in, in the shape the run gave it.
///
/// Two shapes and never a mixture, for the reason the tool result has two: a
/// command run without a terminal wrote to two pipes, and a diagnostic on
/// standard error is not part of its answer; a command run in a terminal wrote
/// to one stream that also holds what the person typed, and splitting it
/// would be claiming a separation the run did not have. Everything that reads
/// or shapes output here does it section by section, so the two pipes stay
/// apart through the whole of a review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Sections<T> {
    /// A run without a terminal: its two pipes.
    Streams {
        /// Standard output.
        stdout: T,
        /// Standard error.
        stderr: T,
    },
    /// A run in a terminal: the one transcript.
    Transcript {
        /// Everything that appeared in the terminal.
        transcript: T,
    },
}

/// Which section of the output one piece of text is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Section {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// A terminal's transcript.
    Transcript,
}

impl Section {
    /// The name the tool result gives it, and the name the window captions it
    /// with: one word for one thing in both places.
    pub fn name(self) -> &'static str {
        match self {
            Section::Stdout => "stdout",
            Section::Stderr => "stderr",
            Section::Transcript => "transcript",
        }
    }
}

impl<T> Sections<T> {
    /// Every section, in the order the tool result prints them.
    pub fn iter(&self) -> impl Iterator<Item = (Section, &T)> {
        let parts: Vec<(Section, &T)> = match self {
            Sections::Streams { stdout, stderr } => {
                vec![(Section::Stdout, stdout), (Section::Stderr, stderr)]
            }
            Sections::Transcript { transcript } => vec![(Section::Transcript, transcript)],
        };
        parts.into_iter()
    }

    /// The same shape, with every section made into something else.
    pub fn map<U>(&self, mut f: impl FnMut(Section, &T) -> U) -> Sections<U> {
        match self {
            Sections::Streams { stdout, stderr } => Sections::Streams {
                stdout: f(Section::Stdout, stdout),
                stderr: f(Section::Stderr, stderr),
            },
            Sections::Transcript { transcript } => {
                Sections::Transcript { transcript: f(Section::Transcript, transcript) }
            }
        }
    }

    /// Pair this with `other` section by section, or `None` when the two are
    /// not the same shape.
    ///
    /// `None` is not a case to paper over. Released output shaped differently
    /// from the output that was captured is a window answering some other
    /// review, and the daemon releases nothing on it.
    pub fn zip<'a, U>(&'a self, other: &'a Sections<U>) -> Option<Vec<(Section, &'a T, &'a U)>> {
        match (self, other) {
            (
                Sections::Streams { stdout: a, stderr: b },
                Sections::Streams { stdout: c, stderr: d },
            ) => Some(vec![(Section::Stdout, a, c), (Section::Stderr, b, d)]),
            (Sections::Transcript { transcript: a }, Sections::Transcript { transcript: b }) => {
                Some(vec![(Section::Transcript, a, b)])
            }
            _ => None,
        }
    }
}

/// One section of output as hatch captured it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Captured {
    /// The text, decoded exactly as the tool result would carry it.
    pub text: String,
    /// Whether hatch's output cap cut it short.
    ///
    /// Carried so the review screen can say so. A person trimming what they
    /// believe is the whole output, when it is the first quarter of a
    /// megabyte, is deciding about text they have not been shown.
    pub truncated: bool,
}

/// The lines of `text`, each with its terminator.
///
/// Terminators kept, so that the lines of a text joined back together are the
/// text: a filter that removes nothing gives back the output byte for byte,
/// and a last line with no newline stays a last line with no newline.
pub fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.split_inclusive('\n')
}

/// Why a filter could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    /// A pattern longer than [`MAX_PATTERN_BYTES`].
    TooLong,
    /// More patterns than [`MAX_PATTERNS`].
    TooMany,
    /// A pattern the matcher could not be built from, which within the bound
    /// above should not happen; refused rather than dropped, for the reason
    /// [`MAX_PATTERN_BYTES`] gives.
    Unbuildable,
}

/// A set of plain-text patterns, any one of which is enough for a line to
/// match.
///
/// See the module docs for why a pattern is a substring and why case is
/// ignored.
#[derive(Debug, Clone)]
pub struct Matcher {
    patterns: Vec<Regex>,
}

impl Matcher {
    /// A matcher over `patterns`. Patterns that are empty or only whitespace
    /// are left out: an empty substring is in every line, and a filter that
    /// matched everything because a field had a space in it would be a keep
    /// that kept all or a drop that dropped all by accident.
    ///
    /// # Errors
    ///
    /// Too many patterns, or one too long. Refused, not trimmed to fit: a
    /// drop filter quietly missing its last pattern is a secret left in.
    pub fn new<S: AsRef<str>>(patterns: &[S]) -> Result<Matcher, PatternError> {
        let meaningful: Vec<&str> =
            patterns.iter().map(AsRef::as_ref).filter(|p| !p.trim().is_empty()).collect();
        if meaningful.len() > MAX_PATTERNS {
            return Err(PatternError::TooMany);
        }
        let mut built = Vec::with_capacity(meaningful.len());
        for pattern in meaningful {
            if pattern.len() > MAX_PATTERN_BYTES {
                return Err(PatternError::TooLong);
            }
            let regex = RegexBuilder::new(&regex::escape(pattern))
                .case_insensitive(true)
                .build()
                .map_err(|_| PatternError::Unbuildable)?;
            built.push(regex);
        }
        Ok(Matcher { patterns: built })
    }

    /// A matcher with no patterns, which matches nothing.
    pub fn none() -> Matcher {
        Matcher { patterns: Vec::new() }
    }

    /// Whether this matcher has any patterns at all.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Whether `line` contains any of the patterns.
    pub fn matches(&self, line: &str) -> bool {
        self.patterns.iter().any(|pattern| pattern.is_match(line))
    }
}

/// The patterns that mean something, as they will be named: blank ones left
/// out, for the reason [`Matcher::new`] leaves them out.
pub fn meaningful<S: AsRef<str>>(patterns: &[S]) -> Vec<String> {
    patterns
        .iter()
        .map(AsRef::as_ref)
        .filter(|pattern| !pattern.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// `text` with only the lines `keep` matches, when it has patterns, and
/// without the lines `drop` matches.
///
/// Keep first and drop second, which is the only order in which both mean
/// what they say: "only lines about errors, and not the one with the token
/// in it".
pub fn filter(text: &str, keep: &Matcher, drop: &Matcher) -> String {
    lines(text)
        .filter(|line| keep.is_empty() || keep.matches(line))
        .filter(|line| !drop.matches(line))
        .collect()
}

/// Whether every line of `part` is a line of `whole`, in the same order.
///
/// The test for "lines were removed and nothing else happened". Linear: a
/// line of `part` is looked for only after the one before it was found.
fn is_line_subsequence(part: &str, whole: &str) -> bool {
    let mut whole = lines(whole);
    lines(part).all(|wanted| whole.any(|line| line == wanted))
}

/// How one released section relates to the section that was captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trimmed {
    /// Nothing was taken out and nothing was changed.
    Whole,
    /// Only lines containing one of the keep patterns are left: exactly those
    /// lines, or — when `further` — some of them, with more removed besides.
    Kept {
        /// Whether lines the keep patterns matched were removed as well.
        further: bool,
    },
    /// Some lines were removed, and every line that is left is as it was.
    Removed,
    /// The text was changed: it is not a selection of the captured lines.
    Edited,
}

impl Trimmed {
    /// Work out what was done to `captured` to make `released`, from the two
    /// texts alone.
    ///
    /// `keep` is the window's claim about which keep patterns it applied, and
    /// it is believed only as far as the texts bear it out: a section is
    /// "limited to lines containing" the patterns only when every line of it
    /// is a line of the capture that contains one of them. A claim the texts
    /// do not support is not an error and not a reason to release less; it
    /// is simply not repeated to the agent, and the section is described by
    /// what can be seen instead.
    ///
    /// The window's other flags are not asked for at all. Whether a drop
    /// filter or a hand edit happened is read off the text, so a window that
    /// forgot to say, or said wrong, cannot make trimmed output read as whole.
    pub fn of(captured: &str, released: &str, keep: &Matcher) -> Trimmed {
        if captured == released {
            return Trimmed::Whole;
        }
        if !keep.is_empty() {
            let kept = filter(captured, keep, &Matcher::none());
            if released == kept {
                return Trimmed::Kept { further: false };
            }
            if is_line_subsequence(released, &kept) {
                return Trimmed::Kept { further: true };
            }
        }
        match is_line_subsequence(released, captured) {
            true => Trimmed::Removed,
            false => Trimmed::Edited,
        }
    }

    /// Whether the agent's view of this section is not the captured text.
    pub fn is_trimmed(self) -> bool {
        self != Trimmed::Whole
    }
}

/// The heading a released section is printed under in the tool result.
///
/// The plain `stdout:` for a section that is whole, so that an agent reading
/// a reviewed run that nobody trimmed reads the result it always has. Every
/// other heading starts with the section's name and says `trimmed` before it
/// says anything else, so that the one word an agent must not miss is the
/// one nearest the output.
///
/// Keep patterns are quoted with Rust's debug quoting, which is also how a
/// pattern containing a quote or a control character stays one legible
/// string. Nothing about a drop filter or an edit is ever passed in here, and
/// that is how this function cannot name one.
pub fn heading(section: Section, trimmed: Trimmed, kept: &[String]) -> String {
    let name = section.name();
    match trimmed {
        Trimmed::Whole => format!("{name}:"),
        Trimmed::Kept { further } => {
            let patterns = kept.iter().map(|p| format!("{p:?}")).collect::<Vec<_>>().join(" or ");
            match further {
                false => format!(
                    "{name} (trimmed by the user: only lines containing {patterns}, ignoring \
                     case, are shown; the other lines were removed):"
                ),
                true => format!(
                    "{name} (trimmed by the user: only lines containing {patterns}, ignoring \
                     case, are shown, and some of those were removed as well):"
                ),
            }
        }
        Trimmed::Removed => format!("{name} (trimmed by the user: lines were removed):"),
        Trimmed::Edited => format!(
            "{name} (trimmed by the user: edited by hand, so lines may be missing or changed):"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(patterns: &[&str]) -> Matcher {
        Matcher::new(patterns).expect("a matcher")
    }

    fn none() -> Matcher {
        matcher(&[])
    }

    const OUTPUT: &str = "starting\nerror: disk full\npassword=hunter2\nERROR again\nwarn: slow\ndone";

    #[test]
    fn a_pattern_is_the_characters_typed_and_not_a_language() {
        // `a.b` is three characters. A reader who typed it did not mean "a,
        // anything, b", and a keep filter that read it that way would keep a
        // line they never asked for.
        let dotted = matcher(&["a.b"]);
        assert!(dotted.matches("the a.b line\n"));
        assert!(!dotted.matches("the axb line\n"), "a dot matched a character that is not a dot");
        for special in ["(", "[", "*", "+", "?", "\\", "^", "$", "|"] {
            let m = matcher(&[special]);
            assert!(m.matches(&format!("x{special}y")), "{special} is not matched as itself");
            assert!(!m.matches("plain words"), "{special} matched as an operator");
        }
    }

    #[test]
    fn case_is_ignored_because_a_secret_is_spelled_every_way_there_is() {
        let m = matcher(&["password"]);
        for line in ["password=1", "Password: 1", "PASSWORD 1", "db_PassWord"] {
            assert!(m.matches(line), "{line:?} escaped a drop filter over its case");
        }
    }

    #[test]
    fn a_blank_pattern_matches_nothing_rather_than_everything() {
        // A field with a space in it must not turn into a keep that keeps
        // all or a drop that drops all.
        let m = matcher(&["", "   "]);
        assert!(m.is_empty());
        assert_eq!(filter(OUTPUT, &none(), &m), OUTPUT);
        assert!(meaningful(&["", " ", "error"]) == vec!["error".to_string()]);
    }

    #[test]
    fn a_filter_too_large_to_hold_is_refused_and_not_shortened() {
        let long = "x".repeat(MAX_PATTERN_BYTES + 1);
        assert_eq!(Matcher::new(&[long]).err(), Some(PatternError::TooLong));
        let many: Vec<String> = (0..=MAX_PATTERNS).map(|n| format!("p{n}")).collect();
        assert_eq!(Matcher::new(&many).err(), Some(PatternError::TooMany));
        assert!(Matcher::new(&["x".repeat(MAX_PATTERN_BYTES)]).is_ok());
    }

    #[test]
    fn keep_keeps_only_matching_lines_and_drop_removes_them() {
        assert_eq!(
            filter(OUTPUT, &matcher(&["error", "warn"]), &none()),
            "error: disk full\nERROR again\nwarn: slow\n"
        );
        assert_eq!(
            filter(OUTPUT, &none(), &matcher(&["password"])),
            "starting\nerror: disk full\nERROR again\nwarn: slow\ndone"
        );
        // Both: keep first, then drop.
        assert_eq!(
            filter(OUTPUT, &matcher(&["error"]), &matcher(&["again"])),
            "error: disk full\n"
        );
    }

    #[test]
    fn a_filter_that_removes_nothing_gives_the_text_back_byte_for_byte() {
        for text in ["", "no newline", "one\n", "\n\n", "a\r\nb\r\n", "last line\nhas none"] {
            assert_eq!(filter(text, &none(), &none()), text);
            assert_eq!(Trimmed::of(text, &filter(text, &none(), &none()), &none()), Trimmed::Whole);
        }
    }

    #[test]
    fn what_was_done_is_read_off_the_two_texts() {
        let keep = matcher(&["error"]);
        let kept = filter(OUTPUT, &keep, &none());
        assert_eq!(Trimmed::of(OUTPUT, OUTPUT, &keep), Trimmed::Whole);
        assert_eq!(Trimmed::of(OUTPUT, &kept, &keep), Trimmed::Kept { further: false });
        assert_eq!(
            Trimmed::of(OUTPUT, "error: disk full\n", &keep),
            Trimmed::Kept { further: true }
        );
        let dropped = filter(OUTPUT, &none(), &matcher(&["password"]));
        assert_eq!(Trimmed::of(OUTPUT, &dropped, &none()), Trimmed::Removed);
        let edited = OUTPUT.replace("hunter2", "…");
        assert_eq!(Trimmed::of(OUTPUT, &edited, &none()), Trimmed::Edited);
        assert_eq!(Trimmed::of(OUTPUT, "", &none()), Trimmed::Removed);
    }

    #[test]
    fn a_keep_claim_the_text_does_not_bear_out_is_not_repeated() {
        // The window says it kept lines containing `error`, and what it sent
        // has a line that does not. That section is not described as limited
        // to `error` lines: it is described by what can be seen.
        let keep = matcher(&["error"]);
        assert_eq!(Trimmed::of(OUTPUT, "starting\nerror: disk full\n", &keep), Trimmed::Removed);
        // And a line that was never in the output is an edit, whatever was
        // claimed about filters.
        assert_eq!(Trimmed::of(OUTPUT, "error: invented\n", &keep), Trimmed::Edited);
    }

    #[test]
    fn a_repeated_line_cannot_be_released_more_times_than_it_was_printed() {
        let captured = "same\nother\n";
        assert_eq!(Trimmed::of(captured, "same\nsame\n", &none()), Trimmed::Edited);
        assert_eq!(Trimmed::of("same\nsame\n", "same\n", &none()), Trimmed::Removed);
    }

    #[test]
    fn reordered_lines_are_an_edit_and_not_a_removal() {
        assert_eq!(Trimmed::of("a\nb\n", "b\na\n", &none()), Trimmed::Edited);
    }

    #[test]
    fn a_heading_names_keep_patterns_and_never_anything_about_a_removal() {
        let kept = vec!["error".to_string(), "wa\"rn".to_string()];
        let heading_kept = heading(Section::Stdout, Trimmed::Kept { further: false }, &kept);
        assert!(heading_kept.starts_with("stdout (trimmed"), "{heading_kept}");
        assert!(heading_kept.contains("\"error\" or \"wa\\\"rn\""), "{heading_kept}");
        assert_eq!(heading(Section::Stderr, Trimmed::Whole, &kept), "stderr:");
        for trimmed in [Trimmed::Removed, Trimmed::Edited] {
            let said = heading(Section::Transcript, trimmed, &kept);
            assert!(said.starts_with("transcript (trimmed by the user"), "{said}");
            assert!(!said.contains("error"), "a heading with no keep in it named a pattern: {said}");
        }
    }

    #[test]
    fn sections_of_different_shapes_do_not_pair() {
        let streams = Sections::Streams { stdout: 1, stderr: 2 };
        let transcript = Sections::Transcript { transcript: 3 };
        assert!(streams.zip(&transcript).is_none());
        assert_eq!(
            streams.zip(&streams).map(|pairs| pairs.len()),
            Some(2),
            "two streams did not pair section by section"
        );
        let names: Vec<_> = streams.iter().map(|(section, _)| section.name()).collect();
        assert_eq!(names, ["stdout", "stderr"]);
    }
}
