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
//! # A redaction is a regular expression, and why that is not a contradiction
//!
//! A filter takes whole lines. It cannot take a token out of the middle of a
//! line whose rest is the reason the output is being sent at all, and a
//! reader who had only filters had to choose between losing the line and
//! sending the token. A redaction is the third thing: what it matches is
//! replaced by [`REDACTION`], and everything else on the line goes as it was.
//!
//! It is a pattern language where a filter is plain text, and the reason is
//! the shape of what each one is aimed at. A filter is aimed at a word its
//! reader can see on the screen — `password` — and they type what they see.
//! A redaction is aimed at something they cannot type, because it is a
//! different run of characters every time: a token, a key, an address.
//! `[0-9a-f]{32}` is the only way to say that, and a substring cannot say it
//! at all. The hazard the plain-text rule guards against is also the other
//! way round here. A `.` that matches more than its reader meant takes more
//! out, which is the safe direction, and what is on the screen is what is
//! sent, so the surprise is in front of them before anything moves.
//!
//! Case is ignored, as it is for a filter and for the same reason. `(?-i)`
//! turns that off for a reader who needs it.
//!
//! # What a redaction cannot do
//!
//! It is applied to one line's content at a time, never to the text as a
//! whole, so no pattern can join two lines, remove one, or eat the characters
//! that end it. The number of lines under a redaction is the number over it,
//! and the caption's "n of m lines" stays true whatever is typed. Matches
//! that overlap or touch become one [`REDACTION`], and a match of no
//! characters is not a match: `x*` would otherwise put a marker between every
//! two characters in the output.
//!
//! The marker is one fixed string however much or little it stands for, so
//! that the length of what was taken is not left behind in the length of what
//! replaced it. Patterns are matched against the line as it was captured
//! rather than one after another over each other's output, so a marker is
//! never redacted again and never becomes part of a later match.
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
//!
//! A redaction is not named either, for the drop pattern's reason doubled:
//! `[0-9a-f]{32}` announces both that something was taken and the shape of
//! the thing. Its patterns never leave the window at all — the keep patterns
//! are the only ones that cross the pipe — and a redacted section reads to
//! the daemon as [`Trimmed::Edited`], because from the two texts alone that
//! is exactly what it is.

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

/// The longest pattern a person may type, in bytes.
///
/// A filter is a word or a phrase, and a redaction is a short expression.
/// The bound exists because the pattern is compiled, case-insensitively, into
/// an automaton whose size grows with it, and a pattern too large to compile
/// would be a filter that silently matched nothing — in a drop filter or a
/// redaction, a secret left in.
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
    /// A redaction the `regex` crate would not build, with what it said about
    /// it in one line: a bracket left open, or an expression that compiles to
    /// more than [`REDACTION_SIZE_LIMIT`].
    ///
    /// Only a redaction can fail this way. A filter's pattern is escaped
    /// before it is compiled, so there is nothing in it left to be malformed;
    /// a redaction is compiled as written, and a reader mistyping a bracket
    /// is the everyday case rather than the impossible one.
    Refused(String),
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

/// What a redaction puts in place of everything it matched.
///
/// One fixed string, the same however much or little it stands for: a marker
/// as long as the text it replaced would leave the length of a secret behind
/// in the shape of the line. It names itself rather than being blank because
/// an agent reading a line that makes no sense without its value is better
/// off knowing a value was withheld than guessing at one.
pub const REDACTION: &str = "[redacted]";

/// How large a redaction may be once compiled.
///
/// The crate's matching is linear in the text, so no pattern can hang the
/// window by running. What a pattern can do is be large: nested repetition
/// compiles to something far bigger than the bytes it was typed in, and this
/// is rebuilt on every keystroke in the field. A megabyte is past anything a
/// person writes by hand and short of anything that costs a frame.
pub const REDACTION_SIZE_LIMIT: usize = 1 << 20;

/// A set of regular expressions whose matches are taken out of the lines that
/// stay.
///
/// See the module docs for why this is a pattern language where a filter is
/// not, and for what a redaction cannot do to a line.
#[derive(Debug, Clone)]
pub struct Redactor {
    patterns: Vec<Regex>,
}

impl Redactor {
    /// A redactor over `patterns`, each compiled as it was written. Patterns
    /// that are empty or only whitespace are left out, for the reason
    /// [`Matcher::new`] leaves them out.
    ///
    /// # Errors
    ///
    /// Too many patterns, or one too long — refused and not trimmed to fit,
    /// for [`Matcher::new`]'s reason. And [`PatternError::Refused`] for one
    /// that does not compile, which is refused for the same reason again: a
    /// redaction that was quietly dropped is the secret it named, sent.
    pub fn new<S: AsRef<str>>(patterns: &[S]) -> Result<Redactor, PatternError> {
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
            let regex = RegexBuilder::new(pattern)
                .case_insensitive(true)
                .size_limit(REDACTION_SIZE_LIMIT)
                .build()
                .map_err(|error| PatternError::Refused(why_refused(&error)))?;
            built.push(regex);
        }
        Ok(Redactor { patterns: built })
    }

    /// A redactor with no patterns, which redacts nothing.
    pub fn none() -> Redactor {
        Redactor { patterns: Vec::new() }
    }

    /// Whether this redactor has any patterns at all.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// The stretches of `body` to be replaced: every pattern's matches over
    /// the line as it was captured, in order, with overlapping and touching
    /// ones merged into one.
    ///
    /// Merged, so two patterns that hit the same token leave one marker and
    /// not a row of them. Taken over the captured line rather than by running
    /// each pattern over the last one's output, so a marker is never redacted
    /// again and never joins a later match.
    fn spans(&self, body: &str) -> Vec<(usize, usize)> {
        let mut found: Vec<(usize, usize)> = self
            .patterns
            .iter()
            .flat_map(|pattern| pattern.find_iter(body))
            // A match of no characters is not a match. `x*` matches between
            // every two characters of every line, and a marker at each would
            // be an output nobody can read that hid nothing at all.
            .filter(|matched| matched.start() < matched.end())
            .map(|matched| (matched.start(), matched.end()))
            .collect();
        found.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(found.len());
        for (start, end) in found {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        merged
    }
}

/// What the person is told about a pattern the `regex` crate refused, in one
/// line.
///
/// The crate's own message is several lines, with the pattern and a caret
/// under the character it stopped at, which is more than a label under a
/// field can hold. Its last line is the sentence that says what is wrong.
fn why_refused(error: &regex::Error) -> String {
    let said = error.to_string();
    let last = said.lines().rev().find(|line| !line.trim().is_empty()).unwrap_or("").trim();
    match last.strip_prefix("error: ") {
        Some(rest) => rest.to_string(),
        None if last.is_empty() => "it is not a regular expression".to_string(),
        None => last.to_string(),
    }
}

/// A text with its redactions made, and how many of its lines they changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redacted {
    /// The text, as it will be sent.
    pub text: String,
    /// How many of its lines a redaction changed.
    ///
    /// For the screen and never for the answer. A pattern that matches
    /// nothing leaves a result identical to one with no redaction on it, and
    /// the reader who typed it to hide a token would have no way to tell that
    /// it missed — the hazard [`MAX_PATTERN_BYTES`] is bounded against,
    /// arriving by the other door. This count is the answer to "did that do
    /// anything", and it is the one thing on the screen that is about the
    /// redaction rather than about the text.
    pub lines: usize,
}

/// `text` with everything `redactor` matches replaced by [`REDACTION`].
///
/// Line by line, over each line's content only: see the module docs for what
/// that rules out. The characters that end a line are not part of what is
/// matched, so no pattern can join two lines or change how one of them ends.
pub fn redact(text: &str, redactor: &Redactor) -> Redacted {
    if redactor.is_empty() {
        return Redacted { text: text.to_string(), lines: 0 };
    }
    let mut out = String::with_capacity(text.len());
    let mut changed = 0;
    for line in lines(text) {
        let (body, ending) = split_ending(line);
        let spans = redactor.spans(body);
        if spans.is_empty() {
            out.push_str(line);
            continue;
        }
        changed += 1;
        let mut cursor = 0;
        for (start, end) in spans {
            out.push_str(&body[cursor..start]);
            out.push_str(REDACTION);
            cursor = end;
        }
        out.push_str(&body[cursor..]);
        out.push_str(ending);
    }
    Redacted { text: out, lines: changed }
}

/// A line split into its content and the characters that end it.
///
/// `\r\n` comes off whole. Stripping only the newline would leave the return
/// at the end of the content, where `.*` matches it, and a redaction would
/// quietly turn a CRLF line into an LF one.
fn split_ending(line: &str) -> (&str, &str) {
    if let Some(body) = line.strip_suffix("\r\n") {
        return (body, "\r\n");
    }
    match line.strip_suffix('\n') {
        Some(body) => (body, "\n"),
        None => (line, ""),
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
/// string. Nothing about a drop filter, a redaction or an edit is ever passed
/// in here, and that is how this function cannot name one.
///
/// [`Trimmed::Edited`] says the text was edited and not how, because the two
/// ways of arriving there — a hand edit and a redaction — are one thing in
/// the texts this is worked out from, and naming either would be the window's
/// word for something the daemon cannot see.
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
            "{name} (trimmed by the user: the text was edited, so lines may be missing or \
             changed):"
        ),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

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

    fn redactor(patterns: &[&str]) -> Redactor {
        Redactor::new(patterns).expect("a redactor")
    }

    #[test]
    fn a_redaction_leaves_the_rest_of_the_line() {
        // The whole reason it exists: the line stays, the token goes.
        let out = redact(OUTPUT, &redactor(&["hunter\\d"]));
        assert_eq!(
            out.text,
            "starting\nerror: disk full\npassword=[redacted]\nERROR again\nwarn: slow\ndone"
        );
        assert_eq!(out.lines, 1, "one line was changed and the count says so");
    }

    #[test]
    fn a_redaction_is_a_pattern_where_a_filter_is_the_characters_typed() {
        // The deliberate opposite of the filters. `a.b` here is "a, anything,
        // b", because the thing a redaction is aimed at cannot be typed out.
        let dotted = redactor(&["a.b"]);
        assert_eq!(redact("the axb line\n", &dotted).text, "the [redacted] line\n");
        assert_eq!(redact("the a.b line\n", &dotted).text, "the [redacted] line\n");
        assert_eq!(redact("no match here\n", &dotted).lines, 0);
    }

    #[test]
    fn a_redaction_cannot_add_or_remove_a_line() {
        // Even a pattern that matches the whole of everything: it is applied
        // to one line's content, so the lines and their endings survive it.
        let greedy = redactor(&[".*"]);
        for text in ["", "no newline", "one\n", "\n\n", "a\r\nb\r\n", "last\nhas none"] {
            let out = redact(text, &greedy);
            assert_eq!(
                lines(&out.text).count(),
                lines(text).count(),
                "{text:?} came back with a different number of lines"
            );
            let endings: Vec<&str> = lines(text).map(|line| split_ending(line).1).collect();
            let after: Vec<&str> = lines(&out.text).map(|line| split_ending(line).1).collect();
            assert_eq!(after, endings, "{text:?} had a line ending changed");
        }
    }

    #[test]
    fn a_redaction_never_eats_the_characters_that_end_a_line() {
        // `.` matches a carriage return, so a CRLF line whose return was left
        // in its content would come back LF — a change to the bytes of a line
        // nobody asked to redact.
        assert_eq!(redact("a\r\nb\r\n", &redactor(&[".*"])).text, "[redacted]\r\n[redacted]\r\n");
        assert_eq!(redact("a\r\n", &redactor(&["a\r"])).text, "a\r\n", "the ending was matched into");
    }

    #[test]
    fn a_match_of_no_characters_redacts_nothing() {
        // `x*` matches between every two characters. A marker at each would
        // be an unreadable output that hid nothing.
        for pattern in ["x*", "z?", "(?:)"] {
            let out = redact("abc\n", &redactor(&[pattern]));
            assert_eq!(out.text, "abc\n", "{pattern:?} redacted where it matched nothing");
            assert_eq!(out.lines, 0);
        }
        // And a pattern that can match empty still redacts where it does match.
        assert_eq!(redact("abxxc\n", &redactor(&["x*"])).text, "ab[redacted]c\n");
    }

    #[test]
    fn matches_that_overlap_or_touch_become_one_marker() {
        assert_eq!(redact("password\n", &redactor(&["pass", "word"])).text, "[redacted]\n");
        assert_eq!(redact("password\n", &redactor(&["asswo", "sword"])).text, "p[redacted]\n");
        // Apart, and they stay apart.
        assert_eq!(redact("a b c\n", &redactor(&["a", "c"])).text, "[redacted] b [redacted]\n");
    }

    #[test]
    fn a_marker_is_never_redacted_again_or_matched_into() {
        // Patterns run over the line as it was captured. Run one after
        // another over each other's output, `re` would eat the marker `pass`
        // had just left behind.
        let out = redact("password\n", &redactor(&["pass", "re"]));
        assert_eq!(out.text, "[redacted]word\n");
        // And a marker does not become a new start of line for an anchor.
        assert_eq!(redact("aab\n", &redactor(&["^a"])).text, "[redacted]ab\n");
    }

    #[test]
    fn the_marker_is_one_length_whatever_it_stands_for() {
        let short = redact("k=1\n", &redactor(&["=.*"])).text;
        let long = redact("k=0123456789abcdef\n", &redactor(&["=.*"])).text;
        assert_eq!(short, long, "the length of the secret survived in the length of the marker");
    }

    #[test]
    fn case_is_ignored_in_a_redaction_too_and_can_be_asked_for() {
        assert_eq!(redact("TOKEN=x\n", &redactor(&["token"])).text, "[redacted]=x\n");
        assert_eq!(redact("TOKEN=x\n", &redactor(&["(?-i)token"])).lines, 0);
    }

    #[test]
    fn a_redaction_that_is_not_a_regular_expression_is_refused_and_said_in_one_line() {
        let Err(PatternError::Refused(why)) = Redactor::new(&["(unclosed"]) else {
            panic!("an unclosed group was accepted");
        };
        assert!(!why.contains('\n'), "the reason is more than a label can hold: {why:?}");
        assert!(!why.is_empty());
        // The bounds a filter has, a redaction has.
        assert_eq!(Redactor::new(&["x".repeat(MAX_PATTERN_BYTES + 1)]).err(), Some(PatternError::TooLong));
        let many: Vec<String> = (0..=MAX_PATTERNS).map(|n| format!("p{n}")).collect();
        assert_eq!(Redactor::new(&many).err(), Some(PatternError::TooMany));
        // A pattern that compiles to more than the limit is refused, not run.
        assert!(matches!(
            Redactor::new(&["((((a{100}){100}){100}){100})"]),
            Err(PatternError::Refused(_))
        ));
    }

    #[test]
    fn a_blank_redaction_changes_nothing_rather_than_everything() {
        let empty = redactor(&["", "   "]);
        assert!(empty.is_empty());
        assert_eq!(redact(OUTPUT, &empty).text, OUTPUT);
        assert_eq!(redact(OUTPUT, &Redactor::none()).text, OUTPUT);
    }

    #[test]
    fn a_redaction_reads_to_the_daemon_as_an_edit_and_is_never_named() {
        // It is not a selection of the captured lines, so it is an edit — the
        // same verdict a hand edit gets, from the texts alone.
        let redacted = redact(OUTPUT, &redactor(&["hunter\\d"])).text;
        assert_eq!(Trimmed::of(OUTPUT, &redacted, &none()), Trimmed::Edited);
        let said = heading(Section::Stdout, Trimmed::Edited, &[]);
        assert!(said.starts_with("stdout (trimmed by the user"), "{said}");
        for leak in ["hunter", "redact", "by hand"] {
            assert!(!said.contains(leak), "a heading said {leak:?} about an edit: {said}");
        }
        // A redaction that matched nothing changed nothing, and reads whole.
        let untouched = redact(OUTPUT, &redactor(&["nothing-like-this"])).text;
        assert_eq!(Trimmed::of(OUTPUT, &untouched, &none()), Trimmed::Whole);
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
    proptest! {
        /// The line structure is the redaction's to keep. Whatever a pattern
        /// matches, what comes out has the same lines in the same order,
        /// ending the same way — which is what lets the pane's "n of m lines"
        /// stay true with a redaction typed, and what stops a pattern from
        /// joining two lines into one the reader never read.
        #[test]
        fn a_redaction_never_changes_the_lines_a_text_has(
            text in "(?s)[a-z0-9=\r\n ]{0,200}",
            pattern in "[a-z0-9]{1,3}[*+?]?",
        ) {
            let redactor = Redactor::new(&[pattern]).expect("a redactor");
            let out = redact(&text, &redactor);
            prop_assert_eq!(lines(&out.text).count(), lines(&text).count());
            let before: Vec<&str> = lines(&text).map(|line| split_ending(line).1).collect();
            let after: Vec<&str> = lines(&out.text).map(|line| split_ending(line).1).collect();
            prop_assert_eq!(after, before);
            prop_assert!(out.lines <= lines(&text).count());
            prop_assert_eq!(out.lines == 0, out.text == text);
        }

        /// Nothing a pattern matched is still readable in what it left: every
        /// piece of the result either side of a marker is text the pattern
        /// does not match. Generated patterns are literals, with no anchor in
        /// them, because `^` means the start of the line it was matched
        /// against and a piece after a marker is not that — see
        /// `a_marker_is_never_redacted_again_or_matched_into` for the anchor.
        #[test]
        fn what_a_redaction_matched_is_not_in_what_it_leaves(
            line in "[a-z0-9= ]{0,60}",
            pattern in "[a-z0-9]{1,3}",
        ) {
            let out = redact(&line, &Redactor::new(&[pattern.as_str()]).expect("a redactor"));
            let same = RegexBuilder::new(&pattern).case_insensitive(true).build().unwrap();
            for piece in out.text.split(REDACTION) {
                prop_assert!(!same.is_match(piece), "{:?} still holds {:?}", piece, pattern);
            }
        }
    }
}
