//! Additive-only command segmentation, variable and binary annotation.
//!
//! A long command needs line breaks before a human can read it, and the
//! obvious way to get them is the wrong one. Earlier tools of this shape
//! replaced `;` with a newline: the display got shorter, the command lost a
//! character, and the reader lost the one thing the window is for. A display
//! that can silently delete one character can in principle delete any of
//! them, so a careful reader is right to stop trusting it on exactly the
//! gnarly commands where trust matters most.
//!
//! So segmentation here is **additive only**. It inserts layout *around*
//! separators and never removes them:
//!
//! * The separator stays on screen as a [`SpanKind::Separator`] span at the
//!   end of the segment it closes, drawn as itself and dimmed by the UI.
//! * The line break is [`Span::break_before`](super::Span::break_before) on
//!   the *following* span — metadata beside the text, not an edit to it.
//!
//! Nothing is trimmed either. `a; b` segments into `a`, `;`, ` b`: the space
//! that happens to follow the separator is part of the command and stays in
//! the rendering, leading position and all.
//!
//! # Quote awareness is honesty, not polish
//!
//! `echo 'a; b'` is one command with one argument. Splitting it at the `;`
//! would draw two apparent commands where the shell will run one, which is a
//! rendering that lies — and a lie in the direction of "looks more dangerous
//! than it is" is still a lie, because it teaches the reader that the
//! boundaries on screen are not the boundaries that run.
//!
//! So the scanner tracks quoting: separators are recognised only outside
//! quotes. It is not a shell parser and does not want to be. It answers one
//! question — *is this byte a command boundary?* — and **for the two
//! constructs it models, quoting and backslash escaping, it is wrong only in
//! the direction of finding no boundary.**
//!
//! That qualifier is load-bearing and an earlier draft of these docs left it
//! out, claiming flatly that the scanner never invents a boundary. It does.
//! The guarantee stops where the model stops, and the next section says
//! where that is in both directions — because a docs page that overstates
//! its own safety argument is the same failure as a display that overstates
//! what it shows.
//!
//! # Where the model stops, and what it costs
//!
//! Five separators — `;`, `&&`, `||`, `|`, a literal newline — plus quoting
//! and backslash escaping around them. The rest of shell grammar is outside
//! the model, and the cost falls in both directions.
//!
//! ## Under-segmentation: structure the shell has that the screen does not
//!
//! Backgrounding (`&`), subshells (`(`, `)`) and command substitution
//! (`` ` `` and `$(`) are not recognised. `sleep 60 & wait` draws as one
//! segment though the shell runs two; `(cd /tmp; rm -rf x)` splits at the `;`
//! but says nothing about the parentheses that nest it; `echo $(rm -rf /)`
//! draws the whole substitution inside one segment. `$(a; b)` is the case
//! worth naming for a later task: the `;` there really is a boundary, so it
//! is drawn at the wrong nesting level rather than fabricated.
//!
//! ## Over-segmentation: boundaries on screen the shell does not have
//!
//! A separator character that some unmodelled construct gives another meaning
//! to is split on anyway. Each of these was checked against a real shell:
//!
//! * `echo a # b; c` — `; c` is inside a comment.
//! * `echo $((1 || 0))` — arithmetic OR.
//! * `[[ -n x || -n y ]]` — conditional OR.
//! * `echo x >| out.txt` — `>|` is one redirection operator.
//! * `$'a\'b; c'` — ANSI-C quoting, where `\'` does not end the string, so
//!   the `;` is data.
//! * A heredoc whose body contains `a; b` — the body is data.
//! * `case x in a) echo 1;; esac` — `;;` is one `case` terminator, drawn as
//!   two separators.
//!
//! ## Why neither direction breaks an invariant
//!
//! Both hold throughout: every byte is on screen, drawn as itself, and
//! `unrender` still reproduces the command exactly. What is wrong in these
//! cases is the *layout*, and layout here is metadata — a reader who
//! distrusts a break can read straight through it and still see the command
//! that will run, which is the whole reason breaks are not characters.
//! Widening the model would move cases out of these two lists; it would not
//! change what either invariant guarantees.
//!
//! Both lists are pinned by tests — `structure_outside_the_five_separators_
//! is_left_unsegmented` and `over_segmentation_where_the_model_stops` — so a
//! change in either direction has to be a deliberate one.
//!
//! # Variables: the window resolves against the environment that will run
//!
//! [`annotate_variables`] tags each `$NAME` and hangs on it the value the
//! child will actually see. The environment is a parameter and there is no
//! default, because hatch **constructs** the child environment rather than
//! inheriting one and none of the environments lying around is it. The
//! daemon's came from wherever the daemon was started; the sandbox's is
//! agent-influenced; and `run0` resets the environment for a `root: true`
//! operation regardless. A `$HOME` resolved against `std::env` would print a
//! value that looks authoritative and is wrong — the worst failure available
//! to a display whose whole job is to be believed, and worse than printing
//! nothing, because nothing does not invite the reader to stop reading.
//!
//! Quoting decides *whether* to annotate, for the same reason it decides
//! where to split. `$HOME` expands in `Normal` and inside `"…"`; inside `'…'`
//! it is five characters of text and after a backslash it is a literal `$`.
//! Annotating those would announce a substitution that does not happen, which
//! is the mirror of splitting `echo 'a; b'` in two. Both questions are asked
//! of one `Scan`, so the two answers cannot disagree about the same byte.
//!
//! ## What `$` is claimed to mean
//!
//! Exactly `$NAME` and `${NAME}`, with `NAME` matching
//! `[A-Za-z_][A-Za-z0-9_]*`. [`super::variable_name`] is the definition, and
//! it lives in the span model rather than here so that the check the model
//! makes is not borrowed from the pass it is checking.
//!
//! Everything else stays `Plain`. Positional and special parameters (`$1`,
//! `$@`, `$?`, `$$`, `$*`, `$#`), brace expansions with a modifier
//! (`${HOME:-/tmp}`, `${#HOME}`), command and arithmetic substitution
//! (`$(id)`, `$((1+1))`) and an unterminated `${HOME` all substitute
//! something the child environment does not contain, so there is no value
//! this window could put beside them that would be true. Under-tagging costs
//! the reader a hint; a wrong value costs them the reason to read at all.
//!
//! Declining is not the same as ignoring: `dollar_extent` steps over the
//! whole of what it declines, so a rejected construct cannot be re-read as an
//! accepted one. `$$HOME` is the case — the shell reads `$$` and then the
//! literal `HOME`, and a pass that resumed one byte later would find `$HOME`
//! and announce an expansion that never happens.

use std::collections::BTreeMap;
use std::ops::Range;

use super::{SpanBuilder, SpanKind, Spans, unicode, variable_name};

/// The separator tokens, longest first.
///
/// The order is the whole of the longest-match rule: the scanner takes the
/// first entry that matches at the cursor, so anything that starts with a
/// shorter token has to come before it — `||` before `|`. Descending length
/// gives that for every such pair, and `separator_table_is_longest_first`
/// holds the table to it. Read the other way round, a shortest-first table
/// would report `||` as two pipes and double the boundaries on screen.
///
/// A bare `&` is deliberately absent — see the module docs — which is why the
/// prefix relationship matters at all: `&&&` matches `&&` and then leaves a
/// plain `&`.
const SEPARATORS: &[&str] = &["&&", "||", ";", "|"];

/// Where the scanner found one segment to end.
#[derive(Debug, PartialEq, Eq)]
enum Boundary {
    /// `;`, `&&`, `||` or `|` occupying this byte range. A token of its own:
    /// it is tagged [`SpanKind::Separator`] and kept on screen at the end of
    /// the segment it closes.
    Separator(Range<usize>),

    /// A literal newline ending at this byte offset. A boundary, but
    /// deliberately **not** a `Separator` span.
    ///
    /// Only a chip may be drawn as something other than itself, so a
    /// `Separator`-kinded U+000A would be drawn as a literal newline — and
    /// then a break on screen would no longer tell the reader whether it is
    /// layout or content, which is the exact ambiguity the whole design of
    /// `break_before` exists to avoid. Worse, the property tests would not
    /// notice: a non-chip span drawn as its own text satisfies invariant 1b
    /// by definition.
    ///
    /// So the newline is left to `unicode::classify_into`, which chips it as
    /// `[LF]` at the end of its segment, and this boundary contributes the
    /// break alone. The character is visible, the layout is metadata, and the
    /// two readings stay apart.
    Newline(usize),
}

/// What the scanner is inside of. Separators are recognised only in
/// [`Quoting::Normal`]; variable references, in `Normal` and `Double`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Quoting {
    Normal,
    /// Inside `'…'`, where nothing at all is special — not even a backslash.
    /// `'a\'` is a complete string, so honouring the escape here would leave
    /// the scanner believing a quote is still open and miss every boundary
    /// after it.
    Single,
    /// Inside `"…"`.
    Double,
}

/// One character of the command, together with the shell state it sits in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scanned {
    /// Byte offset of `ch` in the command.
    offset: usize,
    ch: char,
    /// The quoting in force *at* this character — what the characters before
    /// it left behind, before this one is applied. So the `'` that opens a
    /// string is reported as `Normal` and the one that closes it as `Single`,
    /// which is what a caller asking "is this byte special?" wants.
    quoting: Quoting,
    /// True when the preceding character was a live backslash, so this one is
    /// literal: it neither changes `quoting` nor begins a token.
    escaped: bool,
}

/// One left-to-right pass over the command, tracking quoting and one
/// backslash-escape flag. No backtracking, no nesting, no recursion: the
/// input is agent-controlled and this runs before a human is asked to approve
/// anything, so it is bounded by the length of the string and nothing else.
///
/// This is shared state, not a shared convenience. Two passes ask questions
/// of the same 25-line state machine — [`boundaries`] asks *is this byte a
/// command separator?* and [`references`] asks *does this `$` expand?* — and
/// the two answers have to come from one model or they can disagree with each
/// other about the same character. `'a; $HOME'` is the case that shows why:
/// both questions must answer no, for the same reason, and a second
/// hand-rolled quote tracker is exactly how one of them comes to answer yes.
///
/// # Backslash inside double quotes
///
/// Real `sh` escapes only `$`, `` ` ``, `"`, `\` and newline inside double
/// quotes; before anything else the backslash is literal. This scanner
/// applies the unrestricted rule instead, and the two are indistinguishable
/// for the questions asked of it. The rules differ only on a character that
/// is none of those, and such a character can neither change the quoting
/// state, nor be a separator — separators are recognised in `Normal` only —
/// nor be a `$`. What would matter is getting `\"` wrong: reading it as a
/// closing quote would drop the scanner into `Normal` in the middle of a
/// string and let it invent a boundary out of a `;` that is really an
/// argument.
struct Scan<'a> {
    command: &'a str,
    cursor: usize,
    quoting: Quoting,
    escaped: bool,
}

fn scan(command: &str) -> Scan<'_> {
    Scan {
        command,
        cursor: 0,
        quoting: Quoting::Normal,
        escaped: false,
    }
}

impl Iterator for Scan<'_> {
    type Item = Scanned;

    fn next(&mut self) -> Option<Scanned> {
        let ch = self.command[self.cursor..].chars().next()?;
        let current = Scanned {
            offset: self.cursor,
            ch,
            quoting: self.quoting,
            escaped: self.escaped,
        };

        if self.escaped {
            self.escaped = false;
        } else {
            match self.quoting {
                Quoting::Single => {
                    if ch == '\'' {
                        self.quoting = Quoting::Normal;
                    }
                }
                Quoting::Double => match ch {
                    '\\' => self.escaped = true,
                    '"' => self.quoting = Quoting::Normal,
                    _ => {}
                },
                Quoting::Normal => match ch {
                    '\\' => self.escaped = true,
                    '\'' => self.quoting = Quoting::Single,
                    '"' => self.quoting = Quoting::Double,
                    _ => {}
                },
            }
        }

        // `len_utf8` on the character the cursor is actually at, so the cursor
        // never lands inside one and no offset this yields can split a
        // codepoint.
        self.cursor += ch.len_utf8();
        Some(current)
    }
}

/// Find every command boundary in `command`, in source order.
fn boundaries(command: &str) -> Vec<Boundary> {
    let mut found = Vec::new();
    // One past the last byte already claimed by a separator token. Without
    // it `|||` would report `||` at 0..2 and again at 1..3 — two overlapping
    // boundaries out of one operator and a `;`-worth of screen noise.
    let mut consumed = 0;

    for c in scan(command) {
        if c.offset < consumed || c.escaped || c.quoting != Quoting::Normal {
            continue;
        }
        if c.ch == '\n' {
            found.push(Boundary::Newline(c.offset + c.ch.len_utf8()));
            continue;
        }
        let rest = &command[c.offset..];
        if let Some(token) = SEPARATORS.iter().find(|sep| rest.starts_with(**sep)) {
            consumed = c.offset + token.len();
            found.push(Boundary::Separator(c.offset..consumed));
        }
    }

    found
}

/// True for a character that may appear in a variable name. The first one
/// also has to not be a digit, which [`variable_name`] checks; this is the
/// looser predicate, used to find where a name *ends*.
fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// How many bytes of `rest` — which starts at a `$` — this pass steps over.
///
/// Separate from *whether* those bytes are a reference, which
/// [`variable_name`] decides. The split matters for one case: `$$HOME`. The
/// shell reads that as the PID followed by the literal `HOME`, so nothing in
/// it expands `HOME` — but a scanner that gave up on the first `$` and
/// resumed at the next byte would find `$HOME` there and annotate a
/// substitution the shell will not perform. Stepping over what it declines to
/// claim is what stops a rejected construct being re-read as an accepted one.
///
/// The same rule covers `${…}`: the whole brace expansion is consumed through
/// its first `}` whether or not the interior turns out to be a plain name, so
/// `${HOME:-$USER}` annotates nothing rather than annotating the `$USER`
/// inside it. That is conservative in the safe direction — a reference that
/// may or may not expand is left `Plain` — and it is why this returns a
/// length rather than a yes-or-no.
fn dollar_extent(rest: &str) -> usize {
    let after = &rest[1..];
    match after.chars().next() {
        // A trailing `$`.
        None => 1,
        // Through the first `}`, or just past the `{` if there is none:
        // `${HOME` is unterminated and claims nothing.
        Some('{') => match after[1..].find('}') {
            Some(offset) => 3 + offset,
            None => 2,
        },
        // The whole run of name characters, digits included, so `$1HOME` is
        // stepped over whole instead of leaving `HOME` to be misread.
        Some(c) if is_name_char(c) => {
            1 + after.find(|c: char| !is_name_char(c)).unwrap_or(after.len())
        }
        // `$$`, `$?`, `$@`, `$(`, `$'` … one sigil, stepped over.
        Some(c) => 1 + c.len_utf8(),
    }
}

/// The byte range of every variable reference in `command` that hatch claims
/// to understand, in source order.
///
/// Quoting is the whole point. `$HOME` expands in `Normal` and inside `"…"`;
/// inside `'…'` it is two words of text, and after a backslash it is a
/// literal `$`. Annotating those would tell the reader a substitution happens
/// where none does — the same class of lie as splitting `echo 'a; b'` in two,
/// and the reason both questions are asked of one [`Scan`].
fn references(command: &str) -> Vec<Range<usize>> {
    let mut found = Vec::new();
    let mut consumed = 0;

    for c in scan(command) {
        if c.offset < consumed || c.ch != '$' || c.escaped || c.quoting == Quoting::Single {
            continue;
        }
        let rest = &command[c.offset..];
        let extent = dollar_extent(rest);
        consumed = c.offset + extent;
        if variable_name(&rest[..extent]).is_some() {
            found.push(c.offset..consumed);
        }
    }

    found
}

/// Render `command` as segments: separators tagged and kept, line breaks
/// requested on the spans that follow them, and every run in between handed
/// to the Unicode classifier so chips still appear inside segments.
///
/// One [`SpanBuilder`] drives the whole command. The span model offers no way
/// to splice one [`Spans`] into another — a spliced sequence would have to be
/// trusted rather than checked by `finish` — so composition happens through
/// the builder's cursor instead, and the result tiles the source or panics.
///
/// # Panics
///
/// If the spans do not tile `command` exactly, which would be a bug in this
/// function or in the scanner. A panicking prompt window is a dead prompt
/// window, and hatch treats that as a denial, so failing this way fails
/// closed.
pub fn segment(command: &str) -> Spans {
    let mut builder = SpanBuilder::new(command);

    for boundary in boundaries(command) {
        match boundary {
            Boundary::Separator(token) => {
                // The run before the separator. May be empty — `;;`, or a
                // leading separator — and `classify_into` at the cursor is a
                // no-op, so there is nothing to guard against.
                unicode::classify_into(&mut builder, token.start);
                builder.push_to(token.end, SpanKind::Separator);
            }
            // The newline goes *through* the classifier rather than around
            // it, which is what makes it a chip and not a drawn-as-itself
            // separator.
            Boundary::Newline(end) => unicode::classify_into(&mut builder, end),
        }
        // On the span that follows, never on the separator: the separator is
        // a character the user is approving and it stays where it is.
        builder.break_next();
    }

    unicode::classify_into(&mut builder, command.len());
    builder.finish()
}

/// Tag every variable reference in `spans` and hang the value it will
/// actually have on it.
///
/// A refinement pass, not a renderer: it splits existing spans and retags the
/// halves, so it adds and removes no text and invariant 1 is safe by
/// construction. It is the third pass in [`super::render_command`] and runs
/// after segmentation, which is what lets it find the span a reference lives
/// in rather than having to build one.
///
/// # `env` is the child environment, and nothing else will do
///
/// The value shown must come from [`crate::exec::env::build_child_env`] — the
/// environment hatch will hand the child — because that is the only
/// environment the window can speak for. The daemon's own environment came
/// from wherever the daemon was started, the agent's sandbox environment is
/// agent-influenced, and `run0` resets the environment for a `root: true`
/// operation regardless. Resolving against any of those, or against
/// `std::env`, would print a value that looks authoritative and is wrong,
/// which is worse for a window whose job is to be believed than printing
/// nothing at all. That is why the environment is a parameter here and not a
/// lookup: there is no default that is not a guess.
///
/// A name that environment does not contain resolves to `None` — shown as
/// unset, which is exactly what the child will see.
///
/// # What a reference lands on
///
/// Every character a reference can contain is drawn as itself and is not a
/// separator, so a reference always lies wholly inside one `Plain` span and
/// never straddles a chip or a separator. A span that is neither `Plain` nor
/// already a `Variable` is left alone: some other pass has claimed that text,
/// and this one does not overrule it. Re-running against a different
/// environment does re-resolve, so the last environment applied is the one on
/// screen.
///
/// # Panics
///
/// If a reference is not contained in any single span, which would mean the
/// spans no longer tile their source — a bug in this module. A panicking
/// prompt window is a dead prompt window, and hatch treats that as a denial,
/// so failing this way fails closed.
pub fn annotate_variables(mut spans: Spans, env: &BTreeMap<String, String>) -> Spans {
    for reference in references(spans.source()) {
        let mut index = spans
            .iter()
            .position(|span| {
                span.range().start <= reference.start && reference.end <= span.range().end
            })
            .expect(
                "a reference lies inside one span: every character of one is drawn as itself",
            );

        if !matches!(spans[index].kind(), SpanKind::Plain | SpanKind::Variable { .. }) {
            continue;
        }

        // Trim the span down to the reference from each end in turn. `split`
        // returns the right half's index, which is the one still holding the
        // reference; after the second split the left half at `index` is the
        // reference exactly.
        if spans[index].range().start < reference.start {
            index = spans.split(index, reference.start);
        }
        if reference.end < spans[index].range().end {
            spans.split(index, reference.end);
        }

        let resolved = {
            let name = variable_name(spans[index].text())
                .expect("the span was cut to the extent the scanner matched");
            // Defanged on the way in, not on the way out: the value is not
            // approved text and cannot be a span, so the window has no chip
            // machinery to protect it with. See `unicode::defang`.
            env.get(name).map(|value| unicode::defang(value))
        };
        spans.set_kind(index, SpanKind::Variable { resolved });
    }

    spans
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::render::{Span, unrender};

    /// Segmentation does not depend on the child environment, and most tests
    /// here are about segmentation. Shadowing keeps them reading as they did
    /// while still driving the real, fully wired pipeline.
    fn render_command(command: &str) -> Spans {
        crate::render::render_command(command, &BTreeMap::new())
    }

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// Deliberately driven through `render_command` rather than through
    /// `segment` directly. What has to be true is a property of what the user
    /// is shown, and a pass that is correct but unwired shows the user
    /// nothing.
    fn separators(spans: &Spans) -> Vec<&str> {
        spans
            .iter()
            .filter(|s| s.kind() == &SpanKind::Separator)
            .map(Span::text)
            .collect()
    }

    fn chips(spans: &Spans) -> Vec<char> {
        spans.iter().filter_map(Span::chip_codepoint).collect()
    }

    fn breaks(spans: &Spans) -> Vec<&str> {
        spans.iter().filter(|s| s.break_before()).map(Span::text).collect()
    }

    // --- separators are kept, and marked ----------------------------------

    #[test]
    fn separators_are_kept_and_marked() {
        let spans = render_command("a; b && c");
        assert_eq!(separators(&spans), vec![";", "&&"]);
        assert_eq!(unrender(&spans), "a; b && c", "and nothing was consumed by the layout");
    }

    #[test]
    fn every_separator_form_is_recognised() {
        assert_eq!(separators(&render_command("a; b")), vec![";"]);
        assert_eq!(separators(&render_command("a && b")), vec!["&&"]);
        assert_eq!(separators(&render_command("a || b")), vec!["||"]);
        assert_eq!(separators(&render_command("a | b")), vec!["|"]);
    }

    #[test]
    fn the_longest_separator_wins() {
        // `&&` must not be read as two tokens, and `||` must not be read as
        // two pipes. A shorter match here would double the apparent number of
        // command boundaries.
        assert_eq!(separators(&render_command("a && b || c | d")), vec!["&&", "||", "|"]);
        assert_eq!(unrender(&render_command("a && b || c | d")), "a && b || c | d");
    }

    #[test]
    fn separator_table_is_longest_first() {
        // The whole of the longest-match rule: the first entry that matches
        // wins, so nothing may be preceded by a token it starts with.
        for window in SEPARATORS.windows(2) {
            assert!(
                window[0].len() >= window[1].len(),
                "{:?} is listed before the longer {:?}, so it would match first",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn a_separator_is_never_left_plain() {
        // The properties in tests/fidelity.rs are blind to under-tagging: a
        // separator drawn as Plain round-trips perfectly and hides nothing.
        // This test is the only thing that requires the tagging at all.
        let spans = render_command("a; b");
        let semicolon = spans.iter().find(|s| s.text() == ";").expect("the separator survives");
        assert_eq!(semicolon.kind(), &SpanKind::Separator);
    }

    // --- layout is metadata on the following span -------------------------

    #[test]
    fn a_break_is_requested_after_each_separator() {
        let spans = render_command("a; b");
        assert_eq!(spans.len(), 3, "a, the separator, and the rest");
        assert_eq!(spans[1].text(), ";");
        assert!(!spans[1].break_before(), "layout never lands on the separator itself");
        assert!(spans[2].break_before(), "it lands on the span after it");
        assert_eq!(spans[2].text(), " b", "and no whitespace is trimmed to tidy the line");
    }

    #[test]
    fn every_separator_gets_a_break_after_it() {
        // The trailing space belongs to the run, not to the separator that
        // comes after it: nothing is trimmed on either side of a boundary.
        assert_eq!(breaks(&render_command("a; b && c || d | e")), vec![" b ", " c ", " d ", " e"]);
    }

    #[test]
    fn a_trailing_separator_needs_nothing_to_follow_it() {
        let spans = render_command("a;");
        assert_eq!(separators(&spans), vec![";"]);
        assert_eq!(spans.len(), 2);
        assert_eq!(unrender(&spans), "a;");
    }

    #[test]
    fn a_leading_separator_is_still_a_separator() {
        let spans = render_command("; a");
        assert_eq!(separators(&spans), vec![";"]);
        assert!(!spans[0].break_before(), "nothing precedes the first span to break from");
        assert_eq!(unrender(&spans), "; a");
    }

    #[test]
    fn adjacent_separators_each_close_a_segment() {
        // The run between them is empty, which `classify_into` handles as a
        // no-op. The break from the first lands on the second, because the
        // second really is the span that follows it.
        let spans = render_command("a;;b");
        assert_eq!(separators(&spans), vec![";", ";"]);
        assert_eq!(breaks(&spans), vec![";", "b"]);
        assert_eq!(unrender(&spans), "a;;b");
    }

    // --- quoting ----------------------------------------------------------

    #[test]
    fn separators_inside_single_quotes_are_not_split() {
        assert!(separators(&render_command("echo 'a; b'")).is_empty());
    }

    #[test]
    fn separators_inside_double_quotes_are_not_split() {
        assert!(separators(&render_command("echo \"a && b\"")).is_empty());
    }

    #[test]
    fn a_closed_quote_stops_protecting_what_follows() {
        // Otherwise "not split inside quotes" would pass for a scanner that
        // simply never splits after the first quote character.
        assert_eq!(separators(&render_command("echo 'a; b'; c")), vec![";"]);
        assert_eq!(separators(&render_command("echo \"a; b\" && c")), vec!["&&"]);
    }

    #[test]
    fn quotes_of_the_other_kind_are_ordinary_characters_inside_a_string() {
        // A scanner that toggles on either quote regardless of which one it
        // is inside would fall out of the string at the apostrophe and split
        // the argument in two.
        assert!(separators(&render_command("echo \"it's; here\"")).is_empty());
        assert!(separators(&render_command("echo 'say \"hi\"; now'")).is_empty());
    }

    #[test]
    fn an_unterminated_quote_protects_the_rest_of_the_command() {
        // Under-segmentation, which is the direction the scanner is allowed
        // to be wrong in for the constructs it models: an open quote hides
        // structure rather than fabricating it.
        assert!(separators(&render_command("echo 'a; b")).is_empty());
        assert_eq!(unrender(&render_command("echo 'a; b")), "echo 'a; b");
    }

    // --- escapes ----------------------------------------------------------

    #[test]
    fn escaped_separator_is_not_split() {
        assert!(separators(&render_command(r"echo a\; b")).is_empty());
    }

    #[test]
    fn an_escaped_quote_does_not_open_a_string() {
        // `echo \"a; b\"` runs two commands. A scanner that ignored the
        // escape would see a quoted `a; b` and hide the boundary.
        assert_eq!(separators(&render_command(r#"echo \"a; b\""#)), vec![";"]);
    }

    #[test]
    fn an_escaped_quote_inside_double_quotes_does_not_close_it() {
        // The case that decides how backslash behaves inside `"…"`: reading
        // `\"` as a close would drop the scanner into Normal mid-string and
        // let it invent a boundary out of an argument.
        assert!(separators(&render_command(r#"echo "a\"; b""#)).is_empty());
    }

    #[test]
    fn a_backslash_inside_single_quotes_escapes_nothing() {
        // `'a\'` is a complete string in sh. Honouring the escape would leave
        // the scanner believing the quote is still open for the rest of the
        // command.
        assert_eq!(separators(&render_command(r"echo 'a\'; b")), vec![";"]);
    }

    #[test]
    fn an_escaped_backslash_does_not_escape_what_follows_it() {
        assert_eq!(separators(&render_command(r"echo a\\; b")), vec![";"]);
    }

    #[test]
    fn a_trailing_backslash_escapes_nothing_and_panics_nothing() {
        assert_eq!(unrender(&render_command("echo a\\")), "echo a\\");
    }

    // --- newlines are boundaries but not separators -----------------------

    #[test]
    fn a_newline_breaks_the_line_without_becoming_a_separator() {
        // A Separator-kinded newline would be drawn as itself, and a break on
        // screen would stop telling the reader whether it is layout or
        // content. The chip keeps those two readings apart.
        let spans = render_command("a\nb");
        assert!(separators(&spans).is_empty(), "the newline is not tagged Separator");
        assert_eq!(chips(&spans), vec!['\n'], "it is chipped, like every other control");
        assert_eq!(spans[1].display_text(), "[LF]");
        assert!(!spans[1].break_before(), "the chip closes its segment");
        assert!(spans[2].break_before(), "and the break lands after it");
        assert_eq!(unrender(&spans), "a\nb");
    }

    #[test]
    fn a_newline_inside_quotes_is_not_a_boundary() {
        // A literal newline in an argument is content, not structure.
        let spans = render_command("echo 'a\nb'");
        assert!(breaks(&spans).is_empty());
        assert_eq!(chips(&spans), vec!['\n'], "but it is still shown for what it is");
    }

    #[test]
    fn an_escaped_newline_is_a_line_continuation_and_not_a_boundary() {
        let spans = render_command("echo a\\\nb");
        assert!(breaks(&spans).is_empty());
        assert_eq!(unrender(&spans), "echo a\\\nb");
    }

    // --- composition with the chip pass -----------------------------------

    #[test]
    fn chips_still_appear_inside_segments() {
        // Segmentation drives the builder now, so a rewrite of it that
        // pushed plain runs of its own would silently drop the chip pass and
        // draw a bidi override as itself.
        let spans = render_command("ls\u{202E}txt; rm -rf \u{200B}/");
        assert_eq!(chips(&spans), vec!['\u{202E}', '\u{200B}']);
        assert_eq!(separators(&spans), vec![";"]);
    }

    #[test]
    fn a_separator_next_to_a_chip_keeps_both() {
        let spans = render_command("a\u{202E};\u{200B}b");
        assert_eq!(separators(&spans), vec![";"]);
        assert_eq!(chips(&spans), vec!['\u{202E}', '\u{200B}']);
        assert_eq!(unrender(&spans), "a\u{202E};\u{200B}b");
    }

    // --- scope: where the model stops, in both directions -----------------

    #[test]
    fn structure_outside_the_five_separators_is_left_unsegmented() {
        // Not a wish list. These record one half of the bounded cost of the
        // scope: structure the shell has that the screen does not. See the
        // module docs, and the mirror below.
        assert!(separators(&render_command("sleep 60 & wait")).is_empty(), "backgrounding");
        assert!(separators(&render_command("(cd /tmp)")).is_empty(), "subshells");
        assert!(separators(&render_command("echo `id`")).is_empty(), "backticks");
        assert!(separators(&render_command("echo $(id)")).is_empty(), "substitution");
    }

    #[test]
    fn over_segmentation_where_the_model_stops() {
        // The other half, and the correction of a claim these docs used to
        // make. The scanner is wrong only in the direction of finding no
        // boundary *for the constructs it models* — quoting and escaping.
        // A separator character that some unmodelled construct gives another
        // meaning to is split on anyway. Each case was checked against a real
        // shell; this test is what stops the list drifting from the docs.
        assert_eq!(separators(&render_command("echo a # b; c")), vec![";"], "comment");
        assert_eq!(separators(&render_command("echo $((1 || 0))")), vec!["||"], "arithmetic");
        assert_eq!(separators(&render_command("[[ -n x || -n y ]]")), vec!["||"], "conditional");
        assert_eq!(separators(&render_command("echo x >| out.txt")), vec!["|"], "redirection");
        assert_eq!(separators(&render_command(r"$'a\'b; c'")), vec![";"], "ANSI-C quoting");
        assert_eq!(separators(&render_command("cat <<EOF\na; b\nEOF")), vec![";"], "heredoc");
        assert_eq!(
            separators(&render_command("case x in a) echo 1;; esac")),
            vec![";", ";"],
            "the case terminator is one token, drawn as two separators"
        );
    }

    #[test]
    fn an_over_segmented_command_is_still_rendered_exactly() {
        // The reason this is a docs bug and not a fidelity bug: what is wrong
        // is the layout, and layout is metadata. Every byte is still on
        // screen, drawn as itself.
        for command in ["echo a # b; c", "case x in a) echo 1;; esac", "echo $((1 || 0))"] {
            let spans = render_command(command);
            assert_eq!(unrender(&spans), command);
            let shown: String = spans.iter().map(|s| s.display_text()).collect();
            assert_eq!(shown, command, "{command:?} is drawn as itself throughout");
        }
    }

    #[test]
    fn a_lone_ampersand_after_a_pair_is_not_a_separator() {
        let spans = render_command("a &&& b");
        assert_eq!(separators(&spans), vec!["&&"]);
        assert_eq!(unrender(&spans), "a &&& b");
    }

    // --- fidelity ---------------------------------------------------------

    #[test]
    fn nothing_is_dropped_or_added() {
        for command in [
            "",
            ";",
            "a;;b",
            "a; b && c || d | e",
            "echo 'a; b' | tee \"x && y\"",
            r"echo a\; b\\; c",
            "a\nb\n",
            "\u{202E}; \u{200B}",
            "ünïcödé; ✓",
            "echo 'unterminated; still fine",
        ] {
            let spans = render_command(command);
            assert_eq!(unrender(&spans), command, "{command:?} did not round-trip");
            assert!(spans.covers_source(), "{command:?} is not tiled by its spans");
        }
    }

    #[test]
    fn the_empty_command_segments_into_nothing() {
        let spans = render_command("");
        assert!(spans.is_empty());
        assert_eq!(unrender(&spans), "");
    }

    // --- the scanner itself -----------------------------------------------

    #[test]
    fn the_scanner_reports_boundaries_in_source_order() {
        assert_eq!(
            boundaries("a; b\nc && d"),
            vec![Boundary::Separator(1..2), Boundary::Newline(5), Boundary::Separator(7..9)],
        );
    }

    #[test]
    fn the_scanner_steps_over_multibyte_characters_whole() {
        // The cursor walks by `len_utf8`, so a continuation byte is never
        // mistaken for the start of a token and no offset lands mid-character.
        assert_eq!(boundaries("é; ü"), vec![Boundary::Separator(2..3)]);
        assert_eq!(unrender(&render_command("é; ü")), "é; ü");
    }

    // --- variables: what is claimed, and against which environment --------

    /// Every `Variable` span, as the window would present it: the text the
    /// user approves, and the value shown beside it.
    fn variables(spans: &Spans) -> Vec<(&str, Option<&str>)> {
        spans
            .iter()
            .filter_map(|s| s.variable().map(|(_, resolved)| (s.text(), resolved)))
            .collect()
    }

    #[test]
    fn set_variable_renders_with_its_child_value() {
        let env = env(&[("HOME", "/home/user")]);
        let spans = annotate_variables(render_command("ls $HOME"), &env);
        let variable = spans
            .iter()
            .find(|s| matches!(s.kind(), SpanKind::Variable { .. }))
            .expect("the reference is annotated");
        assert_eq!(variable.text(), "$HOME", "the text is still the approved substring");
        assert_eq!(variable.variable(), Some(("HOME", Some("/home/user"))));
    }

    #[test]
    fn unset_variable_is_flagged_unset() {
        let spans = annotate_variables(render_command("ls $NOPE"), &BTreeMap::new());
        let variable = spans
            .iter()
            .find(|s| matches!(s.kind(), SpanKind::Variable { .. }))
            .expect("an unset reference is still a reference");
        assert_eq!(variable.variable(), Some(("NOPE", None)));
    }

    #[test]
    fn variables_in_single_quotes_are_not_annotated() {
        // `'$HOME'` is the two-word argument `$HOME`, not a substitution.
        // Annotating it would tell the reader an expansion happens where none
        // does -- the same class of lie the quote-aware scanner exists for.
        let env = env(&[("HOME", "/home/user")]);
        let spans = annotate_variables(render_command("echo '$HOME'"), &env);
        assert!(variables(&spans).is_empty());
    }

    #[test]
    fn variables_in_double_quotes_are_annotated() {
        // `"$HOME"` does expand. Refusing to annotate here would be the
        // mirror lie: the reader would be shown a literal where a
        // substitution happens.
        let env = env(&[("HOME", "/home/user")]);
        let spans = annotate_variables(render_command("echo \"$HOME/x\""), &env);
        assert_eq!(variables(&spans), vec![("$HOME", Some("/home/user"))]);
    }

    #[test]
    fn a_closed_single_quote_stops_protecting_what_follows() {
        // Otherwise "not annotated inside single quotes" would pass for a
        // pass that simply gave up at the first quote character.
        let env = env(&[("A", "1"), ("B", "2")]);
        let spans = annotate_variables(render_command("echo '$A' $B"), &env);
        assert_eq!(variables(&spans), vec![("$B", Some("2"))]);
    }

    #[test]
    fn an_escaped_dollar_is_not_a_variable() {
        // `\$HOME` and `"\$HOME"` are both the literal five characters.
        let env = env(&[("HOME", "/home/user")]);
        assert!(variables(&annotate_variables(render_command(r"echo \$HOME"), &env)).is_empty());
        assert!(
            variables(&annotate_variables(render_command(r#"echo "\$HOME""#), &env)).is_empty()
        );
    }

    #[test]
    fn the_braced_form_is_annotated_and_keeps_its_braces() {
        let env = env(&[("HOME", "/home/user")]);
        let spans = annotate_variables(render_command("ls ${HOME}x"), &env);
        assert_eq!(variables(&spans), vec![("${HOME}", Some("/home/user"))]);
        let braced = spans.iter().find(|s| s.variable().is_some()).unwrap();
        assert_eq!(braced.variable().unwrap().0, "HOME", "the name is the interior");
        assert_eq!(unrender(&spans), "ls ${HOME}x");
    }

    #[test]
    fn every_reference_in_a_command_is_annotated() {
        // Under-tagging breaks no invariant in tests/fidelity.rs: a reference
        // left Plain round-trips perfectly and hides nothing. This test and
        // its siblings are the only thing that requires the tagging at all.
        let env = env(&[("A", "1"), ("B", "2"), ("C", "3")]);
        let spans = annotate_variables(render_command("$A x ${B}; echo $C"), &env);
        assert_eq!(
            variables(&spans),
            vec![("$A", Some("1")), ("${B}", Some("2")), ("$C", Some("3"))]
        );
    }

    #[test]
    fn a_reference_beside_a_separator_or_a_chip_keeps_everything() {
        let env = env(&[("HOME", "/home/user")]);
        let spans = annotate_variables(render_command("echo $HOME;\u{202E}$HOME"), &env);
        assert_eq!(separators(&spans), vec![";"]);
        assert_eq!(chips(&spans), vec!['\u{202E}']);
        assert_eq!(
            variables(&spans),
            vec![("$HOME", Some("/home/user")), ("$HOME", Some("/home/user"))]
        );
        assert_eq!(unrender(&spans), "echo $HOME;\u{202E}$HOME");
    }

    #[test]
    fn a_reference_that_is_the_whole_command_needs_no_split() {
        let env = env(&[("A", "1")]);
        let spans = annotate_variables(render_command("$A"), &env);
        assert_eq!(spans.len(), 1);
        assert_eq!(variables(&spans), vec![("$A", Some("1"))]);
    }

    #[test]
    fn a_reference_keeps_the_line_break_on_the_first_span_of_its_line() {
        // `split` leaves `break_before` with the left half, so a reference
        // that starts a line must not steal the break from the space before
        // it -- and one that *is* the start of a line must keep it.
        let env = env(&[("A", "1")]);

        let spans = annotate_variables(render_command("x; $A"), &env);
        assert_eq!(breaks(&spans), vec![" "], "the space is still what starts the line");

        let spans = annotate_variables(render_command("x;$A"), &env);
        assert_eq!(breaks(&spans), vec!["$A"]);
        assert_eq!(variables(&spans), vec![("$A", Some("1"))]);
    }

    #[test]
    fn a_name_may_start_with_an_underscore_and_carry_digits() {
        let env = env(&[("_x9", "ok")]);
        assert_eq!(
            variables(&annotate_variables(render_command("echo $_x9"), &env)),
            vec![("$_x9", Some("ok"))]
        );
    }

    #[test]
    fn a_name_stops_at_the_first_character_that_is_not_one() {
        let env = env(&[("A", "1")]);
        let spans = annotate_variables(render_command("echo $A-$A/$A."), &env);
        assert_eq!(variables(&spans), vec![("$A", Some("1")); 3]);
        assert_eq!(unrender(&spans), "echo $A-$A/$A.");
    }

    // --- the boundary of what `$` is claimed to mean ----------------------

    #[test]
    fn positional_and_special_parameters_are_left_plain() {
        // None of these is a name in the child environment, so none of them
        // has a value this window could show. `$$` is the sharp one: the
        // shell reads it as the PID and leaves `HOME` literal, so a scanner
        // that resumed one byte later would find `$HOME` and annotate an
        // expansion that does not happen.
        let env = env(&[("HOME", "/home/user"), ("1", "no"), ("@", "no")]);
        for command in [
            "echo $1", "echo $@", "echo $?", "echo $$", "echo $*", "echo $#", "echo $-",
            "echo $!", "echo $0", "echo $$HOME", "echo $1HOME", "echo $", "echo $ HOME",
        ] {
            let spans = annotate_variables(render_command(command), &env);
            assert!(variables(&spans).is_empty(), "{command:?} claims a variable it should not");
            assert_eq!(unrender(&spans), command);
        }
    }

    #[test]
    fn substitutions_and_modified_expansions_are_left_plain() {
        // Each of these substitutes something the child environment does not
        // contain, so naming a value beside it would be a claim about the
        // wrong thing. `${HOME:-$USER}` is consumed whole rather than
        // annotated on its inner reference: conservative in the safe
        // direction.
        let env = env(&[("HOME", "/home/user"), ("USER", "user")]);
        for command in [
            "echo $(id)",
            "echo $((1+1))",
            "echo ${HOME:-/tmp}",
            "echo ${#HOME}",
            "echo ${!HOME}",
            "echo ${HOME:-$USER}",
            "echo ${}",
            "echo ${HOME",
            "echo ${ HOME }",
        ] {
            let spans = annotate_variables(render_command(command), &env);
            assert!(variables(&spans).is_empty(), "{command:?} claims a variable it should not");
            assert_eq!(unrender(&spans), command);
        }
    }

    #[test]
    fn a_reference_inside_a_substitution_still_expands_and_is_annotated() {
        // The subshell gets the same environment, so this one is honest --
        // and it is the case that keeps the rule above from being written as
        // "anything after a `$(` is off limits".
        let env = env(&[("HOME", "/home/user")]);
        let spans = annotate_variables(render_command("echo $(ls $HOME)"), &env);
        assert_eq!(variables(&spans), vec![("$HOME", Some("/home/user"))]);
    }

    #[test]
    fn an_ansi_c_string_hides_its_references_like_any_single_quoted_one() {
        // `$'…'` does not expand parameters. The scanner reaches the right
        // answer through the `'`, which is the ordinary single-quote rule.
        let env = env(&[("HOME", "/home/user")]);
        assert!(variables(&annotate_variables(render_command("echo $'$HOME'"), &env)).is_empty());
    }

    // --- the value is beside the text, and it is defanged -----------------

    #[test]
    fn a_variable_is_drawn_as_itself_and_the_value_sits_beside_it() {
        // Invariant 1b permits only a chip to draw something other than its
        // text, so the resolved value may never be substituted for the
        // reference. The span shape has to make that the easy thing: the text
        // is what is drawn, and the value is reachable only through a
        // separate accessor.
        let env = env(&[("HOME", "/home/user")]);
        let spans = annotate_variables(render_command("ls $HOME"), &env);
        let variable = spans.iter().find(|s| s.variable().is_some()).unwrap();
        assert_eq!(variable.display_text(), "$HOME");
        assert_eq!(variable.chip_codepoint(), None, "it is not a chip and may not become one");
        let shown: String = spans.iter().map(|s| s.display_text()).collect();
        assert_eq!(shown, "ls $HOME", "the value is nowhere in the drawn line");
    }

    #[test]
    fn a_resolved_value_cannot_carry_a_control_character_into_the_window() {
        // The value is user-controlled but the *choice* of which value to
        // show is the agent's: it writes the command, so it picks the name.
        // A configured value carrying a bidi override or a newline would
        // reorder or split the line the command is read on, so it arrives
        // flattened to the same chip vocabulary the command itself uses.
        let env = env(&[("V", "/a\u{202E}b\nc\u{200B}")]);
        let spans = annotate_variables(render_command("echo $V"), &env);
        assert_eq!(variables(&spans), vec![("$V", Some("/a[RLO]b[LF]c[ZWSP]"))]);
        let (_, value) = spans.iter().find_map(Span::variable).unwrap();
        assert!(
            !value.unwrap().chars().any(|c| c.is_control() || c == '\u{202E}'),
            "nothing that commands a terminal or reorders a line survives"
        );
    }

    #[test]
    fn an_empty_value_is_not_the_same_as_an_unset_one() {
        let spans = annotate_variables(render_command("echo $A"), &env(&[("A", "")]));
        assert_eq!(variables(&spans), vec![("$A", Some(""))]);
    }

    #[test]
    fn re_annotating_resolves_against_the_environment_it_was_last_given() {
        // The pass is idempotent in shape and current in content: a span that
        // is already a Variable is re-resolved rather than left carrying a
        // value from some other environment.
        let spans = annotate_variables(render_command("ls $HOME"), &env(&[("HOME", "/first")]));
        let spans = annotate_variables(spans, &env(&[("HOME", "/second")]));
        assert_eq!(variables(&spans), vec![("$HOME", Some("/second"))]);
    }

    #[test]
    fn every_annotated_span_is_exactly_one_reference() {
        // The model refuses a `Variable` over anything else, so this is a
        // check that the pass never has to be refused: no split leaves half a
        // name wearing a whole value.
        let env = env(&[("A", "1"), ("HOME", "/home/user")]);
        for command in [
            "$A", "x$A", "$A x", "x$A x", "${HOME}$A", "$A;$A", "echo \"$A\"", "$A\u{202E}$A",
        ] {
            let spans = annotate_variables(render_command(command), &env);
            for span in spans.iter() {
                if let SpanKind::Variable { .. } = span.kind() {
                    assert!(
                        crate::render::variable_name(span.text()).is_some(),
                        "{command:?}: {:?} is not a whole reference",
                        span.text()
                    );
                }
            }
            assert_eq!(unrender(&spans), command);
            assert!(spans.covers_source());
        }
    }

    #[test]
    fn annotation_adds_and_removes_nothing() {
        let env = env(&[("HOME", "/home/user"), ("A", "; rm -rf /")]);
        for command in [
            "",
            "$",
            "$$",
            "$A",
            "echo '$A' \"$A\" \\$A $A",
            "${A}${A}",
            "a; $A && ${A:-x} | $(echo $A)",
            "ünïcödé $A ✓",
            "$A\n$A",
        ] {
            let spans = annotate_variables(render_command(command), &env);
            assert_eq!(unrender(&spans), command, "{command:?} did not round-trip");
            assert!(spans.covers_source(), "{command:?} is not tiled by its spans");
        }
    }

    // --- the shared scanner -----------------------------------------------

    #[test]
    fn the_scanner_reports_the_state_each_character_sits_in() {
        // The state is the one *before* the character is applied, so the
        // quote that opens a string reads Normal and the one that closes it
        // reads Single. Both passes depend on that reading.
        let states: Vec<_> = scan(r"a'b'\;").map(|c| (c.ch, c.quoting, c.escaped)).collect();
        assert_eq!(
            states,
            vec![
                ('a', Quoting::Normal, false),
                ('\'', Quoting::Normal, false),
                ('b', Quoting::Single, false),
                ('\'', Quoting::Single, false),
                ('\\', Quoting::Normal, false),
                (';', Quoting::Normal, true),
            ]
        );
    }

    #[test]
    fn the_scanner_visits_every_character_exactly_once() {
        for command in ["", "a; b", r"echo 'a\'; b", "ünïcödé; ✓", "\u{202E}$A"] {
            let seen: String = scan(command).map(|c| c.ch).collect();
            assert_eq!(seen, command);
            let offsets: Vec<_> = scan(command).map(|c| c.offset).collect();
            assert!(offsets.windows(2).all(|w| w[0] < w[1]), "offsets must ascend");
        }
    }

    #[test]
    fn the_scanner_reports_double_quoted_state_and_its_escapes() {
        let states: Vec<_> = scan(r#""a\"b""#).map(|c| (c.ch, c.quoting, c.escaped)).collect();
        assert_eq!(
            states,
            vec![
                ('"', Quoting::Normal, false),
                ('a', Quoting::Double, false),
                ('\\', Quoting::Double, false),
                ('"', Quoting::Double, true),
                ('b', Quoting::Double, false),
                ('"', Quoting::Double, false),
            ]
        );
    }

    #[test]
    fn the_scanner_finds_references_in_source_order() {
        assert_eq!(references("$A x ${B}"), vec![0..2, 5..9]);
        assert_eq!(references("echo '$A' $B"), vec![10..12]);
        assert_eq!(references("$$A"), Vec::<Range<usize>>::new());
    }

    #[test]
    fn a_dollar_extent_steps_over_what_it_declines_to_claim() {
        // The rule that keeps a rejected construct from being re-read as an
        // accepted one. Each length is the whole of what the shell treats as
        // one thing at that `$`.
        assert_eq!(dollar_extent("$"), 1);
        assert_eq!(dollar_extent("$A"), 2);
        assert_eq!(dollar_extent("$_a9-"), 4);
        assert_eq!(dollar_extent("$1HOME"), 6, "digits and letters are one run");
        assert_eq!(dollar_extent("$$HOME"), 2, "`$$` is one thing; `HOME` is literal");
        assert_eq!(dollar_extent("${A}x"), 4);
        // Through the first closing brace, inner `$` included.
        assert_eq!(dollar_extent("${A:-$B} x"), 8);
        assert_eq!(dollar_extent("${A"), 2, "unterminated: claim nothing past the brace");
        assert_eq!(dollar_extent("$(id)"), 2);
        assert_eq!(dollar_extent("$é"), 3, "a multibyte sigil is stepped over whole");
    }
}
