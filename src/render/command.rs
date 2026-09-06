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

use std::ops::Range;

use super::{SpanBuilder, SpanKind, Spans, unicode};

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
/// [`Quoting::Normal`].
#[derive(Clone, Copy)]
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

/// Find every command boundary in `command`, in source order.
///
/// One left-to-right pass, tracking quoting and one backslash-escape flag. No
/// backtracking, no nesting, no recursion: the input is agent-controlled and
/// this runs before a human is asked to approve anything, so it is bounded by
/// the length of the string and nothing else.
///
/// # Backslash inside double quotes
///
/// Real `sh` escapes only `$`, `` ` ``, `"`, `\` and newline inside double
/// quotes; before anything else the backslash is literal. This function
/// applies the unrestricted rule instead, and the two are indistinguishable
/// for every question it asks. The rules differ only on a character that is
/// neither `"` nor `\`, and such a character can neither change the quoting
/// state nor be a separator — separators are recognised in `Normal` only. What
/// would matter is getting `\"` wrong: reading it as a closing quote would
/// drop the scanner into `Normal` in the middle of a string and let it invent
/// a boundary out of a `;` that is really an argument.
fn boundaries(command: &str) -> Vec<Boundary> {
    let mut found = Vec::new();
    let mut quoting = Quoting::Normal;
    let mut escaped = false;
    let mut cursor = 0;

    while cursor < command.len() {
        let rest = &command[cursor..];
        let c = rest.chars().next().expect("cursor left a character boundary");
        let mut width = c.len_utf8();

        if escaped {
            escaped = false;
        } else {
            match quoting {
                Quoting::Single => {
                    if c == '\'' {
                        quoting = Quoting::Normal;
                    }
                }
                Quoting::Double => match c {
                    '\\' => escaped = true,
                    '"' => quoting = Quoting::Normal,
                    _ => {}
                },
                Quoting::Normal => match c {
                    '\\' => escaped = true,
                    '\'' => quoting = Quoting::Single,
                    '"' => quoting = Quoting::Double,
                    '\n' => found.push(Boundary::Newline(cursor + width)),
                    _ => {
                        if let Some(token) = SEPARATORS.iter().find(|sep| rest.starts_with(**sep)) {
                            width = token.len();
                            found.push(Boundary::Separator(cursor..cursor + width));
                        }
                    }
                },
            }
        }

        cursor += width;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::{Span, render_command, unrender};

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
}
