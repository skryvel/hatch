//! Side-by-side diff model over `Span`s.
//!
//! A file write asks a human to approve replacing a file's entire contents, so
//! the window shows two columns: left is what is on disk now, right is what
//! the agent proposes. This module builds the model behind that view, and it
//! carries invariants 1 and 1b across the line boundary that a diff
//! introduces.
//!
//! For a command the invariant reads `unrender(render(x)) == x`. For a diff it
//! has to read twice, once per column:
//!
//! > Rejoining the left column reproduces the current file exactly, and
//! > rejoining the right column reproduces the proposed content exactly.
//!
//! [`rejoin_left`] and [`rejoin_right`] are that statement made executable.
//! They are not conveniences: they exist so the property can be tested, and
//! they read the *spans* rather than any stored copy of a line, so a rejoin
//! that succeeds is evidence about the rendering and not merely about a field
//! that happens to hold the input.
//!
//! The failure mode this guards against is specific and classic. A diff view
//! that drops a line, reorders one, pairs the wrong two lines, or silently
//! normalises CRLF to LF is showing the user a file that is not the file. The
//! user would then approve a write they did not read, which is the one thing
//! hatch exists to prevent — and unlike a mangled command, a mangled diff
//! looks entirely plausible, because a diff is *expected* to differ from its
//! inputs.
//!
//! # Where the newline lives
//!
//! A row's text includes its own line terminator. That is the decision this
//! module turns on, and the alternative is worse in two separate ways.
//!
//! Splitting a line into "content" plus a terminator held outside the span
//! model would mean [`rejoin_left`] concatenating bytes that were never
//! rendered and never shown — a hole in invariant 1b exactly the width of
//! every line ending in the file. It would also make `foo\n` and `foo\r\n`
//! indistinguishable on screen, so an agent could propose rewriting a file's
//! line endings and the window would draw the two columns identically. A
//! whole-file line-ending change is a real diff and the reader must be able
//! to see it.
//!
//! So the terminator is part of the line, is classified with everything else,
//! and comes out as chips — `⇤`, `↵` — because [`super::unicode`] draws
//! only U+0020..=U+007E as itself. That is honest but noisy, so [`Side`]
//! splits its own spans for the view's benefit: [`Side::content_spans`] is
//! the line without its terminator and [`Side::terminator_spans`] is the
//! terminator, both slices of the *same* span sequence rather than a second
//! rendering. The view can draw the terminator small, dim, or only on rows
//! where it changed; [`Side::spans`] remains the whole line, and that is what
//! the rejoin reads.
//!
//! Line splitting is [`similar`]'s, which cuts after `\r\n`, `\n` or a lone
//! `\r` and keeps the terminator on the line it ends. A final line with no
//! terminator stays a line, an empty file has no lines at all, and a file
//! that is one `"\n"` is one line whose entire content is its terminator. All
//! four round-trip, and there are tests naming each.

use sha2::{Digest, Sha256};
use similar::{DiffOp, TextDiff};

use super::span::{Span, Spans, unrender};
use super::unicode::classify;

/// One side of one row: a single line, rendered.
///
/// The spans tile the whole line *including its terminator*, so
/// `unrender(side.spans())` is the line byte for byte. See the module docs for
/// why the terminator is in here rather than beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Side {
    spans: Spans,
    /// How many leading spans are content rather than terminator. Always
    /// `spans.len()` for a line that has no terminator.
    ///
    /// A span index rather than a byte offset because that is what the view
    /// needs and because it can only be computed here, where the classifier's
    /// output is in hand. It is not a second source of truth about the text:
    /// both slices come out of the one `Spans`, so no arrangement of this
    /// field can add, drop or rewrite a byte.
    content_spans: usize,
}

impl Side {
    /// Render one line. `line` carries its own terminator, if it has one.
    ///
    /// # Panics
    ///
    /// If the classifier does not put a span boundary where the terminator
    /// starts. It always does — `\r` and `\n` are outside U+0020..=U+007E, so
    /// each becomes its own one-codepoint chip — and the assertion is here
    /// because `content_spans` would otherwise silently start pointing into
    /// the middle of a span if that ever changed.
    fn new(line: &str) -> Self {
        let content_len = line.len() - terminator_len(line);
        let spans = classify(line);
        let content_spans = spans.iter().take_while(|s| s.range().end <= content_len).count();
        assert!(
            spans.get(content_spans).is_none_or(|s| s.range().start == content_len),
            "the classifier must break a span at the line terminator"
        );
        Side { spans, content_spans }
    }

    /// Every span in the line, terminator included. This is what the rejoin
    /// reads and what the approval covers.
    pub fn spans(&self) -> &[Span] {
        &self.spans
    }

    /// The line without its terminator: what a view draws as the line.
    pub fn content_spans(&self) -> &[Span] {
        &self.spans[..self.content_spans]
    }

    /// The terminator, as chips. Empty for a final line that has none, one
    /// span for `\n` or a lone `\r`, two for `\r\n`.
    pub fn terminator_spans(&self) -> &[Span] {
        &self.spans[self.content_spans..]
    }

    /// Rebuild a side from a rendering of its own line -- the receiving end
    /// of the wire form in [`crate::protocol`].
    ///
    /// `content_spans` is recomputed here rather than taken as an argument,
    /// for the reason [`Span::chip_codepoint`] is read out of the text rather
    /// than stored beside it: a transmitted copy could disagree with the line
    /// it describes, and a terminator boundary in the wrong place draws part
    /// of the line in the terminator slot. Nothing is transmitted, so nothing
    /// can drift.
    ///
    /// `None` on exactly the condition `Side::new` asserts on: the spans do
    /// not break where the terminator starts. A refusal rather than a panic
    /// because this input arrived over a pipe -- a malformed frame is
    /// something to fail closed on, not something to crash the reader with.
    ///
    /// [`Span::chip_codepoint`]: super::Span::chip_codepoint
    pub fn from_rendering(spans: Spans) -> Option<Side> {
        let content_len = spans.source().len() - terminator_len(spans.source());
        let content_spans = spans.iter().take_while(|s| s.range().end <= content_len).count();
        spans
            .get(content_spans)
            .is_none_or(|s| s.range().start == content_len)
            .then_some(Side { spans, content_spans })
    }

    /// The exact line, terminator included.
    ///
    /// Paired with [`Side::spans`] this is also how a caller re-checks
    /// invariant 1 for itself:
    /// `covers_exactly(side.spans(), side.text())`. There is deliberately no
    /// method here that answers that question on the model's own authority --
    /// a re-check that can only ever return true is not a re-check.
    pub fn text(&self) -> &str {
        self.spans.source()
    }
}

/// The byte length of the line terminator `line` ends with: 2 for `\r\n`, 1
/// for `\n` or a lone `\r`, 0 for a final line that has none.
///
/// Deliberately mirrors [`similar`]'s own line splitting rather than
/// `str::lines`, which would drop the terminator, or `trim_end`, which would
/// eat trailing blank content. A lone `\r` counts because `similar` ends a
/// line on one, and a row whose terminator this function under-reported would
/// draw part of its own text in the terminator slot.
fn terminator_len(line: &str) -> usize {
    if line.ends_with("\r\n") {
        2
    } else if line.ends_with('\n') || line.ends_with('\r') {
        1
    } else {
        0
    }
}

/// One row of the side-by-side view: at most one line on each side.
///
/// Either side may be absent. A pure insertion has no left, a pure deletion
/// has no right, and drawing that as a gap is what lets the two columns stay
/// aligned without inventing a blank line into either file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    left: Option<Side>,
    right: Option<Side>,
    changed: bool,
}

impl Row {
    /// The current file's line, or `None` where this row is an insertion.
    pub fn left(&self) -> Option<&Side> {
        self.left.as_ref()
    }

    /// The proposed content's line, or `None` where this row is a deletion.
    pub fn right(&self) -> Option<&Side> {
        self.right.as_ref()
    }

    /// Whether the view should mark this row.
    ///
    /// Taken from the diff operation the row came out of, not from comparing
    /// the two sides: only `Equal` rows are unmarked, and an `Equal` row's
    /// two lines are byte-identical by construction. Every other row is
    /// marked. That can over-report — a `Replace` block may happen to pair two
    /// identical lines — and over-reporting is the direction to fail in, since
    /// a row wrongly marked changed costs the reader a second look while a row
    /// wrongly marked unchanged costs them the change itself.
    pub fn changed(&self) -> bool {
        self.changed
    }

    /// Assemble a row from two rendered sides -- the receiving end of the
    /// wire form in [`crate::protocol`].
    ///
    /// `changed` is carried rather than recomputed, and that is the one thing
    /// here that could not be derived at the far end anyway: it comes from
    /// the diff operation this row was cut from, and comparing the two lines
    /// would answer a different question -- see [`Row::changed`] for why a
    /// `Replace` block may pair two identical lines and still be marked.
    pub fn from_sides(left: Option<Side>, right: Option<Side>, changed: bool) -> Row {
        Row { left, right, changed }
    }
}

/// Diff two texts into rows, left = `before`, right = `after`.
///
/// Every line of `before` appears in exactly one row's left, in order, and
/// likewise `after` on the right — which is what makes [`rejoin_left`] and
/// [`rejoin_right`] exact. Nothing here is allowed to filter, sort or
/// deduplicate rows.
///
/// # How operations become rows
///
/// [`similar`] reports four kinds of operation and this function turns each
/// into rows in the obvious way, with one real choice in it:
///
/// * `Equal` — one row per line, both sides present, unmarked.
/// * `Delete` — one row per line, left only.
/// * `Insert` — one row per line, right only.
/// * `Replace` — the choice. The two blocks are paired off positionally, so
///   the first `min(old_len, new_len)` rows carry a line on each side and the
///   reader can compare them directly. When the blocks are of unequal length
///   the surplus lines follow as one-sided rows, on whichever side is longer.
///
/// Pairing is what makes a side-by-side view readable, and positional pairing
/// is a display decision with no claim behind it: hatch is not asserting that
/// the two lines in a row correspond, only that they occupy the same row.
/// Both columns still read down in file order, so the pairing cannot cost a
/// line even when it is unhelpful.
///
/// # Cost
///
/// The agent picks the content, so the shapes that make a line differ worst
/// case are all reachable on purpose. Measured in release at the 256 KB
/// [`crate::config::Config::output_cap_bytes`] default, the slowest of them —
/// 262144 empty lines against 262143, and 131072 lines drawn from two
/// distinct values — take about 200 ms and 340 ms; reversal, near-disjoint
/// blocks and pseudorandom lines over a tiny alphabet all land under 200 ms.
/// That is inside a human's patience for a window that is about to open, so
/// there is deliberately no deadline knob here: a timeout would trade a
/// bounded wait for a diff whose shape depends on how loaded the machine was,
/// and the cap is already the bound.
pub fn side_by_side(before: &str, after: &str) -> Vec<Row> {
    let diff = TextDiff::from_lines(before, after);
    let old = |i: usize| Side::new(diff.old_slice(i).expect("an op indexes a line that exists"));
    let new = |i: usize| Side::new(diff.new_slice(i).expect("an op indexes a line that exists"));

    let mut rows = Vec::new();
    for op in diff.ops() {
        match *op {
            DiffOp::Equal { old_index, new_index, len } => {
                for k in 0..len {
                    rows.push(Row {
                        left: Some(old(old_index + k)),
                        right: Some(new(new_index + k)),
                        changed: false,
                    });
                }
            }
            DiffOp::Delete { old_index, old_len, .. } => {
                for k in 0..old_len {
                    rows.push(Row { left: Some(old(old_index + k)), right: None, changed: true });
                }
            }
            DiffOp::Insert { new_index, new_len, .. } => {
                for k in 0..new_len {
                    rows.push(Row { left: None, right: Some(new(new_index + k)), changed: true });
                }
            }
            DiffOp::Replace { old_index, old_len, new_index, new_len } => {
                for k in 0..old_len.max(new_len) {
                    rows.push(Row {
                        left: (k < old_len).then(|| old(old_index + k)),
                        right: (k < new_len).then(|| new(new_index + k)),
                        changed: true,
                    });
                }
            }
        }
    }
    rows
}

/// The left column, rejoined: the current file, byte for byte.
///
/// The diff's [`unrender`], and it goes through the spans on purpose. Reading
/// [`Side::text`] instead would return the same string today and would test
/// nothing, because that string is the input rather than the rendering.
///
/// The two really are indistinguishable today — [`SpanBuilder::finish`]
/// refuses to produce a sequence that does not tile its source, so no `Side`
/// exists for which they differ, and swapping this line for `Side::text` is
/// an equivalent mutation that no test in this crate can kill. That is the
/// argument for writing it this way rather than against it: the day a change
/// to the span model makes the two disagree is the day these tests need to
/// notice, and they only can if they were reading the spans all along.
///
/// [`SpanBuilder::finish`]: super::SpanBuilder::finish
pub fn rejoin_left(rows: &[Row]) -> String {
    rows.iter().filter_map(Row::left).map(|s| unrender(s.spans())).collect()
}

/// The right column, rejoined: the proposed content, byte for byte. See
/// [`rejoin_left`].
pub fn rejoin_right(rows: &[Row]) -> String {
    rows.iter().filter_map(Row::right).map(|s| unrender(s.spans())).collect()
}

/// Why a side could not be shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SummaryReason {
    /// Not valid UTF-8. There is no honest way to draw it as lines.
    NotUtf8,
    /// Longer than the cap.
    TooLarge,
}

/// One side's content, either readable or reduced to facts about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// Valid UTF-8, within the cap. This is what can be diffed.
    Text(String),
    /// What is knowable about content that cannot be shown.
    ///
    /// The hash is over the **raw bytes** — what is on disk or what would be
    /// written, not a decoding of it, which for binary content does not exist
    /// and for text would erase the byte-level distinction the approval
    /// actually covers.
    ///
    /// It is worth a human's attention because a summarised side is the one
    /// thing in the window they cannot read, and the hash is the only handle
    /// they have on it: they can check it against `sha256sum` on the file
    /// themselves, and they can compare the two sides. Equal hashes mean the
    /// swap would change nothing, which is a reason to decline. Unequal
    /// hashes mean it would change something hatch cannot show them, which is
    /// a better reason to decline.
    Summary { bytes: usize, sha256: String, reason: SummaryReason },
}

/// Decide whether a side can be shown as text, and summarise it if not.
///
/// The cap is checked **before** UTF-8 validity, and the order is load
/// bearing rather than incidental: the cap exists to bound the work done on
/// input an agent chose, and validating a gigabyte before honouring a 256 KB
/// limit would spend exactly what the limit was meant to save. Content that
/// is both oversized and binary therefore reports [`SummaryReason::TooLarge`].
///
/// A side of exactly `cap` bytes is text. The cap is a maximum size, not a
/// size that is already too big.
pub fn render_content(bytes: &[u8], cap: usize) -> Content {
    let summary = |reason| Content::Summary {
        bytes: bytes.len(),
        sha256: sha256_hex(bytes),
        reason,
    };
    if bytes.len() > cap {
        return summary(SummaryReason::TooLarge);
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => Content::Text(text.to_string()),
        Err(_) => summary(SummaryReason::NotUtf8),
    }
}

/// Lowercase hex SHA-256 of `bytes`, so it can be compared by eye against
/// `sha256sum`, which prints the same form.
fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().fold(String::with_capacity(64), |mut out, b| {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// What a file write's window has to draw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileDiff {
    /// Both sides were text within the cap, so there is a real diff to read.
    Rows(Vec<Row>),
    /// At least one side could not be rendered as text, so there are no rows.
    ///
    /// Each side still reports for itself rather than one oversized side
    /// summarising both. The window can then say "the file on disk is 3 MB of
    /// binary, and here is the 40 lines the agent proposes to overwrite it
    /// with", which is most of what a reader needs; blanking the readable
    /// side too would discard information for the sake of symmetry.
    ///
    /// What the reader must be told either way is that no line-by-line
    /// comparison was possible — that this is not a diff and nothing on
    /// screen shows what changes. A side shown in full here is what *would be
    /// written*, not a comparison, and the two are easy to confuse.
    Unrenderable { before: Content, after: Content },
}

/// Render a proposed whole-file replacement for approval: `before` is what is
/// on disk, `after` is what the agent proposes, `cap` bounds each side
/// independently.
///
/// Each side is capped on its own because the two arrive from different
/// places and are differently trustworthy — one from disk, one from the agent
/// — and because an oversized file on disk is not a reason to refuse to show
/// a short proposal, nor the reverse. Rows need both sides, though, so one
/// summarised side is enough to leave the window with no diff to draw.
///
/// `cap` is a parameter and there is deliberately no overload that supplies a
/// default, for the reason [`super::render_command`] takes an environment:
/// the caller passes [`crate::config::Config::output_cap_bytes`], and a
/// default compiled in here would be a second number that could drift from
/// the configured one without anybody noticing.
pub fn diff_files(before: &[u8], after: &[u8], cap: usize) -> FileDiff {
    match (render_content(before, cap), render_content(after, cap)) {
        (Content::Text(before), Content::Text(after)) => {
            FileDiff::Rows(side_by_side(&before, &after))
        }
        (before, after) => FileDiff::Unrenderable { before, after },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::{SpanKind, covers_exactly};
    use proptest::prelude::*;

    /// SHA-256 of the empty input, from `sha256sum </dev/null`. Written out
    /// rather than computed, so that a test of the hash is a test of the hash
    /// and not of `sha256_hex` agreeing with itself.
    const SHA_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    /// SHA-256 of the four bytes `00 9f 92 96`.
    const SHA_BINARY: &str = "b02a591131217cb579165aeccf0d94569acffb9934c84d6c813d77e3abedd233";
    /// SHA-256 of 2048 `a` bytes.
    const SHA_2048_A: &str = "b2a3a502fdfc34f4e3edfa94b7f3109cd972d87a4fec63ab21a6673379ccf7ad";
    /// SHA-256 of the two-character string `éé`, as UTF-8.
    const SHA_EE: &str = "f13c007a1d8e6e1300b5957a143810cdd3555825466cf5d2617b1ac2fd8bd76b";

    /// The four named behaviours from the plan.
    #[test]
    fn diff_rows_round_trip_to_the_original_sides() {
        let before = "alpha\nbeta\ngamma\n";
        let after = "alpha\nBETA\ngamma\n";
        let rows = side_by_side(before, after);
        assert_eq!(rejoin_left(&rows), before);
        assert_eq!(rejoin_right(&rows), after);
    }

    #[test]
    fn changed_lines_are_marked_on_both_sides() {
        let rows = side_by_side("a\nb\n", "a\nc\n");
        assert_eq!(rows.iter().filter(|r| r.changed()).count(), 1);
        // And the marked row is the one that actually differs, on both sides
        // -- a count alone would pass with the mark on the wrong row.
        let marked: Vec<_> = rows.iter().filter(|r| r.changed()).collect();
        assert_eq!(marked[0].left().unwrap().text(), "b\n");
        assert_eq!(marked[0].right().unwrap().text(), "c\n");
    }

    #[test]
    fn binary_content_is_summarised_not_rendered() {
        match render_content(&[0, 159, 146, 150], 1024) {
            Content::Summary { bytes, sha256, reason } => {
                assert_eq!(bytes, 4);
                assert_eq!(sha256, SHA_BINARY);
                assert_eq!(reason, SummaryReason::NotUtf8);
            }
            other => panic!("expected a summary, got {other:?}"),
        }
    }

    #[test]
    fn oversized_content_is_summarised() {
        match render_content(&vec![b'a'; 2048], 1024) {
            Content::Summary { bytes, sha256, reason } => {
                assert_eq!(bytes, 2048);
                assert_eq!(sha256, SHA_2048_A);
                assert_eq!(reason, SummaryReason::TooLarge);
            }
            other => panic!("expected a summary, got {other:?}"),
        }
    }

    // ---- the round trip, over the shapes that classically lose a byte ----

    /// Every one of these is a real file, and each is a way a diff loses a
    /// byte: the last line with no terminator, CRLF that gets normalised, the
    /// empty file that becomes one blank line, the file that is only a
    /// newline, a lone `\r`, and endings that are not uniform. The pair is
    /// diffed both ways round, so each string is exercised as the current
    /// file and as the proposed content.
    const FILES: &[&str] = &[
        "",
        "\n",
        "\r\n",
        "\r",
        "a",
        "a\n",
        "a\nb",
        "a\r\nb\r\n",
        "a\r\nb\n",
        "a\n\n\nb",
        "\n\n\n",
        "alpha\nbeta\ngamma\n",
        "alpha\r\nbeta\r\ngamma",
        "ünïcödé\n\u{202E}gnp.exe\n",
        "tab\there\nnbsp\u{00A0}here",
    ];

    #[test]
    fn round_trip_over_every_awkward_file_shape() {
        for before in FILES {
            for after in FILES {
                let rows = side_by_side(before, after);
                assert_eq!(
                    rejoin_left(&rows),
                    *before,
                    "left column lost bytes for {before:?} -> {after:?}"
                );
                assert_eq!(
                    rejoin_right(&rows),
                    *after,
                    "right column lost bytes for {before:?} -> {after:?}"
                );
            }
        }
    }

    #[test]
    fn an_empty_file_has_no_rows_rather_than_one_blank_one() {
        // The difference matters: one blank row would rejoin to "\n" on a
        // file that is zero bytes, and creating a file would look like
        // replacing an empty line.
        let rows = side_by_side("", "");
        assert!(rows.is_empty());
        assert_eq!(rejoin_left(&rows), "");
        assert_eq!(rejoin_right(&rows), "");
    }

    #[test]
    fn a_file_that_is_one_newline_is_one_row_of_pure_terminator() {
        let rows = side_by_side("\n", "\n");
        assert_eq!(rows.len(), 1);
        let side = rows[0].left().unwrap();
        assert_eq!(side.text(), "\n");
        assert!(side.content_spans().is_empty());
        assert_eq!(side.terminator_spans().len(), 1);
    }

    #[test]
    fn a_final_line_without_a_terminator_keeps_all_its_spans_as_content() {
        let rows = side_by_side("a\nb", "a\nb");
        assert_eq!(rows.len(), 2);
        let last = rows[1].left().unwrap();
        assert_eq!(last.text(), "b");
        assert_eq!(last.content_spans().len(), 1);
        assert!(last.terminator_spans().is_empty());
    }

    #[test]
    fn adding_a_final_newline_is_a_change_the_reader_can_see() {
        // "a" and "a\n" are different files, and a view that trimmed
        // terminators before comparing would draw the two columns identically
        // over a write that really does add a byte.
        let rows = side_by_side("a", "a\n");
        assert_eq!(rejoin_left(&rows), "a");
        assert_eq!(rejoin_right(&rows), "a\n");
        assert!(rows.iter().any(Row::changed), "the added newline must be marked");
    }

    #[test]
    fn line_endings_are_never_normalised_away() {
        // A whole-file CRLF-to-LF rewrite. Every row must be marked changed,
        // both columns must survive intact, and the terminators must be
        // visibly different -- otherwise the window draws two identical
        // columns over a write that touches every line.
        let rows = side_by_side("a\r\nb\r\n", "a\nb\n");
        assert_eq!(rejoin_left(&rows), "a\r\nb\r\n");
        assert_eq!(rejoin_right(&rows), "a\nb\n");
        assert!(rows.iter().all(Row::changed), "every line ending changed");
        for row in &rows {
            assert_eq!(row.left().unwrap().terminator_spans().len(), 2, "CRLF is two chips");
            assert_eq!(row.right().unwrap().terminator_spans().len(), 1, "LF is one");
        }
    }

    #[test]
    fn a_lone_carriage_return_ends_a_line_and_stays_in_it() {
        let rows = side_by_side("a\rb", "a\rb");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].left().unwrap().text(), "a\r");
        assert_eq!(rows[0].left().unwrap().terminator_spans().len(), 1);
        assert_eq!(rejoin_left(&rows), "a\rb");
    }

    // ---- that the classifier is actually run (invariant 1b wiring) ----

    #[test]
    fn diff_lines_are_classified_so_chips_appear_in_diffs_too() {
        // The fidelity properties are blind to this: a Side that emitted one
        // Plain span over the whole line would round-trip perfectly and would
        // draw a bidi override as itself, reordering the line the reader is
        // approving. The assertion is on the literal characters, not on
        // whatever the classifier happened to pick.
        let rows = side_by_side("safe\n", "ls\u{202E}txt\u{00A0}\n");
        let right = rows.iter().filter_map(Row::right).next().unwrap();
        let chips: Vec<char> = right.spans().iter().filter_map(Span::chip_codepoint).collect();
        assert_eq!(chips, vec!['\u{202E}', '\u{00A0}', '\n']);
        assert_eq!(unrender(right.spans()), "ls\u{202E}txt\u{00A0}\n");
    }

    #[test]
    fn nothing_in_a_row_is_hidden_behind_a_label() {
        // Invariant 1b, over a diff rather than over a command.
        for before in FILES {
            for after in FILES {
                for row in side_by_side(before, after) {
                    for side in [row.left(), row.right()].into_iter().flatten() {
                        assert!(
                            covers_exactly(side.spans(), side.text()),
                            "{:?} is not tiled by its spans",
                            side.text()
                        );
                        for span in side.spans() {
                            match span.kind() {
                                SpanKind::Chip { .. } => assert_eq!(
                                    span.text().chars().count(),
                                    1,
                                    "a chip may stand in for one codepoint at most"
                                ),
                                _ => assert_eq!(
                                    span.display_text(),
                                    span.text(),
                                    "a non-chip span must be drawn exactly as its text"
                                ),
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_side_is_the_concatenation_of_its_content_and_its_terminator() {
        // The two slices the view draws must still add up to the line the
        // rejoin reads. A `content_spans` off by one would pass every
        // round-trip test above and silently move a character of the file
        // into the terminator slot.
        for before in FILES {
            for after in FILES {
                for row in side_by_side(before, after) {
                    for side in [row.left(), row.right()].into_iter().flatten() {
                        let rebuilt =
                            unrender(side.content_spans()) + &unrender(side.terminator_spans());
                        assert_eq!(rebuilt, side.text());
                        assert!(
                            side.terminator_spans().len() <= 2,
                            "{:?} has more than CRLF worth of terminator",
                            side.text()
                        );
                        assert!(
                            side.terminator_spans()
                                .iter()
                                .all(|s| matches!(s.chip_codepoint(), Some('\r' | '\n'))),
                            "{:?} put a non-terminator character in the terminator",
                            side.text()
                        );
                        assert!(
                            !side
                                .content_spans()
                                .iter()
                                .any(|s| matches!(s.chip_codepoint(), Some('\r' | '\n'))),
                            "{:?} left a terminator character in its content",
                            side.text()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn terminator_len_names_each_ending_exactly() {
        // A table test that does not iterate the table it checks.
        assert_eq!(terminator_len(""), 0);
        assert_eq!(terminator_len("a"), 0);
        assert_eq!(terminator_len("\n"), 1);
        assert_eq!(terminator_len("\r"), 1);
        assert_eq!(terminator_len("\r\n"), 2);
        assert_eq!(terminator_len("a\n"), 1);
        assert_eq!(terminator_len("a\r"), 1);
        assert_eq!(terminator_len("a\r\n"), 2);
        assert_eq!(terminator_len("\n\r"), 1, "that is a CR ending, not a CRLF");
        assert_eq!(terminator_len("a\n\n"), 1, "only the last one ends this line");
    }

    // ---- how operations become rows ----

    #[test]
    fn a_deletion_has_no_right_and_an_insertion_has_no_left() {
        let deleted = side_by_side("a\nb\nc\n", "a\nc\n");
        let gone: Vec<_> = deleted.iter().filter(|r| r.right().is_none()).collect();
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].left().unwrap().text(), "b\n");

        let inserted = side_by_side("a\nc\n", "a\nb\nc\n");
        let added: Vec<_> = inserted.iter().filter(|r| r.left().is_none()).collect();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].right().unwrap().text(), "b\n");
    }

    #[test]
    fn a_row_always_has_at_least_one_side() {
        for before in FILES {
            for after in FILES {
                for row in side_by_side(before, after) {
                    assert!(row.left().is_some() || row.right().is_some());
                }
            }
        }
    }

    #[test]
    fn an_unequal_replace_pairs_what_it_can_and_leaves_the_surplus_one_sided() {
        // Three lines become one. The reader should get one row that pairs
        // the first of each, then two rows carrying the leftover left lines
        // with nothing opposite -- not a silently dropped line, and not a
        // pairing that runs off the end of the shorter block.
        let rows = side_by_side("one\ntwo\nthree\n", "ONE\n");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].left().unwrap().text(), "one\n");
        assert_eq!(rows[0].right().unwrap().text(), "ONE\n");
        assert_eq!(rows[1].left().unwrap().text(), "two\n");
        assert!(rows[1].right().is_none());
        assert_eq!(rows[2].left().unwrap().text(), "three\n");
        assert!(rows[2].right().is_none());
        assert!(rows.iter().all(Row::changed));
        assert_eq!(rejoin_left(&rows), "one\ntwo\nthree\n");
        assert_eq!(rejoin_right(&rows), "ONE\n");
    }

    #[test]
    fn an_unequal_replace_leaves_the_surplus_on_the_longer_side() {
        // The mirror of the test above: when the proposal is longer, the
        // surplus rows must be right-only. A single `min`/`max` confusion
        // would put them on the wrong side, or drop them.
        let rows = side_by_side("ONE\n", "one\ntwo\nthree\n");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].left().unwrap().text(), "ONE\n");
        assert!(rows[1].left().is_none() && rows[2].left().is_none());
        assert_eq!(rows[1].right().unwrap().text(), "two\n");
        assert_eq!(rows[2].right().unwrap().text(), "three\n");
        assert_eq!(rejoin_left(&rows), "ONE\n");
        assert_eq!(rejoin_right(&rows), "one\ntwo\nthree\n");
    }

    #[test]
    fn an_unmarked_row_really_is_two_identical_lines() {
        // `changed` is taken from the operation rather than from comparing
        // the sides, so this is what makes that safe: an unmarked row that
        // was not byte-identical would be a change the reader is told is not
        // one, which is the failure direction that costs them the write.
        for before in FILES {
            for after in FILES {
                for row in side_by_side(before, after) {
                    if !row.changed() {
                        let (left, right) = (row.left().unwrap(), row.right().unwrap());
                        assert_eq!(
                            left.text(),
                            right.text(),
                            "unmarked row differs, in {before:?} -> {after:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn identical_files_produce_no_changed_rows() {
        let rows = side_by_side("alpha\nbeta\n", "alpha\nbeta\n");
        assert_eq!(rows.len(), 2);
        assert!(!rows.iter().any(Row::changed), "nothing changed, so nothing is marked");
    }

    #[test]
    fn rows_stay_in_file_order_on_both_sides() {
        // Reordering rows would still round-trip if the reorder were applied
        // to both columns, so this checks the columns independently against
        // the files they came from.
        let before = "a\nb\nc\nd\n";
        let after = "a\nc\nX\nd\n";
        let rows = side_by_side(before, after);
        let left: Vec<&str> = rows.iter().filter_map(Row::left).map(Side::text).collect();
        let right: Vec<&str> = rows.iter().filter_map(Row::right).map(Side::text).collect();
        assert_eq!(left, vec!["a\n", "b\n", "c\n", "d\n"]);
        assert_eq!(right, vec!["a\n", "c\n", "X\n", "d\n"]);
    }

    #[test]
    fn rejoining_reads_the_spans_and_not_a_stored_line() {
        // What makes the round-trip a test of the rendering at all. Every
        // rejoined byte must come out of a span, so the two ways of spelling
        // a side have to agree for every side in a diff.
        for before in FILES {
            for after in FILES {
                for row in side_by_side(before, after) {
                    for side in [row.left(), row.right()].into_iter().flatten() {
                        assert_eq!(unrender(side.spans()), side.text());
                    }
                }
            }
        }
    }

    // ---- render_content ----

    #[test]
    fn text_within_the_cap_is_returned_verbatim() {
        assert_eq!(render_content(b"alpha\nbeta\n", 1024), Content::Text("alpha\nbeta\n".into()));
        assert_eq!(render_content(b"", 1024), Content::Text(String::new()));
        assert_eq!(render_content("éé".as_bytes(), 1024), Content::Text("éé".into()));
    }

    #[test]
    fn the_cap_is_a_maximum_and_not_a_forbidden_size() {
        // The boundary, pinned from both sides: exactly `cap` bytes is text,
        // one more is a summary. An off-by-one here refuses a file that fits.
        assert!(matches!(render_content(&vec![b'a'; 1024], 1024), Content::Text(_)));
        assert!(matches!(render_content(&vec![b'a'; 1025], 1024), Content::Summary { .. }));
        assert!(matches!(render_content(b"", 0), Content::Text(_)), "a zero cap still fits nothing");
        assert!(matches!(render_content(b"a", 0), Content::Summary { .. }));
    }

    #[test]
    fn an_oversized_summary_reports_its_real_size_and_not_the_cap() {
        match render_content(&vec![b'a'; 2048], 1024) {
            Content::Summary { bytes, .. } => assert_eq!(bytes, 2048),
            other => panic!("expected a summary, got {other:?}"),
        }
    }

    #[test]
    fn oversized_binary_is_reported_as_oversized() {
        // The cap is checked before UTF-8 validity, so that validating input
        // an agent chose is bounded by the limit rather than the other way
        // round. This pins that order: swapping the two checks reports
        // NotUtf8 here.
        let mut big = vec![b'a'; 2048];
        big[0] = 0xff;
        match render_content(&big, 1024) {
            Content::Summary { reason, .. } => assert_eq!(reason, SummaryReason::TooLarge),
            other => panic!("expected a summary, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_multibyte_character_is_not_text() {
        // Valid UTF-8 cut mid-character: the case a byte-length cap creates
        // on its own, and the one a naive `from_utf8_lossy` would paper over
        // by inventing a replacement character into approved content.
        let bytes = &"é".as_bytes()[..1];
        assert!(matches!(
            render_content(bytes, 1024),
            Content::Summary { reason: SummaryReason::NotUtf8, .. }
        ));
    }

    #[test]
    fn the_hash_is_of_the_raw_bytes() {
        // Against `sha256sum`, which is what a reader would check it with.
        // Fixed vectors, so this is a test of the hash rather than of the
        // hasher agreeing with itself.
        assert_eq!(sha256_hex(b""), SHA_EMPTY);
        assert_eq!(sha256_hex(&[0, 159, 146, 150]), SHA_BINARY);
        assert_eq!(sha256_hex("éé".as_bytes()), SHA_EE, "the bytes, not the codepoints");
        assert_eq!(sha256_hex(b"").len(), 64);
        assert!(sha256_hex(&[0xff; 32]).chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn the_hash_distinguishes_content_the_window_cannot_show() {
        // What the hash is for: two summarised sides that a reader can
        // compare. Same bytes must give the same hash, different bytes a
        // different one, or comparing them tells them nothing.
        let hash = |b: &[u8]| match render_content(b, 0) {
            Content::Summary { sha256, .. } => sha256,
            other => panic!("expected a summary, got {other:?}"),
        };
        assert_eq!(hash(b"abc"), hash(b"abc"));
        assert_ne!(hash(b"abc"), hash(b"abd"));
        assert_ne!(hash(b"ab"), hash(b"ab\n"), "a trailing newline is a different file");
    }

    // ---- diff_files ----

    #[test]
    fn two_text_sides_within_the_cap_produce_rows() {
        match diff_files(b"a\nb\n", b"a\nc\n", 1024) {
            FileDiff::Rows(rows) => {
                assert_eq!(rejoin_left(&rows), "a\nb\n");
                assert_eq!(rejoin_right(&rows), "a\nc\n");
                assert_eq!(rows.iter().filter(|r| r.changed()).count(), 1);
            }
            other => panic!("expected rows, got {other:?}"),
        }
    }

    #[test]
    fn one_unrenderable_side_leaves_no_rows_but_keeps_the_readable_one() {
        // Each side reports for itself. A binary file on disk is not a reason
        // to blank out the short text the agent proposes to overwrite it
        // with -- that text is most of what the reader needs.
        match diff_files(&[0, 159, 146, 150], b"hello\n", 1024) {
            FileDiff::Unrenderable { before, after } => {
                assert!(matches!(
                    before,
                    Content::Summary { bytes: 4, reason: SummaryReason::NotUtf8, .. }
                ));
                assert_eq!(after, Content::Text("hello\n".into()));
            }
            other => panic!("expected an unrenderable pair, got {other:?}"),
        }
    }

    #[test]
    fn either_side_can_be_the_unrenderable_one() {
        // The mirror, so that a check written against only one argument is
        // caught. The agent's proposal can be the binary blob just as easily.
        match diff_files(b"hello\n", &[0, 159, 146, 150], 1024) {
            FileDiff::Unrenderable { before, after } => {
                assert_eq!(before, Content::Text("hello\n".into()));
                assert!(matches!(after, Content::Summary { bytes: 4, .. }));
            }
            other => panic!("expected an unrenderable pair, got {other:?}"),
        }
    }

    #[test]
    fn the_cap_applies_to_each_side_independently() {
        // One oversized side does not summarise the other, and the sizes
        // reported are each side's own.
        match diff_files(&vec![b'a'; 2048], b"short\n", 1024) {
            FileDiff::Unrenderable { before, after } => {
                assert!(matches!(
                    before,
                    Content::Summary { bytes: 2048, reason: SummaryReason::TooLarge, .. }
                ));
                assert_eq!(after, Content::Text("short\n".into()));
            }
            other => panic!("expected an unrenderable pair, got {other:?}"),
        }
        // And both sides oversized reports both sizes, not one twice.
        match diff_files(&vec![b'a'; 2048], &vec![b'b'; 4096], 1024) {
            FileDiff::Unrenderable {
                before: Content::Summary { bytes: b1, sha256: h1, .. },
                after: Content::Summary { bytes: b2, sha256: h2, .. },
            } => {
                assert_eq!((b1, b2), (2048, 4096));
                assert_ne!(h1, h2);
            }
            other => panic!("expected two summaries, got {other:?}"),
        }
    }

    #[test]
    fn two_binary_sides_are_both_summarised() {
        assert!(matches!(
            diff_files(&[0xff], &[0xfe], 1024),
            FileDiff::Unrenderable {
                before: Content::Summary { .. },
                after: Content::Summary { .. },
            }
        ));
    }

    // ---- the round trip as a property ----

    /// Lines built from the pieces that break diffs: the two terminators, a
    /// lone `\r`, blank lines, and characters the classifier must chip.
    fn file() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                "[a-z ]{0,6}",
                Just("\n".to_string()),
                Just("\r\n".to_string()),
                Just("\r".to_string()),
                Just("\t".to_string()),
                Just("\u{202E}".to_string()),
                Just("\u{00A0}".to_string()),
                Just("é".to_string()),
            ],
            0..24,
        )
        .prop_map(|parts| parts.concat())
    }

    proptest! {
        /// The property the whole module exists for, over generated pairs
        /// rather than the fixtures above. The one fixture in the plan cannot
        /// reach a replace block of unequal length, a file whose last line is
        /// unterminated, or mixed line endings; this can.
        #[test]
        fn rows_round_trip_to_both_files(before in file(), after in file()) {
            let rows = side_by_side(&before, &after);
            prop_assert_eq!(rejoin_left(&rows), before.clone());
            prop_assert_eq!(rejoin_right(&rows), after.clone());
        }

        /// Round-tripping a file against itself is the case where a diff is
        /// most tempted to take a shortcut, and where a dropped row is least
        /// visible.
        #[test]
        fn a_file_round_trips_against_itself(text in file()) {
            let rows = side_by_side(&text, &text);
            prop_assert_eq!(rejoin_left(&rows), text.clone());
            prop_assert_eq!(rejoin_right(&rows), text.clone());
            prop_assert!(!rows.iter().any(Row::changed));
        }

        /// Invariant 1b over generated diffs, and the content/terminator
        /// split checked with it: every byte of both files is either drawn as
        /// itself or is one codepoint under a chip, and the two slices the
        /// view draws still add up to the line.
        #[test]
        fn nothing_in_a_generated_diff_is_hidden(before in file(), after in file()) {
            for row in side_by_side(&before, &after) {
                prop_assert!(row.left().is_some() || row.right().is_some());
                for side in [row.left(), row.right()].into_iter().flatten() {
                    prop_assert!(covers_exactly(side.spans(), side.text()));
                    prop_assert_eq!(
                        unrender(side.content_spans()) + &unrender(side.terminator_spans()),
                        side.text()
                    );
                    for span in side.spans() {
                        match span.kind() {
                            SpanKind::Chip { .. } => {
                                prop_assert_eq!(span.text().chars().count(), 1);
                            }
                            _ => prop_assert_eq!(span.display_text(), span.text()),
                        }
                    }
                }
            }
        }

        /// `render_content` never invents, drops or rewrites a byte on the
        /// path it says is text.
        #[test]
        fn text_content_round_trips(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            match render_content(&bytes, 512) {
                Content::Text(text) => prop_assert_eq!(text.as_bytes(), &bytes[..]),
                Content::Summary { bytes: n, .. } => {
                    prop_assert_eq!(n, bytes.len());
                    prop_assert!(std::str::from_utf8(&bytes).is_err());
                }
            }
        }
    }
}
