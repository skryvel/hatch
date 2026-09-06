//! The span model and the rendering fidelity invariant.
//!
//! Everything hatch shows a user about a command is a sequence of [`Span`]s,
//! and every span carries the exact bytes it came from. [`unrender`] is the
//! inverse of every renderer in this tree: concatenating span texts reproduces
//! the input byte for byte.
//!
//! This is invariant 1, and it is not a style preference. hatch's whole
//! security story is that nothing runs on the host that the user did not see
//! and approve. A display that is a lossy transformation of what runs cannot
//! carry that story: earlier tools of this shape rewrote `;` as a newline for
//! readability, and a display that can silently delete one character can in
//! principle delete any of them. A careful reader is then right to stop
//! trusting it on exactly the gnarly commands where trust matters most.
//!
//! So the invariant is structural rather than aspirational. Presentation is
//! expressed as *metadata beside* the original text, never as an edit to it:
//!
//! * A character that must not be drawn as itself — a bidi override, a
//!   zero-width space — becomes [`SpanKind::Chip`], which carries a label for
//!   the screen while `text` stays the original character.
//! * A separator that should start a new visual line sets `break_before` on
//!   the *following* span. The separator itself stays on screen and no
//!   character is consumed by the layout.
//!
//! Keeping the text is necessary but not sufficient: a chip *displays*
//! something other than what it covers, so a chip over half the command
//! would satisfy invariant 1 while hiding that half from the reader. Hence
//! invariant 1b, which bounds how much a label may stand in for:
//!
//! > Every span is drawn as itself, or it is a chip standing for exactly one
//! > codepoint.
//!
//! A chip is therefore the one deliberate gap between shown and real text,
//! and it is a gap exactly one character wide. To flag a run of suspect
//! characters, emit one chip each: the reader then sees a label per hidden
//! character rather than one label over an unknown amount of text.
//!
//! Four things enforce all of this rather than asking for it:
//!
//! 1. `Span`'s fields are private and there is no public mutator that can
//!    touch `text`. This module is a *sibling* of the renderer modules, not
//!    their ancestor, so `render::command` and friends cannot reach past the
//!    accessors — in Rust a child module can see its ancestors' private
//!    fields, so a model defined in `render` itself would be unprotected.
//! 2. Spans are cut from a source string and a byte range rather than built
//!    from an owned string, so a renderer cannot invent text that was not in
//!    the string it was handed. Note the bound on that claim: it makes a
//!    span's text a substring of *the source its builder was given*, and says
//!    nothing about whether that source was the command the user is
//!    approving. Passing the real command in stays the caller's job. The span
//!    constructor is private to this module, so [`SpanBuilder`] is the only
//!    way in.
//! 3. [`SpanBuilder`] walks the source once with a cursor, so gaps, overlaps
//!    and out-of-order spans are unconstructible, and [`SpanBuilder::finish`]
//!    refuses to hand back a sequence that does not tile the whole source.
//! 4. Attaching a chip to more than one codepoint is rejected where the kind
//!    meets the text, so invariant 1b is unconstructible rather than merely
//!    tested for.
//!
//! A renderer bug therefore panics at its origin rather than showing a user a
//! command that is not the one that would run. A panicking prompt window is a
//! dead prompt window, which hatch already treats as a denial, so failing this
//! way fails closed.

use std::borrow::Cow;
use std::ops::{Deref, Range};

/// One unit of rendered output.
///
/// `text` is ALWAYS the exact original substring. Presentation lives in `kind`
/// and `break_before`; it never mutates `text`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    text: String,
    range: Range<usize>,
    kind: SpanKind,
    break_before: bool,
}

/// What a span is, for the benefit of the screen. Never for the benefit of
/// [`unrender`], which ignores this entirely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpanKind {
    Plain,
    /// `;` `&&` `||` `|` — dimmed, kept on screen.
    Separator,
    /// `$VAR` / `${VAR}`.
    Variable,
    /// The first word of a segment.
    Command,
    Danger,
    /// A character that must not be drawn as itself. `text` is still the
    /// original character, and stays exactly one codepoint long; `name` is
    /// only what the screen shows in its place.
    ///
    /// The codepoint is deliberately not stored beside the text. It is
    /// [`Span::chip_codepoint`], read from the text on demand, so the label's
    /// subject and the approved character cannot drift apart.
    Chip { name: &'static str },
}

impl Span {
    /// The span covering `source[range]`.
    ///
    /// Private on purpose. Cutting from a source and a range rather than from
    /// an owned string is what stops a renderer inventing text, but only
    /// [`SpanBuilder`] also guarantees that a whole sequence tiles its source
    /// exactly once — so the builder is the only way to make spans, and a
    /// hand-rolled sequence over a fabricated source is not constructible at
    /// all. Widen this when a task actually needs it, not before.
    ///
    /// # Panics
    ///
    /// If `range` is out of bounds, does not fall on character boundaries, or
    /// gives a chip more than one codepoint to stand for.
    fn new(source: &str, range: Range<usize>, kind: SpanKind) -> Self {
        let text = match source.get(range.clone()) {
            Some(text) => text.to_string(),
            None => panic!(
                "span range {}..{} is out of bounds or not on a character boundary of a \
                 {}-byte source",
                range.start,
                range.end,
                source.len()
            ),
        };
        assert_chip_stands_for_one_codepoint(&text, &kind);
        Span {
            text,
            range,
            kind,
            break_before: false,
        }
    }

    /// The original bytes, exactly. This is what [`unrender`] reads and what
    /// the approval covers.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Where this span came from in the source it was rendered against.
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    pub fn kind(&self) -> &SpanKind {
        &self.kind
    }

    /// Layout hint: draw a line break before this span. Purely visual — no
    /// character is added or consumed by it.
    pub fn break_before(&self) -> bool {
        self.break_before
    }

    /// The single codepoint a chip stands for, or `None` for every other
    /// kind.
    ///
    /// Read out of the text rather than stored alongside it: a copy could
    /// disagree with the character the user actually approved, and a field
    /// that can disagree with the text is worse than no field.
    pub fn chip_codepoint(&self) -> Option<char> {
        match self.kind {
            SpanKind::Chip { .. } => self.text.chars().next(),
            _ => None,
        }
    }

    /// What the UI draws: the chip label for a chip, the original text
    /// otherwise.
    ///
    /// This is the one place in hatch where displayed text may differ from
    /// real text, and it is used only by the UI — never by [`unrender`]. By
    /// invariant 1b the difference is at most one codepoint wide: every other
    /// kind is drawn as itself.
    pub fn display_text(&self) -> Cow<'_, str> {
        match &self.kind {
            SpanKind::Chip { name } => Cow::Borrowed(name),
            _ => Cow::Borrowed(&self.text),
        }
    }
}

/// Invariant 1b, enforced where a kind meets the text it labels.
///
/// A chip is the only span whose drawn text differs from its real text, so
/// the amount it may hide has to be bounded or invariant 1 buys nothing: a
/// single chip over `rm -rf /` would round-trip perfectly and still never
/// reach the reader's eye. One codepoint is that bound.
///
/// The message carries a count and never the text, so a panic cannot copy a
/// command into somewhere it was not approved for.
fn assert_chip_stands_for_one_codepoint(text: &str, kind: &SpanKind) {
    if matches!(kind, SpanKind::Chip { .. }) {
        let mut chars = text.chars();
        let one = chars.next().is_some() && chars.next().is_none();
        assert!(
            one,
            "a chip stands for exactly one codepoint, not {}: a label may not \
             hide more text than it replaces",
            text.chars().count()
        );
    }
}

/// The inverse of every renderer in this module. Concatenating span texts
/// reproduces the input exactly. This is invariant 1 and it is property-tested.
pub fn unrender(spans: &[Span]) -> String {
    spans.iter().map(|s| s.text.as_str()).collect()
}

/// True when `spans` tile `source` exactly once: in source order, no gaps, no
/// overlaps, nothing past the end, nothing left over, and every span's text
/// really is the source text of its own range.
///
/// Empty spans are rejected rather than tolerated. They would slip through a
/// pure cursor walk — `source.get(i..i)` is `Some("")` and the cursor does not
/// move — and [`SpanBuilder`] drops them, so accepting them here would bless
/// sequences the builder would not have produced.
///
/// [`SpanBuilder`] cannot produce a sequence that fails this; it is checked in
/// [`SpanBuilder::finish`] and re-checkable at any time through
/// [`Spans::covers_source`], which is what a UI boundary or a renderer's own
/// tests should assert on.
pub fn covers_exactly(spans: &[Span], source: &str) -> bool {
    let mut cursor = 0;
    for span in spans {
        if span.range.start != cursor || span.range.end <= span.range.start {
            return false;
        }
        match source.get(span.range.clone()) {
            Some(text) if text == span.text => {}
            _ => return false,
        }
        cursor = span.range.end;
    }
    cursor == source.len()
}

/// A rendered command: the source it was rendered from, plus the spans that
/// tile it.
///
/// Constructing one goes through [`SpanBuilder`], so a `Spans` in hand is
/// evidence that the invariant held at the moment it was built. The mutators
/// here can retag and relayout but cannot change any span's text, so it keeps
/// holding.
///
/// Derefs to `[Span]`, so `.iter()`, `.len()` and indexing work as usual.
/// There is deliberately no `DerefMut` and no way to obtain a `&mut Span`:
/// that is what keeps `text` out of reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spans {
    source: String,
    spans: Vec<Span>,
}

impl Spans {
    /// The exact input these spans were rendered from. A later pass can start
    /// a fresh [`SpanBuilder`] over it.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Re-label one span. Cannot affect fidelity: kinds are display only.
    ///
    /// # Panics
    ///
    /// If `index` is out of bounds, or the new kind is a chip and the span
    /// stands for more than one codepoint. Retagging is the other way a chip
    /// could come to cover a whole command, so it is checked here as well as
    /// at construction.
    pub fn set_kind(&mut self, index: usize, kind: SpanKind) {
        assert_chip_stands_for_one_codepoint(self.spans[index].text(), &kind);
        self.spans[index].kind = kind;
    }

    /// Draw a line break before one span. Cannot affect fidelity: layout adds
    /// and consumes no characters.
    ///
    /// # Panics
    ///
    /// If `index` is out of bounds.
    pub fn set_break_before(&mut self, index: usize, break_before: bool) {
        self.spans[index].break_before = break_before;
    }

    /// Split the span at `index` in two at absolute source offset `at`, and
    /// return the index of the right half. Both halves keep the original
    /// kind; `break_before` stays with the left half, which is the one that
    /// still starts where the original did.
    ///
    /// This is how a later pass refines an existing rendering — chips inside a
    /// word, a command name at the head of a segment — without rebuilding the
    /// sequence by hand. The text is redistributed, never rewritten.
    ///
    /// Every index after the split point shifts up by one, so use the returned
    /// index rather than the one you were iterating with. Mis-tagging cannot
    /// break invariant 1, but a `Danger` marker drawn against the wrong text
    /// is a safety signal pointing at the wrong thing, which is its own kind
    /// of lie to the reader.
    ///
    /// # Panics
    ///
    /// If `index` is out of bounds, or `at` does not fall strictly inside that
    /// span on a character boundary. A chip is one codepoint, so it has no
    /// interior boundary and can never be split.
    pub fn split(&mut self, index: usize, at: usize) -> usize {
        let span = &self.spans[index];
        assert!(
            span.range.start < at && at < span.range.end,
            "split offset {at} must fall strictly inside the span at {}..{}",
            span.range.start,
            span.range.end
        );
        let (range, kind, break_before) = (span.range.clone(), span.kind.clone(), span.break_before);

        let mut left = Span::new(&self.source, range.start..at, kind.clone());
        left.break_before = break_before;
        let right = Span::new(&self.source, at..range.end, kind);

        self.spans[index] = left;
        self.spans.insert(index + 1, right);
        index + 1
    }

    /// Re-check invariant 1 against the source. Always true unless this module
    /// has a bug; cheap enough to assert on in tests and at UI boundaries.
    pub fn covers_source(&self) -> bool {
        covers_exactly(&self.spans, &self.source)
    }
}

impl Deref for Spans {
    type Target = [Span];

    fn deref(&self) -> &[Span] {
        &self.spans
    }
}

/// Builds a [`Spans`] by walking a source string once, left to right.
///
/// The cursor is the whole trick: a renderer says where each span *ends* and
/// the builder supplies the text from the source itself. There is no way to
/// skip a byte, repeat one, emit spans out of order, or invent text that is
/// not in the source — and [`SpanBuilder::finish`] refuses to return a
/// sequence that stops short of the end.
pub struct SpanBuilder<'a> {
    source: &'a str,
    cursor: usize,
    break_next: bool,
    spans: Vec<Span>,
}

impl<'a> SpanBuilder<'a> {
    pub fn new(source: &'a str) -> Self {
        SpanBuilder {
            source,
            cursor: 0,
            break_next: false,
            spans: Vec::new(),
        }
    }

    /// The string being rendered.
    pub fn source(&self) -> &'a str {
        self.source
    }

    /// Byte offset of the next span's start: everything before it is already
    /// covered.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Emit `source[cursor..end]` as one span and advance the cursor to `end`.
    ///
    /// `end == cursor` emits nothing: an empty span would display nothing and
    /// carry nothing, and letting them through only gives the UI a case to
    /// mishandle. A pending [`SpanBuilder::break_next`] survives such a call
    /// and attaches to the next span that is actually emitted.
    ///
    /// # Panics
    ///
    /// If `end` is behind the cursor, past the end of the source, or not on a
    /// character boundary.
    pub fn push_to(&mut self, end: usize, kind: SpanKind) {
        assert!(
            end >= self.cursor,
            "spans must be pushed in source order: end {end} is behind cursor {}",
            self.cursor
        );
        if end == self.cursor {
            return;
        }
        let mut span = Span::new(self.source, self.cursor..end, kind);
        if self.break_next {
            span.break_before = true;
            self.break_next = false;
        }
        self.spans.push(span);
        self.cursor = end;
    }

    /// Emit everything from the cursor to the end of the source as one span.
    pub fn push_rest(&mut self, kind: SpanKind) {
        self.push_to(self.source.len(), kind);
    }

    /// The next span emitted starts on a new line.
    ///
    /// This is how a separator gets a line break after it: the break belongs
    /// to the span that follows, so the separator stays on screen instead of
    /// being replaced by the newline that a lossy renderer would substitute.
    pub fn break_next(&mut self) {
        self.break_next = true;
    }

    /// Finish, checking that the spans tile the whole source.
    ///
    /// # Panics
    ///
    /// If any of the source is uncovered, or — belt and braces against a bug
    /// in this module itself — if the resulting sequence fails
    /// [`covers_exactly`].
    pub fn finish(self) -> Spans {
        assert_eq!(
            self.cursor,
            self.source.len(),
            "a renderer must cover the whole source: {} of {} bytes rendered",
            self.cursor,
            self.source.len()
        );
        assert!(
            covers_exactly(&self.spans, self.source),
            "rendered spans do not tile the source exactly"
        );
        Spans {
            source: self.source.to_string(),
            spans: self.spans,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIDI: &str = "\u{202E}";

    /// A rendering of `a;\u{202E}b` with a chip, a separator and a line break:
    /// everything a later renderer will do to a span sequence, done by hand
    /// through the public API.
    fn sample() -> (String, Spans) {
        let source = format!("a;{BIDI}b");
        let mut builder = SpanBuilder::new(&source);
        builder.push_to(1, SpanKind::Command);
        builder.push_to(2, SpanKind::Separator);
        builder.break_next();
        builder.push_to(5, SpanKind::Chip { name: "[RLO]" });
        builder.push_rest(SpanKind::Plain);
        let spans = builder.finish();
        (source, spans)
    }

    #[test]
    fn span_text_is_the_source_substring() {
        let span = Span::new("echo hi", 5..7, SpanKind::Plain);
        assert_eq!(span.text(), "hi");
        assert_eq!(span.range(), 5..7);
    }

    #[test]
    #[should_panic(expected = "not on a character boundary")]
    fn span_range_must_be_on_a_character_boundary() {
        Span::new("é", 0..1, SpanKind::Plain);
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn span_range_must_be_in_bounds() {
        Span::new("ab", 0..3, SpanKind::Plain);
    }

    #[test]
    fn unrender_reproduces_the_source() {
        let (source, spans) = sample();
        assert_eq!(unrender(&spans), source);
        assert!(spans.covers_source());
    }

    #[test]
    fn a_chip_displays_its_label_but_keeps_the_original_character() {
        let (_, spans) = sample();
        let chip = &spans[2];
        assert_eq!(chip.text(), BIDI, "the original character must survive");
        assert_eq!(chip.display_text(), "[RLO]", "but it must not be drawn as itself");
    }

    #[test]
    fn plain_spans_display_their_own_text() {
        let (_, spans) = sample();
        assert_eq!(spans[0].display_text(), "a");
        assert_eq!(spans[1].display_text(), ";");
    }

    #[test]
    fn a_line_break_lands_on_the_span_after_the_separator() {
        let (source, spans) = sample();
        assert_eq!(spans[1].text(), ";", "the separator is still a character");
        assert!(!spans[1].break_before());
        assert!(spans[2].break_before(), "the break belongs to the following span");
        assert_eq!(
            unrender(&spans),
            source,
            "layout must not add or consume characters"
        );
    }

    #[test]
    fn builder_skips_empty_spans_but_keeps_a_pending_break() {
        let mut builder = SpanBuilder::new("ab");
        builder.push_to(0, SpanKind::Plain);
        builder.break_next();
        builder.push_to(0, SpanKind::Plain);
        builder.push_rest(SpanKind::Plain);
        let spans = builder.finish();
        assert_eq!(spans.len(), 1);
        assert!(spans[0].break_before());
    }

    #[test]
    #[should_panic(expected = "must be pushed in source order")]
    fn builder_rejects_going_backwards() {
        let mut builder = SpanBuilder::new("abc");
        builder.push_to(2, SpanKind::Plain);
        builder.push_to(1, SpanKind::Plain);
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn builder_rejects_running_past_the_end() {
        let mut builder = SpanBuilder::new("abc");
        builder.push_to(4, SpanKind::Plain);
    }

    #[test]
    #[should_panic(expected = "must cover the whole source")]
    fn builder_rejects_dropping_the_tail() {
        let mut builder = SpanBuilder::new("abc");
        builder.push_to(2, SpanKind::Plain);
        builder.finish();
    }

    #[test]
    fn a_chip_stands_for_exactly_one_codepoint() {
        // Three bytes, one codepoint: the check is on characters, not length.
        let (_, spans) = sample();
        assert_eq!(spans[2].text().len(), 3);
        assert_eq!(spans[2].chip_codepoint(), Some('\u{202E}'));
        assert_eq!(spans[0].chip_codepoint(), None, "only chips have one");
    }

    #[test]
    #[should_panic(expected = "stands for exactly one codepoint, not 10")]
    fn a_chip_may_not_be_built_over_more_than_one_codepoint() {
        // Invariant 1 alone would allow this: the text round-trips perfectly
        // while the screen shows "[NBSP]" and the user never sees the command.
        let source = "echo hi; rm -rf /";
        let mut builder = SpanBuilder::new(source);
        builder.push_to(7, SpanKind::Plain);
        builder.push_rest(SpanKind::Chip { name: "[NBSP]" });
        builder.finish();
    }

    #[test]
    #[should_panic(expected = "stands for exactly one codepoint, not 4")]
    fn a_span_may_not_be_retagged_into_an_oversized_chip() {
        let mut builder = SpanBuilder::new("sudo");
        builder.push_rest(SpanKind::Plain);
        builder
            .finish()
            .set_kind(0, SpanKind::Chip { name: "[NBSP]" });
    }

    #[test]
    fn a_chip_hides_no_more_than_it_shows() {
        let (_, spans) = sample();
        for span in spans.iter() {
            match span.kind() {
                SpanKind::Chip { .. } => assert_eq!(span.text().chars().count(), 1),
                _ => assert_eq!(span.display_text(), span.text()),
            }
        }
    }

    #[test]
    fn split_redistributes_text_without_rewriting_it() {
        let source = "sudo rm";
        let mut builder = SpanBuilder::new(source);
        builder.break_next();
        builder.push_rest(SpanKind::Plain);
        let mut spans = builder.finish();

        let right = spans.split(0, 4);
        spans.set_kind(0, SpanKind::Command);

        assert_eq!(right, 1, "the caller needs the shifted index, not its own");
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].text(), "sudo");
        assert_eq!(spans[1].text(), " rm");
        assert_eq!(spans[0].range(), 0..4);
        assert_eq!(spans[1].range(), 4..7);
        assert_eq!(spans[1].kind(), &SpanKind::Plain, "the right half keeps the kind");
        assert!(spans[0].break_before(), "the break stays with the left half");
        assert!(!spans[1].break_before());
        assert_eq!(unrender(&spans), source);
        assert!(spans.covers_source());
    }

    #[test]
    #[should_panic(expected = "strictly inside")]
    fn split_rejects_an_offset_outside_the_span() {
        let mut builder = SpanBuilder::new("abc");
        builder.push_rest(SpanKind::Plain);
        builder.finish().split(0, 3);
    }

    #[test]
    fn split_returns_an_index_that_survives_earlier_splits() {
        let source = "a b c";
        let mut builder = SpanBuilder::new(source);
        builder.push_rest(SpanKind::Plain);
        let mut spans = builder.finish();

        let tail = spans.split(0, 1);
        let later = spans.split(tail, 3);
        spans.set_kind(later, SpanKind::Danger);

        assert_eq!(spans[later].text(), " c", "the marker lands on the text it names");
        assert_eq!(unrender(&spans), source);
        assert!(spans.covers_source());
    }

    #[test]
    fn retagging_and_relayout_cannot_change_the_text() {
        let (source, mut spans) = sample();
        for index in 0..spans.len() {
            spans.set_kind(index, SpanKind::Danger);
            spans.set_break_before(index, true);
        }
        assert_eq!(unrender(&spans), source);
    }

    #[test]
    fn covers_exactly_accepts_a_faithful_rendering() {
        let (source, spans) = sample();
        assert!(covers_exactly(&spans, &source));
    }

    #[test]
    fn covers_exactly_rejects_gaps_overlaps_and_reordering() {
        let source = "abcd";
        let a = Span::new(source, 0..2, SpanKind::Plain);
        let b = Span::new(source, 2..4, SpanKind::Plain);
        let gap = Span::new(source, 3..4, SpanKind::Plain);
        let overlap = Span::new(source, 1..4, SpanKind::Plain);

        assert!(covers_exactly(&[a.clone(), b.clone()], source));
        assert!(!covers_exactly(&[a.clone(), gap], source), "gap");
        assert!(!covers_exactly(&[a.clone(), overlap], source), "overlap");
        assert!(!covers_exactly(&[b, a.clone()], source), "out of order");
        assert!(!covers_exactly(&[a], source), "tail dropped");
        assert!(!covers_exactly(&[], source), "everything dropped");
        assert!(covers_exactly(&[], ""), "empty source needs no spans");
    }

    #[test]
    fn covers_exactly_rejects_zero_length_spans() {
        // A cursor walk alone would let these through: source.get(2..2) is
        // Some("") and the cursor does not move. The builder drops them, so
        // accepting them here would bless what it would not have produced.
        let source = "abcd";
        let empty = Span {
            text: String::new(),
            range: 2..2,
            kind: SpanKind::Plain,
            break_before: false,
        };
        let a = Span::new(source, 0..2, SpanKind::Plain);
        let b = Span::new(source, 2..4, SpanKind::Plain);
        assert!(!covers_exactly(&[a, empty, b], source));
    }

    #[test]
    fn covers_exactly_rejects_text_that_is_not_the_source() {
        let mut span = Span::new("abcd", 0..4, SpanKind::Plain);
        span.text = "abXd".to_string();
        assert!(
            !covers_exactly(&[span], "abcd"),
            "a span whose text was rewritten must be caught even though its range still fits"
        );
    }
}
