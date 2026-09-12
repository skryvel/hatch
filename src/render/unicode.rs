//! Bidi / zero-width / non-ASCII classification and the NFC check.
//!
//! Agent-controlled text can lie to the reader about itself, and every lie in
//! this module's remit is a lie a plain terminal tells willingly:
//!
//! * **Bidi overrides** (U+202A–U+202E, U+2066–U+2069) reorder displayed text
//!   against the bytes that run — Trojan Source. `rm -rf /tmp\u{202E}txt.exe`
//!   is not the command it looks like.
//! * **Zero-width and invisible characters** (U+200B–U+200D, U+00AD soft
//!   hyphen, U+FEFF) hide inside identifiers and paths, so two different
//!   strings draw identically.
//! * **U+2028 / U+2029** hide a line break from the reader and from naive
//!   segmentation.
//! * **NBSP** passes for a space, so an argument boundary can be faked.
//! * **Homoglyphs** need no trick at all: Cyrillic `а` simply *is* a
//!   different character that draws like ASCII `a`, and `/home/us\u{0430}r`
//!   is not `/home/user`.
//!
//! There is no list of dangerous characters that is both short and complete —
//! the homoglyph case alone spans most of Unicode. So the rule here is not
//! "chip the bad characters" but the inverse: **draw as itself only what is
//! unambiguously safe to draw, and chip everything else.** A chip keeps the
//! original character as its text (invariant 1) and shows a label in its
//! place, so the reader is told *which* character is there rather than being
//! shown a glyph that may not mean what it looks like.
//!
//! The safe set is ASCII printable, U+0020 through U+007E. Everything outside
//! it chips, named where the name helps and `[U+XXXX]` otherwise.
//!
//! # Two tiers of chip, because uniform alarm is no alarm
//!
//! Chipping everything outside the safe set is the right rule and it has one
//! cost: a heredoc puts ten identical orange `[LF]`s down the right edge of
//! the pane, and a reader who learns to skip those is a reader who will skip
//! the one that is a bidi override. A display where everything shouts says
//! nothing.
//!
//! So a chip's *label* is tiered even though its *presence* is not — see
//! [`ChipTier`]. A newline, a carriage return and a tab are ordinary structure
//! in a shell command: they are not disguises, and what a reader needs from
//! them is to see where they are, not to be warned. They get a compact glyph
//! the window draws quietly. Everything else — the bidi controls, the
//! zero-width set, NBSP, homoglyphs, unnamed codepoints — keeps the loud
//! bracketed label, so the alarm is spent only where there is something to be
//! alarmed about.
//!
//! NBSP is deliberately in the loud tier and not with the tab. It is invisible
//! and passes for a space, which makes it a way to fake an argument boundary;
//! that is a hazard rather than structure, and the fact that it is
//! whitespace-shaped is exactly why it must not be drawn like whitespace.
//!
//! Nothing about the tier weakens invariant 1b. A structural chip still stands
//! for exactly one codepoint and still keeps that codepoint as its text; only
//! the string on screen is shorter. And the glyphs are chosen from outside
//! ASCII on purpose, so a command containing a literal `↵` chips it as
//! `[U+21B5]` rather than drawing it: every character either pane draws as
//! itself is ASCII printable, so any of these glyphs on screen is
//! unambiguously hatch's word and never the command's own byte.

use std::borrow::Cow;

use unicode_normalization::is_nfc;

use super::{SpanBuilder, SpanKind, Spans};

/// True for the characters that may be drawn as themselves: ASCII printable,
/// space through `~`.
///
/// **Tab and newline are deliberately outside this set**, even though both are
/// ordinary in a shell command and neither is exotic. Two reasons, and the
/// second is the one that decides it:
///
/// 1. Their width is not their content. A tab renders as between one and eight
///    columns depending on where it lands, and a run of tabs can push text off
///    the visible width of the window or align it to look like a different
///    command. A reader cannot count what they cannot measure.
/// 2. hatch draws layout breaks as metadata — `break_before` on the following
///    span — precisely so that no character is ever consumed by the layout. If
///    a literal U+000A were drawn as itself, a break on screen would no longer
///    tell the reader whether it is layout or content. A chip keeps those two
///    readings apart, and a newline inside a command is exactly the structure a
///    reader most needs to see.
///
/// The cost is that a multi-line command is noisier to read, and
/// [`ChipTier`] is how much of that cost is paid back: these three are the
/// structural tier, so a heredoc shows a column of quiet `↵` rather than a
/// column of orange `[LF]`. They are still chips, and still one per
/// character.
fn is_plain(c: char) -> bool {
    c == ' ' || c.is_ascii_graphic()
}

/// How loudly a chip asks to be drawn.
///
/// A property of the character, computed by [`chip_tier`] and never stored
/// beside the text — [`super::Span::chip_tier`] reads it back out of the
/// codepoint the chip covers, for the same reason
/// [`super::Span::chip_codepoint`] does: a stored copy is a thing that can
/// come to disagree with the character the user approved.
///
/// The window is where this turns into pixels, and the window is told the
/// tier rather than being left to recognise a label. A view that looked for
/// `[LF]` would be reading a label, and a label is the one thing on screen a
/// command may contain literally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipTier {
    /// A newline, a carriage return or a tab: ordinary structure in a shell
    /// command. Drawn as a compact glyph, quietly.
    Structural,
    /// Everything else that must not be drawn as itself. Drawn as its
    /// bracketed label, loudly.
    Loud,
}

/// The characters that are structure rather than disguise, and the compact
/// glyph each is drawn as.
///
/// Three entries and no more, and each one earns its place by being something
/// a reader needs *located* rather than *flagged*. A CRLF then reads `⇤↵`,
/// which is quieter than `[CR][LF]` and also more distinguishable: two glyphs
/// of different shapes rather than two bracketed words of the same shape.
///
/// The glyphs are all outside ASCII, which is what keeps them from ever being
/// confused with the command's own text — see the module docs — and all three
/// are one advance wide in the window's monospace font, which the diff's
/// character-count fit depends on and
/// `every_glyph_the_panes_draw_is_one_monospace_advance` pins.
///
/// `⇤` for the carriage return rather than the Unicode control picture `␍`:
/// the control pictures are in none of the fonts the window ships, so `␍`
/// would draw as nothing at all — a character that is on screen in name only
/// is exactly the failure a chip exists to prevent. `⇤` says what a carriage
/// return does, which is to go back to the start of the line rather than to
/// open a new one, and it pairs with `↵` for the CRLF case.
///
/// `⇥` for the tab and not the plain arrow `→`, which is the glyph a
/// resolved variable's note already uses — `$HOME → /home/user`. Two meanings
/// behind one glyph, told apart only by where they appear, is the argument
/// that lost when the chips stopped being uniform. `⇥` is the tab key's own
/// glyph, it pairs with `⇤` the way the two keys do, and it is one advance
/// of the same font.
const STRUCTURAL: &[(char, &str)] = &[
    ('\u{0009}', "\u{21E5}"),  // TAB, drawn as ⇥
    ('\u{000A}', "\u{21B5}"),  // LF, drawn as ↵
    ('\u{000D}', "\u{21E4}"),  // CR, drawn as ⇤
];

/// Which tier a character's chip is in.
///
/// Total, and defined for every character including the ones that never chip:
/// the question "how loud is this?" has an answer for `a` too, and it is
/// [`ChipTier::Loud`], which costs nothing because `a` is drawn as itself.
pub fn chip_tier(c: char) -> ChipTier {
    match STRUCTURAL.iter().any(|(structural, _)| *structural == c) {
        true => ChipTier::Structural,
        false => ChipTier::Loud,
    }
}

/// Labels for the characters worth naming.
///
/// Membership here changes only what a chip *says*, never whether one is
/// emitted: [`is_plain`] alone decides that, so an unnamed character is
/// chipped just the same and merely gets the terser `[U+XXXX]`. The table is
/// therefore a readability affordance and not a security boundary, and it is
/// short on purpose.
///
/// It covers the characters the threat model names — the bidi controls, the
/// zero-width set, NBSP, soft hyphen, BOM, line and paragraph separator — plus
/// the three bidi *marks* from the same family, and the three ASCII controls a
/// reader is most likely to meet in a real command.
const NAMED: &[(char, &str)] = &[
    ('\u{0009}', "[TAB]"),
    ('\u{000A}', "[LF]"),
    ('\u{000D}', "[CR]"),
    ('\u{00A0}', "[NBSP]"),
    ('\u{00AD}', "[SHY]"),
    ('\u{061C}', "[ALM]"),
    ('\u{200B}', "[ZWSP]"),
    ('\u{200C}', "[ZWNJ]"),
    ('\u{200D}', "[ZWJ]"),
    ('\u{200E}', "[LRM]"),
    ('\u{200F}', "[RLM]"),
    ('\u{2028}', "[LS]"),
    ('\u{2029}', "[PS]"),
    ('\u{202A}', "[LRE]"),
    ('\u{202B}', "[RLE]"),
    ('\u{202C}', "[PDF]"),
    ('\u{202D}', "[LRO]"),
    ('\u{202E}', "[RLO]"),
    ('\u{2066}', "[LRI]"),
    ('\u{2067}', "[RLI]"),
    ('\u{2068}', "[FSI]"),
    ('\u{2069}', "[PDI]"),
    ('\u{FEFF}', "[BOM]"),
];

/// Inclusive ranges of characters that carry no ink of their own, or that
/// pass for an ordinary space.
///
/// **Best-effort, and deliberately not a security boundary.** Nothing here
/// decides what is chipped — [`is_plain`] alone does that, and it is a
/// whitelist, so a character missing from this table is drawn as a chip just
/// the same. The only cost of an omission is that [`ScanReport::invisible`]
/// under-reports, and the only cost of an over-inclusion is that it
/// over-reports. Unicode adds characters that draw as nothing faster than any
/// hand-written list tracks them, so this one claims to be useful rather than
/// complete; the alternative, a `Default_Ignorable_Code_Point` predicate, is
/// a whole dependency bought for a count in a summary line.
///
/// It is also not a subset of "non-ASCII": C0 and C1 controls are folded in
/// separately by [`is_invisible`] through [`char::is_control`].
const INVISIBLE: &[(char, char)] = &[
    ('\u{00A0}', '\u{00A0}'),   // no-break space
    ('\u{00AD}', '\u{00AD}'),   // soft hyphen
    ('\u{061C}', '\u{061C}'),   // Arabic letter mark
    ('\u{115F}', '\u{1160}'),   // Hangul choseong and jungseong fillers
    ('\u{1680}', '\u{1680}'),   // Ogham space mark
    ('\u{17B4}', '\u{17B5}'),   // Khmer inherent vowels
    ('\u{180B}', '\u{180E}'),   // Mongolian variation selectors and vowel separator
    ('\u{2000}', '\u{200F}'),   // the fixed-width spaces, the zero-width set, LRM and RLM
    ('\u{2028}', '\u{202F}'),   // line and paragraph separator, the bidi embeddings, NNBSP
    ('\u{205F}', '\u{2064}'),   // medium mathematical space, word joiner, invisible operators
    ('\u{2066}', '\u{2069}'),   // the bidi isolates
    ('\u{3000}', '\u{3000}'),   // ideographic space
    ('\u{3164}', '\u{3164}'),   // Hangul filler
    ('\u{FE00}', '\u{FE0F}'),   // variation selectors
    ('\u{FEFF}', '\u{FEFF}'),   // BOM, also read as zero-width no-break space
    ('\u{FFA0}', '\u{FFA0}'),   // halfwidth Hangul filler
    ('\u{E0000}', '\u{E007F}'), // language tag and the tag characters
    ('\u{E0100}', '\u{E01EF}'), // variation selectors supplement
];

/// What a chip for `c` shows in its place: the compact glyph for a
/// [`ChipTier::Structural`] character, and the loud label for everything else.
///
/// This is where the tier is decided, beside the label it decides, and not in
/// a view. A view that recognised `[LF]` would be reading a label, and a label
/// is the one thing on screen that a command may contain literally.
fn chip_label(c: char) -> Cow<'static, str> {
    match STRUCTURAL.iter().find(|(structural, _)| *structural == c) {
        Some((_, glyph)) => Cow::Borrowed(*glyph),
        None => loud_label(c),
    }
}

/// The loud form of a chip's label: named where the name helps, `[U+XXXX]`
/// otherwise.
///
/// Every label here is bracketed, including the fallback, so that a chip
/// cannot be mistaken for text that was really there. The brackets are not
/// proof — a command may contain a literal `[LF]` — but they put the two
/// readings in the same shape, which is the most a plain string can do;
/// telling them apart for certain is the UI's job, through styling the chip
/// spans differently.
///
/// Split out from [`chip_label`] because [`defang`] needs this form and only
/// this form: a defanged string is drawn as ordinary text with no chip
/// machinery around it, so every character in it has to be one the window can
/// draw as itself, and the compact glyphs are not.
fn loud_label(c: char) -> Cow<'static, str> {
    match NAMED.iter().find(|(named, _)| *named == c) {
        Some((_, name)) => Cow::Borrowed(*name),
        None => Cow::Owned(format!("[U+{:04X}]", c as u32)),
    }
}

/// True for a character that carries no ink or passes for a space, as far as
/// [`INVISIBLE`] knows — see there for why that is a best-effort answer and
/// why nothing unsafe follows from a wrong one.
///
/// C0 and C1 controls are included through [`char::is_control`]: they print as
/// nothing, or as whatever the terminal does when it obeys them.
fn is_invisible(c: char) -> bool {
    c.is_control() || INVISIBLE.iter().any(|(lo, hi)| (*lo..=*hi).contains(&c))
}

/// The same substitution [`classify`] makes, applied to a string that is
/// **not** part of the command: every character that must not be drawn as
/// itself is replaced by the label that names it.
///
/// This is deliberately lossy, and that is only safe because of what it is
/// used on. A span's text is approved text and may never be rewritten — hence
/// chips, which keep the character and change only what is drawn. But hatch
/// also puts a few strings in the same window that the user is *not*
/// approving and that `unrender` never reads: the value of a `$VAR`, resolved
/// out of the child environment. Those cannot be spans, because a span's text
/// must come from the command; so they are flattened here instead, and the
/// window renders the result as ordinary text.
///
/// The threat is not that the config file attacks its own owner. It is that
/// the value is drawn beside agent-chosen text: the agent picks *which*
/// variable to write, so it chooses which configured value appears on screen,
/// and a value carrying a bidi override or a newline would reorder or split
/// the line the command is being read on. Selection is enough — the agent
/// never has to author the string to weaponise it.
///
/// # Always the loud label, even for a newline
///
/// The result is drawn as ordinary text, with none of the chip machinery
/// around it, so every character in it has to be one the window draws as
/// itself — and the compact structural glyphs are not, by design. That is the
/// mechanical reason, and there is a second one that points the same way: a
/// newline in a *resolved variable value* is not the ordinary structure a
/// newline in a command is. It is a line break the agent chose to have drawn
/// beside the command by picking which variable to write, and splitting the
/// line a command is read on is precisely the hazard the loud tier is for.
pub fn defang(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_plain(c) {
            out.push(c);
        } else {
            out.push_str(&loud_label(c));
        }
    }
    out
}

/// Classify `source` into plain runs and one chip per character that must not
/// be drawn as itself.
///
/// Chips are per codepoint, never per grapheme cluster: invariant 1b bounds a
/// label to one codepoint, so a combining sequence becomes one chip per
/// character rather than one label over an unknown amount of text. `e` plus a
/// combining acute renders as `e` followed by `[U+0301]`, which is exactly the
/// point — the reader is told the accent is a separate character and not part
/// of the letter.
///
/// A newline is chipped like everything else outside the safe set *and* asks
/// the span after it to start a line, so the shape of a multi-line string
/// survives into every pane that draws one. See [`classify_into`].
pub fn classify(source: &str) -> Spans {
    let mut builder = SpanBuilder::new(source);
    classify_into(&mut builder, source.len());
    builder.finish()
}

/// Classify `builder.source()[builder.cursor()..end]` into `builder`.
///
/// The composable form, and the one a later pass wants: segmentation walks the
/// command, pushes its own `Separator` spans, and hands each run in between to
/// this function without having to splice one [`Spans`] into another — which
/// the span model deliberately offers no way to do, since a spliced sequence
/// would have to be trusted rather than checked.
///
/// # Panics
///
/// If `end` is behind the cursor, past the end of the source, or not on a
/// character boundary.
pub fn classify_into(builder: &mut SpanBuilder<'_>, end: usize) {
    let start = builder.cursor();
    // Checked before the slice, which would otherwise fold this into the
    // out-of-bounds case and point a caller with a stale `end` at the wrong
    // mistake. `SpanBuilder::push_to` says the same thing the same way.
    assert!(
        end >= start,
        "runs must be classified in source order: end {end} is behind cursor {start}"
    );
    let run = match builder.source().get(start..end) {
        Some(run) => run,
        None => panic!(
            "classify range {start}..{end} is out of bounds or not on a character boundary \
             of a {}-byte source",
            builder.source().len()
        ),
    };

    // `push_to(cursor, ..)` is a no-op, so flushing an empty plain run before a
    // chip costs nothing and there is no pending-run state to get wrong.
    for (offset, c) in run.char_indices() {
        if is_plain(c) {
            continue;
        }
        let at = start + offset;
        builder.push_to(at, SpanKind::Plain);
        builder.push_to(at + c.len_utf8(), SpanKind::Chip { name: chip_label(c) });
        // A newline gets the chip *and* the break. The two are independent
        // axes and always were — a chip decides what a character is drawn as,
        // `break_before` decides where the next character is drawn — so
        // asking for both is not a weakening of either. The `↵` still stands
        // at the end of the line it ends, which is what keeps a real newline
        // distinguishable from a backslash and an `n` typed as two
        // characters; the break is what stops a pasted script from being one
        // line that scrolls sideways forever.
        //
        // Here rather than in a view, because "a newline ends a line" is true
        // of every pane and of every string this function classifies. A view
        // that broke on `[LF]` itself would be reading a label, and a label
        // is the one thing on screen that a command may contain literally.
        //
        // Only U+000A. A lone `\r` returns to the start of the line it is
        // already on rather than opening a new one, and it is still visible
        // as `⇤`; `\r\n` breaks on its `\n`, so the pair reads as `⇤↵` at the
        // end of the line, which is exactly the sequence that is in the file.
        if c == '\n' {
            builder.break_next();
        }
    }
    builder.push_to(end, SpanKind::Plain);
}

/// What a scan of one string found, for the summary line and the audit record.
///
/// Counts, not verdicts. Nothing here decides anything; it tells a reader how
/// much of what they are looking at is not what it appears to be. The counts
/// overlap on purpose — NBSP is both non-ASCII and invisible — because a
/// reader wants each question answered, not a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanReport {
    /// Characters outside ASCII. Every one of them chips, and every one of
    /// them is a potential homoglyph.
    pub non_ascii: usize,
    /// Characters that carry no ink of their own or pass for a space,
    /// including ASCII controls, **except the structural three**. A subset of
    /// what chips, not of `non_ascii`.
    ///
    /// A floor rather than an exact figure: it counts what `INVISIBLE`
    /// knows about, and that table is best-effort. Under-counting here costs
    /// a reader some context in the summary line and costs the display
    /// nothing, since every one of these characters chips either way.
    ///
    /// # Why a newline is not counted here
    ///
    /// A tab, a newline and a carriage return carry no ink, so they answer to
    /// the letter of this field — and counting them made the summary line
    /// announce "2 invisible" above an ordinary two-line command, which is
    /// every multi-line command there is. A warning that fires on the normal
    /// case is a warning a reader learns to skip, and it was sitting directly
    /// above the pane it was meant to draw attention to.
    ///
    /// The rule that resolves it is already written above [`STRUCTURAL`]:
    /// those three are structure a reader needs *located* rather than
    /// *flagged*, and each is drawn as its own glyph — `⇥`, `↵`, `⇤` — in the
    /// exact position it occupies. A character that has been located cannot
    /// also be hidden, so it is not something this count is about. What
    /// remains here is what would otherwise pass unseen.
    ///
    /// This does mean the field consults [`chip_tier`], which [`scan`] is
    /// otherwise careful not to do. The coupling is to the *set*, not to the
    /// renderer: were the three ever to stop being drawn as themselves they
    /// would become hidden characters and belong in this count again, which
    /// is the same statement read in the other direction.
    pub invisible: usize,
    /// The string is not in Normalization Form C, so at least one visible
    /// glyph is spelled with more codepoints than it needs — the shape a
    /// combining-mark disguise takes.
    pub not_nfc: bool,
}

/// Summarise what is unusual about `source`.
///
/// Deliberately a separate walk from [`classify`]. They answer different
/// questions — "how do I draw this?" against "how odd is this?" — and only one
/// of them is per character at all: `not_nfc` is a property of the whole
/// string and cannot be decided one codepoint at a time. Fusing them would
/// make the renderer carry counts it never reads, and would tie the summary
/// line's meaning to the display's chipping rule, which is free to change.
/// The duplicated walk is a `for` loop over a `char` iterator.
pub fn scan(source: &str) -> ScanReport {
    let mut report = ScanReport {
        not_nfc: !is_nfc(source),
        ..ScanReport::default()
    };
    for c in source.chars() {
        if !c.is_ascii() {
            report.non_ascii += 1;
        }
        // Not `is_invisible` alone: the structural three carry no ink either,
        // and counting them made every multi-line command announce itself as
        // unusual. See `ScanReport::invisible`.
        if is_invisible(c) && chip_tier(c) != ChipTier::Structural {
            report.invisible += 1;
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::{Span, unrender};

    fn chips(spans: &Spans) -> Vec<char> {
        spans.iter().filter_map(Span::chip_codepoint).collect()
    }

    /// Every compact glyph this module promises, written out by hand, for
    /// the same reason `EXPECTED_LABELS` is.
    const EXPECTED_GLYPHS: &[(char, &str)] = &[
        ('\u{0009}', "\u{21E5}"),
        ('\u{000A}', "\u{21B5}"),
        ('\u{000D}', "\u{21E4}"),
    ];

    /// Every loud label this module promises, written out by hand.
    ///
    /// Deliberately a second copy rather than a walk of `NAMED`: a test that
    /// reads its expectations out of the table it is testing agrees with any
    /// table, including one an entry has been deleted from. The spec names
    /// NBSP, the soft hyphen, the BOM and the line and paragraph separators
    /// specifically, and that requirement is only enforced if losing one of
    /// them turns something red.
    const EXPECTED_LABELS: &[(char, &str)] = &[
        ('\u{0009}', "[TAB]"),
        ('\u{000A}', "[LF]"),
        ('\u{000D}', "[CR]"),
        ('\u{00A0}', "[NBSP]"),
        ('\u{00AD}', "[SHY]"),
        ('\u{061C}', "[ALM]"),
        ('\u{200B}', "[ZWSP]"),
        ('\u{200C}', "[ZWNJ]"),
        ('\u{200D}', "[ZWJ]"),
        ('\u{200E}', "[LRM]"),
        ('\u{200F}', "[RLM]"),
        ('\u{2028}', "[LS]"),
        ('\u{2029}', "[PS]"),
        ('\u{202A}', "[LRE]"),
        ('\u{202B}', "[RLE]"),
        ('\u{202C}', "[PDF]"),
        ('\u{202D}', "[LRO]"),
        ('\u{202E}', "[RLO]"),
        ('\u{2066}', "[LRI]"),
        ('\u{2067}', "[RLI]"),
        ('\u{2068}', "[FSI]"),
        ('\u{2069}', "[PDI]"),
        ('\u{FEFF}', "[BOM]"),
    ];

    /// Characters that must be counted invisible, written out by hand for the
    /// same reason. The spec's own set, plus the omissions that motivated
    /// widening the table to ranges.
    const EXPECTED_INVISIBLE: &[char] = &[
        '\u{0009}', '\u{001B}', '\u{0085}', '\u{00A0}', '\u{00AD}', '\u{061C}', '\u{115F}',
        '\u{1160}', '\u{180E}', '\u{2000}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}',
        '\u{200F}', '\u{2028}', '\u{2029}', '\u{202A}', '\u{202E}', '\u{202F}', '\u{2060}',
        '\u{2066}', '\u{2069}', '\u{3000}', '\u{3164}', '\u{FE0F}', '\u{FEFF}', '\u{E0001}',
    ];

    fn labels(spans: &Spans) -> Vec<String> {
        spans
            .iter()
            .filter(|s| s.chip_codepoint().is_some())
            .map(|s| s.display_text().into_owned())
            .collect()
    }

    #[test]
    fn bidi_override_becomes_a_chip() {
        let spans = classify("ls\u{202E}txt");
        assert_eq!(chips(&spans), vec!['\u{202E}'], "the override must not be drawn as itself");
        assert_eq!(labels(&spans), vec!["[RLO]"]);
    }

    #[test]
    fn zero_width_space_becomes_a_chip() {
        let spans = classify("rm\u{200B} -rf");
        assert_eq!(chips(&spans), vec!['\u{200B}']);
        assert_eq!(labels(&spans), vec!["[ZWSP]"]);
    }

    #[test]
    fn cyrillic_homoglyph_becomes_a_chip() {
        let spans = classify("/home/us\u{0430}r");
        let chip = spans.iter().find(|s| s.chip_codepoint().is_some()).expect("a chip");
        assert_eq!(chip.text(), "\u{0430}", "the original character is what was approved");
        assert_eq!(chip.display_text(), "[U+0430]", "and it must not draw as ASCII 'a'");
    }

    #[test]
    fn plain_ascii_produces_no_chips() {
        let spans = classify("systemctl restart sshd");
        assert!(chips(&spans).is_empty());
        assert_eq!(spans.len(), 1, "one uninterrupted plain run");
        assert_eq!(spans[0].kind(), &SpanKind::Plain);
    }

    #[test]
    fn counts_and_nfc_flag_are_reported() {
        let report = scan("caf\u{0065}\u{0301}");
        assert!(report.not_nfc);
        assert_eq!(report.non_ascii, 1);
    }

    // --- what "plain" is, at both ends of the range -----------------------

    #[test]
    fn every_ascii_printable_is_drawn_as_itself() {
        let printable: String = (0x20u8..=0x7e).map(char::from).collect();
        let spans = classify(&printable);
        assert_eq!(spans.len(), 1, "no chip anywhere in space..~");
        assert_eq!(spans[0].display_text(), printable);
    }

    #[test]
    fn no_character_outside_ascii_printable_is_drawn_as_itself() {
        // The rule is a whitelist, so this is the whole claim: sweep the C0
        // and C1 controls, DEL, and a spread of higher planes.
        let suspect: Vec<char> = (0u32..0xa0)
            .filter(|c| !(0x20..0x7f).contains(c))
            .chain([0xa0, 0xad, 0x200b, 0x202e, 0x2028, 0xfeff, 0x430, 0x1d7ce, 0x10ffff])
            .filter_map(char::from_u32)
            .collect();
        for c in suspect {
            let source = format!("a{c}b");
            let spans = classify(&source);
            assert_eq!(chips(&spans), vec![c], "U+{:04X} was drawn as itself", c as u32);
        }
    }

    #[test]
    fn tab_and_newline_are_chipped_rather_than_drawn() {
        // Layout is metadata in this crate; a literal break drawn as itself
        // would stop a reader telling layout from content.
        let spans = classify("a\tb\nc");
        assert_eq!(chips(&spans), vec!['\t', '\n']);
        assert_eq!(labels(&spans), vec!["\u{21E5}", "\u{21B5}"]);
    }

    #[test]
    fn a_newline_is_labelled_and_also_ends_the_line() {
        // Both, not either. A pane that only got the label draws a pasted
        // script as one line that scrolls sideways; a pane that only got the
        // break cannot tell a real newline from a typed backslash-n.
        let spans = classify("a\nb");

        assert_eq!(labels(&spans), vec!["\u{21B5}"], "the character stopped being visible");
        let breaks: Vec<bool> = spans.iter().map(Span::break_before).collect();
        assert_eq!(breaks, vec![false, false, true], "the break is not on the span after the ↵");
    }

    #[test]
    fn only_a_newline_ends_a_line() {
        // A lone `\r` returns to the start of the line it is on. It is still
        // chipped; it just does not open a new one.
        let spans = classify("a\rb");
        assert_eq!(labels(&spans), vec!["\u{21E4}"]);
        assert!(spans.iter().all(|span| !span.break_before()), "a carriage return broke the line");

        // And `\r\n` breaks once, after the pair, so both characters stay on
        // the line they end.
        let crlf = classify("a\r\nb");
        assert_eq!(labels(&crlf), vec!["\u{21E4}", "\u{21B5}"]);
        let breaks: Vec<bool> = crlf.iter().map(Span::break_before).collect();
        assert_eq!(breaks, vec![false, false, false, true]);
    }

    #[test]
    fn a_trailing_newline_does_not_ask_for_a_line_that_is_not_there() {
        // The break is pending when the source runs out, and a pending break
        // that never lands is dropped. This is what keeps a diff line -- which
        // always ends in its own terminator -- from carrying a break at all.
        let spans = classify("a\n");
        assert!(spans.iter().all(|span| !span.break_before()));
    }

    // --- what a chip may and may not do ----------------------------------

    #[test]
    fn a_chip_keeps_the_original_character_as_its_text() {
        let spans = classify("ls\u{202E}txt");
        let chip = &spans[1];
        assert_eq!(chip.text(), "\u{202E}", "the label must not replace the text");
        assert_ne!(chip.display_text(), chip.text(), "nor the text the label");
    }

    #[test]
    fn nothing_is_dropped_or_added() {
        // The historical bug in tools of this shape: an invisible character is
        // deleted for tidiness and the display stops being the command.
        for source in [
            "",
            "ls\u{202E}txt",
            "rm\u{200B} -rf",
            "caf\u{0065}\u{0301}",
            "\u{feff}\u{200b}\u{00ad}",
            "\u{202E}",
            "a\u{a0}b",
            "\u{10ffff}",
        ] {
            let spans = classify(source);
            assert_eq!(unrender(&spans), source, "{source:?} did not round-trip");
            assert!(spans.covers_source(), "{source:?} is not tiled by its spans");
        }
    }

    #[test]
    fn every_chip_stands_for_exactly_one_codepoint() {
        let spans = classify("a\u{202E}\u{200B}\u{0301}b");
        for span in spans.iter() {
            match span.kind() {
                SpanKind::Chip { .. } => assert_eq!(span.text().chars().count(), 1),
                _ => assert_eq!(span.display_text(), span.text()),
            }
        }
    }

    #[test]
    fn a_combining_sequence_becomes_one_chip_per_codepoint() {
        // Invariant 1b forbids one label over a grapheme cluster, so the
        // accent is chipped on its own and the reader is told it is separate.
        let spans = classify("cafe\u{0301}");
        assert_eq!(chips(&spans), vec!['\u{0301}']);
        assert_eq!(spans[0].text(), "cafe", "the base letter is still plain text");
        assert_eq!(labels(&spans), vec!["[U+0301]"]);
    }

    #[test]
    fn adjacent_suspect_characters_get_one_chip_each() {
        let spans = classify("\u{202E}\u{200B}\u{00A0}");
        assert_eq!(chips(&spans), vec!['\u{202E}', '\u{200B}', '\u{00A0}']);
        assert_eq!(spans.len(), 3, "no run of chips is ever merged into one");
    }

    // --- labels -----------------------------------------------------------

    #[test]
    fn named_characters_get_their_names() {
        for (c, expected) in EXPECTED_LABELS {
            assert_eq!(loud_label(*c), *expected, "U+{:04X}", *c as u32);
        }
        assert_eq!(
            NAMED.len(),
            EXPECTED_LABELS.len(),
            "a label was added to or removed from NAMED without saying so here"
        );
    }

    #[test]
    fn a_loud_chip_is_drawn_as_its_bracketed_name() {
        // What reaches the screen, for everything outside the structural
        // three: the loud label and nothing shorter.
        for (c, expected) in EXPECTED_LABELS.iter().filter(|(c, _)| chip_tier(*c) == ChipTier::Loud)
        {
            let spans = classify(&c.to_string());
            assert_eq!(labels(&spans), vec![expected.to_string()], "U+{:04X}", *c as u32);
            assert_eq!(spans[0].chip_tier(), Some(ChipTier::Loud), "U+{:04X}", *c as u32);
        }
    }

    // --- the two tiers ----------------------------------------------------

    #[test]
    fn ordinary_structure_is_drawn_as_a_compact_glyph() {
        // The whole point of the tier: a heredoc's line endings stop being a
        // column of the same alarm the bidi override wears.
        for (c, glyph) in EXPECTED_GLYPHS {
            assert_eq!(chip_tier(*c), ChipTier::Structural, "U+{:04X}", *c as u32);
            assert_eq!(chip_label(*c), *glyph, "U+{:04X}", *c as u32);
            let spans = classify(&c.to_string());
            assert_eq!(labels(&spans), vec![glyph.to_string()], "U+{:04X}", *c as u32);
            assert_eq!(spans[0].chip_tier(), Some(ChipTier::Structural));
        }
        assert_eq!(
            STRUCTURAL.len(),
            EXPECTED_GLYPHS.len(),
            "a glyph was added to or removed from STRUCTURAL without saying so here"
        );
    }

    #[test]
    fn a_crlf_reads_as_two_distinguishable_glyphs() {
        let spans = classify("a\r\nb");
        let shown: String = spans.iter().map(|s| s.display_text()).collect();
        assert_eq!(shown, "a\u{21E4}\u{21B5}b");
    }

    #[test]
    fn everything_that_is_a_disguise_rather_than_structure_stays_loud() {
        // The list that decides whether the quiet tier bought anything. NBSP
        // is the one worth naming: it is whitespace-shaped, which is exactly
        // why it must not be drawn like whitespace.
        for c in [
            '\u{00A0}', '\u{00AD}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{202E}', '\u{2066}',
            '\u{2028}', '\u{2029}', '\u{FEFF}', '\u{0430}', '\u{0301}', '\u{001B}', '\u{0000}',
            '\u{1D7CE}',
        ] {
            assert_eq!(chip_tier(c), ChipTier::Loud, "U+{:04X} went quiet", c as u32);
            let label = chip_label(c);
            assert!(label.starts_with('['), "U+{:04X} lost its brackets", c as u32);
        }
    }

    #[test]
    fn a_compact_glyph_is_outside_the_set_that_is_drawn_as_itself() {
        // What keeps a glyph from ever being confused with the command's own
        // byte: a literal `↵` in a command is non-ASCII and so chips, as
        // `[U+21B5]`, which is not `↵`.
        for (_, glyph) in STRUCTURAL {
            for c in glyph.chars() {
                assert!(!is_plain(c), "U+{:04X} would draw as itself", c as u32);
                assert_eq!(chip_tier(c), ChipTier::Loud, "the glyph is not itself structure");
                assert_ne!(chip_label(c), *glyph, "a literal glyph draws as the glyph");
            }
        }
    }

    #[test]
    fn a_character_that_is_drawn_as_itself_still_has_a_tier() {
        // Total by construction, so a caller never has to ask whether asking
        // is allowed. Loud is the answer, and it costs nothing: `a` is never
        // chipped.
        assert_eq!(chip_tier('a'), ChipTier::Loud);
        assert_eq!(chip_tier(' '), ChipTier::Loud);
    }

    #[test]
    fn the_whole_named_table_is_outside_the_plain_set() {
        // A name for a character that never chips would be dead weight, and a
        // sign the two rules had drifted apart. Checked against the literal
        // list as well as the table, so deleting an entry cannot make this
        // vacuous.
        for (c, name) in EXPECTED_LABELS.iter().chain(NAMED) {
            assert!(!is_plain(*c), "{name} names U+{:04X}, which is drawn as itself", *c as u32);
        }
        for (c, glyph) in EXPECTED_GLYPHS.iter().chain(STRUCTURAL) {
            assert!(!is_plain(*c), "{glyph} stands for U+{:04X}, drawn as itself", *c as u32);
        }
    }

    #[test]
    fn unnamed_characters_fall_back_to_a_hex_label() {
        assert_eq!(chip_label('\u{0430}'), "[U+0430]");
        assert_eq!(chip_label('\u{0007}'), "[U+0007]", "short codepoints stay four digits");
        assert_eq!(chip_label('\u{1D7CE}'), "[U+1D7CE]", "long ones are not truncated");
        assert_eq!(loud_label('\u{0430}'), "[U+0430]");
    }

    #[test]
    fn every_structural_character_is_also_named_for_the_places_that_need_words() {
        // `defang` has no chip machinery to hang a glyph on, so each of these
        // still needs a bracketed name. A structural character missing from
        // `NAMED` would defang to `[U+000A]`, which is a worse thing to read
        // in a variable's value than `[LF]`.
        for (c, _) in STRUCTURAL {
            assert!(
                NAMED.iter().any(|(named, _)| named == c),
                "U+{:04X} is structural but unnamed",
                *c as u32
            );
        }
    }

    #[test]
    fn a_label_is_never_empty_and_never_the_character_itself() {
        // An empty or pass-through label would put the raw character back on
        // screen through the one API that is allowed to differ from the text.
        for c in (0u32..0x3000).chain([0xfeff, 0x1d7ce, 0x10ffff]).filter_map(char::from_u32) {
            if is_plain(c) {
                continue;
            }
            let label = chip_label(c);
            assert!(!label.is_empty(), "U+{:04X} has no label", c as u32);
            assert!(!label.contains(c), "U+{:04X}'s label contains the character", c as u32);
        }
    }

    // --- composition ------------------------------------------------------

    #[test]
    fn classify_into_covers_only_the_run_it_is_given() {
        // What segmentation will do: push its own separator, classify the run
        // after it, and end up with one sequence that still tiles the source.
        //
        // The first run carries a chip of its own on purpose. A second call
        // that measured its offsets from the start of the source rather than
        // from the cursor would re-walk that chip, and the run boundary is the
        // only thing standing between a composed rendering and a duplicated or
        // out-of-order span.
        let source = "l\u{200B}s;\u{202E}txt";
        let mut builder = SpanBuilder::new(source);
        classify_into(&mut builder, 5);
        builder.push_to(6, SpanKind::Separator);
        builder.break_next();
        classify_into(&mut builder, source.len());
        let spans = builder.finish();

        assert!(spans.covers_source());
        assert_eq!(unrender(&spans), source);
        assert_eq!(chips(&spans), vec!['\u{200B}', '\u{202E}']);
        assert_eq!(spans[3].kind(), &SpanKind::Separator, "the caller's own tag survives");
        assert_eq!(spans[3].text(), ";");
        assert!(spans[4].break_before(), "a pending break lands on the run's first span");
    }

    #[test]
    fn classify_into_leaves_the_cursor_at_the_end_of_the_run() {
        let mut builder = SpanBuilder::new("a\u{202E}bc");
        classify_into(&mut builder, 5);
        assert_eq!(builder.cursor(), 5);
    }

    #[test]
    #[should_panic(expected = "end 1 is behind cursor 3")]
    fn classify_into_rejects_going_backwards() {
        // A stale `end` from a caller that split its runs wrongly. Folding
        // this into the out-of-bounds case would point them at the wrong
        // mistake, since the slice is `None` either way.
        let mut builder = SpanBuilder::new("abc");
        classify_into(&mut builder, 3);
        classify_into(&mut builder, 1);
    }

    #[test]
    #[should_panic(expected = "not on a character boundary")]
    fn classify_into_rejects_a_split_character() {
        let mut builder = SpanBuilder::new("\u{202E}");
        classify_into(&mut builder, 1);
    }

    // --- scan -------------------------------------------------------------

    #[test]
    fn scan_counts_invisibles_separately_from_non_ascii() {
        let report = scan("us\u{0430}r\u{200B}\t");
        assert_eq!(report.non_ascii, 2, "the homoglyph and the zero-width space");
        assert_eq!(
            report.invisible, 1,
            "the zero-width space; the tab is located by its own glyph, not hidden"
        );
        assert!(!report.not_nfc);
    }

    #[test]
    fn an_ordinary_multi_line_command_is_not_unusual() {
        // The case that prompted the rule. Two `&&` continuations are what a
        // multi-line command is made of, and a summary line that called them
        // out would fire above almost every command hatch ever shows.
        let command = "cd $HOME/src/service &&\ncargo build --release &&\nsystemctl --user restart service";
        assert_eq!(scan(command), ScanReport::default(), "{command:?}");
        // A tab-indented heredoc body, for the same reason.
        assert_eq!(scan("cat <<'EOF'\n\tindented\nEOF\n"), ScanReport::default());
        // CRLF is structure too: `⇤↵` locates it in the pane, so the summary
        // line stays quiet and the glyphs do the telling.
        assert_eq!(scan("echo one\r\necho two\r\n"), ScanReport::default());
    }

    #[test]
    fn an_escape_hidden_among_newlines_is_still_counted() {
        // The other direction: exempting the structural three must not exempt
        // anything standing next to them.
        let report = scan("echo one\n\u{001b}[2J\techo two\n");
        assert_eq!(report.invisible, 1, "the ANSI escape, and nothing else");
    }

    #[test]
    fn scan_finds_nothing_in_a_plain_command() {
        assert_eq!(scan("systemctl restart sshd"), ScanReport::default());
        assert_eq!(scan(""), ScanReport::default());
    }

    #[test]
    fn a_composed_string_is_not_flagged_as_denormalised() {
        // Same word, one codepoint per glyph: the flag is about spelling, not
        // about being non-ASCII.
        let report = scan("caf\u{00e9}");
        assert!(!report.not_nfc);
        assert_eq!(report.non_ascii, 1);
    }

    #[test]
    fn every_invisible_is_invisible_and_chips() {
        // The literal list first, so that shrinking a range in INVISIBLE is
        // caught rather than agreed with.
        for c in EXPECTED_INVISIBLE {
            assert!(is_invisible(*c), "U+{:04X} is not counted invisible", *c as u32);
        }
        // Then the table itself: an entry that is counted but still drawn as
        // itself would mean the two rules had drifted apart.
        for (lo, hi) in INVISIBLE {
            for c in (*lo as u32..=*hi as u32).filter_map(char::from_u32) {
                assert!(is_invisible(c), "U+{:04X} is listed but not counted", c as u32);
                assert!(!is_plain(c), "U+{:04X} is counted but drawn as itself", c as u32);
            }
        }
        assert!(!is_invisible('a'), "a visible character is not invisible");
        assert!(!is_invisible(' '), "an ordinary space is not what this counts");
        assert!(!is_invisible('\u{0430}'), "a homoglyph is visible; it is merely not what it looks like");
        assert!(is_invisible('\u{001b}'), "an ANSI escape carries no ink");
    }

    // --- defang: display-only text that is not part of the command --------

    #[test]
    fn defang_leaves_ordinary_text_exactly_as_it_is() {
        for text in ["", "/home/user", "xterm-256color", "a b~!", "-"] {
            assert_eq!(defang(text), text);
        }
    }

    #[test]
    fn defang_replaces_what_must_not_be_drawn_as_itself_with_its_label() {
        assert_eq!(defang("/a\u{202E}b"), "/a[RLO]b");
        assert_eq!(defang("a\nb\tc\rd"), "a[LF]b[TAB]c[CR]d");
        assert_eq!(defang("x\u{200B}y\u{00A0}z"), "x[ZWSP]y[NBSP]z");
        // An unnamed character still gets a label.
        assert_eq!(defang("\u{1D7CE}"), "[U+1D7CE]");
        assert_eq!(defang("ünïcödé"), "[U+00FC]n[U+00EF]c[U+00F6]d[U+00E9]");
    }

    #[test]
    fn defang_output_is_entirely_drawable_as_itself() {
        // The point of the function: whatever went in, what comes out can be
        // put in a window beside agent-chosen text without reordering it,
        // clearing a line, or hiding a character.
        for text in [
            "\u{202E}\u{200B}\u{00A0}\n\r\u{1b}[2K\u{9b}",
            "а",
            "\u{2069}\u{2066}",
            "plain",
        ] {
            assert!(
                defang(text).chars().all(is_plain),
                "{text:?} defanged to something that is still not drawable"
            );
        }
    }

    #[test]
    fn defang_is_not_a_span_and_says_so_by_being_lossy() {
        // Deliberately not reversible, unlike everything the span model
        // does. That is only safe because it is never applied to command
        // text: a literal `[LF]` in a config value defangs to itself and
        // becomes indistinguishable from a real newline's label. For approved
        // text that ambiguity would be unacceptable, which is exactly why
        // approved text gets chips instead.
        assert_eq!(defang("[LF]"), defang("\n"));
    }

    #[test]
    fn defang_keeps_the_loud_label_even_for_structure() {
        // Two reasons, and either alone would decide it. The mechanical one:
        // a defanged string is drawn as ordinary text, so every character in
        // it has to be drawable as itself, and the compact glyphs are not.
        // The other: a newline in a variable's value is a line break the
        // agent arranged to have drawn beside the command, which is a hazard
        // and not structure.
        assert_eq!(defang("a\nb"), "a[LF]b");
        assert!(
            defang("\n\r\t").chars().all(is_plain),
            "a compact glyph reached a string with no chip around it"
        );
    }
}
