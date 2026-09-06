//! Invariants 1 and 1b: rendering is lossless, and it hides nothing.
//!
//! Invariant 1 is `unrender(render(x)) == x` for every `x`, no exceptions. The
//! whole security story of hatch is that the user approves what actually runs,
//! so a renderer that drops, adds or rewrites a single byte breaks the
//! product, not just the display.
//!
//! Invariant 1 is necessary but not sufficient: keeping the text is not the
//! same as showing it. A chip draws a label instead of what it covers, so a
//! single chip over `; rm -rf /` would round-trip perfectly while the reader
//! never saw the payload. Invariant 1b closes that: every span is drawn as
//! itself, or is a chip standing for exactly one codepoint. Together they say
//! the approved text and the read text are the same text.
//!
//! These tests exist before the renderers do, and every later renderer has to
//! keep both green.

use hatch::render::{SpanKind, render_command, unrender};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

proptest! {
    #[test]
    fn command_rendering_round_trips(cmd in ".*") {
        prop_assert_eq!(unrender(&render_command(&cmd)), cmd);
    }
}

proptest! {
    #[test]
    fn round_trips_with_separators_and_controls(
        cmd in prop::collection::vec(
            prop_oneof![
                "[a-z/ ._-]{1,10}",
                Just(";".to_string()),
                Just("&&".to_string()),
                Just("||".to_string()),
                Just("|".to_string()),
                Just("\n".to_string()),
                Just("\u{202E}".to_string()),   // bidi override
                Just("\u{200B}".to_string()),   // zero-width space
                Just("\u{00A0}".to_string()),   // non-breaking space
                Just("а".to_string()),          // Cyrillic homoglyph
            ], 1..20)
    ) {
        let cmd = cmd.concat();
        prop_assert_eq!(unrender(&render_command(&cmd)), cmd);
    }
}

/// Invariant 1b, checked over one rendering.
///
/// The bound is what matters: a chip is the only span whose drawn text may
/// differ from its real text, and it may differ by exactly one codepoint. A
/// renderer that wants to flag a run of suspect characters emits one chip
/// each, so the reader gets a label per hidden character rather than one
/// label over an unknown amount of command.
fn every_span_is_shown_as_what_it_is(cmd: &str) -> Result<(), TestCaseError> {
    for span in render_command(cmd).iter() {
        match span.kind() {
            SpanKind::Chip { .. } => prop_assert_eq!(
                span.text().chars().count(),
                1,
                "a chip may stand in for one codepoint at most"
            ),
            _ => prop_assert_eq!(
                span.display_text(),
                span.text(),
                "a span that is not a chip must be drawn exactly as its text"
            ),
        }
    }
    Ok(())
}

proptest! {
    #[test]
    fn nothing_is_hidden_behind_a_label(cmd in ".*") {
        every_span_is_shown_as_what_it_is(&cmd)?;
    }
}

proptest! {
    #[test]
    fn nothing_is_hidden_behind_a_label_around_controls(
        cmd in prop::collection::vec(
            prop_oneof![
                "[a-z/ ._-]{1,10}",
                Just(";".to_string()),
                Just("&&".to_string()),
                Just("\n".to_string()),
                Just("\u{202E}".to_string()),   // bidi override
                Just("\u{200B}".to_string()),   // zero-width space
                Just("\u{00A0}".to_string()),   // non-breaking space
                Just("\u{0301}".to_string()),   // combining acute
            ], 1..20)
    ) {
        every_span_is_shown_as_what_it_is(&cmd.concat())?;
    }
}

#[test]
fn a_chip_cannot_cover_the_rest_of_the_command() {
    // The hazard invariant 1b exists for, spelled out: a renderer that chips
    // "; rm -rf /" under a "[NBSP]" label round-trips perfectly and shows the
    // reader "echo hi[NBSP]". Nothing in this crate can build it.
    let spans = render_command("echo hi; rm -rf /");
    let shown: String = spans.iter().map(|s| s.display_text()).collect();
    assert!(
        shown.contains("rm -rf /"),
        "the command must reach the reader's eye, not just survive round-tripping"
    );
}

#[test]
fn semicolon_survives_segmentation() {
    let spans = render_command("a; b");
    let text: String = spans.iter().map(|s| s.display_text()).collect();
    assert!(text.contains(';'), "the separator must remain visible, not be replaced by layout");
}
