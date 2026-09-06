//! Invariant 1: rendering is lossless.
//!
//! `unrender(render(x)) == x` for every `x`, no exceptions. The whole security
//! story of hatch is that the user approves what actually runs, so a renderer
//! that drops, adds or rewrites a single byte breaks the product, not just the
//! display. These tests exist before the renderers do, and every later renderer
//! has to keep them green.

use hatch::render::{render_command, unrender};
use proptest::prelude::*;

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

#[test]
fn semicolon_survives_segmentation() {
    let spans = render_command("a; b");
    let text: String = spans.iter().map(|s| s.display_text()).collect();
    assert!(text.contains(';'), "the separator must remain visible, not be replaced by layout");
}
