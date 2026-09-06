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

use std::collections::BTreeMap;

use hatch::render::{SpanKind, unrender};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

/// The environment every property here renders against.
///
/// Not empty, and not benign. Rendering resolves `$VAR` against the child
/// environment and hangs the value on the span's kind, so the properties have
/// to run with values present or they would only ever exercise the unset
/// path. The values are the hostile ones on purpose: a resolved value is
/// display-only data that `unrender` must ignore, so a renderer that ever let
/// one leak into a span's text would fail invariant 1 right here rather than
/// in a window. `HOME` and `PATH` are the names a generated command is most
/// likely to mention.
fn child_env() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("HOME".to_string(), "/home/user".to_string()),
        ("PATH".to_string(), "/usr/bin".to_string()),
        ("a".to_string(), "; rm -rf /".to_string()),
        ("b".to_string(), "\u{202E}gnp.exe\n".to_string()),
    ])
}

fn render_command(command: &str) -> hatch::render::Spans {
    hatch::render::render_command(command, &child_env())
}

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
                Just("$HOME".to_string()),      // a reference that resolves
                Just("${a}".to_string()),       // one whose value is a command
                Just("$".to_string()),          // and one that is not a reference
                Just("'".to_string()),
                Just("\"".to_string()),
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
                Just("$HOME".to_string()),      // a reference that resolves
                Just("${b}".to_string()),       // to a value full of controls
                Just("'".to_string()),
                Just("\"".to_string()),
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

#[test]
fn a_resolved_value_never_becomes_part_of_the_command() {
    // The specific hazard the properties above cover generically, spelled
    // out. A window that resolved `$a` *into* the line would show
    // `echo ; rm -rf /` over an approval for `echo $a`, and the user would
    // be approving one command while reading another.
    let spans = render_command("echo $a");
    assert_eq!(unrender(&spans), "echo $a");
    let shown: String = spans.iter().map(|s| s.display_text()).collect();
    assert_eq!(shown, "echo $a", "the value belongs beside the reference, not in it");
    assert!(
        spans.iter().any(|s| s.variable() == Some(("a", Some("; rm -rf /")))),
        "and it must still be available to draw beside it"
    );
}

#[test]
fn what_a_variable_resolves_to_is_the_environment_it_was_given() {
    // Rendering takes the environment as a parameter precisely so that the
    // window can speak for the one the command will run in. Two renderings of
    // the same command against two environments must differ.
    let first = BTreeMap::from([("HOME".to_string(), "/home/one".to_string())]);
    let second = BTreeMap::from([("HOME".to_string(), "/home/two".to_string())]);
    let value = |env: &BTreeMap<String, String>| {
        hatch::render::render_command("ls $HOME", env)
            .iter()
            .find_map(|s| s.variable())
            .map(|(_, resolved)| resolved.map(str::to_string))
    };
    assert_eq!(value(&first), Some(Some("/home/one".to_string())));
    assert_eq!(value(&second), Some(Some("/home/two".to_string())));
    assert_eq!(value(&BTreeMap::new()), Some(None), "and an absent name is shown unset");
}
