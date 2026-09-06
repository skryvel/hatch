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

// ---------------------------------------------------------------------------
// The same two invariants, over a `swap_file` diff.
//
// A diff splits its input into lines and lays them out in two columns, which
// gives invariant 1 two new ways to fail that a command rendering does not
// have: a row can be dropped or reordered, and a line terminator can be
// normalised on the way in. So the invariant reads twice here, once per
// column -- rejoining the left reproduces the current file and rejoining the
// right reproduces the proposed content, byte for byte.
//
// These duplicate properties that `render::diff` also checks internally, on
// purpose: this file is the crate's statement of what may never break, and it
// runs against the public API. A later refactor that quietly stops classifying
// diff lines should fail here as well as there.
// ---------------------------------------------------------------------------

use hatch::render::diff::{Row, Side, rejoin_left, rejoin_right, side_by_side};

/// Files assembled from the pieces that break diffs: both terminators, a lone
/// `\r`, blank lines, and characters that must be chipped rather than drawn.
fn file() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            "[a-z ]{0,6}",
            Just("\n".to_string()),
            Just("\r\n".to_string()),
            Just("\r".to_string()),
            Just("\t".to_string()),
            Just("\u{202E}".to_string()), // bidi override
            Just("\u{200B}".to_string()), // zero-width space
            Just("\u{00A0}".to_string()), // non-breaking space
            Just("é".to_string()),
        ],
        0..24,
    )
    .prop_map(|parts| parts.concat())
}

proptest! {
    #[test]
    fn a_diff_round_trips_to_both_of_its_sides(before in file(), after in file()) {
        let rows = side_by_side(&before, &after);
        prop_assert_eq!(rejoin_left(&rows), before.clone());
        prop_assert_eq!(rejoin_right(&rows), after.clone());
    }
}

proptest! {
    #[test]
    fn nothing_in_a_diff_is_hidden_behind_a_label(before in file(), after in file()) {
        for row in side_by_side(&before, &after) {
            prop_assert!(
                row.left().is_some() || row.right().is_some(),
                "a row with neither side is a row the reader cannot read"
            );
            for side in [row.left(), row.right()].into_iter().flatten() {
                for span in side.spans() {
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
            }
        }
    }
}

#[test]
fn a_diff_does_not_normalise_line_endings() {
    // The diff-shaped version of `semicolon_survives_segmentation`. Rewriting
    // every line ending in a file is a real write, and a view that trimmed
    // terminators before comparing would draw two identical columns over it.
    let rows = side_by_side("a\r\nb\r\n", "a\nb\n");
    assert_eq!(rejoin_left(&rows), "a\r\nb\r\n");
    assert_eq!(rejoin_right(&rows), "a\nb\n");
    assert!(rows.iter().all(Row::changed), "every line of this file changed");
}

#[test]
fn a_diff_does_not_invent_a_line_into_an_empty_file() {
    // Creating a file is `before == ""`. One blank row here would rejoin to
    // "\n" and tell the reader they are replacing an empty line in a file
    // that has no lines at all.
    let rows = side_by_side("", "hello\n");
    assert!(rows.iter().all(|r| r.left().is_none()));
    assert_eq!(rejoin_left(&rows), "");
    assert_eq!(rejoin_right(&rows), "hello\n");
}

#[test]
fn a_row_cannot_cover_the_rest_of_the_file() {
    // The diff-shaped version of `a_chip_cannot_cover_the_rest_of_the_command`:
    // the payload has to reach the reader's eye, not merely survive the
    // round trip.
    let rows = side_by_side("harmless\n", "harmless\nrm -rf /\n");
    let shown: String = rows
        .iter()
        .filter_map(Row::right)
        .flat_map(Side::spans)
        .map(|s| s.display_text())
        .collect();
    assert!(shown.contains("rm -rf /"), "the added line must be readable, not just present");
}
