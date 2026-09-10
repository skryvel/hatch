//! `Span`, `Chip`, render/unrender, and the rendering fidelity invariant.
//!
//! The model and the invariant live in the private `span` submodule and are
//! re-exported here, so the renderer modules below are its siblings rather
//! than its children and cannot reach past its accessors to rewrite a span's
//! text. See that module for what the invariant is and why it is enforced by
//! construction rather than by review.

use std::collections::BTreeMap;

pub mod command;
pub mod danger;
pub mod diff;
mod span;
pub mod unicode;

pub use span::{Span, SpanBuilder, SpanKind, Spans, covers_exactly, unrender, variable_name};

/// Render a command for the approval window, against the environment it will
/// actually run in.
///
/// Four passes. The first two compose through a single `SpanBuilder` rather
/// than by splicing their results: [`command::segment`] walks the command,
/// tags the separators it finds outside quotes and asks for a line break on
/// each span that follows one, and hands every run in between to
/// [`unicode::classify_into`], which draws as itself only what is
/// unambiguously safe to draw and chips the rest. The third,
/// [`command::annotate_variables`], refines that result in place: it splits
/// existing spans down to each `$NAME` and tags them with the value the child
/// will see. The fourth, [`command::highlight`], marks the word that names
/// what runs and the quoted strings.
///
/// The order of the last two is not free. Both refine `Plain` spans and both
/// leave a span another pass has claimed alone, so whichever runs first wins
/// the overlap — and a resolved value is information the reader cannot get
/// anywhere else, while a highlight is decoration they can do without.
/// Annotation therefore goes first, and `"$HOME/x"` keeps its value while the
/// quotes around it are still drawn as a string.
///
/// Every pass is additive. None removes a character to make room for layout,
/// for a label or for a value, which is what keeps `tests/fidelity.rs` green.
///
/// # Why `env` is a parameter
///
/// It is the whole point of the third pass. hatch constructs the child
/// environment rather than inheriting one, so there are three environments
/// around — the daemon's, the sandbox's, and the one that will be handed to
/// the command — and only the last is the one the window can speak for. A
/// `$HOME` resolved against `std::env` would print a value that looks
/// authoritative and is wrong. Callers pass
/// [`crate::exec::env::build_child_env`]'s result, and there is deliberately
/// no overload that supplies a default, because every available default is a
/// guess.
///
/// The renderers still to come — binary annotation, danger markers — refine
/// this result the same way. That order is deliberate: `tests/fidelity.rs`
/// passed before there was anything to break, so no later renderer can be
/// written without it, and wiring each pass in here is what puts it under
/// those properties.
pub fn render_command(command: &str, env: &BTreeMap<String, String>) -> Spans {
    command::highlight(command::annotate_variables(command::segment(command), env))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two-argument form is the only one there is, on purpose. These
    /// tests are about wiring rather than about any particular environment,
    /// so they mostly render against an empty one.
    fn render_command(command: &str) -> Spans {
        super::render_command(command, &BTreeMap::new())
    }

    #[test]
    fn an_ordinary_command_is_its_name_and_the_rest() {
        // Two spans, and no chip, no separator and no note between them: the
        // highlight pass marks the word that names what runs, and everything
        // else in an ordinary command is left alone.
        let spans = render_command("ls -la /etc");
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].text(), "ls");
        assert_eq!(spans[0].kind(), &SpanKind::Command);
        assert_eq!(spans[1].text(), " -la /etc");
        assert_eq!(spans[1].kind(), &SpanKind::Plain);
        assert!(!spans[0].break_before());
        assert_eq!(unrender(&spans), "ls -la /etc");
    }

    #[test]
    fn rendering_marks_the_word_that_names_what_runs() {
        // The fourth wiring guard, and it is here for the reason the other
        // three are: every invariant in `tests/fidelity.rs` holds trivially
        // for one Plain span over the whole command, so nothing there would
        // notice the highlight pass being dropped out of this function.
        let spans = render_command("echo 'hi there'");
        let kinds: Vec<&SpanKind> = spans.iter().map(Span::kind).collect();
        assert_eq!(
            kinds,
            vec![&SpanKind::Command, &SpanKind::Plain, &SpanKind::Quoted],
        );
        assert_eq!(unrender(&spans), "echo 'hi there'");
    }

    #[test]
    fn rendering_chips_what_must_not_be_drawn_as_itself() {
        // That `render_command` is wired to the classifier at all. Every
        // invariant in `tests/fidelity.rs` holds trivially for one Plain span
        // over the whole command, so nothing there would notice the pass being
        // skipped — and a skipped pass draws a bidi override as itself.
        let command = "ls\u{202E}txt";
        let spans = render_command(command);
        let chips: Vec<char> = spans.iter().filter_map(Span::chip_codepoint).collect();
        assert_eq!(chips, vec!['\u{202E}']);
        assert_eq!(unrender(&spans), command, "and the character still survives");
    }

    #[test]
    fn rendering_segmenting_what_the_shell_would_run_separately() {
        // The sibling of the test above, and it is here for the same reason:
        // every invariant in `tests/fidelity.rs` holds trivially for one
        // Plain span over the whole command, so nothing there would notice
        // the segmentation pass being dropped out of this function. The two
        // wiring guards live together because the wiring does.
        let spans = render_command("a; b");
        let separators: Vec<&str> = spans
            .iter()
            .filter(|s| s.kind() == &SpanKind::Separator)
            .map(Span::text)
            .collect();
        assert_eq!(separators, vec![";"]);
        assert!(spans.iter().any(Span::break_before), "and the break it asked for");
    }

    #[test]
    fn rendering_resolves_variables_against_the_environment_it_was_given() {
        // The third wiring guard, here for the same reason as the two above:
        // every invariant in `tests/fidelity.rs` holds trivially for one
        // Plain span over the whole command, so nothing there would notice
        // this pass being dropped out of this function. What it would cost is
        // a window that says nothing about `$HOME` -- or, worse, a later
        // edit that resolves it against the wrong environment, which is why
        // the assertion is on the *value* and not merely on the tag.
        let env = BTreeMap::from([("HOME".to_string(), "/home/user".to_string())]);
        let spans = super::render_command("ls $HOME", &env);
        let annotated: Vec<_> = spans.iter().filter_map(Span::variable).collect();
        assert_eq!(annotated, vec![("HOME", Some("/home/user"))]);
        assert_eq!(unrender(&spans), "ls $HOME", "and the reference still survives");
    }

    #[test]
    fn empty_command_renders_to_no_spans() {
        let spans = render_command("");
        assert!(spans.is_empty());
        assert_eq!(unrender(&spans), "");
    }

    #[test]
    fn rendering_covers_its_source() {
        for command in [
            "",
            "a; b",
            "echo $HOME | tee /tmp/x && rm -rf ~/.cache",
            "printf '\u{202E}gnp.exe'",
            "ünïcödé — ✓",
        ] {
            let spans = render_command(command);
            assert!(spans.covers_source(), "{command:?} is not tiled by its spans");
            assert_eq!(spans.source(), command);
            assert_eq!(unrender(&spans), command);
        }
    }
}
