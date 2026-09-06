//! `Span`, `Chip`, render/unrender, and the rendering fidelity invariant.
//!
//! The model and the invariant live in the private `span` submodule and are
//! re-exported here, so the renderer modules below are its siblings rather
//! than its children and cannot reach past its accessors to rewrite a span's
//! text. See that module for what the invariant is and why it is enforced by
//! construction rather than by review.

pub mod command;
pub mod danger;
pub mod diff;
mod span;
pub mod unicode;

pub use span::{Span, SpanBuilder, SpanKind, Spans, covers_exactly, unrender};

/// Render a command for the approval window.
///
/// Today this is Unicode classification alone: plain runs of ASCII printable
/// text, and one chip per character that must not be drawn as itself. The
/// renderers that follow — segmentation, variable and binary annotation,
/// danger markers — each refine this result while keeping the invariants
/// holding. That order is deliberate. `tests/fidelity.rs` passed before there
/// was anything to break, so no later renderer can be written without it, and
/// wiring each pass in here is what puts it under those properties.
pub fn render_command(command: &str) -> Spans {
    unicode::classify(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_command_is_one_plain_span() {
        let spans = render_command("ls -la /etc");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].text(), "ls -la /etc");
        assert_eq!(spans[0].kind(), &SpanKind::Plain);
        assert!(!spans[0].break_before());
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
