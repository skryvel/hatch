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
/// Today this is one `Plain` span over the whole command: the invariant holds
/// trivially, and the renderers that follow — chips, segmentation, variable
/// and binary annotation, danger markers — each refine this result while
/// keeping it holding. That order is deliberate. `tests/fidelity.rs` passes
/// before there is anything to break, so no later renderer can be written
/// without it.
pub fn render_command(command: &str) -> Spans {
    let mut spans = SpanBuilder::new(command);
    spans.push_rest(SpanKind::Plain);
    spans.finish()
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
