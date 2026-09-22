//! `Span`, `Chip`, render/unrender, and the rendering fidelity invariant.
//!
//! The model and the invariant live in the private `span` submodule and are
//! re-exported here, so the renderer modules below are its siblings rather
//! than its children and cannot reach past its accessors to rewrite a span's
//! text. See that module for what the invariant is and why it is enforced by
//! construction rather than by review.

use std::collections::BTreeMap;
use std::ops::Range;

pub mod blocks;
pub mod command;
pub mod danger;
pub mod diff;
pub mod grammar;
pub mod language;
pub mod roster;
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
/// The renderer still to come — danger markers — refines this result the same
/// way. That order is deliberate: `tests/fidelity.rs` passed before there was
/// anything to break, so no later renderer can be written without it, and
/// wiring each pass in here is what puts it under those properties.
///
/// [`roster`] is the one pass about a command that is deliberately *not* one
/// of these. It produces no spans and touches no character: it answers what
/// the command runs and where each name resolves, which is a list beside the
/// panes rather than a mark on the text, and it reaches the filesystem, which
/// nothing on this path does. Its input is the same string these spans tile,
/// so the two cannot come to describe different requests.
pub fn render_command(command: &str, env: &BTreeMap<String, String>) -> Spans {
    render_command_breaking_at(command, env, None)
}

/// [`render_command`], and one further line break at a byte offset the caller
/// knows and the passes below cannot see.
///
/// One caller has one: an elevated request is drawn as the whole line that
/// will run, `run0 --pipe --setenv=… -- bash -c '…'`, and
/// [`crate::exec::elevate::ElevatedArgv::inner_at`] says where the approved
/// command begins in it, so the window can put the boilerplate on its own
/// lines and start the command on a fresh one. The offset travels from the
/// place that built the line to the place that draws it, because nothing in
/// the finished text marks the seam — a `--` can occur inside the command,
/// and so can the word `run0`. See [`command::segment_breaking_at`].
///
/// The break is metadata on a span and changes no character, so
/// `tests/fidelity.rs` is as blind to it as it is to the breaks segmentation
/// asks for, and so is the reader's approval: the bytes on screen are the
/// bytes that run either way.
///
/// # Panics
///
/// If `at` is not a place the passes below can cut — see
/// [`command::segment_breaking_at`] — or if the break does not survive into
/// the rendering they produce.
///
/// That last check catches the two ways an offset can be wrong that
/// segmentation itself lets through. An `at` past the end of the line is
/// never spent, because no boundary reaches it; and a later pass that
/// rewrote the boundary segmentation cut would take the break with it —
/// which neither of them does, since both only ever subdivide what they are
/// given, so this half is belt and braces in the spirit of the check
/// [`SpanBuilder::finish`] makes against a bug in its own module.
///
/// Either way the alternative to noticing is a line that quietly fails to
/// break, and the whole reason the offset is passed in rather than searched
/// for is that nobody should have to wonder which `--` it found.
pub fn render_command_breaking_at(
    command: &str,
    env: &BTreeMap<String, String>,
    at: Option<usize>,
) -> Spans {
    render_command_reinterpreting(command, env, at, None)
}

/// [`render_command_breaking_at`], and one run of the line read as a shell
/// script in its own right rather than as the string it is to the shell that
/// will receive it.
///
/// # What this is for
///
/// The same caller, and the same line. An elevated `run_command` request runs
/// as `run0 … -- bash -c '<script>'`, where the script is one argument: to
/// the shell it is a single word, and every pass below is right to read it as
/// one. On screen that is the wrong answer to a different question. A reader
/// approving forty lines of shell would be shown forty lines drawn as one
/// quoted string — no separators, no command names, no resolved variables,
/// and no structure for the pane to indent or bracket — because hatch put
/// them inside quotes on the reader's behalf.
///
/// So the run is rendered again, on its own, and the result is spliced in
/// where the string was. It is the same four passes over a smaller source:
/// the script is shell, it is about to be run as shell, and reading it as
/// shell is the honest rendering.
///
/// # What it changes, and what it cannot
///
/// Not one character. Every span the inner rendering produces covers the same
/// bytes it covered as part of the string, shifted to where that string sits,
/// and the quotes around it stay outside as their own spans. The result tiles
/// the same source as before, so `tests/fidelity.rs` is as blind to this as
/// it is to a line break, and the bytes the reader approves are the bytes
/// that run.
///
/// # Why it can decline
///
/// A program in a language hatch has no reader for is left exactly as it is:
/// drawn as the data it is, every byte as itself, which is what the raw pane
/// does with everything. Only a shell program is read again.
///
/// The range comes from
/// [`crate::exec::elevate::ElevatedArgv::script_at`], which only offers one
/// when the quoting left the script's bytes alone. Two more doubts are
/// answered here, both by drawing the line exactly as it would have been
/// drawn without this: a range that is not on character boundaries, and a
/// span of the outer rendering that straddles the range and could not be cut
/// without its kind coming to describe text it does not fit. Neither can be
/// produced by anything known today, and both are checked rather than
/// asserted, because the fallback is a rendering this window already draws
/// every day and a panic is a dead window.
pub fn render_command_reinterpreting(
    command: &str,
    env: &BTreeMap<String, String>,
    at: Option<usize>,
    program: Option<&language::Snippet>,
) -> Spans {
    let segmented = command::segment_breaking_at(command, at);
    let outer = command::highlight(command::annotate_variables(segmented, env));
    // The language decides, here and not at the two call sites. Splicing a
    // shell rendering over Python would mark `import` as the word that names
    // what runs and `for` as the head of a loop -- a reading of the wrong
    // language drawn with the confidence of the right one -- and a gate each
    // caller applies for itself is a gate one of them can be written without.
    // One of them was.
    // Every doubt about the range is answered once, here, so neither of the
    // two passes below has to carry the same four checks.
    let named = program.filter(|program| is_a_run_of(command, &program.range()));
    let spans = match named {
        Some(program) => reinterpret(outer, env, program.range(), program.language()),
        None => outer,
    };
    if let Some(at) = at {
        assert!(
            spans.iter().any(|span| span.range().start == at && span.break_before()),
            "the line break asked for at byte {at} begins no span of this {}-byte rendering: \
             the offset is past the end of the line, or a pass below rewrote the boundary \
             segmentation cut for it",
            command.len()
        );
    }
    spans
}

/// [`render_command_reinterpreting`], and the program only if the rendering
/// really does begin and end where it says.
///
/// The one function both callers use, because the alternative was a rule each
/// of them applied for itself and one of them was written without it. What
/// comes back is a pair that cannot disagree: a payload built from these two
/// says the same thing about the same bytes, and
/// [`crate::protocol::Payload::program`] is free to refuse any other pairing
/// on arrival without a caller having to remember why.
///
/// The program is dropped rather than the rendering refused, because a
/// dropped program costs a sentence in the header and a lost bracket, and a
/// refused rendering is a window that will not open.
pub fn render_command_naming(
    command: &str,
    env: &BTreeMap<String, String>,
    at: Option<usize>,
    program: Option<language::Snippet>,
) -> (Spans, Option<language::Snippet>) {
    let spans = render_command_reinterpreting(command, env, at, program.as_ref());
    let edge = |offset: usize| {
        offset == command.len() || spans.iter().any(|span| span.range().start == offset)
    };
    let kept = program.filter(|program| {
        let at = program.range();
        edge(at.start) && edge(at.end)
    });
    (spans, kept)
}

/// Whether `at` names a run of `source`: non-empty, inside it, and on
/// character boundaries at both ends.
fn is_a_run_of(source: &str, at: &Range<usize>) -> bool {
    at.start < at.end
        && at.end <= source.len()
        && source.is_char_boundary(at.start)
        && source.is_char_boundary(at.end)
}

/// Render `spans.source()[script]` as a command of its own and put the result
/// in place of whatever covered it. See [`render_command_reinterpreting`].
///
/// Returns `spans` unchanged for every doubt. This function is the one that
/// decides, so that its caller has one thing to say about the answer: the
/// line is drawn with the script read as shell, or it is drawn as it always
/// was.
fn reinterpret(
    spans: Spans,
    env: &BTreeMap<String, String>,
    script: Range<usize>,
    language: language::Language,
) -> Spans {
    let source = spans.source().to_string();
    debug_assert!(is_a_run_of(&source, &script));
    let text = &source[script.clone()];
    let inner = match language {
        // Shell, and about to be run as shell by the program named on the
        // line: reading it as shell is the honest rendering.
        language::Language::Shell => render_command(text, env),
        // Anything else is classified -- every byte drawn as itself, the
        // unsafe ones chipped, which is exactly what the raw pane does with
        // everything -- and, with the `highlight` feature, has its strings and
        // comments marked where its own grammar is sure of them. It is *not*
        // enough to leave the outer rendering alone here: the passes above
        // have already read the whole line as shell, so Python's `import`
        // would be marked as the word that names what runs and its `#` as a
        // comment. The program is not in quotes any more -- see
        // `crate::exec::invocation_line` -- so there is nothing else holding
        // those readings off it.
        other => grammar::read(text, other),
    };
    match spliced(&source, &spans, &inner, script.start) {
        Some(merged) => merged,
        None => spans,
    }
}

/// The outer spans with `inner`'s spans in place of the run they cover,
/// rebuilt through [`SpanBuilder`] like every other rendering that crosses a
/// boundary.
///
/// `None` when a span of the outer rendering reaches into the run and could
/// not be cut at its edge: a [`SpanKind::Chip`] stands for one codepoint and
/// a [`SpanKind::Variable`] for one whole reference, and a piece of either
/// would be a kind describing text it does not fit. Neither can straddle the
/// edge of a quoted argument — one is a single codepoint and the other
/// cannot contain a quote — so this is a check that has never fired and is
/// here because the alternative to checking is a panic in a prompt window.
fn spliced(source: &str, outer: &Spans, inner: &Spans, at: usize) -> Option<Spans> {
    let end = at + inner.source().len();
    let mut builder = SpanBuilder::new(source);
    let mut put = false;
    for span in outer.iter() {
        let range = span.range();
        let clear = range.end <= at || range.start >= end;
        if clear {
            if span.break_before() {
                builder.break_next();
            }
            builder.push_to(range.end, span.kind().clone());
            continue;
        }
        // Only a span that reaches out of the run has to survive being cut.
        // One that lies inside it is replaced whole, whatever kind it is —
        // the newline chips the outer pass put in the string are the ordinary
        // case, and the inner rendering produces its own.
        let straddles = range.start < at || range.end > end;
        if straddles && matches!(span.kind(), SpanKind::Chip { .. } | SpanKind::Variable { .. }) {
            return None;
        }
        // The part in front of the run keeps the kind it had: the opening
        // quote is still part of the string it opens.
        if range.start < at {
            if span.break_before() {
                builder.break_next();
            }
            builder.push_to(at, span.kind().clone());
        }
        if !put {
            // A script that is drawn on more than one line starts on one.
            // `bash -c '` is the last thing on the wrapper's line and the
            // script begins under it, rather than the first of forty lines
            // being the one that shares a line with the wrapper. A script
            // that fits on one line stays where it is: a line of its own
            // would be a line spent saying nothing.
            if inner.iter().any(Span::break_before) {
                builder.break_next();
            }
            for nested in inner.iter() {
                if nested.break_before() {
                    builder.break_next();
                }
                builder.push_to(at + nested.range().end, nested.kind().clone());
            }
            put = true;
        }
        // And so does the part behind it. No break: the closing quote ends
        // the line the script's last line is on, rather than starting one.
        if range.end > end {
            builder.push_to(range.end, span.kind().clone());
        }
    }
    put.then(|| builder.finish())
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

    /// The shape the one caller has: a wrapper, then a quoted program.
    fn wrapped(script: &str) -> (String, language::Snippet) {
        let line = format!("run0 --pipe -- bash -c '{script}'");
        let at = "run0 --pipe -- bash -c '".len();
        (line, language::Snippet::declared(at..at + script.len(), language::Language::Shell))
    }

    #[test]
    fn a_script_inside_the_quotes_is_read_as_a_script() {
        // Without this the whole of it is one `Quoted` span: no separators,
        // no command names, no resolved variables, and nothing for the pane
        // to indent. It is shell, and it is about to be run as shell.
        let (line, script) = wrapped("cd /tmp; rm -rf x");
        let spans = render_command_reinterpreting(&line, &BTreeMap::new(), None, Some(&script));
        let inside: Vec<(&str, &SpanKind)> =
            spans.iter().map(|span| (span.text(), span.kind())).collect();
        assert!(inside.contains(&("cd", &SpanKind::Command)), "{inside:?}");
        assert!(inside.contains(&("rm", &SpanKind::Command)), "{inside:?}");
        assert!(inside.contains(&(";", &SpanKind::Separator)), "{inside:?}");
        // The quotes stay outside it. They are what make the script one word
        // to the shell, and the reader is looking at where that word begins.
        assert_eq!(spans.first().map(Span::text), Some("run0"));
        assert_eq!(spans.last().map(Span::text), Some("'"));
        assert_eq!(spans.last().map(Span::kind), Some(&SpanKind::Quoted));
        assert_eq!(unrender(&spans), line);
    }

    #[test]
    fn reading_it_again_moves_no_character() {
        // The whole of what this is allowed to change is what a span says
        // about text. `tests/fidelity.rs` is blind to it for the reason it is
        // blind to a line break, and this is that claim stated where the
        // splice happens.
        let (line, script) = wrapped("echo $HOME\nfor f in a b; do\n  cat \"$f\"\ndone");
        let env = BTreeMap::from([("HOME".to_string(), "/home/x".to_string())]);
        let spans = render_command_reinterpreting(&line, &env, None, Some(&script));
        assert_eq!(unrender(&spans), line);
        assert!(spans.covers_source(), "the spliced spans do not tile the line");
        // And the value comes from the environment the command will get,
        // which is the thing a reader cannot work out from the text.
        let resolved: Vec<(&str, &SpanKind)> = spans
            .iter()
            .filter(|span| matches!(span.kind(), SpanKind::Variable { .. }))
            .map(|span| (span.text(), span.kind()))
            .collect();
        assert_eq!(
            resolved,
            vec![
                ("$HOME", &SpanKind::Variable { resolved: Some("/home/x".to_string()) }),
                // No `$f`: the loop sets it, to each word in turn, so it is
                // neither unset nor any one value and nothing is drawn on it.
                // See `command::loop_name`.
            ],
            "{resolved:?}"
        );
        // Every span of the script lies inside the quotes, so the pane can
        // ask which bytes were read again and get an answer about the run
        // rather than about the whole line.
        let at = script.range();
        let nested: Vec<Range<usize>> = spans
            .iter()
            .map(Span::range)
            .filter(|range| at.start <= range.start && range.end <= at.end)
            .collect();
        assert!(nested.len() > 1, "{nested:?}");
    }

    #[test]
    fn a_program_in_a_language_hatch_cannot_read_is_left_exactly_as_it_is() {
        // `import` is not a command, `for` heads no loop and `sorted(...)` is
        // no pipeline. Marking any of them would be a reading of the wrong
        // language drawn with the confidence of the right one -- and the
        // gate is here rather than at the call sites because a rule each
        // caller applies for itself is one a caller can be written without.
        let (line, shell) = wrapped("for f in a b; do echo $f; done");
        let python = language::Snippet::declared(shell.range(), language::Language::Python);
        let read = render_command_reinterpreting(&line, &BTreeMap::new(), None, Some(&python));
        let named: Vec<&str> = read
            .iter()
            .filter(|span| span.kind() == &SpanKind::Command)
            .map(Span::text)
            .collect();
        assert_eq!(named, vec!["run0"], "{named:?}");
        // The same bytes read as shell do get marked, which is what makes the
        // comparison worth making.
        let as_shell = render_command_reinterpreting(&line, &BTreeMap::new(), None, Some(&shell));
        let as_shell: Vec<&str> = as_shell
            .iter()
            .filter(|span| span.kind() == &SpanKind::Command)
            .map(Span::text)
            .collect();
        assert_eq!(as_shell, vec!["run0", "for", "do", "done"], "{as_shell:?}");
        assert_eq!(unrender(&read), line);
    }

    #[test]
    fn a_program_nobody_reads_is_still_a_whole_run_of_the_spans() {
        // Nothing about it is drawn differently, but its edges become span
        // edges, so everything downstream can point at it -- and
        // `Payload::program` can refuse any pairing that cannot.
        let (line, shell) = wrapped("print(1)");
        let python = language::Snippet::declared(shell.range(), language::Language::Python);
        let (spans, kept) = render_command_naming(&line, &BTreeMap::new(), None, Some(python));
        let at = kept.expect("the program survived the rendering").range();
        assert!(spans.iter().any(|span| span.range().start == at.start), "{spans:?}");
        assert!(spans.iter().any(|span| span.range().end == at.end), "{spans:?}");
        assert_eq!(
            spans.iter().find(|span| span.range() == at).map(Span::text),
            Some("print(1)")
        );
        assert_eq!(unrender(&spans), line);
        assert!(spans.covers_source());
    }

    #[test]
    fn a_rendering_that_cannot_carry_the_claim_comes_back_without_it() {
        // Dropped rather than refused: a dropped program costs a sentence in
        // the header, and a refused rendering is a window that will not open.
        let (line, _) = wrapped("id -u");
        let nonsense =
            language::Snippet::declared(Range { start: 9, end: 8 }, language::Language::Python);
        let (spans, kept) = render_command_naming(&line, &BTreeMap::new(), None, Some(nonsense));
        assert_eq!(kept, None);
        assert_eq!(unrender(&spans), line);
    }

    #[test]
    fn the_line_break_the_caller_asked_for_survives_the_splice() {
        // The two facts the caller supplies are independent, and the splice
        // rebuilds every span: a break dropped on the way through would put
        // the command back behind the wall of wrapper it was moved out from.
        let (line, script) = wrapped("id -u");
        let at = line.find("bash").expect("the wrapper");
        let spans = render_command_reinterpreting(&line, &BTreeMap::new(), Some(at), Some(&script));
        let broken = spans.iter().find(|span| span.range().start == at).expect("a span at the seam");
        assert!(broken.break_before(), "the break at the seam was lost");
    }

    #[test]
    fn a_range_that_is_not_a_run_of_the_line_draws_the_line_as_it_was() {
        // Every doubt draws what hatch drew before there was a splice. None
        // of these can be produced by `ElevatedArgv::script_at`, which is the
        // reason to check rather than to assert: the fallback is a rendering
        // this window draws every day, and a panic is a dead window.
        let (line, _) = wrapped("id -u");
        let plain = render_command(&line);
        for doubt in [0..0, Range { start: 5, end: 4 }, 3..line.len() + 1] {
            let program = language::Snippet::declared(doubt.clone(), language::Language::Shell);
            let spans =
                render_command_reinterpreting(&line, &BTreeMap::new(), None, Some(&program));
            assert_eq!(spans, plain, "{doubt:?} was not declined");
        }
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
