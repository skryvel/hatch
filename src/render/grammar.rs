//! Strings and comments in a program that is not shell, read by a TextMate
//! grammar. Only with the `highlight` feature; without it, [`read`] is
//! [`super::unicode::classify`] and nothing else.
//!
//! # What it may say
//!
//! Two kinds, and only the two hatch already has an honest meaning for:
//! [`SpanKind::Quoted`] for a string, delimiters included, and
//! [`SpanKind::Comment`] for a line comment. A grammar knows a great deal
//! more -- keywords, function names, numbers -- but those are colours an
//! editor picks for taste, and every kind in this window is a claim about the
//! text. A string is data and a comment does not run; `def` being purple says
//! nothing a reader needs to decide anything.
//!
//! # What it may not do
//!
//! Change a byte's drawing into anything but itself. The base is
//! [`super::unicode::classify`], exactly what a program got before this
//! existed, and marks are laid over its `Plain` runs only: a chip stays a
//! chip, a newline still starts a line, and the text under a mark is the text.
//!
//! # When it says nothing
//!
//! A grammar is a set of regular expressions with no notion of being unsure,
//! so a confidently wrong reading cannot be caught here. What can be caught is
//! the grammar knowing it struggled, and every one of those drops *every*
//! mark rather than keeping the ones that look fine -- a reading that went
//! wrong once has no standing anywhere else in the same program:
//!
//! * the tokenizer reports a line [`HighlightStatus::Degraded`] -- its own
//!   budgets stopped it short;
//! * a line's tokens do not tile the line exactly;
//! * the grammar will not load, or refuses a line.
//!
//! One more is caught per string rather than per program: a string whose
//! closing delimiter never comes is drawn plain. The grammars end a
//! single-quoted Python string at the end of its line whether or not it was
//! closed, and report that as a complete, well-formed reading -- so the pairing
//! is done here, from the grammar's own begin and end punctuation, and an
//! opening with no end marks nothing.

use super::language::Language;
use super::span::{SpanBuilder, SpanKind, Spans};
use super::unicode;
use std::ops::Range;

/// `text`, an argument `language` will be handed, drawn byte for byte with
/// its strings and comments marked where the grammar is sure of them.
pub fn read(text: &str, language: Language) -> Spans {
    let plain = unicode::classify(text);
    match marks(text, language) {
        Some(marks) if !marks.is_empty() => overlay(&plain, &marks),
        _ => plain,
    }
}

/// `plain` with each mark laid over the `Plain` text it covers.
///
/// Only `Plain` is overwritten. A chip is a claim about one codepoint that a
/// string around it does not make untrue, and the reader still needs the
/// label that says the quote is a Cyrillic one.
fn overlay(plain: &Spans, marks: &[(Range<usize>, SpanKind)]) -> Spans {
    let mut builder = SpanBuilder::new(plain.source());
    let mut next = 0;
    for span in plain.iter() {
        if span.break_before() {
            builder.break_next();
        }
        let range = span.range();
        if *span.kind() != SpanKind::Plain {
            builder.push_to(range.end, span.kind().clone());
            continue;
        }
        while next < marks.len() && marks[next].0.end <= range.start {
            next += 1;
        }
        let mut at = next;
        while at < marks.len() && marks[at].0.start < range.end {
            let (mark, kind) = &marks[at];
            builder.push_to(mark.start.max(range.start), SpanKind::Plain);
            builder.push_to(mark.end.min(range.end), kind.clone());
            at += 1;
        }
        builder.push_to(range.end, SpanKind::Plain);
    }
    builder.finish()
}

/// Whether this build marks anything in a program in `language`.
///
/// Asked by the sentence the window draws above such a program, which has to
/// say whether hatch read it: "does not read it" beside a string drawn as one
/// would be the window contradicting itself.
pub fn reads(language: Language) -> bool {
    #[cfg(feature = "highlight")]
    return grammar_of(language).is_some();
    #[cfg(not(feature = "highlight"))]
    return {
        let _ = language;
        false
    };
}

/// The grammar name syntaxmate knows `language` by, for the languages this
/// was tried on. Every other one is left alone: a grammar nobody has looked
/// at a real window of is not one to start drawing claims from.
#[cfg(feature = "highlight")]
fn grammar_of(language: Language) -> Option<&'static str> {
    match language {
        Language::Python => Some("python"),
        Language::Clojure => Some("clojure"),
        _ => None,
    }
}

#[cfg(not(feature = "highlight"))]
fn marks(_text: &str, _language: Language) -> Option<Vec<(Range<usize>, SpanKind)>> {
    None
}

/// Every mark the grammar is sure of, in source order and never overlapping,
/// or `None` when it is not sure of the program at all. See the module docs
/// for what counts.
#[cfg(feature = "highlight")]
fn marks(text: &str, language: Language) -> Option<Vec<(Range<usize>, SpanKind)>> {
    use syntaxmate::{HighlightStatus, Tokenizer, TokenizerOptions};

    let mut tokenizer =
        Tokenizer::for_bundled_language(grammar_of(language)?, TokenizerOptions::default())
            .ok()?;
    let mut state = tokenizer.initial_state();
    let mut out = Vec::new();
    // The string being read, if one is open: its tokens so far. Committed to
    // `out` at its closing delimiter, and dropped if the program ends first.
    let mut open: Option<Vec<Range<usize>>> = None;
    // String-scoped tokens that come before an opening delimiter -- Python's
    // `f` or `rb` -- which belong to the string only if one opens right after.
    let mut prefix: Vec<Range<usize>> = Vec::new();

    let mut start = 0;
    for line in text.split('\n') {
        let tokenized = tokenizer.tokenize_line(line, &mut state).ok()?;
        if tokenized.status() == HighlightStatus::Degraded {
            return None;
        }
        let mut cursor = 0;
        for token in tokenized.tokens() {
            let range = token.range();
            if range.start != cursor || range.end <= range.start {
                return None;
            }
            cursor = range.end;
            let at = start + range.start..start + range.end;
            let scopes: Vec<&str> = token.scopes().collect();
            let has = |prefix: &str| scopes.iter().any(|scope| scope.starts_with(prefix));

            if has("comment.line.") && !has("string.") {
                prefix.clear();
                match &mut open {
                    // A comment scope inside a string is a grammar that has
                    // lost its place. Nothing it said is kept.
                    Some(_) => return None,
                    None => out.push((at, SpanKind::Comment)),
                }
                continue;
            }
            if !has("string.") {
                prefix.clear();
                // Inside an open string this is an interpolation -- the
                // `{x}` of an f-string -- which is code, and drawn plain.
                continue;
            }
            let begins = has("punctuation.definition.string.begin");
            let ends = has("punctuation.definition.string.end");
            match &mut open {
                None if begins => {
                    let mut tokens = std::mem::take(&mut prefix);
                    tokens.push(at);
                    if ends {
                        // One token that both opens and closes is not a
                        // shape either grammar produces; not guessed at.
                        return None;
                    }
                    open = Some(tokens);
                }
                None => prefix.push(at),
                Some(tokens) => {
                    tokens.push(at);
                    if ends {
                        out.extend(tokens.drain(..).map(|at| (at, SpanKind::Quoted)));
                        open = None;
                    }
                }
            }
        }
        if cursor != line.len() {
            return None;
        }
        // Prefix tokens never span a line: `f` then a newline then `"` is
        // not a string prefix in either language.
        prefix.clear();
        start += line.len() + 1;
    }
    // A string still open here never closed: see the module docs.
    Some(joined(out))
}

/// `marks`, with each run of touching marks of one kind joined into one.
///
/// One span per stretch of string or comment rather than one per grammar
/// token, so that the spans say what a reader sees -- a string, a comment --
/// and not how the grammar happened to cut it.
#[cfg(feature = "highlight")]
fn joined(marks: Vec<(Range<usize>, SpanKind)>) -> Vec<(Range<usize>, SpanKind)> {
    let mut out: Vec<(Range<usize>, SpanKind)> = Vec::new();
    for (at, kind) in marks {
        match out.last_mut() {
            Some((last, was)) if last.end == at.start && *was == kind => last.end = at.end,
            _ => out.push((at, kind)),
        }
    }
    out
}

#[cfg(all(test, feature = "highlight"))]
mod tests {
    use super::*;

    fn marked(text: &str, language: Language) -> Vec<(&str, SpanKind)> {
        let spans = read(text, language);
        assert_eq!(spans.source(), text);
        assert!(spans.covers_source());
        spans
            .iter()
            .filter(|span| matches!(span.kind(), SpanKind::Quoted | SpanKind::Comment))
            .map(|span| (&text[span.range()], span.kind().clone()))
            .collect()
    }

    #[test]
    fn a_python_string_and_comment_are_marked() {
        assert_eq!(
            marked("x = 'a b'  # note", Language::Python),
            vec![("'a b'", SpanKind::Quoted), ("# note", SpanKind::Comment)]
        );
    }

    #[test]
    fn an_f_string_marks_its_text_and_leaves_its_code_plain() {
        // `{b + 1}` runs. Drawing it as string would be the confident wrong
        // reading this module exists to avoid.
        assert_eq!(
            marked("x = f\"a{b + 1}c\"", Language::Python),
            vec![("f\"a", SpanKind::Quoted), ("c\"", SpanKind::Quoted)]
        );
    }

    #[test]
    fn a_string_that_never_closes_is_not_marked() {
        // The grammar calls this a string to the end of the line, and says
        // it read the line completely.
        assert_eq!(marked("s = 'open", Language::Python), vec![]);
        assert_eq!(marked("s = '''open\nstill", Language::Python), vec![]);
        // And one that did close is still marked beside it.
        assert_eq!(
            marked("a = 'shut'; s = 'open", Language::Python),
            vec![("'shut'", SpanKind::Quoted)]
        );
    }

    #[test]
    fn a_docstring_across_lines_is_marked_and_its_newline_stays_a_chip() {
        let spans = read("'''doc\nmore'''", Language::Python);
        let kinds: Vec<(&str, &SpanKind)> = spans.iter().map(|s| (s.text(), s.kind())).collect();
        assert_eq!(kinds[0], ("'''doc", &SpanKind::Quoted));
        assert!(matches!(kinds[1].1, SpanKind::Chip { .. }), "{kinds:?}");
        assert_eq!(kinds[2], ("more'''", &SpanKind::Quoted));
        let third = spans.iter().find(|span| span.text() == "more'''").unwrap();
        assert!(third.break_before(), "the line after the newline does not start a line");
    }

    #[test]
    fn clojure_strings_and_comments_are_marked_and_its_quote_is_not_a_string() {
        // `'[…]` is Clojure's quote, not a string delimiter -- the case that
        // made shell-quoting the program unreadable in the first place.
        assert_eq!(
            marked("(require '[babashka.fs :as fs]) ; note\n(str \"a\\\"b\")", Language::Clojure),
            vec![("; note", SpanKind::Comment), ("\"a\\\"b\"", SpanKind::Quoted)]
        );
    }

    #[test]
    fn a_chip_inside_a_string_stays_a_chip() {
        // A zero-width space in a string is still a zero-width space.
        let spans = read("x = 'a\u{200B}b'", Language::Python);
        let kinds: Vec<&SpanKind> = spans.iter().map(|s| s.kind()).collect();
        assert!(kinds.iter().any(|k| matches!(k, SpanKind::Chip { .. })), "{kinds:?}");
        assert_eq!(
            spans.iter().filter(|s| *s.kind() == SpanKind::Quoted).map(|s| s.text()).collect::<Vec<_>>(),
            vec!["'a", "b'"]
        );
    }

    #[test]
    fn a_language_nobody_has_looked_at_is_left_plain() {
        assert_eq!(marked("x = 'a' -- c", Language::Lua), vec![]);
        assert_eq!(marked("my $x = 'a'; # c", Language::Perl), vec![]);
    }
}
