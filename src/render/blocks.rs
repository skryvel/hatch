//! Which lines belong together, from a parse that is a hint and never the
//! authority.
//!
//! A long command is read as a shape before it is read as text: a `for` body,
//! an `if` arm, a pipeline broken across three lines. Until now the window
//! drew none of that, and a reader reconstructed it from the words. This
//! module answers one question — *which bytes of this command form one
//! construct?* — and the pane turns the answer into a bracket in the gutter
//! beside the rows those bytes are drawn on.
//!
//! # A box is an assertion, which nothing else here is
//!
//! Every other invariant in this crate guards against hatch changing the
//! text. None of them guards against hatch claiming a structure the shell
//! does not have, because until this module there was no such claim to make.
//! Colour is a hint a reader can discount. A box says *these lines are one
//! thing*, and is read as authoritative.
//!
//! So the rules here are not the rules the rest of rendering lives by:
//!
//! 1. **[`super::SpanBuilder`] stays the coverage authority.** Nothing in
//!    this module produces, consumes or perturbs a span. Spans tile the
//!    source exactly once and that check is untouched; a block is drawn
//!    *around* rows, never instead of them, and the two models meet only in
//!    the pane, through byte offsets both agree on.
//! 2. **Uncertainty draws nothing.** A parse that fails, a block that is not
//!    nested inside its neighbours, a range that is not on a character
//!    boundary, an input deep enough to be worth refusing — each of these
//!    returns *no blocks at all*, not a partial set. Fail towards silence,
//!    which is the same shape as fail towards deny.
//! 3. **The raw pane never groups.** That is [`crate::prompt_ui`]'s
//!    rule, not this module's, but it is why this one is allowed to exist: a
//!    mis-parse can mislead about grouping while the ground truth stays on
//!    screen beside it, unannotated.
//!
//! Rule 2 is worth spelling out, because "no blocks at all" is stronger than
//! it needs to be and that is deliberate. A partial set is the shape where a
//! reader sees three brackets, trusts them, and does not know that a fourth
//! construct was dropped because it confused the parser. Silence is a state a
//! reader can see; a quietly shortened list is not.
//!
//! # Why a parser at all, and why this one
//!
//! [`super::command`]'s scanner is a flat pass over five separators. It
//! cannot nest, and nesting is the whole question here, so this is the first
//! requirement that needs a grammar rather than a scan.
//!
//! `brush-parser` is pure Rust. That matters more here than it would in most
//! places: the bytes it parses are chosen by an agent, and hatch is the thing
//! standing between that agent and the host. The obvious alternative,
//! `tree-sitter-bash`, is a C grammar, and the error tolerance that is its
//! main advantage is worth little here — a command that does not parse is a
//! command bash will not run, so the structure it would uniquely recover is
//! structure over text that was never going to execute.
//!
//! Its parse is strict, which suits rule 2 exactly: input it refuses produces
//! no blocks, with no error nodes to prune and no judgement to make.
//!
//! # Two things the parser does not give, and what is done about each
//!
//! **`if … fi` reports the wrong end.** A bug upstream: every other rule in
//! that grammar computes its end from the token that closes the construct,
//! and the `if` rule binds the closing `fi` and then takes its end from the
//! *opening* keyword instead, so an `IfClauseCommand` reports a span covering
//! the two characters `if`.
//!
//! The end is recovered here rather than waited for, because an `if` is too
//! common a thing to leave unbracketed and the arms inside one then sit at
//! the margin as though they were not inside anything. What it is recovered
//! from is the `fi` *token* at or after the last arm's last pipeline — see
//! [`Walk::closing_fi`], which is also where the reasons that is exact are.
//! Everything else the parse says about an `if` is right, its arms included;
//! only the one number is wrong. When upstream fixes it this can go back to
//! reading `clause.loc`, and `an_if_runs_from_its_keyword_to_its_fi` is the
//! test that says so.
//!
//! **`( (` is read as `((`.** Upstream treats a subshell opened immediately
//! inside another as the arithmetic `((`, ignoring the space between them.
//! bash does not: `( ( echo hi ) )` runs two nested subshells, and
//! `( ( 1 + 1 ) )` is an error because bash runs `1` as a command. This one
//! costs a bracket rather than misplacing one — the mis-parse yields an
//! arithmetic command, which draws nothing — so it is recorded and left
//! alone. `a_subshell_opened_with_a_space_draws_nothing` pins it.
//!
//! **A here-document body is not in its command's span.** It should be
//! bracketed — a body is the clearest case of "these lines are one thing",
//! and it is the one region that is not shell at all — but the parser puts it
//! outside the command's range. [`super::command`]'s scanner already knows
//! exactly where a body starts and ends and has the tests to prove it, so
//! that bracket belongs to the scanner and not here. It is not in this
//! module's output and this module does not pretend to it.
//!
//! # Characters, bytes, and the difference that panics
//!
//! `brush-parser` counts **characters**: its tokenizer advances its index
//! once per `char`. Every offset in this crate is a **byte** offset, because
//! that is what a span is and what `&str` slicing takes. The two agree only
//! on ASCII, and an agent's command is routinely not ASCII — the whole of
//! [`super::unicode`] exists because of that.
//!
//! Getting this wrong does not merely misplace a bracket: slicing a `&str` at
//! a byte offset that is not a character boundary is a panic, and a panic in
//! the approval window is a request nobody can answer. So the conversion is
//! done once, through a table built from [`str::char_indices`], and a
//! character index with no byte offset behind it drops every block rather
//! than indexing anything. `a_block_over_wide_characters_covers_the_same_text`
//! is the case that would have caught the naive version.

use std::ops::Range;

use brush_parser::ast::{self, SourceLocation};

/// How deep a construct may nest before this module stops looking at it.
///
/// The parser is a recursive descent over an agent-chosen string, so nesting
/// depth is an agent-chosen recursion depth, and a stack overflow is an abort
/// rather than an error a caller can catch. A window that dies is a request
/// nobody can answer, which is the same cost as a window that never opened.
///
/// Sixty-four is far past anything a person reads as structure — the gutter
/// has room for a handful of steps — so the bound refuses input that was
/// never going to be drawn usefully anyway. Measured before the parser is
/// called, by counting brackets, because the point is to not call it.
pub const MAX_NESTING: usize = 64;

/// What kind of construct a block is.
///
/// Carried so the pane can decide what to *say* about a bracket, never to
/// decide whether to trust it: every variant here is an equally ordinary
/// claim, and none is drawn differently on the strength of being more
/// certain than another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    /// `for … done`, `while … done`, `until … done`, `for ((…)) … done`.
    Loop,
    /// `case … esac`.
    Case,
    /// `if … fi`, including its `elif` and `else` arms.
    If,
    /// `( … )`, which runs in a shell of its own.
    Subshell,
    /// `{ …; }`, which groups without a subshell.
    BraceGroup,
    /// Two or more commands joined by `|`. A pipeline of one command is not a
    /// pipeline; see [`blocks`].
    Pipeline,
    /// Two or more pipelines joined by `&&` or `||`: one statement whose
    /// parts run, or do not run, on what the part before them did.
    ///
    /// A single pipeline is not one, for [`BlockKind::Pipeline`]'s reason:
    /// every command in a script would otherwise be a block.
    AndOr,
}

impl BlockKind {
    /// What this kind is called, for a caption or a test.
    pub fn name(self) -> &'static str {
        match self {
            Self::Loop => "loop",
            Self::Case => "case",
            Self::If => "if",
            Self::Subshell => "subshell",
            Self::BraceGroup => "group",
            Self::Pipeline => "pipeline",
            Self::AndOr => "and-or",
        }
    }

    /// Whether the construct's last drawn line is a word that closes it,
    /// rather than the last member of it.
    ///
    /// `done`, `esac`, `fi`, `)` and `}` belong to the construct at the
    /// construct's own level, so the line they are on is not indented by it.
    /// A pipeline and an and-or list end with no word of their own: their
    /// last line is the last thing they run, and it is as much inside them
    /// as the lines above it.
    pub fn closed_by_a_word(self) -> bool {
        !matches!(self, Self::Pipeline | Self::AndOr)
    }
}

/// One construct: the bytes it covers, what it is, and how deep it sits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    range: Range<usize>,
    kind: BlockKind,
    depth: usize,
}

impl Block {
    /// The bytes of the source this construct covers.
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    /// What kind of construct it is.
    pub fn kind(&self) -> BlockKind {
        self.kind
    }

    /// How many blocks enclose this one. Zero for a construct at the top
    /// level, and the step the gutter draws it at.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Whether this block contains another entirely.
    fn contains(&self, other: &Self) -> bool {
        self.range.start <= other.range.start && other.range.end <= self.range.end
    }
}

/// The constructs in `source`, outermost first, or nothing at all.
///
/// Empty is the answer for every kind of doubt, and the cases are worth
/// naming because they are not failures of this function — they are what it
/// is for:
///
/// * the tokenizer or the parser refuses the input, which is roughly the
///   input `bash -c` would refuse too;
/// * the input nests deeper than [`MAX_NESTING`];
/// * a reported range is not on a character boundary, or runs past the end;
/// * two blocks overlap without one containing the other, which no shell
///   construct does and which therefore means the offsets are not describing
///   the text they claim to.
///
/// The last two cannot be triggered by any input known today. They are
/// checked anyway, on the same reasoning as every other total check here: the
/// cost is a comparison per block, and what it buys is that a wrong offset
/// draws nothing rather than drawing a bracket around the wrong lines.
pub fn blocks(source: &str) -> Vec<Block> {
    if source.is_empty() || nesting_beyond(source, MAX_NESTING) {
        return Vec::new();
    }
    let options = brush_parser::ParserOptions::default();
    let Ok(tokens) = brush_parser::tokenize_str_with_options(source, &options.tokenizer_options())
    else {
        return Vec::new();
    };
    let Ok(program) = brush_parser::parse_tokens(&tokens, &options) else {
        return Vec::new();
    };

    let mut walk = Walk { out: Vec::new(), tokens: &tokens };
    for list in &program.complete_commands {
        walk_list(list, &mut walk);
    }
    let found = walk.out;

    let offsets = ByteOffsets::of(source);
    let mut out = Vec::with_capacity(found.len());
    for (kind, span) in found {
        let (Some(start), Some(end)) = (offsets.at(span.0), offsets.at(span.1)) else {
            return Vec::new();
        };
        if start >= end {
            continue;
        }
        out.push(Block { range: start..end, kind, depth: 0 });
    }

    out.sort_by_key(|block| (block.range.start, std::cmp::Reverse(block.range.end)));
    if !properly_nested(&out) {
        return Vec::new();
    }
    set_depths(&mut out);
    out
}

/// The constructs in one run of `source`, reported in `source`'s own offsets.
///
/// The run is a shell script hatch quoted into a larger line -- an elevated
/// request is `run0 … -- bash -c '<script>'` -- and the constructs a reader
/// needs to see are the script's. Parsing the whole line would find none of
/// them: to a shell the script is one word, which is the right answer to a
/// different question. See
/// [`crate::exec::elevate::ElevatedArgv::script_at`].
///
/// The script is parsed on its own and every offset is shifted, which is
/// sound because the range is a run of bytes and a block is a range of them.
/// Nothing outside the run is looked at, so a wrapper that happened to
/// contain a `do` cannot put a bracket anywhere.
///
/// The run itself is not a block. It has a beginning and an end and a
/// bracket could be drawn around it, but a bracket says *these lines are one
/// construct* and the quotes on screen already say that, at both ends, in the
/// command's own characters. A second mark for the same fact is the thing
/// [`crate::prompt_ui::panes`]'s gutter is written not to do.
///
/// Empty for every doubt [`blocks`] is empty for, and for a range that is not
/// a run of `source`.
pub fn blocks_within(source: &str, script: Range<usize>) -> Vec<Block> {
    if script.start >= script.end
        || script.end > source.len()
        || !source.is_char_boundary(script.start)
        || !source.is_char_boundary(script.end)
    {
        return Vec::new();
    }
    blocks(&source[script.clone()])
        .into_iter()
        .map(|block| Block {
            range: block.range.start + script.start..block.range.end + script.start,
            ..block
        })
        .collect()
}

/// Whether `source` nests brackets deeper than `limit`.
///
/// A count of `(` and `{` against their closers, which over-counts — a brace
/// in a string or a comment is counted — and over-counting is the safe
/// direction, because the answer is only ever used to decide *not* to parse.
/// It is deliberately not the scanner: this runs before anything else looks
/// at the input, and it must not itself be the thing that recurses.
fn nesting_beyond(source: &str, limit: usize) -> bool {
    let mut depth = 0usize;
    for byte in source.bytes() {
        match byte {
            b'(' | b'{' => {
                depth += 1;
                if depth > limit {
                    return true;
                }
            }
            b')' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// Character index to byte offset, for one source string.
///
/// Built once per call. The extra entry at the end is the source's length, so
/// a span that ends at the last character has somewhere to point.
struct ByteOffsets(Vec<usize>);

impl ByteOffsets {
    fn of(source: &str) -> Self {
        let mut out: Vec<usize> = source.char_indices().map(|(at, _)| at).collect();
        out.push(source.len());
        Self(out)
    }

    /// The byte offset of character `index`, or `None` if there is no such
    /// character — which is the answer that drops every block rather than
    /// slicing at an offset that might not be a boundary.
    fn at(&self, index: usize) -> Option<usize> {
        self.0.get(index).copied()
    }
}

/// Whether every pair of blocks is either disjoint or nested.
///
/// Reads a sorted list, so it is one pass with a stack of open ranges rather
/// than a comparison of every pair against every other.
fn properly_nested(blocks: &[Block]) -> bool {
    let mut open: Vec<Range<usize>> = Vec::new();
    for block in blocks {
        while let Some(last) = open.last() {
            if last.end <= block.range.start {
                open.pop();
            } else if block.range.end <= last.end {
                break;
            } else {
                return false;
            }
        }
        open.push(block.range.clone());
    }
    true
}

/// Fill in how many blocks enclose each one.
fn set_depths(blocks: &mut [Block]) {
    for index in 0..blocks.len() {
        let depth = blocks[..index].iter().filter(|outer| outer.contains(&blocks[index])).count();
        blocks[index].depth = depth;
    }
}

/// A construct found in the parse, before its offsets have been converted.
type Found = (BlockKind, (usize, usize));

/// What the walk carries: where blocks are collected, and the token list the
/// one construct that needs it reads.
///
/// A struct rather than a second parameter on six functions, because only
/// [`Walk::closing_fi`] uses the tokens and threading them by hand would put
/// an argument nothing reads into every signature between here and there.
struct Walk<'a> {
    out: Vec<Found>,
    /// The same tokens the parse was built from, in source order.
    tokens: &'a [brush_parser::Token],
}

impl Walk<'_> {
    fn push(&mut self, kind: BlockKind, span: &brush_parser::SourceSpan) {
        self.out.push((kind, (span.start.index, span.end.index)));
    }

    /// Where the `fi` that closes an `if` beginning before `after` ends.
    ///
    /// # Why the token list rather than the span
    ///
    /// The `if` rule upstream reports an end taken from its opening keyword
    /// -- see the module docs -- so the span says the construct is two
    /// characters long. Everything else about the parse is right, including
    /// where each of the arms' pipelines ends, and `fi` is a reserved word:
    /// the first `fi` *token* at or after the last arm's last pipeline is the
    /// one that closes this `if`, whatever is nested inside the arms.
    ///
    /// It is the token list and not the text because a token cannot be a
    /// substring of something else. `fifo` is one word, `"fi"` is a word
    /// whose text includes its quotes, and a `fi` in a comment is not a token
    /// at all -- none of the three can be mistaken for the keyword here, and
    /// all three could be by a search over the source.
    ///
    /// `None` when there is no such token, which is the shape every doubt in
    /// this module takes: no answer, so no bracket.
    fn closing_fi(&self, after: usize) -> Option<usize> {
        self.tokens
            .iter()
            .filter_map(|token| match token {
                brush_parser::Token::Word(text, span) if text == "fi" => Some(span),
                _ => None,
            })
            .find(|span| span.start.index >= after)
            .map(|span| span.end.index)
    }
}

/// Where the last thing in `list` ends, as the parse reports it.
///
/// Zero for a list with nothing in it, which is what an `if` with an empty
/// arm has: the caller takes the largest of these against the `if`'s own
/// start, so an empty arm contributes nothing rather than moving the search
/// backwards.
fn ends_at(list: &ast::CompoundList) -> usize {
    list.0
        .iter()
        .filter_map(|item| pipelines(&item.0).filter_map(ast::Pipeline::location).last())
        .map(|span| span.end.index)
        .max()
        .unwrap_or(0)
}

/// Every pipeline in one and-or list, in source order.
fn pipelines(list: &ast::AndOrList) -> impl Iterator<Item = &ast::Pipeline> {
    std::iter::once(&list.first).chain(list.additional.iter().map(|extra| match extra {
        ast::AndOr::And(pipeline) | ast::AndOr::Or(pipeline) => pipeline,
    }))
}

fn walk_list(list: &ast::CompoundList, out: &mut Walk<'_>) {
    for item in &list.0 {
        walk_and_or(&item.0, out);
    }
}

fn walk_and_or(list: &ast::AndOrList, out: &mut Walk<'_>) {
    // A list of one pipeline is that pipeline, on `walk_pipeline`'s reasoning:
    // a bracket around every statement in a script says nothing. Two or more
    // is a statement whose second half runs on what its first half did, and
    // the parts after the first are members of it rather than new statements
    // -- which is the fact the indentation is there to carry.
    if !list.additional.is_empty()
        && let (Some(first), Some(last)) =
            (list.first.location(), pipelines(list).last().and_then(ast::Pipeline::location))
    {
        out.push(BlockKind::AndOr, &brush_parser::SourceSpan { start: first.start, end: last.end });
    }
    walk_pipeline(&list.first, out);
    for extra in &list.additional {
        match extra {
            ast::AndOr::And(pipeline) | ast::AndOr::Or(pipeline) => walk_pipeline(pipeline, out),
        }
    }
}

fn walk_pipeline(pipeline: &ast::Pipeline, out: &mut Walk<'_>) {
    // A pipeline of one command is a command. Bracketing it would put a
    // bracket around most lines of most commands, which says nothing.
    if pipeline.seq.len() > 1
        && let Some(span) = pipeline.location()
    {
        out.push(BlockKind::Pipeline, &span);
    }
    for command in &pipeline.seq {
        walk_command(command, out);
    }
}

fn walk_command(command: &ast::Command, out: &mut Walk<'_>) {
    match command {
        ast::Command::Simple(_) | ast::Command::ExtendedTest(..) => {}
        ast::Command::Compound(compound, _) => walk_compound(compound, out),
        ast::Command::Function(function) => walk_compound(&function.body.0, out),
    }
}

fn walk_compound(compound: &ast::CompoundCommand, out: &mut Walk<'_>) {
    use ast::CompoundCommand as Compound;
    match compound {
        Compound::ForClause(clause) => {
            out.push(BlockKind::Loop, &clause.loc);
            walk_list(&clause.body.list, out);
        }
        Compound::ArithmeticForClause(clause) => {
            out.push(BlockKind::Loop, &clause.loc);
            walk_list(&clause.body.list, out);
        }
        Compound::WhileClause(clause) | Compound::UntilClause(clause) => {
            out.push(BlockKind::Loop, &clause.2);
            walk_list(&clause.0, out);
            walk_list(&clause.1.list, out);
        }
        Compound::CaseClause(clause) => {
            out.push(BlockKind::Case, &clause.loc);
            for item in &clause.cases {
                if let Some(commands) = &item.cmd {
                    walk_list(commands, out);
                }
            }
        }
        Compound::Subshell(shell) => {
            out.push(BlockKind::Subshell, &shell.loc);
            walk_list(&shell.list, out);
        }
        Compound::BraceGroup(group) => {
            out.push(BlockKind::BraceGroup, &group.loc);
            walk_list(&group.list, out);
        }
        // The one construct whose end the parse does not give; see the
        // module docs and [`Walk::closing_fi`]. Its arms are walked either
        // way, so what is nested inside them is drawn whether or not the
        // `fi` is found.
        Compound::IfClause(clause) => {
            let start = clause.loc.start.index;
            let mut last = clause.loc.end.index;
            let mut arms = |list: &ast::CompoundList, out: &mut Walk<'_>| {
                last = last.max(ends_at(list));
                walk_list(list, out);
            };
            arms(&clause.condition, out);
            arms(&clause.then, out);
            if let Some(elses) = &clause.elses {
                for arm in elses {
                    if let Some(condition) = &arm.condition {
                        arms(condition, out);
                    }
                    arms(&arm.body, out);
                }
            }
            if let Some(end) = out.closing_fi(last) {
                out.out.push((BlockKind::If, (start, end)));
            }
        }
        Compound::Coprocess(process) => walk_command(&process.body, out),
        Compound::Arithmetic(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The blocks of `source`, as `(kind, the text it covers, depth)`, which
    /// is what a test wants to read and what a bracket is drawn from.
    fn drawn(source: &str) -> Vec<(&'static str, &str, usize)> {
        blocks(source)
            .into_iter()
            .map(|block| (block.kind().name(), &source[block.range()], block.depth()))
            .collect()
    }

    #[test]
    fn a_loop_is_one_block_from_its_keyword_to_its_end() {
        let source = "for x in a b; do\n  echo $x\ndone";
        assert_eq!(drawn(source), vec![("loop", source, 0)]);
    }

    #[test]
    fn a_while_loop_is_the_same_shape_as_a_for_loop() {
        let source = "while read -r line; do\n  echo $line\ndone";
        assert_eq!(drawn(source), vec![("loop", source, 0)]);
    }

    #[test]
    fn a_loop_inside_a_loop_is_one_step_deeper() {
        let source = "for a in 1; do\n  for b in 2; do\n    echo $b\n  done\ndone";
        let found = drawn(source);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0], ("loop", source, 0));
        assert_eq!(found[1].0, "loop");
        assert_eq!(found[1].2, 1, "the inner loop is drawn one step in");
        assert!(found[1].1.starts_with("for b"), "{found:?}");
        assert!(found[1].1.ends_with("done"), "{found:?}");
    }

    #[test]
    fn a_subshell_and_a_brace_group_are_each_one_block() {
        assert_eq!(drawn("(cd /tmp; rm -rf x)"), vec![("subshell", "(cd /tmp; rm -rf x)", 0)]);
        assert_eq!(drawn("{ a; b; }"), vec![("group", "{ a; b; }", 0)]);
    }

    #[test]
    fn a_case_runs_from_case_to_esac() {
        let source = "case $x in\n  a) echo 1;;\n  b) echo 2;;\nesac";
        assert_eq!(drawn(source), vec![("case", source, 0)]);
    }

    #[test]
    fn a_pipeline_of_one_command_is_not_a_pipeline() {
        // Otherwise every ordinary command on screen would wear a bracket,
        // and a bracket that is always there says nothing.
        assert_eq!(drawn("ls -l"), vec![]);
        assert_eq!(drawn("echo hi > /tmp/x"), vec![]);
    }

    #[test]
    fn a_script_quoted_into_a_line_is_parsed_on_its_own() {
        // The wrapper is not shell hatch is entitled to read -- and it does
        // not have to be, because the run is a run of bytes and a block is a
        // range of them. What comes back is in the whole line's offsets.
        let script = "for f in a b; do\n  cat $f\ndone";
        let line = format!("run0 -- bash -c '{script}'");
        let at = line.find(script).expect("the script");
        let found = blocks_within(&line, at..at + script.len());
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(&line[found[0].range()], script);
        // Parsing the line instead finds nothing: to a shell the script is
        // one word. That is the whole of what this function is for.
        assert_eq!(blocks(&line), vec![]);
    }

    #[test]
    fn nothing_outside_the_run_can_put_a_bracket_anywhere() {
        // A wrapper is agent-adjacent text hatch built, and a `done` in it is
        // not a keyword of the script. Only the run is parsed.
        let line = "run0 --setenv=X=done -- bash -c 'cat a'";
        let at = line.find("cat a").expect("the script");
        assert_eq!(blocks_within(line, at..at + "cat a".len()), vec![]);
    }

    #[test]
    fn a_run_that_is_not_a_run_of_the_source_draws_nothing() {
        // Every doubt in this module has one shape. A caller that has lost
        // track of which line its offsets are about gets no brackets, rather
        // than brackets around whatever those offsets happen to hit.
        let line = "run0 -- bash -c 'for f in a b; do cat $f; done'";
        for doubt in [0..0, Range { start: 9, end: 8 }, 3..line.len() + 1] {
            assert_eq!(blocks_within(line, doubt.clone()), vec![], "{doubt:?}");
        }
        // Inside a character, not between two.
        let snowman = "echo '\u{2603} for f in a b; do cat $f; done'";
        assert_eq!(blocks_within(snowman, 7..snowman.len() - 1), vec![]);
    }

    #[test]
    fn two_pipelines_joined_by_an_operator_are_one_statement() {
        // `sed` here runs only if the test passed, so it is a member of the
        // statement the test opens and not a statement of its own. The block
        // is what lets the pane draw it that way.
        let source = "[ -n \"$f\" ] &&\nsed -n '1,40p' \"$f\"";
        assert_eq!(drawn(source), vec![("and-or", source, 0)]);
        // `||` is the same construct: which operator joined them decides when
        // the second half runs, not whether the two are one statement.
        assert_eq!(drawn("a || b"), vec![("and-or", "a || b", 0)]);
    }

    #[test]
    fn one_pipeline_on_its_own_is_not_a_statement_worth_bracketing() {
        // `a_pipeline_of_one_command_is_not_a_pipeline`'s reasoning, one
        // level up: every statement in every script would be a block.
        assert_eq!(drawn("ls -l"), vec![]);
        assert_eq!(drawn("a; b; c"), vec![]);
    }

    #[test]
    fn a_pipeline_inside_a_statement_is_nested_in_it() {
        let source = "grep -o x foo | sort -u &&\necho found";
        let found = drawn(source);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0], ("and-or", source, 0), "{found:?}");
        assert_eq!(found[1], ("pipeline", "grep -o x foo | sort -u", 1), "{found:?}");
    }

    #[test]
    fn a_pipeline_broken_across_lines_is_one_block() {
        let source = "find . -print0 |\n  xargs -0 rm -v |\n  tee -a log";
        assert_eq!(drawn(source), vec![("pipeline", source, 0)]);
    }

    #[test]
    fn an_if_runs_from_its_keyword_to_its_fi() {
        // The end comes from the `fi` token, because the parse does not
        // give it -- see `Walk::closing_fi`. What is nested in the arms is
        // found either way, and now sits a step inside the `if` that holds
        // it rather than at the margin.
        let source = "if [ -f x ]; then\n  for y in 1 2; do\n    echo $y\n  done\nfi";
        let found = drawn(source);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].0, "if");
        assert_eq!(found[0].1, source, "the if does not cover itself: {found:?}");
        assert_eq!(found[0].2, 0);
        assert_eq!(found[1].0, "loop");
        assert_eq!(found[1].2, 1, "the loop is not inside the if: {found:?}");
    }

    #[test]
    fn an_if_with_every_arm_ends_at_the_last_fi_and_not_an_earlier_one() {
        // The search starts after the last arm's last pipeline, so a nested
        // `if` inside an arm -- whose own `fi` comes first in the source --
        // cannot be mistaken for this one's.
        let source = "if a; then\n  if b; then c; fi\nelif d; then\n  e\nelse\n  f\nfi";
        let found = drawn(source);
        let outer = found.iter().find(|b| b.0 == "if" && b.2 == 0).expect("{found:?}");
        assert_eq!(outer.1, source, "the outer if stopped at the inner fi: {found:?}");
        let inner = found.iter().find(|b| b.0 == "if" && b.2 == 1).expect("{found:?}");
        assert_eq!(inner.1, "if b; then c; fi", "{found:?}");
    }

    #[test]
    fn a_word_that_merely_reads_as_fi_does_not_close_an_if() {
        // `fi` closes an `if` as a token and not as text. An argument that
        // happens to be the letters, a word with them inside it, and a
        // quoted one are none of them the keyword -- and the search starts
        // past the arms anyway, which is what keeps the first two out of it.
        let source = "if a; then\n  echo fi fifo \"fi\"\nfi";
        let found = drawn(source);
        let block = found.iter().find(|b| b.0 == "if").expect("no if drawn");
        assert_eq!(block.1, source, "an if ended on something that was not its fi: {found:?}");
    }

    #[test]
    fn a_function_body_is_walked() {
        let source = "deploy() {\n  for host in a b; do\n    ssh $host true\n  done\n}";
        let found = drawn(source);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].0, "group");
        assert_eq!(found[1].0, "loop");
        assert_eq!(found[1].2, 1);
    }

    #[test]
    fn input_the_parser_refuses_draws_nothing() {
        // Each of these is input `bash -c` refuses too, so there is no
        // structure being withheld from a reader — there is no run to draw.
        for refused in [
            "for x in",
            "if [ -f x ]; then",
            "echo 'unterminated",
            "a >&& b",
            "case x in",
        ] {
            assert_eq!(blocks(refused), vec![], "{refused:?} drew something");
        }
    }

    #[test]
    fn an_empty_command_draws_nothing() {
        assert_eq!(blocks(""), vec![]);
    }

    #[test]
    fn nesting_past_the_bound_is_refused_before_the_parser_is_asked() {
        // The parser is a recursive descent over an agent-chosen string, and
        // a stack overflow aborts the process rather than failing a call
        // somebody could handle. So depth is measured first, cheaply, and
        // past the bound nothing is parsed at all.
        let deep = format!("{}true{}", "(".repeat(MAX_NESTING + 1), ")".repeat(MAX_NESTING + 1));
        assert!(nesting_beyond(&deep, MAX_NESTING), "the bound did not fire");
        assert_eq!(blocks(&deep), vec![]);
    }

    #[test]
    fn nesting_inside_the_bound_is_drawn() {
        // The companion to the test above, so that one cannot pass by the
        // input being refused for some other reason.
        let shallow = "for a in 1; do\n  for b in 2; do\n    (cd /tmp; echo x)\n  done\ndone";
        assert!(!nesting_beyond(shallow, MAX_NESTING));
        let found = drawn(shallow);
        assert_eq!(
            found.iter().map(|(kind, _, depth)| (*kind, *depth)).collect::<Vec<_>>(),
            vec![("loop", 0), ("loop", 1), ("subshell", 2)],
            "{found:?}"
        );
    }

    #[test]
    fn an_arithmetic_command_is_not_a_block() {
        // `((` is arithmetic evaluation, not two subshells. It has no body
        // and no lines that belong together, so there is nothing to bracket,
        // and a bracket drawn as though it were a subshell would be a claim
        // about a construct that is not there.
        assert_eq!(blocks("((x = 1 + 2))"), vec![]);
    }

    #[test]
    fn a_subshell_opened_with_a_space_draws_nothing() {
        // Upstream reads `( (` as the arithmetic `((` and ignores the space
        // between them. Checked against bash 5.3.15, which does not:
        // `( ( echo hi ) )` prints hi from two nested subshells, and
        // `( ( 1 + 1 ) )` fails with "command not found" because the `1` is
        // being run as a command rather than added to anything.
        //
        // The cost is a bracket that is missing, not one that is wrong: the
        // mis-parse produces an arithmetic command, and this module draws
        // nothing for one. That is rule 2 doing its job on a parser that is
        // wrong rather than merely unsure, and it is why this is recorded
        // here instead of worked around.
        assert_eq!(blocks("( ( true ) )"), vec![]);
        // The same command without the inner nesting is read correctly, so
        // what is lost is bounded to the shape above.
        assert_eq!(drawn("( true )"), vec![("subshell", "( true )", 0)]);
    }

    #[test]
    fn a_block_over_wide_characters_covers_the_same_text() {
        // The parser counts characters and every offset here is a byte. On
        // this input the two differ by six bytes before the loop even opens,
        // and a naive conversion slices into the middle of a character, which
        // is a panic in the approval window rather than a wrong bracket.
        let source = "echo 日本語\nfor x in é ü; do\n  echo $x\ndone";
        let found = drawn(source);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, "loop");
        assert_eq!(found[0].1, "for x in é ü; do\n  echo $x\ndone");
    }

    proptest! {
        /// Every block's range is a slice of the source that does not panic
        /// and does not start or end inside a character. Generated over text
        /// that mixes wide characters into shell the parser will accept, so
        /// the blocks are real rather than always empty.
        #[test]
        fn a_block_is_always_a_whole_slice_of_its_source(
            name in "[a-z]{1,4}",
            wide in prop::sample::select(vec!["é", "日本語", "ü", "a", "🙂"]),
        ) {
            let source = format!("for {name} in {wide} b; do\n  echo ${name} {wide}\ndone");
            for block in blocks(&source) {
                let range = block.range();
                prop_assert!(source.is_char_boundary(range.start));
                prop_assert!(source.is_char_boundary(range.end));
                prop_assert!(range.end <= source.len());
                // The slice itself, which panics if either end is wrong.
                let _ = &source[range];
            }
        }

        /// No two blocks overlap without one containing the other, and a
        /// block's depth is the number of blocks that contain it. Both are
        /// what the gutter draws steps from, so a violation would put a
        /// bracket at a column that means nothing.
        #[test]
        fn blocks_nest_and_their_depths_say_how_deeply(
            depth in 1usize..6,
        ) {
            let mut source = String::new();
            for level in 0..depth {
                source.push_str(&format!("for x{level} in a; do\n"));
            }
            source.push_str("echo hi\n");
            for _ in 0..depth {
                source.push_str("done\n");
            }
            let found = blocks(&source);
            prop_assert_eq!(found.len(), depth);
            for (index, block) in found.iter().enumerate() {
                prop_assert_eq!(block.depth(), index, "depth is its place in the nesting");
                if index > 0 {
                    let outer = &found[index - 1];
                    prop_assert!(outer.contains(block), "a block escaped its parent");
                }
            }
        }
    }
}
