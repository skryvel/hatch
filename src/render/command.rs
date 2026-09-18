//! Additive-only command segmentation, variable and binary annotation.
//!
//! A long command needs line breaks before a human can read it, and the
//! obvious way to get them is the wrong one. Earlier tools of this shape
//! replaced `;` with a newline: the display got shorter, the command lost a
//! character, and the reader lost the one thing the window is for. A display
//! that can silently delete one character can in principle delete any of
//! them, so a careful reader is right to stop trusting it on exactly the
//! gnarly commands where trust matters most.
//!
//! So segmentation here is **additive only**. It inserts layout *around*
//! separators and never removes them:
//!
//! * The separator stays on screen as a [`SpanKind::Separator`] span at the
//!   end of the segment it closes, drawn as itself and dimmed by the UI.
//! * The line break is [`Span::break_before`](super::Span::break_before) on
//!   the *following* span — metadata beside the text, not an edit to it. It
//!   is not asked for when the author's own newline is about to break the
//!   line anyway; see [`newline_already_ends_the_line`] for what asking twice
//!   costs.
//!
//! Nothing is trimmed either. `a; b` segments into `a`, `;`, ` b`: the space
//! that happens to follow the separator is part of the command and stays in
//! the rendering, leading position and all.
//!
//! # Quote awareness is honesty, not polish
//!
//! `echo 'a; b'` is one command with one argument. Splitting it at the `;`
//! would draw two apparent commands where the shell will run one, which is a
//! rendering that lies — and a lie in the direction of "looks more dangerous
//! than it is" is still a lie, because it teaches the reader that the
//! boundaries on screen are not the boundaries that run.
//!
//! So the scanner tracks quoting: separators are recognised only outside
//! quotes. It is not a shell parser and does not want to be. It answers one
//! question — *is this byte a command boundary?* — and **for the two
//! constructs it models, quoting and backslash escaping, it is wrong only in
//! the direction of finding no boundary.**
//!
//! That qualifier is load-bearing and an earlier draft of these docs left it
//! out, claiming flatly that the scanner never invents a boundary. It does.
//! The guarantee stops where the model stops, and the next section says
//! where that is in both directions — because a docs page that overstates
//! its own safety argument is the same failure as a display that overstates
//! what it shows.
//!
//! # Where the model stops, and what it costs
//!
//! Five separators — `;`, `&&`, `||`, `|`, a literal newline — plus quoting,
//! backslash escaping, comments, redirections, here-documents and command
//! substitution around them. The rest of shell grammar is outside the model,
//! and the cost falls in both directions.
//!
//! ## Under-segmentation: structure the shell has that the screen does not
//!
//! Backgrounding (`&`) and subshells (`(`, `)`) are not recognised.
//! `sleep 60 & wait` draws as one segment though the shell runs two, and
//! `(cd /tmp; rm -rf x)` splits at the `;` but says nothing about the
//! parentheses that nest it.
//!
//! Command substitution — `$(…)` and the older `` `…` `` — is recognised, and
//! is deliberately drawn as *no* boundary at this level. `echo $(a; b)` is
//! one segment: the `;` in it really is a separator, but it separates the two
//! commands inside the substitution, and a break drawn here would put them on
//! screen as two things this command line runs. The substitution is one word
//! of one command; what is inside it is read by a pass of its own, which is
//! where the `a` and the `b` in the roster come from. Before that pass
//! existed the `;` was split on anyway — drawn at the wrong nesting level
//! rather than fabricated — and this is the direction that was chosen when it
//! was fixed.
//!
//! ## Over-segmentation: boundaries on screen the shell does not have
//!
//! A separator character that some unmodelled construct gives another meaning
//! to is split on anyway. Each of these was checked against a real shell:
//!
//! * `[[ -n x || -n y ]]` — conditional OR.
//! * `$'a\'b; c'` — ANSI-C quoting, where `\'` does not end the string, so
//!   the `;` is data.
//! * `case x in a) echo 1;; esac` — `;;` is one `case` terminator, drawn as
//!   two separators.
//!
//! ## Why neither direction breaks an invariant
//!
//! Both hold throughout: every byte is on screen, drawn as itself, and
//! `unrender` still reproduces the command exactly. What is wrong in these
//! cases is the *layout*, and layout here is metadata — a reader who
//! distrusts a break can read straight through it and still see the command
//! that will run, which is the whole reason breaks are not characters.
//! Widening the model would move cases out of these two lists; it would not
//! change what either invariant guarantees.
//!
//! Both lists are pinned by tests — `structure_outside_the_five_separators_
//! is_left_unsegmented` and `over_segmentation_where_the_model_stops` — so a
//! change in either direction has to be a deliberate one.
//!
//! # Comments, and why they are a correctness fix before they are a colour
//!
//! A comment is the one part of a command that will not run, and until it had
//! a pass of its own every other pass read it as if it would.
//! `echo hi   # then && rm -rf /tmp` was drawn with a segment boundary at
//! that `&&` — a boundary the shell does not have — and this page listed the
//! case among the ones where segmentation over-reports. So recognising a
//! comment retires a claim hatch was making falsely; the colour falls out of
//! it.
//!
//! The rules are bash's, and they are written out on [`Scan`] with the cases
//! each of them decides. The short of it: a `#` begins a comment only at the
//! start of a word — at the start of the input or after an unquoted
//! metacharacter — never inside quotes, never after a backslash, and never in
//! `$#` or `${#var}`; and it runs to the end of the line, the newline
//! excluded. The shell in question is the non-interactive one, because
//! commands reach it as `bash -c '<command>'`, where comments are on.
//!
//! One [`Scan`] answers it, exactly as one [`Scan`] answers quoting, and for
//! the same reason: [`boundaries`], [`references`], [`quoted_strings`] and
//! [`comments`] all have to agree about the same byte. What the scanner
//! cannot see it is wrong about in the direction of finding *no* comment,
//! which is the direction that leaves today's behaviour rather than hiding
//! live text behind a quiet colour — see [`is_metacharacter`], which is
//! deliberately stricter than the whitespace rule the rest of this module
//! uses.
//!
//! A `#` inside a here-document body is not a comment, because a body is not
//! shell — see below, which is the pass that decides that, and which runs
//! before this one asks its question.
//!
//! # Redirections, which are structure and not a verdict
//!
//! A redirection is one of the few constructs that changes *where a command's
//! effects land*, and until it had a pass of its own the window drew
//! `> /etc/passwd` with exactly the emphasis it drew `-l` with. So the
//! operator and the word it points at are marked — see [`Redirect`] for why
//! both, and why both the same — and [`Scan`] carries the rules, which are
//! bash's and are written out there with the case each of them decides.
//! [`REDIRECTIONS`] is the set of operators and says which forms of the
//! manual's are deliberately not in it.
//!
//! It is a **lexical** claim and nothing more. `> /dev/null` and
//! `> /etc/passwd` are the same construct and get the same colour; which of
//! them should alarm a reader is a question about the path, and answering it
//! is [`super::danger`]'s job, which is still unwritten. Putting a judgement
//! here would mean two passes with an opinion about the same word and a
//! window that shouts at `/dev/null`.
//!
//! Recognising them is a correctness fix first, in the same way a comment
//! was, and this page is one entry shorter for it: `>|` is one redirection
//! operator, and segmentation used to split at the `|` in it. It cannot any
//! more, because [`boundaries`] reads the same flag [`regions`] does rather
//! than deciding for itself what an operator is — one `Scan`, one answer, the
//! argument [`Scan`] makes at length. Two smaller corrections come with it,
//! both in [`is_word_break`]: `cat<file` names `cat` as the word that runs
//! rather than `cat<file`, and `>out.txt cat` names `cat` rather than
//! `>out.txt`.
//!
//! One boundary moved the other way and is worth naming. `a >&& b` used to be
//! drawn with a segment boundary at the `&&`; the `>&` now claims the first of
//! those two characters, so there is none. Neither rendering is the shell's,
//! because bash refuses to parse the line at all — it is a syntax error near
//! the `&` — so what changed is which wrong layout is drawn over a command
//! that will never run.
//! `an_operator_that_eats_an_ampersand_pair_costs_a_boundary_bash_does_not_
//! have` pins it, so changing it again has to be deliberate.
//!
//! `<<EOF` is recognised as an operator and `EOF` as the word it points at,
//! and the line that ends the body is marked as the same word closing what the
//! operator opened. What is between them is the next section's.
//!
//! # Here-documents, which are the one region that is not shell
//!
//! A body is **data**. The shell hands it to the command on stdin and never
//! reads a word of it as a program, which makes it a stronger statement than
//! a comment: a comment is shell that does nothing, and a body is not shell.
//! Every pass on this page was reading one as if it were, and the day the
//! roster landed the cost stopped being quiet —
//!
//! ```text
//! cat <<'EOF' > /tmp/x
//! hello
//! EOF
//! ```
//!
//! — put an orange line under the panes saying *nothing on the command's PATH
//! answers to hello, EOF*, which is a warning drawn on one of the most
//! ordinary shapes an agent writes. A warning that fires there is a warning
//! nobody reads anywhere.
//!
//! So [`Scan`] knows where a body is, and carries the rules, which are bash's
//! and are written out there with the case each of them decides. Four passes
//! read the one flag: a `;` in a body is not a boundary, its first word is not
//! a command and is not in the roster, a `#` in it is not a comment, and a
//! `$HOME` in it resolves only when the delimiter was left unquoted — which is
//! the distinction that carries the most and is the easiest to flatten.
//! `<<'EOF'` expands **nothing** anywhere in the body, so a value drawn beside
//! one of its `$NAME`s is a lie in the window's most authoritative voice;
//! `<<EOF` expands as usual, so the same value is the truth the reader came
//! for.
//!
//! Two entries came off the lists above for it — a body containing `a; b` was
//! on the over-segmentation list, and a body under a quoted delimiter was on
//! the over-annotation one — which is the same shape the comment work and the
//! `>|` had: recognising a construct retires a claim hatch was making falsely
//! rather than documenting it better.
//!
//! ## The body has no colour, and that is the decision
//!
//! It has no [`SpanKind`] of its own. The window's vocabulary is five
//! meanings and a palette with no unspent hue left in it — red is danger,
//! orange a warning, green a comment, blue a quoted string, violet a
//! redirection — and a sixth would have to sit next to one of them. That is
//! the smaller half of the reason.
//!
//! The larger half is what a body *is*. It is often the whole point of the
//! command: the file `cat <<EOF > /etc/sudoers` is about to write is in the
//! body and nowhere else, so it is the last text on the pane that should be
//! drawn quietly. A comment's colour is quieter than body text because a
//! comment does not happen; a body happens harder than the command around it.
//! Drawn plain, at full contrast, it is the one region of the pane making no
//! claim at all — which is exactly the claim to make about data — and it is
//! bracketed top and bottom by the delimiter, in the colour that already means
//! *this is where the data goes*. That is how a reader finds the end of a body
//! in a shell script anyway.
//!
//! ## An unterminated body runs to the end of the command
//!
//! Because that is what bash does with it, checked against a real shell rather
//! than reasoned about: it warns that the here-document was delimited by
//! end-of-file, hands the command everything that was left, and runs none of
//! it. So in
//!
//! ```text
//! cat <<EOF
//! hello
//! rm -rf /
//! ```
//!
//! the `rm` is text that `cat` prints. Drawing it as shell would be the lie,
//! and it is the lie this whole section exists to stop telling.
//!
//! Choosing the other way would have cost more than it looks. The failure to
//! avoid is *hiding* shell, and nothing here hides anything: a body carries no
//! colour, no fade and no chip, so every character of an unterminated one is
//! on screen drawn as itself, at the same contrast as the line above it. What
//! the choice costs is that the roster does not name a program inside such a
//! body — and neither does the shell run one.
//!
//! # Command substitution, which is a command inside a command
//!
//! `$(…)` and its older spelling `` `…` `` hold shell, and the shell in them
//! is not the shell around them. That is the opposite of a here-document and
//! it is wrong in the opposite way: a body is text this module was reading as
//! a program, and a substitution's interior is a program this module was
//! reading as text — as part of the word it sits in, at the level it sits in.
//!
//! The cost was not silence. `x=$(podman ps -q)` put **`ps`** above the
//! panes as the thing the command runs, one word late: the space inside the
//! substitution was read as a word break, so `x=$(podman` looked like an
//! ordinary assignment and was skipped, and the first word after it landed in
//! command position. A roster whose whole job is answering *what does this
//! run* naming the wrong program is worse than one naming none, because a
//! reader who has been told the answer stops looking for it.
//!
//! So [`Scan`] carries the depth, [`Scanned::nesting`] says what reads it,
//! and the shape is the one the rest of this page already uses. At this level
//! a substitution is **one opaque word**: no boundary inside it, no word break
//! inside it, no comment, no redirection and no string of this level's.
//! [`substitutions`] then takes each interior and hands it to a fresh scan,
//! which finds the command in it, the strings in it and the redirections in
//! it at the level they belong to. `echo $(podman ps -q)` names `echo` and
//! `podman`, and `x=$(podman ps -q)` names `podman` and nothing else.
//!
//! Two decisions inside that are worth naming, because either could have gone
//! the other way.
//!
//! * **Both spellings, and only those two.** A backtick is the same construct
//!   in an older hand and an agent still writes one, so leaving it out would
//!   have left the identical wrong answer reachable by typing a different
//!   character. A `(` with no `$` in front of it is a **subshell**, which is
//!   not this and stays outside the model — see [`Scan::nest_at`].
//! * **`$((…))` is arithmetic, not a command.** It is not special-cased and
//!   it does not have to be: the level it opens holds `(1 + 2` rather than a
//!   command line, and a word carrying a parenthesis is declined by the pass
//!   that names what runs and by the pass that underlines it alike. So an
//!   arithmetic expansion contributes nothing, which is what it should, and
//!   one entry came off the over-segmentation list with it — the `||` of
//!   `echo $((1 || 0))` is no longer drawn as a separator.
//!
//! The one pass that deliberately reads *through* a substitution is
//! [`references`]: a `$HOME` inside one expands out of the same environment
//! with the same value, and a reader wants it either way. Expansion is not a
//! claim about command structure, which is what every other pass here is
//! asking about.
//!
//! # Command position, and the wrappers in front of it
//!
//! [`invoked`] answers the question the window puts above the panes: *what
//! does this run*. It is the same reading of the same text every pass here
//! makes -- the command word of a segment is the first word that is neither
//! an assignment nor a redirection, which is [`is_assignment`]'s answer and
//! [`is_word_break`]'s -- so the word the annotated pane underlines is the
//! word the list is built from. [`command_word`] and [`invoked`] ask one
//! [`words`] for that reason, and a test asserts the two agree.
//!
//! What it adds is that a command word is often not the last word worth
//! reading. `sudo foo` runs two programs and the honest answer names both,
//! and the same is true of `env`, `nice`, `timeout`, `xargs`, `run0` and the
//! rest of [`WRAPPERS`] -- including `bash -c`, which is the wrapper hatch
//! writes itself for every `root: true` request. Each of them has its own
//! argument grammar, and skipping the wrong number of arguments means naming
//! the wrong executable, which is worse than naming the wrapper: a reader who
//! has been told what a command runs stops looking for what it really runs.
//! So the grammars are whitelists and [`past`] gives up rather than guessing,
//! and what a reader gets then is the wrapper's name and a sentence saying
//! the command behind it was not read. Under-claiming is this module's safe
//! direction and this is the same move [`annotate_variables`] makes for a `$`
//! it cannot resolve.
//!
//! The trap on the other side is the shell's own vocabulary. `cd` resolves to
//! no file anywhere, and a list that reported it as missing would draw a
//! warning on the most ordinary command there is -- so [`is_builtin`] and
//! [`is_keyword`] are here, with the argument for each written out on the
//! tables themselves. Where the two lists are the point is the six names that
//! are a builtin *and* a binary: `bash -c` runs the builtin, so hatch reports
//! the builtin.
//!
//! Resolution -- which file a name reaches, and who else may write it -- is
//! deliberately not here. It touches the filesystem, and this module is a
//! pure reading of text; see [`super::roster`], which is the other half.
//!
//! # Variables: the window resolves against the environment that will run
//!
//! [`annotate_variables`] tags each `$NAME` and hangs on it the value the
//! child will actually see. The environment is a parameter and there is no
//! default, because hatch **constructs** the child environment rather than
//! inheriting one and none of the environments lying around is it. The
//! daemon's came from wherever the daemon was started; the sandbox's is
//! agent-influenced; and `run0` resets the environment for a `root: true`
//! operation regardless. A `$HOME` resolved against `std::env` would print a
//! value that looks authoritative and is wrong — the worst failure available
//! to a display whose whole job is to be believed, and worse than printing
//! nothing, because nothing does not invite the reader to stop reading.
//!
//! Quoting decides *whether* to annotate, for the same reason it decides
//! where to split. `$HOME` expands in `Normal` and inside `"…"`; inside `'…'`
//! it is five characters of text and after a backslash it is a literal `$`.
//! Annotating those would announce a substitution that does not happen, which
//! is the mirror of splitting `echo 'a; b'` in two. Both questions are asked
//! of one `Scan`, so the two answers cannot disagree about the same byte.
//!
//! ## What `$` is claimed to mean
//!
//! Exactly `$NAME` and `${NAME}`, with `NAME` matching
//! `[A-Za-z_][A-Za-z0-9_]*`. [`super::variable_name`] is the definition, and
//! it lives in the span model rather than here so that the check the model
//! makes is not borrowed from the pass it is checking.
//!
//! Everything else stays `Plain`. Positional and special parameters (`$1`,
//! `$@`, `$?`, `$$`, `$*`, `$#`), brace expansions with a modifier
//! (`${HOME:-/tmp}`, `${#HOME}`), command and arithmetic substitution
//! (`$(id)`, `$((1+1))`) and an unterminated `${HOME` all substitute
//! something the child environment does not contain, so there is no value
//! this window could put beside them that would be true. Under-tagging costs
//! the reader a hint; a wrong value costs them the reason to read at all.
//!
//! Names the shell maintains itself — `$PWD`, `$IFS`, `$RANDOM`, `$SHLVL`,
//! the `BASH*` family — are declined for the same reason, and it is worth
//! stating separately because they *do* fit the grammar. `build_child_env`
//! has no entry for `PWD`, so tagging it would draw *unset* over an argument
//! the shell is about to fill in: `rm -rf $PWD/build` read as `/build` when
//! it is `/tmp/build`. [`super::variable_name`] holds that list, so the
//! refusal is the model's and not this pass's.
//!
//! Declining is not the same as ignoring: `dollar_extent` steps over the
//! whole of what it declines, so a rejected construct cannot be re-read as an
//! accepted one. `$$HOME` is the case — the shell reads `$$` and then the
//! literal `HOME`, and a pass that resumed one byte later would find `$HOME`
//! and announce an expansion that never happens.
//!
//! ## Over-annotation: the same gaps the segmenter has
//!
//! Annotation asks the same scanner the same question, so it inherits the
//! same model gaps, in the same direction. Where an unmodelled construct
//! makes a `$` inert, it is annotated anyway. Each was checked against a real
//! shell:
//!
//! * `$'a\'$HOME'` — ANSI-C quoting, where `\'` does not close the string, so
//!   the whole of `a'$HOME` is literal.
//!
//! The cost is bounded the same way, and more tightly than for segmentation:
//! the text is still on screen drawn as itself, and what is wrong is a label
//! and a value shown beside a `$` that will not expand. A reader who
//! distrusts the annotation can read straight through it. `over_annotation_
//! where_the_model_stops` pins the list, so a change here has to be a
//! deliberate one.
//!
//! # Highlighting: the same scanner again, and why not `syntect`
//!
//! [`highlight`] is the last pass. It marks the word that names what runs,
//! the quoted strings, the comments and the redirections — a here-document's
//! delimiter being one of the last, at both of the places it appears — so the
//! annotated pane shows *structure* rather than being the raw pane with line
//! breaks in it.
//!
//! The spec called for `syntect` with the bash grammar and this does not use
//! it, for three reasons in descending order of weight:
//!
//! 1. **Two models of quoting can disagree about the same byte.** [`Scan`]
//!    already decides where a string starts and ends, and both other passes
//!    ask it: that is why `echo 'a; b'` is one segment and `'$HOME'` is not
//!    annotated. A second grammar answering the same question is exactly the
//!    "second hand-rolled quote tracker" [`Scan`]'s own docs warn about, and
//!    the disagreement would be visible — a string drawn as quoted across a
//!    `;` that the segmenter split on.
//! 2. **The unit is wrong.** `syntect` highlights a line into styled ranges;
//!    this crate needs kinds attached to spans that already exist and that
//!    were cut by other passes. Every chip, separator and `$NAME` is already
//!    a span boundary, so its output would have to be intersected with them
//!    anyway — which is the whole of the work below.
//! 3. **It brings a palette.** A `syntect` theme assigns colours, and the
//!    colours in this window already mean things: red is danger, the chip's
//!    orange is hatch substituting for a character, italic grey is hatch's
//!    own note. A theme that spent red on a keyword would make the meaningful
//!    ones ordinary.
//!
//! What it costs is scope, and the scope is deliberately small: the first
//! word, the quoted strings, the comments and the redirections, and nothing
//! else. There is no keyword list, no builtin table and no flag rule, because
//! each one is another colour, and a pane where eight things are coloured is
//! a pane where the ones that matter are not. The last two earn their place
//! on different grounds from the first two, and on the same grounds as each
//! other: neither is a hint about what the line means. A comment is the one
//! region of the line that will *not* happen, and a redirection is where what
//! does happen will land — and in both cases the pass that finds it is the
//! pass that stops segmentation lying about the same bytes.
//!
//! **Highlighting is decoration and is never load-bearing.** Every span it
//! marks is still drawn as its own text — nothing is replaced and nothing is
//! hidden — so a reader who ignores colour entirely reads the same characters
//! in the same order. A comment is the one span drawn at less than full
//! contrast, and it is the one span that will not run; it is held at the same
//! legibility floor as the rest of the vocabulary, so quieter is a shade and
//! not a disappearance. See [`crate::prompt_ui::theme`] for the two ratios.
//! The raw pane beside it carries no highlighting at all and remains the
//! thing the approval covers. And the model gaps above are inherited unchanged: where the
//! scanner is wrong about a quote, the highlight is wrong in the same
//! direction, and `highlighting_where_the_model_stops` pins those cases.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Range;

use super::{SpanBuilder, SpanKind, Spans, unicode, variable_name};

/// The separator tokens, longest first.
///
/// The order is the whole of the longest-match rule: the scanner takes the
/// first entry that matches at the cursor, so anything that starts with a
/// shorter token has to come before it — `||` before `|`. Descending length
/// gives that for every such pair, and `separator_table_is_longest_first`
/// holds the table to it. Read the other way round, a shortest-first table
/// would report `||` as two pipes and double the boundaries on screen.
///
/// A bare `&` is deliberately absent — see the module docs — which is why the
/// prefix relationship matters at all: `&&&` matches `&&` and then leaves a
/// plain `&`.
const SEPARATORS: &[&str] = &["&&", "||", ";", "|"];

/// The redirection operators, longest first.
///
/// The order is the same longest-match rule [`SEPARATORS`] is written to, and
/// it matters more here because the table is full of prefixes: `>` starts
/// `>>`, `>|` and `>&`, `<` starts all four of its own, and `&>` starts
/// `&>>`. A shortest-first table would read `2>>log` as `2>` followed by an
/// argument called `>log`. `redirection_table_is_longest_first` holds it.
///
/// The set is bash's, read off its manual's REDIRECTION section rather than
/// off memory. Every form it lists that is one token is here: `<` and `>`,
/// `>>` and `<<`, the here-string `<<<` and the tab-stripping here-document
/// `<<-`, the read-write `<>`, the `noclobber` override `>|`, the descriptor
/// duplications `>&` and `<&`, and `&>` and `&>>`, which are the two spellings
/// that take stdout and stderr together.
///
/// Two forms the manual lists are deliberately absent. `{varname}>` — the
/// shell allocating a descriptor into a variable — needs a brace-word the
/// scanner has no other reason to model, and it is rare enough that missing
/// it costs a highlight on a line hatch still draws correctly. `<<` and `<<-`
/// are here and are the two that do not end with their own token: what follows
/// them is a delimiter and then, after the next newline, a body. [`Scan`]
/// carries those rules and the module docs say why a body has to have a pass
/// of its own.
const REDIRECTIONS: &[&str] =
    &["&>>", "<<<", "<<-", "&>", ">>", "<<", "<>", ">|", ">&", "<&", ">", "<"];

/// Which half of a redirection a character belongs to.
///
/// Two halves and one meaning. `> /etc/passwd` says *the effects of this
/// command land there*, and the arrow alone does not say it: in
/// `echo x > /etc/passwd` the word a reader is scanning for is the path. So
/// both halves are marked, and both are marked the *same*, because they are
/// one fact and a second colour would be a second thing to learn for no
/// second meaning. This distinction exists so that the two can be found
/// separately — the blank between them belongs to neither, and a target the
/// highlighter declines still leaves its operator marked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Redirect {
    /// The operator, with the file descriptor in front of it if it has one:
    /// `>`, `2>>`, `&>`, `>|`, `1>&`.
    Operator,
    /// The word the operator points at: the file it opens, the descriptor
    /// `>&` duplicates, or the delimiter a here-document ends on.
    ///
    /// A here-document's delimiter is the one word that appears twice -- once
    /// after the operator and once on the line that ends the body -- and both
    /// are drawn in this kind. The second one is not found here, because it is
    /// not on this line and not in this state machine: see [`Here::Delimiter`]
    /// and [`delimiter_lines`].
    Target,
}

/// Where the scanner is in a redirection, between one character and the next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Redirecting {
    /// Not in one.
    No,
    /// Inside an operator, which ends at this byte offset.
    Operator { end: usize },
    /// The operator has ended and its word has not started: the blanks bash
    /// allows between them, so that `> out` and `>out` are the same
    /// redirection.
    Blanks,
    /// Inside the word the operator points at.
    Target,
}

/// Which part of a here-document a character belongs to.
///
/// The two are told apart because they are wrong in different ways when they
/// are confused. A body is **data** -- the shell hands it to the command on
/// stdin and never reads a word of it as shell -- and whether a `$NAME` in it
/// expands depends on how the delimiter was written. The line that ends one
/// is **structure**: it is not data, the command never sees it, and it is not
/// a command either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Here {
    /// Inside a body. `expands` is false when the delimiter was quoted, which
    /// is bash's switch for the whole body at once: `<<'EOF'`, `<<"EOF"` and
    /// `<<\EOF` substitute nothing anywhere in it, and a bare `<<EOF` expands
    /// parameters, commands and arithmetic as usual.
    Body { expands: bool },
    /// The line that ends a body: exactly the delimiter, leading tabs aside
    /// for a `<<-`.
    Delimiter,
}

/// A here-document whose operator has been read, waiting for its body.
///
/// Everything the scanner has to remember about one, and it is remembered
/// because the operator and the body are not in the same place: `cat <<EOF`
/// says what the body will be delimited by, and the body itself starts after
/// the newline that ends that line.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HereDoc {
    /// The word the body ends on, quoting removed: `<<'EOF'` ends on `EOF`.
    delimiter: String,
    /// `<<-` rather than `<<`: leading **tabs** are stripped from the body's
    /// lines and from the line that terminates it, so an indented `EOF` still
    /// ends it. Spaces are not stripped and an `EOF` indented with them does
    /// not terminate anything, which was checked against a real shell.
    strip_tabs: bool,
    /// Whether the body expands -- see [`Here::Body`].
    expands: bool,
}

/// A here-document operator whose delimiter word is still being read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Opening {
    /// Whether the operator was `<<-`.
    strip_tabs: bool,
    /// Where the delimiter word starts, once one has begun. `None` while the
    /// scanner is still in the operator or the blanks after it, and an
    /// operator that never gets a word opens nothing.
    word: Option<usize>,
}

/// Where the scanner found one segment to end.
#[derive(Debug, PartialEq, Eq)]
enum Boundary {
    /// `;`, `&&`, `||` or `|` occupying this byte range. A token of its own:
    /// it is tagged [`SpanKind::Separator`] and kept on screen at the end of
    /// the segment it closes.
    Separator(Range<usize>),

    /// A literal newline ending at this byte offset. A boundary, but
    /// deliberately **not** a `Separator` span.
    ///
    /// Only a chip may be drawn as something other than itself, so a
    /// `Separator`-kinded U+000A would be drawn as a literal newline — and
    /// then a break on screen would no longer tell the reader whether it is
    /// layout or content, which is the exact ambiguity the whole design of
    /// `break_before` exists to avoid. Worse, the property tests would not
    /// notice: a non-chip span drawn as its own text satisfies invariant 1b
    /// by definition.
    ///
    /// So the newline is left to `unicode::classify_into`, which chips it as
    /// `[LF]` at the end of its segment and asks the span after it to start a
    /// line. The character is visible, the layout is metadata, and the two
    /// readings stay apart.
    ///
    /// This boundary is therefore no longer the only thing asking for that
    /// break, and is kept anyway: segmentation's own reason for it is that a
    /// newline *ends a segment*, which is a claim about command structure and
    /// not about text layout. The two coincide today. Dropping this arm
    /// because the classifier happens to agree would make the segmenter's
    /// notion of a segment depend on how the classifier draws a character.
    Newline(usize),

    /// A literal newline ending at this byte offset with a here-document's
    /// data after it: a line ending, and **not** the end of a segment.
    ///
    /// The two are different claims and this is the one case where they come
    /// apart. `cat <<EOF` and the body under it are one command -- the shell
    /// reads the body as that command's stdin, not as the next thing to run
    /// -- so a segment that stopped at the first of those newlines would draw
    /// a boundary the shell does not have, and one that stopped at each of
    /// them would draw one per line of a config file. The line still ends,
    /// because a newline is a newline: [`super::unicode::classify_into`]
    /// chips it and asks for the break, exactly as it does inside a
    /// multi-line quoted string, which has never been a segment boundary
    /// either.
    ///
    /// Every newline from the one that opens a body through the one that ends
    /// the last delimiter line of the command is one of these, and the rule is
    /// a single look ahead: a newline is a `HereLine` when the character after
    /// it is inside a here-document. The newline *after* the last delimiter
    /// line has ordinary shell after it and is an ordinary [`Boundary::Newline`],
    /// which is what gives the command on the next line a segment of its own.
    HereLine(usize),
}

/// What the scanner is inside of. Separators are recognised only in
/// [`Quoting::Normal`]; variable references, in `Normal` and `Double`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Quoting {
    Normal,
    /// Inside `'…'`, where nothing at all is special — not even a backslash.
    /// `'a\'` is a complete string, so honouring the escape here would leave
    /// the scanner believing a quote is still open and miss every boundary
    /// after it.
    Single,
    /// Inside `"…"`.
    Double,
}

/// Which spelling of command substitution opened a level of nesting, and so
/// which character closes it.
///
/// One construct, two spellings, and the difference is whether they nest.
/// `$(…)` does — the `)` that closes one level leaves the level above it open
/// — and `` `…` `` does not, because the character that would open a second
/// one is the character that closes the first. Keeping the spelling on the
/// stack is what lets a `)` inside a `` `…` `` and a backtick inside a `$(…)`
/// each be read as the ordinary character it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Nest {
    /// `$(` … `)`.
    Paren,
    /// `` ` `` … `` ` ``.
    Backtick,
}

impl Nest {
    /// The character that ends this spelling.
    fn closer(self) -> char {
        match self {
            Nest::Paren => ')',
            Nest::Backtick => '`',
        }
    }
}

/// One command substitution the scan is inside.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Nested {
    /// Which spelling opened it, and so what closes it.
    kind: Nest,
    /// The quoting the substitution opened in, which is the quoting its
    /// closing character has to be read in.
    ///
    /// Not `Normal`, because a substitution is perfectly ordinary inside a
    /// double-quoted string: the `)` of `"$(ls)"` is in `Double` and closes
    /// what the `$(` opened. Recorded rather than assumed, so that the `)` of
    /// `$(ls 'a)b')` — which is in `Single` where its `$(` was in `Normal` —
    /// closes nothing, which is what bash does with it.
    quoting: Quoting,
}

/// One character of the command, together with the shell state it sits in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scanned {
    /// Byte offset of `ch` in the command.
    offset: usize,
    ch: char,
    /// The quoting in force *at* this character — what the characters before
    /// it left behind, before this one is applied. So the `'` that opens a
    /// string is reported as `Normal` and the one that closes it as `Single`,
    /// which is what a caller asking "is this byte special?" wants.
    quoting: Quoting,
    /// True when the preceding character was a live backslash, so this one is
    /// literal: it neither changes `quoting` nor begins a token.
    escaped: bool,
    /// True when this character is inside a comment, the `#` that opens one
    /// included -- see [`Scan`] for the rules and for why the `#` is reported
    /// as being inside the thing it starts, where an opening quote is
    /// reported as being outside it.
    ///
    /// Nothing inside a comment is anything else: not a separator, not a
    /// quote, not a reference, not a word. Every pass below asks this first.
    comment: bool,
    /// Which half of a redirection this character is part of, if any -- see
    /// [`Scan`] for the rules and [`Redirect`] for why both halves are
    /// marked.
    ///
    /// A second lexical fact threaded through the same pass as `comment`, and
    /// for the same reason: [`boundaries`] has to know that the `|` of a `>|`
    /// is not a pipe, [`is_word_break`] has to know that the `<` of
    /// `cat<file` ends the word `cat`, and [`regions`] has to know where to
    /// put a colour. Three passes reading one flag cannot disagree; three
    /// passes each finding redirections for themselves can.
    redirect: Option<Redirect>,
    /// Which part of a here-document this character is in, if any -- see
    /// [`Scan`] for the rules and [`Here`] for what the two parts are.
    ///
    /// The third lexical fact threaded through this pass, and the one that
    /// costs the most to get wrong: a body is not shell at all, so every
    /// other pass here was reading a config file as a program. A `;` in it is
    /// not a boundary, its first word is not a command, a `#` in it is not a
    /// comment, and whether a `$HOME` in it resolves is decided by how the
    /// delimiter was quoted rather than by the `$`.
    here: Option<Here>,
    /// How many command substitutions deep this character is: `0` outside
    /// every one, `1` for the `podman ps` of `echo $(podman ps)`, and higher
    /// where one holds another.
    ///
    /// The fourth lexical fact threaded through this pass, and the one that
    /// decides *whose* the other three are. A substitution is a command
    /// inside a command: the text between its delimiters is shell, but it is
    /// not this level's shell, and every pass below reads it at the wrong
    /// level. The `;` of `$(a; b)` is a boundary of the nested command and
    /// not of the one on screen; the space in `x=$(podman ps)` is not a word
    /// break, because the whole substitution is one word of the assignment;
    /// and the `>` of `$(ls > f)` redirects the nested command.
    ///
    /// So a character with a non-zero `nesting` belongs to [`substitutions`],
    /// which hands the interior to a fresh scan of its own, and the passes at
    /// this level step over it. That is how the roster came to say `ps` for
    /// `x=$(podman ps -q)`: the space inside the substitution broke the word,
    /// `x=$(podman` looked like an assignment and was skipped, and the next
    /// word along — a word that only existed because the scanner had split
    /// one — landed in command position.
    ///
    /// The delimiters themselves are reported *outside* what they delimit,
    /// the way an opening quote is: the `$`, the `(` and the `)` of a `$(…)`
    /// all carry the depth around it, so a run of characters at a depth is
    /// exactly one substitution's interior.
    nesting: usize,
    /// True for both characters of a `\`+newline line continuation.
    ///
    /// The shell removes the pair before it reads a word, so the two
    /// characters are neither a word break nor part of a word:
    /// `ec\`+newline+`ho` is the single word `echo`, and a `\`+newline
    /// standing between two blanks is no word at all. Without this the
    /// newline was a character like any other and `cd /tmp && \`+newline+`
    /// podman ps` reported a program named `"\n"`.
    ///
    /// A flag rather than a rule each pass applies for itself, because the
    /// rule was already here once: [`Scan::next`] has to know that a
    /// continued line has not ended before it can decide where a
    /// here-document's body begins, and it asked `escaped` about the newline
    /// to find out. Both now ask this, so the two passes cannot come to
    /// disagree about which newlines end a line.
    continuation: bool,
}

/// True for one of bash's metacharacters: a character that, unquoted,
/// separates words -- so the character after it begins a new one.
///
/// `| & ; ( ) < >`, space, tab and newline, which is the manual's list. It is
/// here for one question only: whether a `#` is at the start of a word, which
/// is the whole of what makes it a comment. It is not segmentation. `(`, `)`,
/// `<` and `>` are outside the five separators and stay outside them;
/// recognising them here says nothing about where a command begins or ends,
/// only about where a word does.
///
/// Whitespace is the three ASCII characters the shell names and not
/// [`char::is_whitespace`], which is Unicode-aware and would make a
/// non-breaking space a word break. The looser predicate is what
/// [`is_word_break`] uses, where being wrong costs a highlight; being wrong
/// here would cost a *comment*, and a comment invented over text that is
/// going to run is the one error in this module that hides something from a
/// reader rather than merely mislabelling it. So this is the conservative
/// list, and where it is wrong it is wrong in the direction of finding no
/// comment at all.
fn is_metacharacter(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '|' | '&' | ';' | '(' | ')' | '<' | '>')
}

/// One left-to-right pass over the command, tracking quoting, one
/// backslash-escape flag and whether it is inside a comment. No backtracking,
/// no nesting, no recursion: the input is agent-controlled and this runs
/// before a human is asked to approve anything, so it is bounded by the
/// length of the string and nothing else.
///
/// This is shared state, not a shared convenience. Four passes ask questions
/// of the same state machine — [`boundaries`] asks *is this byte a command
/// separator?*, [`references`] asks *does this `$` expand?*, [`comments`]
/// asks *does this run?* and [`quoted_strings`] asks *where does this string
/// end?* — and the answers have to come from one model or they can disagree
/// with each other about the same character. `'a; $HOME'` is the case that
/// shows why: both of the first two questions must answer no, for the same
/// reason, and a second hand-rolled quote tracker is exactly how one of them
/// comes to answer yes. A comment is the same argument again, one level up:
/// it was the pass that nobody had written, so every other pass answered
/// `echo hi # then && rm -rf /tmp` as if the `&&` were a boundary.
///
/// # Where a comment begins
///
/// These are bash's rules, read off its manual and checked against a real
/// shell. Commands reach hatch's shell as `bash -c '<command>'`, which is
/// **non-interactive**, and comments are enabled there. (Interactive bash
/// without `interactive_comments` is the case where they are not, and it is
/// not the case here.)
///
/// * A `#` begins a comment only at the **start of a word**: at the start of
///   the input, or after an unquoted metacharacter — whitespace, `|`, `&`,
///   `;`, `(`, `)`, `<`, `>`. So `echo a#b`, `curl http://x/#frag` and
///   `echo 'q'#b` contain no comment, and `echo a;#b`, `echo a|#b` and
///   `echo x >#f` all do. [`is_metacharacter`] is that rule.
/// * It is not a comment inside quotes. `'…'` and `"…"` both hold it, and so
///   does `$'…'` — which this scanner reads as an ordinary `'…'`, and which
///   for this question is the same answer.
/// * `${#var}` and `$#` are not comments: the `#` follows a `{` or a `$`, and
///   neither is a metacharacter.
/// * An escaped `#` is not a comment: `echo \#b` prints `#b`.
/// * A comment runs to the end of the line. The newline is **not** part of
///   it, and still ends the segment it ends.
///
/// None of it happens inside a here-document body, where a `#` is a character
/// in a config file and not a comment. That is the same rule again rather than
/// a second one: the body flag is settled before the `#` is looked at, and
/// nothing inside a body is anything else.
///
/// # Where a redirection begins and ends
///
/// These are bash's rules too, read off the REDIRECTION section of its manual
/// and checked against a real shell. [`REDIRECTIONS`] is the set of operators
/// and says which forms are deliberately not in it; what is left is where one
/// starts, how far it reaches, and the word it points at.
///
/// * An operator may be preceded by a **file descriptor**: a run of ASCII
///   digits, immediately in front of the operator with no space, and making
///   up the whole of the token so far. So `2>log`, `2>>log`, `1>&2` and
///   `2>&1` are redirections whose operator includes its number, and
///   `echo a2>log` is not: the token there is `a2`, which is not a number, so
///   the `>` starts a fresh token and `a2` is an argument. That is exactly
///   what bash does with it.
/// * `&>` and `&>>` take no descriptor, because the `&` is part of the
///   operator rather than a number. `2&>x` is the word `2` followed by an
///   `&>`, which is again what bash reads.
/// * The **target** is the word after the operator, with the blanks bash
///   allows in between skipped, so `> out` and `>out` are one redirection
///   either way. It ends where a word ends: at unquoted whitespace or at an
///   unquoted metacharacter, so `>out;ls` points at `out` and `>a>b` is two
///   redirections rather than one pointing at `a>b`. A quoted word is one
///   word -- `> "my file"` points at all of `"my file"` -- because a quoted
///   space is not a word break.
/// * `>&` and `<&` point at a descriptor or a word, and nothing here tells
///   them apart: `2>&1`, `>&2`, `>&-` and `>& out` all get a target, because
///   which it is depends on what the word expands to and this scanner does
///   not expand anything.
/// * None of it is a redirection inside quotes, after a backslash, or inside
///   a comment. That is the same rule a comment is found by, asked of the
///   same state, rather than a second one written out again. A comment also
///   *ends* a redirection that was waiting for its word: `echo z >#f` has no
///   target, and bash agrees -- it is a syntax error there.
///
/// Where the scanner cannot see, it is wrong in the direction of finding no
/// redirection, which leaves the text drawn exactly as it was drawn before
/// this pass existed.
///
/// # Where a here-document's body begins and ends
///
/// bash's rules again, read off the manual's HERE DOCUMENTS section and
/// checked against a real shell. This is the one construct where the text a
/// pass is looking at is **not shell at all**, so it is a correctness rule
/// before it is anything else.
///
/// * `<<WORD` opens one. The body does not start at the operator: it starts
///   after the **next newline**, which is the end of the line the operator is
///   on. `cat <<EOF | grep x` really does pipe into `grep`, and everything on
///   that line is read as the shell reads it.
/// * The body runs to a line that is **exactly** the delimiter and nothing
///   else. Trailing whitespace on that line means it is not the delimiter, and
///   bash agrees.
/// * `<<-WORD` strips leading **tabs** -- not spaces -- from the body's lines
///   and from the terminating line, so an `EOF` indented with tabs ends the
///   body and one indented with spaces does not.
/// * Quoting the delimiter turns expansion off for the whole body. All three
///   spellings do it -- `<<'EOF'`, `<<"EOF"`, `<<\EOF` -- and so does quoting
///   part of it (`<<EO'F'`), because the rule is about the word and not about
///   where the quotes are. The delimiter itself is the word with quoting
///   removed. An unquoted `<<EOF` expands parameters, commands and arithmetic
///   in the body as usual, so a `$HOME` there is real and is annotated.
/// * **Several can open on one line.** `cat <<A <<B` takes body A and then
///   body B, in the order the operators appear, both after that same newline;
///   the line that ends A is followed immediately by the first line of B.
/// * The terminating line is structure: not data, not a command, and not a
///   word of one.
/// * An **unterminated** here-document -- the command ends before the
///   delimiter line arrives -- runs to the end of the command, because that is
///   what bash does with it: it warns, hands the command everything it got,
///   and never runs a word of it. Reading the tail as shell would be the lie
///   there, and this is the one direction that can be checked against the
///   shell rather than argued about.
/// * `<<<` is a here-**string** and is not any of this. Its word is on the
///   same line and [`REDIRECTIONS`] already handles it as the ordinary
///   redirection it is.
///
/// Where the scanner cannot see, it is wrong in the direction of finding no
/// here-document -- `cat <<` with no word after it opens nothing -- and that
/// direction is the one that leaves text drawn as shell. It is the safe
/// direction here for the same reason it is everywhere else in this module,
/// and it is worth saying that it points the *opposite* way from a comment's:
/// a comment invented over live text hides it, while a body invented over
/// live text would only stop hatch reporting what the line runs. Neither
/// hides a character: a body carries no colour of its own, so the text of one
/// is drawn exactly as any other argument is.
///
/// # Backslash inside double quotes
///
/// Real `sh` escapes only `$`, `` ` ``, `"`, `\` and newline inside double
/// quotes; before anything else the backslash is literal. This scanner
/// applies the unrestricted rule instead, and the two are indistinguishable
/// for the questions asked of it. The rules differ only on a character that
/// is none of those, and such a character can neither change the quoting
/// state, nor be a separator — separators are recognised in `Normal` only —
/// nor be a `$`. What would matter is getting `\"` wrong: reading it as a
/// closing quote would drop the scanner into `Normal` in the middle of a
/// string and let it invent a boundary out of a `;` that is really an
/// argument.
struct Scan<'a> {
    command: &'a str,
    cursor: usize,
    quoting: Quoting,
    escaped: bool,
    comment: bool,
    /// Whether the next character would be the first of a word. True at the
    /// start of the input and after every unquoted metacharacter; see
    /// [`is_metacharacter`], which is the whole of the rule.
    word_start: bool,
    /// Where the scan is in a redirection, if it is in one.
    redirecting: Redirecting,
    /// The here-document operator whose delimiter word is being read, if the
    /// scan is in one.
    opening: Option<Opening>,
    /// The here-documents opened on this line whose bodies have not started
    /// yet, in the order their operators appeared. `cat <<A <<B` queues two
    /// and the next newline starts the first of them.
    ///
    /// A queue rather than a `Vec`, because both ends are used and the command
    /// is the agent's: `cat <<A` twenty thousand times over is a line an agent
    /// can write, and taking the front of a vector that long once per body
    /// would be quadratic in a number it chose.
    pending: VecDeque<HereDoc>,
    /// Which part of a here-document the character at the cursor is in.
    here: Option<Here>,
    /// The here-document `here` belongs to, kept because every line of a body
    /// has to be compared against the same delimiter.
    active: Option<HereDoc>,
    /// The command substitutions the cursor is inside, innermost last.
    ///
    /// A stack, which is the one place this pass keeps more than a fixed
    /// amount of state per character, and it is bounded by the command: a
    /// `$(` can only push a level by spending two bytes on it. Nothing here
    /// backtracks or rescans, so the walk is still one pass over an
    /// agent-controlled string. What the depth *costs* is capped elsewhere —
    /// [`SCRIPT_DEPTH`] is how far the passes that read an interior will
    /// follow one down.
    nesting: Vec<Nested>,
    /// Set by a `$` whose next character is a `(`, so that the `(` after it
    /// opens a substitution and a `(` anywhere else opens nothing. A subshell
    /// is not a substitution and this pass still says nothing about one.
    opening_nest: bool,
}

fn scan(command: &str) -> Scan<'_> {
    Scan {
        command,
        cursor: 0,
        quoting: Quoting::Normal,
        escaped: false,
        comment: false,
        // The very first character of the command is the first character of
        // a word, so `#ls` is a comment and the whole command is inert.
        word_start: true,
        redirecting: Redirecting::No,
        opening: None,
        pending: VecDeque::new(),
        here: None,
        active: None,
        nesting: Vec::new(),
        opening_nest: false,
    }
}

impl Iterator for Scan<'_> {
    type Item = Scanned;

    fn next(&mut self) -> Option<Scanned> {
        let ch = self.command[self.cursor..].chars().next()?;

        // A here-document's data is not shell, so the state machine stops for
        // the whole of it, exactly as it stops for a comment and for the same
        // reason: a quote in a config file opens nothing, a backslash escapes
        // nothing, and a `<<` in one starts no second here-document. The
        // quoting the scanner was in when the body began is the quoting it is
        // still in when the body ends, and that is always `Normal`, because a
        // body is only opened at a newline the scanner reads as a newline.
        if let Some(here) = self.here {
            let current = Scanned {
                offset: self.cursor,
                ch,
                quoting: self.quoting,
                escaped: false,
                comment: false,
                redirect: None,
                here: Some(here),
                // A body is data, so nothing in one opens a substitution and
                // nothing in one continues a line: both are claims about
                // shell, and the shell is not reading this.
                nesting: 0,
                continuation: false,
            };
            self.cursor += ch.len_utf8();
            if ch == '\n' {
                self.cross_line();
                // Whatever follows a here-document begins a word, so a `#` or
                // a `2>` on the line after the delimiter is read as one.
                self.word_start = true;
            }
            return Some(current);
        }

        // Both edges of a comment are crossed before the character is
        // reported, so each of them belongs to the state it creates: the `#`
        // is the first character of the comment, and the newline is the first
        // character that is not. A quote is reported the other way round --
        // see `Scanned::quoting` -- because a quote is a delimiter a caller
        // has to be able to recognise, and the `#` is not: everything from it
        // to the end of the line is the same inert run, the `#` included.
        if self.comment {
            if ch == '\n' {
                self.comment = false;
            }
        } else if ch == '#'
            && !self.escaped
            && self.quoting == Quoting::Normal
            && self.word_start
        {
            self.comment = true;
        }

        // Nesting before the redirection, because a redirection inside a
        // substitution is the nested command's and not this one's. The
        // comment flag is already settled and the quoting has not been
        // advanced past this character, so both of these read the shell state
        // *at* it -- the same reading every pass below gets.
        let nesting = self.nest_at(ch);
        let redirect = match nesting {
            0 => self.redirect_at(ch),
            // A `>` in `echo $(ls > f)` redirects `ls`, and the scan of the
            // interior is where that is found. Whatever was waiting for a
            // word at this level does not get one out of a substitution, so
            // the state is dropped exactly as a comment drops it.
            _ => {
                self.redirecting = Redirecting::No;
                self.opening = None;
                None
            }
        };
        let continuation = self.continuation_at(ch);

        let current = Scanned {
            offset: self.cursor,
            ch,
            quoting: self.quoting,
            escaped: self.escaped,
            comment: self.comment,
            redirect,
            here: None,
            nesting,
            continuation,
        };

        match (current.comment, self.escaped) {
            // A comment is not shell. A quote in one opens nothing and a
            // backslash in one escapes nothing, so the state machine simply
            // stops for the rest of the line: the quoting the scanner was in
            // when the `#` arrived is the quoting it is still in when the
            // newline ends it, which is always `Normal`, because a `#` inside
            // quotes is not a comment in the first place.
            (true, _) => {}
            (false, true) => self.escaped = false,
            (false, false) => match self.quoting {
                Quoting::Single => {
                    if ch == '\'' {
                        self.quoting = Quoting::Normal;
                    }
                }
                Quoting::Double => match ch {
                    '\\' => self.escaped = true,
                    '"' => self.quoting = Quoting::Normal,
                    _ => {}
                },
                Quoting::Normal => match ch {
                    '\\' => self.escaped = true,
                    '\'' => self.quoting = Quoting::Single,
                    '"' => self.quoting = Quoting::Double,
                    _ => {}
                },
            },
        }

        // What the *next* character would be the start of. A metacharacter
        // that is quoted, escaped or inside a comment is just a character and
        // ends no word.
        self.word_start = !current.comment
            && !current.escaped
            && current.quoting == Quoting::Normal
            && is_metacharacter(ch);

        // `len_utf8` on the character the cursor is actually at, so the cursor
        // never lands inside one and no offset this yields can split a
        // codepoint.
        self.cursor += ch.len_utf8();

        // The body of a here-document starts after the newline that ends the
        // line its operator is on, and this is that newline. It has to be a
        // newline the shell reads as one: a `\<newline>` is a line
        // continuation, so the line has not ended and the body waits for the
        // one that does end it -- which was checked against a real shell --
        // and a newline inside quotes is a character in a string. A comment
        // between the operator and the newline changes nothing: `cat <<EOF #
        // note` still takes a body, and bash agrees.
        //
        // The continuation is read off the flag rather than out of `escaped`
        // a second time, because [`words`] has to ask the same question and
        // two readings of it are two chances to disagree -- which is how a
        // continued line came to put a program named `"\n"` in the roster.
        if ch == '\n' && !current.continuation && current.quoting == Quoting::Normal {
            self.open_here();
        }
        Some(current)
    }
}

impl Scan<'_> {
    /// How many command substitutions deep the character at the cursor is,
    /// advancing the stack that decides it for the next one.
    ///
    /// Called from [`Scan::next`] after the comment flag for this character
    /// has been settled and before the quoting state is advanced past it, so
    /// what it reads is the shell state *at* this character -- the same
    /// reading [`Scan::redirect_at`] gets, and for the same reason.
    ///
    /// # What opens one, and what does not
    ///
    /// * `$(` opens one and `` ` `` opens one. They are two spellings of the
    ///   same construct; see [`Nest`] for the one way they differ.
    /// * A `(` that no `$` introduces opens nothing. `(cd /tmp && rm x)` is a
    ///   subshell, which this module has always said nothing about, and
    ///   reading it as a substitution would be a second claim about a
    ///   construct the passes below are written to leave alone.
    /// * `$((` is arithmetic rather than a command, and the level it opens
    ///   here contains `(1 + 2` rather than a command word. That is
    ///   deliberate and it is the quiet answer: the interior's first word
    ///   carries a parenthesis, and both the pass that names what runs and
    ///   the pass that underlines it decline such a word -- so an arithmetic
    ///   expansion contributes nothing rather than contributing `1`.
    /// * Nothing inside `'…'`, inside a comment, inside a here-document's
    ///   data or after a backslash opens anything. Those are the answers
    ///   every other question in this scanner gets, asked of the same state.
    ///
    /// # Where one ends
    ///
    /// At the `)` or the backtick that matches it, read in the quoting the
    /// substitution *opened* in -- see [`Nested::quoting`]. Where the scanner
    /// cannot see, it is wrong in the direction of ending a substitution
    /// early, and that direction is the safe one here for a reason worth
    /// writing down: the interior is handed to a scan of its own, an interior
    /// cut short is a prefix of the real one, and the word in command
    /// position is at the front of a prefix as well as of the whole. So the
    /// worst it costs is a command further along the interior, which is the
    /// under-report this module chooses everywhere else.
    fn nest_at(&mut self, ch: char) -> usize {
        let depth = self.nesting.len();
        // A comment is not shell, and an escaped character is itself: `\$(`,
        // `` \` `` and `\)` are all ordinary text. A here-document's data
        // never reaches here at all -- [`Scan::next`] returns before this is
        // called.
        if self.comment || self.escaped {
            self.opening_nest = false;
            return depth;
        }
        // A close before an open, so that the `)` of `$()` closes the level
        // its `(` opened instead of being read as the beginning of anything.
        if let Some(nest) = self.nesting.last()
            && self.quoting == nest.quoting
            && ch == nest.kind.closer()
        {
            self.nesting.pop();
            self.opening_nest = false;
            // The character that closes a substitution is reported outside
            // it, exactly as the quote that closes a string is reported
            // outside the string -- so a run of characters at one depth is
            // exactly one interior, delimiters excluded.
            return depth - 1;
        }
        if std::mem::take(&mut self.opening_nest) && ch == '(' {
            self.nesting.push(Nested { kind: Nest::Paren, quoting: self.quoting });
            return depth;
        }
        if self.quoting == Quoting::Single {
            return depth;
        }
        match ch {
            '`' => self.nesting.push(Nested { kind: Nest::Backtick, quoting: self.quoting }),
            // One character of lookahead, and the `$` is ASCII, so the offset
            // after it is a character boundary and a trailing `$` reads an
            // empty slice rather than panicking.
            '$' if self.command[self.cursor + 1..].starts_with('(') => self.opening_nest = true,
            _ => {}
        }
        depth
    }

    /// Whether the character at the cursor is one of the two a `\`+newline
    /// line continuation is made of.
    ///
    /// The backslash cannot be told from an ordinary escape without looking
    /// at what follows it, and the newline cannot be told from the end of a
    /// line without looking at what precedes it, so the pair is recognised
    /// from both ends and reported on both characters. See
    /// [`Scanned::continuation`] for what reads it.
    fn continuation_at(&self, ch: char) -> bool {
        // Inside `'…'` a backslash escapes nothing, so `'a\` + newline is two
        // characters of a string. A comment runs to the end of its line
        // whatever is at the end of it, and bash agrees.
        if self.comment || self.quoting == Quoting::Single {
            return false;
        }
        match ch {
            '\n' => self.escaped,
            '\\' => !self.escaped && self.command[self.cursor + 1..].starts_with('\n'),
            _ => false,
        }
    }

    /// Which half of a redirection the character at the cursor belongs to,
    /// advancing the state that decides it for the next one.
    ///
    /// Called from [`Scan::next`] after the comment flag for this character
    /// has been settled and before the quoting state is advanced past it, so
    /// what it reads is the shell state *at* this character -- the same
    /// reading every other pass gets. See [`Scan`] for the rules it applies.
    fn redirect_at(&mut self, ch: char) -> Option<Redirect> {
        // A comment is not shell, so nothing in one is a redirection and a
        // redirection still waiting for its word does not get one out of it.
        // A here-document operator waiting for its delimiter loses it the same
        // way: `cat << # x` opens nothing, and bash calls that a syntax error.
        if self.comment {
            self.redirecting = Redirecting::No;
            self.opening = None;
            return None;
        }
        if let Redirecting::Operator { end } = self.redirecting
            && self.cursor < end
        {
            return Some(Redirect::Operator);
        }
        // An operator is tried before the word, so that the `>` of `>a>b`
        // ends the target `a` and starts a second redirection rather than
        // being swallowed by the first one's word.
        if let Some((end, token)) = self.operator_here() {
            // A second operator ends the word the one before it pointed at:
            // `cat <<EOF>out` ends on `EOF` and then redirects, which is what
            // bash reads too.
            self.close_opening(self.cursor);
            self.redirecting = Redirecting::Operator { end };
            // Only these two take a body. `<<<` is a here-string: its word is
            // on this line and there is nothing to wait for.
            self.opening = match token {
                "<<" => Some(Opening { strip_tabs: false, word: None }),
                "<<-" => Some(Opening { strip_tabs: true, word: None }),
                _ => None,
            };
            return Some(Redirect::Operator);
        }
        // Blanks and word breaks are only themselves when the shell would
        // read them as themselves: a quoted or escaped space is part of the
        // word, which is why `> "my file"` points at all of `"my file"`.
        let bare = !self.escaped && self.quoting == Quoting::Normal;
        match self.redirecting {
            Redirecting::No => None,
            Redirecting::Operator { .. } | Redirecting::Blanks => match ch {
                // The blanks bash allows between an operator and its word.
                // Only these two: a newline does not carry a redirection to
                // the next line, and neither does any other metacharacter.
                ' ' | '\t' if bare => {
                    self.redirecting = Redirecting::Blanks;
                    None
                }
                _ if bare && is_metacharacter(ch) => {
                    self.redirecting = Redirecting::No;
                    // An operator with no word after it opens no
                    // here-document: there is no delimiter for a body to end
                    // on, so reading one would be inventing the shape of the
                    // rest of the command.
                    self.opening = None;
                    None
                }
                _ => {
                    self.redirecting = Redirecting::Target;
                    if let Some(opening) = self.opening.as_mut() {
                        opening.word = Some(self.cursor);
                    }
                    Some(Redirect::Target)
                }
            },
            Redirecting::Target => match bare && is_metacharacter(ch) {
                true => {
                    self.redirecting = Redirecting::No;
                    self.close_opening(self.cursor);
                    None
                }
                false => Some(Redirect::Target),
            },
        }
    }

    /// The byte offset a redirection operator starting at the cursor ends at
    /// and the operator itself, or `None` if none starts here.
    ///
    /// The token comes back because `<<` and `<<-` are not finished when they
    /// end: they take a body, and only the operator knows whether that body's
    /// leading tabs are stripped.
    ///
    /// Lookahead, and bounded: a file descriptor is a run of digits the
    /// cursor is already at the start of, and an operator is one of twelve
    /// fixed strings. Nothing here backtracks or rescans, so the pass is
    /// still one left-to-right walk of an agent-controlled string.
    fn operator_here(&self) -> Option<(usize, &'static str)> {
        if self.escaped || self.quoting != Quoting::Normal {
            return None;
        }
        let rest = &self.command[self.cursor..];
        // A file descriptor has to be the whole of the token so far, which is
        // what `word_start` says: `2>x` redirects and `a2>x` does not.
        let digits = match self.word_start {
            true => rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len(),
            false => 0,
        };
        let token = REDIRECTIONS.iter().find(|op| rest[digits..].starts_with(**op))?;
        // A run of digits with no operator behind it is an ordinary word, and
        // `&>` is not an operator a descriptor may precede -- the `&` is part
        // of the operator, not a number. Either way the digits are left to be
        // read as what they are.
        match digits > 0 && token.starts_with('&') {
            true => None,
            false => Some((self.cursor + digits + token.len(), token)),
        }
    }

    /// Queue the here-document whose delimiter word ends at `end`, so that its
    /// body begins after the next newline.
    ///
    /// Called wherever a redirection's target run ends, which is the one place
    /// the whole of the delimiter word is known. An operator that never got a
    /// word queues nothing -- see [`Scan`] for why that is the safe direction.
    fn close_opening(&mut self, end: usize) {
        let Some(opening) = self.opening.take() else { return };
        let Some(start) = opening.word else { return };
        let (delimiter, expands) = delimiter_of(&self.command[start..end]);
        self.pending.push_back(HereDoc { delimiter, strip_tabs: opening.strip_tabs, expands });
    }

    /// Start the next queued here-document's data at the cursor, if there is
    /// one.
    ///
    /// The cursor is already past the newline when this is called, from both
    /// of its callers, so "at the cursor" is the first character of the line
    /// the data begins on.
    fn open_here(&mut self) {
        if let Some(doc) = self.pending.pop_front() {
            self.enter(doc);
        }
    }

    /// Enter `doc`'s data at the cursor: its terminating line when the line
    /// there is already the delimiter, its body otherwise.
    ///
    /// The empty body is not a curiosity -- `cat <<EOF` with `EOF` on the very
    /// next line is how a script says *nothing on stdin* -- and reading it as
    /// a one-line body would leave the scanner looking for a delimiter that
    /// has already gone past.
    fn enter(&mut self, doc: HereDoc) {
        self.here = Some(match self.line_is_delimiter(&doc) {
            true => Here::Delimiter,
            false => Here::Body { expands: doc.expands },
        });
        self.active = Some(doc);
    }

    /// Cross the newline at the cursor, which is inside a here-document.
    ///
    /// Three moves and no others. Inside a body, the line beginning here ends
    /// it if it is the delimiter and is more body if it is not. Past a
    /// delimiter line, this here-document is finished -- and the next one its
    /// operator line queued begins immediately, which is what makes
    /// `cat <<A <<B` read body A, then body B, with no shell in between.
    fn cross_line(&mut self) {
        match self.here {
            Some(Here::Body { .. }) => {
                let doc = self.active.take().expect("a body has a here-document behind it");
                self.enter(doc);
            }
            Some(Here::Delimiter) => {
                self.active = None;
                self.here = None;
                self.open_here();
            }
            None => {}
        }
    }

    /// Whether the line beginning at the cursor is exactly `doc`'s delimiter.
    ///
    /// Exactly: a line of `EOF ` is not the delimiter `EOF`, and bash agrees.
    /// Leading tabs are the one thing stripped first, and only for a `<<-`.
    ///
    /// A line at a time, and each line is looked at once -- once at the
    /// newline in front of it -- so this stays linear in a command the agent
    /// chooses the length of.
    fn line_is_delimiter(&self, doc: &HereDoc) -> bool {
        let rest = &self.command[self.cursor..];
        let line = &rest[..rest.find('\n').unwrap_or(rest.len())];
        let line = match doc.strip_tabs {
            true => line.trim_start_matches('\t'),
            false => line,
        };
        line == doc.delimiter
    }
}

/// The word a here-document's body ends on, and whether that body expands.
///
/// Quote removal, and one flag falling out of it: bash turns expansion off for
/// the whole body when **any** part of the delimiter word is quoted, so
/// `<<'EOF'`, `<<"EOF"`, `<<\EOF` and `<<EO'F'` all end on `EOF` and all
/// substitute nothing anywhere in the body. That was checked against a real
/// shell, including the last one, which is the case a rule written as "starts
/// with a quote" would get wrong.
///
/// The three constructs are the three [`literal_word`] models, and this is a
/// separate reading of them because it answers a different question: a
/// delimiter that hatch cannot read is still a delimiter, and there is no
/// `None` to return -- the body ends where the shell says it ends whether or
/// not the word looks like a name.
fn delimiter_of(word: &str) -> (String, bool) {
    let mut out = String::new();
    let mut quoted = false;
    let mut chars = word.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                quoted = true;
                if let Some(escaped) = chars.next() {
                    out.push(escaped);
                }
            }
            '\'' | '"' => {
                quoted = true;
                // To the matching quote, or to the end of the word if there is
                // none -- bash refuses such a command outright, so what
                // matters here is only that the scan terminates.
                for inner in chars.by_ref() {
                    if inner == c {
                        break;
                    }
                    out.push(inner);
                }
            }
            _ => out.push(c),
        }
    }
    (out, !quoted)
}

/// Find every command boundary in `command`, in source order.
fn boundaries(command: &str) -> Vec<Boundary> {
    let mut found = Vec::new();
    // One past the last byte already claimed by a separator token. Without
    // it `|||` would report `||` at 0..2 and again at 1..3 — two overlapping
    // boundaries out of one operator and a `;`-worth of screen noise.
    let mut consumed = 0;
    // One character of lookahead, for one question: whether a here-document's
    // data starts on the line after a newline. It cannot be answered by the
    // newline itself -- the newline that opens a body is on the operator's
    // line and is ordinary shell -- and it is the whole of what tells a line
    // ending apart from the end of a command. See [`Boundary::HereLine`].
    let mut scan = scan(command).peekable();

    while let Some(c) = scan.next() {
        // A comment first, because nothing in one is a boundary: the `&&` in
        // `echo hi # then && rm -rf /tmp` is text, and a break drawn there
        // claims a boundary the shell does not have. The newline that ends a
        // comment is reported outside it and still lands below.
        //
        // A command substitution next, because a boundary inside one belongs
        // to the command inside it: the `;` of `echo $(a; b)` really is a
        // separator, and drawing it here would draw it at this level -- two
        // segments on screen where the shell runs one command with one
        // argument. The interior gets a pass of its own; see
        // [`substitutions`].
        if c.comment
            || c.nesting > 0
            || c.offset < consumed
            || c.escaped
            || c.quoting != Quoting::Normal
        {
            continue;
        }
        if c.ch == '\n' {
            let end = c.offset + c.ch.len_utf8();
            // A newline with a here-document's data after it ends a line and
            // not a command: the body belongs to the command that opened it.
            found.push(match scan.peek().is_some_and(|next| next.here.is_some()) {
                true => Boundary::HereLine(end),
                false => Boundary::Newline(end),
            });
            continue;
        }
        // A here-document's data next, because a `;` in a config file is a
        // character in a config file. Then a redirection operator, because
        // `>|` is one token and the `|` in it is not a pipe. This is the whole
        // of what it takes for these passes to agree about a byte: one of them
        // decides, and the others read the decision. Only a redirection's
        // operator has to be skipped -- a target ends at any unquoted
        // metacharacter, so a separator character can only be inside one when
        // it is quoted, and quoting already stops it.
        if c.here.is_some() || c.redirect == Some(Redirect::Operator) {
            continue;
        }
        let rest = &command[c.offset..];
        if let Some(token) = SEPARATORS.iter().find(|sep| rest.starts_with(**sep)) {
            consumed = c.offset + token.len();
            found.push(Boundary::Separator(c.offset..consumed));
        }
    }

    found
}

/// True for a character that may appear in a variable name. The first one
/// also has to not be a digit, which [`variable_name`] checks; this is the
/// looser predicate, used to find where a name *ends*.
fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// How many bytes of `rest` — which starts at a `$` — this pass steps over.
///
/// Separate from *whether* those bytes are a reference, which
/// [`variable_name`] decides. The split matters for one case: `$$HOME`. The
/// shell reads that as the PID followed by the literal `HOME`, so nothing in
/// it expands `HOME` — but a scanner that gave up on the first `$` and
/// resumed at the next byte would find `$HOME` there and annotate a
/// substitution the shell will not perform. Stepping over what it declines to
/// claim is what stops a rejected construct being re-read as an accepted one.
///
/// The same rule covers `${…}`: the whole brace expansion is consumed through
/// its first `}` whether or not the interior turns out to be a plain name, so
/// `${HOME:-$USER}` annotates nothing rather than annotating the `$USER`
/// inside it. That is conservative in the safe direction — a reference that
/// may or may not expand is left `Plain` — and it is why this returns a
/// length rather than a yes-or-no.
fn dollar_extent(rest: &str) -> usize {
    let after = &rest[1..];
    match after.chars().next() {
        // A trailing `$`.
        None => 1,
        // Through the first `}`, or just past the `{` if there is none:
        // `${HOME` is unterminated and claims nothing.
        Some('{') => match after[1..].find('}') {
            Some(offset) => 3 + offset,
            None => 2,
        },
        // The whole run of name characters, digits included, so `$1HOME` is
        // stepped over whole instead of leaving `HOME` to be misread.
        Some(c) if is_name_char(c) => {
            1 + after.find(|c: char| !is_name_char(c)).unwrap_or(after.len())
        }
        // `$$`, `$?`, `$@`, `$(`, `$'` … one sigil, stepped over.
        Some(c) => 1 + c.len_utf8(),
    }
}

/// The byte range of every variable reference in `command` that hatch claims
/// to understand, in source order.
///
/// Quoting is the whole point. `$HOME` expands in `Normal` and inside `"…"`;
/// inside `'…'` it is two words of text, and after a backslash it is a
/// literal `$`. Annotating those would tell the reader a substitution happens
/// where none does — the same class of lie as splitting `echo 'a; b'` in two,
/// and the reason both questions are asked of one [`Scan`].
///
/// A comment is the same answer for a different reason: the shell does not
/// expand `$HOME` in `echo # $HOME` because it does not read the line at all.
/// Resolving it on screen would put this machine's home directory beside a
/// reference that is never substituted — a small lie, and one told in the
/// window's most authoritative voice, which is the value it promises comes
/// out of the environment the command will really run in.
///
/// A here-document is the one place the answer is neither always yes nor
/// always no, and the difference is worth keeping. An unquoted `<<EOF` expands
/// its body, so a `$HOME` there really is substituted and is annotated like
/// any other; a quoted `<<'EOF'` expands nothing anywhere in the body, so a
/// value shown beside one would be exactly the lie above. The delimiter line
/// is not data and expands nothing either way.
///
/// A command substitution is the one lexical fact on [`Scanned`] this pass
/// deliberately does not read. Every other pass here steps over an interior
/// and leaves it to a scan of its own, because every other pass is asking
/// about *command structure* and an interior's structure is not this level's.
/// Expansion is not a question about structure: the `$HOME` of
/// `echo $(ls $HOME)` is substituted out of the same environment at either
/// depth, with the same value, and a reader looking at it wants the value
/// either way. So this walk crosses a substitution as if it were not there,
/// which is also what keeps the annotation from vanishing out of every
/// `$(…)` in the window.
/// Whether a `$` in this part of a here-document expands -- and `true` when it
/// is not in one at all, which is every other character in the command.
///
/// Written the round way so that [`references`] reads as one list of reasons
/// not to annotate. The delimiter line expands nothing: it is not handed to
/// the command, so there is nothing there for the shell to substitute into.
fn expands_here(here: Option<Here>) -> bool {
    match here {
        None => true,
        Some(Here::Body { expands }) => expands,
        Some(Here::Delimiter) => false,
    }
}

fn references(command: &str) -> Vec<Range<usize>> {
    let mut found = Vec::new();
    let mut consumed = 0;

    for c in scan(command) {
        if c.comment
            || !expands_here(c.here)
            || c.offset < consumed
            || c.ch != '$'
            || c.escaped
            || c.quoting == Quoting::Single
        {
            continue;
        }
        let rest = &command[c.offset..];
        let extent = dollar_extent(rest);
        consumed = c.offset + extent;
        if variable_name(&rest[..extent]).is_some() {
            found.push(c.offset..consumed);
        }
    }

    found
}

/// Render `command` as segments: separators tagged and kept, line breaks
/// requested on the spans that follow them, and every run in between handed
/// to the Unicode classifier so chips still appear inside segments.
///
/// One [`SpanBuilder`] drives the whole command. The span model offers no way
/// to splice one [`Spans`] into another — a spliced sequence would have to be
/// trusted rather than checked by `finish` — so composition happens through
/// the builder's cursor instead, and the result tiles the source or panics.
///
/// # Panics
///
/// If the spans do not tile `command` exactly, which would be a bug in this
/// function or in the scanner. A panicking prompt window is a dead prompt
/// window, and hatch treats that as a denial, so failing this way fails
/// closed.
///
/// Every break here is one the command's own structure asked for. A caller
/// that knows something about the line the scanner cannot see — where the
/// approved command starts inside an elevated one — wants
/// [`segment_breaking_at`].
pub fn segment(command: &str) -> Spans {
    segment_breaking_at(command, None)
}

/// [`segment`], and one further line break at a byte offset the caller knows
/// and this pass cannot see.
///
/// The elevated line is the whole of why this exists. A root request is drawn
/// as the line that will actually run —
/// `run0 --pipe --setenv=… -- bash -c '…'` — and the command the reader came
/// to read arrives after a wall of boilerplate whose length grows with the
/// size of the child environment. `run0` and its own options are one thing,
/// the approved command is another, so the second starts a line of its own.
///
/// # Why the offset is a parameter
///
/// Because it cannot be recovered from the text. A `--` can occur inside the
/// command, and so can the word `run0`, so a search through the finished line
/// would sometimes find the wrong seam and break the line in the middle of
/// what it claims to be showing.
/// [`crate::exec::elevate::ElevatedArgv::inner_at`] is the one place that
/// knows, because it is the place that joined the two halves, and the offset
/// travels from there to here rather than being guessed at either end.
///
/// # It is layout, and layout only
///
/// The break is [`Span::break_before`](super::Span::break_before) on the span
/// that starts at `at`, exactly as a separator's break is on the span that
/// follows it. Nothing is inserted into the command: a newline character
/// there would change the bytes the reader is approving, and those are the
/// bytes that run.
///
/// # Panics
///
/// If `at` is inside a character, or behind a point this pass has already
/// covered — inside a separator token it has emitted, say. Either means the
/// caller's idea of where the command begins and this pass's have come apart,
/// and a line that quietly failed to break is the worse answer: the reader
/// would be shown a wall of wrapper with no sign that anything was meant to
/// end it.
///
/// An `at` past the end of the command is simply never spent, because no
/// boundary ever reaches it. That one is caught by
/// [`super::render_command_breaking_at`], which asks the finished rendering
/// whether the break it ordered is really on it.
pub fn segment_breaking_at(command: &str, at: Option<usize>) -> Spans {
    let mut builder = SpanBuilder::new(command);
    let found = boundaries(command);
    let mut asked = at;

    for (index, boundary) in found.iter().enumerate() {
        match boundary {
            Boundary::Separator(token) => {
                take_break(&mut builder, &mut asked, token.start);
                // The run before the separator. May be empty — `;;`, or a
                // leading separator — and `classify_into` at the cursor is a
                // no-op, so there is nothing to guard against.
                unicode::classify_into(&mut builder, token.start);
                builder.push_to(token.end, SpanKind::Separator);
                if newline_already_ends_the_line(command, token.end, found.get(index + 1)) {
                    continue;
                }
                // A fallback stays on the line of the thing it is a fallback
                // for. See `ends_a_line`.
                if !ends_a_line(&command[token.start..token.end]) {
                    continue;
                }
                // The blanks the author left after the separator belong to
                // the line the separator ends, not to the one that follows.
                // See `blanks_after`.
                let after = blanks_after(command, token.end);
                if asked.is_none_or(|at| at >= after) {
                    unicode::classify_into(&mut builder, after);
                }
            }
            // The newline goes *through* the classifier rather than around
            // it, which is what makes it a chip and not a drawn-as-itself
            // separator.
            //
            // A here-document's line ending goes the same way, because the
            // drawing is the same drawing: the `↵` at the end of the line and
            // a break after it. What it is not is the end of a segment, and
            // that difference is [`segments`]'s to read -- the body is data
            // belonging to the command above it, and numbering each line of a
            // config file as a command of its own would be the same lie the
            // separators in it used to tell.
            Boundary::Newline(end) | Boundary::HereLine(end) => {
                take_break(&mut builder, &mut asked, *end);
                unicode::classify_into(&mut builder, *end);
            }
        }
        // On the span that follows, never on the separator: the separator is
        // a character the user is approving and it stays where it is.
        builder.break_next();
    }

    take_break(&mut builder, &mut asked, command.len());
    unicode::classify_into(&mut builder, command.len());
    builder.finish()
}

/// Spend the caller's requested break, if the boundary about to be emitted
/// would carry the cursor past it.
///
/// Called before each boundary rather than after, so that a break asked for
/// inside the run leading up to one lands where it was asked for and not
/// after the separator that happens to follow it. Flushing to `at` first is
/// what makes the offset a span boundary at all: everything before it is one
/// span or more, and the next span emitted is the one that starts the line.
///
/// # Panics
///
/// Through [`unicode::classify_into`], if `at` is not a place this pass can
/// still cut: behind the cursor, past the end, or inside a character.
fn take_break(builder: &mut SpanBuilder<'_>, asked: &mut Option<usize>, before: usize) {
    match *asked {
        Some(at) if at <= before => {
            unicode::classify_into(builder, at);
            builder.break_next();
            *asked = None;
        }
        _ => {}
    }
}

/// Whether a separator ends the drawn line it closes.
///
/// Four of the five do. `||` does not, and the difference is not a matter of
/// taste about short lines: a break reads as *then*, and for `;`, `&&` and a
/// pipe that is what happened -- the next thing runs after this one, or takes
/// its output. `||` means *otherwise*. What follows it runs **instead of**
/// what precedes it, and only when that failed, so drawing it as the next
/// line draws a fallback as a next step.
///
/// One line says the true thing: one of these two runs. It also keeps the
/// idiom an agent writes most -- `… || true`, `… || exit 1` -- from spending
/// a whole row on the word `true`, but that is a consequence and not the
/// reason; a rule about how short the right-hand side is would be a
/// per-command decision wearing a statistic.
///
/// This is layout only. `||` is still a boundary everywhere it matters: it is
/// drawn as itself at the end of its segment, [`segments`] still ends one
/// there, so the word after it is still named as a command in the roster and
/// still highlighted as one.
fn ends_a_line(separator: &str) -> bool {
    separator != "||"
}

/// Where the run of blanks immediately after `at` ends.
///
/// Spaces and tabs only, and never a newline: a newline ends the line by
/// itself and is drawn as a chip by the pass that owns it.
///
/// # Why they move
///
/// `a; b` is two commands with a space between them, and the space is there
/// because somebody typed the separator and then a space. Left at the front
/// of the following segment it became that segment's first character, and
/// since every segment after the first begins that way, every drawn line
/// after the first began one column in. A reader sees a column and reads
/// nesting; there is none, and the lines that really are nested got the same
/// one column as the ones that are not.
///
/// So the blanks are drawn at the end of the line their separator ends. This
/// moves no byte and removes none: the spans are pushed in the same order
/// over the same source, [`super::unrender`] concatenates the same text, and
/// the raw pane is not touched at all. What changes is which side of a line
/// break the blanks sit on, and a line break is layout — see the module docs
/// on why breaks are metadata rather than characters.
///
/// A caller that asked for a break of its own inside the run keeps it: the
/// run is left alone in that case rather than swallowing a break somebody
/// placed deliberately.
fn blanks_after(command: &str, at: usize) -> usize {
    command[at..]
        .find(|c: char| c != ' ' && c != '\t')
        .map_or(command.len(), |offset| at + offset)
}

/// Whether the author's own newline is already going to end the line this
/// separator sits on, so segmentation should not ask for a break of its own.
///
/// Both passes want a break in the same place, and they want it for different
/// reasons: segmentation because a separator ends a segment, the classifier
/// because a newline ends a line. Asking twice is not harmless. Segmentation
/// asks first, so its break lands on the very next span emitted — which, when
/// a newline follows the separator, is the newline's own `↵`. The glyph that
/// says *this line ended here* is then drawn alone at the start of the next
/// line, one wasted row per segment, and the two panes disagree about a
/// command neither of them has changed: the raw pane, which has no
/// segmentation in it, draws `&&↵` together and is right.
///
/// So the separator gives way. The newline's break is the one that starts the
/// next segment, and its `↵` stays at the end of the line it ends. Nothing is
/// hidden by this and nothing moves: it decides which span carries
/// [`Span::break_before`](super::Span::break_before), which is layout, and
/// every character is drawn either way.
///
/// Whitespace between the two does not change the answer — it is the run-up to
/// the newline and belongs on the line it is typed on, which is again where
/// the raw pane draws it. Anything else in between is a segment with content
/// in it and gets the break it asked for.
fn newline_already_ends_the_line(command: &str, after: usize, next: Option<&Boundary>) -> bool {
    match next {
        // Through the newline rather than up to it: `end` is one past it and
        // a newline is whitespace, so including it asks the same question and
        // spares an offset that could be off by one.
        //
        // A here-document's line ending counts, because what this function is
        // about is the break and both kinds carry one. `cat <<EOF |` ends a
        // line with a separator on it and a body under it, and a separator
        // that insisted on its own break there would put the `↵` alone at the
        // top of the body.
        Some(Boundary::Newline(end) | Boundary::HereLine(end)) => {
            command[after..*end].chars().all(char::is_whitespace)
        }
        _ => false,
    }
}

/// Tag every variable reference in `spans` and hang the value it will
/// actually have on it.
///
/// A refinement pass: it subdivides the spans it is given at each reference
/// and leaves every other span exactly as it found it. It is the third pass
/// in [`super::render_command`] and runs after segmentation, which is what
/// lets it work with the span a reference lives in rather than having to find
/// the structure again.
///
/// # Why it rebuilds rather than splitting in place
///
/// [`Spans::split`] is the obvious tool and the wrong one at this scale.
/// Splitting copies both halves' text, so subdividing one long run at every
/// reference re-copies the whole tail each time: quadratic in the number of
/// references, and the number of references is chosen by the agent. Measured
/// in release, `$A ` repeated: 100 KB took 940 ms with a rescan from index
/// zero, 68 ms once the search carried a moving start index, and 1 MB still
/// took 6.3 s — the copying is the part the moving index cannot reach.
///
/// Walking the existing spans once into a fresh [`SpanBuilder`] copies every
/// byte exactly once instead, and gives up nothing: the
/// builder cuts every span from the same source, so no text can be invented,
/// and [`SpanBuilder::finish`] re-checks that the result tiles the source
/// from scratch rather than inheriting that guarantee from the input. The
/// same 1 MB takes 63 ms, and 100 KB takes 7 ms.
///
/// # `env` is the child environment, and nothing else will do
///
/// The value shown must come from [`crate::exec::env::build_child_env`] — the
/// environment hatch will hand the child — because that is the only
/// environment the window can speak for. The daemon's own environment came
/// from wherever the daemon was started, the agent's sandbox environment is
/// agent-influenced, and `run0` resets the environment for a `root: true`
/// operation regardless. Resolving against any of those, or against
/// `std::env`, would print a value that looks authoritative and is wrong,
/// which is worse for a window whose job is to be believed than printing
/// nothing at all. That is why the environment is a parameter here and not a
/// lookup: there is no default that is not a guess.
///
/// A name that environment does not contain resolves to `None` — shown as
/// unset. That is only a true claim because [`super::variable_name`] refuses
/// every name the shell supplies for itself, so a `None` here cannot be
/// hatch's ignorance of `$PWD` wearing the appearance of an empty expansion.
///
/// # What a reference lands on
///
/// Every character a reference can contain is drawn as itself and is not a
/// separator, so a reference always lies wholly inside one `Plain` span and
/// never straddles a chip or a separator. That is what lets the two ordered
/// sequences — spans and references — be merged in one walk. Re-running
/// against a different environment does re-resolve, so the last environment
/// applied is the one on screen.
///
/// # Panics
///
/// If a reference straddles a span boundary, which would mean the claim above
/// no longer holds: the builder refuses the out-of-order push. A panicking
/// prompt window is a dead prompt window, and hatch treats that as a denial,
/// so failing this way fails closed.
/// A name the command sets for itself, and what it sets it to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Assignment {
    /// Where it takes effect: the end of the segment that performs it. A
    /// reference before this offset is not covered by it, because the shell
    /// had not run it yet.
    at: usize,
    name: String,
    /// The value, when it can be worked out exactly. `None` is *set, and
    /// hatch is not going to guess* -- which is a different thing from unset
    /// and is drawn as nothing at all rather than as a claim.
    value: Option<String>,
}

/// Where each here-document body is, in source order.
///
/// Exposed so [`super::language`] can read a body without deciding for itself
/// where one is: the scanner is the authority on that, and a second opinion
/// about it is how two passes come to disagree about the same bytes. The
/// terminator line is not part of the range -- it is the delimiter, not the
/// data.
pub(crate) fn here_bodies(command: &str) -> Vec<Range<usize>> {
    let mut out: Vec<Range<usize>> = Vec::new();
    for scanned in scan(command) {
        if !matches!(scanned.here, Some(Here::Body { .. })) {
            continue;
        }
        let end = scanned.offset + scanned.ch.len_utf8();
        match out.last_mut() {
            Some(last) if last.end == scanned.offset => last.end = end,
            _ => out.push(scanned.offset..end),
        }
    }
    out
}

/// The names this command sets for itself, in the order it sets them.
///
/// # Why this exists
///
/// `R=/srv; cp $R/a $R/b` drew `$R` as **unset**, twice, because the
/// environment the daemon resolved against is the one the child will start
/// with and `R` is not in it. That is a false statement of the useful kind:
/// the reader is being told the expansion is empty when the command sets it
/// two words earlier, and the shape is an ordinary one for an agent to write.
///
/// # Only an assignment the shell keeps
///
/// A segment made of nothing but assignments sets them for the rest of the
/// command. `A=1 cmd` does not: it puts `A` in *that command's* environment
/// and leaves the shell's alone, so a later `$A` there is not this one. The
/// rule is therefore the whole segment or nothing, which is also the shape
/// the request came in as -- names declared at the top.
///
/// # Only a value that is already what it will be
///
/// The value is taken as written and expanded no further. Anything holding a
/// `$`, a quote, a backslash, a glob or a substitution yields `None`: working
/// those out means being a shell, and being approximately a shell in a window
/// whose whole claim is that it shows what will run is the wrong kind of
/// clever. `~/` is the one exception, resolved through `HOME` when the
/// environment has one, because it is the common case and it is exact.
///
/// A here-document body is skipped. It is data rather than shell, so an
/// `A=1` in a config file being written is not an assignment, and the same
/// flag that keeps a `;` in a body from being a separator keeps this out.
fn assignments(command: &str, env: &BTreeMap<String, String>) -> Vec<Assignment> {
    // Bytes no assignment may be read out of: a here-document body, and a
    // comment. Both are already decided by the one scan every other pass
    // reads, so this cannot disagree with them.
    let mut inert = vec![false; command.len()];
    for scanned in scan(command) {
        if scanned.here.is_some() || scanned.comment {
            for byte in &mut inert[scanned.offset..scanned.offset + scanned.ch.len_utf8()] {
                *byte = true;
            }
        }
    }

    let mut out = Vec::new();
    for segment in segments(command) {
        if inert[segment.clone()].iter().any(|byte| *byte) {
            continue;
        }
        let words: Vec<&str> = command[segment.clone()].split_ascii_whitespace().collect();
        if words.is_empty() || !words.iter().all(|word| assigned_name(word).is_some()) {
            continue;
        }
        for word in words {
            let name = assigned_name(word).expect("every word was checked above");
            let raw = &word[name.len() + 1..];
            out.push(Assignment {
                at: segment.end,
                name: name.to_string(),
                value: assigned_value(raw, env),
            });
        }
    }
    out
}

/// The name a word assigns to, or `None` if it does not assign at all.
///
/// The shell's rule: a name, then `=`. Not `=x`, not `1A=x`, not `A[0]=x` --
/// an array element is an assignment the shell understands and this does not,
/// so it is left alone rather than read as a name containing a bracket.
fn assigned_name(word: &str) -> Option<&str> {
    let (name, _) = word.split_once('=')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic() && first != '_' {
        return None;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_').then_some(name)
}

/// What a written value is worth, or `None` when hatch will not say.
fn assigned_value(raw: &str, env: &BTreeMap<String, String>) -> Option<String> {
    if let Some(rest) = raw.strip_prefix("~/") {
        let home = env.get("HOME")?;
        return assigned_value(rest, env).map(|rest| format!("{home}/{rest}"));
    }
    let opaque = |ch: char| {
        matches!(ch, '$' | '`' | '\'' | '"' | '\\' | '*' | '?' | '[' | ']' | '~' | '{' | '}')
    };
    (!raw.contains(opaque)).then(|| raw.to_string())
}

/// What the command itself says a name is worth at `at`, if anything.
///
/// The last assignment before that offset wins, which is the shell's own
/// answer: a name set twice is worth what it was set to most recently.
fn assigned_at<'a>(
    assignments: &'a [Assignment],
    name: &str,
    at: usize,
) -> Option<&'a Assignment> {
    assignments.iter().rev().find(|held| held.name == name && held.at <= at)
}

pub fn annotate_variables(spans: Spans, env: &BTreeMap<String, String>) -> Spans {
    let source = spans.source();
    let references = references(source);
    let set_here = assignments(source, env);
    let mut builder = SpanBuilder::new(source);
    let mut next = 0;

    for span in spans.iter() {
        // The break belongs to whatever starts where this span started, which
        // is the first sub-span emitted for it. A pending break survives an
        // empty push, so a reference sitting at the very start of the span
        // inherits it, exactly as `Spans::split` would have left it.
        if span.break_before() {
            builder.break_next();
        }

        let end = span.range().end;
        // A span that is neither `Plain` nor already a `Variable` belongs to
        // some other pass, and this one does not overrule it: it is re-emitted
        // with its kind and any reference inside it is skipped rather than
        // tagged.
        let annotatable = matches!(span.kind(), SpanKind::Plain | SpanKind::Variable { .. });

        while next < references.len() && references[next].end <= end {
            let reference = references[next].clone();
            next += 1;
            if !annotatable {
                continue;
            }
            builder.push_to(reference.start, SpanKind::Plain);
            let name = variable_name(&source[reference.clone()])
                .expect("the scanner matched this range as a whole reference");
            // What the command sets for itself beats the environment it will
            // start in, because it happens second. A name it sets to
            // something hatch will not work out is left untagged: no chip, no
            // claim -- see `assignments`.
            let resolved = match assigned_at(&set_here, name, reference.start) {
                Some(Assignment { value: None, .. }) => {
                    builder.push_to(reference.end, SpanKind::Plain);
                    continue;
                }
                Some(Assignment { value: Some(value), .. }) => Some(unicode::defang(value)),
                None => env.get(name).map(|value| unicode::defang(value)),
            };
            builder.push_to(reference.end, SpanKind::Variable { resolved });
        }

        let rest = if annotatable { SpanKind::Plain } else { span.kind().clone() };
        builder.push_to(end, rest);
    }

    builder.finish()
}

// ---- highlighting ----------------------------------------------------------

/// The byte ranges of the segments `command` is drawn as, excluding the
/// separator tokens between them.
///
/// A newline's boundary is reported one past the newline, and the newline is
/// whitespace, so it ends the word before it without needing to be excluded
/// here. A separator token is not whitespace and does have to be: `ls;rm`
/// would otherwise be one word called `ls;rm`.
///
/// A here-document's line ending is not a segment end at all, so the operator
/// line and the body under it are one segment -- which is what they are to the
/// shell, the body being that command's stdin rather than the next thing to
/// run. The body contributes no words of its own ([`is_word_break`] sees to
/// that), so the segment's command word is still the one on the operator line.
fn segments(command: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut start = 0;
    for boundary in boundaries(command) {
        let (stop, next) = match boundary {
            Boundary::Separator(token) => (token.start, token.end),
            Boundary::Newline(end) => (end, end),
            Boundary::HereLine(_) => continue,
        };
        out.push(start..stop);
        start = next;
    }
    out.push(start..command.len());
    out
}

/// True where a word ends: unescaped whitespace outside quotes, anywhere
/// inside a comment, and anywhere inside a redirection.
///
/// Quoting is the whole of it, and it is the scanner's answer rather than a
/// second one. `echo "a b"` is two words to the shell, so it has to be two
/// words here — a highlight that called `"a` a word would draw a boundary the
/// shell does not have.
///
/// A comment has no words in it, so every character of one breaks: `a; # ls`
/// has a command word in its first segment and none in its second. Saying it
/// this way rather than with a check in [`command_word`] is what keeps a
/// `Command` region from ever overlapping a `Comment` one — two regions that
/// overlap have no honest drawing — and it is the same move [`claimable`]
/// makes for a quoted word.
///
/// A here-document is the same answer and the loudest correction of the three.
/// A body has no words in it because it is not shell: every line of a config
/// file was being read as a command, and the first word of each one was drawn
/// as the thing that runs and reported above the panes as a program nothing
/// answers to. The delimiter line goes with it -- it is structure, and a
/// `Command` region on an `EOF` would be naming a program that does not exist.
///
/// A redirection is the same answer again, and here it is a correction as
/// well as a guard. `<` and `>` are metacharacters, so bash reads `cat<file`
/// as the command `cat` with its input redirected; this pass used to call the
/// whole of `cat<file` one word and underline it as the thing that runs. It
/// also used to underline the `>out.txt` of `>out.txt cat`, where the word
/// that names what runs is `cat` and comes after the redirection. Both are
/// right now, and a `Command` region can no longer overlap a `Redirect` one.
///
/// A command substitution is the loudest correction of the four, and it is
/// the one that goes the other way: **nothing** inside one breaks a word,
/// because the whole substitution is one word of the command it sits in.
/// `$(podman ps -q)` is a single word to the shell and so is
/// `x=$(podman ps -q)`, and a pass that split them at the space inside did
/// not merely miss the nested command -- it invented a word, `ps`, and handed
/// it to the pass that names what runs. The interior's own words are found by
/// the scan of the interior; see [`substitutions`].
fn is_word_break(c: &Scanned) -> bool {
    if c.nesting > 0 {
        return false;
    }
    c.comment
        || c.here.is_some()
        || c.redirect.is_some()
        || (!c.escaped && c.quoting == Quoting::Normal && c.ch.is_whitespace())
}

/// True for `NAME=…`, the form a leading word takes when it is an assignment
/// rather than the command.
///
/// `FOO=1 ls` runs `ls`, so drawing `FOO=1` as the word that names what runs
/// would be a highlight contradicting the text — the one thing decoration in
/// this window may never do. The grammar is the shell's: a name, then `=`.
/// `env FOO=1 ls` is unaffected, because `env` is not an assignment and is
/// genuinely what runs.
fn is_assignment(word: &str) -> bool {
    let Some(at) = word.find('=') else {
        return false;
    };
    // `=1` has no name in front of the `=`, and an empty name fails the
    // first-character test on its own -- no separate guard for it, which
    // would be a second way to say the same thing and a second way to get it
    // wrong.
    let name = &word[..at];
    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(is_name_char)
}

/// The word of `segment` that names what will run, or `None` when the segment
/// has none — it is empty, it is nothing but assignments, or the word it
/// would be carries a quote character.
///
/// `at` is a cursor into `scanned` that this advances past `segment`, so a
/// command of ten thousand segments costs one walk of the command rather than
/// one walk per segment. The input is agent-controlled, so that is the
/// difference between linear and quadratic in something the agent chooses.
///
/// # Why a quoted word is declined
///
/// `"ls" -l` really does run `ls`, so the refusal costs a highlight on a real
/// command name. What it buys is that a [`SpanKind::Command`] region can
/// never overlap a [`SpanKind::Quoted`] one — a word that is inside quotes
/// extends to include them, since a quoted space is not a word break — and
/// two overlapping regions have no honest drawing.
fn command_word(
    command: &str,
    scanned: &[Scanned],
    at: &mut usize,
    segment: &Range<usize>,
) -> Option<Range<usize>> {
    // The first word that is not an assignment: `FOO=1 ls` runs `ls`. What
    // counts as a word, and which characters do not begin one, is
    // [`words`]'s -- and it is the same answer [`invoked`] works from, so the
    // underline in the pane and the roster above it cannot come to disagree
    // about which word names what runs.
    let words = words(scanned, at, segment);
    let first = command_at(command, &words)?;
    claimable(command, words[first].clone())
}

/// The index in `words` of the word that names what the segment runs, or
/// `None` when every word of it is an assignment.
///
/// `FOO=1 BAR=2 ls` runs `ls`, and one line says so for all three passes that
/// have to know: the underline [`command_word`] draws, the walk [`walk`]
/// starts, and the point [`invoke_into`] splits a segment's substitutions at.
/// Three readings of *where a command begins* is three chances for the window
/// to say one thing and the roster another.
fn command_at(command: &str, words: &[Range<usize>]) -> Option<usize> {
    words.iter().position(|word| !is_assignment(&command[word.clone()]))
}

/// Every word of `segment`, in source order.
///
/// A word ends where [`is_word_break`] says it does, so a quoted space is
/// inside one, a redirection is outside every one, and a comment contains
/// none. Empty runs are not words: `a;;b` has a segment with nothing in it
/// and that segment yields nothing rather than one word of no characters.
///
/// `at` is a cursor into `scanned` that this advances past `segment`, so a
/// command of ten thousand segments costs one walk of the command rather than
/// one walk per segment. The input is agent-controlled, so that is the
/// difference between linear and quadratic in something the agent chooses.
fn words(scanned: &[Scanned], at: &mut usize, segment: &Range<usize>) -> Vec<Range<usize>> {
    // Two binary searches rather than two hand-rolled cursor loops. The
    // offsets ascend, so the run belonging to this segment is a slice, and
    // taking it as one is what makes `at` impossible to fail to advance --
    // the input is agent-controlled, and a cursor loop that does not move is
    // a window that never opens.
    *at += scanned[*at..].partition_point(|c| c.offset < segment.start);
    let run = &scanned[*at..];
    let run = &run[..run.partition_point(|c| c.offset < segment.end)];
    *at += run.len();

    let mut out = Vec::new();
    let mut word: Option<usize> = None;
    for c in run {
        // Two kinds of character carry a word on without ever beginning one.
        //
        // A line continuation, because the shell removes it before it reads a
        // word. Both other readings were tried and both are wrong: as a
        // break, `ec\`+newline+`ho` becomes the two words `ec` and `ho` and
        // the roster names `ec` -- the wrong program, which is the one answer
        // this module may not give -- and as an ordinary character, a
        // `\`+newline between two blanks becomes a word of its own and the
        // roster names `"\n"`. Passing through leaves the first as the one
        // word `ec\`+newline+`ho`, which [`literal_word`] reads as `echo`,
        // and the second as no word at all.
        //
        // A command substitution's interior, because it is part of the word
        // that holds it and is not a word of this command in its own right.
        // Not beginning one is the half that has to be said out loud: the
        // delimiter in front of an interior is usually an ordinary character
        // of the word, but in `> `+backtick+`a` it is a redirection's target
        // and therefore a break -- and a word begun after it would be the
        // interior, claimed at this level and claimed again by the scan of
        // the interior. Two regions on one range have no honest drawing.
        let through = c.continuation || c.nesting > 0;
        match (is_word_break(c), word) {
            (false, None) if through => {}
            (true, Some(start)) => {
                out.push(start..c.offset);
                word = None;
            }
            (true, None) => {}
            (false, None) => word = Some(c.offset),
            (false, Some(_)) => {}
        }
    }
    // A word that runs to the end of the segment is never closed by a break.
    if let Some(start) = word {
        out.push(start..segment.end);
    }
    out
}

/// `word`, unless this pass declines to call it the command: an assignment, a
/// word carrying a quote character, or a word carrying [`STRUCTURE`].
///
/// The second of those is [`walk`]'s refusal, written here so that the
/// underline in the pane and the roster above it decline the same words.
fn claimable(command: &str, word: Range<usize>) -> Option<Range<usize>> {
    let text = &command[word.clone()];
    (!is_assignment(text) && !text.contains(['\'', '"']) && !text.contains(STRUCTURE))
        .then_some(word)
}

/// The characters that make a word shell structure rather than a name, for
/// the two passes that have to decline the same words.
///
/// A `(` or a `)` is the `(cd` of a subshell, the `a)` of a `case` branch or
/// the `(1 + 2` of an arithmetic expansion; a backtick or a `$(`…`)` is a
/// command substitution. None of them is the name of a program, and a pass
/// that read one as a name would put a finding on entirely ordinary shell —
/// which is the list crying wolf.
///
/// Silence rather than [`Invocation::Unread`], and the same silence for both
/// spellings of a substitution, which is the decision worth writing down.
/// `` `date` `` and `$(date)` in command position are one construct in two
/// hands, so they get one answer: the command *inside* them is reported at
/// its own level by [`substitutions`], and the word itself is a value hatch
/// cannot know without running something. Reporting it as a word hatch could
/// not read as well would tell the reader twice about one construct, once in
/// a voice that means *something here was not understood*.
///
/// For the pane the refusal is load-bearing rather than tasteful: the
/// interior of `$(podman ps)` carries a `Command` region of its own, and
/// claiming the word around it would lay a second region straight across the
/// first. Two overlapping regions have no honest drawing.
const STRUCTURE: [char; 3] = ['(', ')', '`'];

/// The byte range of every quoted string in `command`, delimiters included,
/// in source order.
///
/// An unterminated string runs to the end of the command, which is what the
/// scanner already believes about it — see
/// `an_unterminated_quote_protects_the_rest_of_the_command` — so the
/// highlight and the segmentation agree about how far the string reaches
/// rather than each having a view.
fn quoted_strings(command: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut open: Option<usize> = None;
    for c in scan(command) {
        // A quote inside a comment opens nothing, because the shell never
        // reads it. Without this, `echo # it's fine` would open a string at
        // the apostrophe and run it to the end of the command, and the
        // highlight would cross a comment it has no business being inside.
        //
        // A quote inside a here-document's data opens nothing for the same
        // reason and with one more consequence: a body can only begin where
        // the scanner reads a real newline, which is in `Normal` quoting, and
        // nothing inside it changes that -- so no string can start in a body
        // and none can span one. That is what keeps a `Quoted` region from
        // ever landing on top of the delimiter line's, and two overlapping
        // regions have no honest drawing.
        // A quote inside a command substitution belongs to the scan of the
        // interior, which finds it there and marks it there. Marking it twice
        // is what this skip prevents, and two regions on one range have no
        // honest drawing.
        if c.escaped || c.comment || c.here.is_some() || c.nesting > 0 {
            continue;
        }
        match (open, c.quoting, c.ch) {
            (None, Quoting::Normal, '\'' | '"') => open = Some(c.offset),
            (Some(start), Quoting::Single, '\'') | (Some(start), Quoting::Double, '"') => {
                out.push(start..c.offset + c.ch.len_utf8());
                open = None;
            }
            _ => {}
        }
    }
    if let Some(start) = open {
        out.push(start..command.len());
    }
    out
}

/// The byte range of every comment in `command`, the `#` included and the
/// newline excluded, in source order.
///
/// Read straight off the scanner's own flag rather than searched for a second
/// time: [`Scan`] has to know where a comment is anyway, because [`boundaries`]
/// and [`references`] both have to stop at one, and a second definition here
/// is how the colour on screen comes to disagree with the boundaries drawn
/// under it.
///
/// A run rather than a search for the terminating newline: the flag is false
/// on the newline itself — see [`Scan`] — so the run ends exactly where the
/// comment does, with no offset arithmetic to get wrong at either end.
fn comments(command: &str) -> Vec<Range<usize>> {
    let mut out: Vec<Range<usize>> = Vec::new();
    for c in scan(command) {
        // A comment inside a command substitution is the interior's, found
        // and marked by the scan of the interior -- the same skip
        // [`quoted_strings`] makes and for the same reason.
        if !c.comment || c.nesting > 0 {
            continue;
        }
        let end = c.offset + c.ch.len_utf8();
        match out.last_mut() {
            Some(last) if last.end == c.offset => last.end = end,
            _ => out.push(c.offset..end),
        }
    }
    out
}

/// The byte range of every redirection operator and every redirection target
/// in `command`, in source order and paired with which it is.
///
/// Read straight off the scanner's own flag, exactly as [`comments`] is, and
/// for the same reason: [`boundaries`] and [`is_word_break`] already have to
/// stop at a redirection, and a second definition here is how the colour on
/// screen comes to disagree with the boundaries drawn under it.
///
/// Adjacent characters of the same half are one run. Two operators with
/// nothing between them -- `>><` -- therefore arrive as one run rather than
/// two, which is a distinction with no drawing behind it and a command bash
/// refuses to parse in the first place.
fn redirections(command: &str) -> Vec<(Range<usize>, Redirect)> {
    let mut out: Vec<(Range<usize>, Redirect)> = Vec::new();
    for c in scan(command) {
        let Some(half) = c.redirect else {
            continue;
        };
        let end = c.offset + c.ch.len_utf8();
        match out.last_mut() {
            Some((last, kind)) if last.end == c.offset && *kind == half => last.end = end,
            _ => out.push((c.offset..end, half)),
        }
    }
    out
}

/// The byte range of every here-document terminating line in `command`, the
/// newline that ends the line excluded, in source order.
///
/// Read off the scanner's flag, exactly as [`comments`] and [`redirections`]
/// are, and for the reason all three are: the passes that stop at a
/// here-document have to stop at the same bytes the colour is drawn on.
///
/// The line is drawn as a redirection because that is what it is. `<<EOF` is
/// an operator whose word is `EOF`, already marked as a redirection target,
/// and the line that ends the body is that same word again closing what the
/// operator opened -- which is how a reader finds the end of a body in the
/// first place. Giving it a colour of its own would be a second name for one
/// fact, and giving it none would leave the block with a marked top and an
/// unmarked bottom.
///
/// The two ends are not always the same colour, and the reason is a rule that
/// was already here: [`regions`] declines a redirection target carrying a
/// quote character, so the `'EOF'` of `<<'EOF'` is drawn as the quoted string
/// it is and the line that ends the body is drawn as the delimiter. Both are
/// marked, which is what the block needs; what a quoted delimiter costs is
/// that they are marked as two different true things.
fn delimiter_lines(command: &str) -> Vec<Range<usize>> {
    let mut out: Vec<Range<usize>> = Vec::new();
    for c in scan(command) {
        // The newline is left out: it is the end of the line rather than part
        // of it, and it is drawn as a chip either way.
        if c.here != Some(Here::Delimiter) || c.ch == '\n' {
            continue;
        }
        let end = c.offset + c.ch.len_utf8();
        match out.last_mut() {
            Some(last) if last.end == c.offset => last.end = end,
            _ => out.push(c.offset..end),
        }
    }
    out
}

/// One command substitution's interior, and whether the substitution is
/// inside a quoted string.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Substitution {
    /// The bytes between the delimiters: the `podman ps` of `$(podman ps)`
    /// and of `` `podman ps` ``. Real shell, and a command of its own, so it
    /// is handed to a fresh scan rather than read at this level.
    interior: Range<usize>,
    /// True when the `$(` or the backtick that opened it is inside `"…"`.
    ///
    /// One pass acts on this and the other does not, which is the same split
    /// [`claimable`] and [`readable_name`] already make about a quoted word.
    /// [`invoked`] is choosing a *name* and follows a substitution either
    /// way, because `echo "$(podman ps)"` runs `podman` whichever quotes are
    /// around it. [`regions`] is choosing a *byte range to colour*, and the
    /// range it would colour is inside a `Quoted` one -- two regions on one
    /// range have no honest drawing, so it leaves the string to be drawn as
    /// the string it is.
    quoted: bool,
}

/// The interior of every command substitution in `command` that is not inside
/// another one, in source order.
///
/// Read straight off the scanner's own depth, exactly as [`comments`] and
/// [`redirections`] are read off its flags, and for the reason all three are:
/// the passes that step over a substitution have to step over the same bytes
/// the interior is taken from. A run of characters at a non-zero depth is one
/// interior with its delimiters excluded -- see [`Scanned::nesting`], which is
/// why the delimiters carry the depth around them -- so `$(a)$(b)` is two
/// runs and `$(a $(b) c)` is one.
///
/// An unterminated substitution runs to the end of the command, which is what
/// the scanner already believes about it and what it believes about an
/// unterminated string. The empty `$()` yields nothing, because there is no
/// run and there is no command in it either.
fn substitutions(command: &str) -> Vec<Substitution> {
    let mut out: Vec<Substitution> = Vec::new();
    for c in scan(command) {
        if c.nesting == 0 {
            continue;
        }
        let end = c.offset + c.ch.len_utf8();
        match out.last_mut() {
            Some(last) if last.interior.end == c.offset => last.interior.end = end,
            // The quoting at the first character of the interior is the
            // quoting the substitution opened in: the `$(` cannot have
            // changed it, and nothing inside has been read yet.
            _ => out.push(Substitution {
                interior: c.offset..end,
                quoted: c.quoting != Quoting::Normal,
            }),
        }
    }
    out
}

/// Every region [`highlight`] wants to mark, in source order and never
/// overlapping.
fn regions(command: &str) -> Vec<(Range<usize>, SpanKind)> {
    let mut out = Vec::new();
    regions_into(command, 0, 0, &mut out);
    out.sort_by_key(|(range, _)| range.start);
    out
}

/// [`regions`] for one command, appending to `out` with every range shifted
/// by `offset`, `depth` substitutions deep and unsorted.
///
/// The recursion is what draws the interior of a `$(…)`. It is the same shape
/// [`invoke_into`] uses to follow a `bash -c` script and it is bounded the
/// same way, by [`SCRIPT_DEPTH`]: the command is the agent's, and `$(` costs
/// it two bytes to nest one level further.
///
/// A substitution inside a quoted string is not followed -- see
/// [`Substitution::quoted`] for why that is this pass's answer and not
/// [`invoked`]'s -- and the regions from one that is cannot overlap anything
/// at this level, because every pass here steps over an interior and
/// [`claimable`] declines the word that holds one.
fn regions_into(
    command: &str,
    offset: usize,
    depth: usize,
    out: &mut Vec<(Range<usize>, SpanKind)>,
) {
    let shift = |range: Range<usize>| range.start + offset..range.end + offset;
    let scanned: Vec<Scanned> = scan(command).collect();
    let mut at = 0;
    out.extend(
        segments(command)
            .iter()
            .filter_map(|segment| command_word(command, &scanned, &mut at, segment))
            .map(|word| (shift(word), SpanKind::Command)),
    );
    out.extend(quoted_strings(command).into_iter().map(|range| (shift(range), SpanKind::Quoted)));
    out.extend(comments(command).into_iter().map(|range| (shift(range), SpanKind::Comment)));
    // Both halves of a redirection, in the one kind: see [`Redirect`] for why
    // the destination is marked as loudly as the arrow and why it is marked
    // the same. A target carrying a quote character is declined, which is the
    // move `claimable` makes for a command word and is here for the identical
    // reason -- a quoted word extends to include its quotes, so claiming
    // `> "my file"`'s target would put a `Redirect` region exactly on top of
    // a `Quoted` one, and two overlapping regions have no honest drawing. The
    // operator in front of it is marked either way, so what the refusal costs
    // is a colour on the path and never the sight of the arrow.
    let marked = redirections(command).into_iter().filter(|(range, half)| {
        *half == Redirect::Operator || !command[range.clone()].contains(['\'', '"'])
    });
    out.extend(marked.map(|(range, _)| (shift(range), SpanKind::Redirect)));
    // The line that closes a here-document, in the kind that opened it. It
    // cannot overlap anything above: a body has no words and no strings in it,
    // and no redirection is recognised inside one.
    out.extend(
        delimiter_lines(command).into_iter().map(|range| (shift(range), SpanKind::Redirect)),
    );
    if depth + 1 >= SCRIPT_DEPTH {
        return;
    }
    for nested in substitutions(command).into_iter().filter(|nested| !nested.quoted) {
        let interior = nested.interior;
        regions_into(&command[interior.clone()], offset + interior.start, depth + 1, out);
    }
}

/// Mark the word that names what runs, and the quoted strings, so the
/// annotated pane shows structure rather than the raw pane with line breaks
/// in it.
///
/// The last pass in [`super::render_command`], and it has to be last: it
/// claims spans, and [`annotate_variables`] leaves a claimed span alone, so
/// running it earlier would cost every `$NAME` inside a command word or a
/// double-quoted string its resolved value. A value is information; a colour
/// is decoration, and the pass that produces decoration yields.
///
/// # A refinement, and only of what nobody else has claimed
///
/// It subdivides `Plain` spans and re-emits every other kind exactly as it
/// found it, so a chip stays a chip, a separator stays a separator and a
/// `$HOME` inside `"…"` keeps its value. A region that straddles such a span
/// — a quoted string with a chip in it — is drawn on the plain parts either
/// side and simply does not cover the chip, which is the right answer: the
/// chip is louder than the highlight and has more to say.
///
/// Walking into a fresh [`SpanBuilder`] rather than calling [`Spans::split`]
/// per region, for the reason [`annotate_variables`] gives at length: split
/// copies both halves' text, and the number of regions is chosen by the
/// agent.
///
/// # Panics
///
/// If the spans do not tile the source, which would be a bug here or in the
/// scanner. A panicking prompt window is a dead prompt window, and hatch
/// treats that as a denial, so failing this way fails closed.
pub fn highlight(spans: Spans) -> Spans {
    let source = spans.source();
    let regions = regions(source);
    let mut builder = SpanBuilder::new(source);
    let mut next = 0;

    for span in spans.iter() {
        if span.break_before() {
            builder.break_next();
        }
        let range = span.range();
        // Regions that ended before this span began are finished with. This
        // is the only place `next` moves, so a region cannot be skipped by
        // one path and re-drawn by another.
        next += regions[next..].partition_point(|(region, _)| region.end <= range.start);

        let rest = match span.kind() {
            // Every region reaching into this span, clipped to it. At most
            // one of them runs past the end, because the region after that
            // one would have to start past the end too, so `take_while` ends
            // the walk exactly there and the next span picks that region up
            // where this one left off.
            SpanKind::Plain => {
                let reaching =
                    regions[next..].iter().take_while(|(region, _)| region.start < range.end);
                for (region, kind) in reaching {
                    builder.push_to(region.start.max(range.start), SpanKind::Plain);
                    builder.push_to(region.end.min(range.end), kind.clone());
                }
                SpanKind::Plain
            }
            // A span another pass has claimed keeps its kind, and any region
            // inside it is simply not drawn.
            kind => kind.clone(),
        };
        builder.push_to(range.end, rest);
    }

    builder.finish()
}

// ---- what the command will actually run ------------------------------------

/// One word in command position, as the text says it.
///
/// Deliberately three answers and not two. A pass that could only say *this
/// name* would have to invent one for `sudo -X ls`, where the argument
/// grammar ran out before the command did, and inventing one there means
/// naming the wrong executable -- which is worse than naming none, because
/// the whole value of the list is that a reader can stop scanning the command
/// once they have read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invocation {
    /// A word hatch reads as the name of what runs.
    Named(String),
    /// A command word hatch will not read a name out of, kept as the text it
    /// is: `$TOOL`, `"$@"`, `*.sh`. The shell expands or matches it and hatch
    /// expands and matches nothing, so the name is not knowable from the text
    /// the reader is being shown.
    Unread(String),
    /// A wrapper hatch could not see past, named by the wrapper. Its own
    /// argument grammar ran out before its command did, so what it runs is
    /// not in the list and the list says so.
    Behind(String),
}

/// What one command puts in command position, and what it defines for itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Invoked {
    /// Everything in command position, in source order and with repeats. The
    /// repeats are the point: `grep ... | grep ... | grep ...` is three
    /// entries here and one line with a count on it by the time a reader sees
    /// it.
    pub runs: Vec<Invocation>,
    /// The names of shell functions this very command defines.
    ///
    /// Carried because a function is the one name that resolves to nothing on
    /// disk and is not missing. `deploy() { rm -rf build; }; deploy` would
    /// otherwise put `deploy` on screen as a name that does not resolve,
    /// which is a warning about the most ordinary thing a script does.
    pub defines: BTreeSet<String>,
}

/// How deep a command inside a command is followed.
///
/// `bash -c '…'` inside `bash -c '…'` is a real thing an agent can write and
/// a real thing hatch itself produces one level of, and each level is a fresh
/// scan of a string the level above it holds. Four is far past anything
/// legible and is a number rather than a stack.
///
/// A `$(…)` is the same shape and is bounded by the same number, and here the
/// bound is load-bearing rather than tidy: the command is the agent's, and
/// `$(` buys a level of nesting for two bytes. Without a cap, a page of them
/// would be a page of recursion in a process whose job is to put a window on
/// screen, and a prompt window that dies is a denial.
const SCRIPT_DEPTH: usize = 4;

/// Everything `command` puts in command position, wrappers unwrapped.
///
/// # Which word is the command
///
/// The first word of a segment that is neither a variable assignment nor a
/// redirection. Both halves of that are somebody else's answer already:
/// [`is_word_break`] excludes a redirection from every word, which is what
/// makes `>out.txt cat` name `cat`, and [`is_assignment`] is the rule that
/// makes `FOO=1 ls` name `ls`. This pass adds no third notion of where a
/// command begins -- it asks [`words`], which is what [`command_word`] asks,
/// so the word underlined in the pane is the word this list is built from.
///
/// # Wrappers
///
/// A wrapper is a program whose own arguments end with another program's
/// name, and the answer to *what does this run* is both of them. See
/// [`WRAPPERS`] for the set and for each one's grammar, and [`past`] for what
/// happens when the grammar runs out: nothing is guessed, the wrapper is
/// named, and the reader is told that what is behind it was not read.
///
/// # The shell's own vocabulary
///
/// A reserved word is structure rather than a program, so `if`, `then` and
/// `{` are recognised and are **not** listed -- see [`is_keyword`]. What they
/// do contribute is a place to keep looking: the word after `if` is a command
/// and would otherwise be missed. A builtin *is* listed, because `cd` and
/// `echo` really are things the command runs; what they are not is things
/// that resolve to a file, which is [`super::roster`]'s distinction to draw.
///
/// # Linear in the command, and the command is the agent's
///
/// Every walk here moves forward only: [`words`] carries one cursor through
/// the whole scan, and a wrapper hop lands on a word strictly further along
/// than the one it started from. The tail a hop hands to [`past`] is a slice
/// of ranges rather than a fresh list of strings, which is the difference
/// that matters -- `sudo ` repeated twenty thousand times is a command an
/// agent can write, and collecting the tail per hop would be quadratic in a
/// number it chooses. Measured in release: twenty thousand wrapper hops in
/// 5.1 ms and a twenty-thousand-stage pipeline in 8.4 ms, against 0.35 ms for
/// a thousand hops.
///
/// # Command substitution, which is followed
///
/// `$(…)` and `` `…` `` hold a command, and the answer to *what does this
/// run* includes it: `echo "$(podman ps -q)"` runs both `echo` and `podman`.
/// The interior is handed to a scan of its own by [`substitutions`] and this
/// pass recurses into it, exactly as it recurses into a `bash -c` script and
/// with the same [`SCRIPT_DEPTH`] bound on how far down it will follow.
///
/// It is followed whether or not the substitution is inside quotes, because
/// the quotes change nothing about what runs -- the difference the pane makes
/// there is about which bytes may carry a colour, and is written down on
/// [`Substitution::quoted`]. `echo $(podman ps)` and `echo "$(podman ps)"`
/// give the same two names, which is the point: a reader cannot be expected
/// to know that one pair of quotes hides a program from the list.
///
/// # Where it stops
///
/// Inside a subshell, inside a `case` branch, and inside any of the other
/// constructs the module docs list as outside [`Scan`]'s model. Those are
/// under-reports -- a command hatch does not list is a command the reader
/// still sees in the pane -- and they are the same gaps every other pass in
/// this module has, for the same reason: one scanner, one model.
///
/// A here-document body is not one of them, and used to be. Nothing in a body
/// is listed because nothing in a body runs: the shell hands it to the command
/// on stdin. That is not silence about a command, it is the absence of one,
/// and before [`Scan`] knew where a body was it was the loudest wrong answer
/// this list gave -- every first word of every line of a config file, reported
/// as a program nothing on the `PATH` answers to.
///
/// Two of them are worth naming because a reader might expect otherwise. A
/// subshell -- `(cd /tmp && rm x)` -- and a `case` branch both put their
/// commands behind a parenthesis, which is a metacharacter this pass does not
/// segment on, so the segment those live in contributes **nothing** rather
/// than contributing a wrong name. Silence is chosen over a finding there
/// because the alternative is a warning on two entirely ordinary constructs,
/// and the parentheses are on screen in the panes either way.
pub fn invoked(command: &str) -> Invoked {
    let mut out = Invoked::default();
    invoke_into(command, &mut out, 0);
    out
}

/// [`invoked`], accumulating into `out`, `depth` nested commands deep.
///
/// # Source order across two levels
///
/// A segment's substitutions are reported around the word that names what the
/// segment runs, in the order they are written: the `date` of
/// `A=$(date) make` comes before `make` and the `podman` of
/// `echo "$(podman ps)"` comes after `echo`. That is the order they are on
/// screen in, which is the order the panes draw and the order the underlines
/// come out in, so the roster and the pane cannot be read as disagreeing
/// about which command came first.
///
/// The one place the two orders part is a wrapper: `sudo $(x) foo` names
/// `sudo`, then `foo` -- the wrapper hop reaches the word it runs before this
/// pass gets back to the substitution -- and the pane underlines `sudo`, `x`
/// and `foo` as they lie. Nothing is missing from either, and the wrapper is
/// the construct where the reader is already being told the second name came
/// from following the first.
fn invoke_into(command: &str, out: &mut Invoked, depth: usize) {
    if depth >= SCRIPT_DEPTH {
        return;
    }
    let scanned: Vec<Scanned> = scan(command).collect();
    let nested = substitutions(command);
    let mut next = 0;
    let mut at = 0;
    for segment in segments(command) {
        let words = words(&scanned, &mut at, &segment);
        // Every substitution lies inside one segment, because a separator
        // inside one is not a boundary at this level -- see [`boundaries`] --
        // so this cursor walks each of them once and in order.
        let here = nested[next..].partition_point(|nested| nested.interior.start < segment.end);
        let here = &nested[next..next + here];
        next += here.len();
        // Where the word that names what this segment runs begins, which is
        // where a substitution stops being in front of it. A segment of
        // nothing but assignments -- `x=$(podman ps -q)` -- has no such word,
        // and everything in it is in front of the nothing that follows.
        let begins = command_at(command, &words).map_or(segment.end, |word| words[word].start);
        let ahead = here.partition_point(|nested| nested.interior.start < begins);
        for nested in &here[..ahead] {
            invoke_into(&command[nested.interior.clone()], out, depth + 1);
        }
        walk(command, &words, out, depth);
        for nested in &here[ahead..] {
            invoke_into(&command[nested.interior.clone()], out, depth + 1);
        }
    }
}

/// Follow one segment from its command word through however many wrappers it
/// names, adding what it finds to `out`.
///
/// The index only ever moves forward -- every arm either returns or lands on
/// a word strictly further along -- so a wrapper that names itself
/// (`sudo sudo sudo ls`) walks to the end of the words and stops there rather
/// than needing a depth count of its own.
fn walk(command: &str, words: &[Range<usize>], out: &mut Invoked, depth: usize) {
    let text = |word: &Range<usize>| &command[word.clone()];
    // `FOO=1 BAR=2 ls` runs `ls`, and every wrapper that takes assignments
    // takes them in the same place, so this is the same skip [`past`] makes.
    let mut index = command_at(command, words).unwrap_or(words.len());

    loop {
        let Some(word) = words.get(index) else { return };
        // A definition is not a run. `deploy() { … }` puts `deploy` in
        // command position and does not execute it, and the `{` after it
        // carries on into the body, so the body's own commands are found.
        if let Some(name) = defined_here(text(word), words.get(index + 1).map(text)) {
            out.defines.insert(name);
            index += 1;
            continue;
        }
        // Shell structure this pass says nothing about: the `(` of a
        // subshell, the `)` that closes one, the pattern of a `case` branch,
        // and either spelling of a command substitution -- whose own commands
        // have already been reported at their own level. See [`STRUCTURE`],
        // which is where the refusal is argued and which [`claimable`] reads
        // too, so the pane declines exactly the words this does.
        if text(word).contains(STRUCTURE) {
            return;
        }
        let Some(name) = readable_name(text(word)) else {
            out.runs.push(Invocation::Unread(text(word).to_string()));
            return;
        };
        // A reserved word is syntax, not a program: see [`invoked`]. It is
        // still looked up below, because half of them are the reason there is
        // another command word further along the segment.
        if !is_keyword(&name) {
            out.runs.push(Invocation::Named(name.clone()));
        }
        let Some(wrapper) = WRAPPERS.iter().find(|w| w.name == name) else { return };
        // The remaining words as a slice of ranges rather than as a fresh
        // vector of strings. A command of `sudo ` repeated is agent-writable
        // and hops once per `sudo`, so collecting the tail at every hop would
        // be quadratic in something the agent chooses -- the same trap
        // `command_word`'s cursor is written around.
        let rest = &words[index + 1..];
        match past(command, wrapper, rest) {
            Step::Command(ahead) => index += 1 + ahead,
            Step::Script(ahead) => {
                // The one place this pass reads text that is not laid out in
                // front of the reader as a command: the argument to `-c` is
                // one word on screen, and what is in it is a command line.
                // Only a word whose characters stand for themselves is
                // followed -- see [`literal_word`] -- so `bash -c "$SCRIPT"`
                // is reported as a wrapper hatch could not see past rather
                // than as a script with nothing in it.
                match literal_word(text(&rest[ahead])) {
                    Some(script) => invoke_into(&script, out, depth + 1),
                    None => out.runs.push(Invocation::Behind(name)),
                }
                return;
            }
            Step::Nothing => return,
            Step::Lost => {
                out.runs.push(Invocation::Behind(name));
                return;
            }
        }
    }
}

/// The name of the function a word in command position defines, if it defines
/// one.
///
/// `deploy() {`, `deploy () {` and `deploy()` are the three spellings that
/// reach here as one word or two, and all three mean the same thing: the name
/// is being bound, not run. `next` is the word after it, because the space in
/// `deploy ()` puts the parentheses in a word of their own.
///
/// The `function` keyword's spelling — `function deploy { … }` — is
/// deliberately not recognised, and costs an entry in [`Invoked::defines`]
/// rather than a wrong one: `function` is a reserved word, so it is not
/// listed, and the walk stops there rather than reading `deploy` as something
/// that runs.
fn defined_here(word: &str, next: Option<&str>) -> Option<String> {
    let name = match word.find("()") {
        Some(at) => &word[..at],
        None if next.is_some_and(|next| next.starts_with('(')) => word,
        None => return None,
    };
    (!name.is_empty()
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(is_name_char))
    .then(|| name.to_string())
}

/// The name a word stands for, or `None` when it stands for something else.
///
/// Quoting is removed, because `'ls' -l` runs `ls` and a list that said
/// otherwise would be under-reporting for a reason the reader cannot see.
/// That is a different answer from [`claimable`]'s, which declines a quoted
/// word — and the difference is deliberate. `claimable` is choosing a *byte
/// range to colour*, and a range that included the quotes would be a
/// `Command` region lying on top of a `Quoted` one; this is choosing a
/// *name*, has no range and no colour, and nothing to overlap.
///
/// What is still declined is a word that stands for something the shell works
/// out and hatch does not: a parameter (`$TOOL`), a substitution, a glob
/// (`*.sh`), a brace expansion and a `~` at the front. Each of those names a
/// program hatch would have to expand, match or run something to learn, and
/// the direction this module is wrong in is the direction that names nothing.
///
/// The shell's own punctuation is the exception, and it has to be: `[` is a
/// builtin and `[[`, `{` and `}` are reserved words, and every one of them is
/// made of characters that are pattern syntax anywhere else. They are matched
/// whole, so `[abc]ls` is still a glob and still declined.
fn readable_name(word: &str) -> Option<String> {
    let text = literal_word(word)?;
    if text.is_empty() {
        return None;
    }
    if PUNCTUATION.contains(&text.as_str()) {
        return Some(text);
    }
    match text.starts_with('~') || text.contains(['*', '?', '[', ']', '{', '}']) {
        true => None,
        false => Some(text),
    }
}

/// The words of the shell's vocabulary that are made of punctuation, so that
/// [`readable_name`] does not read them as patterns.
const PUNCTUATION: &[&str] = &["[", "[[", "{", "}", ":", "!", ".", "]]"];

/// What a word means once quoting and escaping are removed, or `None` when
/// hatch cannot say.
///
/// The shell's rules for the three constructs it models, and a refusal for
/// everything else. `'…'` holds its contents exactly, a backslash outside
/// quotes makes the next character itself, and any other character is itself.
/// A `"`, a `$` or a backtick returns `None`: what is inside a double-quoted
/// string can still expand, and a word that expands is a word whose value is
/// not on screen.
///
/// This is an *unquoting*, which is the one thing the rendering passes in this
/// module are forbidden to do — every one of them is additive, and none of
/// them may remove a character to make room for anything. The rule is not
/// broken here because nothing this produces is drawn in place of the
/// command: the panes still draw every byte as itself, and what comes out of
/// this is a name for a list beside them. The list says where a name resolves;
/// the command says what the characters are.
fn literal_word(word: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = word.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                let mut closed = false;
                for c in chars.by_ref() {
                    if c == '\'' {
                        closed = true;
                        break;
                    }
                    out.push(c);
                }
                // An unterminated string is a command bash refuses to run at
                // all, so there is no name in it to find.
                if !closed {
                    return None;
                }
            }
            // The next character, whatever it is. A trailing backslash has no
            // next character and is the same refusal. A newline is the
            // exception and is the one character a backslash does not stand
            // in front of: the pair is a line continuation, which the shell
            // removes before it reads the word, so `ec\`+newline+`ho` is the
            // name `echo` and not a name with a newline in the middle of it.
            '\\' => match chars.next()? {
                '\n' => {}
                escaped => out.push(escaped),
            },
            '"' | '$' | '`' => return None,
            _ => out.push(c),
        }
    }
    Some(out)
}

// ---- wrappers --------------------------------------------------------------

/// One program whose own arguments end in another program's name.
///
/// Every field exists because getting it wrong names the **wrong**
/// executable, which is the one failure this list must not have: a reader who
/// has been told a command runs `ls` stops looking for what it really runs.
/// So each wrapper carries its own option grammar rather than sharing a
/// guess, and [`past`] refuses anything the grammar does not cover.
struct Wrapper {
    /// The word in command position.
    name: &'static str,
    /// Options that take no value.
    solo: &'static [&'static str],
    /// Options whose value is the next word, or is glued on after an `=` or
    /// straight onto a short option (`-n5`).
    valued: &'static [&'static str],
    /// Whether `NAME=value` words before the command belong to its grammar.
    /// `env FOO=1 ls` and `sudo FOO=1 ls` both run `ls`.
    assignments: bool,
    /// Words that are neither options nor the command, before the command.
    /// One, for `timeout`'s duration; none for everything else.
    positionals: usize,
    /// Whether `--` ends its options.
    dashdash: bool,
    /// The option whose value is a script rather than a program name.
    script: Option<&'static str>,
    /// What the first word that is not an option is.
    after: After,
}

/// What the first non-option word of a wrapper's arguments turns out to be.
#[derive(Clone, Copy, PartialEq, Eq)]
enum After {
    /// The command it runs: `sudo ls`, `env ls`, `nice ls`.
    Command,
    /// Not a command at all. `bash script.sh` runs a *file*, and what is in
    /// the file is not on screen — so the walk stops and says nothing rather
    /// than naming the script as though it were a program.
    Nothing,
}

/// The wrappers, and the reserved words that behave like them.
///
/// Two kinds in one table because the walk asks them one question: *is there
/// another command word further along this segment, and where?* `sudo` and
/// `if` answer it the same way and differ only in what is drawn, which is
/// [`is_keyword`]'s business rather than this table's.
///
/// # What is missing from each grammar, and why that is safe
///
/// Every option list here is a **whitelist**, and [`past`] gives up on
/// anything not in it. That is the whole safety argument: an option hatch has
/// not heard of might take a value, and skipping one word where two were
/// wanted lands on an argument and calls it a program. So the lists are short
/// on purpose and the cases they do not cover come out as
/// [`Invocation::Behind`], which says *hatch did not read this* in the window
/// rather than saying something false.
///
/// Three deliberate omissions are worth naming, because each looks like an
/// oversight:
///
/// * `sudo -i`, `sudo -s` and `doas -s` start a **shell**, and the words
///   after them are a command line for that shell rather than an argv. They
///   are left out, so they are read as an option hatch does not know and the
///   wrapper is reported as unread.
/// * `env -S 'cmd arg'` splits its own string into an argv. Same shape, same
///   answer.
/// * `command -v` and `command -V` do not run their argument at all, they
///   print where it is. Listing what they name would be reporting a program
///   as running when nothing runs, so they are left out too.
///
/// `nice -5` — the adjustment written as the option — is the other one. There
/// is no way to tell it from an option this table has not heard of, so it is
/// read as one.
const WRAPPERS: &[Wrapper] = &[
    Wrapper {
        name: "sudo",
        solo: &[
            "-A", "--askpass", "-b", "--background", "-E", "--preserve-env", "-H", "--set-home",
            "-k", "--reset-timestamp", "-n", "--non-interactive", "-P", "--preserve-groups",
            "-S", "--stdin",
        ],
        valued: &[
            "-C", "--close-from", "-D", "--chdir", "-g", "--group", "-h", "--host", "-p",
            "--prompt", "-R", "--chroot", "-T", "--command-timeout", "-u", "--user",
        ],
        assignments: true,
        positionals: 0,
        dashdash: true,
        script: None,
        after: After::Command,
    },
    Wrapper {
        name: "doas",
        solo: &["-n", "-L"],
        valued: &["-a", "-C", "-u"],
        assignments: false,
        positionals: 0,
        dashdash: false,
        script: None,
        after: After::Command,
    },
    Wrapper {
        name: "run0",
        solo: &[
            "--pipe", "--pty", "-P", "--no-ask-password", "--quiet", "-q", "--no-pager",
        ],
        valued: &[
            "-u", "--user", "-g", "--group", "-M", "--machine", "-E", "--setenv", "-p",
            "--property", "-D", "--chdir", "--nice", "--background", "--unit", "--slice",
            "--description",
        ],
        assignments: false,
        positionals: 0,
        dashdash: true,
        script: None,
        after: After::Command,
    },
    Wrapper {
        name: "env",
        solo: &["-i", "--ignore-environment", "-0", "--null", "-v", "--debug"],
        valued: &["-u", "--unset", "-C", "--chdir"],
        assignments: true,
        positionals: 0,
        dashdash: true,
        script: None,
        after: After::Command,
    },
    Wrapper {
        name: "nice",
        solo: &[],
        valued: &["-n", "--adjustment"],
        assignments: false,
        positionals: 0,
        dashdash: true,
        script: None,
        after: After::Command,
    },
    Wrapper {
        name: "ionice",
        solo: &["-t", "--ignore"],
        valued: &["-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid", "-u",
                  "--uid"],
        assignments: false,
        positionals: 0,
        dashdash: true,
        script: None,
        after: After::Command,
    },
    Wrapper {
        name: "nohup",
        solo: &[],
        valued: &[],
        assignments: false,
        positionals: 0,
        dashdash: true,
        script: None,
        after: After::Command,
    },
    Wrapper {
        name: "setsid",
        solo: &["-c", "--ctty", "-f", "--fork", "-w", "--wait"],
        valued: &[],
        assignments: false,
        positionals: 0,
        dashdash: true,
        script: None,
        after: After::Command,
    },
    Wrapper {
        name: "stdbuf",
        solo: &[],
        valued: &["-i", "--input", "-o", "--output", "-e", "--error"],
        assignments: false,
        positionals: 0,
        dashdash: true,
        script: None,
        after: After::Command,
    },
    Wrapper {
        // The duration is the positional, and it is the whole reason this
        // field exists: `timeout 5 ls` runs `ls`, and a wrapper walk with no
        // notion of a positional would name `5`.
        name: "timeout",
        solo: &["--preserve-status", "--foreground", "-v", "--verbose"],
        valued: &["-s", "--signal", "-k", "--kill-after"],
        assignments: false,
        positionals: 1,
        dashdash: true,
        script: None,
        after: After::Command,
    },
    Wrapper {
        name: "xargs",
        solo: &[
            "-0", "--null", "-r", "--no-run-if-empty", "-t", "--verbose", "-x", "--exit", "-p",
            "--interactive", "--process-slot-var",
        ],
        valued: &[
            "-a", "--arg-file", "-d", "--delimiter", "-E", "-e", "--eof", "-I", "-i",
            "--replace", "-L", "-l", "--max-lines", "-n", "--max-args", "-P", "--max-procs",
            "-s", "--max-chars",
        ],
        assignments: false,
        positionals: 0,
        dashdash: true,
        script: None,
        after: After::Command,
    },
    Wrapper {
        // The reserved word, which is what a bare `time` is in command
        // position. `/usr/bin/time` is a different program with a different
        // grammar and is named by its path, so it is not this entry.
        name: "time",
        solo: &["-p"],
        valued: &[],
        assignments: false,
        positionals: 0,
        dashdash: false,
        script: None,
        after: After::Command,
    },
    Wrapper {
        name: "command",
        solo: &["-p"],
        valued: &[],
        assignments: false,
        positionals: 0,
        dashdash: true,
        script: None,
        after: After::Command,
    },
    Wrapper {
        name: "exec",
        // `-c` here is "with an empty environment" and is not a script flag,
        // which is why the script option is a field per wrapper and not a
        // constant.
        solo: &["-c", "-l"],
        valued: &["-a"],
        assignments: false,
        positionals: 0,
        dashdash: true,
        script: None,
        after: After::Command,
    },
    Wrapper {
        // The one wrapper whose command is a *string* rather than an argv,
        // and the one hatch itself writes: a `root: true` request is drawn as
        // `run0 … -- bash -c '<the approved command>'`, so without this entry
        // the list for every root request would be `run0` and `bash` and
        // nothing about the command the reader came to read.
        name: "bash",
        solo: &[
            "-l", "--login", "-i", "-e", "-u", "-x", "-v", "-n", "-p", "-r", "--norc",
            "--noprofile", "--posix",
        ],
        valued: &[],
        assignments: false,
        positionals: 0,
        dashdash: false,
        script: Some("-c"),
        after: After::Nothing,
    },
    Wrapper {
        name: "sh",
        solo: &["-l", "-i", "-e", "-u", "-x", "-v", "-n", "-p"],
        valued: &[],
        assignments: false,
        positionals: 0,
        dashdash: false,
        script: Some("-c"),
        after: After::Nothing,
    },
    // The reserved words that put a command after themselves. They have no
    // options and nothing to skip; what they contribute is that the walk
    // keeps going, so `if grep -q x f; then rm y; fi` lists `grep` and `rm`
    // rather than nothing at all.
    keyword("if"),
    keyword("then"),
    keyword("elif"),
    keyword("else"),
    keyword("while"),
    keyword("until"),
    keyword("do"),
    keyword("{"),
    keyword("!"),
    keyword("coproc"),
];

/// A reserved word that is followed by a command and nothing else.
const fn keyword(name: &'static str) -> Wrapper {
    Wrapper {
        name,
        solo: &[],
        valued: &[],
        assignments: false,
        positionals: 0,
        dashdash: false,
        script: None,
        after: After::Command,
    }
}

/// Where a wrapper's own command is, relative to the first of its arguments.
enum Step {
    /// The word this far along names the program the wrapper runs.
    Command(usize),
    /// The word this far along is a script to be read as a command line of
    /// its own.
    Script(usize),
    /// The wrapper runs nothing further that is on screen: it ran out of
    /// words (`env -i` alone), or what follows is a file rather than a
    /// program (`bash script.sh`).
    Nothing,
    /// hatch could not read the arguments, so it does not know where the
    /// command is and will not guess. See [`WRAPPERS`].
    Lost,
}

/// Walk a wrapper's arguments to whatever it runs.
///
/// `words` is everything after the wrapper's own name, as ranges into
/// `command`. Options first, then a wrapper's positionals, then the command — which is the shape every entry
/// in [`WRAPPERS`] has, because a program whose arguments do not have that
/// shape is one this table has no way to describe and so does not contain.
///
/// The walk gives up rather than skipping an option it does not recognise,
/// and that is the whole point of it. An unknown option might take a value:
/// skipping one word where two were wanted lands on that value and reports it
/// as the program, and a reader told a command runs `5` has been told
/// something false in a window whose only job is to be believed.
fn past(command: &str, wrapper: &Wrapper, words: &[Range<usize>]) -> Step {
    let mut index = 0;
    let mut positionals = wrapper.positionals;
    let mut options = true;

    while let Some(word) = words.get(index).map(|word| &command[word.clone()]) {
        if options {
            if wrapper.dashdash && word == "--" {
                options = false;
                index += 1;
                continue;
            }
            if wrapper.script == Some(word) {
                // The word after it, if there is one. `bash -c` with nothing
                // after it is a shell that runs nothing.
                return match index + 1 < words.len() {
                    true => Step::Script(index + 1),
                    false => Step::Nothing,
                };
            }
            if let Some(step) = option(wrapper, word) {
                match step {
                    Skip::One => index += 1,
                    Skip::Two => index += 2,
                    Skip::Unknown => return Step::Lost,
                }
                continue;
            }
            if wrapper.assignments && is_assignment(word) {
                index += 1;
                continue;
            }
            // Not an option and not an assignment, so the options are over
            // whether or not a `--` said so.
            options = false;
        }
        if positionals > 0 {
            positionals -= 1;
            index += 1;
            continue;
        }
        return match wrapper.after {
            After::Command => Step::Command(index),
            After::Nothing => Step::Nothing,
        };
    }
    Step::Nothing
}

/// How many words an option takes, or `None` when the word is not one.
enum Skip {
    /// The option and nothing else: a flag, or a value glued onto it.
    One,
    /// The option and the word after it.
    Two,
    /// A word that looks like an option and is not in this wrapper's
    /// grammar.
    Unknown,
}

/// Read one word as an option of `wrapper`.
///
/// `None` for a word that does not begin with `-`, which is the caller's cue
/// that the options are over. A bare `-` is not an option either: it is the
/// conventional name for standard input and is a perfectly ordinary argument.
fn option(wrapper: &Wrapper, word: &str) -> Option<Skip> {
    if !word.starts_with('-') || word == "-" {
        return None;
    }
    let known = |name: &str| match (wrapper.solo.contains(&name), wrapper.valued.contains(&name)) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    };
    if word.starts_with("--") {
        // `--setenv=PATH=/usr/bin` is one word: the head is the option and
        // everything after the first `=` is its value, so the option is
        // satisfied and the next word is not its value.
        return Some(match word.split_once('=') {
            Some((head, _)) => match known(head) {
                Some(_) => Skip::One,
                None => Skip::Unknown,
            },
            None => match known(word) {
                Some(true) => Skip::One,
                Some(false) => Skip::Two,
                None => Skip::Unknown,
            },
        });
    }
    Some(match known(word) {
        Some(true) => Skip::One,
        Some(false) => Skip::Two,
        // `-n5` and `-c2`: a short option with its value written onto it.
        // Only a *valued* option may carry one, and only the two-character
        // head is looked up, so a cluster of flags this table has not heard
        // of is still unknown rather than half-read.
        None => match word.is_char_boundary(2) && wrapper.valued.contains(&&word[..2]) {
            true => Skip::One,
            false => Skip::Unknown,
        },
    })
}

// ---- what the shell does for itself ----------------------------------------

/// bash's reserved words.
///
/// Recognised for two reasons and drawn for neither. They are the reason a
/// segment can have a command word further along than its first — see
/// [`WRAPPERS`] — and they are the reason `if` does not appear in the window
/// as a name that resolves to nothing. Reserved words are not programs, do
/// not resolve and are not listed.
const KEYWORDS: &[&str] = &[
    "!", "[[", "]]", "{", "}", "case", "coproc", "do", "done", "elif", "else", "esac", "fi",
    "for", "function", "if", "in", "select", "then", "time", "until", "while",
];

/// bash's builtins.
///
/// The list matters for one reason: **a builtin does not resolve to a path,
/// and that is not a signal.** `cd`, `echo`, `export` and `:` are the most
/// ordinary words in any command, and a list that marked them as *not found*
/// would put a warning on nearly every request — and a list that cries wolf
/// is a list nobody reads, which costs the reader the one case that was real.
///
/// Six of these are also files on disk: `echo`, `test`, `[`, `kill`, `printf`
/// and `pwd` exist in `/usr/bin` on an ordinary system. **The builtin wins**,
/// and hatch reports the builtin, because commands reach the shell as
/// `bash -c '<command>'` and bash looks for a builtin before it looks at
/// `PATH`. A window that named `/usr/bin/echo` would be naming a file that
/// will not be executed. The one way to reach the file is to name it —
/// `/usr/bin/echo` or `env echo` — and both of those are a different word in
/// command position, so both come out right without a special case.
///
/// Aliases are not here and need no entry: `bash -c` is non-interactive,
/// where `expand_aliases` is off, so an alias cannot change what a name means
/// in a command hatch runs.
const BUILTINS: &[&str] = &[
    ".", ":", "[", "alias", "bg", "bind", "break", "builtin", "caller", "cd", "command",
    "compgen", "complete", "compopt", "continue", "declare", "dirs", "disown", "echo", "enable",
    "eval", "exec", "exit", "export", "false", "fc", "fg", "getopts", "hash", "help", "history",
    "jobs", "kill", "let", "local", "logout", "mapfile", "popd", "printf", "pushd", "pwd",
    "read", "readarray", "readonly", "return", "set", "shift", "shopt", "source", "suspend",
    "test", "times", "trap", "true", "type", "typeset", "ulimit", "umask", "unalias", "unset",
    "wait",
];

/// Whether the shell reads `name` as one of its reserved words.
pub fn is_keyword(name: &str) -> bool {
    KEYWORDS.contains(&name)
}

/// Whether the shell runs `name` itself rather than looking for a file.
///
/// See [`BUILTINS`] for what this is guarding against and for the six names
/// that are both a builtin and a binary.
pub fn is_builtin(name: &str) -> bool {
    BUILTINS.contains(&name)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::render::{Span, unrender};

    /// Segmentation does not depend on the child environment, and most tests
    /// here are about segmentation. Shadowing keeps them reading as they did
    /// while still driving the real, fully wired pipeline.
    fn render_command(command: &str) -> Spans {
        crate::render::render_command(command, &BTreeMap::new())
    }

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// The whole pipeline, which is what the window actually shows. Preferred
    /// over `annotate_variables(render_command(..), ..)` everywhere the
    /// composition itself is not the subject: a test that drives the pass
    /// directly would keep passing if the pass were unwired.
    fn rendered(command: &str, env: &BTreeMap<String, String>) -> Spans {
        crate::render::render_command(command, env)
    }

    /// Deliberately driven through `render_command` rather than through
    /// `segment` directly. What has to be true is a property of what the user
    /// is shown, and a pass that is correct but unwired shows the user
    /// nothing.
    fn separators(spans: &Spans) -> Vec<&str> {
        spans
            .iter()
            .filter(|s| s.kind() == &SpanKind::Separator)
            .map(Span::text)
            .collect()
    }

    fn chips(spans: &Spans) -> Vec<char> {
        spans.iter().filter_map(Span::chip_codepoint).collect()
    }

    fn breaks(spans: &Spans) -> Vec<&str> {
        spans.iter().filter(|s| s.break_before()).map(Span::text).collect()
    }

    // --- separators are kept, and marked ----------------------------------

    #[test]
    fn separators_are_kept_and_marked() {
        let spans = render_command("a; b && c");
        assert_eq!(separators(&spans), vec![";", "&&"]);
        assert_eq!(unrender(&spans), "a; b && c", "and nothing was consumed by the layout");
    }

    #[test]
    fn every_separator_form_is_recognised() {
        assert_eq!(separators(&render_command("a; b")), vec![";"]);
        assert_eq!(separators(&render_command("a && b")), vec!["&&"]);
        assert_eq!(separators(&render_command("a || b")), vec!["||"]);
        assert_eq!(separators(&render_command("a | b")), vec!["|"]);
    }

    #[test]
    fn the_longest_separator_wins() {
        // `&&` must not be read as two tokens, and `||` must not be read as
        // two pipes. A shorter match here would double the apparent number of
        // command boundaries.
        assert_eq!(separators(&render_command("a && b || c | d")), vec!["&&", "||", "|"]);
        assert_eq!(unrender(&render_command("a && b || c | d")), "a && b || c | d");
    }

    #[test]
    fn separator_table_is_longest_first() {
        // The whole of the longest-match rule: the first entry that matches
        // wins, so nothing may be preceded by a token it starts with.
        for window in SEPARATORS.windows(2) {
            assert!(
                window[0].len() >= window[1].len(),
                "{:?} is listed before the longer {:?}, so it would match first",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn a_separator_is_never_left_plain() {
        // The properties in tests/fidelity.rs are blind to under-tagging: a
        // separator drawn as Plain round-trips perfectly and hides nothing.
        // This test is the only thing that requires the tagging at all.
        let spans = render_command("a; b");
        let semicolon = spans.iter().find(|s| s.text() == ";").expect("the separator survives");
        assert_eq!(semicolon.kind(), &SpanKind::Separator);
    }

    // --- layout is metadata on the following span -------------------------

    #[test]
    fn a_break_is_requested_after_each_separator() {
        let spans = render_command("a; b");
        assert_eq!(spans.len(), 4, "a, the separator, the space, and b");
        assert_eq!(spans[1].text(), ";");
        assert!(!spans[1].break_before(), "layout never lands on the separator itself");
        assert_eq!(spans[2].text(), " ", "and no whitespace is trimmed to tidy the line");
        assert!(!spans[2].break_before(), "the blanks stay on the line the separator ends");
        assert!(spans[3].break_before(), "the break lands where the next command starts");
        assert_eq!(spans[3].text(), "b");
    }

    #[test]
    fn every_separator_that_ends_a_line_gets_a_break_after_it() {
        // Nothing is trimmed on either side of a boundary, and the break
        // lands where the next command starts rather than on the blanks in
        // front of it. Those blanks are still drawn -- at the end of the line
        // their separator ends, where they are not read as an indent. See
        // `blanks_after`.
        //
        // Four of the five separators end a line. `||` does not, so `d` --
        // the fallback for `c` -- keeps `c`'s line. See `ends_a_line`.
        assert_eq!(breaks(&render_command("a; b && c || d | e")), vec!["b", "c", "e"]);
        assert_eq!(
            separators(&render_command("a; b && c || d | e")),
            vec![";", "&&", "||", "|"],
            "every separator is still drawn as itself, wherever the lines fall"
        );
    }

    #[test]
    fn a_fallback_stays_on_the_line_of_what_it_falls_back_from() {
        // The reported shape. `true` on a line of its own reads as the next
        // thing that happens; it is what happens *instead*, and only if the
        // pipe before it failed.
        assert_eq!(
            drawn_lines(&render_command("a | b || true")),
            vec!["a | ", "b || true"],
            "the fallback was drawn as a next step"
        );
        // The pipe still ends its line: output flowing into the next command
        // really is the next thing that happens.
        assert_eq!(
            drawn_lines(&render_command("make && ./run || echo failed")),
            vec!["make && ", "./run || echo failed"]
        );
    }

    #[test]
    fn a_fallback_is_still_a_command_of_its_own() {
        // Layout only: `||` still ends a segment everywhere that decides what
        // a word *is*. The roster resolves what runs out of the same segments,
        // so a `true` that stopped being a segment's first word would stop
        // being named at all.
        let spans = render_command("a | b || true");
        assert_eq!(commands(&spans), vec!["a", "b", "true"]);
        assert_eq!(segments("a | b || true").len(), 3);
    }

    #[test]
    fn a_trailing_separator_needs_nothing_to_follow_it() {
        let spans = render_command("a;");
        assert_eq!(separators(&spans), vec![";"]);
        assert_eq!(spans.len(), 2);
        assert_eq!(unrender(&spans), "a;");
    }

    #[test]
    fn a_leading_separator_is_still_a_separator() {
        let spans = render_command("; a");
        assert_eq!(separators(&spans), vec![";"]);
        assert!(!spans[0].break_before(), "nothing precedes the first span to break from");
        assert_eq!(unrender(&spans), "; a");
    }

    #[test]
    fn adjacent_separators_each_close_a_segment() {
        // The run between them is empty, which `classify_into` handles as a
        // no-op. The break from the first lands on the second, because the
        // second really is the span that follows it.
        let spans = render_command("a;;b");
        assert_eq!(separators(&spans), vec![";", ";"]);
        assert_eq!(breaks(&spans), vec![";", "b"]);
        assert_eq!(unrender(&spans), "a;;b");
    }

    // --- a break the caller asks for --------------------------------------

    /// The shape a root request draws: `run0`, its own options, the `--`, and
    /// the approved command at the end of all of it. Two `--setenv` here and
    /// half a dozen in life, which is the point — the wall in front of the
    /// command grows with the child environment.
    const ELEVATED: &str =
        "run0 --pipe --setenv=HOME=/home/u --setenv=PAGER=cat -- bash -c 'rm -rf /tmp/x'";

    /// The whole pipeline with a break asked for at `at`, which is what an
    /// elevated request draws. Through `render_command_breaking_at` rather
    /// than through `segment_breaking_at`, for the reason the other helpers
    /// here give: a pass that is correct but unwired shows the reader nothing.
    fn broken_at(command: &str, at: usize) -> Spans {
        crate::render::render_command_breaking_at(command, &BTreeMap::new(), Some(at))
    }

    #[test]
    fn the_approved_command_starts_a_line_of_its_own() {
        let at = ELEVATED.find("bash").expect("the wrapper ends and the command starts");
        let spans = broken_at(ELEVATED, at);

        let broken: Vec<&Span> = spans.iter().filter(|s| s.break_before()).collect();
        assert_eq!(broken.len(), 1, "one break, and the caller asked for it");
        assert_eq!(broken[0].range().start, at, "and it is where the caller said");
        assert!(broken[0].text().starts_with("bash -c"), "{}", broken[0].text());
    }

    #[test]
    fn a_requested_break_adds_no_character_and_moves_none() {
        // The whole reason it is a flag on a span and not a newline in the
        // text: the bytes the reader approves are the bytes that run, and a
        // line break that changed one of them would be the fidelity failure
        // this crate exists to refuse.
        let at = ELEVATED.find("bash").unwrap();
        let broken = broken_at(ELEVATED, at);
        assert_eq!(unrender(&broken), ELEVATED);
        assert!(broken.covers_source());
        // The one-line form is the same line too, which is what the title bar
        // draws and what `Payload::rendering` checks the spans against.
        let shown = |spans: &Spans| spans.iter().map(Span::display_text).collect::<String>();
        assert_eq!(shown(&broken), shown(&render_command(ELEVATED)));
    }

    #[test]
    fn a_line_nobody_asked_to_break_is_the_line_render_command_draws() {
        // The unelevated path passes `None` and must be untouched by any of
        // this: same spans, same boundaries, same absence of layout.
        let spans = crate::render::render_command_breaking_at(ELEVATED, &BTreeMap::new(), None);
        assert!(breaks(&spans).is_empty(), "a break appeared that nothing asked for");
        assert_eq!(spans, render_command(ELEVATED));
    }

    #[test]
    fn a_requested_break_takes_its_place_among_the_ones_the_command_asked_for() {
        // It is spent where it was asked for rather than at the next
        // boundary: `c` starts a line, and so does each run after a
        // separator. A break deferred to the separator after it would draw
        // ` b c` as one line and put the reader's eye back where it started.
        let line = "a; b c; d";
        let at = line.find('c').unwrap();
        assert_eq!(breaks(&broken_at(line, at)), vec!["b", "c", "d"]);
        assert_eq!(unrender(&broken_at(line, at)), line);
    }

    #[test]
    #[should_panic(expected = "not on a character boundary")]
    fn a_break_inside_a_character_is_refused() {
        // The offset is arithmetic on an argv, so a caller that had counted
        // characters where it should have counted bytes would ask for a cut
        // inside one. There is no half-character to start a line with.
        broken_at("echo é", 6);
    }

    #[test]
    #[should_panic(expected = "behind cursor")]
    fn a_break_behind_what_is_already_drawn_is_refused() {
        // Inside a separator token, which segmentation has emitted by the
        // time the offset comes up. It means the caller's idea of the line
        // and the scanner's have come apart, and the whole reason the offset
        // travels from the caller is that nobody should have to guess which
        // of the two was right -- so it is loud, rather than a line that
        // quietly fails to break.
        broken_at("a && b", 3);
    }

    #[test]
    #[should_panic(expected = "begins no span")]
    fn a_break_past_the_end_of_the_line_is_refused() {
        // One past the last character is not a place anything begins, and a
        // break nothing carries is a break nobody would see. The elevation
        // that has nothing to wrap says `None` instead -- see
        // `ElevatedArgv::inner_at`.
        broken_at("echo hi", "echo hi".len());
    }

    // --- quoting ----------------------------------------------------------

    #[test]
    fn separators_inside_single_quotes_are_not_split() {
        assert!(separators(&render_command("echo 'a; b'")).is_empty());
    }

    #[test]
    fn separators_inside_double_quotes_are_not_split() {
        assert!(separators(&render_command("echo \"a && b\"")).is_empty());
    }

    #[test]
    fn a_closed_quote_stops_protecting_what_follows() {
        // Otherwise "not split inside quotes" would pass for a scanner that
        // simply never splits after the first quote character.
        assert_eq!(separators(&render_command("echo 'a; b'; c")), vec![";"]);
        assert_eq!(separators(&render_command("echo \"a; b\" && c")), vec!["&&"]);
    }

    #[test]
    fn quotes_of_the_other_kind_are_ordinary_characters_inside_a_string() {
        // A scanner that toggles on either quote regardless of which one it
        // is inside would fall out of the string at the apostrophe and split
        // the argument in two.
        assert!(separators(&render_command("echo \"it's; here\"")).is_empty());
        assert!(separators(&render_command("echo 'say \"hi\"; now'")).is_empty());
    }

    #[test]
    fn an_unterminated_quote_protects_the_rest_of_the_command() {
        // Under-segmentation, which is the direction the scanner is allowed
        // to be wrong in for the constructs it models: an open quote hides
        // structure rather than fabricating it.
        assert!(separators(&render_command("echo 'a; b")).is_empty());
        assert_eq!(unrender(&render_command("echo 'a; b")), "echo 'a; b");
    }

    // --- escapes ----------------------------------------------------------

    #[test]
    fn escaped_separator_is_not_split() {
        assert!(separators(&render_command(r"echo a\; b")).is_empty());
    }

    #[test]
    fn an_escaped_quote_does_not_open_a_string() {
        // `echo \"a; b\"` runs two commands. A scanner that ignored the
        // escape would see a quoted `a; b` and hide the boundary.
        assert_eq!(separators(&render_command(r#"echo \"a; b\""#)), vec![";"]);
    }

    #[test]
    fn an_escaped_quote_inside_double_quotes_does_not_close_it() {
        // The case that decides how backslash behaves inside `"…"`: reading
        // `\"` as a close would drop the scanner into Normal mid-string and
        // let it invent a boundary out of an argument.
        assert!(separators(&render_command(r#"echo "a\"; b""#)).is_empty());
    }

    #[test]
    fn a_backslash_inside_single_quotes_escapes_nothing() {
        // `'a\'` is a complete string in sh. Honouring the escape would leave
        // the scanner believing the quote is still open for the rest of the
        // command.
        assert_eq!(separators(&render_command(r"echo 'a\'; b")), vec![";"]);
    }

    #[test]
    fn an_escaped_backslash_does_not_escape_what_follows_it() {
        assert_eq!(separators(&render_command(r"echo a\\; b")), vec![";"]);
    }

    #[test]
    fn a_trailing_backslash_escapes_nothing_and_panics_nothing() {
        assert_eq!(unrender(&render_command("echo a\\")), "echo a\\");
    }

    // --- newlines are boundaries but not separators -----------------------

    #[test]
    fn a_newline_breaks_the_line_without_becoming_a_separator() {
        // A Separator-kinded newline would be drawn as itself, and a break on
        // screen would stop telling the reader whether it is layout or
        // content. The chip keeps those two readings apart.
        let spans = render_command("a\nb");
        assert!(separators(&spans).is_empty(), "the newline is not tagged Separator");
        assert_eq!(chips(&spans), vec!['\n'], "it is chipped, like every other control");
        assert_eq!(spans[1].display_text(), "\u{21B5}");
        assert!(!spans[1].break_before(), "the chip closes its segment");
        assert!(spans[2].break_before(), "and the break lands after it");
        assert_eq!(unrender(&spans), "a\nb");
    }

    #[test]
    fn a_newline_inside_quotes_is_not_a_boundary() {
        // A literal newline in an argument is content, not structure. Asked
        // of the scanner rather than of the finished rendering, because the
        // classifier gives *every* newline a line break of its own — see
        // `unicode::classify_into` — so a break in the result no longer tells
        // these two apart. What segmentation claims is that this newline ends
        // no segment, and this is that claim.
        assert!(boundaries("echo 'a\nb'").is_empty());

        let spans = render_command("echo 'a\nb'");
        assert!(separators(&spans).is_empty(), "a quoted newline was tagged as structure");
        assert_eq!(chips(&spans), vec!['\n'], "but it is still shown for what it is");
        assert_eq!(unrender(&spans), "echo 'a\nb'");
    }

    #[test]
    fn an_escaped_newline_is_a_line_continuation_and_not_a_boundary() {
        assert!(boundaries("echo a\\\nb").is_empty());

        let spans = render_command("echo a\\\nb");
        assert!(separators(&spans).is_empty());
        assert_eq!(unrender(&spans), "echo a\\\nb");
    }

    /// What each drawn line of a rendering reads as, breaks honoured and
    /// chips drawn as their glyphs. The shape of the layout, asked of the
    /// thing a reader actually sees.
    fn drawn_lines(spans: &Spans) -> Vec<String> {
        let mut lines = vec![String::new()];
        for span in spans.iter() {
            if span.break_before() && !lines.last().expect("one line to start with").is_empty() {
                lines.push(String::new());
            }
            lines.last_mut().expect("a line to write into").push_str(&span.display_text());
        }
        lines
    }

    #[test]
    fn a_newline_after_a_separator_keeps_its_glyph_on_the_line_it_ends() {
        // Both passes want a break in the same place. Segmentation asks
        // first, so without the rule its break lands on the newline's own
        // chip and strands a `↵` at the start of the next line — a wasted row
        // per segment, and the one place the two panes disagreed about a
        // command neither had changed.
        assert_eq!(
            drawn_lines(&render_command("cd /src &&\ncargo build &&\nsystemctl restart x")),
            vec!["cd /src &&\u{21B5}", "cargo build &&\u{21B5}", "systemctl restart x"],
        );
        // The run-up to the newline goes with the line it is typed on, which
        // is where the pane beside it draws it.
        assert_eq!(drawn_lines(&render_command("a && \t\nb")), vec!["a && \u{21E5}\u{21B5}", "b"]);
        assert_eq!(drawn_lines(&render_command("a &&\r\nb")), vec!["a &&\u{21E4}\u{21B5}", "b"]);
    }

    #[test]
    fn a_segment_between_a_separator_and_a_newline_still_gets_its_line() {
        // The rule gives way to the author's newline; it does not give away
        // segmentation. `&& b` is a segment with something in it and starts a
        // line of its own, exactly as it would without a newline anywhere.
        assert_eq!(drawn_lines(&render_command("a && b\nc")), vec!["a && ", "b\u{21B5}", "c"]);
    }

    #[test]
    fn a_blank_line_after_a_separator_is_still_a_blank_line() {
        // The second newline's `↵` is alone on its line because the line it
        // ends is empty — a fact about the command, not an artefact of the
        // layout. Losing it here would be hiding a line the reader is
        // approving.
        assert_eq!(drawn_lines(&render_command("a &&\n\nb")), vec![
            "a &&\u{21B5}",
            "\u{21B5}",
            "b",
        ]);
    }

    #[test]
    fn giving_way_to_a_newline_changes_no_character_and_no_kind() {
        // The whole of the change is which span carries `break_before`.
        let spans = render_command("a &&\nb");
        assert_eq!(unrender(&spans), "a &&\nb");
        assert_eq!(separators(&spans), vec!["&&"]);
        assert_eq!(chips(&spans), vec!['\n'], "the newline is still a chip of its own");
        assert_eq!(breaks(&spans), vec!["b"], "and the one break starts the next segment");
    }

    // --- composition with the chip pass -----------------------------------

    #[test]
    fn chips_still_appear_inside_segments() {
        // Segmentation drives the builder now, so a rewrite of it that
        // pushed plain runs of its own would silently drop the chip pass and
        // draw a bidi override as itself.
        let spans = render_command("ls\u{202E}txt; rm -rf \u{200B}/");
        assert_eq!(chips(&spans), vec!['\u{202E}', '\u{200B}']);
        assert_eq!(separators(&spans), vec![";"]);
    }

    #[test]
    fn a_separator_next_to_a_chip_keeps_both() {
        let spans = render_command("a\u{202E};\u{200B}b");
        assert_eq!(separators(&spans), vec![";"]);
        assert_eq!(chips(&spans), vec!['\u{202E}', '\u{200B}']);
        assert_eq!(unrender(&spans), "a\u{202E};\u{200B}b");
    }

    // --- scope: where the model stops, in both directions -----------------

    #[test]
    fn structure_outside_the_five_separators_is_left_unsegmented() {
        // Not a wish list. These record one half of the bounded cost of the
        // scope: structure the shell has that the screen does not. See the
        // module docs, and the mirror below.
        assert!(separators(&render_command("sleep 60 & wait")).is_empty(), "backgrounding");
        assert!(separators(&render_command("(cd /tmp)")).is_empty(), "subshells");
        assert!(separators(&render_command("echo `id`")).is_empty(), "backticks");
        assert!(separators(&render_command("echo $(id)")).is_empty(), "substitution");
        // The one that moved here, and the one that moved on purpose. The `;`
        // of `$(a; b)` is a real separator of the command inside the
        // substitution, and it used to be drawn at this level -- two segments
        // on screen where the shell runs one command with one argument. It is
        // now drawn at no level, and the `a` and the `b` reach the reader
        // through the roster instead.
        assert!(separators(&render_command("echo $(a; b)")).is_empty(), "a nested separator");
        assert!(separators(&render_command("echo `a && b`")).is_empty(), "and in a backtick");
    }

    #[test]
    fn over_segmentation_where_the_model_stops() {
        // The other half, and the correction of a claim these docs used to
        // make. The scanner is wrong only in the direction of finding no
        // boundary *for the constructs it models* — quoting and escaping.
        // A separator character that some unmodelled construct gives another
        // meaning to is split on anyway. Each case was checked against a real
        // shell; this test is what stops the list drifting from the docs.
        //
        // Arithmetic used to be the first entry here: `echo $((1 || 0))` was
        // split at the `||`. The `$(` opens a level of nesting now, and
        // nothing inside one is a separator, so the entry came off the list
        // rather than being documented better.
        assert!(separators(&render_command("echo $((1 || 0))")).is_empty(), "arithmetic, retired");
        assert_eq!(separators(&render_command("[[ -n x || -n y ]]")), vec!["||"], "conditional");
        assert_eq!(separators(&render_command(r"$'a\'b; c'")), vec![";"], "ANSI-C quoting");
        assert_eq!(
            separators(&render_command("case x in a) echo 1;; esac")),
            vec![";", ";"],
            "the case terminator is one token, drawn as two separators"
        );
    }

    #[test]
    fn an_over_segmented_command_is_still_rendered_exactly() {
        // The reason this is a docs bug and not a fidelity bug: what is wrong
        // is the layout, and layout is metadata. Every byte is still on
        // screen, drawn as itself.
        for command in [r"$'a\'b; c'", "case x in a) echo 1;; esac", "echo $((1 || 0))"] {
            let spans = render_command(command);
            assert_eq!(unrender(&spans), command);
            let shown: String = spans.iter().map(|s| s.display_text()).collect();
            assert_eq!(shown, command, "{command:?} is drawn as itself throughout");
        }
    }

    #[test]
    fn a_lone_ampersand_after_a_pair_is_not_a_separator() {
        let spans = render_command("a &&& b");
        assert_eq!(separators(&spans), vec!["&&"]);
        assert_eq!(unrender(&spans), "a &&& b");
    }

    // --- fidelity ---------------------------------------------------------

    #[test]
    fn nothing_is_dropped_or_added() {
        for command in [
            "",
            ";",
            "a;;b",
            "a; b && c || d | e",
            "echo 'a; b' | tee \"x && y\"",
            r"echo a\; b\\; c",
            "a\nb\n",
            "\u{202E}; \u{200B}",
            "ünïcödé; ✓",
            "echo 'unterminated; still fine",
        ] {
            let spans = render_command(command);
            assert_eq!(unrender(&spans), command, "{command:?} did not round-trip");
            assert!(spans.covers_source(), "{command:?} is not tiled by its spans");
        }
    }

    #[test]
    fn the_empty_command_segments_into_nothing() {
        let spans = render_command("");
        assert!(spans.is_empty());
        assert_eq!(unrender(&spans), "");
    }

    // --- the scanner itself -----------------------------------------------

    #[test]
    fn the_scanner_reports_boundaries_in_source_order() {
        assert_eq!(
            boundaries("a; b\nc && d"),
            vec![Boundary::Separator(1..2), Boundary::Newline(5), Boundary::Separator(7..9)],
        );
    }

    #[test]
    fn the_scanner_steps_over_multibyte_characters_whole() {
        // The cursor walks by `len_utf8`, so a continuation byte is never
        // mistaken for the start of a token and no offset lands mid-character.
        assert_eq!(boundaries("é; ü"), vec![Boundary::Separator(2..3)]);
        assert_eq!(unrender(&render_command("é; ü")), "é; ü");
    }

    // --- variables: what is claimed, and against which environment --------

    /// Every `Variable` span, as the window would present it: the text the
    /// user approves, and the value shown beside it.
    fn variables(spans: &Spans) -> Vec<(&str, Option<&str>)> {
        spans
            .iter()
            .filter_map(|s| s.variable().map(|(_, resolved)| (s.text(), resolved)))
            .collect()
    }

    #[test]
    fn set_variable_renders_with_its_child_value() {
        let env = env(&[("HOME", "/home/user")]);
        let spans = annotate_variables(render_command("ls $HOME"), &env);
        let variable = spans
            .iter()
            .find(|s| matches!(s.kind(), SpanKind::Variable { .. }))
            .expect("the reference is annotated");
        assert_eq!(variable.text(), "$HOME", "the text is still the approved substring");
        assert_eq!(variable.variable(), Some(("HOME", Some("/home/user"))));
    }

    #[test]
    fn unset_variable_is_flagged_unset() {
        let spans = annotate_variables(render_command("ls $NOPE"), &BTreeMap::new());
        let variable = spans
            .iter()
            .find(|s| matches!(s.kind(), SpanKind::Variable { .. }))
            .expect("an unset reference is still a reference");
        assert_eq!(variable.variable(), Some(("NOPE", None)));
    }

    #[test]
    fn variables_in_single_quotes_are_not_annotated() {
        // `'$HOME'` is the two-word argument `$HOME`, not a substitution.
        // Annotating it would tell the reader an expansion happens where none
        // does -- the same class of lie the quote-aware scanner exists for.
        let env = env(&[("HOME", "/home/user")]);
        let spans = annotate_variables(render_command("echo '$HOME'"), &env);
        assert!(variables(&spans).is_empty());
    }

    #[test]
    fn variables_in_double_quotes_are_annotated() {
        // `"$HOME"` does expand. Refusing to annotate here would be the
        // mirror lie: the reader would be shown a literal where a
        // substitution happens.
        let env = env(&[("HOME", "/home/user")]);
        let spans = rendered("echo \"$HOME/x\"", &env);
        assert_eq!(variables(&spans), vec![("$HOME", Some("/home/user"))]);
    }

    #[test]
    fn a_closed_single_quote_stops_protecting_what_follows() {
        // Otherwise "not annotated inside single quotes" would pass for a
        // pass that simply gave up at the first quote character.
        let env = env(&[("A", "1"), ("B", "2")]);
        let spans = rendered("echo '$A' $B", &env);
        assert_eq!(variables(&spans), vec![("$B", Some("2"))]);
    }

    #[test]
    fn an_escaped_dollar_is_not_a_variable() {
        // `\$HOME` and `"\$HOME"` are both the literal five characters.
        let env = env(&[("HOME", "/home/user")]);
        assert!(variables(&rendered(r"echo \$HOME", &env)).is_empty());
        assert!(
            variables(&rendered(r#"echo "\$HOME""#, &env)).is_empty()
        );
    }

    #[test]
    fn the_braced_form_is_annotated_and_keeps_its_braces() {
        let env = env(&[("HOME", "/home/user")]);
        let spans = rendered("ls ${HOME}x", &env);
        assert_eq!(variables(&spans), vec![("${HOME}", Some("/home/user"))]);
        let braced = spans.iter().find(|s| s.variable().is_some()).unwrap();
        assert_eq!(braced.variable().unwrap().0, "HOME", "the name is the interior");
        assert_eq!(unrender(&spans), "ls ${HOME}x");
    }

    #[test]
    fn every_reference_in_a_command_is_annotated() {
        // Under-tagging breaks no invariant in tests/fidelity.rs: a reference
        // left Plain round-trips perfectly and hides nothing. This test and
        // its siblings are the only thing that requires the tagging at all.
        let env = env(&[("A", "1"), ("B", "2"), ("C", "3")]);
        let spans = rendered("$A x ${B}; echo $C", &env);
        assert_eq!(
            variables(&spans),
            vec![("$A", Some("1")), ("${B}", Some("2")), ("$C", Some("3"))]
        );
    }

    #[test]
    fn a_reference_beside_a_separator_or_a_chip_keeps_everything() {
        let env = env(&[("HOME", "/home/user")]);
        let spans = rendered("echo $HOME;\u{202E}$HOME", &env);
        assert_eq!(separators(&spans), vec![";"]);
        assert_eq!(chips(&spans), vec!['\u{202E}']);
        assert_eq!(
            variables(&spans),
            vec![("$HOME", Some("/home/user")), ("$HOME", Some("/home/user"))]
        );
        assert_eq!(unrender(&spans), "echo $HOME;\u{202E}$HOME");
    }

    #[test]
    fn a_reference_that_is_the_whole_command_needs_no_split() {
        let env = env(&[("A", "1")]);
        let spans = rendered("$A", &env);
        assert_eq!(spans.len(), 1);
        assert_eq!(variables(&spans), vec![("$A", Some("1"))]);
    }

    // ---- names the command sets for itself ---------------------------------

    #[test]
    fn an_assignment_earlier_in_the_command_resolves_a_later_reference() {
        // The reported shape: `unset` twice, about a name the command sets
        // two words earlier.
        let spans = rendered("R=/srv; cp $R/a $R/b", &env(&[]));
        assert_eq!(variables(&spans), vec![("$R", Some("/srv")), ("$R", Some("/srv"))]);
    }

    #[test]
    fn an_assignment_after_the_reference_does_not_reach_back() {
        // The shell runs them in order and so does this: at the `$R` there is
        // no `R` yet, and saying otherwise would describe a command that ran
        // in a different order from the one on screen.
        let spans = rendered("echo $R; R=/srv", &env(&[]));
        assert_eq!(variables(&spans), vec![("$R", None)]);
    }

    #[test]
    fn the_last_assignment_before_a_reference_is_the_one_that_counts() {
        let spans = rendered("R=/a; R=/b; echo $R", &env(&[]));
        assert_eq!(variables(&spans), vec![("$R", Some("/b"))]);
    }

    #[test]
    fn what_the_command_sets_beats_the_environment_it_starts_in() {
        let spans = rendered("R=/mine; echo $R", &env(&[("R", "/theirs")]));
        assert_eq!(variables(&spans), vec![("$R", Some("/mine"))]);
    }

    #[test]
    fn an_assignment_in_front_of_a_command_sets_nothing_afterwards() {
        // `A=1 cmd` puts `A` in that command's environment and leaves the
        // shell's alone, so the later `$A` is not this one. Reading it as one
        // would be a claim about a variable that does not exist by then.
        let spans = rendered("A=1 ls; echo $A", &env(&[]));
        assert_eq!(variables(&spans), vec![("$A", None)]);
    }

    #[test]
    fn a_value_hatch_will_not_work_out_is_not_claimed_either_way() {
        // Neither a value nor `unset`: the name *is* set, so `unset` would be
        // wrong, and what it is set to needs a shell. So nothing is drawn on
        // it at all -- no chip, no claim.
        for command in ["A=$B; echo $A", "A=$(date); echo $A", "A=*.txt; echo $A"] {
            let spans = rendered(command, &env(&[]));
            let said = variables(&spans);
            assert!(
                !said.iter().any(|(text, _)| *text == "$A"),
                "{command} claimed something about $A: {said:?}"
            );
        }
        // The `$B` inside the first one is a reference in its own right and
        // is still read as one: what is withheld is the claim about `$A`, not
        // every claim on the line.
        let spans = rendered("A=$B; echo $A", &env(&[]));
        assert_eq!(variables(&spans), vec![("$B", None)]);
    }

    #[test]
    fn a_home_relative_value_resolves_through_the_environment() {
        // The one expansion worked out here, because it is the common case
        // and it is exact.
        let spans = rendered("P=~/.config; echo $P", &env(&[("HOME", "/home/u")]));
        assert_eq!(variables(&spans), vec![("$P", Some("/home/u/.config"))]);
        // And with no `HOME` to resolve it through, nothing is claimed.
        let spans = rendered("P=~/.config; echo $P", &env(&[]));
        assert_eq!(variables(&spans), vec![]);
    }

    #[test]
    fn an_assignment_in_a_here_document_body_is_not_an_assignment() {
        // A body is a file being written, not shell. The same flag that stops
        // a `;` in one from being a separator stops this.
        let spans = rendered("cat <<'EOF' > f\nA=1\nEOF\necho $A", &env(&[]));
        assert_eq!(variables(&spans), vec![("$A", None)], "a config file set a variable");
    }

    #[test]
    fn a_word_that_only_looks_like_an_assignment_is_left_alone() {
        assert_eq!(assigned_name("A=1"), Some("A"));
        assert_eq!(assigned_name("_x9=1"), Some("_x9"));
        assert_eq!(assigned_name("=1"), None, "no name at all");
        assert_eq!(assigned_name("1A=1"), None, "a name cannot start with a digit");
        assert_eq!(assigned_name("A[0]=1"), None, "an array element is not modelled");
        assert_eq!(assigned_name("--flag"), None);
        assert_eq!(assigned_name("a.b=1"), None);
    }

    #[test]
    fn a_reference_keeps_the_line_break_on_the_first_span_of_its_line() {
        // `split` leaves `break_before` with the left half, so a reference
        // that starts a line must not steal the break from the space before
        // it -- and one that *is* the start of a line must keep it.
        let env = env(&[("A", "1")]);

        let spans = rendered("x; $A", &env);
        assert_eq!(breaks(&spans), vec!["$A"], "the reference starts the line, not the space");

        let spans = rendered("x;$A", &env);
        assert_eq!(breaks(&spans), vec!["$A"]);
        assert_eq!(variables(&spans), vec![("$A", Some("1"))]);
    }

    #[test]
    fn a_name_may_start_with_an_underscore_and_carry_digits() {
        let env = env(&[("_x9", "ok")]);
        assert_eq!(
            variables(&rendered("echo $_x9", &env)),
            vec![("$_x9", Some("ok"))]
        );
    }

    #[test]
    fn a_name_stops_at_the_first_character_that_is_not_one() {
        let env = env(&[("A", "1")]);
        let spans = rendered("echo $A-$A/$A.", &env);
        assert_eq!(variables(&spans), vec![("$A", Some("1")); 3]);
        assert_eq!(unrender(&spans), "echo $A-$A/$A.");
    }



    #[test]
    fn a_span_another_pass_has_claimed_is_left_exactly_as_it_was() {
        // The guard that keeps this pass from overruling another one. Today
        // it is unreachable through `render_command`, because annotation runs
        // before any pass that could retag a run -- so it is reached here by
        // hand, which is the only way to require that it works before the
        // pass that needs it exists. Without the guard the reference inside a
        // claimed span would be tagged and the claim silently dropped.
        let env = env(&[("HOME", "/home/user")]);
        // `segment` rather than the shadowed `render_command`, which already
        // annotates and would leave nothing whole to claim.
        let mut spans = segment("rm -rf $HOME");
        assert_eq!(spans.len(), 1, "one Plain run to claim");
        spans.set_kind(0, SpanKind::Danger);

        let spans = annotate_variables(spans, &env);
        assert!(variables(&spans).is_empty(), "the claimed run is not re-tagged");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].kind(), &SpanKind::Danger, "and the other pass keeps its claim");
        assert_eq!(unrender(&spans), "rm -rf $HOME");
    }

    #[test]
    fn a_command_of_nothing_but_references_is_annotated_throughout() {
        // Exercises the merge walk at a size where a quadratic pass is
        // noticeable and, more to the point, where an off-by-one in stepping
        // the two ordered sequences would show up. The count is asserted, so
        // a walk that quietly stopped early would not pass.
        let count = 5_000;
        let command = "$A ".repeat(count);
        let spans = rendered(&command, &env(&[("A", "/home/user")]));
        assert_eq!(variables(&spans).len(), count);
        assert!(variables(&spans).iter().all(|v| *v == ("$A", Some("/home/user"))));
        assert_eq!(unrender(&spans), command);
        assert!(spans.covers_source());
    }

    // --- highlighting: the word that runs, and the quoted strings ---------

    /// Every span of one kind, as the window would draw it.
    fn of_kind<'a>(spans: &'a Spans, kind: &SpanKind) -> Vec<&'a str> {
        spans.iter().filter(|s| s.kind() == kind).map(Span::text).collect()
    }

    fn commands(spans: &Spans) -> Vec<&str> {
        of_kind(spans, &SpanKind::Command)
    }

    fn quotes(spans: &Spans) -> Vec<&str> {
        of_kind(spans, &SpanKind::Quoted)
    }

    fn comments(spans: &Spans) -> Vec<&str> {
        of_kind(spans, &SpanKind::Comment)
    }

    #[test]
    fn the_first_word_of_a_segment_is_the_one_that_names_what_runs() {
        assert_eq!(commands(&render_command("ls -la /etc")), vec!["ls"]);
        assert_eq!(commands(&render_command("  ls -la")), vec!["ls"], "leading space is skipped");
        assert_eq!(commands(&render_command("ls")), vec!["ls"], "a command with no arguments");
        assert_eq!(commands(&render_command("sudo rm -rf x")), vec!["sudo"], "sudo is what runs");
    }

    #[test]
    fn every_segment_gets_its_own_command_word() {
        assert_eq!(commands(&render_command("ls; rm -rf x")), vec!["ls", "rm"]);
        assert_eq!(commands(&render_command("a && b || c | d")), vec!["a", "b", "c", "d"]);
        assert_eq!(commands(&render_command("ls\ncat f")), vec!["ls", "cat"], "a newline too");
        assert_eq!(commands(&render_command("ls;rm")), vec!["ls", "rm"], "with no space at all");
    }

    #[test]
    fn a_segment_with_nothing_in_it_names_nothing() {
        assert!(commands(&render_command("")).is_empty());
        assert!(commands(&render_command(";")).is_empty());
        assert!(commands(&render_command("   ")).is_empty());
        assert_eq!(commands(&render_command("a;;b")), vec!["a", "b"]);
    }

    #[test]
    fn a_leading_assignment_is_not_the_command() {
        // `FOO=1 ls` runs `ls`. Marking `FOO=1` as the word that names what
        // runs would be decoration contradicting the text, which is the one
        // thing highlighting in this window may never do.
        assert_eq!(commands(&render_command("FOO=1 ls -l")), vec!["ls"]);
        assert_eq!(commands(&render_command("A=1 B=2 make")), vec!["make"], "and any number");
        assert_eq!(commands(&render_command("env FOO=1 ls")), vec!["env"], "env really runs");
        assert!(commands(&render_command("FOO=1")).is_empty(), "an assignment alone runs nothing");
        // A word that merely contains `=` is not an assignment.
        assert_eq!(commands(&render_command("./x=y arg")), vec!["./x=y"]);
        assert_eq!(commands(&render_command("=1 ls")), vec!["=1"], "no name before the `=`");
    }

    #[test]
    fn a_quoted_string_is_marked_with_its_delimiters() {
        // The quotes are what make the string one word to the shell, so a
        // highlight that covered the interior and left them outside would
        // draw the boundary in the wrong place.
        assert_eq!(quotes(&render_command("echo 'hi there'")), vec!["'hi there'"]);
        assert_eq!(quotes(&render_command("echo \"hi there\"")), vec!["\"hi there\""]);
        assert_eq!(quotes(&render_command("a 'x' 'y'")), vec!["'x'", "'y'"], "one region each");
        assert_eq!(
            quotes(&render_command("echo \"it's here\"")),
            vec!["\"it's here\""],
            "the other kind of quote is ordinary text inside a string"
        );
    }

    #[test]
    fn an_unterminated_string_runs_to_the_end_of_the_command() {
        // The same answer the scanner already gives segmentation, so the two
        // agree about how far the string reaches instead of each having a
        // view.
        assert_eq!(quotes(&render_command("echo 'a; b")), vec!["'a; b"]);
    }

    #[test]
    fn an_escaped_quote_opens_no_string() {
        assert!(quotes(&render_command(r#"echo \"a\""#)).is_empty());
        assert_eq!(
            quotes(&render_command(r#"echo "a\"b""#)),
            vec![r#""a\"b""#],
            "an escaped quote inside a string does not close it"
        );
    }

    #[test]
    fn a_command_word_carrying_a_quote_is_declined_rather_than_overlapped() {
        // `"ls" -l` does run `ls`, so this costs a highlight on a real
        // command name. What it buys is that no `Command` region can ever
        // overlap a `Quoted` one, and two overlapping regions have no honest
        // drawing.
        let spans = render_command("\"ls\" -l");
        assert!(commands(&spans).is_empty());
        assert_eq!(quotes(&spans), vec!["\"ls\""]);
        assert_eq!(unrender(&spans), "\"ls\" -l");
    }

    #[test]
    fn highlighting_never_overrules_a_pass_that_has_more_to_say() {
        // A chip is louder than a highlight and a resolved value is
        // information; both survive being inside a highlighted region.
        let env = env(&[("HOME", "/home/user")]);

        let spans = rendered("ls\u{202E}x -l", &env);
        assert_eq!(chips(&spans), vec!['\u{202E}'], "the override is still a chip");
        assert_eq!(commands(&spans), vec!["ls", "x"], "and the word either side of it is marked");

        let spans = rendered("echo \"$HOME/x\"", &env);
        assert_eq!(variables(&spans), vec![("$HOME", Some("/home/user"))]);
        assert_eq!(quotes(&spans), vec!["\"", "/x\""], "the string is drawn either side of it");
        assert_eq!(unrender(&spans), "echo \"$HOME/x\"");
    }

    #[test]
    fn a_reference_that_is_the_command_word_keeps_its_value_and_not_the_highlight() {
        // Annotation runs first and highlighting yields to it: a value is
        // information the reader cannot get anywhere else, and a colour is
        // decoration they can do without.
        let spans = rendered("$EDITOR f", &env(&[("EDITOR", "vi")]));
        assert_eq!(variables(&spans), vec![("$EDITOR", Some("vi"))]);
        assert!(commands(&spans).is_empty(), "the highlight overruled the value");
    }

    #[test]
    fn a_separator_is_never_swallowed_by_a_command_word() {
        let spans = render_command("ls;rm");
        assert_eq!(separators(&spans), vec![";"]);
        assert_eq!(commands(&spans), vec!["ls", "rm"]);
        assert_eq!(unrender(&spans), "ls;rm");
    }

    #[test]
    fn highlighting_where_the_model_stops() {
        // The mirror of the two lists above, for the same reason: the
        // highlight asks the same scanner the same question, so it inherits
        // the same gaps, and the cost is bounded the same way -- the text is
        // still on screen, drawn as itself.
        //
        // An ANSI-C string's `$` is outside the region the ordinary
        // single-quote rule finds.
        assert_eq!(quotes(&render_command("echo $'a b'")), vec!["'a b'"], "ANSI-C quoting");

        // And in every one of them the text is untouched, character for
        // character: what the highlight got wrong is a colour, and nothing
        // else moved.
        for command in [r"echo $'a\'b'", "echo $'a b'"] {
            let spans = render_command(command);
            assert_eq!(unrender(&spans), command);
            let shown: String = spans.iter().map(|s| s.display_text()).collect();
            assert_eq!(shown, command, "{command:?} is not drawn as itself throughout");
        }
    }


    // --- comments: the part of the line that will not run -----------------

    #[test]
    fn a_comment_contains_no_separator_however_many_it_is_written_with() {
        // The correctness half, and the reason this is not only a colour.
        // Every separator hatch knows, inside one comment: none of them is a
        // boundary, because the shell never reads any of them. The old
        // rendering drew a segment break at that `&&` and told the reader
        // the line ran something after it.
        let command = "echo hi   # then && rm -rf /tmp || true ; ls | wc & done";
        let spans = render_command(command);

        assert!(separators(&spans).is_empty(), "a comment is not a command line");
        assert!(!spans.iter().any(Span::break_before), "and it is not laid out as one");
        assert_eq!(
            comments(&spans),
            vec!["# then && rm -rf /tmp || true ; ls | wc & done"],
            "the comment is one run, from its own `#` to the end of the line"
        );
        assert_eq!(commands(&spans), vec!["echo"], "the only word that runs");
        assert_eq!(unrender(&spans), command);
    }

    #[test]
    fn a_comment_begins_only_at_the_start_of_a_word() {
        // Bash's own rule, checked against bash: a `#` is a comment at the
        // start of the input or after an unquoted metacharacter, and is an
        // ordinary character everywhere else. The second list is the one that
        // matters -- a comment invented over text that is going to run is the
        // only error here that hides something rather than mislabelling it.
        for (command, comment) in [
            ("#ls", "#ls"),
            ("ls #x", "#x"),
            ("ls\t#x", "#x"),
            ("echo a;#b", "#b"),
            ("echo a|#b", "#b"),
            ("echo a&&#b", "#b"),
            ("echo x >#f", "#f"),
            ("(echo a)#b", "#b"),
        ] {
            assert_eq!(comments(&render_command(command)), vec![comment], "{command:?}");
        }
        for command in [
            "echo a#b",
            "curl http://x/#frag",
            r"echo \#b",
            "echo $#",
            "echo ${#PATH}",
            "echo 'q'#b",
            "echo \"q\"#b",
        ] {
            assert!(
                comments(&render_command(command)).is_empty(),
                "{command:?} has no comment in it and the shell agrees"
            );
        }
    }

    #[test]
    fn a_hash_inside_quotes_is_text_and_the_quotes_still_close() {
        // Both halves: the `#` starts nothing, and the scanner is still in
        // the string afterwards -- a comment that swallowed the closing quote
        // would take the rest of the command with it.
        for command in ["echo 'a # b'", "echo \"a # b\""] {
            let spans = render_command(command);
            assert!(comments(&spans).is_empty(), "{command:?}");
            assert_eq!(quotes(&spans).len(), 1, "{command:?}: the string did not close");
        }
        // And a separator after the string is still found, which is the proof
        // that the scanner came back out of it.
        assert_eq!(separators(&render_command("echo 'a # b'; ls")), vec![";"]);
    }

    #[test]
    fn a_comment_ends_at_the_newline_and_the_newline_still_ends_the_segment() {
        // The newline is not part of the comment -- it is the character that
        // is not -- and it is still a boundary, so the line after a comment
        // is a segment of its own with its own command word in it.
        let command = "echo hi # and && this\nrm -rf /tmp";
        let spans = render_command(command);

        assert_eq!(comments(&spans), vec!["# and && this"], "the newline was eaten");
        assert_eq!(chips(&spans), vec!['\n'], "and it is still drawn as the character it is");
        assert_eq!(commands(&spans), vec!["echo", "rm"], "the second line is a second segment");
        assert_eq!(unrender(&spans), command);
    }

    #[test]
    fn a_reference_inside_a_comment_is_left_plain() {
        // The shell does not expand `$HOME` in a comment because it does not
        // read the line at all, so a value beside it would be this machine's
        // home directory dressed as something the command is about to do.
        let env = env(&[("HOME", "/home/user")]);
        let spans = rendered("echo $HOME # not $HOME", &env);

        assert_eq!(
            variables(&spans),
            vec![("$HOME", Some("/home/user"))],
            "the live reference lost its value, or the dead one gained one"
        );
        assert_eq!(comments(&spans), vec!["# not $HOME"]);
        assert_eq!(unrender(&spans), "echo $HOME # not $HOME");
    }

    #[test]
    fn a_comment_has_no_command_word_and_no_string_in_it() {
        // Two regions that overlapped would have no honest drawing, so a
        // comment is the whole of what is marked over its own text: the word
        // after the `#` is not a command, and an apostrophe in it opens no
        // string that would then run to the end of the line.
        let spans = render_command("ls; # it's rm -rf / that would hurt");
        assert_eq!(commands(&spans), vec!["ls"]);
        assert!(quotes(&spans).is_empty(), "an apostrophe in a comment opened a string");
        assert_eq!(comments(&spans), vec!["# it's rm -rf / that would hurt"]);
        assert_eq!(separators(&spans), vec![";"], "the separator before it is still one");
    }

    #[test]
    fn a_comment_is_drawn_as_its_own_text_and_the_spans_still_tile_it() {
        // The bound on every decoration in this module, restated for the one
        // kind that is drawn at less than full contrast: quieter is a colour,
        // not an edit. Nothing is replaced, and a chip inside a comment is
        // still a chip -- the classifier ran before the highlight did, and a
        // bidi override in a comment reorders the line it sits on just as
        // well as one anywhere else.
        let command = "ls # \u{202E}gnp.exe";
        let spans = render_command(command);

        assert_eq!(unrender(&spans), command);
        assert!(spans.covers_source());
        let shown: String = spans.iter().map(|s| s.display_text()).collect();
        assert_eq!(shown, "ls # [RLO]gnp.exe", "the chip is the only substitution");
        assert_eq!(chips(&spans), vec!['\u{202E}'], "a comment swallowed a chip");
    }

    #[test]
    fn a_hash_in_a_here_document_body_is_a_character_in_a_config_file() {
        // This used to be drawn as a comment, and was pinned as a known cost
        // of not knowing where a body starts. A `#` at the start of a line is
        // how half the configuration files ever written begin a line, and
        // drawing one in the colour that says *this will not run* was a claim
        // about text a command is about to be handed.
        let env = env(&[("HOME", "/home/user")]);
        let command = "cat <<'EOF'\n# $HOME && ls\nEOF";
        let spans = rendered(command, &env);

        assert!(comments(&spans).is_empty(), "a `#` in a body is data, not a comment");
        assert!(separators(&spans).is_empty(), "the body's `&&` is not a boundary");
        assert!(variables(&spans).is_empty(), "and a quoted heredoc expands nothing");
        assert_eq!(unrender(&spans), command);
    }

    #[test]
    fn a_command_that_is_nothing_but_a_comment_runs_nothing_and_says_so() {
        let spans = render_command("# rm -rf / ; echo done");
        assert_eq!(comments(&spans), vec!["# rm -rf / ; echo done"]);
        assert!(commands(&spans).is_empty(), "nothing in this line is a command");
        assert!(separators(&spans).is_empty());
    }

    // --- redirections: where the effects land -----------------------------

    fn redirects(spans: &Spans) -> Vec<&str> {
        of_kind(spans, &SpanKind::Redirect)
    }

    #[test]
    fn every_redirection_operator_bash_has_is_recognised() {
        // The set is the manual's, not a memory of it, and this is the list
        // that would notice one going missing. Each is given a target so that
        // the operator is the first of the two marked runs.
        for (command, operator) in [
            ("echo x > out", ">"),
            ("echo x >> out", ">>"),
            ("cat < in", "<"),
            ("cat << EOF", "<<"),
            ("cat <<- EOF", "<<-"),
            ("cat <<< word", "<<<"),
            ("cat <> both", "<>"),
            ("echo x >| out", ">|"),
            ("echo x &> out", "&>"),
            ("echo x &>> out", "&>>"),
            ("echo x >& 2", ">&"),
            ("cat <& 0", "<&"),
        ] {
            let spans = render_command(command);
            assert_eq!(
                redirects(&spans).first().copied(),
                Some(operator),
                "{command:?} did not yield {operator:?}"
            );
            assert_eq!(unrender(&spans), command, "{command:?} did not round-trip");
        }
    }

    #[test]
    fn a_file_descriptor_in_front_of_an_operator_is_part_of_it() {
        // bash reads the number and the operator as one token, so hatch draws
        // them as one run: a `2` left plain beside a marked `>` would be
        // drawing a boundary the shell does not have, in the small.
        assert_eq!(redirects(&render_command("make 2> log")), vec!["2>", "log"]);
        assert_eq!(redirects(&render_command("make 2>> log")), vec!["2>>", "log"]);
        assert_eq!(redirects(&render_command("make 2>&1")), vec!["2>&", "1"]);
        assert_eq!(redirects(&render_command("make 1>&2")), vec!["1>&", "2"]);
        assert_eq!(redirects(&render_command("make 22> log")), vec!["22>", "log"]);
    }

    #[test]
    fn a_number_that_is_not_the_whole_token_is_not_a_file_descriptor() {
        // `echo a2>log` writes `a2` to `log`, which is bash's own answer: the
        // token so far is `a2`, and that is not a number, so the `>` starts a
        // fresh one. Marking the `2` would claim a descriptor the shell never
        // reads and take a character off the argument beside it.
        assert_eq!(redirects(&render_command("echo a2>log")), vec![">", "log"]);
        assert_eq!(redirects(&render_command("echo 1 > 2")), vec![">", "2"]);
        assert_eq!(commands(&render_command("echo a2>log")), vec!["echo"]);
    }

    #[test]
    fn the_ampersand_forms_take_no_descriptor() {
        // The `&` of `&>` is part of the operator rather than a number, so a
        // number in front of it is a word. `echo 2&>x` is the word `2` and
        // then an `&>`, which is what bash reads too.
        assert_eq!(redirects(&render_command("echo 2&>x")), vec!["&>", "x"]);
    }

    #[test]
    fn the_longest_redirection_operator_wins() {
        // The table is full of prefixes -- `>` starts `>>`, `>|` and `>&` --
        // so a shortest-first table would read `2>>log` as `2>` and an
        // argument called `>log`.
        assert_eq!(redirects(&render_command("echo x >>out")), vec![">>", "out"]);
        assert_eq!(redirects(&render_command("cat <<<in")), vec!["<<<", "in"]);
        assert_eq!(redirects(&render_command("echo x &>>out")), vec!["&>>", "out"]);
    }

    #[test]
    fn redirection_table_is_longest_first() {
        // The whole of the longest-match rule, held the way `SEPARATORS` is
        // held: the first entry that matches wins, so nothing may be listed
        // before a token it is a prefix of.
        for (index, token) in REDIRECTIONS.iter().enumerate() {
            for longer in &REDIRECTIONS[index + 1..] {
                assert!(
                    !longer.starts_with(*token),
                    "{token:?} is listed before the longer {longer:?}, so it would match first"
                );
            }
        }
    }

    #[test]
    fn the_target_is_marked_as_well_as_the_operator() {
        // The point of the whole pass. In `echo x > /etc/passwd` the word a
        // reader is scanning for is the path, so the arrow alone would be
        // half an answer -- and both halves are one kind, because they are
        // one fact.
        let spans = render_command("echo x > /etc/passwd");
        assert_eq!(redirects(&spans), vec![">", "/etc/passwd"]);
        // The blank between them belongs to neither and is left alone.
        let between = spans.iter().find(|s| s.text() == " ").expect("the space survives");
        assert_eq!(between.kind(), &SpanKind::Plain);
        assert_eq!(unrender(&spans), "echo x > /etc/passwd");
    }

    #[test]
    fn a_target_with_no_space_in_front_of_it_is_still_a_target() {
        assert_eq!(redirects(&render_command("echo x >/etc/passwd")), vec![">", "/etc/passwd"]);
        assert_eq!(redirects(&render_command("echo x >   out")), vec![">", "out"]);
    }

    #[test]
    fn a_target_ends_where_a_word_ends() {
        // Unquoted whitespace or an unquoted metacharacter, which is bash's
        // own rule. A target that ran to the end of the line would swallow
        // the command after the `;` and colour it as a destination.
        assert_eq!(redirects(&render_command("echo x >out; ls")), vec![">", "out"]);
        assert_eq!(redirects(&render_command("echo x >out ls")), vec![">", "out"]);
        assert_eq!(redirects(&render_command("echo x >out|wc")), vec![">", "out"]);
        assert_eq!(separators(&render_command("echo x >out; ls")), vec![";"]);
        assert_eq!(separators(&render_command("echo x >out|wc")), vec!["|"]);
    }

    #[test]
    fn a_second_operator_ends_the_first_ones_target() {
        // `>a>b` is two redirections and not one pointing at `a>b`, which is
        // again what bash does with it.
        assert_eq!(redirects(&render_command("echo x >a>b")), vec![">", "a", ">", "b"]);
    }

    #[test]
    fn an_operator_with_nothing_after_it_has_no_target() {
        // Every one of these is a syntax error in bash. Marking a target that
        // is not there would be the window inventing a destination.
        assert_eq!(redirects(&render_command("echo x >")), vec![">"]);
        assert_eq!(redirects(&render_command("echo x > ")), vec![">"]);
        assert_eq!(redirects(&render_command("echo x >\nls")), vec![">"]);
        assert_eq!(redirects(&render_command("echo x > ; ls")), vec![">"]);
    }

    #[test]
    fn a_comment_ends_a_redirection_that_was_waiting_for_its_word() {
        // `echo z >#f` is a syntax error in bash: the `#` is at the start of
        // a word, so the comment swallows the line and the redirection never
        // gets its target. The operator is still an operator.
        let spans = render_command("echo z >#f");
        assert_eq!(redirects(&spans), vec![">"]);
        assert_eq!(comments(&spans), vec!["#f"]);
    }

    #[test]
    fn nothing_in_a_comment_is_a_redirection() {
        // The same answer a separator and a `$NAME` get there, from the same
        // flag: the shell does not read the line, so there is nothing on it
        // to redirect.
        let spans = render_command("ls   # writes to > /etc/passwd");
        assert!(redirects(&spans).is_empty(), "a comment contains a redirection");
        assert_eq!(comments(&spans), vec!["# writes to > /etc/passwd"]);
    }

    #[test]
    fn nothing_inside_quotes_or_behind_a_backslash_is_a_redirection() {
        // The mirror of `echo 'a; b'` being one segment. An arrow inside a
        // string is an argument, and colouring it as structure would tell the
        // reader the shell is about to open a file it will not open.
        assert!(redirects(&render_command("echo '> /etc/passwd'")).is_empty());
        assert!(redirects(&render_command("echo \"> /etc/passwd\"")).is_empty());
        assert!(redirects(&render_command(r"echo \> /etc/passwd")).is_empty());
        assert!(redirects(&render_command(r"grep -e '2>&1' log")).is_empty());
    }

    #[test]
    fn a_quoted_target_keeps_its_operator_and_is_left_to_the_string_colour() {
        // A quoted word extends to include its quotes, so claiming this
        // target would put a `Redirect` region exactly on top of a `Quoted`
        // one, and two overlapping regions have no honest drawing. The same
        // refusal `claimable` makes for a command word, and it costs the same
        // thing: a colour on a word that is still on screen, drawn as itself,
        // with its operator still marked in front of it.
        let spans = render_command("echo x > \"my file\"");
        assert_eq!(redirects(&spans), vec![">"]);
        assert_eq!(quotes(&spans), vec!["\"my file\""]);
        assert_eq!(unrender(&spans), "echo x > \"my file\"");
    }

    #[test]
    fn a_target_with_a_variable_in_it_keeps_the_value_beside_it() {
        // Annotation runs before highlighting and a claimed span is left
        // alone, so the `$HOME` keeps the value the child will see and the
        // rest of the path is still drawn as a destination. A value is
        // information; a colour is decoration, and the decoration yields.
        let spans = rendered("echo x > $HOME/out", &env(&[("HOME", "/home/user")]));
        assert_eq!(variables(&spans), vec![("$HOME", Some("/home/user"))]);
        assert_eq!(redirects(&spans), vec![">", "/out"]);
        assert_eq!(unrender(&spans), "echo x > $HOME/out");
    }

    #[test]
    fn the_pipe_of_a_redirection_operator_is_not_a_pipe() {
        // The correctness half, and the entry this change takes off the
        // over-segmentation list. `>|` is one token; hatch used to draw a
        // segment boundary inside it, which is a boundary the shell does not
        // have.
        let spans = render_command("echo x >| out.txt");
        assert!(separators(&spans).is_empty(), "the `|` of a `>|` was read as a pipe");
        assert_eq!(redirects(&spans), vec![">|", "out.txt"]);
        assert_eq!(commands(&spans), vec!["echo"], "and only one segment has a command word");
    }

    #[test]
    fn a_real_pipe_beside_a_redirection_is_still_a_pipe() {
        // The other direction of the same claim: skipping an operator's bytes
        // must not skip a separator that merely stands next to one.
        let spans = render_command("make 2>&1 | tee log");
        assert_eq!(separators(&spans), vec!["|"]);
        assert_eq!(redirects(&spans), vec!["2>&", "1"]);
        assert_eq!(commands(&spans), vec!["make", "tee"]);
    }

    #[test]
    fn an_ampersand_pair_next_to_a_redirection_is_still_a_separator() {
        // `&>` and `&&` both begin with an `&`, and the first is looked for
        // at every byte the second is. A `&&` read as an `&>` would cost the
        // reader a segment boundary that really is one.
        assert_eq!(separators(&render_command("a &> out && b")), vec!["&&"]);
        assert_eq!(redirects(&render_command("a &> out && b")), vec!["&>", "out"]);
        assert_eq!(separators(&render_command("a && b")), vec!["&&"]);
    }

    #[test]
    fn a_redirection_ends_the_word_in_front_of_it() {
        // `<` and `>` are metacharacters, so bash reads `cat<file` as the
        // command `cat` with its input redirected. This pass used to
        // underline the whole of `cat<file` as the word that names what runs.
        let spans = render_command("cat<file");
        assert_eq!(commands(&spans), vec!["cat"]);
        assert_eq!(redirects(&spans), vec!["<", "file"]);
    }

    #[test]
    fn a_redirection_in_front_of_a_command_is_not_the_command() {
        // A redirection may precede the command it belongs to, so the word
        // that names what runs is the one after it. `>out.txt cat` runs
        // `cat`, and hatch used to underline `>out.txt`.
        let spans = render_command(">out.txt cat");
        assert_eq!(commands(&spans), vec!["cat"]);
        assert_eq!(redirects(&spans), vec![">", "out.txt"]);
        assert_eq!(commands(&render_command("2>&1 make")), vec!["make"]);
    }

    #[test]
    fn a_redirection_is_not_a_danger_marker() {
        // The line this pass does not cross. `/dev/null` and `/etc/passwd`
        // are the same construct and get the same colour; which of them
        // should alarm a reader is a question about the path, and answering
        // it is `render::danger`'s job. A window that shouted at `/dev/null`
        // would be teaching a reader to ignore it.
        let harmless = render_command("make > /dev/null");
        let alarming = render_command("make > /etc/passwd");
        assert_eq!(redirects(&harmless), vec![">", "/dev/null"]);
        assert_eq!(redirects(&alarming), vec![">", "/etc/passwd"]);
        for spans in [&harmless, &alarming] {
            assert!(
                spans.iter().all(|s| s.kind() != &SpanKind::Danger),
                "this pass reached a verdict it has no business reaching"
            );
        }
    }

    #[test]
    fn a_here_document_is_marked_at_both_ends_and_is_plain_in_between() {
        // `<<EOF` is an operator and the `EOF` after it is the word it points
        // at, which was true before the body had a pass of its own. What is
        // new is the third mark: the line that ends the body closes what the
        // operator opened, in the same colour, so the block a reader is
        // looking at has a top and a bottom. Between them the body is drawn
        // plain -- it is the payload, and quieting it or colouring it would be
        // a claim about text that is nothing but data.
        let command = "cat <<EOF\na; b\nEOF";
        let spans = render_command(command);
        assert_eq!(redirects(&spans), vec!["<<", "EOF", "EOF"]);
        assert_eq!(commands(&spans), vec!["cat"], "the body names nothing that runs");
        assert!(separators(&spans).is_empty(), "the body's `;` is data");
        assert_eq!(unrender(&spans), command);
    }

    #[test]
    fn a_redirection_is_drawn_as_its_own_text_and_the_spans_still_tile_it() {
        // The bound on every decoration in this module, restated for the kind
        // that is most tempting to treat as a claim. Nothing is replaced,
        // nothing is hidden, and a chip inside a target is still a chip.
        let command = "echo x > /tmp/\u{202E}gnp.exe";
        let spans = render_command(command);
        assert_eq!(unrender(&spans), command);
        assert!(spans.covers_source());
        let shown: String = spans.iter().map(|s| s.display_text()).collect();
        assert_eq!(shown, "echo x > /tmp/[RLO]gnp.exe", "the chip is the only substitution");
        assert_eq!(chips(&spans), vec!['\u{202E}']);
    }

    #[test]
    fn redirections_add_and_remove_nothing() {
        // The property the rest of this section is worth nothing without, on
        // the shapes most likely to trip the state machine: an operator at
        // either end of the input, one with no target, one whose target is
        // quoted, and one inside every construct that must suppress it.
        for command in [
            ">",
            "<",
            ">>>",
            ">|",
            "&>",
            "2>",
            "2",
            "22",
            "echo x >",
            "echo x > ",
            ">a>b>c",
            "echo x > 'out'",
            "echo x > \"out",
            r"echo x > a\ b",
            "echo '>' out",
            "# > out",
            "a >| b || c",
            "a >&& b",
            "echo x > \\\nout",
            "cat <<EOF\n> not a redirection\nEOF",
            "ünïcödé > ✓",
        ] {
            let spans = render_command(command);
            assert_eq!(unrender(&spans), command, "{command:?} did not round-trip");
            assert!(spans.covers_source(), "{command:?} is not tiled by its spans");
        }
    }

    #[test]
    fn a_descriptor_target_is_a_target_like_any_other() {
        // `>&` and `<&` point at a descriptor or a word and nothing here
        // tells them apart: which it is depends on what the word expands to,
        // and this scanner expands nothing. `-` closes a descriptor and
        // `1-` moves one, and both are words as far as this pass is
        // concerned.
        assert_eq!(redirects(&render_command("exec 2>&-")), vec!["2>&", "-"]);
        assert_eq!(redirects(&render_command("exec 2>&1-")), vec!["2>&", "1-"]);
        assert_eq!(redirects(&render_command("exec 3<&0")), vec!["3<&", "0"]);
    }

    #[test]
    fn an_operator_that_eats_an_ampersand_pair_costs_a_boundary_bash_does_not_have() {
        // Pinned because it moved and because the move is invisible in the
        // lists above. `a >&& b` used to be drawn with a segment boundary at
        // the `&&`; the `>&` now claims the first of those two characters, so
        // there is none. Neither rendering is the shell's, because bash
        // refuses to parse the line at all -- it is a syntax error near the
        // `&` -- so what changed is which wrong layout is drawn over a
        // command that will never run. It is here so that changing it again
        // has to be deliberate.
        let spans = render_command("a >&& b");
        assert!(separators(&spans).is_empty());
        assert_eq!(redirects(&spans), vec![">&"]);
        assert_eq!(unrender(&spans), "a >&& b");
    }

    #[test]
    fn an_escaped_space_keeps_a_target_in_one_piece() {
        // A quoted or escaped space is not a word break, so `a\ b` is one
        // word to the shell and one destination on screen.
        let spans = render_command(r"echo x > a\ b");
        assert_eq!(redirects(&spans), vec![">", r"a\ b"]);
    }

    #[test]
    fn highlighting_adds_and_removes_nothing() {
        let env = env(&[("HOME", "/home/user"), ("A", "; rm -rf /")]);
        for command in [
            "",
            " ",
            ";",
            "'",
            "\"",
            "''",
            "ls",
            "ls; rm 'a b' && echo \"$A\"",
            "FOO=1 BAR=2 env",
            "a\u{202E}b 'c\u{200B}d'",
            "ünïcödé 'ünïcödé'",
            "echo 'a; b",
            "cat <<EOF\na; b\nEOF",
            r"echo \'a\' $A",
        ] {
            let spans = rendered(command, &env);
            assert_eq!(unrender(&spans), command, "{command:?} did not round-trip");
            assert!(spans.covers_source(), "{command:?} is not tiled by its spans");
        }
    }

    #[test]
    fn a_command_of_many_segments_is_highlighted_in_one_walk() {
        // The command word of each segment is found with a cursor that only
        // ever moves forwards, so this is linear rather than one walk of the
        // command per segment -- and the number of segments is the agent's to
        // choose. The count is asserted so a walk that stopped early would
        // not pass.
        let count = 5_000;
        let command = "ls;".repeat(count);
        let spans = render_command(&command);
        assert_eq!(commands(&spans).len(), count);
        assert_eq!(unrender(&spans), command);
        assert!(spans.covers_source());
    }

    #[test]
    fn the_scanner_finds_quoted_strings_in_source_order() {
        assert_eq!(quoted_strings("a 'b' \"c\""), vec![2..5, 6..9]);
        assert_eq!(quoted_strings("no quotes"), Vec::<Range<usize>>::new());
        assert_eq!(quoted_strings("'"), vec![0..1], "an unterminated string is still one");
    }

    #[test]
    fn a_segment_stops_at_its_separator_and_not_after_it() {
        assert_eq!(segments("a; b"), vec![0..1, 2..4]);
        assert_eq!(segments("a\nb"), vec![0..2, 2..3], "a newline ends the word by being space");
        assert_eq!(segments("a"), vec![0..1]);
        assert_eq!(segments(""), vec![0..0]);
    }

    // ---- what the command will run ---------------------------------------

    /// The names, in source order and with repeats, as [`invoked`] reads
    /// them. A word hatch declined and a wrapper it could not see past are
    /// spelled out so a test cannot mistake one for a name.
    fn runs(command: &str) -> Vec<String> {
        invoked(command)
            .runs
            .into_iter()
            .map(|found| match found {
                Invocation::Named(name) => name,
                Invocation::Unread(word) => format!("<unread {word}>"),
                Invocation::Behind(name) => format!("<behind {name}>"),
            })
            .collect()
    }

    #[test]
    fn the_name_of_what_runs_is_the_word_the_pane_underlines() {
        // The two passes have to agree, because they are two drawings of one
        // claim: the underline in the annotated pane and the first entry of
        // the roster above it. They agree by construction -- both ask
        // `words` -- and this is what holds the construction in place.
        for command in [
            "ls -la /etc",
            "FOO=1 ls",
            ">out.txt cat f",
            "cat<f",
            "a && b || c | d",
            "cd /tmp; make -j4",
            // A command inside a command is two drawings of one claim as
            // well, and the first of these is the case that made the roster
            // say `ps`. The pane underlines the word inside the substitution
            // and the roster names it, in the order they are written.
            "x=$(podman ps -q)",
            "echo $(podman ps -q)",
            "echo `podman ps`",
            "$(podman ps) | wc -l",
            "A=$(date) make",
            "echo $(a; b)",
            "cd /tmp && \\\n  podman ps",
        ] {
            let spans = render_command(command);
            let underlined: Vec<String> =
                commands(&spans).into_iter().map(str::to_string).collect();
            assert_eq!(underlined, runs(command), "{command:?}");
        }
    }

    #[test]
    fn a_repeat_is_kept_because_the_count_is_the_point() {
        // Ten greps in a pipeline is the case the roster was built for, and
        // this pass is where the ten come from: deduplicating here would
        // throw away the number before anybody could draw it.
        assert_eq!(runs("grep a f | grep b | grep c"), vec!["grep", "grep", "grep"]);
    }

    #[test]
    fn a_wrapper_is_named_and_so_is_what_it_runs() {
        // "Ask what does this run of `sudo foo` and hatch answers `sudo`" was
        // the whole complaint. Both of them run, and both are here.
        assert_eq!(runs("sudo foo"), vec!["sudo", "foo"]);
        assert_eq!(runs("sudo -u root -- systemctl restart x"), vec!["sudo", "systemctl"]);
        assert_eq!(runs("env FOO=1 BAR=2 make"), vec!["env", "make"]);
        assert_eq!(runs("nice -n 19 ionice -c3 tar cf - ."), vec!["nice", "ionice", "tar"]);
        assert_eq!(runs("timeout -k 5s 30 curl https://x"), vec!["timeout", "curl"]);
        assert_eq!(runs("xargs -0 -n 1 rm -f"), vec!["xargs", "rm"]);
        assert_eq!(runs("nohup setsid --fork my-daemon"), vec!["nohup", "setsid", "my-daemon"]);
        assert_eq!(runs("stdbuf -oL grep x"), vec!["stdbuf", "grep"]);
        assert_eq!(runs("command -p ls"), vec!["command", "ls"]);
        assert_eq!(runs("exec -a login /bin/bash"), vec!["exec", "/bin/bash"]);
        assert_eq!(runs("doas -u root reboot"), vec!["doas", "reboot"]);
    }

    #[test]
    fn a_timeouts_duration_is_not_the_program_it_runs() {
        // The one wrapper with a positional in front of its command, and the
        // one whose grammar a wrapper walk with no notion of a positional
        // gets exactly wrong: it would name `30`.
        assert_eq!(runs("timeout 30 curl https://x"), vec!["timeout", "curl"]);
        assert_eq!(runs("timeout --foreground 30 curl https://x"), vec!["timeout", "curl"]);
    }

    #[test]
    fn an_option_hatch_has_not_heard_of_stops_the_walk_rather_than_moving_it() {
        // The failure this is shaped to avoid: an unknown option might take a
        // value, so skipping one word where two were wanted lands on the
        // value and reports it as the program. Naming nothing is the safe
        // direction and the window says which wrapper it is behind.
        assert_eq!(runs("sudo -X systemctl restart x"), vec!["sudo", "<behind sudo>"]);
        assert_eq!(runs("nice -5 make"), vec!["nice", "<behind nice>"], "the adjustment as an option");
        assert_eq!(runs("nohup -q foo"), vec!["nohup", "<behind nohup>"], "nohup has no options");
        assert_eq!(
            runs("sudo -i rm -rf /"),
            vec!["sudo", "<behind sudo>"],
            "a login shell turns the rest into a command line and not an argv"
        );
        assert_eq!(runs("command -v ls"), vec!["command", "<behind command>"], "which runs nothing");
    }

    #[test]
    fn a_wrapper_with_nothing_after_it_hides_nothing() {
        // Running out of words is not a failure to read them. `env` on its
        // own prints the environment, and a window that said hatch could not
        // see past it would be warning about a command with nothing behind
        // it.
        assert_eq!(runs("env"), vec!["env"]);
        assert_eq!(runs("env -i"), vec!["env"]);
        assert_eq!(runs("xargs -0"), vec!["xargs"]);
    }

    #[test]
    fn a_shells_script_argument_is_read_as_the_command_it_is() {
        // The line `Daemon::prepare_run` draws for a `root: true` request.
        // Without this the roster for every root command would be `run0` and
        // `bash`, which is hatch's own wrapper reported back as news.
        assert_eq!(
            runs("run0 --pipe --setenv=PAGER=cat -- bash -c 'systemctl restart x | tee log'"),
            vec!["run0", "bash", "systemctl", "tee"]
        );
        assert_eq!(runs("sh -c 'rm -rf /tmp/x'"), vec!["sh", "rm"]);
        assert_eq!(
            runs(r"bash -c 'echo '\''a b'\'' | wc'"),
            vec!["bash", "echo", "wc"],
            "the escaping `shell_quote` produces unquotes back to what it quoted"
        );
    }

    #[test]
    fn a_script_hatch_cannot_read_is_a_wrapper_it_cannot_see_past() {
        // `"$SCRIPT"` expands to something that is not on screen, so there is
        // nothing here to read as a command. Reporting an empty script would
        // say the shell runs nothing, which is the opposite of true.
        assert_eq!(runs("bash -c \"$SCRIPT\""), vec!["bash", "<behind bash>"]);
        assert_eq!(runs("bash -c"), vec!["bash"], "and no script at all runs nothing");
    }

    #[test]
    fn a_shell_given_a_file_names_the_shell_and_stops() {
        // What is in `deploy.sh` is not on screen, so the only honest answer
        // is `bash`. Naming the script file as though it were a program would
        // put a path in the list that nothing execs.
        assert_eq!(runs("bash deploy.sh --now"), vec!["bash"]);
    }

    #[test]
    fn a_reserved_word_is_not_a_program_and_is_not_listed() {
        // The other half of the crying-wolf problem. `if` is on no PATH
        // anywhere, and a list that reported it as unresolvable would put a
        // warning on every conditional anybody writes.
        assert_eq!(runs("if grep -q x f; then rm y; else touch y; fi"), vec!["grep", "rm", "touch"]);
        assert_eq!(runs("while read line; do echo $line; done"), vec!["read", "echo"]);
        assert_eq!(runs("! grep -q x f"), vec!["grep"], "negation is a reserved word too");
        assert_eq!(runs("time make -j4"), vec!["make"], "and so is a bare `time`");
        assert_eq!(runs("{ ls; cat f; }"), vec!["ls", "cat"]);
    }

    #[test]
    fn a_reserved_word_that_is_not_followed_by_a_command_stops_the_walk() {
        // `for x in *.txt` is a name and a word list, not a command, so
        // reading past `for` would name `x`. The body is a segment of its own
        // and is found there.
        assert_eq!(runs("for f in *.txt; do cat $f; done"), vec!["cat"]);
        assert_eq!(
            runs("case $x in a) ls ;; esac"),
            Vec::<String>::new(),
            "and a `case` branch is a parenthesis this pass says nothing about"
        );
    }

    #[test]
    fn a_function_the_command_defines_is_bound_and_not_run() {
        // Three spellings of the same thing, and in all three the body's own
        // commands are what run. The name is recorded so that calling it
        // later resolves to the command itself rather than to nothing.
        let bound = invoked("deploy() { rsync -a . host:/srv; }; deploy");
        assert_eq!(
            bound.runs,
            vec![
                Invocation::Named("rsync".to_string()),
                Invocation::Named("deploy".to_string())
            ]
        );
        assert!(bound.defines.contains("deploy"));
        assert!(invoked("deploy () { ls; }").defines.contains("deploy"), "with a space");
        assert!(invoked("deploy(){ ls; }").defines.contains("deploy"), "and with none");
    }

    #[test]
    fn a_name_is_read_through_its_quoting_and_not_through_its_expansions() {
        // `'ls' -l` really does run `ls`, so declining it would be
        // under-reporting for a reason the reader cannot see. `$TOOL` is the
        // other way round: what it stands for is not on screen and hatch
        // expands nothing.
        assert_eq!(runs("'ls' -l"), vec!["ls"]);
        assert_eq!(runs(r"\ls -l"), vec!["ls"]);
        assert_eq!(runs("'/usr/bin/grep' x"), vec!["/usr/bin/grep"]);
        assert_eq!(runs("$TOOL --version"), vec!["<unread $TOOL>"]);
        assert_eq!(runs("\"$TOOL\" --version"), vec!["<unread \"$TOOL\">"]);
        assert_eq!(runs("*.sh"), vec!["<unread *.sh>"], "a glob names whatever it matches");
        assert_eq!(runs("~/bin/tool"), vec!["<unread ~/bin/tool>"], "and a tilde expands");
        assert_eq!(runs("'unterminated"), vec!["<unread 'unterminated>"]);
    }

    #[test]
    fn the_shells_punctuation_is_read_whole_and_not_as_a_pattern() {
        // `[` is the test builtin and is made entirely of characters that are
        // pattern syntax anywhere else. Declining it would put `[ -f x ]` --
        // one of the commonest lines in any script -- in the list as a word
        // hatch could not read.
        assert_eq!(runs("[ -f x ] && echo yes"), vec!["[", "echo"]);
        assert_eq!(runs("[[ -n $x ]] && echo yes"), vec!["echo"], "the keyword is not listed");
        assert_eq!(runs(": ; ls"), vec![":", "ls"]);
        assert_eq!(runs("[abc]ls"), vec!["<unread [abc]ls>"], "and a real glob still is one");
    }

    #[test]
    fn nothing_in_a_comment_runs() {
        // The comment pass already decided this for segmentation and for
        // `$NAME`; asking it again here is what keeps the three from
        // disagreeing about the same bytes.
        assert_eq!(runs("echo hi   # then && rm -rf /tmp"), vec!["echo"]);
        assert!(runs("# rm -rf /").is_empty());
    }

    #[test]
    fn a_redirection_is_never_the_thing_that_runs() {
        // Both corrections the redirection work made, asked of this pass:
        // `>out.txt cat` runs `cat`, and `cat<f` runs `cat`.
        assert_eq!(runs(">out.txt cat f"), vec!["cat"]);
        assert_eq!(runs("cat<f"), vec!["cat"]);
        assert!(runs("> out.txt").is_empty(), "a redirection alone runs nothing");
    }

    #[test]
    fn a_script_inside_a_script_stops_at_a_depth_rather_than_at_a_stack() {
        // The input is agent-controlled, so the one thing that must not
        // happen is an unbounded recursion in a pass that runs before a human
        // is asked anything.
        let mut command = "ls".to_string();
        for _ in 0..12 {
            command = format!("bash -c '{}'", command.replace('\'', r"'\''"));
        }
        let found = runs(&command);
        assert!(found.len() <= SCRIPT_DEPTH + 1, "{found:?}");
        assert!(found.iter().all(|name| name == "bash"), "and it stopped before the innermost");
    }

    #[test]
    fn the_builtin_and_keyword_tables_hold_the_names_the_window_leans_on() {
        // Named individually because each of them is a way for the list to
        // cry wolf: `cd` on every second command, `echo` on every first, `:`
        // in every loop.
        for name in [":", ".", "cd", "echo", "export", "read", "set", "test", "["] {
            assert!(is_builtin(name), "{name} is a builtin and would be reported as missing");
        }
        for name in ["if", "then", "else", "fi", "for", "do", "done", "while", "[[", "time"] {
            assert!(is_keyword(name), "{name} is a reserved word");
        }
        assert!(!is_builtin("grep"), "and an ordinary program is neither");
        assert!(!is_keyword("grep"));
    }

    #[test]
    fn a_name_that_is_both_a_builtin_and_a_binary_is_read_as_the_builtin() {
        // bash looks for a builtin before it looks at PATH, and commands
        // reach it as `bash -c`. The six that are both are listed here so
        // that a later edit to `BUILTINS` cannot quietly drop one.
        for name in ["echo", "test", "[", "kill", "printf", "pwd"] {
            assert!(is_builtin(name), "{name}");
        }
    }

    #[test]
    fn every_wrapper_in_the_table_is_reachable_by_its_own_name() {
        // A table entry whose name never appears in command position is an
        // entry nothing can use. This is cheap and catches a typo in a name,
        // which would otherwise show up only as a wrapper that silently
        // stopped being unwrapped.
        for wrapper in WRAPPERS {
            // Its positionals filled in, because `timeout`'s duration comes
            // before its command and a wrapper handed one word would name
            // that word.
            let filler = "1 ".repeat(wrapper.positionals);
            let command = format!("{} {filler}whatever-runs", wrapper.name);
            let found = runs(&command);
            assert!(
                found.contains(&"whatever-runs".to_string())
                    || matches!(wrapper.after, After::Nothing),
                "{found:?} did not reach past {}",
                wrapper.name
            );
        }
    }

    use proptest::prelude::*;

    #[test]
    fn a_command_an_agent_wrote_to_be_slow_is_read_in_one_pass() {
        // Twenty thousand wrapper hops and a twenty-thousand-stage pipeline.
        // The numbers are here as a shape rather than as a clock: a pass that
        // re-collected the remaining words at every hop would be quadratic in
        // a length the agent picks, and this window opens before anybody is
        // asked anything.
        let hops = format!("{}ls", "sudo ".repeat(20_000));
        assert_eq!(invoked(&hops).runs.len(), 20_001);

        let pipeline = "grep x | ".repeat(20_000) + "ls";
        assert_eq!(invoked(&pipeline).runs.len(), 20_001);
    }

    proptest! {
        /// The input is agent-controlled and this pass runs before a human is
        /// asked anything, so what has to hold over arbitrary text is that it
        /// finishes and that nothing it says is longer than what it was given.
        /// The bound is the real check: every walk here is an index into a
        /// finite word list and every name is a substring, so a result with
        /// more entries than the command has characters would mean an index
        /// that stopped moving forward.
        #[test]
        fn reading_what_runs_terminates_on_anything_an_agent_can_write(command in ".*") {
            let found = invoked(&command);
            prop_assert!(found.runs.len() <= command.len());
            prop_assert!(found.defines.len() <= command.len());
        }

        /// The same over text made of the characters that actually decide
        /// this pass, which a `.*` generator reaches only by accident: the
        /// wrapper names, the separators, the quotes and the punctuation the
        /// shell keeps for itself.
        #[test]
        fn reading_what_runs_survives_the_characters_that_decide_it(
            command in prop::collection::vec(
                prop::sample::select(vec![
                    "sudo ", "env ", "bash ", "-c ", "timeout ", "run0 ", "-- ", "if ", "then ",
                    "{ ", "} ", "( ", ") ", "; ", "&& ", "| ", "> ", "# ", "'", "\\", "$x ",
                    "A=1 ", "ls ", "f() ", "\n", "<<EOF ", "EOF",
                ].into_iter().map(str::to_string).collect::<Vec<String>>()),
                0..40,
            ).prop_map(|parts| parts.concat()),
        ) {
            let found = invoked(&command);
            prop_assert!(found.runs.len() <= command.len());
        }
    }

    #[test]
    fn an_assignment_is_a_name_then_an_equals_and_nothing_looser() {
        assert!(is_assignment("A=1"));
        assert!(is_assignment("_a9="), "an empty value is still an assignment");
        assert!(!is_assignment("=1"), "no name at all");
        assert!(!is_assignment("9A=1"), "a name may not start with a digit");
        assert!(!is_assignment("a-b=1"), "nor carry a hyphen");
        assert!(!is_assignment("ls"), "and a word with no `=` is not one");
        assert!(!is_assignment(""));
    }


    // --- here-documents: the region that is not shell ---------------------

    /// Every run of here-document data in `command`, in source order, paired
    /// with which part of one it is.
    ///
    /// Straight off the scanner's flag, because the flag is what the four
    /// passes read: a test that inferred the body from the colours would be
    /// checking the drawing rather than the reading it comes from.
    fn parts(command: &str) -> Vec<(&str, Here)> {
        let mut out: Vec<(Range<usize>, Here)> = Vec::new();
        for c in scan(command) {
            let Some(here) = c.here else { continue };
            let end = c.offset + c.ch.len_utf8();
            match out.last_mut() {
                Some((last, part)) if last.end == c.offset && *part == here => last.end = end,
                _ => out.push((c.offset..end, here)),
            }
        }
        out.into_iter().map(|(range, part)| (&command[range], part)).collect()
    }

    const EXPANDS: Here = Here::Body { expands: true };
    const LITERAL: Here = Here::Body { expands: false };

    #[test]
    fn a_body_is_data_and_the_four_passes_that_read_it_all_say_so() {
        // The report this work came from, drawn exactly as it was written.
        // `invoked` answered `[cat, hello, EOF]`, so the roster said *nothing
        // on the command's PATH answers to hello, EOF* -- an orange line under
        // one of the plainest shapes an agent writes, which is how a warning
        // stops being read at all.
        let env = env(&[("HOME", "/home/user")]);
        let command = "cat <<'EOF' > /tmp/x\nhello\nEOF";
        let spans = rendered(command, &env);

        assert_eq!(invoked(command).runs, vec![Invocation::Named("cat".to_string())]);
        assert_eq!(commands(&spans), vec!["cat"], "no word of the body runs");
        assert!(separators(&spans).is_empty());
        assert!(comments(&spans).is_empty());
        assert_eq!(unrender(&spans), command);
    }

    #[test]
    fn the_body_starts_after_the_next_newline_and_not_after_the_operator() {
        // The rule that makes `cat <<EOF | grep x` work: everything on the
        // operator's own line is shell, pipe and all, and the body is what
        // comes after the newline. A pass that started the body at the
        // operator would swallow a whole pipeline stage.
        let command = "cat <<EOF | grep x\nbody\nEOF\nls";
        let spans = render_command(command);

        assert_eq!(parts(command), vec![("body\n", EXPANDS), ("EOF\n", Here::Delimiter)]);
        assert_eq!(separators(&spans), vec!["|"], "the pipe is on the operator's line");
        assert_eq!(commands(&spans), vec!["cat", "grep", "ls"]);
    }

    #[test]
    fn a_body_ends_on_a_line_that_is_exactly_the_delimiter() {
        // Exactly, which is bash's rule and not a convenience: a line of
        // `EOF ` does not end the body, and the shell reads the rest of the
        // command as more of it. Checked against a real shell, which is also
        // where the trailing-space case comes from.
        assert_eq!(
            parts("cat <<EOF\na\nEOF\nls"),
            vec![("a\n", EXPANDS), ("EOF\n", Here::Delimiter)]
        );
        assert_eq!(parts("cat <<EOF\na\nEOF \nls"), vec![("a\nEOF \nls", EXPANDS)]);
        assert_eq!(
            parts("cat <<EOF\na\nXEOF\nEOF"),
            vec![("a\nXEOF\n", EXPANDS), ("EOF", Here::Delimiter)],
            "a line the delimiter is only part of ends nothing"
        );
    }

    #[test]
    fn a_dash_here_document_strips_tabs_from_its_delimiter_and_not_spaces() {
        // `<<-` strips leading tabs from the body's lines and from the line
        // that terminates it, so an `EOF` indented with tabs ends the body.
        // Spaces are not stripped and an `EOF` indented with them terminates
        // nothing -- which was checked against a real shell, where the rest of
        // the command went on being data.
        assert_eq!(
            parts("cat <<-EOF\n\tbody\n\tEOF\nls"),
            vec![("\tbody\n", EXPANDS), ("\tEOF\n", Here::Delimiter)]
        );
        assert_eq!(parts("cat <<-EOF\n  body\n  EOF\nls"), vec![("  body\n  EOF\nls", EXPANDS)]);
        assert_eq!(
            parts("cat <<EOF\n\tbody\n\tEOF\nls"),
            vec![("\tbody\n\tEOF\nls", EXPANDS)],
            "a plain `<<` strips nothing, so an indented delimiter is body"
        );
    }

    #[test]
    fn quoting_the_delimiter_turns_expansion_off_for_the_whole_body() {
        // The half of this that is most tempting to flatten, and the half a
        // reader is most entitled to. A bare `<<EOF` expands, so the value
        // beside a `$HOME` in its body is the value the command will receive;
        // a quoted delimiter expands nothing anywhere in the body, so the same
        // value would be a lie told in the window's most authoritative voice.
        //
        // All four spellings are bash's, the last one included: the rule is
        // about the word carrying a quote anywhere, not about the quote being
        // in front. Each was checked against a real shell.
        let env = env(&[("HOME", "/home/user")]);
        let resolved = vec![("$HOME", Some("/home/user"))];
        assert_eq!(variables(&rendered("cat <<EOF\n$HOME\nEOF", &env)), resolved);
        for quoted in [
            "cat <<'EOF'\n$HOME\nEOF",
            "cat <<\"EOF\"\n$HOME\nEOF",
            "cat <<\\EOF\n$HOME\nEOF",
            "cat <<EO'F'\n$HOME\nEOF",
        ] {
            assert!(
                variables(&rendered(quoted, &env)).is_empty(),
                "{quoted:?} substitutes nothing, and the window may not say otherwise"
            );
            assert_eq!(parts(quoted), vec![("$HOME\n", LITERAL), ("EOF", Here::Delimiter)]);
        }
    }

    #[test]
    fn several_here_documents_on_one_line_take_their_bodies_in_order() {
        // `cat <<A <<B` reads body A and then body B, both starting after that
        // same newline, and the line that ends A is followed immediately by
        // the first line of B with no shell in between. Checked against a real
        // shell, which runs `echo after` and nothing in either body.
        let command = "cat <<A <<B\nbodyA\nA\nbodyB\nB\nrm -rf /";
        assert_eq!(
            parts(command),
            vec![
                ("bodyA\n", EXPANDS),
                ("A\n", Here::Delimiter),
                ("bodyB\n", EXPANDS),
                ("B\n", Here::Delimiter),
            ]
        );
        assert_eq!(commands(&render_command(command)), vec!["cat", "rm"]);
        assert_eq!(invoked(command).runs.len(), 2, "two commands, not six");
    }

    #[test]
    fn the_line_that_ends_a_body_is_structure_and_not_a_command() {
        // It is the delimiter closing what the operator opened, so it is drawn
        // in the kind the operator's own word is drawn in -- the block a
        // reader is looking at gets a top and a bottom. What it is not is a
        // program: `EOF` resolves to nothing anywhere, and naming it is how
        // the roster came to report a word nothing answers to.
        let command = "cat <<EOF\nbody\nEOF";
        let spans = render_command(command);
        assert_eq!(redirects(&spans), vec!["<<", "EOF", "EOF"]);
        assert_eq!(commands(&spans), vec!["cat"]);
        assert_eq!(invoked(command).runs, vec![Invocation::Named("cat".to_string())]);
    }

    #[test]
    fn the_body_itself_is_drawn_plain_and_carries_no_colour_at_all() {
        // The decision, pinned. A body is the payload -- the file
        // `cat <<EOF > /etc/sudoers` writes is in it and nowhere else -- so it
        // is the last text on the pane that should be quieted or tinted. Plain
        // at full contrast is the one drawing that claims nothing, which is
        // the right claim to make about data, and the delimiters either side
        // of it are what say where the block ends.
        let env = env(&[("HOME", "/home/user")]);
        let command = "cat <<EOF\n'quoted' # hash > arrow\nEOF";
        let spans = rendered(command, &env);
        let body: Vec<&str> = spans
            .iter()
            .filter(|s| s.range().start >= 10 && s.range().end <= 34)
            .filter(|s| s.kind() != &SpanKind::Plain)
            .map(Span::text)
            .collect();
        assert_eq!(body, vec!["\n"], "only the line ending, which is a chip");
        assert!(quotes(&spans).is_empty(), "a quote in a body opens nothing");
    }

    #[test]
    fn an_unterminated_here_document_runs_to_the_end_of_the_command() {
        // Because that is what bash does with it: it warns that the
        // here-document was delimited by end-of-file, hands the command
        // everything that was left, and runs none of it. So the `rm` below is
        // text `cat` prints, and drawing it as shell would be the lie.
        //
        // Nothing is hidden by this. A body carries no colour, no fade and no
        // chip, so every character of one is on screen drawn as itself at the
        // contrast of the line above it; what the choice costs is that the
        // roster does not name a program the shell does not run either.
        let command = "cat <<EOF\nhello\nrm -rf /";
        let spans = render_command(command);
        assert_eq!(parts(command), vec![("hello\nrm -rf /", EXPANDS)]);
        assert_eq!(commands(&spans), vec!["cat"]);
        assert!(separators(&spans).is_empty());
        assert_eq!(unrender(&spans), command);
        let shown: String = spans.iter().map(|s| s.display_text()).collect();
        assert_eq!(shown, "cat <<EOF↵hello↵rm -rf /", "every character is still on screen");
    }

    #[test]
    fn a_here_string_is_not_a_here_document() {
        // `<<<` takes a word on the same line and nothing after it, which is
        // the redirection work's answer and stays that way.
        assert!(parts("cat <<<word\nls").is_empty());
        assert_eq!(commands(&render_command("cat <<<word\nls")), vec!["cat", "ls"]);
        assert_eq!(redirects(&render_command("cat <<<word")), vec!["<<<", "word"]);
    }

    #[test]
    fn an_operator_with_no_delimiter_after_it_opens_no_body() {
        // There is no word for a body to end on, so reading one would be
        // inventing the shape of the rest of the command. bash calls this a
        // syntax error; hatch draws the next line as the shell it looks like,
        // which is this module's safe direction -- being wrong towards *no*
        // here-document leaves text drawn exactly as it was drawn before.
        assert!(parts("cat <<\nls").is_empty());
        assert!(parts("cat << ;\nls").is_empty());
        assert!(parts("cat <<EOF # note\nbody\nEOF").len() == 2, "a comment after one is fine");
        assert!(parts("cat << # EOF\nls").is_empty(), "and a comment instead of one is not");
    }

    #[test]
    fn a_continued_line_is_not_the_line_the_body_starts_after() {
        // `\<newline>` is a line continuation, so the line the operator is on
        // has not ended and the body waits for the newline that really ends
        // it. Checked against a real shell.
        assert_eq!(
            parts("cat <<EOF \\\n  -\nbody\nEOF"),
            vec![("body\n", EXPANDS), ("EOF", Here::Delimiter)]
        );
    }

    #[test]
    fn a_here_document_is_one_segment_with_the_command_that_opened_it() {
        // The body is that command's stdin rather than the next thing to run,
        // so none of the newlines through the last delimiter line ends a
        // segment -- and the one after it does, which is what gives the
        // command on the next line a segment of its own.
        //
        // The lines still break, because a newline is still a newline: the
        // classifier chips it and asks for the break, exactly as it does
        // inside a multi-line quoted string. So a forty-line config file is
        // forty rows on screen and one segment, which is what it is.
        let command = "cat <<EOF\none\ntwo\nEOF\nls";
        assert_eq!(segments(command), vec![0..22, 22..24]);
        let spans = render_command(command);
        assert_eq!(breaks(&spans), vec!["one", "two", "EOF", "ls"]);
    }

    #[test]
    fn nothing_in_a_body_is_read_as_shell_state_the_rest_of_the_line_inherits() {
        // A quote in a body opens nothing and a `<<` in one starts no second
        // here-document, so the shell after the delimiter line is read exactly
        // as it would have been. Without this an apostrophe in a sentence
        // would open a string that ran to the end of the command and took
        // every boundary after it with it.
        let command = "cat <<EOF\nit's fine <<AGAIN\nEOF\nls; echo done";
        let spans = render_command(command);
        assert_eq!(commands(&spans), vec!["cat", "ls", "echo"]);
        assert_eq!(separators(&spans), vec![";"]);
        assert!(quotes(&spans).is_empty());
        assert!(redirects(&spans).iter().all(|r| *r != "AGAIN"));
    }

    #[test]
    fn a_here_document_operator_inside_quotes_is_two_characters_of_text() {
        // The same rule every other construct on this page is found by, asked
        // of the same state rather than written out again.
        assert!(parts("echo '<<EOF'\nls").is_empty());
        assert!(parts("echo \"<<EOF\"\nls").is_empty());
        assert!(parts("echo \\<<EOF\nls").is_empty(), "an escaped `<` is not an operator");
    }

    #[test]
    fn a_delimiter_may_be_any_word_the_shell_accepts() {
        // Including one made of punctuation. `<<';'` ends on a line that is a
        // single `;`, and that line is the delimiter rather than a separator
        // -- the flag is read before the separator table is, so the two cannot
        // disagree about the byte.
        let command = "cat <<';'\nbody\n;\nls";
        let spans = render_command(command);
        assert_eq!(parts(command), vec![("body\n", LITERAL), (";\n", Here::Delimiter)]);
        assert!(separators(&spans).is_empty(), "the terminating line is not a boundary");
        assert_eq!(commands(&spans), vec!["cat", "ls"]);
    }

    #[test]
    fn an_empty_body_is_a_delimiter_line_and_not_a_body_of_one_line() {
        // `cat <<EOF` with `EOF` on the very next line is how a script says
        // *nothing on stdin*. Reading it as a one-line body would leave the
        // scanner looking for a delimiter that has already gone past, and the
        // rest of the command would be data.
        let command = "cat <<EOF\nEOF\nls";
        assert_eq!(parts(command), vec![("EOF\n", Here::Delimiter)]);
        assert_eq!(commands(&render_command(command)), vec!["cat", "ls"]);
    }

    #[test]
    fn a_here_document_is_drawn_as_itself_and_the_spans_still_tile_it() {
        // The bound on all of it, restated for the region that is not shell: a
        // body is not a place where characters may go missing, and a chip in
        // one is still a chip.
        let env = env(&[("HOME", "/home/user")]);
        for command in [
            "cat <<EOF",
            "cat <<EOF\n",
            "cat <<EOF\n\n",
            "cat <<EOF\nEOF",
            "cat <<-EOF\n\t\tEOF",
            "cat <<'EOF'\n$HOME\nEOF\n",
            "cat <<EOF\n\u{202E}gnp.exe\nEOF",
            "cat <<EOF <<EOF\nEOF\nEOF\nls",
            "cat <<\u{00A0}\n\u{00A0}\nls",
            "cat <<EOF\nünïcödé ✓\nEOF",
        ] {
            let spans = rendered(command, &env);
            assert_eq!(unrender(&spans), command, "{command:?} did not round-trip");
            assert!(spans.covers_source(), "{command:?} is not tiled by its spans");
        }
        let spans = render_command("cat <<EOF\n\u{202E}gnp.exe\nEOF");
        assert_eq!(chips(&spans), vec!['\n', '\u{202E}', '\n'], "a body still chips");
    }

    #[test]
    fn a_command_of_many_here_documents_is_read_in_one_walk() {
        // The input is the agent's, and a line of twenty thousand `<<A`s with
        // twenty thousand bodies under it is a line an agent can write. Every
        // walk here moves forward only: the queue is taken from the front, and
        // each line is compared against its delimiter once, at the newline in
        // front of it. The counts are asserted so that a walk which gave up
        // early would not pass for a fast one.
        let count = 2_000;
        let command = format!(
            "cat{}\n{}",
            " <<A".repeat(count),
            "body\nA\n".repeat(count)
        );
        let spans = render_command(&command);
        assert_eq!(commands(&spans), vec!["cat"]);
        assert_eq!(
            redirects(&spans).len(),
            count * 3,
            "an operator, the word it points at, and the line the body ends on, each time"
        );
        assert_eq!(unrender(&spans), command);
    }

    #[test]
    fn the_delimiter_of_a_here_document_is_the_word_with_its_quoting_removed() {
        // The reading `delimiter_of` does, and the flag that falls out of it.
        // Quoting *any* part of the word turns expansion off for the whole
        // body, which is bash's rule and the reason this is not "starts with a
        // quote".
        assert_eq!(delimiter_of("EOF"), ("EOF".to_string(), true));
        assert_eq!(delimiter_of("'EOF'"), ("EOF".to_string(), false));
        assert_eq!(delimiter_of("\"EOF\""), ("EOF".to_string(), false));
        assert_eq!(delimiter_of("\\EOF"), ("EOF".to_string(), false));
        assert_eq!(delimiter_of("EO'F'"), ("EOF".to_string(), false));
        assert_eq!(delimiter_of("E\\ OF"), ("E OF".to_string(), false));
        assert_eq!(delimiter_of("'EOF"), ("EOF".to_string(), false), "unterminated: no panic");
        assert_eq!(delimiter_of(""), (String::new(), true));
    }

    // --- the boundary of what `$` is claimed to mean ----------------------

    #[test]
    fn positional_and_special_parameters_are_left_plain() {
        // None of these is a name in the child environment, so none of them
        // has a value this window could show. `$$` is the sharp one: the
        // shell reads it as the PID and leaves `HOME` literal, so a scanner
        // that resumed one byte later would find `$HOME` and annotate an
        // expansion that does not happen.
        let env = env(&[("HOME", "/home/user"), ("1", "no"), ("@", "no")]);
        for command in [
            "echo $1", "echo $@", "echo $?", "echo $$", "echo $*", "echo $#", "echo $-",
            "echo $!", "echo $0", "echo $$HOME", "echo $1HOME", "echo $", "echo $ HOME",
        ] {
            let spans = rendered(command, &env);
            assert!(variables(&spans).is_empty(), "{command:?} claims a variable it should not");
            assert_eq!(unrender(&spans), command);
        }
    }

    #[test]
    fn substitutions_and_modified_expansions_are_left_plain() {
        // Each of these substitutes something the child environment does not
        // contain, so naming a value beside it would be a claim about the
        // wrong thing. `${HOME:-$USER}` is consumed whole rather than
        // annotated on its inner reference: conservative in the safe
        // direction.
        let env = env(&[("HOME", "/home/user"), ("USER", "user")]);
        for command in [
            "echo $(id)",
            "echo $((1+1))",
            "echo ${HOME:-/tmp}",
            "echo ${#HOME}",
            "echo ${!HOME}",
            "echo ${HOME:-$USER}",
            "echo ${}",
            "echo ${HOME",
            "echo ${ HOME }",
        ] {
            let spans = rendered(command, &env);
            assert!(variables(&spans).is_empty(), "{command:?} claims a variable it should not");
            assert_eq!(unrender(&spans), command);
        }
    }

    #[test]
    fn a_reference_inside_a_substitution_still_expands_and_is_annotated() {
        // The subshell gets the same environment, so this one is honest --
        // and it is the case that keeps the rule above from being written as
        // "anything after a `$(` is off limits".
        let env = env(&[("HOME", "/home/user")]);
        let spans = rendered("echo $(ls $HOME)", &env);
        assert_eq!(variables(&spans), vec![("$HOME", Some("/home/user"))]);
    }

    #[test]
    fn an_unescaped_ansi_c_string_hides_its_references_by_accident() {
        // `$'…'` does not expand parameters, and this case comes out right --
        // but through the ordinary single-quote rule, not through any model
        // of `$'…'`. The distinction is not pedantic: the moment the string
        // contains `\'` the same accident stops working, which is the first
        // entry in `over_annotation_where_the_model_stops` below.
        let env = env(&[("HOME", "/home/user")]);
        assert!(variables(&rendered("echo $'$HOME'", &env)).is_empty());
    }

    #[test]
    fn over_annotation_where_the_model_stops() {
        // The mirror of `over_segmentation_where_the_model_stops`, and it
        // exists for the same reason: annotation asks the same scanner the
        // same question, so it inherits the same gaps. Where an unmodelled
        // construct makes a `$` inert, it is annotated anyway. Each case was
        // checked against a real shell; this test is what stops the list
        // drifting from the docs.
        // One entry, where there were two: a body under a quoted delimiter was
        // the other, and it is annotated correctly now rather than recorded
        // here. What is left is ANSI-C quoting, where `\'` does not close the
        // string, so the whole of `a'$HOME` is literal and hatch resolves a
        // `$HOME` the shell never substitutes.
        let env = env(&[("HOME", "/home/user")]);
        let command = r"echo $'a\'$HOME'";
        let spans = rendered(command, &env);
        assert_eq!(variables(&spans), vec![("$HOME", Some("/home/user"))]);
        // The bound on the cost: the text is untouched and drawn as itself, so
        // what is wrong is a label beside a `$`, not the command the reader
        // approves.
        assert_eq!(unrender(&spans), command);
    }

    #[test]
    fn names_the_shell_maintains_are_left_plain() {
        // The sibling of `positional_and_special_parameters_are_left_plain`,
        // and it fails the same test those do: the shell substitutes these
        // from somewhere other than the environment hatch constructs. They
        // differ only in fitting the grammar, which is what makes drawing
        // them as *unset* possible and wrong. `$PWD` shown unset turns
        // `rm -rf $PWD/build` into an argument the reader parses as `/build`.
        //
        // The second environment is the point of the `exec_env` half: even
        // configured, they stay Plain, because the shell overwrites `PWD` and
        // `IFS` at startup regardless of what it inherits and we cannot tell
        // which value wins.
        for env in [
            env(&[]),
            env(&[("PWD", "/configured"), ("IFS", ":"), ("SHLVL", "9"), ("TERM", "xterm")]),
        ] {
            for command in [
                "rm -rf $PWD/build", "echo ${PWD}", "echo $IFS", "echo $RANDOM",
                "echo $SECONDS", "echo $LINENO", "echo $PPID", "echo $UID", "echo $EUID",
                "echo $HOSTNAME", "echo $OPTARG", "echo $SHLVL", "echo $_", "echo $OLDPWD",
                "echo $OPTIND", "echo $REPLY", "echo $FUNCNAME", "echo $BASH_SOURCE",
                "echo $PS1", "echo $PS4", "echo $SHELL", "echo $TERM",
            ] {
                let spans = rendered(command, &env);
                assert!(
                    variables(&spans).is_empty(),
                    "{command:?} must not be drawn as a variable, set or unset"
                );
                assert_eq!(unrender(&spans), command);
            }
        }
    }

    #[test]
    fn path_and_home_are_still_annotated() {
        // The two names in that family hatch can answer for. `PATH` because
        // `build_child_env` always supplies it and a shell that finds it set
        // uses it; `HOME` because no shell invents one.
        let env = env(&[("PATH", "/usr/bin"), ("HOME", "/home/user")]);
        let spans = rendered("PATH=$PATH ls $HOME", &env);
        assert_eq!(
            variables(&spans),
            vec![("$PATH", Some("/usr/bin")), ("$HOME", Some("/home/user"))]
        );
    }

    // --- the value is beside the text, and it is defanged -----------------

    #[test]
    fn a_variable_is_drawn_as_itself_and_the_value_sits_beside_it() {
        // Invariant 1b permits only a chip to draw something other than its
        // text, so the resolved value may never be substituted for the
        // reference. The span shape has to make that the easy thing: the text
        // is what is drawn, and the value is reachable only through a
        // separate accessor.
        let env = env(&[("HOME", "/home/user")]);
        let spans = rendered("ls $HOME", &env);
        let variable = spans.iter().find(|s| s.variable().is_some()).unwrap();
        assert_eq!(variable.display_text(), "$HOME");
        assert_eq!(variable.chip_codepoint(), None, "it is not a chip and may not become one");
        let shown: String = spans.iter().map(|s| s.display_text()).collect();
        assert_eq!(shown, "ls $HOME", "the value is nowhere in the drawn line");
    }

    #[test]
    fn a_resolved_value_cannot_carry_a_control_character_into_the_window() {
        // The value is user-controlled but the *choice* of which value to
        // show is the agent's: it writes the command, so it picks the name.
        // A configured value carrying a bidi override or a newline would
        // reorder or split the line the command is read on, so it arrives
        // flattened to the same chip vocabulary the command itself uses.
        let env = env(&[("V", "/a\u{202E}b\nc\u{200B}")]);
        let spans = rendered("echo $V", &env);
        assert_eq!(variables(&spans), vec![("$V", Some("/a[RLO]b[LF]c[ZWSP]"))]);
        let (_, value) = spans.iter().find_map(Span::variable).unwrap();
        assert!(
            !value.unwrap().chars().any(|c| c.is_control() || c == '\u{202E}'),
            "nothing that commands a terminal or reorders a line survives"
        );
    }

    #[test]
    fn an_empty_value_is_not_the_same_as_an_unset_one() {
        let spans = rendered("echo $A", &env(&[("A", "")]));
        assert_eq!(variables(&spans), vec![("$A", Some(""))]);
    }

    #[test]
    fn re_annotating_resolves_against_the_environment_it_was_last_given() {
        // The pass is idempotent in shape and current in content: a span that
        // is already a Variable is re-resolved rather than left carrying a
        // value from some other environment.
        let spans = rendered("ls $HOME", &env(&[("HOME", "/first")]));
        let spans = annotate_variables(spans, &env(&[("HOME", "/second")]));
        assert_eq!(variables(&spans), vec![("$HOME", Some("/second"))]);
    }

    #[test]
    fn every_annotated_span_is_exactly_one_reference() {
        // The model refuses a `Variable` over anything else, so this is a
        // check that the pass never has to be refused: no split leaves half a
        // name wearing a whole value.
        let env = env(&[("A", "1"), ("HOME", "/home/user")]);
        for command in [
            "$A", "x$A", "$A x", "x$A x", "${HOME}$A", "$A;$A", "echo \"$A\"", "$A\u{202E}$A",
        ] {
            let spans = rendered(command, &env);
            for span in spans.iter() {
                if let SpanKind::Variable { .. } = span.kind() {
                    assert!(
                        crate::render::variable_name(span.text()).is_some(),
                        "{command:?}: {:?} is not a whole reference",
                        span.text()
                    );
                }
            }
            assert_eq!(unrender(&spans), command);
            assert!(spans.covers_source());
        }
    }

    #[test]
    fn annotation_adds_and_removes_nothing() {
        let env = env(&[("HOME", "/home/user"), ("A", "; rm -rf /")]);
        for command in [
            "",
            "$",
            "$$",
            "$A",
            "echo '$A' \"$A\" \\$A $A",
            "${A}${A}",
            "a; $A && ${A:-x} | $(echo $A)",
            "ünïcödé $A ✓",
            "$A\n$A",
        ] {
            let spans = rendered(command, &env);
            assert_eq!(unrender(&spans), command, "{command:?} did not round-trip");
            assert!(spans.covers_source(), "{command:?} is not tiled by its spans");
        }
    }

    // --- the shared scanner -----------------------------------------------

    #[test]
    fn the_scanner_reports_the_state_each_character_sits_in() {
        // The state is the one *before* the character is applied, so the
        // quote that opens a string reads Normal and the one that closes it
        // reads Single. Both passes depend on that reading.
        let states: Vec<_> = scan(r"a'b'\;").map(|c| (c.ch, c.quoting, c.escaped)).collect();
        assert_eq!(
            states,
            vec![
                ('a', Quoting::Normal, false),
                ('\'', Quoting::Normal, false),
                ('b', Quoting::Single, false),
                ('\'', Quoting::Single, false),
                ('\\', Quoting::Normal, false),
                (';', Quoting::Normal, true),
            ]
        );
    }

    #[test]
    fn the_scanner_visits_every_character_exactly_once() {
        for command in ["", "a; b", r"echo 'a\'; b", "ünïcödé; ✓", "\u{202E}$A"] {
            let seen: String = scan(command).map(|c| c.ch).collect();
            assert_eq!(seen, command);
            let offsets: Vec<_> = scan(command).map(|c| c.offset).collect();
            assert!(offsets.windows(2).all(|w| w[0] < w[1]), "offsets must ascend");
        }
    }

    #[test]
    fn the_scanner_reports_double_quoted_state_and_its_escapes() {
        let states: Vec<_> = scan(r#""a\"b""#).map(|c| (c.ch, c.quoting, c.escaped)).collect();
        assert_eq!(
            states,
            vec![
                ('"', Quoting::Normal, false),
                ('a', Quoting::Double, false),
                ('\\', Quoting::Double, false),
                ('"', Quoting::Double, true),
                ('b', Quoting::Double, false),
                ('"', Quoting::Double, false),
            ]
        );
    }

    #[test]
    fn the_scanner_finds_references_in_source_order() {
        assert_eq!(references("$A x ${B}"), vec![0..2, 5..9]);
        assert_eq!(references("echo '$A' $B"), vec![10..12]);
        assert_eq!(references("$$A"), Vec::<Range<usize>>::new());
    }

    #[test]
    fn a_dollar_extent_steps_over_what_it_declines_to_claim() {
        // The rule that keeps a rejected construct from being re-read as an
        // accepted one. Each length is the whole of what the shell treats as
        // one thing at that `$`.
        assert_eq!(dollar_extent("$"), 1);
        assert_eq!(dollar_extent("$A"), 2);
        assert_eq!(dollar_extent("$_a9-"), 4);
        assert_eq!(dollar_extent("$1HOME"), 6, "digits and letters are one run");
        assert_eq!(dollar_extent("$$HOME"), 2, "`$$` is one thing; `HOME` is literal");
        assert_eq!(dollar_extent("${A}x"), 4);
        // Through the first closing brace, inner `$` included.
        assert_eq!(dollar_extent("${A:-$B} x"), 8);
        assert_eq!(dollar_extent("${A"), 2, "unterminated: claim nothing past the brace");
        assert_eq!(dollar_extent("$(id)"), 2);
        assert_eq!(dollar_extent("$é"), 3, "a multibyte sigil is stepped over whole");
    }
}
