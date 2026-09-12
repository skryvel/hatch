//! What the window draws between the headline and the buttons: the command,
//! twice, and the facts around it.
//!
//! # Two panes, both always on screen
//!
//! The annotated pane is the useful one — separators marked and each one
//! starting a new line, variables resolved. It is also the one that could be
//! wrong: it is produced by passes that make claims about the text, and a
//! reader who suspects a claim has nowhere to check it. So the
//! raw pane sits above it, unsegmented and unreflowed, drawn from the same
//! string the spans tile. It is not behind a toggle, because a reader who has
//! to *ask* for the unembellished view has to first suspect that they need
//! it, and the whole point of the pane is to be there for the reader who does
//! not know to suspect anything.
//!
//! Both panes chip. A raw pane that drew a zero-width joiner as nothing would
//! be the more authoritative-looking of the two views and the more misleading
//! one, which is the worst thing in this window it is possible to be.
//!
//! # What is checked, and when
//!
//! [`Shown::of`] is the only door from a [`Payload`] to something drawn. It
//! reads the rendering through [`Payload::rendering`] and the diff through
//! [`Payload::rows`] — never through the wire fields — so every span on
//! screen has been rebuilt by the real [`crate::render::SpanBuilder`] and
//! tiles its source exactly once. It runs once, when the request arrives, and
//! a payload it refuses closes the window instead of drawing a guess; see
//! [`crate::prompt_ui::PromptState::handle`].
//!
//! # Text that is not the command
//!
//! Three strings reach this module from outside the span model and so cannot
//! be protected by chips: a variable's resolved value, the working directory,
//! and a swap's path. Each is [`defang`]ed here, at the point it is turned
//! into something drawable. The daemon already defangs the first of those in
//! [`crate::render::command::annotate_variables`], and defanging is
//! idempotent — every label it produces is printable ASCII — so doing it
//! again costs nothing and removes the need for this module to trust a field
//! that crossed a pipe unchecked. `title` and `reason` are the exception:
//! they arrive defanged and are drawn as they arrive, per
//! [`crate::protocol::Request`].

use eframe::egui::epaint::text::ByteRangeExt as _;
use eframe::egui::{self, Color32, RichText, Ui};

use crate::protocol::{Outcome, Payload, ProtocolError};
use crate::render::diff::{Row, Side};
use crate::render::unicode::{ChipTier, ScanReport, classify, defang, scan};
use crate::prompt_ui::theme::{self, Palette};
use crate::render::{Span, SpanKind, Spans};
use crate::swap::{PlanKind, SwapPlan};

/// Seconds at or below which the countdown reads as urgent.
const IMMINENT: i64 = 10;

/// Seconds at or below which the countdown stops being background noise.
const SOON: i64 = 30;

/// The most of the window the headline may take before it scrolls.
///
/// `title` and `reason` are agent-written and capped only at four kilobytes,
/// which is enough to push both panes off the bottom of the screen. A
/// fraction rather than a line count, because the thing being protected is
/// the panes' share of the window.
const HEADLINE_SHARE: f32 = 0.30;

/// The most of the space below the header the raw pane may take, whatever
/// [`RAW_STRIP_ROWS`] works out to.
///
/// A backstop for a short window rather than the ordinary rule: at a window
/// height where six rows would be most of the space, the annotated pane still
/// gets the larger half.
const RAW_SHARE: f32 = 0.40;

/// How many lines of the raw command the stacked strip shows at once.
///
/// Enough to see the line you are checking with its neighbours around it,
/// which is what makes a discrepancy between the two panes visible at all,
/// and few enough that the pane a reader actually reads keeps the window.
/// See [`raw_ceiling`] for why this is a strip and not a share.
const RAW_STRIP_ROWS: f32 = 6.0;

/// Characters of gutter in front of each diff column: the `-`/`+` mark and
/// the space after it.
///
/// Diff furniture only. The two command panes have no gutter, which is why
/// [`column_chars`] takes the figure rather than knowing it.
const GUTTER_CHARS: usize = 2;

/// Characters of empty space between two columns, in either view.
///
/// Two and not one, so that a line ending in a space and a line starting with
/// one are still two lines to the eye. It doubles as the slack that keeps the
/// character-count fit from depending on sub-pixel rounding.
const GAP_CHARS: usize = 2;

// ---- the checked rendering -------------------------------------------------

/// One request's payload, rebuilt through the real builder and ready to draw.
///
/// Held by the state machine rather than derived per frame: the check that
/// makes it trustworthy is the same work as producing it, and a window that
/// re-derived it every frame would either repeat that work sixty times a
/// second or be tempted to skip it.
#[derive(Debug, Clone)]
pub enum Shown {
    /// A command, in both of the forms the window draws it.
    Command {
        /// The rendering, as the renderer's passes left it.
        annotated: Spans,
        /// The same source, classified and nothing else. Its `source()` is
        /// `annotated.source()` — the text this window's approval covers.
        raw: Spans,
        /// The widest line either pane would have to draw, in characters.
        ///
        /// Measured here for the reason the diff's is: it decides whether the
        /// two panes are drawn side by side, and it depends only on the two
        /// renderings, so measuring it once is not a cache that can go stale.
        longest: usize,
        /// How odd that source is, for the header line.
        scan: ScanReport,
        /// The danger labels the daemon found, defanged for drawing.
        danger: Vec<String>,
        /// The working directory, defanged for drawing.
        cwd: String,
        /// Whether it was asked for as root.
        root: bool,
        /// Whether it runs in a terminal of its own.
        interactive: bool,
        /// How a root command will differ from the same command run
        /// unprivileged, defanged for drawing. `None` when it will not.
        caveat: Option<String>,
    },
    /// A file swap, drawn in whichever of the two views fits — see
    /// [`draw_swap`].
    Swap {
        /// The file, defanged for drawing.
        path: String,
        /// Where the bytes land.
        plan: SwapPlan,
        /// The diff, rebuilt through the real builder.
        rows: Vec<Row>,
        /// The widest line either column would have to draw, in characters.
        ///
        /// Measured here rather than per frame because it decides which view
        /// the diff gets, and a 256 KB replacement is a quarter of a million
        /// rows: a decision procedure that walked all of them sixty times a
        /// second would cost more than the view it is choosing. It depends
        /// only on `rows`, so measuring it once is not a cache that can go
        /// stale.
        longest: usize,
    },
}

impl Shown {
    /// Read a payload the only way a window is allowed to.
    ///
    /// # Errors
    ///
    /// The frame does not describe a rendering this window can believe: spans
    /// that do not tile their source, a chip over more than one codepoint, a
    /// one-line form that disagrees with the spans it claims to summarise.
    /// The window closes on it rather than drawing part of it.
    pub fn of(payload: &Payload) -> Result<Shown, ProtocolError> {
        match payload {
            Payload::Command { danger, cwd, root, interactive, caveat, .. } => {
                let annotated = payload.rendering()?;
                // From the rebuilt spans, not from the payload's own `raw`
                // field: the two are equal by construction, and taking it
                // from here means every character in either pane came out of
                // something the builder checked.
                let source = annotated.source();
                let raw = classify(source);
                Ok(Shown::Command {
                    scan: scan(source),
                    danger: danger.iter().map(|label| defang(label)).collect(),
                    cwd: defang(&cwd.display().to_string()),
                    root: *root,
                    interactive: *interactive,
                    // Defanged like every other string the daemon sends.
                    // This one is hatch's own text rather than the agent's,
                    // which is a reason to expect it to be clean and not a
                    // reason to let it through unchecked: the rule this
                    // window holds is that nothing reaches the screen
                    // undefanged, and an exception for trusted text is how
                    // the rule stops being one.
                    caveat: caveat.as_deref().map(defang),
                    longest: widest_line(&annotated).max(widest_line(&raw)),
                    raw,
                    annotated,
                })
            }
            Payload::Swap { path, plan, .. } => {
                let rows = payload.rows()?;
                Ok(Shown::Swap {
                    path: defang(&path.display().to_string()),
                    plan: plan.clone(),
                    longest: longest_drawn_line(&rows),
                    rows,
                })
            }
        }
    }

    /// Whether this runs in a terminal of its own, which is the one thing
    /// that takes the stream checkbox away from a command.
    pub fn interactive(&self) -> bool {
        matches!(self, Shown::Command { interactive: true, .. })
    }

    /// Whether an approval of this would produce output to stream.
    ///
    /// A swap writes a file and says nothing, so the checkbox that asks to
    /// watch it has nothing to offer.
    pub fn streamable(&self) -> bool {
        matches!(self, Shown::Command { .. })
    }
}

// ---- the countdown ---------------------------------------------------------

/// How much attention the countdown should be taking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Urgency {
    /// There is time. Say the number and stay out of the way.
    Calm,
    /// Reading time is nearly gone.
    Soon,
    /// The window is about to be taken away.
    Imminent,
}

/// Which of the three a number of seconds is.
///
/// A threshold rather than a fade, because the point is to be readable
/// without being read: a gradient tells a glancing reader nothing, and three
/// states are three things a colour can say at a glance. Colour *and* weight,
/// not colour alone — this number matters to a reader who cannot tell red
/// from grey.
pub fn urgency(seconds_left: i64) -> Urgency {
    if seconds_left <= IMMINENT {
        Urgency::Imminent
    } else if seconds_left <= SOON {
        Urgency::Soon
    } else {
        Urgency::Calm
    }
}

/// The countdown in words.
///
/// Seconds all the way up rather than a clock, because the number is being
/// compared against "can I read this in time", and nobody reads `02:15` as a
/// quantity of reading.
pub fn countdown_text(seconds_left: i64) -> String {
    match seconds_left {
        seconds if seconds <= 0 => "no time left".to_string(),
        seconds if seconds < 60 => format!("{seconds} s left to decide"),
        // Above an hour the exact figure has stopped being information and
        // started being a number to squint at. A window is normally open for
        // a minute or two; a deadline further out than an hour says only
        // that time is not what the reader should be thinking about.
        seconds if seconds >= 3600 => "over an hour left to decide".to_string(),
        seconds => {
            let (minutes, rest) = (seconds / 60, seconds % 60);
            match rest {
                0 => format!("{minutes} min left to decide"),
                rest => format!("{minutes} min {rest} s left to decide"),
            }
        }
    }
}

/// What the linger countdown says, once a streamed command has finished.
///
/// Seconds and a verb, for the reason [`countdown_text`] gives: the number is
/// being compared against "can I reach the button in time", and that is a
/// quantity of seconds rather than a clock. Different words from the approval
/// countdown on purpose — these two numbers mean opposite things, and a reader
/// who has just watched one run out must not read the other as more of it.
pub fn closing_text(seconds_left: u64) -> String {
    match seconds_left {
        0 => "closing now".to_string(),
        1 => "closing in 1 s".to_string(),
        seconds => format!("closing in {seconds} s"),
    }
}

/// How the approved operation ended, in words, and whether that is the ending
/// nobody needs to look at.
///
/// The flag rather than a colour: this module works out what a line says, and
/// the window works out how loudly to say it — the visuals are the caller's,
/// because the colours come from the reader's theme.
///
/// `false` covers every ending that is not a clean exit, the signals included:
/// a command hatch killed at the Kill button ended by signal too, and a reader
/// who pressed that button is not surprised to see it called out.
pub fn outcome_text(outcome: &Outcome) -> (String, bool) {
    match outcome {
        Outcome::Exit { code: 0 } => ("Finished — exit 0".to_string(), true),
        Outcome::Exit { code } => (format!("Finished — exit {code}"), false),
        Outcome::Signal { signal } => (format!("Ended by signal {signal}"), false),
        // Defanged here and not upstream: this is the one variant carrying
        // text from outside, and it is drawn beside a number the reader is
        // meant to trust.
        Outcome::ElevationFailed { message } => {
            (format!("Nothing ran — {}", defang(message)), false)
        }
        // Not "nothing ran" and not an exit code. The window is closing on
        // this line, and the reader's next move — check the machine, or do
        // not — depends on it saying which of those two hatch is unable to
        // choose between.
        Outcome::Unclear { message } => {
            (format!("hatch cannot tell whether this ran — {}", defang(message)), false)
        }
    }
}

// ---- the header line -------------------------------------------------------

/// What the command will run as, as a word rather than a boolean.
pub fn principal(root: bool) -> &'static str {
    if root { "ROOT" } else { "you" }
}

/// What the unicode scan found, or `None` when it found nothing worth a line.
///
/// Nothing is drawn for an ordinary ASCII command: a permanent "0 non-ASCII,
/// 0 invisible" is a line a reader learns to skip, and a line a reader skips
/// is not there when it finally says something.
pub fn scan_summary(report: &ScanReport) -> Option<String> {
    let mut parts = Vec::new();
    if report.non_ascii > 0 {
        parts.push(format!("{} non-ASCII", report.non_ascii));
    }
    if report.invisible > 0 {
        parts.push(format!("{} invisible", report.invisible));
    }
    if report.not_nfc {
        parts.push("not in NFC".to_string());
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

// ---- the swap stand-in -----------------------------------------------------

/// The plan as a list of labelled facts.
///
/// Every one of them is something the reader cannot get from the diff: the
/// mode the file is left at, who ends up owning it, and whether the file
/// exists at all before this runs.
pub fn plan_facts(plan: &SwapPlan) -> Vec<(&'static str, String)> {
    vec![
        (
            "Change",
            match plan.kind {
                PlanKind::Create => "create a file that is not there".to_string(),
                PlanKind::Replace => "replace the whole contents of the file".to_string(),
            },
        ),
        ("Mode", format!("{:04o}", plan.landing_mode & 0o7777)),
        (
            "Owner",
            defang(&format!("{}:{}", plan.landing_owner, plan.landing_group)),
        ),
        ("Size", size_delta(plan.size_delta)),
    ]
}

/// How much bigger or smaller the file gets.
///
/// A one-byte change says "1 byte", not "1 bytes". This is a line in a panel
/// whose whole job is to be read carefully before someone approves a write,
/// and a sentence that reads as a formatting slip invites the eye to skim the
/// four facts beside it.
fn size_delta(delta: i64) -> String {
    match delta {
        0 => "the same number of bytes".to_string(),
        delta if delta > 0 => format!("{} larger", bytes(delta)),
        delta => format!("{} smaller", bytes(-delta)),
    }
}

/// A byte count and its noun, agreeing in number.
fn bytes(count: i64) -> String {
    match count {
        1 => "1 byte".to_string(),
        count => format!("{count} bytes"),
    }
}

/// How many of the rows are marked as changed.
pub fn changed_rows(rows: &[Row]) -> usize {
    rows.iter().filter(|row| row.changed()).count()
}

// ---- does it fit in two columns? -------------------------------------------

/// How a diff is being drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffView {
    /// Two columns: the file on the left, what replaces it on the right.
    SideBySide,
    /// One column, `-`/`+` marked, the current file's form first. What a diff
    /// falls back to when two columns cannot hold it.
    Unified,
}

/// How the two command panes are being drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandView {
    /// Two columns: the exact text on the left, hatch's annotated form on the
    /// right, each with the whole height of the window.
    SideBySide,
    /// The annotated pane under the raw one. What the panes fall back to when
    /// two columns cannot hold them.
    Stacked,
}

/// One drawn line's width in characters, notes included.
///
/// Characters and not pixels, and the count is exact rather than an estimate.
/// Almost everything that reaches the screen does so as
/// [`Span::display_text`]: a plain span is U+0020..=U+007E because
/// [`classify`] chips everything else, and a loud chip's label is ASCII too.
/// The exceptions are the three compact glyphs a structural chip draws and
/// the `\u{2192}` in a variable's note, each of which is one advance of the
/// same monospace font — `every_glyph_the_panes_draw_is_one_monospace_advance`
/// is what holds that true. So a drawn line is monospace throughout, one
/// character is one advance, and the sum of the counts is the width.
///
/// A variable's note is counted because it is drawn: it sits inside the line,
/// after the reference, and a fit that ignored it would put the annotated
/// pane's longest line off the side of its column.
fn line_chars(line: &[Span]) -> usize {
    line.iter()
        .map(|span| {
            let note = span.variable().map_or(0, |(_, resolved)| {
                variable_note(resolved).chars().count()
            });
            span.display_text().chars().count() + note
        })
        .sum()
}

/// The widest line of one rendering, in characters, split where the rendering
/// asked to be split.
pub fn widest_line(spans: &Spans) -> usize {
    lines(spans).into_iter().map(line_chars).max().unwrap_or(0)
}

/// The width of the widest line either column would have to draw, in
/// characters.
///
/// A row's terminator counts only where it would be drawn, because that is
/// the question — how wide is this line *on screen* — and not how many bytes
/// it has.
pub fn longest_drawn_line(rows: &[Row]) -> usize {
    rows.iter()
        .map(|row| {
            let terminator = terminator_changed(row);
            [row.left(), row.right()]
                .into_iter()
                .flatten()
                .map(|side| drawn_width(side, terminator))
                .max()
                .unwrap_or(0)
        })
        .max()
        .unwrap_or(0)
}

/// One side's drawn width in characters, terminator included only when the
/// view would draw it.
fn drawn_width(side: &Side, terminator: bool) -> usize {
    line_chars(if terminator { side.spans() } else { side.content_spans() })
}

/// How many characters one of two columns holds, in a region that holds
/// `region` of them and spends `furniture` on each column before any text.
///
/// The furniture is a parameter because the two views that ask this have
/// different amounts of it: a diff column carries a `-`/`+` gutter, and a
/// command pane carries none. The gap between the columns is the same in
/// both, so it is not.
///
/// Saturating rather than signed: a region too narrow for its own furniture
/// holds no column at all, and that is a reason to fall back rather than a
/// negative number to propagate.
fn column_chars(region: usize, furniture: usize) -> usize {
    region.saturating_sub(2 * furniture + GAP_CHARS) / 2
}

/// Two columns only when *every* line fits one of them whole.
///
/// One rule, asked by both views, because it is one question: can a column
/// this wide hold the widest thing that would go in it? What each view does
/// when the answer is no differs — a diff has a unified form to fall back to,
/// the command panes stack — but the measurement and the threshold do not.
///
/// # Why the longest line and not a percentile
///
/// A threshold that let some proportion of lines overflow is a per-row
/// decision wearing a statistic: the rows past it would still have to be
/// truncated, wrapped or allowed to run into the neighbouring column, and all
/// three are worse than one column. Truncation hides bytes the reader is
/// approving. Wrapping makes a row a different height on each side, so the
/// two columns stop lining up and the pairing the view is entirely *for*
/// stops being visible. Overflow draws one line on top of another.
///
/// All-or-nothing is what makes "side by side is showing" mean something: it
/// is a promise that every line on screen is complete and that nothing needs
/// to be scrolled to horizontally. The cost is that one long line sends the
/// whole thing back to one column, and the caption says so with the number in
/// it, so the reader can widen the window and watch it flip back.
pub fn fits_two_columns(longest: usize, column: usize) -> bool {
    column > 0 && longest <= column
}

/// Which view a diff gets.
pub fn diff_view(longest: usize, column: usize) -> DiffView {
    if fits_two_columns(longest, column) { DiffView::SideBySide } else { DiffView::Unified }
}

/// Which arrangement the two command panes get.
pub fn command_view(longest: usize, column: usize) -> CommandView {
    if fits_two_columns(longest, column) { CommandView::SideBySide } else { CommandView::Stacked }
}

/// The one line above the command panes: which pane is which, what each of
/// them promises, and — in the fallback — why the reader is not getting the
/// other arrangement.
///
/// # Why one caption and not one per pane
///
/// Each pane used to carry a label of its own. Two labels are two rows when
/// the panes are stacked, and the window has no rows to spare: the thing
/// being read is a command somebody is about to let run, and every row of
/// furniture is a row of it they cannot see.
///
/// What the labels said, though, is not furniture. "No colour" and "the
/// colour is hatch's notes, not the command" is the *claim that makes the raw
/// pane worth having* — without it the reader has no reason to believe the
/// two panes differ in anything but prettiness — so it survives whole, in one
/// sentence per pane, said once.
///
/// The arrangement is named because the caption now has to say which pane it
/// is talking about. That is a change from before, when side by side said
/// nothing at all: naming a view a reader can see is worth a word when the
/// same word is what points at the promise.
pub fn command_caption(view: CommandView, longest: usize, column: usize) -> String {
    match view {
        CommandView::SideBySide => "Left: exactly the text being approved — no reflow, no \
             grouping, no colour. Right: the same command, annotated — the colour, the underline \
             and the italics are hatch's notes, not the command."
            .to_string(),
        CommandView::Stacked => format!(
            "Above, a strip that scrolls with the pane below: exactly the text being approved — \
             no reflow, no grouping, no colour. Below: the same command, annotated — the colour, \
             the underline and the italics are hatch's notes, not the command. Side by side \
             would need a column of {longest} characters and this window holds {column}; widen \
             it for that view."
        ),
    }
}

/// The line above the diff: how much changes, which view this is, and — when
/// it is the fallback — the measurement that chose it.
///
/// The reader is told which view they are looking at either way. A view that
/// silently swapped itself for another as the window was dragged wider would
/// be the same class of thing as a diff that silently normalises line
/// endings: a rendering that changed without saying so.
pub fn diff_caption(view: DiffView, rows: &[Row], longest: usize, column: usize) -> String {
    let counted = format!("{} of {} lines change.", changed_rows(rows), rows.len());
    match view {
        DiffView::SideBySide => format!(
            "{counted} Side by side: on the left the file as it is, on the right what replaces \
             it. A tinted empty cell is a row that side has no line for — not a blank line."
        ),
        DiffView::Unified => format!(
            "{counted} One column, not two: the longest line is {longest} characters and a column \
             here holds {column}, so two of them could not show it whole. Every line is below, \
             the current file's form first. Widen the window for the side-by-side view."
        ),
    }
}

// ---- drawing ---------------------------------------------------------------

/// The colours the panes use, resolved against whatever theme is in force.
///
/// The values live in [`crate::prompt_ui::theme`], which is also what builds
/// the `Visuals` the rest of the window draws with, so a pane and the panel
/// behind it cannot be told two different things. What is written here is
/// what each colour *means*, which is a fact about this window rather than
/// about a theme:
///
/// * `danger` — red — is the one colour that means *be careful*: a danger
///   marker, the `-` side of a diff, and the block the word `ROOT` is
///   reversed out of. That last one is the only place in the window where the
///   colour is a fill rather than ink, and it is deliberate — see
///   [`draw_root_mark`].
/// * `warn` — orange — is hatch substituting for a character it will not draw
///   as itself: the loud chip, and the unusual-character count above the
///   panes.
/// * `quiet` — grey — is hatch talking rather than the command: captions, the
///   resolved value of a variable (italic and boxed as well), and the
///   structural chip glyphs.
/// * `text` is the command's own bytes.
///
/// Highlighting gets what is left, and it deliberately does not get a colour
/// that means anything else:
///
/// * `command`, the word that names what runs, is not a hue at all. It is the
///   theme's *strong* text — white on dark, black on light — plus an
///   underline. Two channels rather than one: contrast alone reads as
///   slightly brighter text at a glance, and bold is not available (the
///   bundled monospace face has no bold cut, and a synthetic one would change
///   the advance width the side-by-side fit is measured in). The underline is
///   drawn under the row by the text layout and adds nothing to any glyph's
///   advance, so the measurement and the drawing still agree — see
///   `an_underlined_command_word_is_exactly_as_wide_as_a_plain_one`.
/// * `quoted` is the theme's link colour, which is the one hue in this window
///   with no other job, and it is the coolest thing on screen — as far from
///   red and orange as the palette goes. It is never underlined, and the
///   command word is never that hue, so the two marks cannot combine into
///   something that reads as a hyperlink — which is a thing this window does
///   not have.
///
/// The rule underneath all of it: **highlighting only ever adds.** Nothing
/// here fades a span, boxes one, or replaces its text, so a reader who
/// ignores colour entirely reads the same characters in the same order. The
/// raw pane beside it carries no highlighting at all.
fn palette(ui: &Ui) -> Palette {
    theme::of(ui)
}

/// Who and where an operation runs, for the corner of the title row.
///
/// A copy rather than a borrow of the payload, because the row that draws it
/// has to measure it before it decides where to put it, and measuring twice
/// from two places is how the measurement and the drawing come to disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunContext {
    /// The working directory, already defanged.
    pub cwd: String,
    /// Whether it was asked for as root.
    pub root: bool,
}

impl RunContext {
    /// The run context of whatever this window is showing, if it has one.
    ///
    /// A `swap_file` request has none: it names an absolute path in its own
    /// header and runs as whoever the plan says, which is a different claim
    /// drawn in a different place.
    pub fn of(shown: &Shown) -> Option<RunContext> {
        match shown {
            Shown::Command { cwd, root, .. } => {
                Some(RunContext { cwd: cwd.clone(), root: *root })
            }
            Shown::Swap { .. } => None,
        }
    }
}

/// The most of the title's row the run context may take before it gives up
/// and takes a row of its own.
///
/// The title is the agent's sentence and the run context is a path of
/// unbounded length, so on a narrow window or a deep directory the two cannot
/// share a line. Rather than truncating either — a truncated path is a
/// security-relevant fact removed from the screen — the row splits back into
/// two, which is what it always was.
const ASIDE_SHARE: f32 = 0.45;

/// Whether a run context `width` points wide may share a `room`-wide title
/// row.
///
/// A separate answer from the drawing, so the rule is a thing a test can ask
/// rather than a thing a screenshot has to be read for. Nothing is truncated
/// either way: `false` means the run context takes a row of its own, which is
/// what it always had.
fn aside_fits(width: f32, room: f32) -> bool {
    width > 0.0 && width <= room * ASIDE_SHARE
}

/// How wide the rule beside the agent's words is drawn.
const QUOTE_RULE: f32 = 2.0;

/// How far the quoted text sits from that rule.
const QUOTE_GAP: f32 = 8.0;

/// What hatch says in front of the agent's first line.
///
/// Short, and not a warning. The agent is usually telling the truth, and a
/// window that shouted about every title would teach the reader to skip the
/// one that matters — the same argument that keeps a structural chip quiet.
/// What this has to do is answer *whose sentence is this*, which takes three
/// words.
pub const ATTRIBUTION: &str = "The agent says";

/// The agent's two lines, above everything, with the run context in the
/// corner of the first one.
///
/// Drawn through [`classify`], which is more than the protocol requires: they
/// arrive defanged, so nothing dangerous is left in them, but a chip is a
/// label a reader can see and a defanged string has already lost the
/// difference between a label the agent wrote and one hatch substituted.
/// Classifying what arrives puts every remaining oddity in a box that reads
/// as hatch's own voice.
///
/// # Why the title is marked as a quotation
///
/// The title is the first thing read, the most persuasive thing on screen,
/// and written by the party whose request is being judged. Drawn plainly it
/// reads as a description of what is about to happen; it is a claim about
/// intent by the requester, and a prompt-injected agent's cheapest lever is a
/// reassuring title over a hostile command. The two panes already answer this
/// for the command — *the colour, the underline and the italics are hatch's
/// notes, not the command* — and the header had no equivalent.
///
/// So the title and the reason are drawn as what they are: quoted. A rule in
/// hatch's own quiet grey runs down the left of both, and [`ATTRIBUTION`]
/// leads the first line in that same voice — small, quiet, italic — set in
/// the same laid-out run as the title, so the whole treatment costs no row at
/// all. The reading room this window fights for is the point of it; an
/// attribution that took a line from the command would be paid for out of the
/// thing the reader is here to read.
///
/// Nothing is dimmed, boxed or hedged. The agent's words keep full contrast
/// and their heading size: the reader is being told *whose* words these are,
/// not being told to disbelieve them.
///
/// # Why "Runs as … in …" is up here
///
/// It used to be a row of its own below the separator, and a row of its own
/// is a row of the window that the command being read does not get. It is
/// also, read plainly, part of the same sentence as the title: *this* is what
/// the agent wants, and *this* is who and where it happens. So the title
/// takes the left of the row and the run context the right, and they cost one
/// row between them instead of two.
pub fn draw_headline(ui: &mut Ui, title: &str, reason: &str, aside: Option<&RunContext>) {
    egui::ScrollArea::vertical()
        .id_salt("hatch-headline")
        .max_height(ui.available_height() * HEADLINE_SHARE)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            quoted(ui, |ui| {
                let width = aside.map_or(0.0, |aside| run_context_width(ui, aside));
                match aside_fits(width, ui.available_width()) {
                    true => {
                        draw_title_row(ui, title, aside.expect("a width came from one"), width)
                    }
                    false => {
                        draw_attributed(ui, &classify(title), Weight::Heading);
                        if let Some(aside) = aside {
                            ui.horizontal_wrapped(|ui| draw_run_context(ui, aside));
                        }
                    }
                }
                ui.add_space(4.0);
                draw_spans(ui, &classify(reason), Weight::Body);
            });
        });
}

/// Draw `add` beside a rule that says the text in it is a quotation.
///
/// The rule is painted after the block, over the height the block turned out
/// to need, so a title that wrapped to three lines is marked for all three
/// without anyone having to predict how many there would be. It is drawn in
/// the quiet grey the rest of hatch's own chrome uses — see [`palette`] — and
/// it costs no row: it is beside the text, not above it.
fn quoted<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    let colour = palette(ui).quiet;
    let room = ui.available_rect_before_wrap();
    let inside = egui::Rect::from_min_max(
        egui::pos2(room.left() + QUOTE_RULE + QUOTE_GAP, room.top()),
        room.max,
    );
    let mut block = ui.new_child(egui::UiBuilder::new().max_rect(inside));
    let out = add(&mut block);
    let drawn = block.min_rect();
    ui.painter().vline(
        room.left() + QUOTE_RULE / 2.0,
        drawn.y_range(),
        egui::Stroke::new(QUOTE_RULE, colour),
    );
    ui.advance_cursor_after_rect(egui::Rect::from_min_size(
        room.min,
        egui::vec2(room.width(), (drawn.bottom() - room.top()).max(0.0)),
    ));
    out
}

/// The title, with the run context right-aligned against the end of its first
/// line.
///
/// Two children over one rect rather than one flow: the title wraps, and a
/// title that grew to two lines must push the reason down without dragging
/// the run context into the middle of the paragraph.
fn draw_title_row(ui: &mut Ui, title: &str, aside: &RunContext, width: f32) {
    let row = ui.available_rect_before_wrap();
    let gap = ui.spacing().item_spacing.x;
    let line = ui.text_style_height(&egui::TextStyle::Body);

    let left = egui::Rect::from_min_max(
        row.min,
        egui::pos2(row.right() - width - gap, row.bottom()),
    );
    let mut title_ui = ui.new_child(egui::UiBuilder::new().max_rect(left));
    draw_attributed(&mut title_ui, &classify(title), Weight::Heading);
    let used = title_ui.min_rect().height();

    let right = egui::Rect::from_min_size(
        egui::pos2(row.right() - width, row.top()),
        egui::vec2(width, ui.text_style_height(&egui::TextStyle::Heading).max(line)),
    );
    let mut aside_ui = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(right)
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
    );
    draw_run_context(&mut aside_ui, aside);

    ui.advance_cursor_after_rect(egui::Rect::from_min_size(
        row.min,
        egui::vec2(row.width(), used.max(right.height())),
    ));
}

/// The air the root mark keeps between its word and its own edge.
///
/// Sideways, enough that the block reads as a block rather than as text with
/// a background accident. Downwards, one point: the mark sits on a row whose
/// height is set by text a size larger than the word in it — see
/// [`draw_title_row`] — so this much padding is taken out of room the row
/// already has, and the mark costs no part of a line.
const ROOT_MARK_PAD: egui::Vec2 = egui::vec2(5.0, 1.0);

/// How round the root mark's corners are.
///
/// Barely: a pill reads as a decoration and a sharp rectangle reads as a
/// stamp, and this is a stamp.
const ROOT_MARK_RADIUS: u8 = 2;

/// The word inside the root mark, laid out in the ink it is drawn in.
///
/// One function for the drawing and for the measuring, because the mark is
/// placed by subtracting a width from the right edge of the window and two
/// measurements of the same word are how a thing ends up off the side of it.
fn root_mark_galley(ui: &Ui) -> std::sync::Arc<egui::Galley> {
    let (_, ink) = palette(ui).root_mark();
    let font = egui::TextStyle::Body.resolve(ui.style());
    ui.ctx().fonts_mut(|fonts| fonts.layout_no_wrap(principal(true).to_string(), font, ink))
}

/// How much room the root mark takes.
fn root_mark_size(ui: &Ui) -> egui::Vec2 {
    root_mark_galley(ui).size() + 2.0 * ROOT_MARK_PAD
}

/// `ROOT`, reversed out of a filled block.
///
/// The word is unchanged — capitals already do their share — and what is
/// added is a shape. The old treatment was the same word tinted red, which is
/// a channel a reader who cannot tell red from grey does not have; this is a
/// solid rectangle where the rest of the header has none, with its text
/// knocked out of it, so the mark is there at a glance and there in a
/// screenshot somebody prints in black and white. See
/// [`crate::prompt_ui::theme::Palette::root_mark`] for the two colours and
/// why neither of them moves with the phase.
///
/// It costs no row: the block is the height of one line of body text plus two
/// points, drawn on a row that is already as tall as the heading beside it.
pub fn draw_root_mark(ui: &mut Ui) {
    let (fill, ink) = palette(ui).root_mark();
    let galley = root_mark_galley(ui);
    let (rect, _) =
        ui.allocate_exact_size(galley.size() + 2.0 * ROOT_MARK_PAD, egui::Sense::hover());
    ui.painter().rect_filled(rect, ROOT_MARK_RADIUS, fill);
    ui.painter().galley(rect.min + ROOT_MARK_PAD, galley, ink);
}

/// "Runs as you in /some/path", as three labels — or as two and a mark, when
/// the answer to *as who* is root.
fn draw_run_context(ui: &mut Ui, aside: &RunContext) {
    let palette = palette(ui);
    ui.spacing_mut().item_spacing.x = ui.spacing().item_spacing.x.min(4.0);
    ui.label(RichText::new("Runs as").small().color(palette.quiet));
    match aside.root {
        true => draw_root_mark(ui),
        false => {
            ui.label(RichText::new(principal(false)).strong());
        }
    }
    ui.label(RichText::new("in").small().color(palette.quiet));
    ui.label(RichText::new(&aside.cwd).monospace());
}

/// How wide that row of labels is, measured in the fonts actually in force.
///
/// Measured and not guessed: the row is placed by subtracting this from the
/// right edge, and a guess that came out short would put the path off the
/// side of the window.
fn run_context_width(ui: &Ui, aside: &RunContext) -> f32 {
    let gap = ui.spacing().item_spacing.x.min(4.0);
    let small = egui::TextStyle::Small.resolve(ui.style());
    let body = egui::TextStyle::Body.resolve(ui.style());
    let mono = egui::TextStyle::Monospace.resolve(ui.style());
    let text = |font: &egui::FontId, s: &str| {
        ui.ctx().fonts_mut(|fonts| {
            fonts.layout_no_wrap(s.to_string(), font.clone(), egui::Color32::WHITE).size().x
        })
    };
    let who = match aside.root {
        true => root_mark_size(ui).x,
        false => text(&body, principal(false)),
    };
    text(&small, "Runs as") + who + text(&small, "in") + text(&mono, &aside.cwd) + 3.0 * gap
}

/// Everything below the headline and above the buttons.
pub fn draw_payload(ui: &mut Ui, shown: &Shown) {
    match shown {
        Shown::Command { annotated, raw, scan, danger, longest, caveat, .. } => {
            draw_command_header(ui, scan, danger, caveat.as_deref());
            draw_command(ui, annotated, raw, *longest);
        }
        Shown::Swap { path, plan, rows, longest } => draw_swap(ui, path, plan, rows, *longest),
    }
}

/// How odd the text is, and what it was marked for.
///
/// Only what is there: an ordinary command in an ordinary directory draws
/// neither of these lines, so the two rows this can cost are rows a request
/// that needs them pays for and no other request does. Who it runs as and
/// where is up in the title row — see [`draw_headline`].
fn draw_command_header(
    ui: &mut Ui,
    report: &ScanReport,
    danger: &[String],
    caveat: Option<&str>,
) {
    let palette = palette(ui);
    if let Some(summary) = scan_summary(report) {
        // Bold, like the marked list: this is one of the two colours the
        // chrome draws at large-text contrast rather than body contrast, and
        // bold is the half of "large" it can actually have. See
        // `crate::prompt_ui::theme`.
        ui.label(
            RichText::new(format!("Unusual characters: {summary}")).color(palette.warn).strong(),
        );
    }
    if !danger.is_empty() {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Marked:").color(palette.danger).strong());
            for label in danger {
                ui.label(RichText::new(label).color(palette.danger).strong());
            }
        });
    }
    // Before the approval and not after it. What this says is that a root
    // command can behave differently from the same command run as the user —
    // it may be given a terminal, so it may colour its output or stop to ask
    // something — and a reader learning that from the output pane afterwards
    // has already approved the thing it is about.
    //
    // Warn and not danger: it is a statement about how the command will
    // behave, not a mark on what the command does, and spending the red on it
    // would spend it on every root request.
    if let Some(caveat) = caveat {
        ui.label(RichText::new(caveat).color(palette.warn).small());
    }
}

// ---- keeping the two stacked panes together --------------------------------

/// How far two offsets may differ and still count as the same one.
///
/// Half a logical pixel: smaller than anything a reader can produce and
/// larger than the rounding a scroll area does to itself, so a pane that was
/// given an offset and handed it straight back is never mistaken for a pane
/// the reader scrolled.
const SCROLL_EPSILON: f32 = 0.5;

/// Where the two stacked panes' shared scroll position is kept.
fn scroll_link_id() -> egui::Id {
    egui::Id::new("hatch-command-scroll")
}

/// Where the two stacked panes' own account of how far they reach is kept.
fn pane_reach_id() -> egui::Id {
    egui::Id::new("hatch-command-reach")
}

/// Which of the two command panes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pane {
    Raw,
    Annotated,
}

/// Which pane the reader last scrolled, and where they left it.
///
/// Kept in egui's own per-frame-persistent store rather than threaded through
/// the state machine: it is a scroll position, which is not part of what the
/// window is deciding, and [`crate::prompt_ui::PromptState`] deliberately
/// knows nothing about how anything is drawn.
#[derive(Debug, Clone, Copy, PartialEq)]
struct ScrollLink {
    /// The pane the reader is driving. It is given back exactly the offset it
    /// last reported, so it can never be pulled away from where they put it.
    driver: Pane,
    offset: f32,
}

impl Default for ScrollLink {
    fn default() -> ScrollLink {
        ScrollLink { driver: Pane::Raw, offset: 0.0 }
    }
}

/// Where a pane ended up, and the furthest down it had anything to show.
///
/// The maximum is measured and not predicted, and it has to be: it depends on
/// the width the pane really wrapped at, on whether its scroll bars took any
/// room — egui's float over the content and take none — and on the frame
/// around it, none of which is settled until the pane has been drawn. The
/// scroll area hands back the content it laid out and the viewport it laid it
/// out in, and the difference between them is the offset it clamps anything
/// larger to.
#[derive(Debug, Clone, Copy, PartialEq)]
struct PaneAt {
    /// Where the pane is scrolled to.
    offset: f32,
    /// The largest offset it has anything to show at.
    max: f32,
}

impl PaneAt {
    /// Whether the only thing between this pane and the offset it was asked
    /// for is that it has nothing that far down.
    ///
    /// Both halves are the point. A pane asked for more than it has *and*
    /// sitting at its maximum was clamped and did not move. A pane sitting at
    /// its maximum that was asked for no more than that was put there by the
    /// reader, and that is the case this must never swallow: scrolling a pane
    /// to its end is how a reader takes it over.
    fn clamped(self, want: f32) -> bool {
        want > self.max + SCROLL_EPSILON && self.offset >= self.max - SCROLL_EPSILON
    }
}

/// How far each pane reached when it was last drawn.
///
/// Kept from one frame to the next because the question it answers — how far
/// may this pane be asked to scroll — is asked before the pane that knows
/// exists. `None` is a pane that has not been drawn yet, which is the first
/// frame of a window and no other.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
struct PaneReach {
    /// How far the raw strip reached.
    raw: Option<f32>,
    /// How far the annotated pane reached.
    annotated: Option<f32>,
}

/// Where one drawn line of a pane begins: in the source, and on screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PaneLine {
    /// The byte offset in the source this line starts at.
    at: usize,
    /// The row it starts on, counting the extra rows any wrapped line above
    /// it took.
    row: usize,
}

/// One pane's lines, and how many rows they take altogether.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PaneRows {
    lines: Vec<PaneLine>,
    rows: usize,
}

/// Where every drawn line of a rendering begins, in both coordinates.
///
/// The source offset is what the two panes share. They are two renderings of
/// one string and both tile it exactly — that is invariant 1 — so a byte
/// offset means the same thing in both. A *line number* does not: the
/// annotated pane opens a line at every separator as well as at every
/// newline, so its line twelve and the raw pane's line twelve are routinely
/// different text. Nor do pixels, once the line counts differ.
///
/// `wrap` is the pane's width in characters, or `None` for a pane that does
/// not reflow. A wrapped line takes more than one row, and a link that
/// assumed one row per line would put the follower steadily too high down a
/// pane with wrapping above the target — the silent kind of drift.
///
/// The count is an estimate in one direction only. egui breaks at word
/// boundaries where it can, so it wraps at or before the character count
/// says, which means this can under-count rows and never over-count them.
/// The follower therefore lands at the linked line or a little above it,
/// showing context before it — never past it, which is the answer that would
/// hide the line the reader was looking for.
fn pane_lines(spans: &Spans, wrap: Option<usize>) -> PaneRows {
    let mut lines_out = Vec::new();
    let mut rows = 0;
    for line in lines(spans) {
        let Some(first) = line.first() else { continue };
        lines_out.push(PaneLine { at: first.range().start, row: rows });
        rows += match wrap {
            Some(width) if width > 0 => line_chars(line).div_ceil(width).max(1),
            _ => 1,
        };
    }
    PaneRows { lines: lines_out, rows }
}

/// Which line a pane is showing at its top, from its offset in pixels.
fn line_at(offset: f32, row: f32, lines: &[PaneLine]) -> usize {
    let at = (offset / row).floor().max(0.0) as usize;
    lines.partition_point(|line| line.row <= at).saturating_sub(1)
}

/// The line of `to` that holds the place line `line` of `from` begins at.
///
/// The last line that starts at or before it, which is the line that place is
/// *on* — never the line after, so scrolling to the top of a segment in one
/// pane cannot scroll past it in the other.
fn linked_line(from: &[PaneLine], to: &[PaneLine], line: usize) -> usize {
    let Some(from) = from.get(line) else {
        return 0;
    };
    to.partition_point(|line| line.at <= from.at).saturating_sub(1)
}

/// A first guess at how far a pane of `rows` rows reaches inside `viewport`,
/// for the one frame before the pane has reported its own.
///
/// It used to be the whole answer, and was deliberately an under-estimate: a
/// request past a pane's range comes back clamped, a clamped offset was
/// indistinguishable from a reader scrolling, and staying short of the range
/// was what kept the two apart. It could not carry that. The row count behind
/// it is measured in characters, by [`pane_lines`], against a pane whose real
/// width nothing knows until the pane is drawn — and egui's scroll bars float
/// over the content rather than taking a column of it, so the real pane is
/// wider than the measurement thinks and fits a line in fewer rows than it
/// counted. One row of over-count is all it takes for the guard to invert
/// into the bug it was there to prevent: the follower clamps, [`drove`] reads
/// the clamp as a reader, the driver changes hands, and the pane the reader
/// is holding is dragged back up. See [`PaneAt`] for what settles it now.
fn max_offset(rows: usize, row: f32, viewport: f32) -> f32 {
    (rows as f32 * row - viewport).max(0.0)
}

/// What to ask one pane for this frame.
///
/// The driver gets exactly what it last reported, so the reader's own pane
/// never moves under them. The follower gets the place the driver is looking
/// at, translated through the source offset the two renderings share, and
/// capped at `reach` — the furthest down that pane has anything to show.
///
/// The cap is not what keeps [`drove`] honest any more; that is
/// [`PaneAt::clamped`]'s job. It is there because a scroll area asked for an
/// offset past its content lays the content out there and draws the gap: a
/// pane asked for more than it has shows blank space in the frame it is
/// asked, and corrects itself only in the next one. The end of a long command
/// is exactly where that would happen, and exactly where a reader is looking.
fn requested_offset(
    link: ScrollLink,
    pane: Pane,
    of: &PaneRows,
    driver: &PaneRows,
    row: f32,
    reach: f32,
) -> f32 {
    if link.driver == pane {
        return link.offset;
    }
    let line = linked_line(&driver.lines, &of.lines, line_at(link.offset, row, &driver.lines));
    let at = of.lines.get(line).map_or(0, |line| line.row) as f32 * row;
    at.min(reach)
}

/// Who drove, after a frame in which both panes were asked for an offset.
///
/// A pane that hands back what it was given did not move; a pane that hands
/// back something else was scrolled, and becomes the one the other follows.
/// The follower is asked first, because it is the pane whose answer is news:
/// the driver is being handed its own offset and agreeing with it says
/// nothing.
///
/// That order is why a clamp had to be told apart from a reader. A pane that
/// was asked for more than it has hands back its maximum instead, which is a
/// disagreement, and it arrives in the arm that takes the driver's role away
/// from a pane that is agreeing with what it was handed — so a follower with
/// nothing further to show could unseat the pane the reader had hold of. It
/// did it every other frame, for as long as they held it: the follower
/// clamped and took the role, the next frame handed the reader's own pane a
/// position translated from the clamp and the reader's hand dragged it back,
/// and the two took turns.
fn drove(
    link: ScrollLink,
    raw: PaneAt,
    want_raw: f32,
    annotated: PaneAt,
    want_annotated: f32,
) -> ScrollLink {
    if moved(link, Pane::Annotated, annotated, want_annotated) {
        ScrollLink { driver: Pane::Annotated, offset: annotated.offset }
    } else if moved(link, Pane::Raw, raw, want_raw) {
        ScrollLink { driver: Pane::Raw, offset: raw.offset }
    } else {
        link
    }
}

/// Whether a pane that is not where it was asked to be was put there by the
/// reader.
///
/// The driver's disagreement always counts, clamp or not. It is already the
/// pane the other follows, so agreeing that it moved takes nothing from
/// anyone, and a link that ignored the clamp would keep handing out an offset
/// its own pane no longer has — which, after a window was made taller, is a
/// follower reading from a place in the command nobody is looking at.
fn moved(link: ScrollLink, pane: Pane, at: PaneAt, want: f32) -> bool {
    (at.offset - want).abs() > SCROLL_EPSILON && (link.driver == pane || !at.clamped(want))
}

// ---- saying how much of a pane is out of sight -----------------------------

/// Where each command pane's account of how much of itself it showed is kept.
fn pane_rows_id() -> egui::Id {
    egui::Id::new("hatch-command-showing")
}

/// Where the swap window's diff pane keeps the same thing.
fn diff_rows_id() -> egui::Id {
    egui::Id::new("hatch-diff-showing")
}

/// How many rows a pane laid out, and how many of them it had room to show.
///
/// Measured off a pane that has been drawn, for the reason [`PaneAt`] gives:
/// how many rows a rendering takes depends on the width the pane really
/// wrapped at and on what its own furniture took out of its height, and
/// neither is settled until it has been drawn. The two counts are rounded
/// apart — laid out rounds up, shown rounds down — so a row with half of it
/// under the bottom edge counts as a row that exists and not as a row that
/// was seen. Both errors point the same way, which is the way that tells a
/// reader there is more when there is barely any rather than the other way
/// round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Rows {
    /// Rows the pane laid out.
    of: usize,
    /// Rows of them the pane showed.
    shown: usize,
}

impl Rows {
    /// What a drawn pane's content height and viewport height come to, in
    /// rows of `row` points.
    fn measured(content: f32, viewport: f32, row: f32) -> Rows {
        if row <= 0.0 {
            return Rows::default();
        }
        Rows {
            of: (content / row - ROW_EPSILON).ceil().max(0.0) as usize,
            shown: (viewport / row + ROW_EPSILON).floor().max(0.0) as usize,
        }
    }

    /// Whether the reader was shown all of it.
    fn whole(self) -> bool {
        self.shown >= self.of
    }

    /// How many rows are not on screen.
    fn hidden(self) -> usize {
        self.of.saturating_sub(self.shown)
    }
}

/// How much of a row is allowed to be rounding rather than content.
///
/// A pane draws `n` lines in `n` text heights and `n - 1` gaps, and a row is a
/// text height *plus* a gap — see [`row_height`] — so a pane that fits its
/// content exactly comes out a fraction of a row short of a whole number in
/// one direction and a fraction over in the other. A twentieth of a row is
/// far more than that fraction and far less than the sliver of a real row
/// that this has to go on reporting.
const ROW_EPSILON: f32 = 0.05;

/// The sentence that says a pane is showing only some of the rows it has.
///
/// # Why this is said in words at all
///
/// Everything else this window does assumes the reader saw the text. The
/// chips, the raw pane beside the annotated one, the round-trip invariant
/// that refuses a payload whose spans do not tile their source — all of it is
/// about what is *on screen* being honest, and none of it says anything about
/// the part that is not. A pane showing twenty-four rows of a sixty-three-row
/// command used to say so through its scroll bar alone, and that bar floated
/// over the content and faded to nothing whenever the pointer was elsewhere.
/// A command can be written for that: blank lines to the height of a pane,
/// and the payload under them.
///
/// The bar is solid now — see [`theme::scroll_bars`] — and this is the other
/// half. Words beat an affordance on every axis that matters here: they are
/// unambiguous, they survive a reader who has never learned what a scroll bar
/// means, they survive a screenshot with no colour in it, and they can be
/// asserted in a test, which a fading rectangle cannot.
///
/// # Why it is a proportion and not a distance
///
/// It says how much there is against how much fits, and deliberately not how
/// far the reader still has to go. A sentence that counted down as they
/// scrolled would be a sentence that changes length, and this one is drawn
/// *above* the panes, so its length is part of how tall they are. A caption
/// that grew or shrank with the scroll position would move the panes under
/// the reader's hand — which is the exact shape of the bug `306c834` was
/// about, arriving through the caption instead of through the link. Content
/// against viewport does not move while anybody scrolls.
///
/// It also keeps saying it after they have reached the end, which is right:
/// "this pane holds twenty-four of sixty-three rows" is as true at the bottom
/// as at the top, and a notice that vanished the moment they got there would
/// be telling them they had seen everything on the evidence of where their
/// scroll bar is.
///
/// One loop survives that, and it is the reason for a test rather than a
/// paragraph. Being above the panes, this sentence's own height is part of
/// how tall they are, and what it says is measured off them — so two layouts
/// could in principle each imply the other, a sentence a character from
/// wrapping fitting on one row when the pane is short and on two when it is
/// tall. It takes a coincidence of a window width and a row count either side
/// of a digit, and a window that flickered between two sentences for as long
/// as it was open would be worse than the scroll bar this replaces. So it is
/// swept rather than argued away: see
/// `the_line_above_the_panes_settles_at_every_window_size`, which drags a
/// window through every width a reader plausibly would, at two heights, and
/// requires the last frames of each to draw the same line.
///
/// # Why there is no sentence for the case where it all fits
///
/// Because it would be a claim of completeness, and this measurement is one
/// frame old — it is read off the pane that was drawn last frame, which is
/// the only pane that has been drawn. One frame is nothing while a reader
/// scrolls and it is a real window while one is being resized, and "all of it
/// is on screen" is precisely the sentence a reader would stop reading on.
/// Saying only *there is more* puts every staleness in the direction that
/// costs them nothing. What carries the all-clear instead is the scroll bar,
/// which is drawn from this frame's own layout and is now always there to be
/// looked at.
///
/// # The stronger rule, and why it is not here
///
/// There is an honest version of this: **Approve stays disabled until the
/// command has actually been scrolled to the end.** For a program whose whole
/// premise is "you saw what you approved", telling the reader there is more
/// and then letting them approve anyway is the weaker thing to do, and it is
/// worth writing down why it is nonetheless the thing that is here.
///
/// * **It would check scrolling, not reading.** The gesture that satisfies it
///   is dragging a handle to the bottom, which takes a quarter of a second
///   and reads nothing. So the rule would not make the guarantee true; it
///   would make the window *assert* the guarantee on the evidence of a scroll
///   offset. A check that is cheaper to perform than to mean is worse than no
///   check, because the sentence above is honest about what it knows and a
///   greyed-out button would not be.
/// * **The cost lands entirely on the honest case.** Most requests fit and
///   the gate would never fire; the ones where it fires are the long ones,
///   which are already the slow ones to read. A window that is not answered
///   is resolved as a denial, so friction on a long command is not only
///   irritating — it is a new way for a request to be refused, and the reader
///   who is being made to hurry is the one who was reading.
/// * **"The end" is not one place.** The two panes are two renderings, and
///   the end of one is not the end of the other; a window resized while it is
///   being read moves both. A rule enforced against a number that ambiguous
///   would fire when it should not, and the reader would learn to work around
///   it rather than with it.
/// * **It needs state this window deliberately does not keep.** A high-water
///   mark per pane, surviving resizes and arrangement changes, would have to
///   live in [`crate::prompt_ui::PromptState`], which knows nothing about how
///   anything is drawn and is better for it.
///
/// What makes it acceptable to stop here: the reader is not being asked to
/// certify that they read everything, they are being asked whether to let
/// something run, and the window's own default is no. A reader who has been
/// told there are thirty-nine rows they have not seen and approves anyway has
/// made a decision, which is what this program is for.
///
/// What would change the answer is a narrower signal. A command padded with
/// blank lines to the height of a pane is a *shape*, and a shape can be
/// scanned for and marked in the danger tier, on the requests that have it
/// and no others — which is the register the rest of this window already
/// works in. That is a better use of the reader's attention than a rule
/// applied to every request they ever answer.
fn rows_out_of_sight(rows: Rows, of: &str, pane: &str) -> Option<String> {
    (!rows.whole()).then(|| {
        format!(
            "Only {} of {of}'s {} rows fit {pane}, so {} of them are out of sight; scroll \
             for the rest.",
            rows.shown,
            rows.of,
            rows.hidden(),
        )
    })
}

/// The sentence that says a pane's lines run off its right edge.
///
/// The same gap sideways, and the raw pane is where it bites: it deliberately
/// does not reflow — that is the promise the caption makes for it — so a long
/// line runs past the right edge and stops, with the scroll bar along the
/// bottom as the only sign that it did not end there. In a root request the
/// strip ends part-way through `run0`'s argument list.
///
/// Unlike the rows this needs no measurement and is not a frame old.
/// `longest` is counted off the rendering when the payload is read, `across`
/// is [`pane_chars`] for the box being drawn, and the pane's characters are
/// all one advance wide — `every_glyph_the_panes_draw_is_one_monospace_advance`
/// is what holds that — so the comparison is exact in the frame it is made.
fn width_out_of_sight(longest: usize, across: usize, pane: &str) -> Option<String> {
    (longest > across).then(|| {
        format!(
            "Lines run to {longest} characters and {pane} shows {across}; scroll sideways \
             for the rest."
        )
    })
}

/// The two sentences above, joined into the line that is drawn.
///
/// Empty when there is nothing to say, which is what the caller draws no row
/// for.
fn out_of_sight(rows: Option<String>, width: Option<String>) -> String {
    [rows, width].into_iter().flatten().collect::<Vec<_>>().join(" ")
}

/// How much of itself each command pane showed, the last time they were
/// drawn.
///
/// Kept in egui's own per-frame store beside [`ScrollLink`] and [`PaneReach`],
/// for the same reason and with the same shape: it is a fact about a layout
/// rather than about what the window is deciding, and the default is a pair
/// of panes that have never been drawn, which say nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct CommandRows {
    raw: Rows,
    annotated: Rows,
}

impl CommandRows {
    /// The worse of the two, for an arrangement that draws them level.
    ///
    /// The larger row count against the smaller viewport: side by side the
    /// two panes are the same height and hold two renderings of one command,
    /// and which of them has the most rows is not something a reader should
    /// have to be told. Taking the worst of each figure makes the one
    /// sentence true of both panes.
    fn worst(self) -> Rows {
        Rows {
            of: self.raw.of.max(self.annotated.of),
            shown: self.raw.shown.min(self.annotated.shown),
        }
    }
}

/// The out-of-sight line for the command panes, in whichever arrangement.
///
/// # Which pane each axis is reported off
///
/// Side by side, the two panes are level and the same height, so one sentence
/// covers both — see [`CommandRows::worst`] — and neither can run off to the
/// side, because the arrangement is only offered when every line fits its
/// column whole. That is what [`fits_two_columns`] is for, and it is why
/// there is no sideways sentence here.
///
/// Stacked, the rows are reported off the annotated pane alone. The raw pane
/// is a strip of [`RAW_STRIP_ROWS`] rows by deliberate choice — see
/// [`raw_ceiling`] — so "only six of sixty-three rows fit the strip" would be
/// hatch reporting its own layout decision back to the reader as news, every
/// time, which is the fastest way to teach somebody to stop reading a line.
/// The strip is also dragged to wherever the annotated pane is looking, so a
/// reader who scrolls that pane to the end has been past all of the raw text
/// six rows at a time.
///
/// Sideways is the strip's alone, and it is the one that surprises: the raw
/// pane does not reflow, so a long line runs off the right edge of a
/// full-width strip and stops there. `longest` is the command's longest line
/// as either rendering would draw it, which is the figure the caption above
/// already quotes, and `across` is what one full-width box holds.
fn command_note(view: CommandView, seen: CommandRows, longest: usize, across: usize) -> String {
    match view {
        CommandView::SideBySide => {
            out_of_sight(rows_out_of_sight(seen.worst(), "the command", "the panes"), None)
        }
        CommandView::Stacked => out_of_sight(
            rows_out_of_sight(seen.annotated, "the command", "the pane below"),
            width_out_of_sight(longest, across, "the strip"),
        ),
    }
}

/// Draw the out-of-sight line, if there is one.
///
/// In [`Palette::warn`] and not in the caption's quiet grey, and that is the
/// point of giving it a row of its own. The caption says how to read the
/// panes; this says the reader has not been shown all of what is in them,
/// which is a fact about the thing they are about to approve rather than a
/// note about the furniture. It is the same colour, and the same small size,
/// as the caveat that says a root command may behave differently — the other
/// line in this window that is a warning about the request rather than a mark
/// on the text.
///
/// The row it costs is a row the panes do not get, and it is spent in exactly
/// the case where they are already short of rows. That is the right way
/// round: a row that says "there are thirty-nine more" is worth more than the
/// thirty-ninth row would have been. It cannot flicker, either — taking the
/// row can only ever make the panes shorter, so a notice that has appeared
/// cannot make itself untrue.
fn draw_out_of_sight(ui: &mut Ui, note: &str) {
    if note.is_empty() {
        return;
    }
    ui.label(RichText::new(note).small().color(palette(ui).warn));
}

/// The two panes.
///
/// # Side by side, when they fit
///
/// Reading a command is a top-to-bottom act, so each pane wants the window's
/// whole height rather than half of it. Two columns also put the raw and the
/// annotated form of the same text at the same height, so a discrepancy
/// between them is something the eye catches rather than something the reader
/// has to scroll between and hold in memory — which is the entire reason the
/// raw pane is there.
///
/// That second benefit is exactly what a column too narrow to hold a line
/// destroys: one pane wrapping or scrolling sideways while the other does not
/// puts the two forms of a line at different heights, which is worse than
/// stacking them. So the panes go side by side only when every line of both
/// fits a column whole, by [`fits_two_columns`] — the same rule, and the same
/// function, the diff uses — and stack when it does not. Nothing is ever
/// truncated to make them fit, and [`command_caption`] says which case this
/// is when the answer is the fallback.
///
/// # Stacked, when they do not
///
/// The space is not split, and deliberately not: the raw pane becomes a strip
/// of [`RAW_STRIP_ROWS`] lines and everything else goes to the annotated
/// pane. Stacking is chosen *because the command is long*, so an even split
/// would take the most reading room away in the case that needs the most —
/// and spend it drawing the same command twice. See [`raw_ceiling`].
///
/// Stacked, and only stacked, the two panes scroll together. Side by side
/// needs no help: corresponding text is already level, which is the whole
/// reason to prefer it. Stacked puts line N and its annotated form half a
/// window apart, and scrolling them independently turns comparing the two
/// forms of one line into a memory exercise — in the arrangement the reader
/// did not choose. So the panes are linked, by *position in the command*
/// rather than by pixels or by line number: see [`pane_lines`] for why those
/// two would drift and a source offset cannot.
fn draw_command(ui: &mut Ui, annotated: &Spans, raw: &Spans, longest: usize) {
    let palette = palette(ui);
    let column = column_chars(pane_chars(ui, 2), 0);
    let view = command_view(longest, column);
    // One line for both panes: which is which, and what each promises. See
    // `command_caption` for why the promise is not furniture.
    ui.label(RichText::new(command_caption(view, longest, column)).small().color(palette.quiet));

    // And, under it, how much of the command the panes are not showing. The
    // row counts are last frame's, because a pane is the only thing that
    // knows how many rows it laid out and it does not know until it has —
    // see `rows_out_of_sight`. A window that has drawn no frame yet has a
    // pair of panes that showed nothing of nothing, which says nothing.
    let seen = ui.data(|data| data.get_temp::<CommandRows>(pane_rows_id()).unwrap_or_default());
    let across = pane_chars(ui, 1);
    draw_out_of_sight(ui, &command_note(view, seen, longest, across));

    let shown = match view {
        CommandView::SideBySide => {
            let height = ui.available_height();
            ui.columns(2, |columns| {
                let raw =
                    draw_command_pane(&mut columns[0], raw, PaneBox::raw(height, false, None));
                let annotated =
                    draw_command_pane(&mut columns[1], annotated, PaneBox::annotated(height, None));
                CommandRows { raw: raw.rows, annotated: annotated.rows }
            })
        }
        CommandView::Stacked => {
            let row = row_height(ui);
            // The raw pane does not reflow, so one line is one row there; the
            // annotated pane wraps at the width of one full-width box.
            let raw_rows = pane_lines(raw, None);
            let annotated_rows = pane_lines(annotated, Some(pane_chars(ui, 1)));
            let (link, reach) = ui.data(|data| {
                (
                    data.get_temp::<ScrollLink>(scroll_link_id()).unwrap_or_default(),
                    data.get_temp::<PaneReach>(pane_reach_id()).unwrap_or_default(),
                )
            });
            let driver = match link.driver {
                Pane::Raw => &raw_rows,
                Pane::Annotated => &annotated_rows,
            };

            // The strip grows a horizontal bar exactly when a line runs past
            // its right edge, which is the same question the sideways
            // sentence above asked, so it is asked once and answered here
            // too.
            let sideways = match longest > across {
                true => ui.spacing().scroll.allocated_width(),
                false => 0.0,
            };
            let ceiling = raw_ceiling(ui.available_height(), row, sideways);
            let raw_reach = reach.raw.unwrap_or_else(|| max_offset(raw_rows.rows, row, ceiling));
            let want_raw = requested_offset(link, Pane::Raw, &raw_rows, driver, row, raw_reach);
            let drawn_raw = draw_command_pane(ui, raw, PaneBox::raw(ceiling, true, Some(want_raw)));
            let at_raw = drawn_raw.at;

            ui.add_space(4.0);
            let rest = ui.available_height();
            let annotated_reach =
                reach.annotated.unwrap_or_else(|| max_offset(annotated_rows.rows, row, rest));
            let want_annotated = requested_offset(
                link,
                Pane::Annotated,
                &annotated_rows,
                driver,
                row,
                annotated_reach,
            );
            let drawn_annotated =
                draw_command_pane(ui, annotated, PaneBox::annotated(rest, Some(want_annotated)));
            let at_annotated = drawn_annotated.at;

            let link = drove(link, at_raw, want_raw, at_annotated, want_annotated);
            let reach = PaneReach { raw: Some(at_raw.max), annotated: Some(at_annotated.max) };
            ui.data_mut(|data| {
                data.insert_temp(scroll_link_id(), link);
                data.insert_temp(pane_reach_id(), reach);
            });
            CommandRows { raw: drawn_raw.rows, annotated: drawn_annotated.rows }
        }
    };

    // The line above the panes was built from the frame before this one, and
    // this is the first frame that knows better. Asking for another is what
    // makes "one frame old" the whole of the staleness: without it the notice
    // would wait for whatever else wakes the window next, which on a window
    // that is only counting down a deadline is as much as a second.
    if shown != seen {
        ui.ctx().request_repaint();
    }
    ui.data_mut(|data| data.insert_temp(pane_rows_id(), shown));
}

/// One command pane: the rendering in a framed, scrolling box.
///
/// No label of its own — the one caption above both panes says which is which
/// and what each promises, in the rows two labels would have cost.
///
/// Each pane keeps the weight it has always had, in both arrangements. The
/// raw pane never reflows, so a line too wide for it is scrolled to; the
/// annotated pane wraps, so a stacked window shows a long command without
/// anyone having to drag sideways. Side by side is only offered when neither
/// behaviour can fire, which is what [`fits_two_columns`] is measuring.
///
/// `at` is where the pane is asked to be scrolled to, and `None` is "wherever
/// the reader left it". What comes back is where it actually ended up and how
/// far down it had anything to show, which is how the caller tells a pane
/// that agreed with what it was asked from a pane the reader scrolled — and
/// both of those from a pane that simply ran out of command. See [`PaneAt`].
/// The same two numbers, in rows rather than in pixels, are what the caption
/// says out loud on the next frame: see [`Rows`].
fn draw_command_pane(ui: &mut Ui, spans: &Spans, pane: PaneBox) -> PaneShown {
    // A pane that cannot wrap needs somewhere to scroll a long line to; one
    // that wraps has nothing to the side and a horizontal bar would only be
    // furniture.
    let mut scroll = match pane.weight.wraps() {
        true => egui::ScrollArea::vertical(),
        false => egui::ScrollArea::both(),
    }
    .id_salt(pane.id)
    .max_height(pane.height)
    .auto_shrink([false, pane.shrink]);
    if let Some(at) = pane.at {
        scroll = scroll.vertical_scroll_offset(at);
    }
    let row = row_height(ui);
    pane_frame(ui)
        .show(ui, |ui| {
            let drawn = scroll.show(ui, |ui| draw_spans(ui, spans, pane.weight));
            PaneShown {
                at: PaneAt {
                    offset: drawn.state.offset.y,
                    max: (drawn.content_size.y - drawn.inner_rect.height()).max(0.0),
                },
                rows: Rows::measured(drawn.content_size.y, drawn.inner_rect.height(), row),
            }
        })
        .inner
}

/// What one drawn pane reports about itself: where it is, and how much of
/// itself the reader was shown.
#[derive(Debug, Clone, Copy, PartialEq)]
struct PaneShown {
    at: PaneAt,
    rows: Rows,
}

/// One command pane's box: everything about it except what is in it.
#[derive(Debug, Clone, Copy)]
struct PaneBox {
    /// Its scroll area's identity, so a pane keeps its position across
    /// frames.
    id: &'static str,
    weight: Weight,
    /// The most of the window it may take.
    height: f32,
    /// Whether it shrinks to its content rather than filling `height`.
    shrink: bool,
    /// Where to scroll it, or `None` for wherever the reader left it.
    at: Option<f32>,
}

impl PaneBox {
    /// The raw pane, which never reflows.
    fn raw(height: f32, shrink: bool, at: Option<f32>) -> PaneBox {
        PaneBox { id: "hatch-raw", weight: Weight::Mono, height, shrink, at }
    }

    /// The annotated pane, which wraps.
    fn annotated(height: f32, at: Option<f32>) -> PaneBox {
        PaneBox {
            id: "hatch-annotated",
            weight: Weight::Wrapped,
            height,
            shrink: false,
            at,
        }
    }
}

/// What a `swap_file` request looks like.
///
/// Not an empty pane, and not a summary either. An empty pane in this window
/// reads as "nothing changes", which is the one thing it must never say by
/// accident; a summary — "12 lines change" — reads as a fact the reader has
/// checked when they have checked nothing. So every line is drawn, through
/// exactly the same span machinery the command panes use, chips and all.
///
/// # Two views, and which one a diff gets
///
/// Side by side is the view this is for: the file as it is on the left, what
/// replaces it on the right, one row per row of the model. It is only offered
/// when every line fits its column whole — see [`diff_view`] — and when one
/// does not, the whole diff falls back to the unified view, `-` and `+` in
/// one column, where a long line can run off the side and be scrolled to.
/// The caption says which view this is and, in the fallback, the two numbers
/// that chose it. Degrading in the open beats a second column that quietly
/// holds part of a line.
///
/// Side by side never scrolls horizontally, and that is the point of the
/// all-or-nothing rule rather than an accident of it: everything in view is
/// whole, so a row that looks identical on both sides *is* identical, except
/// for the one thing the terminator rule below covers.
///
/// # What a row that only exists on one side looks like
///
/// A gap — a row where the model has no line for one column — is drawn as a
/// tinted empty cell with nothing in its gutter, never as a blank line. The
/// difference matters and is exactly the difference between "this file has no
/// line here" and "this file has an empty line here", which is a real line
/// that a reader is approving. Two channels say it, so neither has to be
/// colour alone: the tint, and the absence of the `-`/`+` mark that every
/// present line of a changed row carries.
///
/// # What the pairing does and does not claim
///
/// `similar` pairs a delete with an insert positionally inside a replace
/// block, and the surplus follows one-sided. That pairing is a display
/// decision the model is explicit about making with no claim behind it, and
/// two columns are where it starts to *look* like a claim. So the view adds
/// nothing to it: no intra-line highlighting of the "changed part", which
/// would be an assertion that the two lines are versions of each other, and
/// no reordering to make pairs look better. Each cell carries its own `-` or
/// `+`, which says this line goes or this line arrives — a statement about
/// one line, not about a correspondence between two.
///
/// # Line terminators
///
/// Drawn only where the two sides' terminators differ, as in the unified
/// view, and two columns make the argument for that rule stronger rather than
/// weaker. The case it exists for — content identical, ending rewritten — is
/// precisely the case where two columns would otherwise be drawn pixel for
/// pixel the same over a change to every byte at the end of every line. When
/// it fires, both cells draw their terminator, because a `↵` shown against a
/// cell that hides its own is not a comparison. Drawing them always would put
/// a chip on every line of the file, and a reader who has learned to skip
/// chips is a reader who will skip the one that is a bidi override. That
/// argument is weaker than it was — a terminator is in the structural tier
/// now, so it is a quiet glyph rather than an orange box, and a whole column
/// of them is much less of an imposition. It is not gone: a chip on every
/// line is still a mark on every line, and the rule costs a reader nothing,
/// because the case it hides is exactly the case where both sides agree.
fn draw_swap(ui: &mut Ui, path: &str, plan: &SwapPlan, rows: &[Row], longest: usize) {
    let palette = palette(ui);
    ui.horizontal_wrapped(|ui| {
        ui.label("Writes");
        ui.label(RichText::new(path).monospace().strong());
    });
    for (label, value) in plan_facts(plan) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(label).color(palette.quiet));
            ui.label(RichText::new(value).monospace());
        });
    }
    ui.separator();

    let advance = advance(ui);
    let across = pane_chars(ui, 1);
    let column = column_chars(across, GUTTER_CHARS);
    let view = diff_view(longest, column);
    ui.label(
        RichText::new(diff_caption(view, rows, longest, column)).small().color(palette.quiet),
    );

    // The same notice the command panes carry, for the same reason: a diff is
    // a list of lines somebody is about to let be written, and a pane showing
    // forty of two hundred of them said so through its scroll bar alone. Side
    // by side has nothing off to the side — every line fits its column, which
    // is what chose the view — so only the unified view can run off the right
    // edge, and it does so past a `-`/`+` gutter that is not text.
    let seen = ui.data(|data| data.get_temp::<Rows>(diff_rows_id()).unwrap_or_default());
    draw_out_of_sight(
        ui,
        &out_of_sight(
            rows_out_of_sight(seen, "the diff", "the pane"),
            match view {
                DiffView::SideBySide => None,
                DiffView::Unified => width_out_of_sight(
                    longest,
                    across.saturating_sub(GUTTER_CHARS),
                    "the pane",
                ),
            },
        ),
    );

    if rows.is_empty() {
        // Said in words, because an empty pane here would read as "nothing
        // changes" over a request that does change something: creating an
        // empty file, or emptying one, is a write with no lines in it.
        ui.label(
            RichText::new("Neither side has any lines at all.").italics().color(palette.quiet),
        );
        return;
    }

    // `show_rows` and not a loop: a 256 KB replacement is a quarter of a
    // million rows, and a pane that laid all of them out per frame would be
    // a window nobody can answer in time — which the daemon resolves as a
    // denial, but by making the machine unusable rather than by anyone
    // deciding anything. Every drawn row is one line of monospace, so the
    // uniform height the API wants is a fact rather than an assumption, and
    // it is a fact in both views: side by side never wraps a cell, because a
    // diff that would have to wrap one is drawn unified instead.
    let row_height = row_height(ui);
    let shown = pane_frame(ui)
        .show(ui, |ui| {
            let drawn = match view {
                DiffView::SideBySide => {
                    let size = Cells {
                        gutter: advance * GUTTER_CHARS as f32,
                        cell: advance * column as f32,
                        gap: advance * GAP_CHARS as f32,
                        height: row_height,
                    };
                    // Vertical only. Every line fits, so there is nothing to
                    // the side to scroll to, and a horizontal bar that moved
                    // one column out from under the other would break the
                    // alignment the view is for.
                    egui::ScrollArea::vertical()
                        .id_salt("hatch-diff-columns")
                        .max_height(ui.available_height())
                        .auto_shrink([false, false])
                        .show_rows(ui, row_height, rows.len(), |ui, range| {
                            for row in &rows[range] {
                                draw_row(ui, row, &palette, size);
                            }
                        })
                }
                DiffView::Unified => {
                    let lines = diff_lines(rows);
                    egui::ScrollArea::both()
                        .id_salt("hatch-diff")
                        .max_height(ui.available_height())
                        .auto_shrink([false, false])
                        .show_rows(ui, row_height, lines.len(), |ui, range| {
                            for line in &lines[range] {
                                draw_diff_line(ui, line, palette.danger, palette.warn);
                            }
                        })
                }
            };
            // Counted at the pitch `show_rows` really laid the diff out at,
            // which is not `row_height`. It adds an item spacing to the
            // height it is handed, and the height handed to it here is
            // already a line plus a gap — so a diff row is a line and two
            // gaps. That extra gap is how this pane has always looked and is
            // not this count's business; what is, is that a figure the
            // caption quotes be counted at the pitch on screen, or a
            // two-hundred-row diff would be reported as two hundred and
            // twenty-eight.
            let pitch = row_height + ui.spacing().item_spacing.y;
            Rows::measured(drawn.content_size.y, drawn.inner_rect.height(), pitch)
        })
        .inner;

    // As above the command panes: the caption was built from the frame
    // before, and this is the first frame that knows better.
    if shown != seen {
        ui.ctx().request_repaint();
    }
    ui.data_mut(|data| data.insert_temp(diff_rows_id(), shown));
}

/// The box a pane is drawn in: a fill that is not the chrome, and an edge
/// that says so.
///
/// egui's own group frame is a hairline and no fill at all, which on a dark
/// theme is a pane that reads as part of the window behind it — see
/// [`crate::prompt_ui::theme`] for the measurement. The fill is the anchor
/// for the eye and the border is the boundary claim; the two together are
/// what make a pane an object.
///
/// One function, used by every reading box and by the width arithmetic that
/// has to know how much of a column the furniture takes: a frame measured
/// through one constructor and drawn through another is how a column comes to
/// promise room it does not have.
fn pane_frame(ui: &Ui) -> egui::Frame {
    egui::Frame::group(ui.style()).fill(palette(ui).surface)
}

/// The width `boxes` framed, scrolling boxes really leave for text.
///
/// Subtracting the furniture rather than measuring inside the box, because
/// the view has to be chosen before the box that would report its own width
/// exists. Every term is something that is definitely there: each box's group
/// frame, border and padding on both sides, and each box's vertical scroll
/// bar, which anything long enough to matter grows.
///
/// The bar's term is asked of the style — `ScrollStyle::allocated_width` is
/// egui's own answer to "how much of a box does a bar take" — and not added
/// up out of its fields here. It used to be `bar_width + bar_inner_margin`,
/// which is the right sum for a solid bar and the wrong one for the floating
/// bar egui defaults to: a floating bar draws over the content and allocates
/// nothing, so the subtraction took fourteen points a pane still had. That
/// over-count is what made [`pane_lines`] fit a line in more rows than the
/// real pane does, which is the row of slack that inverted the scroll link's
/// guard — see [`max_offset`]. This window's bars are solid, by
/// [`theme::scroll_bars`], so the column is real; asking the style is what
/// keeps the two from disagreeing again if it ever stops being.
///
/// `boxes` is one for a diff, which is drawn in a single frame, and two for
/// the command panes side by side.
fn text_width(ui: &Ui, boxes: usize) -> f32 {
    let frame = pane_frame(ui);
    let border = (frame.inner_margin.sum() + frame.outer_margin.sum()).x + 2.0 * frame.stroke.width;
    let scroll = ui.spacing().scroll.allocated_width();
    (ui.available_width() - boxes as f32 * (border + scroll)).max(0.0)
}

/// The height of one drawn line, from the font in force and the space the
/// layout puts between two of them.
///
/// Both terms are needed and neither is the other: a row is a line of text
/// *plus* the gap to the next one, and the scroll link turns a line index
/// into an offset by multiplying by exactly this.
///
/// The font's term is rounded to whole device pixels first, because that is
/// what happens to it on the way to the screen: a galley's size is rounded
/// there, so a pane really advances by the rounded figure and not by the
/// font's own. The two differ by a third of a point at sixteen, which is
/// nothing in one line and a whole row in sixty — which is a row of drift in
/// the scroll link over a long command, and a row of over-count in the
/// sentence that says how many rows there are. Both of those are the length
/// of command this window exists for.
fn row_height(ui: &Ui) -> f32 {
    let text = ui.text_style_height(&egui::TextStyle::Monospace);
    let points = ui.ctx().pixels_per_point();
    (text * points).round() / points + ui.spacing().item_spacing.y
}

/// How tall the raw pane is when the panes are stacked.
///
/// # Why a strip
///
/// Stacking happens *because the command is long* — that is the whole of the
/// rule that chose it — and long is exactly when a reader needs vertical
/// room. Splitting the space between two renderings of the same text was
/// therefore backwards: it took the most room away in the case where reading
/// was hardest, and spent it drawing the command a second time.
///
/// The two panes do not have the same job. The annotated pane is the one a
/// reader *reads*. The raw pane is the one they *check* — it is the answer to
/// "the pretty view might be misleading me" — and checking is done a line at
/// a time, against the line you are already on. So stacked, the raw pane is a
/// strip of [`RAW_STRIP_ROWS`] lines and the annotated pane takes everything
/// else.
///
/// # Why it is not behind a toggle
///
/// The point of the raw pane is to be there without being asked for: a pane
/// behind a disclosure triangle is a pane the reader forgets exists, and the
/// one time it matters is the one time nobody clicks. So the strip is always
/// drawn, never collapsed, and all of the raw text is reachable in it —
/// scrolled directly, or by scrolling the annotated pane, which drags the
/// strip to the same place in the command. See [`ScrollLink`].
///
/// The share is still a ceiling on top of the strip, for the short window
/// where six rows would be most of what there is.
///
/// `bar` is what a horizontal scroll bar will take out of the box, which is
/// its allocated width where the strip is going to grow one and zero where it
/// is not. It is added rather than absorbed, because [`RAW_STRIP_ROWS`] is a
/// count of rows of *command* and a bar is not one: a strip that paid for its
/// own bar out of its six rows would show five and a sliver of the sixth, and
/// a row cut off halfway is the thing this whole pass is about.
fn raw_ceiling(available: f32, row: f32, bar: f32) -> f32 {
    (RAW_STRIP_ROWS * row + bar).min(available * RAW_SHARE)
}

/// The width of one character of the font both panes and both diff views draw
/// in.
///
/// `'0'` because every glyph of a monospace font is the same width and a
/// digit is the one that is certainly present. Floored at one so that a font
/// that reports nothing cannot make a column infinitely wide.
fn advance(ui: &Ui) -> f32 {
    let font = font(Weight::Mono, ui.style());
    ui.ctx().fonts_mut(|fonts| fonts.glyph_width(&font, '0')).max(1.0)
}

/// How many characters of that font fit across `boxes` framed boxes.
fn pane_chars(ui: &Ui, boxes: usize) -> usize {
    (text_width(ui, boxes) / advance(ui)).floor().max(0.0) as usize
}

/// The pixel geometry of one side-by-side row.
#[derive(Debug, Clone, Copy)]
struct Cells {
    /// Width of one column's `-`/`+` mark and the space after it.
    gutter: f32,
    /// Width of one column's text.
    cell: f32,
    /// Width of the empty space between the two columns.
    gap: f32,
    /// Height of the whole row, which every cell fills whether or not it has
    /// a line — a shorter gap cell would make the tint stop short of the row
    /// it belongs to.
    height: f32,
}

/// What one column of one row has to show.
#[derive(Debug, Clone, Copy)]
enum Cell<'a> {
    /// A line of that side's file.
    Line {
        side: &'a Side,
        /// `-` for the file as it is, `+` for what replaces it, a space for a
        /// line both sides agree on.
        marker: &'static str,
        changed: bool,
        /// Whether this row's terminator is part of what changed, and so has
        /// to be on screen. See [`draw_swap`].
        terminator: bool,
    },
    /// That side has no line on this row. **Not** an empty line: see
    /// [`draw_swap`].
    Gap,
}

/// The two cells of one row.
///
/// The only place the gap is decided, so "the model had no line here" and
/// "the line here is empty" cannot be confused by a drawing function reading
/// an empty span slice and guessing.
fn cells(row: &Row) -> [Cell<'_>; 2] {
    let terminator = terminator_changed(row);
    let changed = row.changed();
    [
        cell(row.left(), "-", changed, terminator),
        cell(row.right(), "+", changed, terminator),
    ]
}

/// One column of one row. A `None` side is a gap and never a blank line --
/// the model says the column has nothing here, and a `Side` with no content
/// spans would say the opposite.
fn cell<'a>(
    side: Option<&'a Side>,
    marked: &'static str,
    changed: bool,
    terminator: bool,
) -> Cell<'a> {
    match side {
        Some(side) => Cell::Line {
            side,
            marker: if changed { marked } else { " " },
            changed,
            terminator,
        },
        None => Cell::Gap,
    }
}

/// One row of the side-by-side view.
fn draw_row(ui: &mut Ui, row: &Row, palette: &Palette, size: Cells) {
    let [left, right] = cells(row);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        draw_cell(ui, left, palette, size);
        ui.add_space(size.gap);
        draw_cell(ui, right, palette, size);
    });
}

/// One column of one row: a mark, and a line or a tinted absence.
fn draw_cell(ui: &mut Ui, cell: Cell<'_>, palette: &Palette, size: Cells) {
    match cell {
        Cell::Line { side, marker, changed, terminator } => {
            let colour = match (changed, marker) {
                (false, _) => palette.quiet,
                (true, "-") => palette.danger,
                (true, _) => palette.warn,
            };
            slot(ui, size.gutter, size.height, |ui| {
                ui.add(
                    egui::Label::new(RichText::new(marker).monospace().color(colour))
                        .wrap_mode(egui::TextWrapMode::Extend),
                );
            });
            let spans = if terminator { side.spans() } else { side.content_spans() };
            slot(ui, size.cell, size.height, |ui| draw_line(ui, spans, Weight::Mono));
        }
        Cell::Gap => {
            // No mark and no text: the gutter is left empty on purpose, so
            // that the reader has a second, colourless way to tell a gap from
            // a line that happens to be blank.
            let (rect, _) = ui.allocate_exact_size(
                egui::vec2(size.gutter + size.cell, size.height),
                egui::Sense::hover(),
            );
            ui.painter().rect_filled(rect, 2.0, palette.gap_bg);
        }
    }
}

/// Reserve exactly `width` by `height` and draw into it.
///
/// The reservation is the whole point and is why this is not
/// `allocate_ui_with_layout`, which shrinks to what its contents used: the
/// two columns line up only if a short line still costs its column's full
/// width, and a row whose left cell shrank would put its right cell
/// somewhere no other row's is. The contents are not clipped to the slot —
/// a clip would silently cut a line off, and the whole reason this view is
/// only offered when every line fits is so that it never has to.
fn slot(ui: &mut Ui, width: f32, height: f32, draw: impl FnOnce(&mut Ui)) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let mut inner = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(rect)
            .layout(egui::Layout::left_to_right(egui::Align::Min)),
    );
    draw(&mut inner);
}

/// One line of the unified view: which side it came from, and how it is
/// marked.
struct DiffLine<'a> {
    side: &'a Side,
    /// `-` for the file as it is, `+` for what would replace it, a space for
    /// a line that both sides agree on.
    marker: &'static str,
    changed: bool,
    /// Whether this line's terminator is part of what changed, and so has to
    /// be on screen. See [`draw_swap`].
    terminator: bool,
}

/// Flatten the rows into the lines the unified view draws, in order.
///
/// A changed row contributes both of its sides, and either may be missing —
/// that is what an insertion and a deletion are. An unchanged row contributes
/// one line, because drawing context twice would double the length of an
/// almost-unchanged file and say nothing.
fn diff_lines(rows: &[Row]) -> Vec<DiffLine<'_>> {
    let mut out = Vec::new();
    for row in rows {
        let terminator = terminator_changed(row);
        if row.changed() {
            if let Some(side) = row.left() {
                out.push(DiffLine { side, marker: "-", changed: true, terminator });
            }
            if let Some(side) = row.right() {
                out.push(DiffLine { side, marker: "+", changed: true, terminator });
            }
        } else if let Some(side) = row.left().or(row.right()) {
            out.push(DiffLine { side, marker: " ", changed: false, terminator });
        }
    }
    out
}

/// Whether this row's two sides end differently.
///
/// A row with only one side is an insertion or a deletion: the marker already
/// says the whole line — terminator included — is arriving or going, so there
/// is nothing a chip would add.
fn terminator_changed(row: &Row) -> bool {
    match (row.left(), row.right()) {
        (Some(left), Some(right)) => terminator_of(left) != terminator_of(right),
        _ => false,
    }
}

/// One side's terminator as text, for comparison only.
fn terminator_of(side: &Side) -> String {
    side.terminator_spans().iter().map(Span::text).collect()
}

/// One drawn line of the unified view.
fn draw_diff_line(ui: &mut Ui, line: &DiffLine<'_>, removed: Color32, added: Color32) {
    let quiet = ui.visuals().weak_text_color();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        let gutter = RichText::new(format!("{} ", line.marker)).monospace();
        ui.label(if line.changed {
            gutter.color(if line.marker == "-" { removed } else { added })
        } else {
            gutter.color(quiet)
        });
        let spans = if line.terminator { line.side.spans() } else { line.side.content_spans() };
        draw_line(ui, spans, Weight::Mono);
    });
}

/// How a run of spans is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Weight {
    /// Monospace, no reflow: the line runs off the side and is scrolled to.
    Mono,
    /// Monospace, wrapped at the pane's edge.
    Wrapped,
    /// Proportional body text, wrapped.
    Body,
    /// Proportional, large, wrapped.
    Heading,
}

impl Weight {
    /// Whether a line of this weight may be broken by the layout.
    fn wraps(self) -> bool {
        self != Weight::Mono
    }
}

/// The font a weight draws in, resolved against the style in force.
///
/// Heading is body at a larger size rather than egui's own `Heading` style,
/// which is what the per-span form did and is worth keeping: the headline is
/// two paragraphs of agent-written prose, and it should read as prose set
/// large. A multiple of body and not a point count, so that it follows the
/// size the reader chose — see [`super::apply_font_size`].
fn font(weight: Weight, style: &egui::Style) -> egui::FontId {
    match weight {
        Weight::Mono | Weight::Wrapped => egui::TextStyle::Monospace.resolve(style),
        Weight::Body => egui::TextStyle::Body.resolve(style),
        Weight::Heading => {
            let mut font = egui::TextStyle::Body.resolve(style);
            font.size *= super::HEADLINE_SCALE;
            font
        }
    }
}

/// Draw a whole rendering, one drawn line per requested break.
///
/// The breaks come from the rendering, not from this function: segmentation
/// asked for them, and a layout that invented its own would be grouping the
/// command differently from the pass whose grouping the reader is being shown.
fn draw_spans(ui: &mut Ui, spans: &Spans, weight: Weight) {
    for line in lines(spans) {
        draw_line(ui, line, weight);
    }
}

/// The same, with [`ATTRIBUTION`] in front of the first line.
///
/// In front of it and not above it: the lead-in is appended into the same
/// [`egui::text::LayoutJob`] the line is drawn as, so it wraps with the
/// sentence it introduces and takes no row of its own. See [`draw_headline`]
/// for why the headline says whose words it is carrying at all.
///
/// An empty rendering still gets the lead-in, on a line by itself. A title
/// the agent left blank is a strange thing for this window to be showing, and
/// dropping the attribution there would leave the reason below it as the
/// first line on screen with nothing saying who wrote it.
fn draw_attributed(ui: &mut Ui, spans: &Spans, weight: Weight) {
    let palette = palette(ui);
    let font = font(weight, ui.style());
    let drawn = lines(spans);
    let empty: &[&[Span]] = &[&[]];
    let drawn = if drawn.is_empty() { empty } else { &drawn };
    for (index, line) in drawn.iter().enumerate() {
        let job = line_job(line, &palette, &font);
        let job = match index {
            0 => led_by(ATTRIBUTION, &palette, ui.style(), job),
            _ => job,
        };
        ui.add(egui::Label::new(job).wrap_mode(wrap_mode(weight)));
    }
}

/// One laid-out line with hatch's own words in front of the agent's.
///
/// Rebuilt rather than prepended, because a [`egui::text::LayoutJob`]'s
/// sections are byte ranges into its own text and there is no way to push
/// anything onto the front of one. Re-appending each section keeps the
/// formats [`line_job`] chose — chips, separators, resolved values and all —
/// so this adds a voice and changes nothing about how the line it leads is
/// drawn.
///
/// Small, quiet and italic: the three ways this window already says *hatch is
/// talking*, none of which the agent's own text is ever drawn in.
fn led_by(
    lead: &str,
    palette: &Palette,
    style: &egui::Style,
    job: egui::text::LayoutJob,
) -> egui::text::LayoutJob {
    let mut out = egui::text::LayoutJob::default();
    // A real space and not a `leading_space`, which is an offset the layout
    // applies and not a character: the two look the same on screen, and only
    // one of them is there when something reads the line back as a string.
    out.append(&format!("{lead} "), 0.0, egui::TextFormat {
        font_id: egui::TextStyle::Small.resolve(style),
        color: palette.quiet,
        italics: true,
        ..Default::default()
    });
    for section in &job.sections {
        out.append(
            section.byte_range.slice(&job.text),
            section.leading_space,
            section.format.clone(),
        );
    }
    out
}

/// Split a rendering where it asked to be split.
///
/// A break on the first span is not a split: it would put an empty line above
/// everything, and `break_before` on the first span means "this starts a
/// line", which it does anyway.
fn lines(spans: &[Span]) -> Vec<&[Span]> {
    let mut out = Vec::new();
    let mut start = 0;
    for (index, span) in spans.iter().enumerate() {
        if span.break_before() && index > start {
            out.push(&spans[start..index]);
            start = index;
        }
    }
    if start < spans.len() {
        out.push(&spans[start..]);
    }
    out
}

/// One drawn line of spans, as a single laid-out run of text.
///
/// # One job, not one label per span
///
/// The obvious shape — an `egui::Label` per span, laid out side by side —
/// costs a widget per span, and the number of spans is chosen by the agent:
/// a kilobyte of combining marks is a thousand chips, and every one of them
/// would be allocated, sensed and painted on every frame. It resolves to a
/// window nobody can read in time, which the daemon settles as a denial, so
/// it is a quality problem rather than a safety one — but a diff draws two
/// columns of it per row, which is where a slow pane becomes an unusable one.
///
/// A [`LayoutJob`] is one widget per *line* with a format per span, and it is
/// the honest shape for a second reason. Adjacent labels are separated by
/// egui's item spacing, so the per-span form had to zero that out or put a
/// gap on screen that is not in the text; here there is nothing between two
/// spans to zero, because they are two ranges of one string. And that string
/// is [`line_text`] — testable, unlike a sequence of widgets — so what the
/// reader is shown can be asserted against what the spans say.
fn draw_line(ui: &mut Ui, line: &[Span], weight: Weight) {
    let palette = palette(ui);
    let font = font(weight, ui.style());
    let job = line_job(line, &palette, &font);
    ui.add(egui::Label::new(job).wrap_mode(wrap_mode(weight)));
}

/// One line of spans as an [`egui::text::LayoutJob`]: the text every span
/// draws, in order, each in the format its kind asks for.
///
/// # Why a chip has two loudnesses
///
/// The tier comes from [`Span::chip_tier`], which reads it out of the
/// character, and never from the label: a view that recognised `[LF]` would
/// be reading a label, and a label is the one thing on screen that a command
/// may contain literally. A loud chip keeps the box and the warning colour; a
/// structural one — a newline, a carriage return, a tab — is a compact glyph
/// in the quiet colour with no box at all, because a heredoc's ten line
/// endings shouting as loudly as a bidi override teaches the reader to skip
/// both. The glyph is still not the command's own text and cannot be mistaken
/// for it: every character either pane draws as itself is ASCII printable, and
/// none of these glyphs is.
///
/// # Why a separator is not faded
///
/// The model calls a separator "dimmed, kept on screen", and the obvious
/// reading of that — lower the alpha — is the historical bug in a new
/// costume: a `;` nobody notices is how a second command gets approved along
/// with the first. So nothing here reduces the contrast of a separator's
/// text. It is drawn at full strength, in the colour of ordinary text, and
/// de-emphasised the other way round: a faint block behind it says "this is
/// punctuation, not a word", and the line break the renderer already asked
/// for is what actually stops it hiding between two commands. Emphasis is
/// taken off it by giving the eye somewhere else to land, never by making it
/// harder to see.
fn line_job(line: &[Span], palette: &Palette, font: &egui::FontId) -> egui::text::LayoutJob {
    let plain = egui::TextFormat {
        font_id: font.clone(),
        color: palette.text,
        ..Default::default()
    };
    let mut job = egui::text::LayoutJob::default();
    for span in line {
        let format = match span.kind() {
            // Chips are hatch's word, not the agent's: a background is what
            // says "this box is a substitution", and the label inside it is
            // the only text in either pane that is not the source's own
            // bytes. Structure is the exception, and it is quieter rather
            // than absent -- see above.
            SpanKind::Chip { .. } => match span.chip_tier() {
                Some(ChipTier::Structural) => {
                    egui::TextFormat { color: palette.quiet, ..plain.clone() }
                }
                _ => egui::TextFormat {
                    color: palette.warn,
                    background: palette.chip_bg,
                    ..plain.clone()
                },
            },
            SpanKind::Separator => {
                egui::TextFormat { background: palette.separator_bg, ..plain.clone() }
            }
            SpanKind::Danger => egui::TextFormat { color: palette.danger, ..plain.clone() },
            // Decoration, and additive only: never a box, never a fade,
            // never a substitution.
            //
            // Two channels, not one. Contrast alone -- the theme's strongest
            // text -- turned out to read as *slightly brighter text* rather
            // than as a mark, and bold is not available here: the bundled
            // monospace face has no bold cut and a synthetic one would change
            // the advance width the side-by-side fit is measured in. An
            // underline is drawn beneath the row by the text layout and adds
            // nothing to any glyph's advance, so the measurement and the
            // drawing still agree.
            //
            // It cannot be mistaken for a link: `quoted` is the only hue with
            // a link's colour and it is never underlined, and the command
            // word is never that hue.
            SpanKind::Command => egui::TextFormat {
                color: palette.command,
                underline: egui::Stroke::new(1.0, palette.command),
                ..plain.clone()
            },
            SpanKind::Quoted => egui::TextFormat { color: palette.quoted, ..plain.clone() },
            SpanKind::Variable { .. } | SpanKind::Plain => plain.clone(),
        };
        job.append(&span.display_text(), 0.0, format);

        // The value goes beside the reference and never in place of it: the
        // reference is what was approved, and a window that showed
        // `/home/user` where the command says `$HOME` would have quietly
        // replaced the text it is asking about. Italic, coloured and boxed,
        // so nothing about it reads as part of the command.
        if let Some((_, resolved)) = span.variable() {
            job.append(
                &variable_note(resolved),
                0.0,
                egui::TextFormat {
                    color: palette.quiet,
                    background: palette.value_bg,
                    italics: true,
                    ..plain.clone()
                },
            );
        }
    }
    job
}

/// What a resolved variable reads as beside its reference.
fn variable_note(resolved: Option<&str>) -> String {
    match resolved {
        Some(value) => format!(" \u{2192} {} ", defang(value)),
        None => " \u{2192} unset ".to_string(),
    }
}

/// What a weight does with a label too wide for the space it is in.
fn wrap_mode(weight: Weight) -> egui::TextWrapMode {
    if weight.wraps() { egui::TextWrapMode::Wrap } else { egui::TextWrapMode::Extend }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::*;
    use crate::protocol::{WireSpan, display_line, wire_spans};
    use crate::render::render_command;
    use crate::render::unicode::classify;
    use crate::swap::Principal;

    #[test]
    fn a_quotation_is_marked_beside_its_text_and_costs_no_row() {
        // The geometry of `quoted`, which is the whole of the mark: the rule
        // stands in the margin the block was given, the text is indented
        // exactly past it, and the block hands the cursor back where its
        // contents ended — so the attribution takes no row of the window the
        // command is read in.
        let ctx = egui::Context::default();
        theme::apply(&ctx, theme::Theme::Dark);
        let mut measured = None;
        let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
            // Something above it, so the block does not start at the top of
            // the world: a rule placed by adding to zero is a rule placed
            // correctly by accident.
            ui.label("the line above the quotation");
            let room = ui.available_rect_before_wrap();
            assert!(room.top() > 0.0, "the block starts at the top of the world");
            let inside = quoted(ui, |ui| {
                ui.label("a line of it");
                ui.label("and another");
                ui.min_rect()
            });
            measured = Some((room, inside, ui.min_rect()));
        });

        let (room, inside, parent) = measured.expect("the block drew");
        assert!(
            (inside.left() - (room.left() + QUOTE_RULE + QUOTE_GAP)).abs() < 0.01,
            "the text starts at {} and the margin is {} wide from {}",
            inside.left(),
            QUOTE_RULE + QUOTE_GAP,
            room.left()
        );
        assert!(
            (parent.bottom() - inside.bottom()).abs() < 0.01,
            "the block took {} of height for {} of text",
            parent.bottom() - room.top(),
            inside.height()
        );

        // And the rule itself: one vertical line, in hatch's quiet grey, in
        // the margin, as tall as everything it is marking.
        let mut lines = Vec::new();
        for clipped in &out.shapes {
            if let egui::epaint::Shape::LineSegment { points, stroke } = &clipped.shape {
                lines.push((*points, stroke.color, stroke.width));
            }
        }
        out.textures_delta.clear();
        assert_eq!(lines.len(), 1, "the quotation is marked by {} lines", lines.len());
        let ([from, to], colour, width) = lines[0];
        assert_eq!(colour, theme::DARK.quiet, "the rule is not in hatch's own voice");
        assert!((width - QUOTE_RULE).abs() < 0.01, "the rule is {width} wide");
        assert!(
            (from.x - (room.left() + QUOTE_RULE / 2.0)).abs() < 0.01,
            "the rule is at {} and the margin starts at {}",
            from.x,
            room.left()
        );
        assert!((from.y - inside.top()).abs() < 0.01, "the rule starts at {}", from.y);
        assert!((to.y - inside.bottom()).abs() < 0.01, "and ends at {}", to.y);
    }

    #[test]
    fn hatch_leads_the_agents_line_in_its_own_voice() {
        // The lead-in shares a laid-out run with the agent's sentence, which
        // is what makes it free of a row — and is also the one way it could
        // come to look like part of that sentence. So it is drawn in the
        // three marks this window keeps for itself, and the agent's own
        // sections come through the rebuild unchanged.
        let ctx = egui::Context::default();
        theme::apply(&ctx, theme::Theme::Dark);
        crate::prompt_ui::apply_font_size(&ctx, 16.0);
        let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
            let palette = palette(ui);
            let spans = classify("the agent's own sentence");
            let font = font(Weight::Heading, ui.style());
            let plain = line_job(&spans, &palette, &font);
            let led = led_by(ATTRIBUTION, &palette, ui.style(), plain.clone());

            assert!(led.text.starts_with(ATTRIBUTION), "the lead-in is not first: {:?}", led.text);
            assert_eq!(
                led.text,
                format!("{ATTRIBUTION} {}", plain.text),
                "a real space separates the two, and nothing else was added"
            );

            let lead = &led.sections[0].format;
            assert_eq!(
                lead.font_id,
                egui::TextStyle::Small.resolve(ui.style()),
                "the lead-in is not drawn small"
            );
            assert_eq!(lead.color, palette.quiet, "the lead-in is not in hatch's grey");
            assert!(lead.italics, "the lead-in is not italic");
            assert_ne!(lead.font_id, font, "the lead-in is set like the title it introduces");

            // Everything after it is the agent's line, formatted exactly as
            // it would have been drawn without any of this.
            assert_eq!(led.sections.len(), plain.sections.len() + 1);
            for (after, before) in led.sections[1..].iter().zip(&plain.sections) {
                assert_eq!(after.format, before.format, "a section changed format");
                assert_eq!(
                    after.byte_range.slice(&led.text),
                    before.byte_range.slice(&plain.text),
                    "a section changed text"
                );
            }
        });
        out.textures_delta.clear();
    }

    fn a_command(command: &str) -> Payload {
        Payload::command(
            &render_command(command, &BTreeMap::from([("HOME".to_string(), "/home/u".to_string())])),
            Vec::new(),
            PathBuf::from("/tmp"),
            false,
            false,
        )
    }

    // ---- the checked door --------------------------------------------------

    #[test]
    fn a_command_is_read_through_the_builder_and_kept_in_both_forms() {
        let shown = Shown::of(&a_command("rm -rf target")).expect("a real payload");

        let Shown::Command { annotated, raw, .. } = shown else { panic!("not a command") };
        assert_eq!(annotated.source(), "rm -rf target");
        assert_eq!(raw.source(), annotated.source(), "the panes disagree about the command");
    }

    #[test]
    fn a_payload_whose_spans_do_not_tile_its_source_is_refused() {
        let Payload::Command { display_line, raw, danger, cwd, root, interactive, .. } =
            a_command("rm -rf target")
        else {
            panic!("not a command")
        };
        // One span, ending one byte short of the source.
        let payload = Payload::Command {
            display_line,
            spans: vec![WireSpan { end: raw.len() - 1, kind: SpanKind::Plain, break_before: false }],
            raw,
            danger,
            cwd,
            root,
            interactive,
            caveat: None,
        };

        assert!(Shown::of(&payload).is_err(), "a window drew a rendering nobody checked");
    }

    #[test]
    fn a_payload_whose_one_line_form_disagrees_with_its_spans_is_refused() {
        let Payload::Command { spans, raw, danger, cwd, root, interactive, .. } =
            a_command("rm -rf target")
        else {
            panic!("not a command")
        };
        let payload = Payload::Command {
            display_line: "rm -rf /".to_string(),
            spans,
            raw,
            danger,
            cwd,
            root,
            interactive,
            caveat: None,
        };

        assert!(Shown::of(&payload).is_err(), "the title bar and the panes could disagree");
    }

    #[test]
    fn the_working_directory_is_defanged_before_it_is_drawn() {
        let payload = Payload::command(
            &render_command("ls", &BTreeMap::new()),
            Vec::new(),
            PathBuf::from("/tmp/a\u{202e}b"),
            false,
            false,
        );

        let Shown::Command { cwd, .. } = Shown::of(&payload).expect("a real payload") else {
            panic!("not a command")
        };
        assert_eq!(cwd, "/tmp/a[RLO]b", "a bidi override in the path reached the window");
    }

    #[test]
    fn a_danger_label_is_defanged_before_it_is_drawn() {
        let payload = Payload::command(
            &render_command("ls", &BTreeMap::new()),
            vec!["wipes\u{202e}disk".to_string()],
            PathBuf::from("/tmp"),
            false,
            false,
        );

        let Shown::Command { danger, .. } = Shown::of(&payload).expect("a real payload") else {
            panic!("not a command")
        };
        assert_eq!(danger, vec!["wipes[RLO]disk".to_string()]);
    }

    #[test]
    fn the_raw_pane_chips_everything_the_annotated_pane_chips() {
        // A homoglyph and a bidi override, in the pane whose whole job is to
        // be the unembellished one. "Unembellished" is not "unlabelled".
        let shown = Shown::of(&a_command("echo us\u{0430}r\u{202e}")).expect("a real payload");

        let Shown::Command { raw, .. } = shown else { panic!("not a command") };
        let chips: Vec<char> = raw.iter().filter_map(Span::chip_codepoint).collect();
        assert_eq!(chips, vec!['\u{0430}', '\u{202e}']);
    }

    #[test]
    fn a_swap_is_read_through_the_row_builder() {
        let payload = swap_payload("one\ntwo\n", "one\nTWO\n");

        let Shown::Swap { rows, path, .. } = Shown::of(&payload).expect("a real payload") else {
            panic!("not a swap")
        };
        assert_eq!(path, "/tmp/f");
        assert_eq!(changed_rows(&rows), 1, "the one changed line was not marked");

        let both = Shown::of(&swap_payload("one\ntwo\n", "ONE\nTWO\n"));
        let Shown::Swap { rows, .. } = both.expect("a real payload") else { panic!("not a swap") };
        assert_eq!(changed_rows(&rows), 2, "the count is not counting");
    }

    #[test]
    fn a_swap_path_is_defanged_before_it_is_drawn() {
        let mut payload = swap_payload("a\n", "b\n");
        if let Payload::Swap { path, .. } = &mut payload {
            *path = PathBuf::from("/tmp/f\u{202e}");
        }

        let Shown::Swap { path, .. } = Shown::of(&payload).expect("a real payload") else {
            panic!("not a swap")
        };
        assert_eq!(path, "/tmp/f[RLO]");
    }

    fn swap_payload(before: &str, after: &str) -> Payload {
        Payload::swap(
            PathBuf::from("/tmp/f"),
            SwapPlan {
                kind: PlanKind::Replace,
                landing_mode: 0o644,
                landing_owner: Principal { id: 1000, name: Some("u".to_string()) },
                landing_group: Principal { id: 1000, name: Some("u".to_string()) },
                hash_before: Some("00".to_string()),
                size_delta: 0,
            },
            &crate::render::diff::side_by_side(before, after),
        )
    }

    #[test]
    fn only_a_command_has_output_to_stream() {
        assert!(Shown::of(&a_command("ls")).expect("a real payload").streamable());
        assert!(!Shown::of(&swap_payload("a\n", "b\n")).expect("a real payload").streamable());
    }

    #[test]
    fn a_command_with_a_terminal_of_its_own_is_the_only_thing_that_reads_as_interactive() {
        let terminal = Payload::command(
            &render_command("vim /etc/hosts", &BTreeMap::new()),
            Vec::new(),
            PathBuf::from("/tmp"),
            false,
            true,
        );

        assert!(Shown::of(&terminal).expect("a real payload").interactive());
        assert!(!Shown::of(&a_command("ls")).expect("a real payload").interactive());
        assert!(!Shown::of(&swap_payload("a\n", "b\n")).expect("a real payload").interactive());
    }

    // ---- the countdown -----------------------------------------------------

    #[test]
    fn the_countdown_changes_colour_before_the_time_runs_out_rather_than_as_it_does() {
        assert_eq!(urgency(255), Urgency::Calm);
        assert_eq!(urgency(SOON + 1), Urgency::Calm);
        assert_eq!(urgency(SOON), Urgency::Soon);
        assert_eq!(urgency(IMMINENT + 1), Urgency::Soon);
        assert_eq!(urgency(IMMINENT), Urgency::Imminent);
        assert_eq!(urgency(0), Urgency::Imminent);
    }

    #[test]
    fn the_countdown_is_seconds_all_the_way_up() {
        assert_eq!(countdown_text(0), "no time left");
        assert_eq!(countdown_text(-5), "no time left");
        assert_eq!(countdown_text(8), "8 s left to decide");
        assert_eq!(countdown_text(59), "59 s left to decide");
        assert_eq!(countdown_text(60), "1 min left to decide");
        assert_eq!(countdown_text(135), "2 min 15 s left to decide");
        assert_eq!(countdown_text(3599), "59 min 59 s left to decide");
        assert_eq!(countdown_text(3600), "over an hour left to decide");
        // Three years, which is what an absurd deadline looks like. A window
        // that answered with a seven-digit minute count would be a window
        // reporting nonsense with a straight face.
        assert_eq!(countdown_text(100_000_000), "over an hour left to decide");
    }

    // ---- the header --------------------------------------------------------

    #[test]
    fn a_run_context_shares_the_title_row_only_while_it_leaves_the_title_a_row() {
        // The title is the agent's sentence and a path has no length limit,
        // so the two cannot always share. Rather than truncating either --
        // a truncated path is a security-relevant fact taken off the screen
        // -- the row splits back into the two it always was.
        assert!(aside_fits(100.0, 1000.0), "a short path did not fit a wide window");
        assert!(aside_fits(450.0, 1000.0), "a path at the share exactly did not fit");
        assert!(!aside_fits(451.0, 1000.0), "a path over the share still took the row");
        assert!(!aside_fits(100.0, 100.0), "a narrow window still shared its title row");
        assert!(!aside_fits(0.0, 1000.0), "a request with no run context reserved room for one");
    }

    #[test]
    fn a_run_context_is_measured_in_the_fonts_it_is_drawn_in() {
        // The row is placed by subtracting this from the right edge, so a
        // measurement that came out short would put the path off the side.
        at_font_size(16.0, |ui| {
            let short = RunContext { cwd: "/tmp".to_string(), root: false };
            let long = RunContext {
                cwd: "/home/user/src/service/deploy/staging/registry".to_string(),
                root: false,
            };
            assert!(run_context_width(ui, &short) > 0.0, "it measured as nothing at all");
            assert!(
                run_context_width(ui, &long) > run_context_width(ui, &short),
                "a longer path measured no wider"
            );
            // Root is a longer word than the ordinary one and is drawn in a
            // block wider still, and the block is measured the way it is
            // drawn -- both go through `root_mark_size`.
            let rooted = RunContext { cwd: short.cwd.clone(), root: true };
            assert!(run_context_width(ui, &rooted) > run_context_width(ui, &short));
            assert!(
                root_mark_size(ui).x > root_mark_galley(ui).size().x,
                "the mark measured no wider than the word inside it"
            );
        });
    }

    #[test]
    fn only_a_command_has_a_run_context_to_put_in_the_corner() {
        // A swap names an absolute path in its own header and runs as
        // whoever the plan says: a different claim, drawn in a different
        // place.
        let command = Shown::of(&a_command("ls")).expect("a command");
        let context = RunContext::of(&command).expect("a command runs somewhere");
        assert_eq!(context.cwd, "/tmp");
        assert!(!context.root);

        let swap = Shown::of(&swap_payload("a\n", "b\n")).expect("a swap");
        assert_eq!(RunContext::of(&swap), None);
    }

    #[test]
    fn the_header_says_root_in_words() {
        assert_eq!(principal(true), "ROOT");
        assert_eq!(principal(false), "you");
    }

    /// One frame of a run context, as the shapes it painted.
    fn a_drawn_run_context(root: bool) -> egui::FullOutput {
        let ctx = egui::Context::default();
        theme::apply(&ctx, theme::Theme::Dark);
        crate::prompt_ui::apply_font_size(&ctx, 16.0);
        let aside = RunContext { cwd: "/tmp".to_string(), root };
        let mut out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1280.0, 700.0),
                )),
                ..Default::default()
            },
            |ui| {
                ui.horizontal(|ui| draw_run_context(ui, &aside));
            },
        );
        out.textures_delta.clear();
        out
    }

    /// Every rectangle a frame filled, with the colour it filled it with.
    fn filled_rects(out: &egui::FullOutput) -> Vec<(egui::Rect, Color32)> {
        fn walk(shape: &egui::epaint::Shape, into: &mut Vec<(egui::Rect, Color32)>) {
            match shape {
                egui::epaint::Shape::Rect(rect) if rect.fill.a() > 0 => {
                    into.push((rect.rect, rect.fill));
                }
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        walk(shape, into);
                    }
                }
                _ => {}
            }
        }
        let mut into = Vec::new();
        for clipped in &out.shapes {
            walk(&clipped.shape, &mut into);
        }
        into
    }

    /// Every galley a frame drew, with where it put it and the ink it asked
    /// for.
    fn drawn_galleys(out: &egui::FullOutput) -> Vec<(String, egui::Rect, Color32)> {
        fn walk(shape: &egui::epaint::Shape, into: &mut Vec<(String, egui::Rect, Color32)>) {
            match shape {
                egui::epaint::Shape::Text(text) => into.push((
                    text.galley.text().to_string(),
                    egui::Rect::from_min_size(text.pos, text.galley.size()),
                    text.fallback_color,
                )),
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        walk(shape, into);
                    }
                }
                _ => {}
            }
        }
        let mut into = Vec::new();
        for clipped in &out.shapes {
            walk(&clipped.shape, &mut into);
        }
        into
    }

    #[test]
    fn root_is_a_filled_block_with_the_word_knocked_out_of_it() {
        // The old treatment was the same word tinted red, and red is a
        // channel some readers do not have: to them it was the word `ROOT` in
        // ordinary text, in the corner of the header, which is the least
        // looked-at part of the window. So the word is now inside a shape,
        // and the shape is what this asserts -- a solid block where the rest
        // of the header has none, with the word reversed out of it. Both
        // colours come from the palette, and the ratios between them are
        // `crate::prompt_ui::theme`'s business.
        let out = a_drawn_run_context(true);
        let (fill, ink) = theme::DARK.root_mark();

        let block = filled_rects(&out)
            .into_iter()
            .find(|(_, colour)| *colour == fill)
            .map(|(rect, _)| rect)
            .expect("nothing on screen is a block at all");
        let word = drawn_galleys(&out)
            .into_iter()
            .find(|(text, ..)| text == principal(true))
            .expect("the word is not on screen");

        assert_eq!(word.2, ink, "the word is drawn in a colour that is not the mark's ink");
        assert!(
            block.contains_rect(word.1),
            "the word at {:?} is not inside the block at {block:?}",
            word.1
        );
        // And the block is padding around the word rather than a stripe
        // across the header: it is the width of the word plus its own air.
        assert!(
            block.width() < word.1.width() + 4.0 * ROOT_MARK_PAD.x,
            "the block is {} wide around a {} word",
            block.width(),
            word.1.width()
        );
    }

    #[test]
    fn an_unprivileged_command_gets_no_mark_to_learn_to_ignore() {
        // A mark on every window is a mark nobody sees on the one that
        // matters -- the same argument that keeps a structural chip quiet and
        // leaves the scan line off an ordinary command.
        let out = a_drawn_run_context(false);
        let (fill, _) = theme::DARK.root_mark();

        assert!(
            !filled_rects(&out).iter().any(|(_, colour)| *colour == fill),
            "a command that runs as the reader was marked as root"
        );
        assert!(
            drawn_galleys(&out).iter().any(|(text, ..)| text == principal(false)),
            "it did not say who it runs as at all"
        );
    }

    #[test]
    fn an_ordinary_command_gets_no_scan_line() {
        assert_eq!(scan_summary(&scan("rm -rf target")), None);
    }

    #[test]
    fn the_scan_line_names_each_thing_it_found() {
        assert_eq!(
            scan_summary(&scan("us\u{0430}r\u{202e}")),
            Some("2 non-ASCII, 1 invisible".to_string())
        );
        assert_eq!(
            scan_summary(&scan("e\u{0301}")),
            Some("1 non-ASCII, not in NFC".to_string())
        );
    }

    // ---- the swap stand-in -------------------------------------------------

    #[test]
    fn the_plan_says_the_mode_in_four_octal_digits() {
        let plan = SwapPlan {
            kind: PlanKind::Replace,
            landing_mode: 0o4755,
            landing_owner: Principal { id: 0, name: Some("root".to_string()) },
            landing_group: Principal { id: 0, name: None },
            hash_before: None,
            size_delta: -3,
        };

        let facts = plan_facts(&plan);
        assert_eq!(facts[1], ("Mode", "4755".to_string()), "setuid was rounded away");
        assert_eq!(facts[2].1, "root:0", "a gid with no name lost its number");
        assert_eq!(facts[3].1, "3 bytes smaller");
    }

    #[test]
    fn a_single_byte_is_a_byte_and_not_bytes() {
        // The panel is read once, carefully, before somebody approves a write
        // to a file. A line that reads as a formatting slip is an invitation
        // to skim the four beside it.
        assert_eq!(size_delta(1), "1 byte larger");
        assert_eq!(size_delta(-1), "1 byte smaller");
        assert_eq!(size_delta(2), "2 bytes larger");
        assert_eq!(size_delta(-2), "2 bytes smaller");
        assert_eq!(size_delta(0), "the same number of bytes");
    }

    #[test]
    fn a_create_and_a_replace_do_not_read_the_same() {
        let plan = |kind| SwapPlan {
            kind,
            landing_mode: 0o644,
            landing_owner: Principal { id: 1, name: None },
            landing_group: Principal { id: 1, name: None },
            hash_before: None,
            size_delta: 7,
        };

        assert_ne!(plan_facts(&plan(PlanKind::Create))[0], plan_facts(&plan(PlanKind::Replace))[0]);
        assert_eq!(plan_facts(&plan(PlanKind::Create))[3].1, "7 bytes larger");
    }

    #[test]
    fn a_changed_row_is_drawn_from_both_sides_and_an_unchanged_one_once() {
        let rows = crate::render::diff::side_by_side("keep\nold\n", "keep\nnew\n");

        let lines = diff_lines(&rows);
        let marks: Vec<&str> = lines.iter().map(|line| line.marker).collect();
        assert_eq!(marks, vec![" ", "-", "+"], "context was doubled or a side was dropped");
        assert!(
            lines.iter().all(|line| !line.terminator),
            "every line was tagged with its ending, which is where a reader stops seeing chips"
        );
    }

    #[test]
    fn a_line_ending_that_changed_is_the_one_that_is_drawn() {
        let crlf = crate::render::diff::side_by_side("a\n", "a\r\n");
        assert!(
            diff_lines(&crlf).iter().all(|line| line.terminator),
            "a change that is only a change of line ending drew two identical lines"
        );

        let dropped = crate::render::diff::side_by_side("a\nb\n", "a\nb");
        assert!(
            diff_lines(&dropped).iter().any(|line| line.terminator),
            "a last line that lost its newline looks unchanged"
        );
    }

    #[test]
    fn an_insertion_has_no_left_side_to_draw_and_is_still_drawn() {
        let rows = crate::render::diff::side_by_side("", "added\n");

        let lines = diff_lines(&rows);
        assert!(!lines.is_empty(), "a pure insertion drew nothing at all");
        assert!(lines.iter().all(|line| line.marker == "+"));
    }

    #[test]
    fn a_swap_that_changes_nothing_still_says_so_in_words() {
        assert_eq!(size_delta(0), "the same number of bytes");
    }

    // ---- which of the two diff views ---------------------------------------

    #[test]
    fn the_widest_line_is_measured_as_it_is_drawn_and_not_as_it_is_stored() {
        // A chip is one character in the file and five on screen, and it is
        // the five that decide whether a column can hold the line.
        let rows = crate::render::diff::side_by_side("ab\n", "a\u{202e}b\n");
        assert_eq!(longest_drawn_line(&rows), 7, "[RLO] was counted as one character");

        // The terminator counts only where it is drawn, and it is drawn in
        // the structural tier: these two rows differ only in their line
        // ending, so both sides show `↵` or `⇤↵`, one character each.
        let endings = crate::render::diff::side_by_side("ab\n", "ab\r\n");
        assert_eq!(longest_drawn_line(&endings), 2 + "\u{21E4}\u{21B5}".chars().count());
    }

    #[test]
    fn an_empty_diff_has_no_widest_line_rather_than_a_wrong_one() {
        assert_eq!(longest_drawn_line(&[]), 0);
        assert_eq!(longest_drawn_line(&crate::render::diff::side_by_side("\n", "\n")), 0);
    }

    #[test]
    fn a_column_is_what_is_left_after_the_furniture_and_the_gap() {
        // A diff column: 2 + 2 gutter, 2 gap, and the rest halved.
        assert_eq!(column_chars(86, GUTTER_CHARS), 40);
        assert_eq!(
            column_chars(87, GUTTER_CHARS),
            40,
            "an odd character cannot be split between columns"
        );
        // A command pane has no gutter, so the same width holds more.
        assert_eq!(column_chars(86, 0), 42);
        assert_eq!(column_chars(6, 0), 2, "the gap is still spent");
        // Narrower than its own furniture is no column at all, not a panic
        // and not a negative width.
        assert_eq!(column_chars(6, GUTTER_CHARS), 0);
        assert_eq!(column_chars(0, GUTTER_CHARS), 0);
        assert_eq!(column_chars(0, 0), 0);
    }

    #[test]
    fn two_columns_only_when_every_line_fits_one() {
        assert_eq!(diff_view(40, 40), DiffView::SideBySide, "a line that exactly fits does");
        assert_eq!(diff_view(41, 40), DiffView::Unified, "one character over sends it back");
        assert_eq!(diff_view(0, 40), DiffView::SideBySide, "a file of empty lines fits");
        // A pane with no room for a column falls back however short the
        // lines are, including when there are none.
        assert_eq!(diff_view(0, 0), DiffView::Unified);
    }

    #[test]
    fn the_caption_says_which_view_this_is_and_the_fallback_says_why() {
        let rows = crate::render::diff::side_by_side("keep\nold\n", "keep\nnew\n");

        let side = diff_caption(DiffView::SideBySide, &rows, 4, 40);
        assert!(side.starts_with("1 of 2 lines change."), "got: {side}");
        assert!(side.contains("Side by side"), "the reader is not told which view this is");
        assert!(side.contains("not a blank line"), "the tinted cell is unexplained");

        let unified = diff_caption(DiffView::Unified, &rows, 214, 40);
        assert!(unified.contains("214"), "the fallback does not say what was too long");
        assert!(unified.contains("40"), "nor what it was too long for");
        assert!(!unified.contains("not built"), "the caption still promises a missing view");
    }

    #[test]
    fn a_side_with_no_line_is_a_gap_and_an_empty_line_is_a_line() {
        // The distinction the two-column view turns on. A gap is a row this
        // column's file has nothing on; an empty line is a line, and drawing
        // the two the same would put a byte in a column that is not in the
        // file -- or hide one that is.
        let inserted = crate::render::diff::side_by_side("", "added\n");
        let [left, right] = cells(&inserted[0]);
        assert!(matches!(left, Cell::Gap), "an insertion drew a blank line into the old file");
        assert!(matches!(right, Cell::Line { marker: "+", .. }));

        let blank = crate::render::diff::side_by_side("a\n\n", "a\n\n");
        let [left, right] = cells(&blank[1]);
        let Cell::Line { side, .. } = left else { panic!("an empty line was drawn as a gap") };
        assert!(side.content_spans().is_empty(), "this is the empty line, not a filled one");
        assert!(matches!(right, Cell::Line { .. }));
    }

    #[test]
    fn only_a_changed_row_marks_its_cells() {
        let rows = crate::render::diff::side_by_side("keep\nold\n", "keep\nnew\n");

        let [left, right] = cells(&rows[0]);
        assert!(matches!(left, Cell::Line { marker: " ", changed: false, .. }));
        assert!(matches!(right, Cell::Line { marker: " ", changed: false, .. }));

        let [left, right] = cells(&rows[1]);
        assert!(matches!(left, Cell::Line { marker: "-", changed: true, .. }));
        assert!(matches!(right, Cell::Line { marker: "+", changed: true, .. }));
    }

    #[test]
    fn a_row_that_changed_only_its_line_ending_shows_the_ending_in_both_columns() {
        // The case two columns would otherwise draw pixel for pixel the same
        // over a change to every line in the file.
        let rows = crate::render::diff::side_by_side("a\n", "a\r\n");
        let [left, right] = cells(&rows[0]);

        for cell in [left, right] {
            let Cell::Line { terminator, .. } = cell else { panic!("both sides are present") };
            assert!(terminator, "a column hid the only thing that changed");
        }
    }

    #[test]
    fn the_closing_countdown_reads_as_a_quantity_of_seconds() {
        assert_eq!(closing_text(10), "closing in 10 s");
        assert_eq!(closing_text(1), "closing in 1 s", "a window does not close in 1 seconds");
        assert_eq!(closing_text(0), "closing now");
        // Deliberately not the approval countdown's words: the two numbers
        // mean opposite things and appear minutes apart on the same window.
        assert!(!closing_text(10).contains("decide"));
    }

    #[test]
    fn how_it_ended_is_said_plainly_and_only_a_clean_exit_is_quiet() {
        assert_eq!(outcome_text(&Outcome::Exit { code: 0 }), ("Finished — exit 0".into(), true));
        assert_eq!(outcome_text(&Outcome::Exit { code: 3 }), ("Finished — exit 3".into(), false));
        assert_eq!(
            outcome_text(&Outcome::Signal { signal: 9 }),
            ("Ended by signal 9".into(), false)
        );
        // Every nonzero ending is called out, including the one the reader
        // caused themselves: a window that stayed quiet about a failure would
        // be the exit code reaching the agent and nobody else.
        for code in [1, 2, 127, -1] {
            assert!(!outcome_text(&Outcome::Exit { code }).1, "exit {code} was drawn as fine");
        }
    }

    #[test]
    fn text_that_came_from_outside_is_defanged_before_it_is_drawn() {
        // The one outcome carrying a message, drawn beside a number the
        // reader is meant to trust. A bidi override in it would reorder the
        // line it sits on.
        let (text, clean) = outcome_text(&Outcome::ElevationFailed {
            message: "\u{202E}denied".to_string(),
        });
        assert!(!text.contains('\u{202E}'), "an override reached the screen: {text}");
        assert!(text.contains("[RLO]"), "{text}");
        assert!(!clean);
    }

    #[test]
    fn every_glyph_the_panes_draw_is_one_monospace_advance() {
        // What the whole character-count fit rests on. A drawn line is
        // measured in characters and laid out in pixels, and the two agree
        // only while every character is one advance of the pane's own font.
        // ASCII is by definition; these are not, and one of them -- the
        // control picture `␍` an earlier draft used for a carriage return --
        // is in none of the fonts the window ships and measured zero, drawing
        // as nothing at all. This test is what caught that, and what stops the
        // next such glyph reaching a reader.
        let ctx = egui::Context::default();
        let mut out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(800.0, 600.0),
                )),
                ..Default::default()
            },
            |ui| {
                let font = font(Weight::Mono, ui.style());
                let width =
                    |c: char| ui.ctx().fonts_mut(|fonts| fonts.glyph_width(&font, c));
                let ascii = width('0');
                assert!(ascii > 0.0, "the monospace font draws nothing at all");
                // The three compact chip glyphs, and the arrow a variable's
                // note is drawn with. The tab's `⇥` and the note's `→` are
                // deliberately different glyphs, and both are checked: the
                // pair used to be one arrow doing two jobs.
                for c in ['\u{21E5}', '\u{21B5}', '\u{21E4}'] {
                    assert_eq!(
                        width(c),
                        ascii,
                        "U+{:04X} is not one advance of the pane's font",
                        c as u32
                    );
                }
                assert_eq!(width('\u{2192}'), ascii, "the note's arrow is measured as one too");
            },
        );
        // epaint refuses to be dropped holding texture deltas nobody applied.
        out.textures_delta.clear();
    }

    /// Run one frame at `points` and hand back what a caller measured.
    fn at_font_size<T>(points: f32, mut measure: impl FnMut(&Ui) -> T) -> T {
        let ctx = egui::Context::default();
        crate::prompt_ui::apply_font_size(&ctx, points);
        // And the window's own scroll bars, which are a column of the style
        // rather than egui's floating default: `text_width` subtracts that
        // column, so a measurement taken against egui's style would be a
        // measurement of a window nobody is shown. See `theme::scroll_bars`.
        theme::apply(&ctx, theme::Theme::Dark);
        let mut measured = None;
        let mut out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1280.0, 700.0),
                )),
                ..Default::default()
            },
            |ui| measured = Some(measure(ui)),
        );
        out.textures_delta.clear();
        measured.expect("the frame ran")
    }

    #[test]
    fn a_column_is_measured_in_the_font_the_window_is_actually_drawing_in() {
        // The fit rule is the reason the font size cannot be a number the
        // drawing code knows and the measuring code does not. A constant
        // advance pinned to one size would go on claiming that two columns
        // fit after the reader chose a larger one, and the reader would get
        // truncation or overflow instead of the honest fallback.
        let small = at_font_size(12.0, |ui| (advance(ui), pane_chars(ui, 2)));
        let large = at_font_size(24.0, |ui| (advance(ui), pane_chars(ui, 2)));

        assert!(large.0 > small.0 * 1.9, "a doubled font did not widen a character");
        assert!(
            large.1 * 2 <= small.1 + 4,
            "a doubled font left a column holding about as much: {} against {}",
            large.1,
            small.1
        );
        assert!(
            column_chars(large.1, 0) < column_chars(small.1, 0),
            "the fit rule did not follow the font"
        );
    }

    #[test]
    fn a_framed_scrolling_box_costs_the_width_of_its_own_furniture() {
        // The view has to be chosen before the box that would report its own
        // width exists, so the furniture is subtracted rather than measured.
        // What has to be true of that subtraction: it takes something, it
        // takes the same amount per box, and what it takes is a border and a
        // scroll bar rather than a rounding error or a quarter of the window.
        at_font_size(16.0, |ui| {
            let (none, one, two) = (ui.available_width(), text_width(ui, 1), text_width(ui, 2));
            assert!(one < none, "a framed, scrolling box cost nothing at all");
            assert!(two < one, "the second box cost nothing");
            let furniture = none - one;
            assert!(
                (furniture - (one - two)).abs() < 0.01,
                "two boxes cost {} and one costs {furniture}",
                none - two
            );
            assert!(furniture > 8.0, "the furniture is {furniture}, which is not a border");
            assert!(furniture < none / 4.0, "the furniture is {furniture} of {none}");
        });
    }

    #[test]
    fn a_row_is_a_line_of_text_and_the_gap_to_the_next_one() {
        // The scroll link turns a line index into an offset by multiplying by
        // this, so it has to be the whole of a row: a bare text height would
        // put the follower steadily above the line it is meant to be on.
        at_font_size(16.0, |ui| {
            let text = ui.text_style_height(&egui::TextStyle::Monospace);
            let row = row_height(ui);
            assert!(row > text, "the gap between two lines was dropped: {row} against {text}");
            assert!(row < 2.0 * text, "the gap is a gap, not a second line: {row}");
        });
    }

    #[test]
    fn the_stacked_raw_pane_is_a_strip_and_not_a_share_of_the_window() {
        // The bug: stacking is chosen because the command is long, and a
        // 40% share handed the least reading room to the longest commands.
        let row = 22.0;
        let strip = RAW_STRIP_ROWS * row;
        assert_eq!(raw_ceiling(600.0, row, 0.0), strip, "a tall window still gets a strip");
        assert!(
            raw_ceiling(600.0, row, 0.0) < 600.0 * RAW_SHARE,
            "the strip is not an improvement on the share it replaced"
        );
        // And the share is still the backstop, for a window too short for
        // even six rows to be a strip rather than the whole of it.
        assert_eq!(raw_ceiling(100.0, row, 0.0), 100.0 * RAW_SHARE);
        assert!(raw_ceiling(100.0, row, 0.0) < 50.0, "the pane a reader falls back to took half");
        assert_eq!(raw_ceiling(0.0, row, 0.0), 0.0, "no window is no ceiling, not a panic");
        assert!(raw_ceiling(600.0, row, 0.0) > 0.0, "the raw text is not on screen at all");

        // A strip that is going to grow a horizontal bar gets the bar's room
        // on top of its six rows rather than out of them: six rows of command
        // is what the constant means, and five and a sliver is not six.
        assert_eq!(raw_ceiling(600.0, row, 14.0), strip + 14.0, "the bar came out of the rows");
        assert!(
            raw_ceiling(600.0, row, 14.0) < 600.0 * RAW_SHARE,
            "the bar pushed the strip past the share that is still its ceiling"
        );
        assert_eq!(raw_ceiling(100.0, row, 14.0), 100.0 * RAW_SHARE, "the share still caps it");
    }

    #[test]
    fn a_font_the_window_cannot_measure_still_leaves_a_column_of_some_width() {
        // `advance` floors at one point, so a font that reported nothing
        // gives a very narrow column rather than an infinitely wide one --
        // and an infinitely wide column is the value that would claim every
        // line fits.
        let chars = at_font_size(12.0, |ui| pane_chars(ui, 2));
        assert!(chars > 0, "a pane held no characters at all");
        assert!(chars < 100_000, "a pane held an impossible number of them");
    }

    // ---- which arrangement the command panes get ---------------------------

    #[test]
    fn the_widest_command_line_is_measured_as_it_is_drawn() {
        // The lines are the rendering's own, so a segment break shortens the
        // longest line rather than being ignored.
        assert_eq!(widest_line(&classify("ls -l")), 5);
        assert_eq!(
            widest_line(&render_command("ls -l; rm -rf target", &BTreeMap::new())),
            " rm -rf target".chars().count(),
            "the two segments are two lines and the longer one wins"
        );
        // A chip is one character in the command and one or five on screen.
        assert_eq!(widest_line(&classify("a\u{202e}b")), 7, "[RLO] counted as one character");
        // `a` and the `↵` that ends its line; `b` alone on the next.
        assert_eq!(widest_line(&classify("a\nb")), 2, "the glyph ends the line it ends");
        assert_eq!(widest_line(&classify("")), 0, "no lines, not one empty one");
    }

    #[test]
    fn a_variables_note_is_part_of_the_line_it_has_to_fit_on() {
        // The note is drawn inside the line, after the reference, so a fit
        // that ignored it would put the annotated pane's longest line off the
        // side of its column.
        let env = BTreeMap::from([("HOME".to_string(), "/home/u".to_string())]);
        let spans = render_command("echo $HOME", &env);

        assert_eq!(widest_line(&spans), "echo $HOME \u{2192} /home/u ".chars().count());
        assert!(widest_line(&spans) > widest_line(&classify("echo $HOME")), "the note is free");
    }

    #[test]
    fn the_two_panes_share_the_rule_the_diff_uses() {
        // One question -- can a column this wide hold the widest thing that
        // would go in it? -- and one answer, so the two views cannot drift
        // apart about what "fits" means.
        assert!(fits_two_columns(40, 40), "a line that exactly fits does");
        assert!(!fits_two_columns(41, 40), "one character over does not");
        assert!(fits_two_columns(0, 40), "nothing to draw fits");
        assert!(!fits_two_columns(0, 0), "a column with no room falls back however short");

        assert_eq!(command_view(40, 40), CommandView::SideBySide);
        assert_eq!(command_view(41, 40), CommandView::Stacked);
        assert_eq!(diff_view(40, 40), DiffView::SideBySide);
        assert_eq!(diff_view(41, 40), DiffView::Unified);
    }

    #[test]
    fn one_caption_names_both_panes_and_keeps_what_each_of_them_promises() {
        // The panes carry no labels of their own any more -- two labels are
        // two rows when the panes are stacked -- so the claim that made the
        // raw pane worth having has to survive here, in both arrangements.
        for (view, first, second) in [
            (CommandView::SideBySide, "Left", "Right"),
            (CommandView::Stacked, "Above", "Below"),
        ] {
            let caption = command_caption(view, 214, 40);
            assert!(caption.contains(first), "the first pane is not named: {caption}");
            assert!(caption.contains(second), "the second pane is not named: {caption}");
            assert!(
                caption.contains("no colour"),
                "the raw pane's promise is gone: {caption}"
            );
            assert!(
                caption.contains("hatch's notes, not the command"),
                "the annotated pane's warning is gone: {caption}"
            );
        }

        // And the fallback still says what was too long and what to do.
        let stacked = command_caption(CommandView::Stacked, 214, 40);
        assert!(stacked.contains("214"), "the fallback does not say what was too long");
        assert!(stacked.contains("40"), "nor what it was too long for");
        assert!(stacked.contains("widen"), "nor what the reader can do about it");
    }

    // ---- keeping the two stacked panes together ----------------------------

    /// A pane's lines as `(source offset, row)` pairs, for readable
    /// expectations.
    fn rows_of(pane: &PaneRows) -> Vec<(usize, usize)> {
        pane.lines.iter().map(|line| (line.at, line.row)).collect()
    }

    #[test]
    fn a_lines_place_in_the_command_is_what_the_two_panes_share() {
        // The annotated pane opens a line at every separator as well as at
        // every newline, so the two panes have different line counts over the
        // same string -- which is exactly why a line number is not a shared
        // coordinate and a byte offset is.
        let source = "ls; rm\ncat";
        let raw = pane_lines(&classify(source), None);
        let annotated = pane_lines(&render_command(source, &BTreeMap::new()), None);

        assert_eq!(rows_of(&raw), vec![(0, 0), (7, 1)], "the raw pane breaks only at the newline");
        assert_eq!(
            rows_of(&annotated),
            vec![(0, 0), (3, 1), (7, 2)],
            "the annotated pane breaks at the `;` too"
        );
        assert_eq!((raw.rows, annotated.rows), (2, 3));
    }

    #[test]
    fn a_wrapped_line_takes_the_rows_it_takes() {
        // The link's other half. A pane that assumed one row per line would
        // put the follower steadily too high down a pane with wrapping above
        // the target, which is the silent kind of drift.
        let spans = classify("aaaaaaaaaa\nbb\ncc");

        assert_eq!(
            rows_of(&pane_lines(&spans, None)),
            vec![(0, 0), (11, 1), (14, 2)],
            "a pane that does not reflow gives every line one row"
        );
        // Eleven characters -- ten and the `↵` -- across a four-character
        // pane is three rows, so the lines below start three rows down.
        let wrapped = pane_lines(&spans, Some(4));
        assert_eq!(rows_of(&wrapped), vec![(0, 0), (11, 3), (14, 4)]);
        assert_eq!(wrapped.rows, 5);

        // A width of nothing is not a division by zero and not an infinite
        // number of rows: it is a pane that cannot be measured, and one row
        // per line is the answer that never scrolls past anything.
        assert_eq!(rows_of(&pane_lines(&spans, Some(0))), vec![(0, 0), (11, 1), (14, 2)]);
        // An empty rendering has no lines and no rows, not one blank row.
        assert_eq!(pane_lines(&classify(""), None), PaneRows { lines: Vec::new(), rows: 0 });
    }

    /// The two panes of `ls; rm\ncat`, which is the shape the link is for:
    /// two lines against three, over the same string.
    fn linked_panes() -> (PaneRows, PaneRows) {
        let source = "ls; rm\ncat";
        (
            pane_lines(&classify(source), None),
            pane_lines(&render_command(source, &BTreeMap::new()), None),
        )
    }

    #[test]
    fn a_line_in_one_pane_finds_the_line_it_is_on_in_the_other() {
        let (raw, annotated) = linked_panes();

        // Down: the annotated pane's extra line is on the raw pane's first.
        assert_eq!(linked_line(&annotated.lines, &raw.lines, 0), 0);
        assert_eq!(linked_line(&annotated.lines, &raw.lines, 1), 0, "`; rm` is still line one");
        assert_eq!(linked_line(&annotated.lines, &raw.lines, 2), 1);
        // Up: the raw pane's line two is the annotated pane's line three.
        assert_eq!(linked_line(&raw.lines, &annotated.lines, 0), 0);
        assert_eq!(linked_line(&raw.lines, &annotated.lines, 1), 2);
        // Never past the place asked about, and never out of bounds.
        assert_eq!(linked_line(&raw.lines, &annotated.lines, 9), 0, "a line that is not there");
        assert_eq!(linked_line(&[], &annotated.lines, 0), 0);
        assert_eq!(linked_line(&raw.lines, &[], 1), 0);
    }

    #[test]
    fn a_panes_offset_reads_as_the_line_it_is_showing() {
        let lines = pane_lines(&classify("aaaaaaaaaa\nbb\ncc"), Some(4)).lines;

        assert_eq!(line_at(0.0, 10.0, &lines), 0);
        assert_eq!(line_at(9.9, 10.0, &lines), 0, "part of a row is still that row");
        assert_eq!(line_at(20.0, 10.0, &lines), 0, "and so is a wrapped row of the same line");
        assert_eq!(line_at(30.0, 10.0, &lines), 1, "the line whose first row this is");
        assert_eq!(line_at(1e9, 10.0, &lines), 2, "past the end is the last line, not a panic");
        assert_eq!(line_at(-5.0, 10.0, &lines), 0, "and above the top is the first");
        assert_eq!(line_at(50.0, 10.0, &[]), 0, "a pane with no lines is on line zero");
    }

    #[test]
    fn a_pane_that_has_never_been_drawn_still_gets_a_guess_at_its_reach() {
        // All this is now: the one frame before a pane has reported how far
        // it really reaches. It was once the whole answer, and the bug is
        // what that cost -- see `max_offset` and `PaneAt`.
        assert_eq!(max_offset(10, 10.0, 40.0), 60.0);
        assert_eq!(max_offset(3, 10.0, 40.0), 0.0, "a pane that fits does not scroll");
        assert_eq!(max_offset(0, 10.0, 40.0), 0.0);
    }

    #[test]
    fn a_pane_that_ran_out_of_command_is_told_apart_from_one_a_reader_moved() {
        // The distinction the whole fix rests on. Both panes end up at their
        // maximum; only one of them was asked for something else.
        let end = PaneAt { offset: 100.0, max: 100.0 };

        assert!(end.clamped(140.0), "a pane asked for more than it has was not read as clamped");
        assert!(!end.clamped(100.0), "a pane given exactly its maximum had nothing to clamp");
        assert!(
            !end.clamped(20.0),
            "a reader who scrolled a pane to its end was read as the pane running out"
        );
        // The epsilon is the same everywhere: a request larger than the
        // maximum by less than one is the rounding a scroll area does to
        // itself, not a request it cannot honour.
        assert!(!end.clamped(100.0 + SCROLL_EPSILON));
        assert!(end.clamped(100.0 + SCROLL_EPSILON * 1.01));
        // And a pane that is nowhere near its maximum did not get there by
        // being clamped to it, whatever it was asked for.
        assert!(!PaneAt { offset: 40.0, max: 100.0 }.clamped(140.0));
    }

    #[test]
    fn the_pane_the_reader_is_scrolling_is_handed_back_its_own_offset() {
        // The driver must never be pulled away from where the reader put it,
        // which is also what stops the two panes fighting: it is asked for
        // exactly what it reported, so it never disagrees.
        let (raw, annotated) = linked_panes();
        let link = ScrollLink { driver: Pane::Raw, offset: 13.0 };

        assert_eq!(requested_offset(link, Pane::Raw, &raw, &raw, 10.0, 100.0), 13.0);
        // Raw line one is annotated line two, and there is room for it.
        assert_eq!(requested_offset(link, Pane::Annotated, &annotated, &raw, 10.0, 20.0), 20.0);
        // A pane with nowhere to scroll stays at its top rather than being
        // asked for an offset it would draw as blank space.
        assert_eq!(requested_offset(link, Pane::Annotated, &annotated, &raw, 10.0, 0.0), 0.0);
    }

    /// A pane at `offset` with room to spare below it, so that nothing it
    /// hands back can be explained by it running out of command.
    fn freely(offset: f32) -> PaneAt {
        PaneAt { offset, max: offset + 1_000.0 }
    }

    #[test]
    fn whichever_pane_moved_is_the_one_the_other_follows() {
        let link = ScrollLink { driver: Pane::Raw, offset: 10.0 };

        // Nobody moved: both handed back what they were given.
        assert_eq!(drove(link, freely(10.0), 10.0, freely(20.0), 20.0), link);
        // The follower moved, so it takes over.
        assert_eq!(
            drove(link, freely(10.0), 10.0, freely(55.0), 20.0),
            ScrollLink { driver: Pane::Annotated, offset: 55.0 }
        );
        // The driver moved, and stays the driver at its new place.
        assert_eq!(
            drove(link, freely(44.0), 10.0, freely(20.0), 20.0),
            ScrollLink { driver: Pane::Raw, offset: 44.0 }
        );
        // Rounding inside a scroll area is not a reader, and half a logical
        // pixel exactly is the line: smaller than anything a hand produces
        // and larger than anything a scroll area rounds by.
        assert_eq!(drove(link, freely(10.2), 10.0, freely(20.0), 20.1), link);
        assert_eq!(
            drove(
                link,
                freely(10.0 + SCROLL_EPSILON),
                10.0,
                freely(20.0 + SCROLL_EPSILON),
                20.0
            ),
            link,
            "a pane that moved by exactly the epsilon was read as a reader"
        );
        assert_eq!(
            drove(link, freely(10.0), 10.0, freely(20.0 + SCROLL_EPSILON * 1.01), 20.0),
            ScrollLink { driver: Pane::Annotated, offset: 20.0 + SCROLL_EPSILON * 1.01 },
            "a pane that moved by more than the epsilon was read as rounding"
        );
        assert_eq!(
            drove(link, freely(10.0 + SCROLL_EPSILON * 1.01), 10.0, freely(20.0), 20.0),
            ScrollLink { driver: Pane::Raw, offset: 10.0 + SCROLL_EPSILON * 1.01 }
        );
    }

    #[test]
    fn a_follower_with_nothing_further_to_show_does_not_take_the_reader_s_pane() {
        // The bug, in the three numbers it comes down to. The reader is
        // holding the raw pane at 40; the annotated pane is asked for 90,
        // has 70, and says 70. Reading that as a reader scrolling handed the
        // driver's role to a pane nobody touched.
        let link = ScrollLink { driver: Pane::Raw, offset: 40.0 };
        let ran_out = PaneAt { offset: 70.0, max: 70.0 };

        assert_eq!(drove(link, freely(40.0), 40.0, ran_out, 90.0), link);
        // What must still work: the reader takes a pane over by scrolling it,
        // including by scrolling it to its very end. The pane is in the same
        // place as above and the only difference is what it was asked for.
        assert_eq!(
            drove(link, freely(40.0), 40.0, ran_out, 20.0),
            ScrollLink { driver: Pane::Annotated, offset: 70.0 },
            "a reader who scrolled the follower to its end could not take it over"
        );
        // And the driver's own clamp is taken at face value, because it
        // cannot cost it a role it already has: a window made taller leaves
        // the link carrying an offset the pane no longer has, and this is
        // where it is corrected.
        let stale = ScrollLink { driver: Pane::Annotated, offset: 90.0 };
        assert_eq!(
            drove(stale, freely(40.0), 40.0, ran_out, 90.0),
            ScrollLink { driver: Pane::Annotated, offset: 70.0 }
        );
    }

    #[test]
    fn a_linked_pane_settles_rather_than_oscillating() {
        // The failure this shape exists to avoid: an offset fed back into the
        // pane that produced it, with the two dragging each other a little
        // further apart every frame. Two frames of the real arithmetic, with
        // the reader scrolling once and then stopping.
        let (raw, annotated) = linked_panes();
        let (row, reach) = (10.0, 20.0);
        let mut link = ScrollLink::default();

        // Frame one: the reader drags the raw pane to its second line.
        let want_raw = requested_offset(link, Pane::Raw, &raw, &raw, row, reach);
        let want_annotated = requested_offset(link, Pane::Annotated, &annotated, &raw, row, reach);
        link = drove(link, freely(10.0), want_raw, freely(want_annotated), want_annotated);
        assert_eq!(link, ScrollLink { driver: Pane::Raw, offset: 10.0 });

        // Frame two: nobody touches anything, and both panes hand back what
        // they were asked for.
        let want_raw = requested_offset(link, Pane::Raw, &raw, &raw, row, reach);
        let want_annotated = requested_offset(link, Pane::Annotated, &annotated, &raw, row, reach);
        assert_eq!(want_raw, 10.0, "the driver was pulled off its own line");
        assert_eq!(want_annotated, 20.0, "the follower is on the line the driver is on");
        assert_eq!(
            drove(link, freely(want_raw), want_raw, freely(want_annotated), want_annotated),
            link,
            "a frame nobody scrolled changed the shared position"
        );
    }

    #[test]
    fn a_wrapped_follower_lands_on_the_linked_line_and_never_past_it() {
        // The bound on the estimate: egui wraps at or before the character
        // count says, so this can put the follower a row or two above the
        // line the driver is on -- showing context before it -- and never
        // below it, which is the direction that would hide the line the
        // reader was looking for.
        let source = "aaaaaaaaaa; bb";
        let raw = pane_lines(&classify(source), None);
        let annotated = pane_lines(&render_command(source, &BTreeMap::new()), Some(4));
        let link = ScrollLink { driver: Pane::Raw, offset: 0.0 };

        // One raw line, so the follower is asked for the top whatever the
        // wrapping below it.
        assert_eq!(requested_offset(link, Pane::Annotated, &annotated, &raw, 10.0, 20.0), 0.0);
        // And the wrapping really is counted: the second segment does not
        // start on row one.
        assert!(annotated.lines[1].row > 1, "the wrapped first line took one row");
    }

    /// One window's two stacked panes, drawn for real, frame by frame.
    ///
    /// The scroll link is a conversation between this file's arithmetic and a
    /// real scroll area, and what a scroll area does with an offset it cannot
    /// honour is the whole of what the conversation goes wrong over. So the
    /// test below draws real panes, sends real pointer events at them and
    /// reads the link back out of egui's own store, rather than asserting
    /// against numbers this file made up about a layout it did not perform.
    struct StackedWindow {
        ctx: egui::Context,
        raw: Spans,
        annotated: Spans,
        longest: usize,
        size: egui::Vec2,
        time: f64,
    }

    impl StackedWindow {
        /// A window of `size` showing `source` in both panes.
        fn showing(source: &str, size: egui::Vec2) -> StackedWindow {
            let ctx = egui::Context::default();
            crate::prompt_ui::apply_faces(&ctx);
            crate::prompt_ui::apply_font_size(&ctx, 16.0);
            theme::apply(&ctx, theme::Theme::Dark);
            let home = BTreeMap::from([("HOME".to_string(), "/home/alex".to_string())]);
            let annotated = render_command(source, &home);
            let raw = classify(source);
            let longest = widest_line(&annotated).max(widest_line(&raw));
            StackedWindow { ctx, raw, annotated, longest, size, time: 0.0 }
        }

        /// One frame's worth of input: the window, the clock and the reader.
        ///
        /// A clock that advances, because egui animates a scroll bar into
        /// view: in a window where no time passes it never finishes
        /// arriving, and the panes are never the ones a reader sees.
        fn input(&mut self, events: Vec<egui::Event>) -> egui::RawInput {
            self.time += 1.0 / 60.0;
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, self.size)),
                time: Some(self.time),
                events,
                ..Default::default()
            }
        }

        /// Which arrangement this window's panes are in, measured in the
        /// window itself: the rule is a question about width, and a test that
        /// assumed the answer would go on passing after it changed.
        fn view(&mut self) -> CommandView {
            let longest = self.longest;
            let input = self.input(Vec::new());
            let mut view = None;
            let mut out = self.ctx.run_ui(input, |ui| {
                view = Some(command_view(longest, column_chars(pane_chars(ui, 2), 0)));
            });
            out.textures_delta.clear();
            view.expect("the frame ran")
        }

        /// One frame, with whatever the reader did during it.
        fn frame(&mut self, events: Vec<egui::Event>) -> Drawn {
            let input = self.input(events);
            let (raw, annotated, longest) = (&self.raw, &self.annotated, self.longest);
            let mut out = self.ctx.run_ui(input, |ui| draw_command(ui, annotated, raw, longest));
            let text = drawn_text(&out);
            // epaint refuses to be dropped holding texture deltas nobody
            // applied.
            out.textures_delta.clear();
            let link = self.ctx.data(|data| data.get_temp(scroll_link_id())).unwrap_or_default();
            Drawn { link, text }
        }

        /// Press at `at` and keep the button down there for `frames` frames,
        /// as a reader holding a scroll handle does.
        fn holding(&mut self, at: egui::Pos2, frames: usize) -> Vec<Drawn> {
            self.frame(vec![
                egui::Event::PointerMoved(at),
                egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ]);
            (0..frames).map(|_| self.frame(vec![egui::Event::PointerMoved(at)])).collect()
        }
    }

    /// What one frame left behind: where the two panes settled, and what the
    /// reader could see.
    #[derive(Debug, Clone, PartialEq)]
    struct Drawn {
        /// Which pane the other one is following, and from where.
        link: ScrollLink,
        /// Every line of the command a reader could actually see, and the
        /// height it was drawn at. Two frames that put the same text in the
        /// same places are two frames a reader cannot tell apart, which is
        /// the whole of what "it jumps" means.
        text: Vec<(String, i32)>,
    }

    /// Every string a frame drew where its own pane could show it.
    ///
    /// Clipped by hand, because a scroll area lays its whole content out and
    /// leaves the clipping to the painter: text scrolled off the end of a
    /// pane is still in the frame's shapes, at a position outside the pane.
    /// A pane asked for an offset past its content draws every line of it
    /// somewhere nobody can see, and that is one of the two things this is
    /// here to catch.
    fn drawn_text(out: &egui::FullOutput) -> Vec<(String, i32)> {
        fn walk(shape: &egui::epaint::Shape, clip: egui::Rect, into: &mut Vec<(String, i32)>) {
            match shape {
                egui::epaint::Shape::Text(text) => {
                    let row = egui::Rect::from_min_size(text.pos, text.galley.size());
                    if clip.intersects(row) {
                        into.push((text.galley.text().to_string(), text.pos.y.round() as i32));
                    }
                }
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        walk(shape, clip, into);
                    }
                }
                _ => {}
            }
        }
        let mut into = Vec::new();
        for clipped in &out.shapes {
            walk(&clipped.shape, clipped.clip_rect, &mut into);
        }
        into
    }

    /// How many characters of the pane's own font a window of `size` believes
    /// one full-width pane holds.
    ///
    /// The count [`pane_lines`] wraps its estimate at. It is still an
    /// under-count of what the real pane fits — [`pane_chars`] floors, and
    /// the scroll bar's column is subtracted whether or not the pane grows
    /// one — so the estimate still reaches more rows than the pane does, and
    /// the guard that tells a clamp from a reader is still load-bearing. What
    /// it no longer is is a whole bar out: the bars take the column this
    /// subtracts. See [`text_width`].
    fn estimated_pane_chars(size: egui::Vec2) -> usize {
        let ctx = egui::Context::default();
        crate::prompt_ui::apply_faces(&ctx);
        crate::prompt_ui::apply_font_size(&ctx, 16.0);
        theme::apply(&ctx, theme::Theme::Dark);
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            ..Default::default()
        };
        let mut chars = 0;
        let mut out = ctx.run_ui(input, |ui| chars = pane_chars(ui, 1));
        out.textures_delta.clear();
        chars
    }

    #[test]
    fn a_pane_held_at_its_end_stays_there_for_as_long_as_it_is_held() {
        // The bug, in the reader's words: "the scroll bar jumps when reaching
        // the end, so I can never see the final part of the command". With a
        // handle held at the bottom, the two panes took the driver's role
        // from each other every other frame, and the pane the reader had hold
        // of was dragged back up the command on each of them.
        //
        // What made it possible: the follower's maximum was estimated from a
        // character count, the estimate came out a row high, the scroll area
        // clamped a request it could not honour, and `drove` read the clamp
        // as the reader scrolling. Every term of that is a real layout's, so
        // this asserts against a real layout.

        // Every line one character wider than the annotated pane is thought
        // to hold, and so two rows to the estimate and one row to the pane:
        // forty lines the estimate believes are eighty. That is the whole
        // failure, arranged rather than hoped for -- the estimate has the
        // pane reaching twice as far down the command as it does.
        let size = egui::vec2(900.0, 700.0);
        let width = estimated_pane_chars(size);
        let mut command = String::new();
        for n in 0..40 {
            // Exactly as many characters as the estimate believes fit. The
            // line the pane draws is one wider, because the terminator is
            // drawn and counted too -- which is the character over.
            let mut line = format!("cat /tmp/{n:02}/");
            while line.chars().count() < width {
                line.push('x');
            }
            command.push_str(&line);
            command.push('\n');
        }
        let mut window = StackedWindow::showing(&command, size);
        assert_eq!(
            widest_line(&window.annotated),
            width + 1,
            "the lines are not the one character over the estimate this is about"
        );
        assert_eq!(
            window.view(),
            CommandView::Stacked,
            "side by side panes are not linked, so this would assert nothing"
        );
        // Frames enough to settle: a pane learns its size from the frame
        // before, a reader does not scroll what they have not been shown, and
        // a solid scroll bar animates its column in rather than appearing
        // with it — so for the eighth of a second that takes, the viewport is
        // still narrowing and a pane's maximum offset is still growing. The
        // clock advances a sixtieth per frame; this is three times the
        // animation.
        for _ in 0..16 {
            window.frame(Vec::new());
        }

        // The raw strip's own scroll handle, taken to the bottom of its bar
        // and held there. The strip is the pane the reader reaches for to
        // check a line, and it is the one whose follower wraps.
        let grab = egui::pos2(window.size.x - 9.0, 180.0);
        let held = window.holding(grab, 8);

        // The grab landed and the strip went somewhere, or the rest of this
        // asserts nothing about a scroll bar.
        assert!(
            held.iter().any(|f| f.link.driver == Pane::Raw && f.link.offset > 0.0),
            "nothing took hold of the raw strip's scroll bar"
        );
        let (first, rest) = held.split_first().expect("the reader held it for some frames");
        assert_eq!(
            first.link.driver,
            Pane::Raw,
            "the pane the reader is holding lost the link to the pane they are not touching"
        );
        // The annotated pane is the lower two thirds of this window, and a
        // pane asked for an offset it has nothing at draws its whole content
        // above itself. The reader would be holding the raw strip at the end
        // of the command with blank space where the annotated form of it
        // should be.
        for drawn in &held {
            assert!(
                drawn.text.iter().any(|(_, row)| *row as f32 > window.size.y / 2.0),
                "the annotated pane showed nothing at all: {:?}",
                drawn.text
            );
        }
        for (frame, drawn) in rest.iter().enumerate() {
            assert_eq!(
                drawn.link, first.link,
                "frame {frame} moved a pane the reader had not let go of"
            );
            assert_eq!(drawn.text, first.text, "frame {frame} drew the command somewhere else");
        }
    }


    // ---- saying how much of a pane is out of sight -------------------------

    /// Every string a window of `size` draws for `payload`, once its panes
    /// have stopped changing size.
    ///
    /// Through [`draw_payload`], which is the door the window itself uses, so
    /// what this reads is the header, the caption, the out-of-sight line and
    /// the panes exactly as a reader gets them. Frames enough for a scroll
    /// area to learn its content height, for a solid scroll bar to finish
    /// animating its column in, and for a caption built from the frame before
    /// to catch up with the panes under it.
    fn settled_text(payload: &Payload, size: egui::Vec2) -> Vec<(String, i32)> {
        frames_of(payload, size, SETTLED).pop().expect("some frames were drawn")
    }

    /// Frames enough for everything in this window to stop moving.
    const SETTLED: u32 = 20;

    /// A context set up the way [`crate::prompt_ui::open_window`] sets one up.
    ///
    /// Expensive — building the font atlas is most of it — so a test that
    /// draws many windows builds one of these and re-uses it, which is also
    /// the more honest thing to draw: a reader dragging a window wider is one
    /// context and many sizes, not many windows.
    fn a_drawing_context() -> egui::Context {
        let ctx = egui::Context::default();
        crate::prompt_ui::apply_faces(&ctx);
        crate::prompt_ui::apply_font_size(&ctx, 16.0);
        theme::apply(&ctx, theme::Theme::Dark);
        ctx
    }

    /// What a window of `size` drew on each of its first `frames` frames.
    fn frames_of(payload: &Payload, size: egui::Vec2, frames: u32) -> Vec<Vec<(String, i32)>> {
        frames_in(&a_drawing_context(), payload, size, frames)
    }

    /// The same, in a context that has already drawn something.
    fn frames_in(
        ctx: &egui::Context,
        payload: &Payload,
        size: egui::Vec2,
        frames: u32,
    ) -> Vec<Vec<(String, i32)>> {
        let shown = Shown::of(payload).expect("a real payload");
        (0..frames)
            .map(|frame| {
                let input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    time: Some(ctx.input(|i| i.time) + f64::from(frame + 1) / 60.0),
                    ..Default::default()
                };
                let mut out = ctx.run_ui(input, |ui| draw_payload(ui, &shown));
                let text = drawn_text(&out);
                out.textures_delta.clear();
                text
            })
            .collect()
    }

    /// The out-of-sight line a window drew, if it drew one.
    ///
    /// Found by the clause both of its sentences end in, so a window that
    /// only has something to say about one axis is still found.
    fn out_of_sight_line(text: &[(String, i32)]) -> Option<String> {
        text.iter().map(|(line, _)| line).find(|line| line.contains("for the rest.")).cloned()
    }

    /// A window the size the reader opens one at.
    fn a_window() -> egui::Vec2 {
        egui::vec2(1280.0, 700.0)
    }

    #[test]
    fn a_row_half_under_the_edge_is_a_row_that_was_not_read() {
        // The two counts are rounded apart on purpose: what a pane laid out
        // rounds up and what it showed rounds down, so a row with its bottom
        // half below the edge is a row that exists and not a row that was
        // seen. Getting this backwards is the failure mode that matters --
        // a window that says nothing over a line the reader cannot finish.
        let row = 20.0;
        assert_eq!(Rows::measured(200.0, 200.0, row), Rows { of: 10, shown: 10 });
        assert!(Rows::measured(200.0, 200.0, row).whole(), "a pane that fits said it did not");
        assert_eq!(Rows::measured(210.0, 200.0, row), Rows { of: 11, shown: 10 });
        assert_eq!(Rows::measured(210.0, 200.0, row).hidden(), 1, "half a row is a row");
        assert_eq!(Rows::measured(1260.0, 200.0, row), Rows { of: 63, shown: 10 });

        // A pane draws n lines in n text heights and n - 1 gaps, and a row is
        // a text height plus a gap, so a pane that fits its content exactly
        // comes out a hair under a whole number of rows. That is rounding and
        // not a hidden row.
        assert!(Rows::measured(199.4, 200.0, row).whole(), "a gap at the bottom read as a row");
        // And a pane nobody has drawn yet reports nothing rather than
        // claiming everything is on screen -- which is the same thing here,
        // because nothing is what it says out loud.
        assert!(Rows::default().whole());
        assert_eq!(Rows::measured(100.0, 100.0, 0.0), Rows::default(), "a font of no height");
    }

    #[test]
    fn the_words_say_how_much_is_out_of_sight_and_what_to_do_about_it() {
        let note = rows_out_of_sight(Rows { of: 63, shown: 24 }, "the command", "the pane below")
            .expect("a pane showing 24 of 63 rows has something to say");
        assert!(note.contains("63"), "the sentence does not say how much there is: {note}");
        assert!(note.contains("24"), "nor how much is on screen: {note}");
        assert!(note.contains("39"), "nor how much is not: {note}");
        assert!(note.contains("out of sight"), "nor that that is what it means: {note}");
        assert!(note.contains("scroll"), "nor what the reader can do about it: {note}");
        assert!(note.contains("the pane below"), "nor which pane it is about: {note}");

        // Nothing at all when the reader has been shown all of it. The
        // measurement is a frame old, and "all of it is on screen" is the one
        // sentence a reader would stop reading on, so this never says it.
        assert_eq!(rows_out_of_sight(Rows { of: 24, shown: 24 }, "the command", "the pane"), None);
        assert_eq!(rows_out_of_sight(Rows::default(), "the command", "the pane"), None);

        // And the same sideways, which is the axis the raw pane loses text
        // off: it does not reflow, so a long line stops at the right edge.
        let wide = width_out_of_sight(218, 123, "the strip")
            .expect("a 218-character line in a 123-character strip has something to say");
        assert!(wide.contains("218"), "the sentence does not say how wide the lines run: {wide}");
        assert!(wide.contains("123"), "nor how much of that is on screen: {wide}");
        assert!(wide.contains("sideways"), "nor which way to scroll: {wide}");
        assert_eq!(width_out_of_sight(123, 123, "the strip"), None, "a line that just fits");
        assert_eq!(width_out_of_sight(0, 123, "the strip"), None, "an empty command");
    }

    #[test]
    fn side_by_side_speaks_for_whichever_pane_is_the_worse_off() {
        // The two panes are the same height and hold two renderings of one
        // command, and which of them has the most rows is not something a
        // reader should have to be told. So one sentence, made true of both
        // by taking the larger row count against the smaller viewport.
        let seen = CommandRows {
            raw: Rows { of: 60, shown: 25 },
            annotated: Rows { of: 63, shown: 24 },
        };
        assert_eq!(seen.worst(), Rows { of: 63, shown: 24 });
        let note = command_note(CommandView::SideBySide, seen, 40, 120);
        assert!(note.contains("63"), "the worse pane's row count is not the one quoted: {note}");
        assert!(note.contains("the panes"), "one sentence did not speak for both: {note}");
        // Side by side is only offered when every line fits its column whole,
        // so nothing can be off to the side and nothing says it is -- even
        // when the numbers handed in would say so anywhere else.
        assert!(!note.contains("sideways"), "side by side claimed a line ran off it: {note}");

        // Stacked, the strip's own six rows are hatch's layout decision and
        // not news; the pane the reader reads is the one reported.
        let note = command_note(CommandView::Stacked, seen, 218, 123);
        assert!(note.contains("the pane below"), "the wrong pane is reported: {note}");
        assert!(note.contains("24"), "the annotated pane's figures are not the ones used: {note}");
        assert!(note.contains("the strip"), "nothing said the strip loses text sideways: {note}");
        assert!(note.contains("218"), "nor how far the lines run: {note}");

        // And a window showing all of both panes says neither thing.
        let whole = CommandRows {
            raw: Rows { of: 6, shown: 20 },
            annotated: Rows { of: 8, shown: 20 },
        };
        assert_eq!(command_note(CommandView::Stacked, whole, 40, 123), "");
        assert_eq!(command_note(CommandView::SideBySide, whole, 40, 123), "");
    }

    #[test]
    fn a_command_that_runs_past_the_bottom_of_its_pane_says_so_in_the_window() {
        // The reader's report: "when the command has lines beyond what's
        // being seen we need some sign. why: scrollbar is tiny, easy to think
        // it ends". Asserted against a real window, because what a pane
        // manages to show is a fact about a layout and nothing else knows it.
        //
        // Sixty short lines: every one of them fits a column, so this is the
        // side-by-side arrangement, and the two panes are level.
        let long = (0..60).map(|n| format!("echo {n}")).collect::<Vec<_>>().join("\n");
        let text = settled_text(&a_command(&long), a_window());
        let note = out_of_sight_line(&text)
            .unwrap_or_else(|| panic!("a 60-row command in a 700-point window said nothing"));
        assert!(note.contains("60"), "the notice does not say how long the command is: {note}");
        assert!(note.contains("the panes"), "nor which arrangement it is about: {note}");

        // And a command that fits says nothing, so the line means something
        // when it is there.
        let text = settled_text(&a_command("cargo build --release"), a_window());
        assert_eq!(
            out_of_sight_line(&text),
            None,
            "a one-line command was reported as running off the pane: {text:?}"
        );
    }

    #[test]
    fn a_line_that_runs_off_the_raw_strip_says_so_too() {
        // The strip deliberately does not reflow -- that is the promise the
        // caption makes for it -- so a long line runs past the right edge and
        // stops there, with a horizontal scroll bar as the only sign it did
        // not end. In a root request the strip ends part-way through `run0`'s
        // argument list.
        let wide = format!("echo {}", "x".repeat(400));
        let text = settled_text(&a_command(&format!("{wide}\n{wide}\n{wide}")), a_window());
        let note = out_of_sight_line(&text)
            .unwrap_or_else(|| panic!("a 405-character line said nothing: {text:?}"));
        assert!(note.contains("sideways"), "nothing said which way the rest of it is: {note}");
        // 406 and not 405: the `↵` that ends each line is drawn, so it is
        // counted -- the same rule the fit measurement uses.
        assert!(note.contains("406"), "nor how far the lines run: {note}");
        assert!(note.contains("the strip"), "nor which pane loses them: {note}");
    }

    #[test]
    fn a_diff_taller_than_its_pane_says_so_in_the_same_words() {
        // The swap window's pane is the same promise about a different kind
        // of text: a list of lines somebody is about to let be written. A
        // pane showing forty of two hundred of them said so through its
        // scroll bar alone.
        let before = (0..200).map(|n| format!("key{n} = {n}\n")).collect::<String>();
        let after = before.replace("key7 =", "key7 = ");
        let text = settled_text(&swap_payload(&before, &after), a_window());
        let note = out_of_sight_line(&text)
            .unwrap_or_else(|| panic!("a 200-row diff said nothing: {text:?}"));
        assert!(note.contains("200"), "the notice does not say how long the diff is: {note}");
        assert!(note.contains("the diff"), "nor what it is counting: {note}");

        // A diff that fits says nothing.
        let text = settled_text(&swap_payload("a\n", "b\n"), a_window());
        assert_eq!(
            out_of_sight_line(&text),
            None,
            "a one-line diff was reported as running off the pane: {text:?}"
        );
    }


    #[test]
    fn the_line_above_the_panes_settles_at_every_window_size() {
        // The one loop in this: the notice is drawn *above* the panes, so its
        // height is part of how tall they are, and what it says is measured
        // off them. Two layouts could in principle each imply the other -- a
        // sentence one character from wrapping fits on one row, which leaves
        // the pane a row taller, which drops the row count past a digit
        // boundary, which shortens the sentence, which fits on one row; and
        // the two-row version implies the one-row version back. A window that
        // flickered between two sentences for as long as it was open would be
        // a worse thing than the bar this replaced.
        //
        // Argued away on paper it is a coincidence of a width and a row count.
        // Swept here instead, because "unlikely" is not a property. Every
        // width across the range a reader might drag a window through, at two
        // heights, on a command long enough and wide enough that both halves
        // of the sentence are in play: the last two frames have to draw the
        // same line.
        let wide = format!("rsync -avz {} src dest", "--exclude '*.tmp' ".repeat(12));
        let command = (0..14)
            .map(|n| match n % 7 {
                0 => wide.clone(),
                _ => format!("systemctl --user restart worker-{n}.service"),
            })
            .collect::<Vec<_>>()
            .join("\n");
        let payload = a_command(&command);

        let ctx = a_drawing_context();
        let (mut down, mut across) = (0, 0);
        for height in [260.0_f32, 420.0] {
            for width in (460..=1500).step_by(7) {
                let size = egui::vec2(width as f32, height);
                let frames = frames_in(&ctx, &payload, size, SETTLED);
                let notes: Vec<_> =
                    frames.iter().rev().take(4).map(|frame| out_of_sight_line(frame)).collect();
                assert!(
                    notes.windows(2).all(|pair| pair[0] == pair[1]),
                    "a {width} by {height} window never settles on one sentence: {notes:#?}"
                );
                let settled = notes.first().cloned().flatten().unwrap_or_default();
                down += usize::from(settled.contains("out of sight"));
                across += usize::from(settled.contains("sideways"));
            }
        }
        // And the sweep really did draw the sentence it is about -- both
        // halves of it -- rather than passing over three hundred windows that
        // had nothing to say.
        assert!(down > 200, "only {down} of the swept windows reported rows out of sight");
        assert!(across > 100, "only {across} of them reported a line running off the side");
    }

    // ---- layout ------------------------------------------------------------

    #[test]
    fn a_rendering_is_split_where_it_asked_to_be_and_nowhere_else() {
        let spans = render_command("ls; rm -rf target", &BTreeMap::new());
        let drawn = lines(&spans);

        assert!(drawn.len() > 1, "the segmenter's line break was ignored");
        let rejoined: String = drawn.iter().flat_map(|line| line.iter()).map(Span::text).collect();
        assert_eq!(rejoined, "ls; rm -rf target", "splitting into lines lost or moved text");
    }

    #[test]
    fn a_rendering_with_no_spans_draws_no_lines() {
        // An empty command renders to nothing, and nothing is zero lines
        // rather than one blank one.
        assert!(lines(&classify("")).is_empty());
    }

    #[test]
    fn a_break_on_the_very_first_span_does_not_open_an_empty_line() {
        let mut spans = classify("ls");
        spans.set_break_before(0, true);

        assert_eq!(lines(&spans).len(), 1);
    }

    #[test]
    fn every_span_of_a_rendering_is_drawn_on_exactly_one_line() {
        let spans = render_command("a && b || c | d; e", &BTreeMap::new());
        let drawn: usize = lines(&spans).iter().map(|line| line.len()).sum();

        assert_eq!(drawn, spans.len(), "a span was dropped or drawn twice");
    }

    #[test]
    fn only_the_unreflowed_pane_refuses_to_wrap() {
        assert!(!Weight::Mono.wraps());
        assert!(Weight::Wrapped.wraps());
        assert!(Weight::Body.wraps());
        assert!(Weight::Heading.wraps());
        assert_eq!(wrap_mode(Weight::Mono), egui::TextWrapMode::Extend);
        assert_eq!(wrap_mode(Weight::Wrapped), egui::TextWrapMode::Wrap);
    }


    // ---- what a laid-out line actually says --------------------------------

    /// A palette of distinguishable colours, so a test can tell which format
    /// a stretch of the job was given. The real one comes from the theme.
    fn a_palette() -> Palette {
        Palette {
            chrome: Color32::from_rgb(11, 0, 0),
            running: Color32::from_rgb(17, 0, 0),
            finished: Color32::from_rgb(18, 0, 0),
            surface: Color32::from_rgb(12, 0, 0),
            border: Color32::from_rgb(13, 0, 0),
            button: Color32::from_rgb(14, 0, 0),
            button_hovered: Color32::from_rgb(15, 0, 0),
            button_active: Color32::from_rgb(16, 0, 0),
            text: Color32::from_rgb(1, 0, 0),
            quiet: Color32::from_rgb(2, 0, 0),
            danger: Color32::from_rgb(3, 0, 0),
            warn: Color32::from_rgb(4, 0, 0),
            command: Color32::from_rgb(5, 0, 0),
            quoted: Color32::from_rgb(6, 0, 0),
            chip_bg: Color32::from_rgb(7, 0, 0),
            separator_bg: Color32::from_rgb(8, 0, 0),
            value_bg: Color32::from_rgb(9, 0, 0),
            gap_bg: Color32::from_rgb(10, 0, 0),
        }
    }

    fn job_of(spans: &Spans) -> egui::text::LayoutJob {
        line_job(spans, &a_palette(), &egui::FontId::monospace(12.0))
    }

    /// The format covering the byte at `at` in the job's text.
    fn format_at(job: &egui::text::LayoutJob, at: usize) -> &egui::TextFormat {
        &job
            .sections
            .iter()
            .find(|section| (section.byte_range.start.0..section.byte_range.end.0).contains(&at))
            .expect("the sections cover the whole text")
            .format
    }

    #[test]
    fn a_laid_out_line_says_exactly_what_the_spans_say() {
        // The assertion the per-span form could not make: one string, and it
        // is the concatenation of every span's drawn text with nothing
        // between them. A gap here would be a character on screen that is
        // not in the command.
        let job = job_of(&classify("ls a\u{202e}b"));

        assert_eq!(job.text, "ls a[RLO]b");
    }

    #[test]
    fn a_resolved_value_is_in_the_line_beside_its_reference_and_not_in_place_of_it() {
        let spans =
            render_command("echo $HOME", &BTreeMap::from([("HOME".into(), "/home/u".into())]));

        assert_eq!(job_of(&spans).text, "echo $HOME → /home/u ");
    }

    #[test]
    fn an_unset_reference_says_so_rather_than_reading_as_an_empty_value() {
        let spans = render_command("echo $NOPE", &BTreeMap::new());

        assert_eq!(job_of(&spans).text, "echo $NOPE → unset ");
    }

    #[test]
    fn a_chip_is_the_only_stretch_of_a_line_drawn_in_hatch_s_own_colours() {
        let palette = a_palette();
        let job = job_of(&classify("a\u{202e}b"));

        // `a` and `b` are the command's own text; `[RLO]` is hatch's label
        // for one character of it, and it is boxed and coloured so that it
        // cannot be read as text that was really there.
        assert_eq!(format_at(&job, 0).color, palette.text);
        assert_eq!(format_at(&job, 0).background, Color32::TRANSPARENT);
        assert_eq!(format_at(&job, 1).color, palette.warn);
        assert_eq!(format_at(&job, 1).background, palette.chip_bg);
        assert_eq!(format_at(&job, "a[RLO]".len()).color, palette.text);
    }

    #[test]
    fn every_stretch_of_a_line_is_laid_out_in_the_font_the_pane_asked_for() {
        // A format that lost its font falls back to egui's default, which is
        // proportional: a monospace pane would stop being one, and the
        // character-count fit that chooses the side-by-side view would be
        // measuring a font nothing is drawn in.
        let job = job_of(&classify("ls"));

        assert_eq!(format_at(&job, 0).font_id, egui::FontId::monospace(12.0));
    }

    #[test]
    fn a_span_the_daemon_marked_dangerous_is_drawn_in_the_danger_colour() {
        let palette = a_palette();
        let mut spans = classify("mkfs");
        spans.set_kind(0, SpanKind::Danger);

        assert_eq!(format_at(&job_of(&spans), 0).color, palette.danger);
    }

    #[test]
    fn a_resolved_value_is_marked_as_hatch_s_note_and_not_as_command_text() {
        // Italic, quiet and boxed, all three: the note sits inside the same
        // line as the command it annotates, so nothing but its formatting
        // separates "what will run" from "what hatch worked out".
        let palette = a_palette();
        let spans =
            render_command("echo $HOME", &BTreeMap::from([("HOME".into(), "/home/u".into())]));
        let job = job_of(&spans);
        let note = job.text.find('\u{2192}').expect("the note is on screen");

        assert_eq!(format_at(&job, note).color, palette.quiet);
        assert_eq!(format_at(&job, note).background, palette.value_bg);
        assert!(format_at(&job, note).italics, "the note reads as part of the command");

        // And the reference it belongs to does not take the note's styling.
        let reference = job.text.find('$').expect("the reference is on screen");
        assert_eq!(format_at(&job, reference).color, palette.text);
        assert!(!format_at(&job, reference).italics);
    }

    #[test]
    fn a_structural_chip_is_quiet_and_a_loud_one_is_boxed() {
        // The whole of the tier, where it turns into pixels. A newline that
        // shouted as loudly as a bidi override is what teaches a reader to
        // skip both.
        let palette = a_palette();
        let job = job_of(&classify("a\nb\u{202e}"));

        let newline = job.text.find('\u{21B5}').expect("the glyph is on screen");
        assert_eq!(format_at(&job, newline).color, palette.quiet, "a newline shouted");
        assert_eq!(
            format_at(&job, newline).background,
            Color32::TRANSPARENT,
            "a newline was boxed like a substitution the reader has to look at"
        );

        let override_at = job.text.find("[RLO]").expect("the label is on screen");
        assert_eq!(format_at(&job, override_at).color, palette.warn);
        assert_eq!(format_at(&job, override_at).background, palette.chip_bg);
    }

    #[test]
    fn the_tier_is_read_from_the_character_and_not_from_the_label() {
        // A view that recognised `[LF]` would be reading a label, and a label
        // is the one thing on screen a command may contain literally. Here
        // the command contains that literal, and it must draw loudly like the
        // ordinary text it is -- not quietly like a newline.
        let palette = a_palette();
        let job = job_of(&classify("[LF]"));

        assert_eq!(job.text, "[LF]", "four characters of the command, drawn as themselves");
        assert_eq!(format_at(&job, 0).color, palette.text, "text was drawn as hatch's own word");
        assert_eq!(format_at(&job, 0).background, Color32::TRANSPARENT);
    }

    #[test]
    fn the_word_that_runs_and_the_strings_are_drawn_apart_from_the_rest() {
        let palette = a_palette();
        let spans = render_command("ls 'a b' -l", &BTreeMap::new());
        let job = job_of(&spans);

        assert_eq!(job.text, "ls 'a b' -l", "highlighting changed the text");
        assert_eq!(format_at(&job, 0).color, palette.command, "the command name is not marked");
        assert_eq!(format_at(&job, 3).color, palette.quoted, "the string is not marked");
        assert_eq!(format_at(&job, 9).color, palette.text, "an argument took a highlight");
    }

    #[test]
    fn highlighting_only_ever_adds_contrast() {
        // The rule that keeps decoration from becoming load-bearing: a
        // highlighted span is drawn as its own text, in the pane's own font,
        // with nothing behind it and nothing done to it that a reader who
        // ignores colour would notice.
        let spans = render_command("ls 'a b'", &BTreeMap::new());
        let job = job_of(&spans);

        for section in &job.sections {
            assert_eq!(section.format.background, Color32::TRANSPARENT, "a highlight was boxed");
            assert!(!section.format.italics, "a highlight leaned");
            assert_eq!(section.format.font_id, egui::FontId::monospace(12.0));
        }
    }

    #[test]
    fn the_highlight_colours_are_not_the_colours_that_already_mean_something() {
        // Red is danger, orange is hatch substituting for a character, grey
        // is hatch talking. A palette that spent one of those on a keyword
        // would make the meaningful ones ordinary, so the two the highlight
        // uses have to be distinct from all of them -- and from each other.
        // Both palettes, because a theme is a choice and neither of them may
        // collapse two meanings into one colour.
        for theme in [crate::prompt_ui::theme::Theme::Dark, crate::prompt_ui::theme::Theme::Light]
        {
            let palette = theme.palette();
            let named = [
                ("text", palette.text),
                ("quiet", palette.quiet),
                ("danger", palette.danger),
                ("warn", palette.warn),
                ("command", palette.command),
                ("quoted", palette.quoted),
            ];
            for (i, (a, colour)) in named.iter().enumerate() {
                for (b, other) in &named[i + 1..] {
                    assert_ne!(colour, other, "{theme:?}: {a} and {b} are the same colour");
                }
            }
        }
    }

    #[test]
    fn the_command_word_carries_an_underline_as_well_as_its_contrast() {
        // Contrast alone read as slightly brighter text rather than as a
        // mark. Two channels, so a glance finds it.
        let palette = a_palette();
        let spans = render_command("ls -l", &BTreeMap::new());
        let job = job_of(&spans);
        let format = format_at(&job, 0);

        assert_eq!(format.color, palette.command);
        assert_eq!(format.underline.color, palette.command, "the command word is not underlined");
        assert!(format.underline.width > 0.0);
    }

    #[test]
    fn nothing_reads_as_a_hyperlink_that_this_window_does_not_have() {
        // The link colour belongs to quoted strings, and it was chosen for
        // them. Underlining it as well would draw a hyperlink -- a thing this
        // window has none of -- so the underline goes on the one span kind
        // that is never that colour.
        let palette = a_palette();
        let spans = render_command("echo 'hello'", &BTreeMap::new());
        let job = job_of(&spans);
        let quote = job.text.find('\'').expect("the quoted string is on screen");
        let quoted = format_at(&job, quote);

        assert_eq!(quoted.color, palette.quoted);
        assert_eq!(quoted.underline, egui::Stroke::NONE, "a quoted string reads as a link");
        assert_ne!(palette.command, palette.quoted, "the underlined word is the link colour");
    }

    #[test]
    fn an_underlined_command_word_is_exactly_as_wide_as_a_plain_one() {
        // The side-by-side fit is measured in characters against the
        // monospace advance, so a mark that widened a glyph would make the
        // measurement and the drawing disagree about what fits a column.
        // Verified through egui's own layout rather than assumed.
        at_font_size(16.0, |ui| {
            let advance = advance(ui);
            let font = font(Weight::Mono, ui.style());
            let plain = egui::TextFormat { font_id: font.clone(), ..Default::default() };
            let marked = egui::TextFormat {
                underline: egui::Stroke::new(1.0, Color32::WHITE),
                ..plain.clone()
            };
            let width = |format: egui::TextFormat| {
                let mut job = egui::text::LayoutJob::default();
                job.append("0000000000", 0.0, format);
                job.wrap.max_width = f32::INFINITY;
                ui.ctx().fonts_mut(|fonts| fonts.layout_job(job)).size().x
            };
            assert_eq!(width(marked), width(plain.clone()), "the underline moved the glyphs");
            assert!(
                (width(plain) - 10.0 * advance).abs() < 0.5,
                "ten characters are not ten advances wide"
            );
        });
    }

    #[test]
    fn a_separator_is_boxed_and_never_faded() {
        // A `;` nobody notices is how a second command gets approved along
        // with the first, so the de-emphasis is a block behind it and never
        // a reduction of its contrast.
        let palette = a_palette();
        let spans = render_command("ls; rm", &BTreeMap::new());
        let job = job_of(&spans);
        let semicolon = job.text.find(';').expect("the separator is on screen");

        assert_eq!(format_at(&job, semicolon).color, palette.text, "a separator was faded");
        assert_eq!(format_at(&job, semicolon).background, palette.separator_bg);
    }

    #[test]
    fn every_weight_draws_in_a_font_and_only_the_unreflowed_one_refuses_to_wrap() {
        let style = egui::Style::default();
        assert_eq!(font(Weight::Mono, &style), font(Weight::Wrapped, &style));
        assert_ne!(font(Weight::Body, &style).family, font(Weight::Mono, &style).family);
        assert_eq!(
            font(Weight::Heading, &style).size,
            font(Weight::Body, &style).size * crate::prompt_ui::HEADLINE_SCALE,
            "the headline stopped following the size the reader chose"
        );
        assert_eq!(font(Weight::Heading, &style).family, font(Weight::Body, &style).family);
    }

    #[test]
    fn a_variable_is_drawn_as_itself_and_its_value_only_beside_it() {
        let spans =
            render_command("echo $HOME", &BTreeMap::from([("HOME".into(), "/home/u".into())]));
        let reference = spans.iter().find(|span| span.variable().is_some()).expect("a $HOME span");

        assert_eq!(reference.display_text(), "$HOME", "the value was drawn in place of the name");
        assert_eq!(reference.variable().unwrap().1, Some("/home/u"));
    }

    #[test]
    fn a_resolved_value_reaches_the_window_defanged() {
        // The daemon defangs it, and this asserts the property the window
        // relies on rather than the line of code that provides it.
        let spans = render_command(
            "echo $HOME",
            &BTreeMap::from([("HOME".into(), "/home/\u{202e}u".into())]),
        );
        let reference = spans.iter().find(|span| span.variable().is_some()).expect("a $HOME span");

        assert_eq!(reference.variable().unwrap().1, Some("/home/[RLO]u"));
    }

    #[test]
    fn the_one_line_form_of_a_payload_is_what_the_panes_would_draw() {
        // The panes draw `display_text` per span; `display_line` is that
        // concatenated. If these ever disagree, the title bar and the window
        // are describing different commands.
        let spans = render_command("ls\u{202e}", &BTreeMap::new());
        let payload = Payload::command(&spans, Vec::new(), PathBuf::from("/"), false, false);

        let Shown::Command { annotated, .. } = Shown::of(&payload).expect("a real payload") else {
            panic!("not a command")
        };
        let drawn: String =
            lines(&annotated).iter().flat_map(|l| l.iter()).map(Span::display_text).collect();
        assert_eq!(drawn, display_line(&annotated));
        assert!(drawn.contains("[RLO]"));
    }

    #[test]
    fn wire_spans_of_a_rendering_round_trip_into_something_drawable() {
        let spans = render_command("ls -l", &BTreeMap::new());
        assert_eq!(wire_spans(&spans).len(), spans.len());
    }
}

