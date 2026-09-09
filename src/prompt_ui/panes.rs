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

use eframe::egui::{self, Color32, RichText, Ui};

use crate::protocol::{Payload, ProtocolError};
use crate::render::diff::{Row, Side};
use crate::render::unicode::{ScanReport, classify, defang, scan};
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

/// The most of the space below the header the raw pane may take.
///
/// A newline now ends a line in every pane, so a pasted script is as many
/// lines in the raw pane as it has, and without a ceiling a fifty-line
/// heredoc would push the annotated pane off the bottom. The raw pane is the
/// one a reader falls back to, not the one they read first, so it yields the
/// space and scrolls.
const RAW_SHARE: f32 = 0.40;

/// Characters of gutter in front of each diff column: the `-`/`+` mark and
/// the space after it.
const GUTTER_CHARS: usize = 2;

/// Characters of empty space between the two diff columns.
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
            Payload::Command { danger, cwd, root, interactive, .. } => {
                let annotated = payload.rendering()?;
                // From the rebuilt spans, not from the payload's own `raw`
                // field: the two are equal by construction, and taking it
                // from here means every character in either pane came out of
                // something the builder checked.
                let source = annotated.source();
                Ok(Shown::Command {
                    raw: classify(source),
                    scan: scan(source),
                    danger: danger.iter().map(|label| defang(label)).collect(),
                    cwd: defang(&cwd.display().to_string()),
                    root: *root,
                    interactive: *interactive,
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
fn size_delta(delta: i64) -> String {
    match delta {
        0 => "the same number of bytes".to_string(),
        delta if delta > 0 => format!("{delta} bytes larger"),
        delta => format!("{} bytes smaller", -delta),
    }
}

/// How many of the rows are marked as changed.
pub fn changed_rows(rows: &[Row]) -> usize {
    rows.iter().filter(|row| row.changed()).count()
}

// ---- which of the two diff views ------------------------------------------

/// How a diff is being drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffView {
    /// Two columns: the file on the left, what replaces it on the right.
    SideBySide,
    /// One column, `-`/`+` marked, the current file's form first. What a diff
    /// falls back to when two columns cannot hold it.
    Unified,
}

/// The width of the widest line either column would have to draw, in
/// characters.
///
/// Characters and not pixels, and the count is exact rather than an estimate.
/// Everything that reaches the screen from a diff line does so as
/// [`Span::display_text`]: a plain span is U+0020..=U+007E because
/// [`classify`] chips everything else, and every chip label is ASCII too. So
/// a drawn diff line is ASCII in a monospace font, where one character is one
/// advance and the sum of the counts is the width.
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
    let spans = if terminator { side.spans() } else { side.content_spans() };
    spans.iter().map(|span| span.display_text().chars().count()).sum()
}

/// How many characters one of the two columns holds, in a pane that holds
/// `pane` of them.
///
/// Saturating rather than signed: a pane too narrow for its own furniture
/// holds no column at all, and that is a reason to fall back rather than a
/// negative number to propagate.
fn column_chars(pane: usize) -> usize {
    pane.saturating_sub(2 * GUTTER_CHARS + GAP_CHARS) / 2
}

/// Two columns only when *every* line fits one of them whole.
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
/// whole file to the unified view, and the caption says so with the number in
/// it, so the reader can widen the window and watch it flip back.
pub fn diff_view(longest: usize, column: usize) -> DiffView {
    if column > 0 && longest <= column { DiffView::SideBySide } else { DiffView::Unified }
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
struct Palette {
    text: Color32,
    quiet: Color32,
    danger: Color32,
    warn: Color32,
    chip_bg: Color32,
    separator_bg: Color32,
    value_bg: Color32,
    /// Behind a side-by-side cell for a row that side has no line on.
    ///
    /// Deliberately not the faint background the chips and notes sit on: a
    /// gap has to be distinguishable from a line whose content happens to be
    /// empty, and if the two tints matched, the only difference on screen
    /// would be a missing `-` or `+` in a gutter. It is a tint and not a
    /// colour with meaning — nothing is wrong with a gap.
    gap_bg: Color32,
}

impl Palette {
    fn of(ui: &Ui) -> Palette {
        let visuals = ui.visuals();
        Palette {
            text: visuals.text_color(),
            quiet: visuals.weak_text_color(),
            danger: visuals.error_fg_color,
            warn: visuals.warn_fg_color,
            chip_bg: visuals.code_bg_color,
            separator_bg: visuals.faint_bg_color,
            value_bg: visuals.faint_bg_color,
            gap_bg: visuals.extreme_bg_color,
        }
    }
}

/// The agent's two lines, above everything.
///
/// Drawn through [`classify`], which is more than the protocol requires: they
/// arrive defanged, so nothing dangerous is left in them, but a chip is a
/// label a reader can see and a defanged string has already lost the
/// difference between a label the agent wrote and one hatch substituted.
/// Classifying what arrives puts every remaining oddity in a box that reads
/// as hatch's own voice.
pub fn draw_headline(ui: &mut Ui, title: &str, reason: &str) {
    egui::ScrollArea::vertical()
        .id_salt("hatch-headline")
        .max_height(ui.available_height() * HEADLINE_SHARE)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            draw_spans(ui, &classify(title), Weight::Heading);
            ui.add_space(4.0);
            draw_spans(ui, &classify(reason), Weight::Body);
        });
}

/// Everything below the headline and above the buttons.
pub fn draw_payload(ui: &mut Ui, shown: &Shown) {
    match shown {
        Shown::Command { annotated, raw, scan, danger, cwd, root, .. } => {
            draw_command_header(ui, scan, danger, cwd, *root);
            ui.separator();
            draw_command(ui, annotated, raw);
        }
        Shown::Swap { path, plan, rows, longest } => draw_swap(ui, path, plan, rows, *longest),
    }
}

/// Who it runs as, where, and how odd the text is.
fn draw_command_header(
    ui: &mut Ui,
    report: &ScanReport,
    danger: &[String],
    cwd: &str,
    root: bool,
) {
    let palette = Palette::of(ui);
    ui.horizontal_wrapped(|ui| {
        ui.label("Runs as");
        let who = RichText::new(principal(root)).strong();
        ui.label(if root { who.color(palette.danger) } else { who });
        ui.label("in");
        ui.label(RichText::new(cwd).monospace());
    });
    if let Some(summary) = scan_summary(report) {
        ui.label(RichText::new(format!("Unusual characters: {summary}")).color(palette.warn));
    }
    if !danger.is_empty() {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Marked:").color(palette.danger).strong());
            for label in danger {
                ui.label(RichText::new(label).color(palette.danger).strong());
            }
        });
    }
}

/// The two panes, in the order a suspicious reader wants them.
///
/// The space is not split evenly. The raw pane grows to as many lines as the
/// command has — a newline is drawn as `[LF]` *and* ends the line, so a
/// heredoc is a block and not one line scrolling sideways forever — and then
/// stops at [`RAW_SHARE`] and scrolls. Everything left over goes to the
/// annotated pane, which is the one a reader spends their time in.
fn draw_command(ui: &mut Ui, annotated: &Spans, raw: &Spans) {
    let palette = Palette::of(ui);

    ui.label(
        RichText::new("Exactly the text being approved — no reflow, no grouping")
            .small()
            .color(palette.quiet),
    );
    let raw_ceiling = ui.available_height() * RAW_SHARE;
    egui::Frame::group(ui.style()).show(ui, |ui| {
        egui::ScrollArea::both()
            .id_salt("hatch-raw")
            .max_height(raw_ceiling)
            .auto_shrink([false, true])
            .show(ui, |ui| draw_spans(ui, raw, Weight::Mono));
    });

    ui.add_space(4.0);
    ui.label(
        RichText::new("The same command, annotated — italics are hatch's notes, not the command")
            .small()
            .color(palette.quiet),
    );
    egui::Frame::group(ui.style()).show(ui, |ui| {
        egui::ScrollArea::vertical()
            .id_salt("hatch-annotated")
            .max_height(ui.available_height())
            .auto_shrink([false, false])
            .show(ui, |ui| draw_spans(ui, annotated, Weight::Wrapped));
    });
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
/// it fires, both cells draw their terminator, because a `[LF]` shown against
/// a cell that hides its own is not a comparison. Drawing them always instead
/// would put an orange `[LF]` on every line of the file, and a reader who has
/// learned to skip chips is a reader who will skip the one that is a bidi
/// override.
fn draw_swap(ui: &mut Ui, path: &str, plan: &SwapPlan, rows: &[Row], longest: usize) {
    let palette = Palette::of(ui);
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

    let font = font(Weight::Mono, ui.style());
    let advance = ui.ctx().fonts_mut(|fonts| fonts.glyph_width(&font, '0')).max(1.0);
    let column = column_chars((text_width(ui) / advance).floor().max(0.0) as usize);
    let view = diff_view(longest, column);
    ui.label(
        RichText::new(diff_caption(view, rows, longest, column)).small().color(palette.quiet),
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
    let row_height =
        ui.text_style_height(&egui::TextStyle::Monospace) + ui.spacing().item_spacing.y;
    egui::Frame::group(ui.style()).show(ui, |ui| match view {
        DiffView::SideBySide => {
            let size = Cells {
                gutter: advance * GUTTER_CHARS as f32,
                cell: advance * column as f32,
                gap: advance * GAP_CHARS as f32,
                height: row_height,
            };
            // Vertical only. Every line fits, so there is nothing to the
            // side to scroll to, and a horizontal bar that moved one column
            // out from under the other would break the alignment the view is
            // for.
            egui::ScrollArea::vertical()
                .id_salt("hatch-diff-columns")
                .max_height(ui.available_height())
                .auto_shrink([false, false])
                .show_rows(ui, row_height, rows.len(), |ui, range| {
                    for row in &rows[range] {
                        draw_row(ui, row, &palette, size);
                    }
                });
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
                });
        }
    });
}

/// The width a diff pane really has for text.
///
/// Subtracting the furniture rather than measuring inside the pane, because
/// the view has to be chosen before the pane that would report its own width
/// exists. Every term is something that is definitely there: the group
/// frame's border and padding on both sides, and the vertical scroll bar,
/// which a diff of any length grows.
fn text_width(ui: &Ui) -> f32 {
    let frame = egui::Frame::group(ui.style());
    let border = (frame.inner_margin.sum() + frame.outer_margin.sum()).x + 2.0 * frame.stroke.width;
    let scroll = ui.spacing().scroll.bar_width + ui.spacing().scroll.bar_inner_margin;
    (ui.available_width() - border - scroll).max(0.0)
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
/// large.
fn font(weight: Weight, style: &egui::Style) -> egui::FontId {
    match weight {
        Weight::Mono | Weight::Wrapped => egui::TextStyle::Monospace.resolve(style),
        Weight::Body => egui::TextStyle::Body.resolve(style),
        Weight::Heading => {
            let mut font = egui::TextStyle::Body.resolve(style);
            font.size = 20.0;
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
    let palette = Palette::of(ui);
    let font = font(weight, ui.style());
    let job = line_job(line, &palette, &font);
    ui.add(egui::Label::new(job).wrap_mode(wrap_mode(weight)));
}

/// One line of spans as an [`egui::text::LayoutJob`]: the text every span
/// draws, in order, each in the format its kind asks for.
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
            // bytes.
            SpanKind::Chip { .. } => egui::TextFormat {
                color: palette.warn,
                background: palette.chip_bg,
                ..plain.clone()
            },
            SpanKind::Separator => {
                egui::TextFormat { background: palette.separator_bg, ..plain.clone() }
            }
            SpanKind::Danger => egui::TextFormat { color: palette.danger, ..plain.clone() },
            SpanKind::Command | SpanKind::Variable { .. } | SpanKind::Plain => plain.clone(),
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
    fn the_header_says_root_in_words() {
        assert_eq!(principal(true), "ROOT");
        assert_eq!(principal(false), "you");
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

        // The terminator counts only where it is drawn. These two rows differ
        // only in their line ending, so both sides show `[LF]` or `[CR][LF]`.
        let endings = crate::render::diff::side_by_side("ab\n", "ab\r\n");
        assert_eq!(longest_drawn_line(&endings), 2 + "[CR][LF]".len());
    }

    #[test]
    fn an_empty_diff_has_no_widest_line_rather_than_a_wrong_one() {
        assert_eq!(longest_drawn_line(&[]), 0);
        assert_eq!(longest_drawn_line(&crate::render::diff::side_by_side("\n", "\n")), 0);
    }

    #[test]
    fn a_column_is_what_is_left_after_the_gutters_and_the_gap() {
        // 2 + 2 gutter, 2 gap, and the rest halved.
        assert_eq!(column_chars(86), 40);
        assert_eq!(column_chars(87), 40, "an odd character cannot be split between columns");
        // Narrower than its own furniture is no column at all, not a panic
        // and not a negative width.
        assert_eq!(column_chars(6), 0);
        assert_eq!(column_chars(0), 0);
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
            text: Color32::from_rgb(1, 0, 0),
            quiet: Color32::from_rgb(2, 0, 0),
            danger: Color32::from_rgb(3, 0, 0),
            warn: Color32::from_rgb(4, 0, 0),
            chip_bg: Color32::from_rgb(5, 0, 0),
            separator_bg: Color32::from_rgb(6, 0, 0),
            value_bg: Color32::from_rgb(7, 0, 0),
            gap_bg: Color32::from_rgb(8, 0, 0),
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
        assert_eq!(font(Weight::Heading, &style).size, 20.0);
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
