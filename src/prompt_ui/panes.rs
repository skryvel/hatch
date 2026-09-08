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
    /// A file swap. The side-by-side view is not built yet; see
    /// [`draw_swap`] for what stands in its place and why it is not nothing.
    Swap {
        /// The file, defanged for drawing.
        path: String,
        /// Where the bytes land.
        plan: SwapPlan,
        /// The diff, rebuilt through the real builder.
        rows: Vec<Row>,
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
            Payload::Swap { path, plan, .. } => Ok(Shown::Swap {
                path: defang(&path.display().to_string()),
                plan: plan.clone(),
                rows: payload.rows()?,
            }),
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
        Shown::Swap { path, plan, rows } => draw_swap(ui, path, plan, rows),
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
/// The space is not split between them. The raw pane is exactly one line
/// high whatever the command is — nothing in it can start a new line, since
/// a newline is a chip like any other character that is not drawn as itself
/// — so it takes that line and scrolls sideways, and everything left over
/// goes to the annotated pane, which is the one that grows.
fn draw_command(ui: &mut Ui, annotated: &Spans, raw: &Spans) {
    let palette = Palette::of(ui);

    ui.label(
        RichText::new("Exactly the text being approved — no reflow, no grouping")
            .small()
            .color(palette.quiet),
    );
    egui::Frame::group(ui.style()).show(ui, |ui| {
        egui::ScrollArea::both()
            .id_salt("hatch-raw")
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

/// What a `swap_file` request looks like until the side-by-side view exists.
///
/// Not an empty pane, and not a summary either. An empty pane in this window
/// reads as "nothing changes", which is the one thing it must never say by
/// accident; a summary — "12 lines change" — reads as a fact the reader has
/// checked when they have checked nothing. So every line is drawn, one under
/// the other, through exactly the same span machinery the command panes use:
/// chips and all, with the current file's form of a changed line marked `-`
/// and the proposed one `+`. It is a worse view than the side-by-side one
/// will be, and it is a view: approving from it is approving something that
/// was drawn.
///
/// A line terminator is drawn only where the two sides' terminators differ —
/// a `\n` that became a `\r\n`, or a last line that lost its newline. Hiding
/// that always would show two identical-looking lines for a change that is
/// only a change of line ending, which is a rendering that lies about the
/// bytes; drawing it always puts an orange `[LF]` on every line of the file,
/// and a reader who has learned to skip chips is a reader who will skip the
/// one that is a bidi override.
fn draw_swap(ui: &mut Ui, path: &str, plan: &SwapPlan, rows: &[Row]) {
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

    let lines = diff_lines(rows);
    ui.label(
        RichText::new(format!(
            "{} of {} lines change. Side-by-side is not built yet; every line is below, the \
             current file's form first.",
            changed_rows(rows),
            rows.len()
        ))
        .small()
        .color(palette.quiet),
    );
    // `show_rows` and not a loop: a 256 KB replacement is a quarter of a
    // million rows, and a pane that laid all of them out per frame would be
    // a window nobody can answer in time — which the daemon resolves as a
    // denial, but by making the machine unusable rather than by anyone
    // deciding anything. Every drawn line is one line of monospace, so the
    // uniform height the API wants is a fact rather than an assumption.
    let row_height =
        ui.text_style_height(&egui::TextStyle::Monospace) + ui.spacing().item_spacing.y;
    egui::Frame::group(ui.style()).show(ui, |ui| {
        egui::ScrollArea::both()
            .id_salt("hatch-diff")
            .max_height(ui.available_height())
            .auto_shrink([false, false])
            .show_rows(ui, row_height, lines.len(), |ui, range| {
                for line in &lines[range] {
                    draw_diff_line(ui, line, palette.danger, palette.warn);
                }
            });
    });
}

/// One line of the stand-in diff: which side it came from, and how it is
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

/// Flatten the rows into the lines that are drawn, in order.
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

/// One drawn line of the stand-in diff.
fn draw_diff_line(ui: &mut Ui, line: &DiffLine<'_>, removed: Color32, added: Color32) {
    let quiet = ui.visuals().weak_text_color();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        let gutter = RichText::new(format!("{} ", line.marker)).monospace();
        ui.label(if line.changed {
            gutter.color(if line.marker == "-" { removed } else { added }).strong()
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

    /// The base text this weight draws a span's own text as.
    fn text(self, text: &str) -> RichText {
        match self {
            Weight::Mono | Weight::Wrapped => RichText::new(text).monospace(),
            Weight::Body => RichText::new(text),
            Weight::Heading => RichText::new(text).size(20.0),
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

/// One drawn line of spans.
///
/// Item spacing goes to zero for the whole line, and that is not cosmetic:
/// egui's default gap between widgets would appear between two adjacent
/// spans as a space that is not in the command. Every gap on screen inside a
/// pane is a gap that is in the text, except the padding a chip or a note
/// carries with it, and those are coloured so they cannot be read as
/// whitespace.
fn draw_line(ui: &mut Ui, line: &[Span], weight: Weight) {
    let draw = |ui: &mut Ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        let palette = Palette::of(ui);
        for span in line {
            draw_span(ui, span, weight, &palette);
        }
    };
    if weight.wraps() {
        ui.horizontal_wrapped(draw);
    } else {
        ui.horizontal(draw);
    }
}

/// One span, as itself or as the chip that stands for it.
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
fn draw_span(ui: &mut Ui, span: &Span, weight: Weight, palette: &Palette) {
    let text = weight.text(&span.display_text());
    let label = match span.kind() {
        // Chips are hatch's word, not the agent's: a background is what says
        // "this box is a substitution", and the label inside it is the only
        // text in either pane that is not the source's own bytes.
        SpanKind::Chip { .. } => text.color(palette.warn).background_color(palette.chip_bg),
        SpanKind::Separator => text.color(palette.text).background_color(palette.separator_bg),
        SpanKind::Command => text.color(palette.text).strong(),
        SpanKind::Danger => text.color(palette.danger).strong(),
        SpanKind::Variable { .. } | SpanKind::Plain => text.color(palette.text),
    };
    ui.add(egui::Label::new(label).wrap_mode(wrap_mode(weight)));

    // The value goes beside the reference and never in place of it: the
    // reference is what was approved, and a window that showed `/home/user`
    // where the command says `$HOME` would have quietly replaced the text it
    // is asking about. Italic, coloured and boxed, so nothing about it reads
    // as part of the command.
    if let Some((_, resolved)) = span.variable() {
        let note = match resolved {
            Some(value) => format!(" → {} ", defang(value)),
            None => " → unset ".to_string(),
        };
        ui.add(
            egui::Label::new(
                weight
                    .text(&note)
                    .italics()
                    .color(palette.quiet)
                    .background_color(palette.value_bg),
            )
            .wrap_mode(wrap_mode(weight)),
        );
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
