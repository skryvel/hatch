//! The review screen: a finished command's output, held on the window until
//! its reader says what of it the agent may have.
//!
//! See [`crate::review`] for what a filter is and what the agent is told, and
//! [`crate::protocol::DaemonMsg::Review`] for how the output gets here. This
//! module is the person's half: what they see, what they can do to it, and
//! the one frame that answers.
//!
//! # What is on the screen is what is sent
//!
//! The panes below the filters draw the text that Send sends — not the
//! output with the removed lines struck through, and not the output beside a
//! description of the filters. A reader approves the result, never the
//! transformation, for the reason a write is approved as the bytes a patch
//! produced and not as the patch. Each pane's caption says how many of its
//! lines are going, so a filter that removed everything, or nothing, is
//! visible without scrolling.
//!
//! # Redacting, and hand editing
//!
//! A filter cannot take a token out of the middle of a line that has to stay,
//! and for a long time the only answer was to lose the line or edit it by
//! hand. The redaction field does it instead — see [`crate::review::Redactor`]
//! — and a reader who can describe the thing they are hiding needs nothing
//! more. It is the third field and the last one applied, so what it works on
//! is the lines the other two left.
//!
//! Hand editing stays, for what no pattern describes: the one value that is
//! only wrong in context. The reader turns the result into text they edit,
//! and it is allowed on three conditions that keep it safe and legible:
//!
//! * **It starts from the shaped result, and the fields stop.** Two ways
//!   of shaping the same text at once would leave the reader unable to say
//!   which of them made what is on the screen. While editing the three fields
//!   are drawn but disabled, and undoing the edits gives them back as they
//!   were.
//! * **The editor is the text that is sent**, with nothing between the two.
//!   The one thing an editor draws differently from the text is a character
//!   that draws as nothing, so the caption counts those when there are any
//!   and says they go as they are. The read-only panes have no such gap: they
//!   draw every one of them by name — see [`crate::render::unicode::reveal`].
//! * **It cannot add lines.** Enter is the typing guard's and never reaches a
//!   field — see [`super::guard`] — so an edit can change or remove text and
//!   join lines, and cannot compose new ones by typing. Taking a value out
//!   does not
//!   need to, and the agent is told only that the output was edited — which
//!   is also all it is told about a redaction, for the reason
//!   [`crate::review::heading`] gives.
//!
//! # Keys
//!
//! The window is asking again, so it is [`super::guard::Keyboard::Asking`]:
//! the approve chord sends, Escape sends nothing, and both wait out the typing
//! guard, which starts again when this screen appears — see
//! [`super::guard::Guard::question_changed`]. Escape is the direction that
//! costs nothing to regret, as Deny is: nothing leaves the machine, and the
//! agent is told to ask.

use eframe::egui;

use super::guard;
use super::panes::{self, Shown};
use super::{
    Phase, PromptApp, answer, centred_row, cluster_width, paint_guard_notice, primary,
    secondary, unfocusable,
};
use crate::protocol::{self, Release};
use crate::render::unicode::{reveal, scan};
use crate::review::{self, Captured, Matcher, PatternError, Redactor, Section, Sections};

/// What the reader is told before anything else on the screen.
///
/// First, because the reader who asked for this screen is asking whether the
/// thing they were worried about has already happened, and the answer is the
/// first thing they should not have to look for.
pub const NOTHING_SENT_YET: &str =
    "Nothing has been sent to the agent yet. Below is exactly what it receives when you press Send.";

/// The label on the button that sends what is on the screen.
pub const SEND_LABEL: &str = "Send this";

/// The label on the button that sends none of it.
pub const WITHHOLD_LABEL: &str = "Send nothing";

/// What happens when the review clock runs out, said beside it.
pub const EXPIRY: &str = "When it runs out, nothing is sent.";

/// The three fields' labels.
pub const KEEP_LABEL: &str = "Keep only lines containing";
pub const DROP_LABEL: &str = "Drop lines containing";
pub const REDACT_LABEL: &str = "Redact text matching";

/// How a pattern is read, said once under the two fields.
///
/// The whole of what a reader needs to predict a match: not a pattern
/// language, and not case. The sentence exists because the other reading is
/// the one a person who knows `grep` brings with them.
pub const FILTER_HINT: &str = "Plain text, not a pattern: a dot is a dot. Case is ignored. \
     Keep applies first, then drop, then the redaction below.";

/// How a redaction is read, said under its own field.
///
/// The opposite of [`FILTER_HINT`] in the one way that matters, and the two
/// sentences sit under the fields each of them describes so that neither can
/// be read as the rule for the other. A reader who knows `grep` was told the
/// filters are not that; they have to be told this one is.
pub const REDACT_HINT: &str = "A regular expression, not plain text: a dot matches any \
     character. Case is ignored. Each match is replaced by [redacted] and the rest of its line \
     is sent.";

/// What a filter the matcher refuses does to Send.
pub const PATTERN_REFUSED: &str =
    "A filter is too long, or there are too many: nothing can be sent until it is shorter.";

/// What a redaction the `regex` crate would not build does to Send, said with
/// the crate's own reason after it.
pub const REDACTION_REFUSED: &str = "That redaction cannot be used, so nothing can be sent:";

/// What the reader is told about a field that stopped Send.
///
/// A redaction says why, where a filter says only that it is too big. The
/// difference is that a redaction is a language a person can be wrong in, and
/// "unclosed group" is the whole of what they need to fix it; a pattern over
/// the bound is already described by the bound.
pub fn refusal_said(error: &PatternError) -> String {
    match error {
        PatternError::Refused(why) => format!("{REDACTION_REFUSED} {why}."),
        _ => PATTERN_REFUSED.to_string(),
    }
}

/// The button that turns the result into text to edit, and the one that
/// turns it back.
pub const EDIT_LABEL: &str = "Edit the text by hand";
pub const UNEDIT_LABEL: &str = "Undo my edits";

/// What the reader is told while editing.
pub const EDITING_NOTE: &str = "Editing the text itself: the agent is told it was edited, not \
     what changed. The filters are set aside until you undo your edits.";

/// Which of the three fields the reader shapes the output with.
///
/// One enum for all three because everything a field does — hold what is
/// being typed, add it to a list, take one back — is the same work, and the
/// only place the three differ is what their patterns are then used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    /// Only lines containing a pattern stay.
    Keep,
    /// Lines containing a pattern go.
    Drop,
    /// What a pattern matches is replaced, and the rest of its line stays.
    Redact,
}

/// What the reader has done to the output so far.
///
/// Not a preference and not remembered: it belongs to the output on the
/// screen, and a filter carried into the next review would be shaping text
/// its reader has not read.
#[derive(Debug, Clone, Default)]
pub struct Draft {
    keep: Vec<String>,
    drop: Vec<String>,
    redact: Vec<String>,
    /// What is in each field, which counts as a pattern as it is typed: the
    /// result on the screen is the result of what the reader can see in the
    /// fields, not of what they have confirmed.
    keep_field: String,
    drop_field: String,
    redact_field: String,
    /// The text as the reader has edited it, once they have started to.
    edits: Option<Sections<String>>,
}

impl Draft {
    /// The patterns one filter holds, the field's own text included.
    pub fn patterns(&self, filter: Filter) -> Vec<String> {
        let (added, field) = match filter {
            Filter::Keep => (&self.keep, &self.keep_field),
            Filter::Drop => (&self.drop, &self.drop_field),
            Filter::Redact => (&self.redact, &self.redact_field),
        };
        review::meaningful(&added.iter().chain([field]).collect::<Vec<_>>())
    }

    /// The field one filter is typed into.
    pub fn field(&mut self, filter: Filter) -> &mut String {
        match filter {
            Filter::Keep => &mut self.keep_field,
            Filter::Drop => &mut self.drop_field,
            Filter::Redact => &mut self.redact_field,
        }
    }

    /// The patterns already added to one filter, without its field.
    pub fn added(&self, filter: Filter) -> &[String] {
        match filter {
            Filter::Keep => &self.keep,
            Filter::Drop => &self.drop,
            Filter::Redact => &self.redact,
        }
    }

    /// Move the field's text into the filter's list, so another can be typed.
    ///
    /// Nothing about the result changes: the field already counted.
    pub fn add(&mut self, filter: Filter) {
        let text = std::mem::take(self.field(filter));
        if text.trim().is_empty() {
            return;
        }
        match filter {
            Filter::Keep => self.keep.push(text),
            Filter::Drop => self.drop.push(text),
            Filter::Redact => self.redact.push(text),
        }
    }

    /// Take one added pattern back out.
    pub fn remove(&mut self, filter: Filter, index: usize) {
        let list = match filter {
            Filter::Keep => &mut self.keep,
            Filter::Drop => &mut self.drop,
            Filter::Redact => &mut self.redact,
        };
        if index < list.len() {
            list.remove(index);
        }
    }

    /// Whether the reader is editing the text rather than filtering it.
    pub fn editing(&self) -> bool {
        self.edits.is_some()
    }

    /// The output as all three fields leave it, with how much each section's
    /// redactions did.
    ///
    /// Keep and drop choose the lines, and the redaction is applied to what
    /// they left — the order [`FILTER_HINT`] states, and the only one in
    /// which each field means what it says: lines are chosen by what they
    /// hold, so a redaction that ran first would hide a line from the filter
    /// aimed at it.
    ///
    /// # Errors
    ///
    /// A pattern any of the three refuses; see [`Matcher::new`] and
    /// [`Redactor::new`]. Nothing is sent while one stands, rather than
    /// something other than what the fields say.
    fn shaped(
        &self,
        output: &Sections<Captured>,
    ) -> Result<Sections<review::Redacted>, PatternError> {
        let keep = Matcher::new(&self.patterns(Filter::Keep))?;
        let drop = Matcher::new(&self.patterns(Filter::Drop))?;
        let redactor = Redactor::new(&self.patterns(Filter::Redact))?;
        Ok(output.map(|_, captured| {
            review::redact(&review::filter(&captured.text, &keep, &drop), &redactor)
        }))
    }

    /// The output as the fields leave it.
    ///
    /// # Errors
    ///
    /// As [`Draft::shaped`].
    pub fn filtered(&self, output: &Sections<Captured>) -> Result<Sections<String>, PatternError> {
        Ok(self.shaped(output)?.map(|_, redacted| redacted.text.clone()))
    }

    /// How many lines of each section a redaction changed, or `None` when
    /// there is nothing to say about one: no redaction typed, or an edit
    /// under way with the fields set aside.
    ///
    /// On the screen, never in the answer. See [`review::Redacted::lines`]
    /// for why a reader needs it: a pattern that matched nothing leaves a
    /// result identical to one with no redaction on it. Worked out a second
    /// time rather than carried out of [`Draft::result`], which keeps the
    /// result one thing; the pass is over at most hatch's output cap and only
    /// happens while a redaction is typed.
    pub fn redacted(&self, output: &Sections<Captured>) -> Option<Sections<usize>> {
        if self.editing() || self.patterns(Filter::Redact).is_empty() {
            return None;
        }
        Some(self.shaped(output).ok()?.map(|_, redacted| redacted.lines))
    }

    /// What Send would send now.
    ///
    /// # Errors
    ///
    /// As [`Draft::filtered`], and only while not editing: an edit is text,
    /// and text cannot be refused.
    pub fn result(&self, output: &Sections<Captured>) -> Result<Sections<String>, PatternError> {
        match &self.edits {
            Some(edits) => Ok(edits.clone()),
            None => self.filtered(output),
        }
    }

    /// Start editing, from what the three fields leave — redactions included,
    /// so an edit never reveals what one of them took. Does nothing while a
    /// pattern is refused, since there is then no result to start from.
    pub fn start_editing(&mut self, output: &Sections<Captured>) {
        if let Ok(filtered) = self.filtered(output) {
            self.edits = Some(filtered);
        }
    }

    /// Throw the edits away and give the filters back.
    pub fn stop_editing(&mut self) {
        self.edits = None;
    }

    /// The text being edited, one section of it, while editing.
    pub fn edited(&mut self, section: Section) -> Option<&mut String> {
        match (self.edits.as_mut()?, section) {
            (Sections::Streams { stdout, .. }, Section::Stdout) => Some(stdout),
            (Sections::Streams { stderr, .. }, Section::Stderr) => Some(stderr),
            (Sections::Transcript { transcript }, Section::Transcript) => Some(transcript),
            _ => None,
        }
    }

    /// The answer Send gives, or `None` while there is nothing it could send.
    ///
    /// The keep patterns go with it always, edited or not. They are the one
    /// claim the agent may hear, and the daemon repeats them only where the
    /// text bears them out — see [`crate::review::Trimmed::of`] — so a claim
    /// an edit has made untrue is not repeated.
    pub fn release(&self, output: &Sections<Captured>) -> Option<Release> {
        let result = self.result(output).ok()?;
        Some(Release::Send { output: result, kept: self.patterns(Filter::Keep) })
    }
}

impl PromptApp {
    /// Send what is on the screen, if the window is asking and there is
    /// something Send could send.
    ///
    /// One method for the button and the chord, for the reason
    /// [`PromptApp::approval`] is one.
    pub(super) fn send_review(&mut self) {
        let Some(review) = self.state.review() else { return };
        let Some(release) = self.draft.release(&review.output) else { return };
        let frame = self.state.release(release);
        answer(&mut self.out, &mut self.state, frame);
    }

    /// Send none of it.
    pub(super) fn withhold_review(&mut self) {
        let frame = self.state.release(Release::Withhold);
        answer(&mut self.out, &mut self.state, frame);
    }

    /// The review screen's body: what ran, the filters, and the output as it
    /// will go.
    pub(super) fn reviewer(&mut self, ui: &mut egui::Ui, title: &str) {
        let Some(review) = self.state.review().cloned() else { return };
        let quiet = ui.visuals().weak_text_color();

        // What ran, named once, as the viewer names it: the question is about
        // this command's output, and output nobody can place is output the
        // reader has to remember the provenance of.
        ui.horizontal_wrapped(|ui| {
            if self.state.runs_as_root() {
                panes::draw_root_mark(ui);
            }
            ui.label(egui::RichText::new(title).strong());
        });
        if let Some(Shown::Command { raw, .. }) = self.state.shown() {
            ui.label(egui::RichText::new(protocol::display_line(raw)).monospace().small().color(quiet));
        }
        ui.label(egui::RichText::new(NOTHING_SENT_YET).strong());
        ui.separator();

        let editing = self.draft.editing();
        ui.add_enabled_ui(!editing, |ui| {
            let label_width = [KEEP_LABEL, DROP_LABEL, REDACT_LABEL]
                .iter()
                .map(|label| super::text_width(ui, label, egui::TextStyle::Body))
                .fold(0.0, f32::max);
            // The two that choose lines, under the sentence that says how
            // their patterns are read; then the one that rewrites them, under
            // the sentence that says how its own are. Each rule sits under the
            // fields it governs, because the two rules are opposites.
            for filter in [Filter::Keep, Filter::Drop] {
                self.filter_row(ui, filter, label_width);
            }
            ui.label(egui::RichText::new(FILTER_HINT).small().color(quiet));
            self.filter_row(ui, Filter::Redact, label_width);
            ui.label(egui::RichText::new(REDACT_HINT).small().color(quiet));
        });
        let result = self.draft.result(&review.output);
        if let Err(error) = &result {
            ui.label(
                egui::RichText::new(refusal_said(error))
                    .strong()
                    .color(ui.visuals().error_fg_color),
            );
        }
        if editing {
            ui.label(egui::RichText::new(EDITING_NOTE).small().color(ui.visuals().warn_fg_color));
        }
        ui.separator();

        let released: Option<Vec<String>> =
            result.ok().map(|sections| sections.iter().map(|(_, text)| text.clone()).collect());
        let redacted: Option<Vec<usize>> = self
            .draft
            .redacted(&review.output)
            .map(|counts| counts.iter().map(|(_, lines)| *lines).collect());
        let captured: Vec<(Section, Captured)> =
            review.output.iter().map(|(section, captured)| (section, captured.clone())).collect();
        let count = captured.len();
        ui.columns(count, |columns| {
            for (index, (column, (section, captured))) in
                columns.iter_mut().zip(&captured).enumerate()
            {
                let sent = released.as_ref().map(|texts| texts[index].as_str());
                let changed = redacted.as_ref().map(|counts| counts[index]);
                self.section_pane(column, *section, captured, sent, changed);
            }
        });
    }

    /// One filter: its label, its field, the patterns already added to it.
    fn filter_row(&mut self, ui: &mut egui::Ui, filter: Filter, label_width: f32) {
        let label = match filter {
            Filter::Keep => KEEP_LABEL,
            Filter::Drop => DROP_LABEL,
            Filter::Redact => REDACT_LABEL,
        };
        let mut removed = None;
        let mut add = false;
        ui.horizontal_wrapped(|ui| {
            // Right-aligned in a column as wide as the longer label, so the
            // two fields start at one edge and each label is read against
            // the field it names.
            ui.allocate_ui_with_layout(
                egui::vec2(label_width, ui.spacing().interact_size.y),
                egui::Layout::right_to_left(egui::Align::Center),
                |ui| ui.label(label),
            );
            ui.add(
                egui::TextEdit::singleline(self.draft.field(filter))
                    .desired_width(12.0 * ui.text_style_height(&egui::TextStyle::Body))
                    .char_limit(review::MAX_PATTERN_BYTES),
            );
            let typed = !self.draft.field(filter).trim().is_empty();
            add = ui.add_enabled(typed, egui::Button::new("Add another").sense(egui::Sense::CLICK)).clicked();
            for (index, pattern) in self.draft.added(filter).iter().enumerate() {
                // The pattern the reader typed, and a way to take it back. A
                // button of its own rather than a label, so the thing to
                // press to undo it is the thing that names it.
                if secondary(ui, &format!("{pattern}  ×")).clicked() {
                    removed = Some(index);
                }
            }
        });
        if add {
            self.draft.add(filter);
        }
        if let Some(index) = removed {
            self.draft.remove(filter, index);
        }
    }

    /// One section of the output: how much of it is going, and the text that
    /// is — or the text being edited, while the reader edits.
    ///
    /// `sent` is `None` while a pattern is refused, when nothing is going.
    /// `redacted` is how many of its lines a redaction changed, and `None`
    /// when there is no redaction to report on — see [`Draft::redacted`].
    fn section_pane(
        &mut self,
        ui: &mut egui::Ui,
        section: Section,
        captured: &Captured,
        sent: Option<&str>,
        redacted: Option<usize>,
    ) {
        let name = section.name();
        let total = review::lines(&captured.text).count();
        let mut caption = match (self.draft.editing(), sent) {
            (true, _) => format!("{name} — edited by hand"),
            (false, Some(sent)) => {
                let going = review::lines(sent).count();
                let mut said = format!("{name} — {going} of {total} lines will be sent");
                // Said even when it is none, which is the number the reader
                // most needs: a redaction that matched nothing leaves a screen
                // identical to one with no redaction typed, and "0 redacted"
                // is the only thing that tells them it missed.
                if let Some(lines) = redacted {
                    said.push_str(&format!(", {lines} of them redacted"));
                }
                said
            }
            (false, None) => format!("{name} — nothing can be sent yet"),
        };
        if captured.truncated {
            caption.push_str("; hatch's output cap cut it short");
        }
        ui.label(egui::RichText::new(caption).small().strong());
        // Above the pane and not under the editor, where a pane that takes
        // the height it is given would push it off the window: this is the
        // one thing the editor draws differently from what is sent, and it
        // has to be on the screen for that to be a disclosure.
        let hidden = self.draft.edited(section).map_or(0, |text| scan(text).invisible);
        if hidden > 0 {
            ui.label(
                egui::RichText::new(format!(
                    "{hidden} character(s) in the text below draw as nothing, and are sent as \
                     they are."
                ))
                .small()
                .color(ui.visuals().warn_fg_color),
            );
        }

        let row = ui.text_style_height(&egui::TextStyle::Monospace);
        panes::pane_frame(ui).show(ui, |ui| {
            ui.set_min_height(ui.available_height());
            let scroll = egui::ScrollArea::both()
                .id_salt(("hatch-review", name))
                .auto_shrink([false, false])
                // A bar across an output that fits is a control for nothing,
                // drawn under the text of every short review.
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded);
            if let Some(text) = self.draft.edited(section) {
                scroll.show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(text)
                            .code_editor()
                            .desired_width(f32::INFINITY),
                    );
                });
                return;
            }
            let Some(sent) = sent else { return };
            if sent.is_empty() {
                let said = match captured.text.is_empty() {
                    true => "It printed nothing here.",
                    false => "None of this will be sent.",
                };
                ui.label(egui::RichText::new(said).color(ui.visuals().weak_text_color()));
                return;
            }
            // Revealed line by line, so a character that would draw as
            // nothing or reorder its line is on the screen by name — see
            // `reveal` — and only the rows in view are laid out, because a
            // capture is up to a quarter of a megabyte and this is redrawn
            // on every keystroke in a filter.
            let lines: Vec<&str> = review::lines(sent).collect();
            scroll.show_rows(ui, row, lines.len(), |ui, range| {
                for line in &lines[range] {
                    let bare = line.strip_suffix('\n').unwrap_or(line);
                    ui.add(egui::Label::new(egui::RichText::new(reveal(bare)).monospace()).extend());
                }
            });
        });
    }

    /// Everything below the review: how the run ended, the clock, and the
    /// buttons that answer.
    ///
    /// The buttons are the verdict buttons' shape and size, in the verdict
    /// buttons' place, disabled while the typing guard is shut and with the
    /// same sentence painted across them: this is a decision in the same
    /// window, and a keystroke meant for another window must not make it.
    pub(super) fn review_row(&mut self, ui: &mut egui::Ui, guard_open: bool) {
        let visuals = ui.visuals().clone();
        let runs = self.runs();
        ui.vertical_centered(|ui| {
            if let Some(outcome) = self.state.outcome() {
                let (text, clean) = panes::outcome_text(outcome, runs);
                let colour = if clean { visuals.weak_text_color() } else { visuals.error_fg_color };
                ui.label(egui::RichText::new(text).color(colour).strong());
            }
            if let Some(left) = self.state.review_seconds_remaining(chrono::Utc::now()) {
                let colour = match panes::urgency(left) {
                    panes::Urgency::Calm => visuals.weak_text_color(),
                    panes::Urgency::Soon | panes::Urgency::Imminent => visuals.warn_fg_color,
                };
                ui.label(
                    egui::RichText::new(format!("{} — {EXPIRY}", panes::review_countdown_text(left)))
                        .color(colour),
                );
            }
        });
        ui.add_space(6.0);

        let sendable = self
            .state
            .review()
            .is_some_and(|review| self.draft.release(&review.output).is_some());
        let editing = self.draft.editing();
        let width = cluster_width(ui);
        let (mut send, mut withhold, mut edit) = (false, false, false);
        let buttons = ui
            .add_enabled_ui(guard_open, |ui| {
                let row = ui
                    .vertical_centered(|ui| {
                        centred_row(ui, width, |ui| {
                            send = ui
                                .add_enabled_ui(sendable, |ui| {
                                    unfocusable(ui, primary(ui, SEND_LABEL, guard::APPROVE_CHORD))
                                })
                                .inner
                                .clicked();
                            ui.add_space(super::PRIMARY_GAP);
                            let nothing = unfocusable(ui, primary(ui, WITHHOLD_LABEL, guard::DENY_CHORD));
                            withhold = nothing.clicked();
                            nothing.rect
                        })
                    })
                    .inner;
                ui.add_space(4.0);
                ui.vertical_centered(|ui| {
                    let label = if editing { UNEDIT_LABEL } else { EDIT_LABEL };
                    edit = secondary(ui, label).clicked();
                });
                row
            })
            .inner;
        if !guard_open {
            let over = egui::Rect::from_center_size(
                egui::pos2(ui.max_rect().center().x, buttons.center().y),
                egui::vec2(width, buttons.height()),
            );
            paint_guard_notice(ui, over);
        }

        if send {
            self.send_review();
        }
        if withhold {
            self.withhold_review();
        }
        if edit && self.state.phase() == Phase::Reviewing {
            match editing {
                true => self.draft.stop_editing(),
                false => {
                    if let Some(review) = self.state.review() {
                        let output = review.output.clone();
                        self.draft.start_editing(&output);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output() -> Sections<Captured> {
        Sections::Streams {
            stdout: Captured { text: "ok: one\ntoken=hunter2\nerror: two\n".to_string(), truncated: false },
            stderr: Captured { text: "error: on stderr\n".to_string(), truncated: false },
        }
    }

    fn stdout_of(sections: &Sections<String>) -> &str {
        match sections {
            Sections::Streams { stdout, .. } => stdout,
            Sections::Transcript { transcript } => transcript,
        }
    }

    #[test]
    fn an_untouched_draft_sends_the_output_as_it_was_captured() {
        let draft = Draft::default();
        let Some(Release::Send { output: sent, kept }) = draft.release(&output()) else {
            panic!("an untouched draft could not be sent");
        };
        assert_eq!(sent, output().map(|_, captured| captured.text.clone()));
        assert!(kept.is_empty());
    }

    #[test]
    fn what_is_being_typed_counts_before_it_is_added() {
        // The result on the screen follows the field, not a button: a filter
        // the reader can see and that did nothing until confirmed would be a
        // screen showing a result other than the one Send sends.
        let mut draft = Draft::default();
        draft.field(Filter::Drop).push_str("TOKEN");
        let result = draft.result(&output()).unwrap();
        assert_eq!(stdout_of(&result), "ok: one\nerror: two\n");

        draft.add(Filter::Drop);
        assert!(draft.field(Filter::Drop).is_empty());
        assert_eq!(draft.added(Filter::Drop), ["TOKEN".to_string()]);
        assert_eq!(draft.result(&output()).unwrap(), result, "adding it changed what goes");

        draft.remove(Filter::Drop, 0);
        assert!(stdout_of(&draft.result(&output()).unwrap()).contains("hunter2"));
    }

    #[test]
    fn a_keep_pattern_goes_with_the_answer_and_a_drop_pattern_never_does() {
        let mut draft = Draft::default();
        draft.field(Filter::Keep).push_str("error");
        draft.add(Filter::Keep);
        draft.field(Filter::Drop).push_str("on std");
        let Some(Release::Send { output: sent, kept }) = draft.release(&output()) else {
            panic!("no answer");
        };
        assert_eq!(kept, ["error".to_string()]);
        assert_eq!(stdout_of(&sent), "error: two\n");
        let Sections::Streams { stderr, .. } = &sent else { panic!() };
        assert!(stderr.is_empty(), "the drop filter did not reach stderr");
        let encoded = crate::protocol::encode(&Release::Send { output: sent.clone(), kept }).unwrap();
        assert!(!encoded.contains("on std"), "the drop pattern rode along: {encoded}");
    }

    #[test]
    fn editing_starts_from_the_filtered_result_and_the_filters_stop_until_it_is_undone() {
        let mut draft = Draft::default();
        draft.field(Filter::Drop).push_str("ok:");
        draft.start_editing(&output());
        assert!(draft.editing());
        let text = draft.edited(Section::Stdout).expect("stdout is being edited");
        assert_eq!(text, "token=hunter2\nerror: two\n", "editing did not start from the filtered text");
        *text = text.replace("hunter2", "…");

        // A filter typed while editing changes nothing that goes.
        draft.field(Filter::Keep).push_str("nothing matches this");
        assert_eq!(stdout_of(&draft.result(&output()).unwrap()), "token=…\nerror: two\n");

        draft.stop_editing();
        assert!(!draft.editing());
        assert_eq!(draft.result(&output()).unwrap().iter().map(|(_, t)| t.len()).sum::<usize>(), 0);
    }

    #[test]
    fn a_redaction_leaves_the_rest_of_the_line_and_never_rides_along() {
        // The line the filters could only have lost whole goes, with the one
        // thing on it that could not go taken out.
        let mut draft = Draft::default();
        draft.field(Filter::Redact).push_str("hunter\\d");
        let Some(Release::Send { output: sent, kept }) = draft.release(&output()) else {
            panic!("no answer");
        };
        assert_eq!(stdout_of(&sent), "ok: one\ntoken=[redacted]\nerror: two\n");
        assert!(kept.is_empty(), "a redaction was claimed as a keep pattern");
        let encoded =
            crate::protocol::encode(&Release::Send { output: sent.clone(), kept }).unwrap();
        assert!(!encoded.contains("hunter"), "the redaction or its subject rode along: {encoded}");
    }

    #[test]
    fn a_redaction_applies_to_what_the_filters_left() {
        // Lines are chosen first and rewritten second. A redaction that ran
        // first would have hidden `token` from the keep filter aimed at it.
        let mut draft = Draft::default();
        draft.field(Filter::Keep).push_str("token");
        draft.add(Filter::Keep);
        draft.field(Filter::Redact).push_str("=.*");
        assert_eq!(stdout_of(&draft.result(&output()).unwrap()), "token[redacted]\n");
    }

    #[test]
    fn the_caption_is_told_how_many_lines_a_redaction_changed() {
        let mut draft = Draft::default();
        assert!(draft.redacted(&output()).is_none(), "counted with no redaction typed");

        draft.field(Filter::Redact).push_str("hunter\\d");
        let Some(Sections::Streams { stdout, stderr }) = draft.redacted(&output()) else {
            panic!("no counts");
        };
        assert_eq!((stdout, stderr), (1, 0));

        // The case the count exists for: a pattern that matched nothing
        // leaves a screen identical to one with no redaction on it.
        draft.field(Filter::Redact).clear();
        draft.field(Filter::Redact).push_str("nothing-like-this");
        let Some(Sections::Streams { stdout, .. }) = draft.redacted(&output()) else {
            panic!("no counts");
        };
        assert_eq!(stdout, 0);
        assert_eq!(draft.result(&output()).unwrap(), output().map(|_, c| c.text.clone()));

        // While editing there is nothing to count: the fields are set aside.
        draft.start_editing(&output());
        assert!(draft.redacted(&output()).is_none());
    }

    #[test]
    fn editing_starts_from_the_redacted_text() {
        // An edit that started from the unredacted text would put the token
        // back on the screen and into what Send sends.
        let mut draft = Draft::default();
        draft.field(Filter::Redact).push_str("hunter\\d");
        draft.start_editing(&output());
        let text = draft.edited(Section::Stdout).expect("stdout is being edited");
        assert_eq!(text, "ok: one\ntoken=[redacted]\nerror: two\n");
    }

    #[test]
    fn a_redaction_that_will_not_build_leaves_nothing_to_send_and_says_why() {
        let mut draft = Draft::default();
        draft.field(Filter::Redact).push_str("(unclosed");
        assert_eq!(draft.release(&output()), None);
        let Err(error) = draft.result(&output()) else {
            panic!("an unclosed group was accepted");
        };
        let said = refusal_said(&error);
        assert!(said.starts_with(REDACTION_REFUSED), "{said}");
        assert!(said.len() > REDACTION_REFUSED.len(), "no reason was given: {said}");
        assert_eq!(refusal_said(&PatternError::TooLong), PATTERN_REFUSED);
        draft.start_editing(&output());
        assert!(!draft.editing(), "an edit started from a result that does not exist");
    }

    #[test]
    fn a_refused_filter_leaves_nothing_to_send_rather_than_something_else() {
        let mut draft = Draft::default();
        draft.field(Filter::Drop).push_str(&"é".repeat(review::MAX_PATTERN_BYTES));
        assert_eq!(draft.release(&output()), None);
        draft.start_editing(&output());
        assert!(!draft.editing(), "an edit started from a result that does not exist");
    }
}
