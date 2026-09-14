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
//! # Hand editing, and what makes it fit
//!
//! A filter cannot take a password out of the middle of a line that has to
//! stay. So the reader can turn the result into text they edit, and it is
//! allowed on three conditions that keep it safe and legible:
//!
//! * **It starts from the filtered result, and the filters stop.** Two ways
//!   of shaping the same text at once would leave the reader unable to say
//!   which of them made what is on the screen. While editing the filters are
//!   drawn but disabled, and undoing the edits gives them back as they were.
//! * **The editor is the text that is sent**, with nothing between the two.
//!   The one thing an editor draws differently from the text is a character
//!   that draws as nothing, so the caption counts those when there are any
//!   and says they go as they are. The read-only panes have no such gap: they
//!   draw every one of them by name — see [`crate::render::unicode::reveal`].
//! * **It cannot add lines.** Enter is the typing guard's and never reaches a
//!   field — see [`super::guard`] — so an edit can change or remove text and
//!   join lines, and cannot compose new ones by typing. A redaction does not
//!   need to, and the agent is told only that the output was edited.
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
use crate::review::{self, Captured, Matcher, PatternError, Section, Sections};

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

/// The two filters' labels.
pub const KEEP_LABEL: &str = "Keep only lines containing";
pub const DROP_LABEL: &str = "Drop lines containing";

/// How a pattern is read, said once under the two fields.
///
/// The whole of what a reader needs to predict a match: not a pattern
/// language, and not case. The sentence exists because the other reading is
/// the one a person who knows `grep` brings with them.
pub const FILTER_HINT: &str =
    "Plain text, not a pattern: a dot is a dot. Case is ignored. Keep applies first, then drop.";

/// What a filter the matcher refuses does to Send.
pub const PATTERN_REFUSED: &str =
    "A filter is too long, or there are too many: nothing can be sent until it is shorter.";

/// The button that turns the result into text to edit, and the one that
/// turns it back.
pub const EDIT_LABEL: &str = "Edit the text by hand";
pub const UNEDIT_LABEL: &str = "Undo my edits";

/// What the reader is told while editing.
pub const EDITING_NOTE: &str = "Editing the text itself: the agent is told it was edited, not \
     what changed. The filters are set aside until you undo your edits.";

/// Which of the two filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    /// Only lines containing a pattern stay.
    Keep,
    /// Lines containing a pattern go.
    Drop,
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
    /// What is in each field, which counts as a pattern as it is typed: the
    /// result on the screen is the result of what the reader can see in the
    /// fields, not of what they have confirmed.
    keep_field: String,
    drop_field: String,
    /// The text as the reader has edited it, once they have started to.
    edits: Option<Sections<String>>,
}

impl Draft {
    /// The patterns one filter holds, the field's own text included.
    pub fn patterns(&self, filter: Filter) -> Vec<String> {
        let (added, field) = match filter {
            Filter::Keep => (&self.keep, &self.keep_field),
            Filter::Drop => (&self.drop, &self.drop_field),
        };
        review::meaningful(&added.iter().chain([field]).collect::<Vec<_>>())
    }

    /// The field one filter is typed into.
    pub fn field(&mut self, filter: Filter) -> &mut String {
        match filter {
            Filter::Keep => &mut self.keep_field,
            Filter::Drop => &mut self.drop_field,
        }
    }

    /// The patterns already added to one filter, without its field.
    pub fn added(&self, filter: Filter) -> &[String] {
        match filter {
            Filter::Keep => &self.keep,
            Filter::Drop => &self.drop,
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
        }
    }

    /// Take one added pattern back out.
    pub fn remove(&mut self, filter: Filter, index: usize) {
        let list = match filter {
            Filter::Keep => &mut self.keep,
            Filter::Drop => &mut self.drop,
        };
        if index < list.len() {
            list.remove(index);
        }
    }

    /// Whether the reader is editing the text rather than filtering it.
    pub fn editing(&self) -> bool {
        self.edits.is_some()
    }

    /// The output as the filters leave it.
    ///
    /// # Errors
    ///
    /// A filter the matcher refuses; see [`Matcher::new`]. Nothing is sent
    /// while one stands, rather than something other than what the fields say.
    pub fn filtered(&self, output: &Sections<Captured>) -> Result<Sections<String>, PatternError> {
        let keep = Matcher::new(&self.patterns(Filter::Keep))?;
        let drop = Matcher::new(&self.patterns(Filter::Drop))?;
        Ok(output.map(|_, captured| review::filter(&captured.text, &keep, &drop)))
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

    /// Start editing, from what the filters leave. Does nothing while a
    /// filter is refused, since there is then no result to start from.
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
    fn edit_of(&mut self, section: Section) -> Option<&mut String> {
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
            let label_width = [KEEP_LABEL, DROP_LABEL]
                .iter()
                .map(|label| super::text_width(ui, label, egui::TextStyle::Body))
                .fold(0.0, f32::max);
            for filter in [Filter::Keep, Filter::Drop] {
                self.filter_row(ui, filter, label_width);
            }
            ui.label(egui::RichText::new(FILTER_HINT).small().color(quiet));
        });
        let result = self.draft.result(&review.output);
        if result.is_err() {
            ui.label(
                egui::RichText::new(PATTERN_REFUSED).strong().color(ui.visuals().error_fg_color),
            );
        }
        if editing {
            ui.label(egui::RichText::new(EDITING_NOTE).small().color(ui.visuals().warn_fg_color));
        }
        ui.separator();

        let released: Option<Vec<String>> =
            result.ok().map(|sections| sections.iter().map(|(_, text)| text.clone()).collect());
        let captured: Vec<(Section, Captured)> =
            review.output.iter().map(|(section, captured)| (section, captured.clone())).collect();
        let count = captured.len();
        ui.columns(count, |columns| {
            for (index, (column, (section, captured))) in
                columns.iter_mut().zip(&captured).enumerate()
            {
                let sent = released.as_ref().map(|texts| texts[index].as_str());
                self.section_pane(column, *section, captured, sent);
            }
        });
    }

    /// One filter: its label, its field, the patterns already added to it.
    fn filter_row(&mut self, ui: &mut egui::Ui, filter: Filter, label_width: f32) {
        let label = match filter {
            Filter::Keep => KEEP_LABEL,
            Filter::Drop => DROP_LABEL,
        };
        let mut removed = None;
        let mut add = false;
        ui.horizontal_wrapped(|ui| {
            ui.add_sized(
                egui::vec2(label_width, ui.spacing().interact_size.y),
                egui::Label::new(label),
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
    /// `sent` is `None` while a filter is refused, when nothing is going.
    fn section_pane(
        &mut self,
        ui: &mut egui::Ui,
        section: Section,
        captured: &Captured,
        sent: Option<&str>,
    ) {
        let name = section.name();
        let total = review::lines(&captured.text).count();
        let mut caption = match (self.draft.editing(), sent) {
            (true, _) => format!("{name} — edited by hand"),
            (false, Some(sent)) => {
                format!("{name} — {} of {total} lines will be sent", review::lines(sent).count())
            }
            (false, None) => format!("{name} — nothing can be sent yet"),
        };
        if captured.truncated {
            caption.push_str("; hatch's output cap cut it short");
        }
        ui.label(egui::RichText::new(caption).small().strong());

        let row = ui.text_style_height(&egui::TextStyle::Monospace);
        panes::pane_frame(ui).show(ui, |ui| {
            ui.set_min_height(ui.available_height());
            let scroll = egui::ScrollArea::both()
                .id_salt(("hatch-review", name))
                .auto_shrink([false, false]);
            if let Some(text) = self.draft.edit_of(section) {
                let hidden = scan(text).invisible;
                scroll.show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(text)
                            .code_editor()
                            .desired_width(f32::INFINITY),
                    );
                });
                if hidden > 0 {
                    ui.label(
                        egui::RichText::new(format!(
                            "{hidden} character(s) in this text draw as nothing here, and are \
                             sent as they are."
                        ))
                        .small()
                        .color(ui.visuals().warn_fg_color),
                    );
                }
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
