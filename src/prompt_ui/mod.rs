//! The `hatch prompt` window: the phase machine, and the NDJSON wiring that
//! feeds it.
//!
//! One process draws one window and exits. It speaks [`crate::protocol`] on
//! its own stdin and stdout, and it owns nothing: not the clock, not the
//! rendering, not the decision to apply. What it owns is a phase — which of
//! the things a window can be at this moment — and the promise that exactly
//! one verdict leaves it.
//!
//! # The shape
//!
//! [`PromptState`] is the whole state machine and knows nothing about egui,
//! so every rule below is a test that runs without a display. The eframe app
//! around it is a drain and a draw: a reader thread turns stdin into
//! [`Incoming`] items, [`drain`] hands each of them to the state machine, and
//! the buttons hand their verdicts to [`PromptState::decide`] and
//! [`answer`] whatever comes back.
//!
//! # Exactly one verdict
//!
//! The protocol says exactly one, and no type can enforce a rule about a
//! stream. What enforces it here is that [`PromptState::decide`] is the only
//! thing that builds a [`PromptMsg::Verdict`], and it answers only in
//! [`Phase::AwaitingVerdict`] — which is a phase it leaves on the way out. A
//! double-click, a second button pressed in the same frame, and a click on a
//! window that is already running all reach a state that is no longer waiting
//! for a verdict, and get nothing to send.
//!
//! # Input
//!
//! Nothing here reads a key. Every event of every frame goes to
//! [`guard::intercept`] first, which decides what the window may act on and
//! what a widget may even see; see [`guard`] for why that is the only door.
//!
//! # Failing closed
//!
//! A window may not assume its frames are well-formed. When one is not — an
//! unreadable line, a frame before the request, a second request down a
//! channel that carries one — the window closes with a reason rather than
//! drawing a guess. Before a verdict the daemon reads that as
//! [`crate::audit::LogVerdict::PromptDied`], which is a denial, so the
//! unsafe direction is the one that costs nothing. `QueueDepth` is the
//! exception in the other direction: a badge is decoration, and a stale one
//! is not worth a window.

pub mod guard;
pub mod panes;
pub mod visibility;

use std::collections::VecDeque;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, OnceLock};
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use eframe::egui;

use crate::exec::Stream;
use crate::prompt_ui::guard::{Action, Guard, intercept};
use crate::prompt_ui::panes::{Shown, Urgency, countdown_text, urgency};
use crate::protocol::{self, DaemonMsg, Outcome, PromptMsg, Request, ReviseKind, Verdict};

/// The window's application id.
///
/// Wayland has no way for a client to raise itself, so placement is the
/// compositor's job and this string is how a rule names the window. It is
/// also the name eframe reports to the desktop.
const APP_ID: &str = "hatch-prompt";

/// The size the window opens at.
const WINDOW_SIZE: [f32; 2] = [900.0, 700.0];

/// How often the window redraws when nothing arrives.
///
/// The countdown is computed from the deadline, not accumulated, so this is
/// only how often the drawn number is refreshed: a channel that says nothing
/// for ninety seconds still shows a number ninety seconds smaller, at worst a
/// second stale. Frames do not wait for it — the reader thread wakes the
/// event loop as each one lands.
const CLOCK_TICK: Duration = Duration::from_secs(1);

/// How long the process may take to leave after it has decided to.
///
/// The daemon waits 500 ms for the window to go and then kills it, so a
/// window that lingers is a window that is killed — which works, and is not a
/// plan. Asking the viewport to close is the ordinary path; this is the
/// backstop for an event loop that is no longer running one, and it is a
/// thread precisely because a wedged loop cannot run a timer of its own.
const EXIT_BACKSTOP: Duration = Duration::from_millis(250);

/// How much of an approved command's output the window keeps.
///
/// The live view exists so the user can decide whether to press Kill, and a
/// decision is made from the last screenful, not the first megabyte. Without
/// a cap a chatty command would grow this window's memory for as long as it
/// runs, which is a denial of service written by the agent that asked for the
/// command.
const OUTPUT_CAP: usize = 1 << 20;

/// The size of the two buttons that settle the request.
///
/// Wide and tall enough that they are aimed at rather than clipped, and the
/// same size as each other: Approve is the one that runs something, and
/// making it the larger of the two would be an invitation dressed as an
/// affordance.
const PRIMARY_BUTTON: egui::Vec2 = egui::vec2(150.0, 34.0);

/// The gap between Approve and Deny.
///
/// A slipped pointer has to cross it, and it lands on the panel rather than
/// on the other verdict. Deliberately larger than egui's own spacing, which
/// is tuned for buttons whose worst outcome is being pressed by accident.
const PRIMARY_GAP: f32 = 28.0;

/// The most of the window the live output takes while a command runs.
const RUNNING_OUTPUT_HEIGHT: f32 = 180.0;

// ---- the state machine -----------------------------------------------------

/// Where this window is between opening and leaving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Open, but with nothing to show: the request has not arrived yet.
    WaitingForRequest,
    /// Showing an operation and waiting for the user to decide.
    AwaitingVerdict,
    /// The operation was approved and is running; the window is an indicator.
    Running,
    /// Over. The process is leaving.
    Closed,
}

/// One thing that came up the channel, or the reason nothing else will.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// A frame the window understood.
    Frame(DaemonMsg),
    /// The channel is finished, and why. Sent exactly once, last.
    Broken(String),
}

/// Everything one window knows, and nothing about how it is drawn.
#[derive(Debug)]
pub struct PromptState {
    phase: Phase,
    request: Option<Request>,
    shown: Option<Shown>,
    queue_depth: u32,
    outcome: Option<Outcome>,
    output: VecDeque<(Stream, String)>,
    output_bytes: usize,
    broken: Option<String>,
    close_taken: bool,
}

impl Default for PromptState {
    fn default() -> PromptState {
        PromptState::new()
    }
}

impl PromptState {
    /// A window that has been opened and told nothing.
    pub fn new() -> PromptState {
        PromptState {
            phase: Phase::WaitingForRequest,
            request: None,
            shown: None,
            queue_depth: 0,
            outcome: None,
            output: VecDeque::new(),
            output_bytes: 0,
            broken: None,
            close_taken: false,
        }
    }

    /// What this window currently is.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The request being decided, once it has arrived.
    pub fn request(&self) -> Option<&Request> {
        self.request.as_ref()
    }

    /// The payload as something drawable, checked when it arrived.
    ///
    /// There is never a request without one: a payload that could not be
    /// rebuilt through the real builder closed the window instead of
    /// becoming one. See [`PromptState::handle`].
    pub fn shown(&self) -> Option<&Shown> {
        self.shown.as_ref()
    }

    /// The last depth the daemon published, whether or not it is drawn.
    pub fn queue_depth(&self) -> u32 {
        self.queue_depth
    }

    /// The "N more waiting" badge, or `None` when there must not be one.
    ///
    /// The badge is only true while this window holds the approval. After an
    /// approval the permit is released and the daemon keeps publishing depths
    /// — but they now describe the queue behind *somebody else's* window, and
    /// a running indicator that drew them would be reporting a number that is
    /// no longer about anything on screen.
    pub fn queue_badge(&self) -> Option<u32> {
        match self.phase {
            Phase::AwaitingVerdict if self.queue_depth > 0 => Some(self.queue_depth),
            _ => None,
        }
    }

    /// How the approved operation ended, once it has.
    pub fn outcome(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }

    /// The approved command's output so far, oldest first.
    pub fn output(&self) -> &VecDeque<(Stream, String)> {
        &self.output
    }

    /// Why the channel ended badly, if it did.
    pub fn broken(&self) -> Option<&str> {
        self.broken.as_deref()
    }

    /// Whether the process should now leave.
    pub fn should_close(&self) -> bool {
        self.phase == Phase::Closed
    }

    /// True at the first moment the window should close, and never again.
    ///
    /// The latch is here rather than in the eframe app because closing is not
    /// idempotent: it arms a thread that will end the process. Asking a
    /// viewport to close twice is harmless, arming two backstops is noise, and
    /// re-arming one on every frame of a window that is slow to go would keep
    /// resetting the deadline it exists to enforce.
    pub fn take_close(&mut self) -> bool {
        if self.phase != Phase::Closed || self.close_taken {
            return false;
        }
        self.close_taken = true;
        true
    }

    /// Seconds left before the approval expires, at `now`.
    ///
    /// Read off the deadline every time rather than counted down, so a window
    /// that was slow to start, or descheduled, or paused with its laptop lid
    /// shut, shows the time the daemon will actually act on. A local timer
    /// would be a clock this window could extend by being slow, which is the
    /// one thing [`Request::deadline`] is shaped to prevent.
    ///
    /// Clamped at zero: the daemon kills the window at the deadline, and in
    /// the moments before it gets there a negative number would be the window
    /// inventing a state of its own.
    pub fn seconds_remaining(&self, now: DateTime<Utc>) -> Option<i64> {
        let deadline = self.request.as_ref()?.deadline;
        Some((deadline - now).num_seconds().max(0))
    }

    /// Take in one frame from the daemon.
    pub fn handle(&mut self, msg: DaemonMsg) {
        if self.phase == Phase::Closed {
            return;
        }
        if self.phase == Phase::WaitingForRequest && !matches!(msg, DaemonMsg::Request(_)) {
            self.channel_broken("hatch spoke to this window before it sent the request");
            return;
        }
        match msg {
            DaemonMsg::Request(req) => {
                if self.phase != Phase::WaitingForRequest {
                    self.channel_broken("hatch sent a second request to a window that has one");
                    return;
                }
                // The rendering is checked here, once, and before the window
                // has anything to show — not per frame while drawing, where
                // the only thing left to do about a bad one is to draw part
                // of it. A payload whose spans do not tile their source, or
                // whose one-line form disagrees with them, is a frame this
                // window cannot show the truth of, so it closes: the daemon
                // reads that as a denial, which is the safe direction.
                let shown = match Shown::of(&req.payload) {
                    Ok(shown) => shown,
                    Err(e) => {
                        self.channel_broken(format!(
                            "hatch sent a request this window cannot draw: {e}"
                        ));
                        return;
                    }
                };
                self.queue_depth = req.queue_depth;
                self.request = Some(req);
                self.shown = Some(shown);
                self.phase = Phase::AwaitingVerdict;
            }
            DaemonMsg::QueueDepth { depth } => self.queue_depth = depth,
            DaemonMsg::Output { stream, text } => self.push_output(stream, text),
            DaemonMsg::Finished(outcome) => {
                self.outcome = Some(outcome);
                self.phase = Phase::Closed;
            }
        }
    }

    /// End the window because the channel can no longer be believed.
    ///
    /// A no-op once the window is already closing: the first ending is the
    /// true one, and a daemon hanging up its half after sending the outcome
    /// is the ordinary way this process finishes.
    pub fn channel_broken(&mut self, why: impl Into<String>) {
        if self.phase == Phase::Closed {
            return;
        }
        self.broken = Some(why.into());
        self.phase = Phase::Closed;
    }

    /// Record the user's decision, and hand back the one frame to send.
    ///
    /// `None` means there is nothing to send, and that is the whole guarantee
    /// of "exactly one verdict": a decision is only produced while the window
    /// is waiting for one, and producing it is what stops the waiting.
    pub fn decide(&mut self, verdict: Verdict) -> Option<PromptMsg> {
        if self.phase != Phase::AwaitingVerdict {
            return None;
        }
        // Approve is the only verdict that leaves anything to watch. The rest
        // return a note to the agent and there is nothing further to show, so
        // the window is over the moment the frame is written.
        self.phase = match verdict {
            Verdict::Approve { .. } => Phase::Running,
            Verdict::Deny { .. } | Verdict::Revise { .. } | Verdict::SelfRun { .. } => {
                Phase::Closed
            }
        };
        Some(PromptMsg::Verdict(verdict))
    }

    /// The Kill frame, if there is something running to kill.
    ///
    /// Kill can stop a command and can never start one, so the only reason to
    /// withhold it is honesty: a button that did nothing would be a window
    /// claiming a power over a command that has not been approved.
    pub fn request_kill(&self) -> Option<PromptMsg> {
        (self.phase == Phase::Running).then_some(PromptMsg::Kill)
    }

    /// Append a chunk, dropping the oldest ones once the cap is passed.
    ///
    /// The newest chunk is never dropped, whatever its size: a view that
    /// answered a huge write by showing nothing would be worse than one that
    /// briefly holds more than it meant to.
    fn push_output(&mut self, stream: Stream, text: String) {
        self.output_bytes += text.len();
        self.output.push_back((stream, text));
        while self.output_bytes > OUTPUT_CAP && self.output.len() > 1 {
            if let Some((_, dropped)) = self.output.pop_front() {
                self.output_bytes -= dropped.len();
            }
        }
    }
}

// ---- reading the channel ---------------------------------------------------

/// Turn the daemon's half of the channel into [`Incoming`] items until there
/// is nothing left to believe.
///
/// Every exit sends exactly one [`Incoming::Broken`], so the window learns
/// that the channel ended as a fact rather than as silence — including the
/// clean end, where the daemon has said its last word and hung up.
///
/// `wake` runs after each item so an event loop asleep on its own timer
/// notices immediately; the loop's periodic repaint is for the clock, not for
/// this.
pub fn read_frames<R: BufRead>(reader: R, tx: &Sender<Incoming>, wake: impl Fn()) {
    for line in reader.lines() {
        let item = match line {
            Ok(line) => match protocol::read_message::<DaemonMsg>(&line) {
                Ok(msg) => Incoming::Frame(msg),
                // Both ends of this channel are the same build, so a frame
                // that will not parse is not a version to tolerate: it means
                // the thing on the other end is not what it claims to be, and
                // the next line from it is worth no more than this one.
                Err(e) => {
                    Incoming::Broken(format!("hatch sent a frame it cannot read: {e}"))
                }
            },
            Err(e) => Incoming::Broken(format!("this window could not read from hatch: {e}")),
        };
        let last = matches!(item, Incoming::Broken(_));
        if tx.send(item).is_err() {
            return;
        }
        wake();
        if last {
            return;
        }
    }
    let _ = tx.send(Incoming::Broken("hatch closed the channel".to_string()));
    wake();
}

// ---- the window ------------------------------------------------------------

/// Draw one approval window, and do not return until it is over.
///
/// # Errors
///
/// The window could not be opened at all, or the channel ended in a way that
/// is worth telling the operator about. Neither is something the daemon reads:
/// it sees a process that exited without deciding, which is a denial.
pub fn run_prompt() -> anyhow::Result<()> {
    let fatal: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_app_id(APP_ID)
            .with_title("hatch — approval")
            .with_inner_size(WINDOW_SIZE)
            // A no-op on Wayland, where only the compositor may raise a
            // window, and correct everywhere else. The Wayland answer is a
            // compositor rule matching the app id above.
            .with_always_on_top(),
        ..Default::default()
    };

    let app_fatal = Arc::clone(&fatal);
    eframe::run_native(
        APP_ID,
        options,
        Box::new(move |cc| {
            // The reader is started here, not before, so it has a real
            // context to wake and so a window that never opens never reads a
            // request it could not have shown. Nothing is lost by waiting:
            // the daemon's first write fits in the pipe.
            let (tx, rx) = std::sync::mpsc::channel();
            let ctx = cc.egui_ctx.clone();
            std::thread::spawn(move || {
                read_frames(io::stdin().lock(), &tx, || ctx.request_repaint());
            });
            Ok(Box::new(PromptApp::new(rx, Box::new(io::stdout()), app_fatal)))
        }),
    )
    .map_err(|e| anyhow::anyhow!("the approval window could not be opened: {e}"))?;

    match fatal.get() {
        Some(why) => Err(anyhow::anyhow!("{why}")),
        None => Ok(()),
    }
}

/// The eframe side: drain, draw, and write back.
struct PromptApp {
    state: PromptState,
    inbox: Receiver<Incoming>,
    out: Box<dyn Write + Send>,
    /// The Stream output checkbox. A display preference and nothing else.
    stream: bool,
    /// What the user is telling the agent, for every verdict but Approve.
    note: String,
    /// The one thing between a keystroke meant for another window and an
    /// approved command.
    guard: Guard,
    /// Whether the guard was open when this frame's input was judged, so the
    /// drawing half of the frame agrees with the judging half.
    guard_open: bool,
    fatal: Arc<OnceLock<String>>,
}

impl PromptApp {
    fn new(
        inbox: Receiver<Incoming>,
        out: Box<dyn Write + Send>,
        fatal: Arc<OnceLock<String>>,
    ) -> PromptApp {
        PromptApp {
            state: PromptState::new(),
            inbox,
            out,
            // Headless by default: streaming is what the reader opts into
            // when they want to watch, not what they get for asking.
            stream: false,
            note: String::new(),
            guard: Guard::new(Instant::now()),
            guard_open: false,
            fatal,
        }
    }
}

/// Hand everything that has arrived to the state machine.
///
/// Draining rather than taking one at a time, because the phase after a burst
/// is the phase the user should see: a window that drew one frame per arrival
/// would flash a verdict screen for an operation the daemon has already
/// finished.
pub fn drain(state: &mut PromptState, inbox: &Receiver<Incoming>) {
    while let Ok(item) = inbox.try_recv() {
        match item {
            Incoming::Frame(msg) => state.handle(msg),
            Incoming::Broken(why) => state.channel_broken(why),
        }
    }
}

/// Write one frame back to the daemon, if there is one to write.
///
/// A failure is fatal on purpose: an approval that never reached the daemon
/// must not leave a window sitting there as if something were running.
pub fn answer<W: Write>(out: &mut W, state: &mut PromptState, msg: Option<PromptMsg>) {
    let Some(msg) = msg else { return };
    if let Err(e) = protocol::write_message(out, &msg) {
        state.channel_broken(format!("this window could not answer hatch: {e}"));
    }
}

/// Leave in `EXIT_BACKSTOP`, whatever the event loop is doing by then.
fn arm_exit_backstop(fatal: Arc<OnceLock<String>>) {
    std::thread::spawn(move || {
        std::thread::sleep(EXIT_BACKSTOP);
        match fatal.get() {
            Some(why) => {
                eprintln!("hatch prompt: {why}");
                std::process::exit(1);
            }
            None => std::process::exit(0),
        }
    });
}

impl eframe::App for PromptApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        drain(&mut self.state, &self.inbox);
        // Before anything is drawn, and before any widget sees the frame.
        // Whatever the guard did not hand back is gone from this frame.
        let now = Instant::now();
        for action in intercept(&mut self.guard, ctx, now) {
            self.act(action);
        }
        self.guard_open = self.guard.is_open(now);
        if self.state.take_close() {
            if let Some(why) = self.state.broken() {
                let _ = self.fatal.set(why.to_string());
            }
            arm_exit_backstop(Arc::clone(&self.fatal));
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        ctx.request_repaint_after(CLOCK_TICK);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.window(ui, self.guard_open);
    }
}

impl PromptApp {
    /// The whole window, for one frame.
    ///
    /// Split out of [`eframe::App::ui`] so the tests below can draw the real
    /// layout — panes, panels and buttons — through egui's own `run_ui`,
    /// without a display and without an `eframe::Frame` to hand it. The
    /// guard's answer is a parameter for the same reason it is a field: the
    /// half of the frame that judges input and the half that draws it must
    /// agree.
    fn window(&mut self, ui: &mut egui::Ui, guard_open: bool) {
        // Agent-controlled text, defanged by the daemon. Drawn as text and
        // not interpreted; nothing here undoes the defanging. Copied out so
        // the panels below can still borrow the state machine.
        let headline = self.state.request().map(|r| (r.title.clone(), r.reason.clone()));
        let Some((title, reason)) = headline else {
            egui::CentralPanel::default().show(ui, |ui| {
                ui.label("Waiting for hatch to send the request…");
            });
            return;
        };

        // The controls are a panel and not the bottom of the scrolling
        // region, and that is the whole answer to "two scroll areas plus the
        // buttons". A bottom panel takes its height out of the window before
        // anything above it is laid out, so a command of any length reaches
        // the end of its pane rather than the end of the window: Approve
        // cannot be pushed off the screen, and there is no scroll position
        // from which the buttons are missing.
        egui::Panel::bottom("hatch-controls").show(ui, |ui| self.controls(ui, guard_open));

        egui::CentralPanel::default().show(ui, |ui| {
            panes::draw_headline(ui, &title, &reason);
            ui.separator();
            // There is always one once a request has arrived: a payload that
            // could not be rebuilt closed the window instead of becoming one.
            if let Some(shown) = self.state.shown() {
                panes::draw_payload(ui, shown);
            }
        });
    }

    /// Carry out one decision the guard made.
    ///
    /// A decision, not a suggestion: it is applied where it is received. The
    /// state machine is what makes a doubled one harmless — it answers only
    /// while the window awaits a verdict, and it leaves that phase on the way
    /// out.
    fn act(&mut self, action: Action) {
        let verdict = match action {
            Action::Approve => Verdict::Approve { stream: self.stream },
            Action::Deny => Verdict::Deny { note: self.note.clone() },
            Action::Ignored | Action::Passthrough => return,
        };
        let frame = self.state.decide(verdict);
        answer(&mut self.out, &mut self.state, frame);
    }

    /// Everything below the panes: what the clock says, and what can be
    /// pressed.
    ///
    /// One method rather than a panel closure per phase, because the phase is
    /// what decides between them and the two must never both be drawn.
    fn controls(&mut self, ui: &mut egui::Ui, guard_open: bool) {
        ui.add_space(4.0);
        self.status_row(ui);
        match self.state.phase() {
            Phase::AwaitingVerdict => {
                self.verdict_area(ui, guard_open);
            }
            Phase::Running => self.running_row(ui),
            Phase::WaitingForRequest | Phase::Closed => {}
        }
        ui.add_space(4.0);
    }

    /// The clock and the badge.
    ///
    /// The countdown changes colour *and* weight on the way down rather than
    /// only shrinking as a number: plain text is legible at 255 s and useless
    /// at 8 s, when the reader is no longer reading anything. Two thresholds,
    /// not a fade — see [`panes::urgency`] — and never colour alone, which
    /// would say nothing at all to a reader who cannot tell red from grey.
    fn status_row(&self, ui: &mut egui::Ui) {
        let (calm, soon, imminent) = {
            let visuals = ui.visuals();
            (visuals.weak_text_color(), visuals.warn_fg_color, visuals.error_fg_color)
        };
        ui.horizontal(|ui| {
            if let Some(left) = self.state.seconds_remaining(Utc::now()) {
                let text = egui::RichText::new(countdown_text(left));
                ui.label(match urgency(left) {
                    Urgency::Calm => text.color(calm),
                    Urgency::Soon => text.color(soon).strong(),
                    Urgency::Imminent => text.color(imminent).strong().size(17.0),
                });
            }
            if let Some(waiting) = self.state.queue_badge() {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!("{waiting} more waiting"))
                            .small()
                            .color(calm),
                    );
                });
            }
        });
    }

    /// What an approved command's window offers while it runs.
    ///
    /// The output is here, in the same panel as Kill, and capped: the reason
    /// to watch it is to decide whether to press that button, and a decision
    /// is made from the last screenful.
    fn running_row(&mut self, ui: &mut egui::Ui) {
        ui.label("Approved. It is running now.");
        if self.stream {
            let text: String =
                self.state.output().iter().map(|(_, chunk)| chunk.as_str()).collect();
            egui::ScrollArea::vertical()
                .id_salt("hatch-output")
                .max_height(RUNNING_OUTPUT_HEIGHT)
                .auto_shrink([false, true])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    // Already decoded by the daemon; drawn, never decoded
                    // again. See `crate::protocol`.
                    ui.add(egui::Label::new(egui::RichText::new(text).monospace()));
                });
        } else {
            ui.label(
                egui::RichText::new("Its output is not being streamed to this window.").small(),
            );
        }
        if unfocusable(ui, egui::Button::new("Kill")).clicked() {
            let kill = self.state.request_kill();
            answer(&mut self.out, &mut self.state, kill);
        }
    }

    /// The verdict area, shut while the guard is.
    ///
    /// Disabled rather than hidden, and this is the guard's second layer, not
    /// decoration: egui works out pointer clicks from this frame's events
    /// before [`guard::intercept`] ever sees them, so emptying the event
    /// queue does not stop a mouse. A disabled widget reports no click at
    /// all, real or faked, which is what stops someone double-clicking at
    /// another window from answering this one.
    ///
    /// Returns the Approve button, so a test can ask egui itself what it
    /// would do with it.
    fn verdict_area(&mut self, ui: &mut egui::Ui, guard_open: bool) -> egui::Response {
        let approve = ui.add_enabled_ui(guard_open, |ui| self.verdict_buttons(ui)).inner;
        if !guard_open {
            ui.label(
                "Waiting a moment, so a keystroke meant for another window \
                 cannot answer this one…",
            );
        }
        approve
    }

    /// The buttons, the note and the checkbox, weighted so that the two that
    /// decide do not look like the three that ask.
    ///
    /// Five buttons stacked in one column at one size is the layout that
    /// produces a misclick, and a misclick here is an approval. So Approve
    /// and Deny are one row of large buttons with a real gap between them —
    /// the gap is not decoration, it is the distance a slipped pointer has to
    /// cross to turn a refusal into a root command — and Explain, Simplify
    /// and "I'll run it myself" are a smaller row underneath. They are escape
    /// hatches: they send the agent away with something to do and nothing
    /// runs, which is the same class of outcome as Deny and does not deserve
    /// the same size as it.
    ///
    /// Every one of them is built with [`egui::Sense::CLICK`] rather than
    /// [`egui::Sense::click`], which is the same thing without `FOCUSABLE`.
    /// egui fakes a primary click on the *focused* widget when Space or Enter
    /// is pressed, so a button that can never hold focus can never be
    /// activated by a key at all — which is the hole that taking Enter out of
    /// the frame leaves open on its own, because Space is ordinary typing and
    /// has to reach the note field. [`unfocusable`] is the one door: do not
    /// swap these back to `ui.button`.
    ///
    /// Returns the Approve button.
    fn verdict_buttons(&mut self, ui: &mut egui::Ui) -> egui::Response {
        // Read before the fields below are borrowed to draw.
        let (streamable, interactive) = match self.state.shown() {
            Some(shown) => (shown.streamable(), shown.interactive()),
            None => (false, false),
        };

        ui.horizontal(|ui| {
            ui.label("Note to the agent");
            ui.text_edit_singleline(&mut self.note);
        });
        // One name for it, used by the checkbox and by the line that says why
        // it is dead: a control that cannot be ticked and does not say why is
        // a window asking the reader to guess.
        let can_stream = !interactive;
        if streamable {
            ui.add_enabled(
                can_stream,
                egui::Checkbox::new(&mut self.stream, "Stream output to this window"),
            );
            if !can_stream {
                ui.label(
                    egui::RichText::new("It runs in a terminal of its own.")
                        .small()
                        .weak(),
                );
            }
        }

        ui.add_space(8.0);
        let note = self.note.clone();
        let mut decided = None;

        let approve = ui
            .horizontal(|ui| {
                let approve =
                    unfocusable(ui, egui::Button::new(strong("Approve")).min_size(PRIMARY_BUTTON));
                // A pointer that slips off Deny must land on nothing.
                ui.add_space(PRIMARY_GAP);
                if unfocusable(ui, egui::Button::new(strong("Deny")).min_size(PRIMARY_BUTTON))
                    .clicked()
                {
                    decided = Some(Verdict::Deny { note: note.clone() });
                }
                approve
            })
            .inner;
        if approve.clicked() {
            decided = Some(Verdict::Approve { stream: self.stream });
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if secondary(ui, "Explain first").clicked() {
                decided = Some(Verdict::Revise { kind: ReviseKind::Explain, note: note.clone() });
            }
            if secondary(ui, "Ask for something simpler").clicked() {
                decided = Some(Verdict::Revise { kind: ReviseKind::Simplify, note: note.clone() });
            }
            if secondary(ui, "I'll run it myself").clicked() {
                decided = Some(Verdict::SelfRun { note });
            }
        });

        if let Some(verdict) = decided {
            let frame = self.state.decide(verdict);
            answer(&mut self.out, &mut self.state, frame);
        }
        approve
    }
}

/// A button a mouse can press and a keyboard cannot reach.
///
/// The single place [`egui::Sense::CLICK`] is applied, so a new button cannot
/// be added with the focusable sense by forgetting rather than by deciding.
/// See [`PromptApp::verdict_buttons`] for why that matters.
fn unfocusable(ui: &mut egui::Ui, button: egui::Button<'_>) -> egui::Response {
    ui.add(button.sense(egui::Sense::CLICK))
}

/// One of the three ways to send the agent away without running anything.
fn secondary(ui: &mut egui::Ui, label: &str) -> egui::Response {
    unfocusable(ui, egui::Button::new(egui::RichText::new(label).small()))
}

/// A primary button's label.
fn strong(label: &str) -> egui::RichText {
    egui::RichText::new(label).strong().size(16.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use chrono::Utc;

    use crate::protocol::{DaemonMsg, Outcome, Payload, Request, ReviseKind, Verdict};
    use crate::render::render_command;

    fn a_request(seconds_left: i64) -> Request {
        Request {
            title: "delete the build directory".to_string(),
            reason: "the last build left files the tests trip over".to_string(),
            deadline: Utc::now() + chrono::Duration::seconds(seconds_left),
            queue_depth: 0,
            payload: Payload::command(
                &render_command("rm -rf target", &BTreeMap::new()),
                Vec::new(),
                PathBuf::from("/"),
                false,
                false,
            ),
        }
    }

    // ---- the close latch ---------------------------------------------------

    #[test]
    fn output_is_not_streamed_unless_the_reader_asks_for_it() {
        // The spec makes execution headless by default; the checkbox is the
        // opt-in. Defaulting it on means every approval silently chooses the
        // mode the reader never picked.
        let (_tx, rx) = std::sync::mpsc::channel();
        let app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()));
        assert!(!app.stream, "streaming is opted into, not defaulted on");
    }

    #[test]
    fn the_close_is_taken_once_and_only_once() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        assert!(!state.take_close(), "there is nothing to close yet");

        state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));

        assert!(state.take_close(), "the window was never told to go");
        assert!(!state.take_close(), "it would arm a second backstop every frame");
        assert!(state.should_close(), "and it is still closing");
    }

    // ---- the wiring --------------------------------------------------------

    #[test]
    fn draining_hands_every_arrival_to_the_state_machine() {
        let mut state = PromptState::new();
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Incoming::Frame(DaemonMsg::Request(a_request(90)))).unwrap();
        tx.send(Incoming::Frame(DaemonMsg::QueueDepth { depth: 5 })).unwrap();

        drain(&mut state, &rx);

        assert_eq!(state.phase(), Phase::AwaitingVerdict);
        assert_eq!(state.queue_depth(), 5, "a later arrival in the same burst was dropped");
    }

    #[test]
    fn draining_a_broken_channel_closes_the_window() {
        let mut state = PromptState::new();
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Incoming::Broken("hatch closed the channel".to_string())).unwrap();

        drain(&mut state, &rx);

        assert!(state.should_close());
        assert_eq!(state.broken(), Some("hatch closed the channel"));
    }

    #[test]
    fn a_verdict_goes_out_as_one_framed_line() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        let mut wire = Vec::new();

        let frame = state.decide(Verdict::Approve { stream: true });
        answer(&mut wire, &mut state, frame);

        assert_eq!(
            String::from_utf8(wire).unwrap(),
            "{\"type\":\"verdict\",\"verdict\":\"approve\",\"stream\":true}\n"
        );
        assert_eq!(state.broken(), None, "a written verdict is not a failure");
    }

    #[test]
    fn nothing_to_say_writes_nothing() {
        let mut state = PromptState::new();
        let mut wire = Vec::new();

        answer(&mut wire, &mut state, None);

        assert!(wire.is_empty());
        assert_eq!(state.broken(), None);
    }

    /// A pipe whose far end is gone.
    struct Deaf;

    impl std::io::Write for Deaf {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn an_approval_that_cannot_be_sent_does_not_leave_a_window_pretending() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        let frame = state.decide(Verdict::Approve { stream: true });
        assert_eq!(state.phase(), Phase::Running);

        answer(&mut Deaf, &mut state, frame);

        assert!(state.should_close(), "it is still showing a command that was never authorised");
        assert!(state.broken().is_some(), "and it did not say why");
    }

    // ---- the countdown -----------------------------------------------------

    #[test]
    fn a_fresh_window_and_the_default_one_are_the_same_window() {
        let made = PromptState::new();
        let defaulted = PromptState::default();

        assert_eq!(made.phase(), defaulted.phase());
        assert_eq!(made.queue_depth(), defaulted.queue_depth());
        assert!(made.request().is_none() && defaulted.request().is_none());
        assert!(made.output().is_empty() && defaulted.output().is_empty());
    }

    #[test]
    fn the_request_is_kept_so_the_window_can_draw_it() {
        let mut state = PromptState::new();
        assert!(state.request().is_none(), "there is nothing to draw yet");

        let sent = a_request(90);
        state.handle(DaemonMsg::Request(sent.clone()));

        assert_eq!(state.request(), Some(&sent), "the window would draw something else");
    }

    #[test]
    fn there_is_no_countdown_before_the_request_arrives() {
        assert_eq!(PromptState::new().seconds_remaining(Utc::now()), None);
    }

    #[test]
    fn the_countdown_stops_at_zero_rather_than_running_negative() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(-30)));

        assert_eq!(state.seconds_remaining(Utc::now()), Some(0));
    }

    // ---- the badge ---------------------------------------------------------

    #[test]
    fn the_badge_starts_at_the_depth_the_request_carried() {
        let mut state = PromptState::new();
        let mut req = a_request(90);
        req.queue_depth = 3;
        state.handle(DaemonMsg::Request(req));

        assert_eq!(state.queue_depth(), 3);
        assert_eq!(state.queue_badge(), Some(3));
    }

    #[test]
    fn nothing_waiting_is_not_a_badge() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));

        assert_eq!(state.queue_badge(), None);
    }

    #[test]
    fn a_running_window_does_not_draw_a_badge_about_someone_elses_queue() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(Verdict::Approve { stream: false });
        state.handle(DaemonMsg::QueueDepth { depth: 7 });

        assert_eq!(state.queue_depth(), 7, "the depth is still recorded");
        assert_eq!(state.queue_badge(), None, "but it is no longer about this window");
    }

    // ---- exactly one verdict ----------------------------------------------

    #[test]
    fn a_second_press_of_the_same_button_sends_nothing() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));

        assert!(state.decide(Verdict::Approve { stream: true }).is_some());
        assert_eq!(state.decide(Verdict::Approve { stream: true }), None);
    }

    #[test]
    fn a_verdict_pressed_while_the_command_runs_sends_nothing() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(Verdict::Approve { stream: true });

        assert_eq!(state.decide(Verdict::Deny { note: String::new() }), None);
        assert_eq!(state.phase(), Phase::Running, "and it did not change what is happening");
    }

    #[test]
    fn no_verdict_can_be_given_before_the_request_arrives() {
        let mut state = PromptState::new();

        assert_eq!(state.decide(Verdict::Approve { stream: true }), None);
        assert_eq!(state.phase(), Phase::WaitingForRequest);
    }

    #[test]
    fn the_verdict_that_goes_out_is_the_one_that_was_pressed() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));

        let sent = state.decide(Verdict::Revise {
            kind: ReviseKind::Simplify,
            note: "too long".to_string(),
        });
        assert_eq!(
            sent,
            Some(PromptMsg::Verdict(Verdict::Revise {
                kind: ReviseKind::Simplify,
                note: "too long".to_string(),
            }))
        );
    }

    #[test]
    fn everything_that_is_not_an_approval_closes_the_window() {
        for verdict in [
            Verdict::Deny { note: "no".to_string() },
            Verdict::Revise { kind: ReviseKind::Explain, note: String::new() },
            Verdict::Revise { kind: ReviseKind::Simplify, note: String::new() },
            Verdict::SelfRun { note: String::new() },
        ] {
            let mut state = PromptState::new();
            state.handle(DaemonMsg::Request(a_request(90)));
            assert!(state.decide(verdict.clone()).is_some());

            assert!(state.should_close(), "{verdict:?} left the window open");
            assert_eq!(state.broken(), None, "{verdict:?} is not a failure");
        }
    }

    // ---- kill --------------------------------------------------------------

    #[test]
    fn kill_is_offered_only_while_something_is_running() {
        let mut state = PromptState::new();
        assert_eq!(state.request_kill(), None);

        state.handle(DaemonMsg::Request(a_request(90)));
        assert_eq!(state.request_kill(), None, "nothing has been approved yet");

        state.decide(Verdict::Approve { stream: false });
        assert_eq!(state.request_kill(), Some(PromptMsg::Kill));

        state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));
        assert_eq!(state.request_kill(), None, "it is already over");
    }

    // ---- the ending --------------------------------------------------------

    #[test]
    fn the_outcome_survives_the_frame_that_closed_the_window() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(Verdict::Approve { stream: false });
        state.handle(DaemonMsg::Finished(Outcome::Signal { signal: 9 }));

        assert_eq!(state.outcome(), Some(&Outcome::Signal { signal: 9 }));
        assert_eq!(state.broken(), None, "a signal is an outcome, not a failure");
    }

    #[test]
    fn the_daemon_hanging_up_after_the_outcome_does_not_rewrite_the_ending() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(Verdict::Approve { stream: false });
        state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));
        state.channel_broken("hatch closed the channel");

        assert_eq!(state.broken(), None);
        assert_eq!(state.outcome(), Some(&Outcome::Exit { code: 0 }));
    }

    #[test]
    fn nothing_arriving_after_the_close_can_reopen_the_window() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(Verdict::Deny { note: String::new() });
        state.handle(DaemonMsg::Request(a_request(90)));

        assert!(state.should_close());
        assert_eq!(state.phase(), Phase::Closed);
    }

    // ---- failing closed ----------------------------------------------------

    #[test]
    fn an_unreadable_channel_closes_the_window_with_a_reason() {
        let mut state = PromptState::new();
        state.channel_broken("hatch sent a frame this window cannot read");

        assert!(state.should_close());
        assert_eq!(state.broken(), Some("hatch sent a frame this window cannot read"));
    }

    #[test]
    fn a_second_request_is_not_believed() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.handle(DaemonMsg::Request(a_request(90)));

        assert!(state.should_close());
        assert!(state.broken().is_some(), "and it said why");
    }

    #[test]
    fn a_frame_before_the_request_is_not_believed() {
        for early in [
            DaemonMsg::QueueDepth { depth: 1 },
            DaemonMsg::Output { stream: Stream::Stdout, text: "hi".to_string() },
            DaemonMsg::Finished(Outcome::Exit { code: 0 }),
        ] {
            let mut state = PromptState::new();
            state.handle(early.clone());

            assert!(state.should_close(), "{early:?} was taken as if it were a request");
            assert!(state.broken().is_some(), "{early:?} closed the window silently");
        }
    }

    // ---- output ------------------------------------------------------------

    #[test]
    fn output_arrives_in_order_with_the_pipe_it_came_from() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(Verdict::Approve { stream: true });
        state.handle(DaemonMsg::Output { stream: Stream::Stdout, text: "one".to_string() });
        state.handle(DaemonMsg::Output { stream: Stream::Stderr, text: "two".to_string() });

        let seen: Vec<_> = state.output().iter().cloned().collect();
        assert_eq!(
            seen,
            vec![
                (Stream::Stdout, "one".to_string()),
                (Stream::Stderr, "two".to_string()),
            ]
        );
    }

    /// Feed `chunks` chunks of `size` bytes to an approved command's window.
    fn after_output(chunks: usize, size: usize) -> PromptState {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(Verdict::Approve { stream: true });
        let chunk = "x".repeat(size);
        for _ in 0..chunks {
            state.handle(DaemonMsg::Output { stream: Stream::Stdout, text: chunk.clone() });
        }
        state
    }

    fn held_bytes(state: &PromptState) -> usize {
        state.output().iter().map(|(_, t)| t.len()).sum()
    }

    #[test]
    fn a_chatty_command_cannot_grow_the_window_without_bound() {
        let mut state = after_output(64, 64 * 1024);
        state.handle(DaemonMsg::Output { stream: Stream::Stdout, text: "last".to_string() });

        let held = held_bytes(&state);
        assert!(held <= OUTPUT_CAP, "the window is holding {held} bytes");
        assert_eq!(
            state.output().back().map(|(_, t)| t.as_str()),
            Some("last"),
            "the newest chunk is the one that must survive"
        );
    }

    #[test]
    fn the_cap_drops_the_oldest_output_rather_than_almost_all_of_it() {
        // Four megabytes through a one-megabyte window. Dropping until only
        // the newest chunk is left would also stay under the cap, and would
        // leave the user watching a single line of a running command.
        let state = after_output(64, 64 * 1024);

        let held = held_bytes(&state);
        assert!(held > OUTPUT_CAP / 2, "only {held} bytes survived of a {OUTPUT_CAP}-byte window");
        assert!(held <= OUTPUT_CAP, "the window is holding {held} bytes");
    }

    #[test]
    fn output_that_exactly_fills_the_window_is_all_kept() {
        let state = after_output(16, OUTPUT_CAP / 16);

        assert_eq!(state.output().len(), 16, "a full window is not an overflowing one");
        assert_eq!(held_bytes(&state), OUTPUT_CAP);
    }

    #[test]
    fn one_chunk_larger_than_the_cap_is_still_shown() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(Verdict::Approve { stream: true });
        state.handle(DaemonMsg::Output {
            stream: Stream::Stdout,
            text: "y".repeat(OUTPUT_CAP * 2),
        });

        assert_eq!(state.output().len(), 1);
    }

    // ---- the reader --------------------------------------------------------

    /// Read `input` to the end and collect everything the window would see,
    /// plus how many times the event loop was woken.
    fn read_all(input: &str) -> (Vec<Incoming>, usize) {
        let (tx, rx) = std::sync::mpsc::channel();
        let wakes = std::sync::atomic::AtomicUsize::new(0);
        read_frames(input.as_bytes(), &tx, || {
            wakes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });
        drop(tx);
        (rx.into_iter().collect(), wakes.load(std::sync::atomic::Ordering::Relaxed))
    }

    #[test]
    fn each_line_becomes_a_frame_and_wakes_the_window() {
        let request = protocol::encode(&DaemonMsg::Request(a_request(90))).unwrap();
        let depth = protocol::encode(&DaemonMsg::QueueDepth { depth: 2 }).unwrap();

        let (seen, wakes) = read_all(&format!("{request}\n{depth}\n"));

        assert_eq!(seen.len(), 3, "two frames and the hang-up");
        assert!(matches!(seen[0], Incoming::Frame(DaemonMsg::Request(_))));
        assert_eq!(seen[1], Incoming::Frame(DaemonMsg::QueueDepth { depth: 2 }));
        assert!(matches!(seen[2], Incoming::Broken(_)));
        assert_eq!(wakes, 3, "the loop was not woken for every item");
    }

    #[test]
    fn the_daemon_hanging_up_is_reported_rather_than_left_as_silence() {
        let (seen, _) = read_all("");

        assert_eq!(seen.len(), 1);
        assert!(matches!(seen[0], Incoming::Broken(_)));
    }

    #[test]
    fn a_line_that_will_not_parse_ends_the_channel_there() {
        let depth = protocol::encode(&DaemonMsg::QueueDepth { depth: 2 }).unwrap();

        let (seen, _) = read_all(&format!("{{not a frame\n{depth}\n"));

        assert_eq!(seen.len(), 1, "the window kept reading a source it cannot trust");
        assert!(matches!(seen[0], Incoming::Broken(_)));
    }

    #[test]
    fn the_reader_stops_when_the_window_is_gone() {
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        let depth = protocol::encode(&DaemonMsg::QueueDepth { depth: 2 }).unwrap();

        // Nothing to assert but that this returns: a reader that ignored a
        // closed channel would run to the end of a stdin that never ends.
        read_frames(format!("{depth}\n").as_bytes(), &tx, || {});
    }

    #[test]
    fn starts_awaiting_the_request() {
        assert_eq!(PromptState::new().phase(), Phase::WaitingForRequest);
    }

    #[test]
    fn queue_depth_updates_do_not_disturb_the_verdict_phase() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.handle(DaemonMsg::QueueDepth { depth: 4 });

        assert_eq!(state.phase(), Phase::AwaitingVerdict);
        assert_eq!(state.queue_depth(), 4);
    }

    #[test]
    fn approve_moves_to_running_and_the_window_stays_open() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));

        assert!(state.decide(Verdict::Approve { stream: true }).is_some());
        assert_eq!(state.phase(), Phase::Running);
        assert!(!state.should_close());
    }

    #[test]
    fn finished_closes_the_window() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(Verdict::Approve { stream: false });
        state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));

        assert!(state.should_close());
    }

    #[test]
    fn countdown_comes_from_the_deadline_not_a_local_timer() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(42)));

        let left = state.seconds_remaining(Utc::now()).expect("a request sets the deadline");
        assert!((left - 42).abs() <= 1, "the countdown said {left}s, not 42s");
    }

    // ---- the guard's second layer, against real egui widget handling ------
    //
    // The guard takes Enter out of the frame, and that covers Enter. It does
    // not cover a mouse — egui works clicks out from this frame's events
    // before the guard is called — and it must not cover Space, which is
    // ordinary typing and has to reach the note field. Those two are held by
    // the widgets themselves: disabled while the guard is shut, and never
    // focusable. Both are asserted here through egui's own handling rather
    // than by reading the code, because that is the only way to know egui
    // agrees. No display is needed for any of it.

    /// A window in the phase where it has buttons, writing where a test can
    /// read what went out.
    fn an_awaiting_window() -> (PromptApp, Arc<std::sync::Mutex<Vec<u8>>>) {
        let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app =
            PromptApp::new(rx, Box::new(Sink(Arc::clone(&sink))), Arc::new(OnceLock::new()));
        app.state.handle(DaemonMsg::Request(a_request(90)));
        (app, sink)
    }

    struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("sink").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn raw(events: Vec<egui::Event>) -> egui::RawInput {
        egui::RawInput {
            events,
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(800.0, 600.0),
            )),
            ..Default::default()
        }
    }

    /// Draw the verdict area for one frame and hand back the Approve button.
    fn draw(
        app: &mut PromptApp,
        ctx: &egui::Context,
        events: Vec<egui::Event>,
        open: bool,
    ) -> egui::Response {
        let mut approve = None;
        // The same entry point eframe uses to hand an app its root `Ui`.
        let mut out = ctx.run_ui(raw(events), |ui| {
            approve = Some(
                egui::CentralPanel::default().show(ui, |ui| app.verdict_area(ui, open)).inner,
            );
        });
        // epaint refuses to be dropped holding texture deltas nobody applied.
        out.textures_delta.clear();
        approve.expect("the central panel drew")
    }

    /// Press and release the mouse on the Approve button, the way a hand
    /// would: one frame to place the pointer, one to press, one to release.
    fn click_approve(open: bool) -> Vec<u8> {
        let (mut app, sink) = an_awaiting_window();
        let ctx = egui::Context::default();
        let at = draw(&mut app, &ctx, Vec::new(), open).rect.center();
        let button = |pressed| egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        draw(&mut app, &ctx, vec![egui::Event::PointerMoved(at)], open);
        draw(&mut app, &ctx, vec![button(true)], open);
        draw(&mut app, &ctx, vec![button(false)], open);
        sink.lock().expect("sink").clone()
    }

    #[test]
    fn a_mouse_click_during_the_guard_approves_nothing() {
        assert!(
            click_approve(false).is_empty(),
            "a click landed on Approve while the guard was shut"
        );
    }

    #[test]
    fn the_same_click_after_the_guard_does_approve() {
        // The control for the test above: without this, a click that never
        // lands would look like a guard that works.
        let out = String::from_utf8(click_approve(true)).expect("utf-8");
        assert!(out.contains("approve"), "the click did not reach Approve at all: {out:?}");
    }

    #[test]
    fn egui_will_not_give_a_verdict_button_the_focus_that_space_activates() {
        let (mut app, _sink) = an_awaiting_window();
        let ctx = egui::Context::default();

        let approve = draw(&mut app, &ctx, Vec::new(), true);
        assert!(
            !approve.sense.is_focusable(),
            "a verdict button asks for focus, so Space would activate it"
        );

        // And egui agrees, when asked the hard way: focus requested, and
        // surrendered again by the next frame because the button is not the
        // sort of thing that holds it.
        approve.request_focus();
        let approve = draw(&mut app, &ctx, Vec::new(), true);
        assert!(!approve.has_focus(), "egui gave a verdict button the keyboard focus");
    }

    // ---- what the window actually draws -----------------------------------
    //
    // The bug this layout exists to fix is a window that showed the title and
    // the reason and not the command, so it is not enough to know that the
    // drawing code runs. These tests read the text egui laid out and assert
    // the command is in it. No display is needed: `run_ui` produces the same
    // shapes it would send to a GPU.

    /// Every string egui laid out this frame, joined.
    fn text_on_screen(output: &egui::FullOutput) -> String {
        fn walk(shape: &egui::epaint::Shape, out: &mut String) {
            match shape {
                egui::epaint::Shape::Text(text) => {
                    out.push_str(text.galley.text());
                    out.push('\n');
                }
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        walk(shape, out);
                    }
                }
                _ => {}
            }
        }
        let mut out = String::new();
        for clipped in &output.shapes {
            walk(&clipped.shape, &mut out);
        }
        out
    }

    /// Draw the whole window and hand back what it says.
    ///
    /// Three frames, not one: a panel learns its height from the frame
    /// before, so a pane measured against the first frame's guess is not the
    /// pane a reader sees.
    fn window_text(app: &mut PromptApp, open: bool) -> String {
        let ctx = egui::Context::default();
        // Twice: the first frame is what teaches the panels their size, and
        // a pane sized against a zero-height guess is not the pane a user
        // sees.
        for _ in 0..2 {
            let mut out = ctx.run_ui(raw(Vec::new()), |ui| app.window(ui, open));
            out.textures_delta.clear();
        }
        let mut out = ctx.run_ui(raw(Vec::new()), |ui| app.window(ui, open));
        let text = text_on_screen(&out);
        out.textures_delta.clear();
        text
    }

    /// A window awaiting a verdict on `command`.
    fn a_window_showing(command: &str) -> PromptApp {
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()));
        let mut request = a_request(90);
        request.payload = Payload::command(
            &render_command(command, &BTreeMap::from([("HOME".into(), "/home/u".into())])),
            Vec::new(),
            PathBuf::from("/tmp"),
            false,
            false,
        );
        app.state.handle(DaemonMsg::Request(request));
        app
    }

    #[test]
    fn the_window_draws_the_command_and_not_only_the_agents_summary() {
        let drawn = window_text(&mut a_window_showing("rm -rf /var/tmp/build"), true);

        assert!(drawn.contains("delete the build directory"), "the title is missing: {drawn}");
        assert!(
            drawn.contains("rm -rf /var/tmp/build"),
            "the window is asking about a command it does not show: {drawn}"
        );
    }

    #[test]
    fn a_separator_is_on_screen_rather_than_faded_out_of_it() {
        let drawn = window_text(&mut a_window_showing("ls; rm -rf target"), true);

        assert!(drawn.contains(';'), "the separator was not drawn at all: {drawn}");
    }

    #[test]
    fn a_disguised_character_is_chipped_in_both_panes() {
        // Cyrillic a and a right-to-left override. Each chips once per pane,
        // so each label appears twice: the raw pane is not the pane that gets
        // to be honest second.
        let drawn = window_text(&mut a_window_showing("echo us\u{0430}r\u{202e}"), true);

        assert_eq!(drawn.matches("[U+0430]").count(), 2, "chipped in one pane only: {drawn}");
        assert_eq!(drawn.matches("[RLO]").count(), 2, "chipped in one pane only: {drawn}");
    }

    #[test]
    fn a_variable_is_shown_with_its_value_beside_it_and_never_instead_of_it() {
        let drawn = window_text(&mut a_window_showing("echo $HOME"), true);

        assert!(drawn.contains("$HOME"), "the reference was replaced by its value: {drawn}");
        assert!(drawn.contains("/home/u"), "the value was not shown at all: {drawn}");
    }

    #[test]
    fn the_window_draws_the_clock_and_the_queue_behind_it() {
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()));
        let mut request = a_request(45);
        request.queue_depth = 2;
        app.state.handle(DaemonMsg::Request(request));

        let drawn = window_text(&mut app, true);

        assert!(drawn.contains("s left to decide"), "there is no countdown at all: {drawn}");
        assert!(drawn.contains("2 more waiting"), "the queue badge is missing: {drawn}");
    }

    #[test]
    fn an_approved_command_gets_a_window_that_says_so_and_offers_kill() {
        let mut app = a_window_showing("sleep 5");
        app.stream = true;
        let frame = app.state.decide(Verdict::Approve { stream: true });
        answer(&mut app.out, &mut app.state, frame);
        app.state.handle(DaemonMsg::Output {
            stream: Stream::Stdout,
            text: "half way through".to_string(),
        });

        let drawn = window_text(&mut app, true);

        assert_eq!(app.state.phase(), Phase::Running);
        assert!(drawn.contains("running"), "the window does not say what it is doing: {drawn}");
        assert!(drawn.contains("Kill"), "there is no way to stop it: {drawn}");
        assert!(drawn.contains("half way through"), "the output is not shown: {drawn}");
        // "Approved." contains "Approve", so the verdict row is checked by
        // the button that has no other reason to be on screen.
        assert!(!drawn.contains("Deny"), "it still offers a verdict on what is running: {drawn}");
    }

    #[test]
    fn the_window_says_who_it_runs_as_and_where() {
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()));
        let mut request = a_request(90);
        request.payload = Payload::command(
            &render_command("id", &BTreeMap::new()),
            Vec::new(),
            PathBuf::from("/srv/app"),
            true,
            false,
        );
        app.state.handle(DaemonMsg::Request(request));

        let drawn = window_text(&mut app, true);

        assert!(drawn.contains("ROOT"), "a root command did not say so: {drawn}");
        assert!(drawn.contains("/srv/app"), "the working directory is missing: {drawn}");
    }

    #[test]
    fn no_debug_formatted_rust_name_reaches_the_window() {
        // The skeleton drew the phase as `AwaitingVerdict`. Developer text in
        // a window whose job is to be believed reads as unfinished.
        let drawn = window_text(&mut a_window_showing("ls"), true);

        for name in ["AwaitingVerdict", "WaitingForRequest", "Phase::", "SpanKind", "Payload"] {
            assert!(!drawn.contains(name), "{name} is on screen: {drawn}");
        }
    }

    #[test]
    fn a_command_too_long_for_the_window_cannot_push_the_buttons_off_it() {
        // Fifty segments, each asking for its own line: far more than fits.
        let long = vec!["echo hello"; 50].join("; ");
        let drawn = window_text(&mut a_window_showing(&long), true);

        assert!(drawn.contains("Approve"), "Approve was pushed off the window: {drawn}");
        assert!(drawn.contains("Deny"), "Deny was pushed off the window: {drawn}");
    }

    #[test]
    fn a_long_title_cannot_push_the_command_off_the_window() {
        // `title` is agent-written and capped only at four kilobytes, which
        // is enough prose to fill the window twice over. An agent that could
        // do that could hide the command behind its own summary.
        let mut app = a_window_showing("rm -rf /var/tmp/build");
        let long = "a very long story about why this is necessary. ".repeat(90);
        let mut request = a_request(90);
        request.title = long;
        request.payload = app.state.request().expect("a request").payload.clone();
        app.state = PromptState::new();
        app.state.handle(DaemonMsg::Request(request));

        let drawn = window_text(&mut app, true);

        assert!(
            drawn.contains("rm -rf /var/tmp/build"),
            "a long title crowded the command off the window: {drawn}"
        );
        assert!(drawn.contains("Approve"), "and it took the buttons with it: {drawn}");
    }

    #[test]
    fn a_danger_marker_is_drawn_where_the_reader_will_see_it() {
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()));
        let mut request = a_request(90);
        request.payload = Payload::command(
            &render_command("rm -rf /", &BTreeMap::new()),
            vec!["deletes a directory tree".to_string()],
            PathBuf::from("/tmp"),
            false,
            false,
        );
        app.state.handle(DaemonMsg::Request(request));

        let drawn = window_text(&mut app, true);

        assert!(
            drawn.contains("deletes a directory tree"),
            "a marker the daemon found never reached the window: {drawn}"
        );
    }

    #[test]
    fn a_swap_never_draws_an_empty_pane_that_reads_as_nothing_changing() {
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()));
        let mut request = a_request(90);
        request.payload = Payload::swap(
            PathBuf::from("/tmp/conf.toml"),
            crate::swap::SwapPlan {
                kind: crate::swap::PlanKind::Replace,
                landing_mode: 0o644,
                landing_owner: crate::swap::Principal { id: 1000, name: Some("u".into()) },
                landing_group: crate::swap::Principal { id: 1000, name: Some("u".into()) },
                hash_before: Some("aa".into()),
                size_delta: 4,
            },
            &crate::render::diff::side_by_side("port = 80\n", "port = 8080\n"),
        );
        app.state.handle(DaemonMsg::Request(request));

        let drawn = window_text(&mut app, true);

        assert!(drawn.contains("/tmp/conf.toml"), "the file is not named: {drawn}");
        assert!(drawn.contains("0644"), "the landing mode is missing: {drawn}");
        assert!(drawn.contains("port = 8080"), "the proposed line was never drawn: {drawn}");
        assert!(drawn.contains("port = 80"), "the current line was never drawn: {drawn}");
    }

    #[test]
    fn a_command_in_its_own_terminal_says_why_it_cannot_be_streamed_here() {
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()));
        let mut request = a_request(90);
        request.payload = Payload::command(
            &render_command("vim /etc/hosts", &BTreeMap::new()),
            Vec::new(),
            PathBuf::from("/tmp"),
            false,
            true,
        );
        app.state.handle(DaemonMsg::Request(request));

        let drawn = window_text(&mut app, true);

        assert!(
            drawn.contains("terminal of its own"),
            "a checkbox that cannot be ticked was left unexplained: {drawn}"
        );
    }

    #[test]
    fn a_swap_offers_no_checkbox_for_output_it_will_never_produce() {
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()));
        let mut request = a_request(90);
        request.payload = Payload::swap(
            PathBuf::from("/tmp/f"),
            crate::swap::SwapPlan {
                kind: crate::swap::PlanKind::Create,
                landing_mode: 0o600,
                landing_owner: crate::swap::Principal { id: 1, name: None },
                landing_group: crate::swap::Principal { id: 1, name: None },
                hash_before: None,
                size_delta: 2,
            },
            &crate::render::diff::side_by_side("", "hi\n"),
        );
        app.state.handle(DaemonMsg::Request(request));

        let drawn = window_text(&mut app, true);

        assert!(!drawn.contains("Stream output"), "a swap offered to stream output: {drawn}");
    }

    #[test]
    fn a_request_this_window_cannot_draw_closes_it_rather_than_being_guessed_at() {
        let mut state = PromptState::new();
        let mut request = a_request(90);
        let Payload::Command { spans, raw, danger, cwd, root, interactive, .. } = request.payload
        else {
            panic!("not a command")
        };
        // A one-line form that does not match the spans it claims to
        // summarise: the two halves of the window would describe different
        // commands.
        request.payload = Payload::Command {
            display_line: "something else entirely".to_string(),
            spans,
            raw,
            danger,
            cwd,
            root,
            interactive,
        };

        state.handle(DaemonMsg::Request(request));

        assert!(state.should_close(), "the window drew a frame it could not check");
        assert!(state.broken().is_some(), "and it did not say why");
        assert_eq!(state.phase(), Phase::Closed);
        assert!(state.shown().is_none(), "it kept something to draw anyway");
    }

    #[test]
    fn a_request_that_can_be_drawn_is_kept_in_its_checked_form() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));

        assert!(state.shown().is_some(), "the window has nothing to draw");
        assert_eq!(state.phase(), Phase::AwaitingVerdict);
    }

    #[test]
    fn the_verdict_buttons_are_dead_to_every_kind_of_press_while_the_guard_is_shut() {
        let (mut app, _sink) = an_awaiting_window();
        let ctx = egui::Context::default();

        let shut = draw(&mut app, &ctx, Vec::new(), false);
        assert!(!shut.enabled(), "the buttons are live while the guard is shut");

        let open = draw(&mut app, &ctx, Vec::new(), true);
        assert!(open.enabled(), "the buttons never become live at all");
    }
}

