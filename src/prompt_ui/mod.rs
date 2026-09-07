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
pub mod visibility;

use std::collections::VecDeque;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, OnceLock};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use chrono::{DateTime, Utc};
use eframe::egui;

use crate::exec::Stream;
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
                self.queue_depth = req.queue_depth;
                self.request = Some(req);
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
            stream: true,
            note: String::new(),
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
        egui::CentralPanel::default().show(ui, |ui| {
            // Agent-controlled text, defanged by the daemon. Drawn as text
            // and not interpreted; nothing here undoes the defanging. Copied
            // out so the buttons below can still borrow the state machine.
            let shown = self.state.request().map(|r| (r.title.clone(), r.reason.clone()));
            let Some((title, reason)) = shown else {
                ui.label("Waiting for hatch to send the request…");
                return;
            };

            ui.heading(title);
            ui.label(reason);
            ui.separator();

            if let Some(left) = self.state.seconds_remaining(Utc::now()) {
                ui.label(format!("{left}s left"));
            }
            if let Some(waiting) = self.state.queue_badge() {
                ui.label(format!("{waiting} more waiting"));
            }
            ui.label(format!("{:?}", self.state.phase()));

            match self.state.phase() {
                Phase::AwaitingVerdict => self.verdict_buttons(ui),
                Phase::Running => {
                    if ui.button("Kill").clicked() {
                        let kill = self.state.request_kill();
                        answer(&mut self.out, &mut self.state, kill);
                    }
                }
                Phase::WaitingForRequest | Phase::Closed => {}
            }
        });
    }
}

impl PromptApp {
    /// The buttons, and nothing more than the buttons.
    ///
    /// The layout, the typing guard and the diff view are other work; this is
    /// here to prove that a press becomes a frame on the wire.
    fn verdict_buttons(&mut self, ui: &mut egui::Ui) {
        ui.checkbox(&mut self.stream, "Stream output");
        ui.text_edit_singleline(&mut self.note);

        let note = self.note.clone();
        let mut decided = None;
        if ui.button("Approve").clicked() {
            decided = Some(Verdict::Approve { stream: self.stream });
        }
        if ui.button("Deny").clicked() {
            decided = Some(Verdict::Deny { note: note.clone() });
        }
        if ui.button("Explain").clicked() {
            decided = Some(Verdict::Revise { kind: ReviseKind::Explain, note: note.clone() });
        }
        if ui.button("Simplify").clicked() {
            decided = Some(Verdict::Revise { kind: ReviseKind::Simplify, note: note.clone() });
        }
        if ui.button("I'll run it myself").clicked() {
            decided = Some(Verdict::SelfRun { note });
        }

        if let Some(verdict) = decided {
            let frame = self.state.decide(verdict);
            answer(&mut self.out, &mut self.state, frame);
        }
    }
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
}

