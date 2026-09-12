//! The `hatch prompt` window: the phase machine, and the NDJSON wiring that
//! feeds it.
//!
//! One process draws one window and exits — usually when the daemon says so,
//! and once on its own; see "After the command". It speaks [`crate::protocol`] on
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
//! double-click, a second button pressed in the same frame, a click on a
//! window that is already running, and every button on a window that has
//! outlived its request all reach a state that is no longer waiting for a
//! verdict, and get nothing to send.
//!
//! # After the command
//!
//! A window whose reader ticked "Stream output to this window" does not close
//! on [`DaemonMsg::Finished`]. The whole life of an ordinary command is
//! milliseconds, so closing there took the output away at the instant it
//! arrived — the box working exactly as built and being useless. Instead the
//! window *lingers* for [`LINGER`], showing the result with a countdown on it,
//! and a button turns it into a *detached viewer*: no countdown, no verdict,
//! just the output, a way to copy it and a way to close it. A run nobody asked
//! to watch is unchanged and closes on the frame.
//!
//! From the moment that frame is sent the daemon has let go — see
//! [`crate::prompter::PromptSession::detach`] — so this is the only state in
//! this program's life with nothing outside it holding a deadline over it. Two
//! things follow, and both are load-bearing:
//!
//! * **It cannot decide anything.** [`Phase::Lingering`] and
//!   [`Phase::Detached`] are past [`Phase::AwaitingVerdict`] and no phase
//!   returns there, so [`PromptState::decide`] produces nothing; the guard's
//!   two keys are answered before they reach it as well. A verdict from a
//!   detached window is not merely ignored by the daemon — it cannot be built.
//! * **It has to end itself.** Four ways out, and each has a backstop that
//!   does not need the event loop: the countdown ([`arm_linger_backstop`]),
//!   the reader closing it (the viewport's close, then [`arm_exit_backstop`]),
//!   the channel ending because the daemon has gone (the reader thread, after
//!   [`CHANNEL_END_GRACE`]), and a window that never opened or stopped drawing
//!   (`eframe` returning, which returns from [`run_prompt`]).
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
pub mod theme;
pub mod visibility;

use std::collections::VecDeque;
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use eframe::egui;

use crate::exec::Stream;
use crate::prefs::{Prefs, PrefsFile};
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
///
/// Wide enough for the side-by-side diff to be the view a `swap_file` request
/// actually gets: the two columns and their gutters are measured in
/// characters of the monospace font, and at 900 points a column held few
/// enough of them that ordinary source lines sent the whole diff to the
/// unified fallback. Height is unchanged -- the panes scroll, and a taller
/// window would only take more of the screen for the same reading.
const WINDOW_SIZE: [f32; 2] = [1280.0, 700.0];

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
/// Asking the viewport to close is the ordinary path; this is the backstop for
/// an event loop that is no longer running one, and it is a thread precisely
/// because a wedged loop cannot run a timer of its own.
///
/// It used to be belt to the daemon's braces — a window that would not go was
/// killed 500 ms after its outcome. A window the daemon has let go of has no
/// braces, so this is the only thing between "the reader closed it" and the
/// process actually ending.
const EXIT_BACKSTOP: Duration = Duration::from_millis(250);

/// How long a finished window stays when the reader asked to watch the
/// command run.
///
/// The bug this exists for: everything up to `Finished` takes milliseconds for
/// an ordinary command, so a window that closed on that frame closed at the
/// exact moment the output it was asked to show arrived. Ten seconds is long
/// enough to read a screenful and reach the button that keeps it, and short
/// enough that a reader running one command after another is not collecting
/// windows. It is not long enough to *read* a long output in, which is what
/// the button is for.
///
/// It applies to streamed runs only. A window nobody asked to watch has
/// nothing to linger over and closes on the outcome as it always did.
const LINGER: Duration = Duration::from_secs(10);

/// How long after the countdown has run out the process leaves anyway.
///
/// [`LINGER`] is enforced by the event loop, and a lingering window is the
/// first state in this program's life with no daemon watching it — nothing
/// else will kill it if that loop stops running. So the countdown gets a
/// thread as well, and the slack is what separates "the loop is busy" from
/// "the loop is gone".
const LINGER_BACKSTOP: Duration = Duration::from_secs(2);

/// How long the process may outlive its own channel.
///
/// The daemon holds this window's stdin open for as long as the window lives,
/// so the channel ending means the daemon has gone — at which point nothing
/// will ever arrive again and nothing is left to kill this process either.
/// The grace is there so the ordinary ending, where the state machine sees the
/// break and closes properly, is the one that happens.
const CHANNEL_END_GRACE: Duration = Duration::from_secs(1);

/// How long a "copied" note stays up.
///
/// A button that puts something on the clipboard and says nothing is a button
/// the reader presses twice.
const COPY_NOTICE: Duration = Duration::from_secs(2);

/// How much of an approved command's output the window keeps.
///
/// The live view exists so the user can decide whether to press Kill, and a
/// decision is made from the last screenful, not the first megabyte. Without
/// a cap a chatty command would grow this window's memory for as long as it
/// runs, which is a denial of service written by the agent that asked for the
/// command.
const OUTPUT_CAP: usize = 1 << 20;

/// The size of the two buttons that settle the request, in multiples of one
/// line of button text: width, then height.
///
/// Wide and tall enough that they are aimed at rather than clipped, and the
/// same size as each other: Approve is the one that runs something, and
/// making it the larger of the two would be an invitation dressed as an
/// affordance.
///
/// Multiples and not points, because the font size is the reader's to choose
/// — see [`crate::config::Config::font_size`] — and a button pinned to 34
/// points is a button the text grows out of.
const PRIMARY_BUTTON_ROWS: egui::Vec2 = egui::vec2(10.0, 2.3);

/// The gap between Approve and Deny.
///
/// A slipped pointer has to cross it, and it lands on the panel rather than
/// on the other verdict. Deliberately larger than egui's own spacing, which
/// is tuned for buttons whose worst outcome is being pressed by accident.
///
/// Points, and deliberately not a multiple of the text like its neighbours:
/// what this measures is how far a slipped pointer has to travel, which is a
/// distance on the screen and not a quantity of text.
const PRIMARY_GAP: f32 = 28.0;

/// The label on the control that gives a command a terminal.
///
/// "Run it" rather than "Interactive", because the reader is being asked what
/// to do with this command and not to classify it. The word the agent's
/// parameter uses is the agent's business.
const TERMINAL_LABEL: &str = "Run it in a terminal";

/// What choosing a terminal costs, said where it is chosen.
///
/// Two sentences and no hedging. The first states the mechanism, because a
/// reader who knows *why* it happens can work out the cases this sentence does
/// not list; the second is the one instruction that follows from it, which is
/// the part somebody skimming will take away. See
/// [`PromptApp::terminal_row`] for why it is not a tooltip.
const TERMINAL_CAPTURE: &str = "Everything in that terminal is sent to the agent, including what you type into it. Do not type a password there.";

/// Why the control is dead on a request that already asked for a terminal.
const TERMINAL_ASKED: &str = "The agent asked for one.";

/// The label on the control that sends the window away at the verdict.
///
/// "When I decide" and not "after approving", although approving is the only
/// verdict it changes anything about. Every other verdict already closes this
/// window on the frame it is sent — see [`PromptState::decide`] — so a control
/// named after the exception would be named after the one case it does not
/// cover. This one is a promise about the whole row of buttons, and all six of
/// them keep it.
const CLOSE_LABEL: &str = "Close when I decide";

/// What ticking it gives up, said where it is ticked.
///
/// Beside the box and not in a tooltip, for the reason
/// [`PromptApp::terminal_row`] gives at length: a cost belongs next to the
/// control that incurs it, before it is incurred, where the person who does
/// not already suspect there is something to read will see it.
///
/// One short sentence where the terminal's warning gets two, and that is
/// proportion rather than economy. What is given up here is an affordance the
/// reader is choosing to do without: for an ordinary run `exec_timeout_secs`
/// still ends a runaway, and a terminal run — which has no such deadline, by
/// design — is one the reader is sitting in front of, which is a better stop
/// than a button behind another window. Nothing about it leaves the machine,
/// which is what the other sentence is about.
const CLOSE_COST: &str = "The Kill button goes with it.";

/// Why the control is dead on a run the reader asked to watch.
///
/// Ticking Stream wins, and this is the window saying which of two
/// contradictory instructions it is following rather than quietly dropping
/// one. The asymmetry is deliberate: Stream is a choice about *this* command,
/// made in front of it, and a standing preference set some other day must not
/// silently overrule one. The preference itself is untouched — the box is
/// drawn unticked because that is what will happen, not because anything was
/// forgotten — so unticking Stream brings it straight back.
const CLOSE_WATCHING: &str = "You asked to watch this one.";

/// The most of the window the live output takes while a command runs, in
/// lines of the monospace font it is drawn in.
///
/// Lines and not points, for the reason [`PRIMARY_BUTTON_ROWS`] gives: the
/// question is how much of the output a reader can see at once, and that is a
/// number of lines whatever size they have chosen to read at.
const RUNNING_OUTPUT_ROWS: f32 = 10.0;

/// How much larger than body text the headline is drawn.
///
/// The headline is two paragraphs of agent-written prose and should read as
/// prose set large, so it scales with whatever size the reader chose rather
/// than being pinned to a point count of its own.
pub const HEADLINE_SCALE: f32 = 1.5;

/// How the other text styles are sized against the configured one.
///
/// `Small` is the pane labels and the captions, `Heading` is egui's own and
/// is unused by this window — set anyway, so a widget that reaches for it
/// does not fall back to a size nothing else here uses.
const SMALL_SCALE: f32 = 0.8;
const HEADING_SCALE: f32 = 1.4;

/// The face the two panes are drawn in.
///
/// # Chosen, not inherited
///
/// Hack is what egui bundles and what this window has always used, and it was
/// right by accident until this was written down. It is named here because
/// the *reasons* it is right are requirements of this program and not
/// preferences:
///
/// * **No ligatures.** A programming face with them draws `&&` as one glyph,
///   `!=` as `≠`, `->` as `→`. That is the display rendering something that
///   is not the characters — the thing this project refuses everywhere else —
///   and it would break the side-by-side fit rule, which counts characters
///   against one advance. Hack has none, and
///   `the_pane_draws_two_characters_as_two_characters` is what keeps a
///   replacement face from having any.
/// * **One advance, every glyph.** [`panes::widest_line`] measures a line in
///   characters and the fit rule multiplies by the width of `'0'`. A face
///   where one glyph is wider makes that arithmetic a guess.
/// * **The characters that change a command's meaning are told apart.**
///   `l`/`1`/`I`, `0`/`O`, `,`/`.`, and the three quotes: a misread quote is a
///   different command. Hack draws a slashed zero and a serifed `1`, and
///   `the_characters_a_misreading_turns_into_another_command_are_not_alike`
///   holds it to that by comparing what is actually rasterised.
///
/// # Why the fallback chain is one face long
///
/// egui's own monospace family falls back to the *proportional* face for
/// anything Hack lacks, which is a glyph of another width in a column
/// measured in one. It cannot fire today — everything either pane draws is
/// ASCII printable plus the handful of glyphs below, and Hack has every one
/// of them — and "cannot fire" is the kind of claim that stops being true
/// quietly.
/// So the family is Hack alone, and a face that lost a glyph would draw a
/// visible box rather than a silently mismeasured line.
pub const MONOSPACE_FACE: &str = "Hack";

/// The face everything that is not a command is drawn in.
///
/// Ubuntu-Light, which is egui's own, kept deliberately: it is a humanist
/// sans with open counters that reads well as the prose the headline is. It
/// carries none of the load above — nothing measured in characters is drawn
/// in it, and nothing a reader approves is either.
///
/// It does draw chips, though, which is why [`MONOSPACE_FACE`] is behind it
/// in that family. The lingering window names the command it ran as one small
/// proportional line, chips included, and Ubuntu-Light has no `↵`: the glyph
/// that stands in for an invisible character was itself drawn as an empty
/// box. A chip nobody can read is the failure chips exist to prevent, so the
/// face that has the glyph is the fallback — and it can fire only where
/// nothing is measured in characters.
pub const PROPORTIONAL_FACE: &str = "Ubuntu-Light";

/// The glyphs this window draws that are not the source's own characters.
///
/// The three structural chips, the arrow that introduces a resolved value,
/// and the ellipsis egui elides with and this window's own sentences end in.
/// Listed here because they are the only non-ASCII either family has to
/// serve, and so are the whole of what the chains above have to be checked
/// against.
#[cfg(test)]
const DRAWN_GLYPHS: &[char] = &['\u{21B5}', '\u{21E5}', '\u{21E4}', '\u{2192}', '\u{2026}'];

/// Install the faces this window draws in.
///
/// Applied to the context before anything is laid out, and before
/// [`apply_font_size`], which sizes what this chooses.
pub fn apply_faces(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.families.insert(egui::FontFamily::Monospace, vec![MONOSPACE_FACE.to_owned()]);
    fonts.families.insert(
        egui::FontFamily::Proportional,
        vec![
            PROPORTIONAL_FACE.to_owned(),
            // The chips' glyphs, which this face does not have. Behind it,
            // so it is reached only for what Ubuntu-Light cannot draw.
            MONOSPACE_FACE.to_owned(),
            // Kept, and only here: the proportional family draws text nothing
            // measures, so a glyph of another width in it costs nothing.
            "NotoEmoji-Regular".to_owned(),
            "emoji-icon-font".to_owned(),
        ],
    );
    ctx.set_fonts(fonts);
}

/// Draw every text style at the size the config asks for.
///
/// Applied once, to the context's style, rather than at each label: the
/// side-by-side fit rule measures a column in characters of the monospace
/// font *as the style resolves it* — see
/// [`crate::prompt_ui::panes::widest_line`] and the `advance` it is compared
/// against — so the size has to reach the measurement and the drawing through
/// the same place, or the two disagree and the window promises a column that
/// cannot hold its lines.
pub fn apply_font_size(ctx: &egui::Context, points: f32) {
    use egui::{FontFamily, FontId, TextStyle};

    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (TextStyle::Small, FontId::new(points * SMALL_SCALE, FontFamily::Proportional)),
            (TextStyle::Body, FontId::new(points, FontFamily::Proportional)),
            (TextStyle::Button, FontId::new(points, FontFamily::Proportional)),
            (TextStyle::Heading, FontId::new(points * HEADING_SCALE, FontFamily::Proportional)),
            (TextStyle::Monospace, FontId::new(points, FontFamily::Monospace)),
        ]
        .into();
    });
}

/// How much larger than body text the countdown is drawn once the window is
/// about to be taken away.
///
/// A multiple rather than a point count, for the reason
/// [`PRIMARY_BUTTON_ROWS`] gives. Colour *and* size, never colour alone,
/// which would say nothing to a reader who cannot tell red from grey.
const IMMINENT_SCALE: f32 = 1.35;

/// The size of one primary button, against the style in force.
fn primary_button(ui: &egui::Ui) -> egui::Vec2 {
    ui.text_style_height(&egui::TextStyle::Button) * PRIMARY_BUTTON_ROWS
}

/// How wide the controls are: exactly the two primary buttons and the gap
/// between them.
///
/// The cluster is centred in the panel rather than left against its edge —
/// Approve and Deny are the question the window exists to ask, and at 1280
/// points wide a row of controls in the bottom-left corner reads as an
/// afterthought. Everything in the cluster is this wide, so the note field
/// and the buttons line up as one thing rather than three left edges that
/// happen to agree.
fn cluster_width(ui: &egui::Ui) -> f32 {
    2.0 * primary_button(ui).x + PRIMARY_GAP
}

/// Lay out `add` in a `width`-wide row, centred in whatever it is placed in.
///
/// The width is given rather than measured because every row here has one it
/// knows: a row that shrank to its contents would move as the contents
/// changed, and the two verdict buttons must not drift under a pointer that
/// is already on the way to one.
fn centred_row<R>(
    ui: &mut egui::Ui,
    width: f32,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    ui.allocate_ui_with_layout(
        egui::vec2(width, 0.0),
        egui::Layout::left_to_right(egui::Align::Center).with_main_align(egui::Align::Center),
        add,
    )
    .inner
}

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
    /// The command has finished, the reader asked to watch it, and the window
    /// is holding the result up for a few seconds before taking itself away.
    ///
    /// Reachable only through [`Phase::Running`], and only for a run the
    /// reader ticked the stream box on.
    Lingering,
    /// The reader kept the window. It is a viewer now: the output, a way to
    /// copy it and a way to close it, and no decision of any kind.
    ///
    /// The request that opened this window is over by the time this phase is
    /// reachable, and the daemon has let go of the process — see
    /// [`crate::prompter::PromptSession::detach`].
    Detached,
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
    output_dropped: bool,
    streaming: bool,
    elevating: bool,
    linger_until: Option<Instant>,
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
            output_dropped: false,
            streaming: false,
            elevating: false,
            linger_until: None,
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

    /// Whether what this window is showing runs, or ran, as root.
    ///
    /// Read off the payload and not off the phase, because it is not a phase:
    /// it is true from the moment the request arrives until the window goes,
    /// and every phase in between draws the mark that says so. A `swap_file`
    /// request answers `false` here whatever its plan says — it states its
    /// own ownership in its own header, and a second claim about the same
    /// thing in a second vocabulary is how the two come to disagree.
    pub fn runs_as_root(&self) -> bool {
        self.shown().and_then(panes::RunContext::of).is_some_and(|context| context.root)
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

    /// The output as one string, which is what is drawn and what is copied.
    ///
    /// One place, so the copy action cannot drift from the view: a button that
    /// puts something other than what is on screen on the clipboard is worse
    /// than no button.
    pub fn output_text(&self) -> String {
        self.output().iter().map(|(_, chunk)| chunk.as_str()).collect()
    }

    /// Whether the cap has already thrown some of the output away.
    ///
    /// Said out loud once there is a copy action: a window that hands over the
    /// last megabyte of a command's output while looking like it is handing
    /// over all of it is a window that lies quietly.
    pub fn output_dropped(&self) -> bool {
        self.output_dropped
    }

    /// Whether the reader asked to watch this run.
    ///
    /// Recorded from the verdict rather than from the checkbox, because the
    /// verdict is the thing that was actually sent: a box unticked in the same
    /// frame as Approve must not change what happens afterwards.
    pub fn streaming(&self) -> bool {
        self.streaming
    }

    /// Whether the window is showing a result rather than asking anything.
    ///
    /// The two phases with no question in them, and the test every path that
    /// could produce a verdict checks itself against.
    pub fn is_viewer(&self) -> bool {
        matches!(self.phase, Phase::Lingering | Phase::Detached)
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
            DaemonMsg::Elevating => self.elevating = true,
            DaemonMsg::Output { stream, text } => {
                // The first byte out of the elevated command is proof that
                // the dialog was answered and the command is running, which
                // is the only signal hatch gets: nothing tells the daemon
                // that a password was typed, so nothing can tell this window
                // either. A run that prints nothing keeps saying it is
                // waiting until the outcome arrives, which is the honest
                // reading of what hatch actually knows.
                self.elevating = false;
                self.push_output(stream, text);
            }
            DaemonMsg::Finished(outcome) => {
                self.outcome = Some(outcome);
                self.elevating = false;
                // The reader ticked a box that says "I want to watch this".
                // For anything but a slow command the whole run is over in
                // milliseconds, so a window that closed on this frame closed
                // at the moment the output arrived — the box working exactly
                // as built and being useless. A streamed run therefore stays,
                // with the result on it, until its own clock or its reader
                // says otherwise.
                //
                // Nothing else changes. A run nobody asked to watch has no
                // result to hold up and closes here as it always did, and the
                // daemon still waits its own grace for that.
                self.phase = match self.streaming {
                    true => {
                        self.linger_until = Some(Instant::now() + LINGER);
                        Phase::Lingering
                    }
                    false => Phase::Closed,
                };
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
        // Not a failure once the window is only a viewer. The request is over,
        // the daemon holds this window's stdin for as long as the window lives,
        // and so the channel ending means the daemon has gone — which is news
        // about hatch, not about this window, and there is nobody left to tell.
        // It still ends the process: a viewer with no channel is exactly the
        // orphan this window must never become.
        if !self.is_viewer() {
            self.broken = Some(why.into());
        }
        self.phase = Phase::Closed;
    }

    /// Let the clock move the window on.
    ///
    /// The one thing this window's own clock is allowed to decide, and it is
    /// allowed to decide it because there is no longer a question open: a
    /// linger that has run out closes. The approval deadline is not decided
    /// here and never will be — that clock belongs to the daemon, which
    /// enforces it by killing this process.
    pub fn tick(&mut self, now: Instant) {
        if self.phase == Phase::Lingering && self.linger_until.is_some_and(|until| now >= until) {
            self.phase = Phase::Closed;
        }
    }

    /// Seconds until a lingering window takes itself away, at `now`.
    ///
    /// `None` in every other phase, which is what tells the drawing half that
    /// there is no countdown to say out loud. Rounded up, so the number the
    /// reader sees is the number of seconds they still have: it reads 1 for
    /// the whole of the last second and reaches 0 as the window goes.
    pub fn linger_seconds_remaining(&self, now: Instant) -> Option<u64> {
        let until = self.linger_until.filter(|_| self.phase == Phase::Lingering)?;
        let left = until.saturating_duration_since(now);
        Some(left.as_secs() + u64::from(left.subsec_nanos() > 0))
    }

    /// Keep the window: stop the countdown and become a viewer.
    ///
    /// Returns whether it did anything, which is how the drawing half knows
    /// not to arm anything twice. Only from [`Phase::Lingering`], and the
    /// phase it moves to has no way back to a question: [`PromptState::decide`]
    /// answers in [`Phase::AwaitingVerdict`] alone, and no phase returns there.
    pub fn keep(&mut self) -> bool {
        if self.phase != Phase::Lingering {
            return false;
        }
        self.phase = Phase::Detached;
        self.linger_until = None;
        true
    }

    /// End the window because the reader asked to, or because the desktop did.
    ///
    /// Deliberately not a failure and deliberately without a reason: a window
    /// somebody closed has nothing to report to the operator. Before a verdict
    /// the daemon reads the dead process as a denial, which is what a window
    /// closed from its title bar already meant.
    pub fn dismiss(&mut self) {
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
        if let Verdict::Approve { stream, .. } = verdict {
            self.streaming = stream;
        }
        self.phase = match verdict {
            // The reader ticked "Close when I decide", so an approval joins
            // the five verdicts that were always over on the frame that
            // carried them. The command is authorised and runs on with no
            // window, which is a state an approved command could always reach
            // — the difference is that this time somebody asked for it, and
            // the frame just written is where they said so.
            Verdict::Approve { closing: true, .. } => Phase::Closed,
            Verdict::Approve { .. } => Phase::Running,
            Verdict::Deny { .. }
            | Verdict::Revise { .. }
            | Verdict::SelfRun { .. }
            | Verdict::StopAndSync { .. } => Phase::Closed,
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
    /// Whether hatch is waiting on a password dialog that is not its own.
    ///
    /// True from the [`DaemonMsg::Elevating`] frame until the first byte of
    /// output or the outcome, whichever comes first. It is not a claim that a
    /// dialog is on screen this instant — hatch is never told that the
    /// password was typed — it is a claim that nothing the user approved is
    /// known to have run yet, which is the thing the reader needs.
    pub fn elevating(&self) -> bool {
        self.elevating
    }

    fn push_output(&mut self, stream: Stream, text: String) {
        self.output_bytes += text.len();
        self.output.push_back((stream, text));
        while self.output_bytes > OUTPUT_CAP && self.output.len() > 1 {
            if let Some((_, dropped)) = self.output.pop_front() {
                self.output_bytes -= dropped.len();
                self.output_dropped = true;
            }
        }
    }
}

// ---- reading the channel ---------------------------------------------------

/// What the reader saw in the item it has just handed over.
///
/// An item cannot be looked at after it has been sent, and these are the two
/// facts a thread outside the event loop needs about one: that the daemon has
/// said its last word, and that the channel is over. Both are the moments a
/// backstop is armed at, and neither may depend on the loop having run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Noticed {
    /// The outcome has arrived. Nothing follows it, and from here the window
    /// answers to its own clock.
    pub final_frame: bool,
    /// The channel has ended, well or badly. This is the last item there is.
    pub last: bool,
}

/// Turn the daemon's half of the channel into [`Incoming`] items until there
/// is nothing left to believe.
///
/// Every exit sends exactly one [`Incoming::Broken`], so the window learns
/// that the channel ended as a fact rather than as silence — including the
/// clean end, where the daemon has said its last word and hung up.
///
/// `wake` runs after each item so an event loop asleep on its own timer
/// notices immediately; the loop's periodic repaint is for the clock, not for
/// this. It is told what the item was, because this thread is the one place
/// that learns the daemon has finished without needing the loop to be running
/// — see [`arm_linger_backstop`].
pub fn read_frames<R: BufRead>(reader: R, tx: &Sender<Incoming>, wake: impl Fn(Noticed)) {
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
        // Read before the item is given away, reported after: the loop must
        // not be woken for something it cannot yet see.
        let noticed = Noticed {
            final_frame: matches!(item, Incoming::Frame(DaemonMsg::Finished(_))),
            last: matches!(item, Incoming::Broken(_)),
        };
        if tx.send(item).is_err() {
            return;
        }
        wake(noticed);
        if noticed.last {
            return;
        }
    }
    let _ = tx.send(Incoming::Broken("hatch closed the channel".to_string()));
    wake(Noticed { final_frame: false, last: true });
}

// ---- the window ------------------------------------------------------------

/// What [`open_window`] is handed to make the app it is going to run.
///
/// A name for it, because eframe's own creator type is one of these wrapped
/// in a `Result` and a lifetime, and spelling it out at the call site is a
/// line of angle brackets that says less than the word does.
pub(crate) type Build = Box<dyn FnOnce(&eframe::CreationContext<'_>) -> Box<dyn eframe::App>>;

/// Open the window this program draws, whatever is going to fill it.
///
/// The viewport, the faces, the point size and the palette, and then whatever
/// `build` makes of the context they were applied to. Two things open this
/// window: [`run_prompt`], which fills it from the daemon on this process's
/// stdin, and [`crate::preview`], which fills it from a sample it built
/// itself. Sharing the function is the point rather than a tidiness: a
/// preview that opened a window of its own would be evidence about a window
/// nobody is ever shown, and the screenshots in the README would be pictures
/// of something that does not exist.
///
/// `title` is the one thing the two differ on, and it is deliberately the one
/// thing that is not in the picture: the screenshot is the client area, so a
/// preview can say "preview" in its title bar and on the taskbar without
/// changing a pixel of what it is a preview *of*. Everything a reader sees
/// inside the frame comes from the same code either way.
///
/// # Errors
///
/// The window could not be opened at all. What happens *in* it is the
/// caller's to report.
pub(crate) fn open_window(
    title: &str,
    font_size: f32,
    theme: theme::Theme,
    build: Build,
) -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_app_id(APP_ID)
            .with_title(title)
            .with_inner_size(WINDOW_SIZE)
            // A no-op on Wayland, where only the compositor may raise a
            // window, and correct everywhere else. The Wayland answer is a
            // compositor rule matching the app id above.
            .with_always_on_top(),
        ..Default::default()
    };

    eframe::run_native(
        APP_ID,
        options,
        Box::new(move |cc| {
            apply_faces(&cc.egui_ctx);
            apply_font_size(&cc.egui_ctx, font_size);
            theme::apply(&cc.egui_ctx, theme);
            Ok(build(cc))
        }),
    )
    .map_err(|e| anyhow::anyhow!("the approval window could not be opened: {e}"))
}

/// Draw one approval window, and do not return until it is over.
///
/// # Errors
///
/// The window could not be opened at all, or the channel ended in a way that
/// is worth telling the operator about. Neither is something the daemon reads:
/// it sees a process that exited without deciding, which is a denial.
pub fn run_prompt() -> anyhow::Result<()> {
    let fatal: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
    // Best effort, and deliberately read-only: this process draws a window
    // and owns nothing, so a missing or unreadable config is a window at the
    // default size rather than a request that never opens one -- which the
    // daemon would resolve as a denial.
    let (font_size, theme) = crate::config::display_style();
    // The one file this process owns, held to the same rule: see
    // `crate::prefs`. A window that would not open over a preference it could
    // not read would be a denial of a request nobody was ever shown.
    let prefs = PrefsFile::from_env();

    let app_fatal = Arc::clone(&fatal);
    open_window(
        "hatch — approval",
        font_size,
        theme,
        Box::new(move |cc| {
            // The reader is started here, not before, so it has a real
            // context to wake and so a window that never opens never reads a
            // request it could not have shown. Nothing is lost by waiting:
            // the daemon's first write fits in the pipe.
            let (tx, rx) = std::sync::mpsc::channel();
            let ctx = cc.egui_ctx.clone();
            let app = PromptApp::new(rx, Box::new(io::stdout()), Arc::clone(&app_fatal), prefs);
            let kept = app.kept();
            std::thread::spawn(move || {
                read_frames(io::stdin().lock(), &tx, |noticed| {
                    ctx.request_repaint();
                    // The daemon's last word. Everything after this is the
                    // window's own business, so the deadline that does not
                    // need the event loop is armed here — on this thread,
                    // which has just proved it is running.
                    if noticed.final_frame {
                        arm_linger_backstop(Arc::clone(&kept), Arc::clone(&app_fatal));
                    }
                });
                // The channel is over, and the daemon holds this window's
                // stdin for as long as the window lives — so this is the
                // daemon going away, and nothing will ever arrive again.
                // The state machine has been told and will close in the
                // ordinary way; this is what happens if it does not.
                std::thread::sleep(CHANNEL_END_GRACE);
                leave(&app_fatal);
            });
            Box::new(app)
        }),
    )?;

    match fatal.get() {
        Some(why) => Err(anyhow::anyhow!("{why}")),
        None => Ok(()),
    }
}

/// The eframe side: drain, draw, and write back.
///
/// Visible to the crate rather than to this module, because there is a second
/// thing that opens this window: [`crate::preview`] builds one of these with
/// a sample in its inbox and nobody on the other end of its `out`. It is the
/// same app, drawing the same frames through the same code -- which is the
/// whole of what makes a preview evidence about the real window.
pub(crate) struct PromptApp {
    state: PromptState,
    inbox: Receiver<Incoming>,
    out: Box<dyn Write + Send>,
    /// The Stream output checkbox. A display preference and nothing else.
    stream: bool,
    /// The Close when I decide checkbox, as the reader last left it.
    ///
    /// The *stored* preference rather than the effective answer: it stays as
    /// it was set while a ticked Stream box overrules it for one request, so
    /// unticking Stream brings it back instead of asking for it again.
    /// [`PromptApp::closes_on_decide`] is the only thing that should be asked
    /// what will actually happen.
    close_on_decide: bool,
    /// Where the preference above is remembered between windows.
    ///
    /// Held rather than reached for at the moment of writing, so a test and a
    /// preview can be handed a file that is nowhere. See [`crate::prefs`].
    prefs: PrefsFile,
    /// The Run it in a terminal checkbox.
    ///
    /// Not a display preference: this one decides what runs. It is the
    /// reader's half of a decision the agent also has a half of — see
    /// [`PromptApp::in_a_terminal`], which is the only thing that should be
    /// asked whether this run gets one.
    terminal: bool,
    /// What the user is telling the agent, for every verdict but Approve.
    note: String,
    /// The one thing between a keystroke meant for another window and an
    /// approved command.
    guard: Guard,
    /// Whether the guard was open when this frame's input was judged, so the
    /// drawing half of the frame agrees with the judging half.
    guard_open: bool,
    /// Set when the reader keeps a lingering window, and read by the thread
    /// in [`arm_linger_backstop`]. Shared rather than checked through the
    /// state machine, because the point of that thread is to work when
    /// nothing is running the state machine any more.
    kept: Arc<AtomicBool>,
    /// When something was last put on the clipboard, so the window can say so.
    copied: Option<Instant>,
    fatal: Arc<OnceLock<String>>,
}

impl PromptApp {
    pub(crate) fn new(
        inbox: Receiver<Incoming>,
        out: Box<dyn Write + Send>,
        fatal: Arc<OnceLock<String>>,
        prefs: PrefsFile,
    ) -> PromptApp {
        // The one thing this window starts with that another window decided.
        // Read once, here, and not per frame: a file changing under an open
        // window would move a control somebody is looking at.
        let close_on_decide = prefs.read().close_on_decide;
        PromptApp {
            state: PromptState::new(),
            inbox,
            out,
            // Headless by default: streaming is what the reader opts into
            // when they want to watch, not what they get for asking.
            stream: false,
            close_on_decide,
            prefs,
            // And a terminal is not opened for a command that did not ask
            // for one unless the person reading it decides otherwise.
            terminal: false,
            note: String::new(),
            guard: Guard::new(Instant::now()),
            guard_open: false,
            kept: Arc::new(AtomicBool::new(false)),
            copied: None,
            fatal,
        }
    }

    /// The flag the linger backstop reads, so the thread that arms it can be
    /// started before the window has anything to keep.
    fn kept(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.kept)
    }

    /// What this window currently is.
    ///
    /// For a caller wrapping this app rather than one inside it: a preview
    /// has to know when the window has stopped asking, because a preview is
    /// over the moment it has been decided -- there is nothing behind it to
    /// run what was approved, and a window that sat there saying "running"
    /// would be claiming one.
    pub(crate) fn state(&self) -> &PromptState {
        &self.state
    }

    /// Take in everything that has arrived on the channel.
    ///
    /// The first thing [`eframe::App::logic`] does, and a method as well so
    /// that a caller with no event loop can put a window into the state one
    /// frame would have put it in. The tests that drive this window without
    /// a display want that, and so does the preview's own -- both of which
    /// exist precisely so that the window under test is this one.
    pub(crate) fn take_arrivals(&mut self) {
        drain(&mut self.state, &self.inbox);
    }

    /// Whether the typing guard was open when this frame's input was judged.
    ///
    /// The one thing a screenshot has to wait for that is not layout. Until
    /// the guard opens the verdict buttons are drawn disabled -- see
    /// [`guard`] -- so a picture taken before then is a picture of a window
    /// nobody can answer yet, which is true for 750 ms and misleading for
    /// ever afterwards in a README.
    pub(crate) fn guard_open(&self) -> bool {
        self.guard_open
    }

    /// Whether this run gets a terminal of its own.
    ///
    /// Either half is enough and neither can veto the other, which is the
    /// whole rule: the control **grants** interactivity, it does not withdraw
    /// it. An agent that asked for a terminal knows something about its
    /// command — that it is going to want typing at — and a command that needs
    /// one and is denied it does not fail, it hangs with nowhere to type. So
    /// there is no state of this window in which a request that asked for a
    /// terminal does not get one.
    ///
    /// The other direction is what the control is for. A person reading
    /// `pacman -S foo` can see the confirmation prompt coming when the agent
    /// that wrote the line could not.
    fn in_a_terminal(&self) -> bool {
        self.terminal || self.state.shown().is_some_and(|shown| shown.interactive())
    }

    /// The approval this window would send, however it was asked for.
    ///
    /// One function rather than one expression per button, because there are
    /// two ways to approve — the button and the chord — and an approval that
    /// carried the terminal from one of them and not the other would be a
    /// window whose keyboard and mouse ran different commands.
    fn approval(&self) -> Verdict {
        Verdict::Approve {
            stream: self.stream,
            terminal: self.in_a_terminal(),
            closing: self.closes_on_decide(),
            note: self.note.clone(),
        }
    }

    /// Whether this window goes as soon as the verdict has been sent.
    ///
    /// The reader's standing preference, minus the one thing that overrules
    /// it. Streaming and closing are a contradiction — the live view exists to
    /// be watched, and a window that has gone shows nothing — and the tick
    /// made in front of *this* command wins over the one made some other day.
    /// See [`CLOSE_WATCHING`], which is the window saying so out loud.
    ///
    /// A terminal run is not the same case and is deliberately not excluded.
    /// The terminal is a window of its own that the reader is about to be
    /// sitting in front of, so hatch's window standing behind it shows them
    /// nothing they are not already looking at — and this box is at its most
    /// useful there. `stream` is already false whenever there is a terminal,
    /// so a terminal run reads as true here without having to say so twice.
    fn closes_on_decide(&self) -> bool {
        self.close_on_decide && !self.stream
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

/// End the process now, saying why if there is a why.
///
/// Every backstop below ends here, so an exit forced by a thread reports what
/// an exit through the event loop would have reported.
fn leave(fatal: &OnceLock<String>) -> ! {
    match fatal.get() {
        Some(why) => {
            eprintln!("hatch prompt: {why}");
            std::process::exit(1);
        }
        None => std::process::exit(0),
    }
}

/// Leave in `EXIT_BACKSTOP`, whatever the event loop is doing by then.
fn arm_exit_backstop(fatal: Arc<OnceLock<String>>) {
    std::thread::spawn(move || {
        std::thread::sleep(EXIT_BACKSTOP);
        leave(&fatal);
    });
}

/// Leave when the linger has run out, unless the reader kept the window.
///
/// Armed by the reading thread, on the outcome frame, and that is the point of
/// it: until now every window had a daemon holding a deadline over it, and a
/// lingering one does not. A deadline the event loop arms is no deadline at
/// all against a loop that has stopped running, so this one is armed by the
/// thread that took the frame off the pipe and enforced by a thread of its
/// own. Both ends of it are outside the loop.
///
/// It is armed for a window that will not linger too, which costs nothing: one
/// closes in milliseconds and the daemon kills it in half a second, so a
/// deadline twelve seconds out is only ever reached by a window that is
/// already broken.
///
/// `kept` is the reader's answer, and it is read once, at the end: pressing
/// the button is what turns this from a deadline into nothing.
fn arm_linger_backstop(kept: Arc<AtomicBool>, fatal: Arc<OnceLock<String>>) {
    std::thread::spawn(move || {
        std::thread::sleep(LINGER + LINGER_BACKSTOP);
        if kept.load(Ordering::SeqCst) {
            return;
        }
        leave(&fatal);
    });
}

impl eframe::App for PromptApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.take_arrivals();
        // Before anything is drawn, and before any widget sees the frame.
        // Whatever the guard did not hand back is gone from this frame.
        let now = Instant::now();
        for action in intercept(&mut self.guard, ctx, now) {
            self.act(action);
        }
        self.guard_open = self.guard.is_open(now);
        // The linger's own clock. What enforces it when this loop is not the
        // thing running is `arm_linger_backstop`, armed by the reader thread.
        self.state.tick(now);
        // The desktop's own close: the title bar, the compositor, a session
        // ending. A detached window has no daemon left to kill it, so this is
        // the path that has to end the process rather than only hide it.
        if ctx.input(|i| i.viewport().close_requested()) {
            self.state.dismiss();
        }
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
        // Before anything is laid out, because the panels below take their
        // frames from this `Ui`'s style. What the window is doing is the
        // first thing about it a reader takes in, and for a long time three
        // different things looked like one.
        theme::wear(ui, mood(self.state.phase()));
        // Taken before the panels divide it up, because that is what it is:
        // the whole window, which is what the root edge is painted around.
        let window = ui.max_rect();
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
            if self.state.is_viewer() {
                // The question has been answered and the command has run, so
                // the two panes arguing about what the command says are of no
                // further use. What is worth the window now is what it
                // printed.
                self.viewer(ui, &title);
                return;
            }
            // There is always one once a request has arrived: a payload that
            // could not be rebuilt closed the window instead of becoming one.
            let aside = self.state.shown().and_then(panes::RunContext::of);
            panes::draw_headline(ui, &title, &reason, aside.as_ref());
            ui.separator();
            if let Some(shown) = self.state.shown() {
                panes::draw_payload(ui, shown);
            }
        });

        // Last, so it is over the panels rather than under them, and outside
        // the `if` above so that it reaches the finished window too: a root
        // command that has already run is still the thing that ran as root.
        // It is painted, not laid out, so it takes nothing from the panes.
        if self.state.runs_as_root() {
            theme::mark_root(ui, window);
        }
    }

    /// What a finished streamed run shows: its command, named once, and all
    /// of the output it produced.
    ///
    /// The command is the one-line display form and not the two panes: those
    /// exist so a reader can tell what they are approving apart from what it
    /// looks like, and nothing is being approved any more. It is here at all
    /// because output with nothing naming it is output the reader has to
    /// remember the provenance of.
    fn viewer(&self, ui: &mut egui::Ui, title: &str) {
        // The headline and its corner are gone with the question they
        // belonged to, so this row is the only place left that can say what
        // just ran, and what just ran was root. Wrapped rather than
        // horizontal: the mark leads the title, and a title long enough to
        // need a second line still gets one.
        ui.horizontal_wrapped(|ui| {
            if self.state.runs_as_root() {
                panes::draw_root_mark(ui);
            }
            ui.label(egui::RichText::new(title).strong());
        });
        if let Some(Shown::Command { raw, .. }) = self.state.shown() {
            ui.label(
                egui::RichText::new(protocol::display_line(raw)).monospace().small().weak(),
            );
        }
        if self.state.output_dropped() {
            ui.label(
                egui::RichText::new(
                    "Earlier output was dropped: this window keeps the last megabyte.",
                )
                .strong()
                .color(ui.visuals().warn_fg_color),
            );
        }
        ui.separator();
        let text = self.state.output_text();
        if text.is_empty() {
            ui.label(egui::RichText::new("It printed nothing.").weak());
            return;
        }
        egui::ScrollArea::vertical()
            .id_salt("hatch-viewer-output")
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                // Already decoded by the daemon; drawn, never decoded again.
                // See `crate::protocol`.
                ui.add(egui::Label::new(egui::RichText::new(text).monospace()));
            });
    }

    /// Carry out one decision the guard made.
    ///
    /// A decision, not a suggestion: it is applied where it is received. The
    /// state machine is what makes a doubled one harmless — it answers only
    /// while the window awaits a verdict, and it leaves that phase on the way
    /// out.
    pub(crate) fn act(&mut self, action: Action) {
        // A window that is only showing a result has nothing to decide, so the
        // two keys the guard owns mean the only things left: Escape puts the
        // window away, and Enter means nothing at all. Neither reaches
        // `decide`, which is a second lock on the same door rather than the
        // first — `decide` answers in `AwaitingVerdict` alone.
        if self.state.is_viewer() {
            if action == Action::Deny {
                self.state.dismiss();
            }
            return;
        }
        let verdict = match action {
            // The note goes with an approval as it goes with a denial: the
            // field says "Note to the agent", and which button was pressed
            // afterwards does not change who the words were for.
            Action::Approve => self.approval(),
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
        match self.state.phase() {
            Phase::AwaitingVerdict => {
                self.status_row(ui);
                self.verdict_area(ui, guard_open);
            }
            Phase::Running => {
                self.status_row(ui);
                self.running_row(ui);
            }
            // No approval clock here: it measured the time somebody had to
            // decide, that time was used, and a second countdown beside the
            // one that matters now is two numbers the reader has to tell
            // apart.
            Phase::Lingering | Phase::Detached => self.viewer_row(ui),
            Phase::WaitingForRequest | Phase::Closed => self.status_row(ui),
        }
        ui.add_space(4.0);
    }

    /// What a finished window offers: how it ended, how long it is staying,
    /// and the actions that decide nothing.
    ///
    /// Nothing in this row can produce a verdict, and that is not a matter of
    /// which buttons are drawn: the request is over, the daemon has let go of
    /// this process, and [`PromptState::decide`] answers only in
    /// [`Phase::AwaitingVerdict`], which no phase returns to.
    fn viewer_row(&mut self, ui: &mut egui::Ui) {
        let closing = self.state.linger_seconds_remaining(Instant::now());
        let (weak, warn, bad) = {
            let visuals = ui.visuals();
            (visuals.weak_text_color(), visuals.warn_fg_color, visuals.error_fg_color)
        };
        let body = egui::TextStyle::Body.resolve(ui.style()).size;

        ui.vertical_centered(|ui| {
            if let Some(outcome) = self.state.outcome() {
                let (text, clean) = panes::outcome_text(outcome);
                let colour = if clean { weak } else { bad };
                ui.label(egui::RichText::new(text).color(colour).strong());
            }
            match closing {
                // Colour *and* size, never colour alone, for the reason the
                // approval countdown gives: this number is the reader's last
                // chance to keep what is on the screen.
                Some(left) => ui.label(
                    egui::RichText::new(panes::closing_text(left))
                        .color(warn)
                        .strong()
                        .size(body * IMMINENT_SCALE),
                ),
                None => ui.label(
                    egui::RichText::new("Kept. This window is yours to close.").small().color(weak),
                ),
            };
        });

        ui.add_space(6.0);
        let width = cluster_width(ui);
        let (mut keep, mut close) = (false, false);
        let (mut copy_output, mut copy_command) = (false, false);
        let has_command = matches!(self.state.shown(), Some(Shown::Command { .. }));
        ui.vertical_centered(|ui| {
            centred_row(ui, width, |ui| {
                if closing.is_some() {
                    keep = unfocusable(
                        ui,
                        egui::Button::new(strong("Keep this window"))
                            .min_size(primary_button(ui)),
                    )
                    .clicked();
                    // The same gap the verdict buttons keep, for a weaker
                    // reason: nothing here is dangerous, but a pointer on its
                    // way to Keep must not find Close under it.
                    ui.add_space(PRIMARY_GAP);
                }
                close = unfocusable(ui, egui::Button::new("Close")).clicked();
            });
            ui.add_space(4.0);
            centred_row(ui, width, |ui| {
                copy_output = secondary(ui, "Copy output").clicked();
                if has_command {
                    copy_command = secondary(ui, "Copy command").clicked();
                }
                if self.copied.is_some_and(|at| at.elapsed() < COPY_NOTICE) {
                    ui.label(egui::RichText::new("copied").small().color(weak));
                }
            });
        });

        if keep && self.state.keep() {
            // Read by the backstop thread, which is the one thing still
            // holding a deadline over this window. Set before anything else
            // so a stall between here and the next frame cannot lose it.
            self.kept.store(true, Ordering::SeqCst);
        }
        if close {
            self.state.dismiss();
        }
        // The output as it is on screen, and the command as it really is: the
        // one-line form above is drawn with chip glyphs standing in for tabs
        // and newlines, and pasting those into a shell would be pasting a
        // different command from the one that ran.
        if copy_output {
            ui.ctx().copy_text(self.state.output_text());
            self.copied = Some(Instant::now());
        }
        if copy_command && let Some(Shown::Command { raw, .. }) = self.state.shown() {
            ui.ctx().copy_text(raw.source().to_string());
            self.copied = Some(Instant::now());
        }
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
        // One row, drawn twice over: the clock belongs to the question and is
        // centred with it, and the badge is an aside about *other* windows
        // and stays out at the edge. Two children over one rect rather than
        // one flow, so that a badge appearing cannot shove the clock sideways
        // -- a countdown that moves when something unrelated arrives is a
        // countdown the eye has to find again.
        let body = egui::TextStyle::Body.resolve(ui.style()).size;
        let (rect, _) = ui.allocate_exact_size(
            egui::vec2(ui.available_width(), body * IMMINENT_SCALE * 1.4),
            egui::Sense::hover(),
        );
        let child = |ui: &mut egui::Ui, align| {
            ui.new_child(egui::UiBuilder::new().max_rect(rect).layout(align))
        };

        // Only while there is something to decide. The number measures the
        // time somebody has to answer *this question*, so it stops meaning
        // anything the moment they answer: an approved command ran on its own
        // clock, `exec_timeout_secs`, which this deadline knows nothing about
        // and is not counting down to. Gating on the outcome instead was not
        // enough, because an outcome arrives when the command *ends* — so an
        // approved command spent its whole run under a countdown that had
        // already been beaten, ticking towards a moment at which nothing
        // would now happen.
        //
        // `Lingering` and `Detached` say the same thing in `panel`, where the
        // approval clock is left out for the reason this condition encodes.
        if self.state.phase() == Phase::AwaitingVerdict
            && let Some(left) = self.state.seconds_remaining(Utc::now())
        {
            let text = egui::RichText::new(countdown_text(left));
            child(ui, egui::Layout::top_down(egui::Align::Center)).label(match urgency(left) {
                Urgency::Calm => text.color(calm),
                Urgency::Soon => text.color(soon).strong(),
                Urgency::Imminent => text.color(imminent).strong().size(body * IMMINENT_SCALE),
            });
        }
        if let Some(waiting) = self.state.queue_badge() {
            child(ui, egui::Layout::right_to_left(egui::Align::Center)).label(
                egui::RichText::new(format!("{waiting} more waiting")).small().color(calm),
            );
        }
    }

    /// What an approved command's window offers while it runs.
    ///
    /// The output is here, in the same panel as Kill, and capped: the reason
    /// to watch it is to decide whether to press that button, and a decision
    /// is made from the last screenful.
    fn running_row(&mut self, ui: &mut egui::Ui) {
        // Two different sentences and not one with a suffix, because they say
        // opposite things about the only question the reader has: whether the
        // thing they approved has happened. A password dialog from another
        // process is about to cover this window, and a reader who has just
        // been told "it is running" would have no reason to link the two.
        //
        // Neither sentence asserts that a dialog is on screen, and neither
        // says nothing has run — because this window cannot see either. It is
        // told that elevation was spawned, and `elevating` stays true until
        // the first byte of output or the outcome; a command that is silent
        // for its first few seconds is indistinguishable here from a dialog
        // nobody has answered. These two therefore have to read as true from
        // the spawn until the first evidence, which is the span they are
        // shown over. An earlier pair claimed the dialog was being waited on
        // and that nothing had run, and went on saying both after the
        // password had been typed.
        if self.state.elevating() {
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("Approved. Waiting for the system to authorise this.")
                        .strong(),
                );
                ui.label(
                    egui::RichText::new(
                        "If a password dialog is up, dismissing it cancels this.",
                    )
                    .small(),
                );
            });
        } else {
            ui.vertical_centered(|ui| ui.label("Approved. It is running now."));
        }
        if self.stream {
            let text = self.state.output_text();
            egui::ScrollArea::vertical()
                .id_salt("hatch-output")
                .max_height(ui.text_style_height(&egui::TextStyle::Monospace) * RUNNING_OUTPUT_ROWS)
                .auto_shrink([false, true])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    // Already decoded by the daemon; drawn, never decoded
                    // again. See `crate::protocol`.
                    ui.add(egui::Label::new(egui::RichText::new(text).monospace()));
                });
        } else if self.in_a_terminal() {
            ui.label(egui::RichText::new("It is running in a terminal of its own.").small());
        } else {
            ui.label(
                egui::RichText::new("Its output is not being streamed to this window.").small(),
            );
        }
        // Centred with the verdict buttons it replaces. The output above it
        // is not: it is monospace text being read, and a column of it down
        // the middle of a 1280-point window is harder to follow than one that
        // starts where every other line of text in this window starts.
        let killed = ui
            .vertical_centered(|ui| unfocusable(ui, egui::Button::new("Kill")).clicked())
            .inner;
        if killed {
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
    /// decide do not look like the four that ask.
    ///
    /// Six buttons stacked in one column at one size is the layout that
    /// produces a misclick, and a misclick here is an approval. So Approve
    /// and Deny are one row of large buttons with a real gap between them —
    /// the gap is not decoration, it is the distance a slipped pointer has to
    /// cross to turn a refusal into a root command — and the four [`Hatch`]
    /// buttons are small, out at the right-hand edge of the same row. They
    /// are escape hatches: they send the agent away with something to do and
    /// nothing runs, which is the same class of outcome as Deny and does not
    /// deserve the same size as it.
    ///
    /// # Why they share a row
    ///
    /// A row of this panel is a row the command above it does not get, and
    /// this window is read at 700 points high. The escape hatches had a row
    /// of their own and a 1280-point window has half of that row empty either
    /// side of the two buttons that matter, so they moved into the empty
    /// half. Nothing about the weighting moved with them: they are still
    /// small, still secondary, and they are now *further* from Approve than
    /// they were, because they sit past Deny with a full [`PRIMARY_GAP`]
    /// between. Approve and Deny do not move at all — they stay centred in
    /// the panel, in the same place, at the same size, whether or not the
    /// hatches fit beside them.
    ///
    /// When they do not fit — a narrow window, a large font — they take a row
    /// of their own again rather than overlapping Deny. That is measured, not
    /// hoped: see [`row_width`].
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
        // Read before the fields below are borrowed to draw. `streamable` is
        // "this is a command", asked from the streaming side: a file swap
        // writes bytes and says nothing, so it has neither output to watch
        // nor anything a terminal could run.
        let (streamable, asked_for) = match self.state.shown() {
            Some(shown) => (shown.streamable(), shown.interactive()),
            None => (false, false),
        };

        // Streaming and a terminal are exclusive, and it is not a rule this
        // window enforces so much as a fact it reports: the terminal *is* the
        // stream. Cleared rather than merely disabled, because a ticked box
        // that has been greyed out reads as a promise to stream, and nothing
        // is going to.
        if self.in_a_terminal() {
            self.stream = false;
        }
        // One name for it, used by the checkbox and by the line that says why
        // it is dead: a control that cannot be ticked and does not say why is
        // a window asking the reader to guess.
        let can_stream = !self.in_a_terminal();
        let note = self.note.clone();
        let mut decided = None;
        let width = cluster_width(ui);

        if streamable {
            self.terminal_row(ui, asked_for);
            ui.add_space(2.0);
        }
        self.note_row(ui, width, streamable, can_stream);
        ui.add_space(6.0);
        let approve = self.decision_row(ui, width, &note, &mut decided);

        if approve.clicked() {
            decided = Some(self.approval());
        }

        if let Some(verdict) = decided {
            let frame = self.state.decide(verdict);
            answer(&mut self.out, &mut self.state, frame);
        }
        approve
    }

    /// One row: what to tell the agent, and whether to watch the output.
    ///
    /// Three rows before — a label, a field, a checkbox — and the label was
    /// above the field rather than beside it only so that the field stayed
    /// centred on the buttons below. That is still true and is still the
    /// constraint: the field is centred at exactly `width`, and the label and
    /// the checkbox are hung off its two ends. So the cluster still lines up
    /// as one thing, and it costs one row instead of three.
    fn note_row(&mut self, ui: &mut egui::Ui, width: f32, streamable: bool, can_stream: bool) {
        let quiet = ui.visuals().weak_text_color();
        let label = "Note to the agent";
        let height = ui.spacing().interact_size.y.max(ui.text_style_height(&egui::TextStyle::Body));
        let flanks = [
            // Small, because that is what it is drawn at: a row measured in
            // one style and drawn in another is a row that reserves the wrong
            // amount of it.
            text_width(ui, label, egui::TextStyle::Small),
            match streamable {
                true => self.stream_width(ui),
                false => 0.0,
            },
        ];
        let places = flanked_row(ui, height, width, flanks);
        // All of it or none of it, unlike the decision row below: what hangs
        // off this field is a label naming it and a box about the command in
        // it, and one of the two moving to a row of its own while the other
        // stayed would be two rows saying one thing.
        let [Some(left), Some(right)] = places.flanks else {
            // Too narrow to hang anything off the field. Back to the stack,
            // which is a taller row and a correct one.
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new(label).small().color(quiet));
                ui.add_sized(egui::vec2(width, height), egui::TextEdit::singleline(&mut self.note));
                if streamable {
                    self.stream_box(ui, can_stream);
                }
            });
            return;
        };
        ui.advance_cursor_after_rect(places.row);

        ui.scope_builder(
            egui::UiBuilder::new()
                .max_rect(left)
                .layout(egui::Layout::right_to_left(egui::Align::Center)),
            |ui| ui.label(egui::RichText::new(label).small().color(quiet)),
        );
        ui.scope_builder(
            egui::UiBuilder::new()
                .max_rect(places.centre)
                .layout(egui::Layout::top_down_justified(egui::Align::Center)),
            |ui| ui.add(egui::TextEdit::singleline(&mut self.note)),
        );
        if streamable {
            ui.scope_builder(
                egui::UiBuilder::new()
                    .max_rect(right)
                    .layout(egui::Layout::left_to_right(egui::Align::Center)),
                |ui| self.stream_box(ui, can_stream),
            );
        }
    }

    /// One row: whether to give the command a terminal, and what that costs.
    ///
    /// # Why the warning is here and not in a tooltip
    ///
    /// The transcript of that terminal goes back to the agent, and a terminal
    /// records *everything in it* — including what the person types, because
    /// the terminal echoes it. Somebody who answers a prompt inside that
    /// window with a password has put the password in the agent's context, and
    /// they will have done it while believing they were typing into their own
    /// terminal, which in every other respect they are.
    ///
    /// That is a cost, and a cost belongs next to the control that incurs it,
    /// before it is incurred. A tooltip is read by people who already suspect
    /// there is something to read; this sentence has to reach the person who
    /// does not. So it is drawn beside the box, at every width — when the row
    /// is too narrow for it to sit alongside, it goes under the box rather
    /// than away.
    ///
    /// # Why the box is dead when the agent asked
    ///
    /// See [`PromptApp::in_a_terminal`]. The control grants and never
    /// withdraws, so for a request that already asked for a terminal there is
    /// nothing for it to decide — and the row still says what the terminal
    /// costs, because that is exactly the case where nobody chose it.
    fn terminal_row(&mut self, ui: &mut egui::Ui, asked_for: bool) {
        let quiet = ui.visuals().weak_text_color();
        let warn = ui.visuals().warn_fg_color;
        let mut ticked = self.in_a_terminal();
        let width = text_width(ui, TERMINAL_LABEL, egui::TextStyle::Button)
            + ui.spacing().icon_width
            + ui.spacing().icon_spacing
            + text_width(ui, TERMINAL_CAPTURE, egui::TextStyle::Small)
            + match asked_for {
                true => text_width(ui, TERMINAL_ASKED, egui::TextStyle::Small),
                false => 0.0,
            }
            + 3.0 * ui.spacing().item_spacing.x;

        let mut controls = |ui: &mut egui::Ui| {
            ui.add_enabled(!asked_for, egui::Checkbox::new(&mut ticked, TERMINAL_LABEL));
            if asked_for {
                ui.label(egui::RichText::new(TERMINAL_ASKED).small().color(quiet));
            }
            ui.label(egui::RichText::new(TERMINAL_CAPTURE).small().color(warn));
        };
        if width <= ui.available_width() {
            centred_row(ui, width, &mut controls);
        } else {
            // Under the box rather than beside it. The sentence is the part
            // that must not be dropped, so the row that cannot hold it gets
            // taller instead of shorter.
            ui.vertical_centered(|ui| {
                ui.add_enabled(!asked_for, egui::Checkbox::new(&mut ticked, TERMINAL_LABEL));
                if asked_for {
                    ui.label(egui::RichText::new(TERMINAL_ASKED).small().color(quiet));
                }
                ui.label(egui::RichText::new(TERMINAL_CAPTURE).small().color(warn));
            });
        }
        // Only the reader's half is stored. `ticked` is the *effective*
        // answer, which is already true for a request the agent asked for, and
        // writing that back would turn the agent's ask into the reader's
        // choice — indistinguishable afterwards, and the wrong thing to show
        // if the payload ever changed under this window.
        if !asked_for {
            self.terminal = ticked;
        }
    }

    /// The stream checkbox, and the reason it is dead when it is.
    fn stream_box(&mut self, ui: &mut egui::Ui, can_stream: bool) {
        ui.add_enabled(
            can_stream,
            egui::Checkbox::new(&mut self.stream, "Stream output to this window"),
        );
        if !can_stream {
            ui.label(
                egui::RichText::new("It runs in a terminal of its own.")
                    .small()
                    .color(ui.visuals().weak_text_color()),
            );
        }
    }

    /// How much room the checkbox and its note need beside the field.
    ///
    /// Deliberately generous. This is the flank that is drawn *rightwards*
    /// from the field, so it is the one an under-measurement pushes off the
    /// side of the window — and egui's own checkbox carries gaps between its
    /// box and its text that are not worth reproducing here exactly. A slack
    /// of two ordinary gaps costs a fallback that fires a little early and
    /// buys a control that is never half off the screen; the claim that it is
    /// enough is
    /// `the_stream_box_sits_beside_the_field_and_stays_inside_the_window`.
    fn stream_width(&self, ui: &egui::Ui) -> f32 {
        let box_ = ui.spacing().icon_width + ui.spacing().icon_spacing;
        // `Button` and not `Body`: that is the style a checkbox draws its own
        // label in.
        let label = text_width(ui, "Stream output to this window", egui::TextStyle::Button);
        let dead = match self.in_a_terminal() {
            true => {
                ui.spacing().item_spacing.x
                    + text_width(ui, "It runs in a terminal of its own.", egui::TextStyle::Small)
            }
            false => 0.0,
        };
        box_ + label + dead + 2.0 * ui.spacing().item_spacing.x
    }

    /// The Close when I decide checkbox, and what it costs or why it is dead.
    ///
    /// Two lines, stacked. The row it belongs to is a primary button tall and
    /// half of it was empty, so the sentence under the box gets a line of its
    /// own for nothing — where beside the box it would have been the first
    /// thing to run out of room, and [`CLOSE_COST`] is not a sentence this
    /// window may drop for want of width.
    fn close_box(&mut self, ui: &mut egui::Ui) {
        // Drawn as the effective answer and stored only when the reader is the
        // one who settled it, exactly as the terminal box is: the box says
        // what this window will do, and the field remembers what its reader
        // asked for. Writing the effective answer back would turn a ticked
        // Stream box into the reader having unticked this one, and it would
        // stay unticked after Stream was cleared again.
        let live = !self.stream;
        let mut ticked = self.closes_on_decide();
        if ui.add_enabled(live, egui::Checkbox::new(&mut ticked, CLOSE_LABEL)).changed() {
            self.close_on_decide = ticked;
            // On the click, and not on the way out, because there may be no
            // way out to write it on: this window's ordinary ending is the
            // daemon killing the process once the operation is over.
            self.prefs.write(&Prefs { close_on_decide: ticked });
        }
        ui.label(
            egui::RichText::new(match live {
                true => CLOSE_COST,
                false => CLOSE_WATCHING,
            })
            .small()
            .color(ui.visuals().weak_text_color()),
        );
    }

    /// How much room the close control needs: the wider of its two lines.
    ///
    /// The sentence is measured as **whichever of the two is longer** rather
    /// than as the one about to be drawn. A flank that narrowed when Stream
    /// was ticked could hand the row back to the fallback under a pointer
    /// already on its way to Approve, and nothing beside the two buttons that
    /// decide is allowed to move them.
    fn close_width(&self, ui: &egui::Ui) -> f32 {
        let box_ = ui.spacing().icon_width + ui.spacing().icon_spacing;
        // `Button` and not `Body`: that is the style a checkbox draws its own
        // label in.
        let label = box_ + text_width(ui, CLOSE_LABEL, egui::TextStyle::Button);
        let said = text_width(ui, CLOSE_COST, egui::TextStyle::Small)
            .max(text_width(ui, CLOSE_WATCHING, egui::TextStyle::Small));
        label.max(said) + 2.0 * ui.spacing().item_spacing.x
    }

    /// How tall the close control is: its box, and the sentence under it.
    fn close_height(&self, ui: &egui::Ui) -> f32 {
        let box_ = ui
            .spacing()
            .interact_size
            .y
            .max(ui.text_style_height(&egui::TextStyle::Button));
        box_ + ui.spacing().item_spacing.y + ui.text_style_height(&egui::TextStyle::Small)
    }

    /// One row: the two buttons that decide, the four that do not, and the one
    /// that says what deciding is going to do to this window.
    fn decision_row(
        &mut self,
        ui: &mut egui::Ui,
        width: f32,
        note: &str,
        decided: &mut Option<Verdict>,
    ) -> egui::Response {
        let height = primary_button(ui).y;
        // `Hatch::ALL`, measured and then drawn: one list, in one order or
        // the other. Two lists is how a button ends up in one arrangement and
        // not the other.
        let needed =
            row_width(ui, Hatch::ALL.iter().map(|hatch| hatch.label()), egui::TextStyle::Small);
        // Past Deny on one side and short of Approve on the other, each with
        // the same gap the two of them keep between themselves: a pointer
        // sliding off either lands on the panel, never on a button and never
        // on a checkbox. The left flank was empty until the close control
        // moved into it, and that is why that control costs no row — this
        // panel is 1280 points wide and the two buttons that matter are 400 of
        // them in the middle of it.
        let flanks = [self.close_width(ui) + PRIMARY_GAP, needed + PRIMARY_GAP];
        // Asked before anything is drawn and then asked again, because a close
        // control with nowhere to sit beside Approve goes *above* the row —
        // which moves the row. Both calls only measure; see [`Places`].
        if flanked_row(ui, height, width, flanks).flanks[0].is_none() {
            // First, because it says what pressing one of the buttons under it
            // is going to do to this window.
            ui.vertical_centered(|ui| self.close_box(ui));
            ui.add_space(4.0);
        }
        let places = flanked_row(ui, height, width, flanks);
        ui.advance_cursor_after_rect(places.row);

        if let Some(left) = places.flanks[0] {
            // Centred against the buttons rather than hung from the top of the
            // row: two lines of text level with one tall button, which is what
            // the eye reads as one row.
            let place = egui::Rect::from_center_size(
                left.center(),
                egui::vec2(left.width(), self.close_height(ui)),
            );
            ui.scope_builder(
                egui::UiBuilder::new()
                    .max_rect(place)
                    .layout(egui::Layout::top_down(egui::Align::Min)),
                |ui| self.close_box(ui),
            );
        }

        let mut verdicts = |ui: &mut egui::Ui| {
            let approve = unfocusable(ui, primary(ui, "Approve", guard::APPROVE_CHORD));
            // A pointer that slips off Deny must land on nothing.
            ui.add_space(PRIMARY_GAP);
            if unfocusable(ui, primary(ui, "Deny", guard::DENY_CHORD)).clicked() {
                *decided = Some(Verdict::Deny { note: note.to_string() });
            }
            approve
        };
        let approve = ui
            .scope_builder(
                egui::UiBuilder::new().max_rect(places.centre).layout(
                    egui::Layout::left_to_right(egui::Align::Center)
                        .with_main_align(egui::Align::Center),
                ),
                &mut verdicts,
            )
            .inner;

        let mut hatch_row = |ui: &mut egui::Ui, reversed: bool| {
            let mut order = Hatch::ALL;
            if reversed {
                order.reverse();
            }
            for hatch in order {
                if secondary(ui, hatch.label()).clicked() {
                    *decided = Some(hatch.verdict(note));
                }
            }
        };
        match places.flanks[1] {
            // Right to left, so the row is built from the window's edge
            // inwards and they end where they started however wide the
            // labels turn out to be. Reversed, so that reading order is the
            // same as it is in the fallback below.
            Some(right) => {
                ui.scope_builder(
                    egui::UiBuilder::new()
                        .max_rect(right)
                        .layout(egui::Layout::right_to_left(egui::Align::Center)),
                    |ui| hatch_row(ui, true),
                );
            }
            // A row of their own, centred under the two that decide, when
            // there is no room beside them.
            None => {
                ui.add_space(4.0);
                ui.vertical_centered(|ui| centred_row(ui, width, |ui| hatch_row(ui, false)));
            }
        }
        approve
    }
}

/// Where a `width`-wide centre and a flank on each side of it would go, in the
/// row that starts at the cursor.
///
/// Returned by [`flanked_row`], which measures and does not take: a caller
/// that uses the row takes it with [`egui::Ui::advance_cursor_after_rect`],
/// and one that cannot starts its own layout where this row would have been,
/// so a refusal still costs no space.
///
/// Measuring and taking used to be the same call, which was right while a row
/// had one flank that could fail: the answer was "all three places, or none".
/// The decision row has two, and they are separate questions — the escape
/// hatches not fitting beside Deny is no reason for the close control on the
/// other side of the same row to lose its place — so the answer is now one per
/// flank and the taking is the caller's.
struct Places {
    /// The whole row, for the caller that takes it.
    row: egui::Rect,
    /// Where the `width`-wide centre goes.
    ///
    /// Placed from the row's own width rather than from what the flanks turned
    /// out to need, so the two verdict buttons sit in exactly the same place
    /// whether or not anything is beside them.
    centre: egui::Rect,
    /// Each flank, or `None` where it would reach into the centre.
    ///
    /// That refusal is the whole point: the centre of this panel is where
    /// Approve and Deny are, and a control allowed to overlap them is a
    /// control that can be pressed instead of them. A caller holding a `None`
    /// puts that flank somewhere else; nothing is ever moved or shrunk to make
    /// room.
    flanks: [Option<egui::Rect>; 2],
}

/// Measure a row with something `width` wide centred in it and a flank on each
/// side. See [`Places`]; nothing is drawn or allocated here.
fn flanked_row(ui: &egui::Ui, height: f32, width: f32, flanks: [f32; 2]) -> Places {
    let gap = ui.spacing().item_spacing.x;
    let row = egui::Rect::from_min_size(
        ui.available_rect_before_wrap().min,
        egui::vec2(ui.available_width(), height),
    );
    let centre = egui::Rect::from_center_size(row.center(), egui::vec2(width, height));
    // A flank stops a gap short of the centre. Without it a label reads as
    // part of the field it is naming and a checkbox reads as a button on the
    // end of it.
    let left = egui::Rect::from_min_max(row.min, egui::pos2(centre.left() - gap, row.bottom()));
    let right =
        egui::Rect::from_min_max(egui::pos2(centre.right() + gap, row.top()), row.max);
    Places {
        row,
        centre,
        flanks: [
            (flanks[0] <= left.width()).then_some(left),
            (flanks[1] <= right.width()).then_some(right),
        ],
    }
}

/// How wide one string is in the style it will be drawn in.
fn text_width(ui: &egui::Ui, text: &str, style: egui::TextStyle) -> f32 {
    let font = style.resolve(ui.style());
    ui.ctx().fonts_mut(|fonts| {
        fonts.layout_no_wrap(text.to_string(), font, egui::Color32::WHITE).size().x
    })
}

/// How wide a row of buttons carrying `labels` is, furniture included.
///
/// Measured rather than guessed, because what it decides is whether those
/// buttons may sit beside the two that settle the request — and a guess that
/// came out short would put one of them under a pointer aimed at Deny.
fn row_width<'a>(
    ui: &egui::Ui,
    labels: impl IntoIterator<Item = &'a str>,
    style: egui::TextStyle,
) -> f32 {
    let padding = 2.0 * ui.spacing().button_padding.x;
    let mut total = 0.0;
    let mut count: f32 = 0.0;
    for label in labels {
        total += text_width(ui, label, style.clone()) + padding;
        count += 1.0;
    }
    total + (count - 1.0).max(0.0) * ui.spacing().item_spacing.x
}

/// A button a mouse can press and a keyboard cannot reach.
///
/// The single place [`egui::Sense::CLICK`] is applied, so a new button cannot
/// be added with the focusable sense by forgetting rather than by deciding.
/// See [`PromptApp::verdict_buttons`] for why that matters.
fn unfocusable(ui: &mut egui::Ui, button: egui::Button<'_>) -> egui::Response {
    ui.add(button.sense(egui::Sense::CLICK))
}

/// One of the four ways to send the agent away without running anything.
///
/// The outcomes themselves, named. They used to be an `Option<ReviseKind>`,
/// which worked only while "not a revision" could mean exactly one other
/// thing; a fourth outcome makes that encoding a lie, and a list whose
/// entries cannot say what they are is a list a button quietly falls out of.
/// Both of the two things a hatch needs — its label and its verdict — hang
/// off this one enum, so neither can be added for three of them and forgotten
/// for the fourth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hatch {
    /// Explain what this does before I decide.
    Explain,
    /// Send me a more legible form of this.
    Simplify,
    /// I will run it myself.
    SelfRun,
    /// Stop, and wait for me.
    StopAndSync,
}

impl Hatch {
    /// Every hatch, in the order the row reads left to right.
    ///
    /// The one list. The row is measured from it and drawn from it, so a
    /// button cannot be wide enough to be counted and absent from the
    /// drawing, or drawn in one arrangement and not the other.
    const ALL: [Hatch; 4] = [Hatch::Explain, Hatch::Simplify, Hatch::SelfRun, Hatch::StopAndSync];

    /// What the button says.
    ///
    /// Short on purpose: all four measure against the room left beside
    /// Approve and Deny, and a label that outgrows it costs every one of them
    /// their place on that row. See [`PromptApp::verdict_buttons`].
    fn label(self) -> &'static str {
        match self {
            Hatch::Explain => "Explain first",
            Hatch::Simplify => "Ask for something simpler",
            Hatch::SelfRun => "I'll run it myself",
            Hatch::StopAndSync => "Stop, let's sync",
        }
    }

    /// The verdict it sends, carrying whatever the note field holds.
    fn verdict(self, note: &str) -> Verdict {
        let note = note.to_string();
        match self {
            Hatch::Explain => Verdict::Revise { kind: ReviseKind::Explain, note },
            Hatch::Simplify => Verdict::Revise { kind: ReviseKind::Simplify, note },
            Hatch::SelfRun => Verdict::SelfRun { note },
            Hatch::StopAndSync => Verdict::StopAndSync { note },
        }
    }
}

/// One of the four ways to send the agent away without running anything, as a
/// button.
fn secondary(ui: &mut egui::Ui, label: &str) -> egui::Response {
    unfocusable(ui, egui::Button::new(egui::RichText::new(label).small()))
}

/// Which ground a phase is drawn on.
///
/// The mapping and not the colours: [`theme::Mood`] is about what a window is
/// doing, and this is the one place that says which of this machine's phases
/// is which of those. `Closed` is a phase the window leaves on, and a window
/// that repainted itself on the way out would flash a colour at somebody for
/// one frame, so it keeps whatever it had — which, since nothing else is a
/// question either, is the asking ground it started in.
fn mood(phase: Phase) -> theme::Mood {
    match phase {
        Phase::Running => theme::Mood::Running,
        Phase::Lingering | Phase::Detached => theme::Mood::Finished,
        Phase::WaitingForRequest | Phase::AwaitingVerdict | Phase::Closed => theme::Mood::Asking,
    }
}

/// A primary button's label.
fn strong(label: &str) -> egui::RichText {
    egui::RichText::new(label).strong().size(16.0)
}

/// One of the two buttons that decide: what it does, and the key that does
/// the same thing.
///
/// # Why the shortcut is on the button
///
/// `Ctrl+Enter` and `Escape` have always worked and nothing on screen said
/// so, which made them discoverable by reading the source. A window whose
/// fastest way to deny is a secret is a window people answer with the mouse
/// while they are busy, and the whole point of the escape key here is that
/// refusing should cost nothing.
///
/// It is drawn from [`guard::APPROVE_CHORD`] and [`guard::DENY_CHORD`], which
/// live beside the rule they describe and are held to it by a test. Nothing
/// here may word the shortcut for itself: `Ctrl+Shift+Enter` is deliberately
/// inert, so a label loose enough for a reader to expect it to work would be
/// this window promising something it refuses to do.
///
/// The hint is small and quiet — hatch's own voice, beside the word for what
/// the button does — and it fits inside the width the button already had, so
/// the cluster the two buttons are centred in does not move. That claim is
/// `the_shortcut_hints_fit_the_buttons_that_were_already_there`.
fn primary(ui: &egui::Ui, label: &str, chord: &str) -> egui::Button<'static> {
    egui::Button::new((strong(label), egui::RichText::new(chord).small().weak()))
        .min_size(primary_button(ui))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use chrono::Utc;

    use crate::protocol::{
        DaemonMsg, Outcome, Payload, Request, ReviseKind, Verdict, approved, every_verdict,
    };
    use crate::render::render_command;

    #[test]
    fn every_text_style_is_drawn_at_the_size_the_config_asked_for() {
        // One application, to the style, so that the fit rule and the drawing
        // resolve the same font. A style left at egui's own size would be a
        // column measured in a font nothing is drawn in.
        use egui::{FontFamily, TextStyle};

        let ctx = egui::Context::default();
        apply_font_size(&ctx, 20.0);
        let style = ctx.style_of(egui::Theme::Dark);
        let size = |text_style: TextStyle| text_style.resolve(&style);

        assert_eq!(size(TextStyle::Body).size, 20.0);
        assert_eq!(size(TextStyle::Button).size, 20.0);
        assert_eq!(size(TextStyle::Monospace).size, 20.0);
        assert_eq!(size(TextStyle::Small).size, 20.0 * SMALL_SCALE);
        assert_eq!(size(TextStyle::Heading).size, 20.0 * HEADING_SCALE);
        assert_eq!(
            size(TextStyle::Monospace).family,
            FontFamily::Monospace,
            "the pane the fit rule measures stopped being monospace"
        );
        assert_eq!(size(TextStyle::Body).family, FontFamily::Proportional);
        assert_eq!(
            TextStyle::Monospace.resolve(&ctx.style_of(egui::Theme::Light)).size,
            20.0,
            "a reader on a light theme got a different size"
        );

        // And a second size really moves it, so this is not agreeing with
        // whatever egui happened to have.
        apply_font_size(&ctx, 11.0);
        let restyled = ctx.style_of(egui::Theme::Dark);
        assert_eq!(TextStyle::Monospace.resolve(&restyled).size, 11.0);
    }

    #[test]
    fn the_buttons_grow_with_the_text_in_them() {
        // A button pinned to a point count is a button the text grows out of.
        let measure = |points: f32| {
            let ctx = egui::Context::default();
            apply_font_size(&ctx, points);
            let mut size = None;
            let mut out = ctx.run_ui(raw(Vec::new()), |ui| size = Some(primary_button(ui)));
            out.textures_delta.clear();
            size.expect("the frame ran")
        };

        let small = measure(10.0);
        let large = measure(20.0);
        assert!(large.x > small.x, "a larger font left the button the same width");
        assert!(large.y > small.y, "and the same height");
    }

    // ---- the face the command is read in ----------------------------------

    /// A context with this window's faces and a size on them, run once so
    /// that its fonts exist.
    fn a_typeset_context() -> egui::Context {
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let mut out = ctx.run_ui(egui::RawInput::default(), |_| {});
        out.textures_delta.clear();
        ctx
    }

    /// Everything either pane can draw: the set `render::unicode::is_plain`
    /// admits, plus the glyphs hatch adds. The space is left out — it is
    /// drawn by the layout and has no glyph of its own in any face.
    fn drawable() -> Vec<char> {
        ('!'..='~').chain(DRAWN_GLYPHS.iter().copied()).collect()
    }

    /// What one character is actually rasterised as, in the face the style
    /// resolves to: the size of its patch of the atlas, and the coverage in
    /// it.
    ///
    /// The picture and not the codepoint, because both questions asked of it
    /// below are about what a reader sees. Two characters with the same ink
    /// cannot be told apart, and a character whose ink is the replacement box
    /// is one the window is not really drawing.
    ///
    /// `Fonts::has_glyph` would be the obvious tool and cannot be used: it
    /// answers by comparing the resolved face with the family's replacement
    /// face, so for a family one face long — which the monospace family
    /// deliberately is — it says no about every character in it.
    fn ink(ctx: &egui::Context, font: &egui::FontId, c: char) -> (u16, u16, Vec<u8>) {
        let galley = ctx.fonts_mut(|fonts| {
            fonts.layout_no_wrap(c.to_string(), font.clone(), egui::Color32::WHITE)
        });
        let uv = galley.rows[0].glyphs[0].uv_rect;
        let image = ctx.fonts(|fonts| fonts.image());
        let mut pixels = Vec::new();
        for y in uv.min[1]..uv.max[1] {
            for x in uv.min[0]..uv.max[0] {
                pixels.push(image[(usize::from(x), usize::from(y))].a());
            }
        }
        (uv.max[0] - uv.min[0], uv.max[1] - uv.min[1], pixels)
    }

    /// A character no face this window loads has, so whatever it rasterises
    /// to is the replacement glyph.
    const ABSENT: char = '\u{4E00}';

    #[test]
    fn the_panes_are_drawn_in_the_face_this_window_chose() {
        // Inherited is how it was right by accident. The monospace family is
        // one face long on purpose — see `MONOSPACE_FACE` — because egui's
        // own falls back to the proportional face, which is a glyph of
        // another width in a column measured in one.
        let ctx = a_typeset_context();
        let families = ctx.fonts(|fonts| fonts.definitions().families.clone());

        assert_eq!(
            families[&egui::FontFamily::Monospace],
            vec![MONOSPACE_FACE.to_string()],
            "the pane's family is not this face alone"
        );
        assert_eq!(
            families[&egui::FontFamily::Proportional].first().map(String::as_str),
            Some(PROPORTIONAL_FACE),
            "the prose face is not the one that was chosen"
        );
    }

    #[test]
    fn no_glyph_this_window_draws_comes_out_as_an_empty_box() {
        // Found by looking at the real window. The lingering window names the
        // command it ran in one small *proportional* line, chips and all, and
        // Ubuntu-Light has no `↵`: what got drawn where the glyph standing in
        // for an invisible character should have been was an empty box. That
        // is the failure a chip exists to prevent, arriving through the font
        // stack rather than through the renderer.
        //
        // Every style the window draws in, because the chips are not the
        // panes' alone.
        let ctx = a_typeset_context();
        let style = ctx.style_of(egui::Theme::Dark);
        for text_style in
            [egui::TextStyle::Monospace, egui::TextStyle::Small, egui::TextStyle::Body]
        {
            let font = text_style.resolve(&style);
            let missing = ink(&ctx, &font, ABSENT);
            for c in drawable() {
                assert_ne!(
                    ink(&ctx, &font, c),
                    missing,
                    "{text_style:?} draws U+{:04X} {c:?} as the replacement box",
                    c as u32
                );
            }
        }
    }

    #[test]
    fn every_glyph_a_pane_can_draw_is_one_advance_wide() {
        // The premise under `panes::advance` and the whole side-by-side fit
        // rule: a line is measured in characters and the column is measured
        // in widths of `'0'`. A glyph of another width — or a missing one,
        // which is width zero and therefore invisible — makes that a guess.
        let ctx = a_typeset_context();
        let font = egui::TextStyle::Monospace.resolve(&ctx.style_of(egui::Theme::Dark));
        ctx.fonts_mut(|fonts| {
            let advance = fonts.glyph_width(&font, '0');
            assert!(advance > 0.0, "the face has no zero in it");
            for c in drawable().into_iter().chain([' ']) {
                let width = fonts.glyph_width(&font, c);
                assert_eq!(
                    width,
                    advance,
                    "U+{:04X} {c:?} is {width} wide against an advance of {advance}",
                    c as u32
                );
            }
        });
    }

    #[test]
    fn the_pane_draws_two_characters_as_two_characters() {
        // A ligature is the display rendering something that is not the
        // characters, which is the one thing this whole program refuses. A
        // face with them would draw `&&` as a single glyph and `!=` as `≠` —
        // and it would break the fit rule at the same time, since the run
        // would no longer be as wide as it has characters.
        let ctx = a_typeset_context();
        let font = egui::TextStyle::Monospace.resolve(&ctx.style_of(egui::Theme::Dark));
        let advance = ctx.fonts_mut(|fonts| fonts.glyph_width(&font, '0'));

        for pair in
            ["&&", "||", "!=", "==", "->", "<-", "=>", ">=", "<=", "::", "|>", "//", "...", ";;"]
        {
            let galley = ctx.fonts_mut(|fonts| {
                fonts.layout_no_wrap(pair.to_string(), font.clone(), egui::Color32::WHITE)
            });
            let glyphs: usize = galley.rows.iter().map(|row| row.glyphs.len()).sum();
            assert_eq!(
                glyphs,
                pair.chars().count(),
                "{pair:?} was drawn as fewer glyphs than it has characters"
            );
            let want = advance * pair.chars().count() as f32;
            // Half a point of slack: a galley's width is rounded to the
            // pixel grid, and what is being refused here is a glyph going
            // missing, which costs a whole advance.
            assert!(
                (galley.size().x - want).abs() < 0.5,
                "{pair:?} laid out {} wide against {want} for its characters",
                galley.size().x
            );
        }
    }

    #[test]
    fn the_characters_a_misreading_turns_into_another_command_are_not_alike() {
        // A misread quote is a different command, and `rm -rf /l` is not
        // `rm -rf /1`. Asked of what is actually rasterised rather than of
        // the face's name: two characters whose bitmaps match are two
        // characters a reader cannot tell apart, whatever the face claims.
        let ctx = a_typeset_context();
        let font = egui::TextStyle::Monospace.resolve(&ctx.style_of(egui::Theme::Dark));

        for group in [
            ['l', '1', 'I'].as_slice(),
            ['0', 'O'].as_slice(),
            [',', '.'].as_slice(),
            ['\'', '`', '"'].as_slice(),
            [';', ':'].as_slice(),
        ] {
            for (index, first) in group.iter().enumerate() {
                for second in &group[index + 1..] {
                    assert_ne!(
                        ink(&ctx, &font, *first),
                        ink(&ctx, &font, *second),
                        "{first:?} and {second:?} are drawn as the same picture"
                    );
                }
            }
        }
    }

    #[test]
    fn the_shortcut_hints_fit_the_buttons_that_were_already_there() {
        // The rect Approve and Deny are centred in is `cluster_width`, which
        // is two button minimums and the gap between them, and what sits just
        // past its edge is the escape hatches. A label that outgrew the
        // minimum would widen the buttons without widening the rect, and the
        // fallback that gives the hatches a row of their own would stop
        // firing when it is needed — so the hint has to fit the button that
        // was already there, not enlarge it.
        //
        // Two sizes, because the minimum is a multiple of the font and the
        // hint is drawn in a style that follows it: a claim made at one size
        // only would not be a claim about the reader's size.
        for points in [11.0, 20.0] {
            let ctx = egui::Context::default();
            apply_faces(&ctx);
            apply_font_size(&ctx, points);
            let mut measured = Vec::new();
            let mut out = ctx.run_ui(raw_sized(Vec::new(), opening_size()), |ui| {
                let least = primary_button(ui).x;
                for (label, chord) in
                    [("Approve", guard::APPROVE_CHORD), ("Deny", guard::DENY_CHORD)]
                {
                    let width = unfocusable(ui, primary(ui, label, chord)).rect.width();
                    measured.push((label, width, least));
                }
            });
            out.textures_delta.clear();

            assert_eq!(measured.len(), 2, "the buttons were not drawn");
            for (label, width, least) in measured {
                assert!(
                    width <= least,
                    "{label} with its shortcut is {width} wide at {points} points, past the \
                     {least} the cluster is measured from"
                );
            }
        }
    }

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
        let app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
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

        // With a note in it, because an approval carries one and this is the
        // test that says what the frame looks like.
        let frame = state.decide(Verdict::Approve {
            stream: true,
            terminal: false,
            closing: false,
            note: "go on".to_string(),
        });
        answer(&mut wire, &mut state, frame);

        assert_eq!(
            String::from_utf8(wire).unwrap(),
            "{\"type\":\"verdict\",\"verdict\":\"approve\",\"stream\":true,\"terminal\":false,\
             \"closing\":false,\"note\":\"go on\"}\n"
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
        let frame = state.decide(approved(true));
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
        state.decide(approved(false));
        state.handle(DaemonMsg::QueueDepth { depth: 7 });

        assert_eq!(state.queue_depth(), 7, "the depth is still recorded");
        assert_eq!(state.queue_badge(), None, "but it is no longer about this window");
    }

    // ---- exactly one verdict ----------------------------------------------

    #[test]
    fn a_second_press_of_the_same_button_sends_nothing() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));

        assert!(state.decide(approved(true)).is_some());
        assert_eq!(state.decide(approved(true)), None);
    }

    #[test]
    fn a_verdict_pressed_while_the_command_runs_sends_nothing() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(approved(true));

        assert_eq!(state.decide(Verdict::Deny { note: String::new() }), None);
        assert_eq!(state.phase(), Phase::Running, "and it did not change what is happening");
    }

    #[test]
    fn no_verdict_can_be_given_before_the_request_arrives() {
        let mut state = PromptState::new();

        assert_eq!(state.decide(approved(true)), None);
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
        // The whole set, minus the one verdict that leaves something to
        // watch. See `crate::protocol::every_verdict` on why the list is not
        // written out here.
        for verdict in every_verdict()
            .into_iter()
            .filter(|verdict| !matches!(verdict, Verdict::Approve { .. }))
        {
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

        state.decide(approved(false));
        assert_eq!(state.request_kill(), Some(PromptMsg::Kill));

        state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));
        assert_eq!(state.request_kill(), None, "it is already over");
    }

    // ---- the ending --------------------------------------------------------

    #[test]
    fn the_outcome_survives_the_frame_that_closed_the_window() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(approved(false));
        state.handle(DaemonMsg::Finished(Outcome::Signal { signal: 9 }));

        assert_eq!(state.outcome(), Some(&Outcome::Signal { signal: 9 }));
        assert_eq!(state.broken(), None, "a signal is an outcome, not a failure");
    }

    #[test]
    fn the_daemon_hanging_up_after_the_outcome_does_not_rewrite_the_ending() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(approved(false));
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

    // ---- lingering, and what it becomes ------------------------------------

    /// A window whose streamed command has just finished.
    fn a_lingering_state() -> PromptState {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(approved(true));
        state.handle(DaemonMsg::Output { stream: Stream::Stdout, text: "hello\n".to_string() });
        state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));
        state
    }

    #[test]
    fn a_run_the_reader_asked_to_watch_stays_instead_of_closing() {
        // The bug. An ordinary command is approved, runs and finishes inside a
        // few milliseconds, so a window that closed on the outcome closed at
        // the moment the output it was asked to show arrived.
        let state = a_lingering_state();

        assert_eq!(state.phase(), Phase::Lingering);
        assert!(!state.should_close(), "the window went at the moment it had something to show");
        assert_eq!(state.outcome(), Some(&Outcome::Exit { code: 0 }));
        assert_eq!(state.output_text(), "hello\n");
    }

    #[test]
    fn a_run_nobody_asked_to_watch_closes_on_the_outcome_as_it_always_did() {
        // The other half of the fix: nothing changes for the default path, so
        // an agent's headless command still costs the reader no window at all.
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(approved(false));
        state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));

        assert_eq!(state.phase(), Phase::Closed);
        assert_eq!(state.linger_seconds_remaining(Instant::now()), None);
    }

    #[test]
    fn the_window_that_is_about_to_go_says_how_long_it_has() {
        let state = a_lingering_state();

        assert_eq!(
            state.linger_seconds_remaining(Instant::now()),
            Some(LINGER.as_secs()),
            "the countdown did not start at the whole linger"
        );
        // Rounded up, so the last second reads as a second rather than as
        // nothing, and it reaches zero exactly where the window goes.
        assert_eq!(state.linger_seconds_remaining(Instant::now() + LINGER), Some(0));
        assert_eq!(
            state.linger_seconds_remaining(Instant::now() + LINGER * 2),
            Some(0),
            "a clock past the deadline must not wrap round"
        );
    }

    #[test]
    fn the_linger_running_out_closes_the_window() {
        let mut state = a_lingering_state();

        state.tick(Instant::now());
        assert_eq!(state.phase(), Phase::Lingering, "it went early");

        state.tick(Instant::now() + LINGER);

        assert_eq!(state.phase(), Phase::Closed);
        assert!(state.take_close(), "the process was never told to leave");
        assert_eq!(state.broken(), None, "a countdown running out is not a failure");
    }

    #[test]
    fn keeping_the_window_stops_the_countdown_for_good() {
        let mut state = a_lingering_state();

        assert!(state.keep());

        assert_eq!(state.phase(), Phase::Detached);
        assert_eq!(state.linger_seconds_remaining(Instant::now()), None, "it is still counting");
        state.tick(Instant::now() + LINGER * 100);
        assert_eq!(state.phase(), Phase::Detached, "the clock took a window somebody kept");
        assert_eq!(state.output_text(), "hello\n", "and the output it was kept for is gone");
    }

    #[test]
    fn keeping_is_only_possible_from_the_phase_that_is_counting_down() {
        let mut fresh = PromptState::new();
        assert!(!fresh.keep());
        assert_eq!(fresh.phase(), Phase::WaitingForRequest);

        let mut awaiting = PromptState::new();
        awaiting.handle(DaemonMsg::Request(a_request(90)));
        assert!(!awaiting.keep(), "a window with a question open is not a viewer");
        assert_eq!(awaiting.phase(), Phase::AwaitingVerdict);

        let mut running = PromptState::new();
        running.handle(DaemonMsg::Request(a_request(90)));
        running.decide(approved(true));
        assert!(!running.keep(), "there is nothing to keep until it has finished");
        assert_eq!(running.phase(), Phase::Running);

        let mut kept = a_lingering_state();
        assert!(kept.keep());
        assert!(!kept.keep(), "keeping twice is not keeping");
        assert_eq!(kept.phase(), Phase::Detached);
    }

    #[test]
    fn no_verdict_can_come_out_of_a_window_that_has_outlived_its_request() {
        // The rule the whole hand-over rests on. By the time either of these
        // phases is reachable the daemon has returned to the agent and let go
        // of this process: a verdict from here would be answering a question
        // nobody is listening to, so there must be no way to build one.
        for detached in [false, true] {
            let mut state = a_lingering_state();
            if detached {
                assert!(state.keep());
            }
            let was = state.phase();
            for verdict in every_verdict() {
                assert_eq!(state.decide(verdict.clone()), None, "{verdict:?} from {was:?}");
            }
            assert_eq!(state.request_kill(), None, "there is nothing left to kill");
            assert_eq!(state.phase(), was, "a refused verdict moved the window anyway");
        }
    }

    #[test]
    fn a_viewer_whose_channel_ends_still_closes_and_still_is_not_a_failure() {
        // The daemon holds a handed-over window's standard input for as long
        // as the window lives, so this is hatch itself going away. There is
        // nobody left to report it to, and nobody left to end this process
        // either — so it ends itself, quietly.
        for detached in [false, true] {
            let mut state = a_lingering_state();
            if detached {
                assert!(state.keep());
            }

            state.channel_broken("hatch closed the channel");

            assert!(state.should_close(), "a viewer with no channel is an orphan");
            assert_eq!(state.broken(), None, "the daemon going away is not this window's failure");
        }
    }

    #[test]
    fn the_guards_two_keys_decide_nothing_once_the_request_is_over() {
        // Enter and Escape never reach a widget — the guard takes them out of
        // the frame either way — so what they mean is decided here. On a
        // window with nothing to decide, Escape puts it away and Enter does
        // nothing at all, and neither writes a frame to a daemon that has
        // already returned.
        for (action, after) in
            [(Action::Approve, Phase::Lingering), (Action::Deny, Phase::Closed)]
        {
            let (mut app, sink) = a_finished_window();
            app.act(action);
            assert_eq!(app.state.phase(), after, "{action:?}");
            assert!(sink.lock().unwrap().is_empty(), "{action:?} answered a request that is over");
        }

        let (mut app, sink) = a_finished_window();
        assert!(app.state.keep());
        app.act(Action::Approve);
        assert_eq!(app.state.phase(), Phase::Detached);
        app.act(Action::Deny);
        assert_eq!(app.state.phase(), Phase::Closed);
        assert!(sink.lock().unwrap().is_empty(), "a detached viewer wrote to the daemon");
    }

    #[test]
    fn what_would_be_copied_is_what_is_on_the_screen() {
        // One string, built once, so the button cannot drift from the view.
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(approved(true));
        state.handle(DaemonMsg::Output { stream: Stream::Stdout, text: "one\n".to_string() });
        state.handle(DaemonMsg::Output { stream: Stream::Stderr, text: "two\n".to_string() });

        assert_eq!(state.output_text(), "one\ntwo\n");
        assert!(!state.output_dropped(), "nothing was dropped");
    }

    #[test]
    fn output_the_cap_threw_away_is_admitted_to() {
        // A copy action over a capped buffer is a window that can hand over
        // less than it appears to. Saying so is the difference between a cap
        // and a quiet lie.
        let state = after_output(64, 64 * 1024);

        assert!(state.output_dropped(), "the cap bit without the window admitting it");
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
        state.decide(approved(true));
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
        state.decide(approved(true));
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
        state.decide(approved(true));
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
        read_noticing(input).0
    }

    /// The same, plus what the reader said about each item it handed over.
    fn read_noticing(input: &str) -> ((Vec<Incoming>, usize), Vec<Noticed>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let seen = std::sync::Mutex::new(Vec::new());
        read_frames(input.as_bytes(), &tx, |noticed| {
            seen.lock().unwrap().push(noticed);
        });
        drop(tx);
        let noticed = seen.into_inner().unwrap();
        ((rx.into_iter().collect(), noticed.len()), noticed)
    }

    #[test]
    fn the_reader_says_when_the_daemon_has_had_its_last_word() {
        // Not a convenience: the backstop that bounds a lingering window is
        // armed off this, on this thread, precisely so that a window whose
        // event loop has stopped is still bounded by something.
        let request = protocol::encode(&DaemonMsg::Request(a_request(90))).unwrap();
        let output = protocol::encode(&DaemonMsg::Output {
            stream: Stream::Stdout,
            text: "hi".to_string(),
        })
        .unwrap();
        let finished =
            protocol::encode(&DaemonMsg::Finished(Outcome::Exit { code: 0 })).unwrap();

        let (_, noticed) = read_noticing(&format!("{request}\n{output}\n{finished}\n"));

        assert_eq!(
            noticed,
            vec![
                Noticed { final_frame: false, last: false },
                Noticed { final_frame: false, last: false },
                Noticed { final_frame: true, last: false },
                Noticed { final_frame: false, last: true },
            ]
        );
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
        read_frames(format!("{depth}\n").as_bytes(), &tx, |_| {});
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

        assert!(state.decide(approved(true)).is_some());
        assert_eq!(state.phase(), Phase::Running);
        assert!(!state.should_close());
    }

    #[test]
    fn finished_closes_the_window() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(a_request(90)));
        state.decide(approved(false));
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
            PromptApp::new(
                rx,
                Box::new(Sink(Arc::clone(&sink))),
                Arc::new(OnceLock::new()),
                PrefsFile::none(),
            );
        app.state.handle(DaemonMsg::Request(a_request(90)));
        (app, sink)
    }

    /// The same window, once its streamed command has finished: lingering,
    /// with the daemon already gone from the other end.
    fn a_finished_window() -> (PromptApp, Arc<std::sync::Mutex<Vec<u8>>>) {
        let (mut app, sink) = an_awaiting_window();
        app.state.decide(approved(true));
        app.state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));
        assert_eq!(app.state.phase(), Phase::Lingering);
        // Nothing has been written yet: `decide` hands back the frame and
        // `answer` is what sends it, and this window's verdict never went
        // through `answer`.
        assert!(sink.lock().unwrap().is_empty());
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
        raw_sized(events, egui::vec2(800.0, 600.0))
    }

    /// The same, on a window of a given size.
    ///
    /// The size is a parameter because two of the claims below are about
    /// space: how much of the window the panes get at the size the window
    /// opens at, and what the controls do when there is not enough of it.
    fn raw_sized(events: Vec<egui::Event>, size: egui::Vec2) -> egui::RawInput {
        egui::RawInput {
            events,
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
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
    ///
    /// `note` is what is in the note field when the button goes down, which
    /// is half of what an approval carries.
    fn click_approve(open: bool, note: &str) -> Vec<u8> {
        let (mut app, sink) = an_awaiting_window();
        app.note = note.to_string();
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
            click_approve(false, "").is_empty(),
            "a click landed on Approve while the guard was shut"
        );
    }

    #[test]
    fn the_same_click_after_the_guard_does_approve() {
        // The control for the test above: without this, a click that never
        // lands would look like a guard that works.
        let out = String::from_utf8(click_approve(true, "")).expect("utf-8");
        assert!(out.contains("approve"), "the click did not reach Approve at all: {out:?}");
    }

    #[test]
    fn a_note_typed_before_approve_leaves_with_the_approval() {
        // The field is labelled "Note to the agent", and until now an
        // approval was the one press that read it and threw it away. Both
        // ways of approving are asked, because they build the verdict in two
        // different places.
        let typed = "fine — but watch the mount";

        let out = String::from_utf8(click_approve(true, typed)).expect("utf-8");
        assert!(out.contains("\"verdict\":\"approve\""), "the click did not approve: {out}");
        assert!(out.contains(typed), "the click dropped the note: {out}");

        let (mut app, sink) = an_awaiting_window();
        app.note = typed.to_string();
        app.act(Action::Approve);
        let out = String::from_utf8(sink.lock().expect("sink").clone()).expect("utf-8");
        assert!(out.contains("\"verdict\":\"approve\""), "the key did not approve: {out}");
        assert!(out.contains(typed), "the key dropped the note: {out}");
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
        apply_faces(&ctx);
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

    /// Every string a window of a given size lays out.
    ///
    /// The size is the parameter because the controls arrange themselves two
    /// ways, and which one a reader gets is a question about width.
    fn window_text_sized(app: &mut PromptApp, size: egui::Vec2) -> String {
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        for _ in 0..2 {
            let mut out = ctx.run_ui(raw_sized(Vec::new(), size), |ui| app.window(ui, true));
            out.textures_delta.clear();
        }
        let mut out = ctx.run_ui(raw_sized(Vec::new(), size), |ui| app.window(ui, true));
        let text = text_on_screen(&out);
        out.textures_delta.clear();
        text
    }

    /// A window awaiting a verdict on `command`, which the agent asked to run
    /// as root.
    fn a_root_window_showing(command: &str) -> PromptApp {
        let mut app = a_window_showing(command);
        let mut request = a_request(90);
        request.payload = Payload::command(
            &render_command(command, &BTreeMap::new()),
            Vec::new(),
            PathBuf::from("/tmp"),
            true,
            false,
        );
        app.state = PromptState::new();
        app.state.handle(DaemonMsg::Request(request));
        app
    }

    /// A window awaiting a verdict on `command`, which runs in a terminal of
    /// its own and so cannot be streamed to this one.
    fn an_interactive_window_showing(command: &str) -> PromptApp {
        let mut app = a_window_showing(command);
        let mut request = a_request(90);
        request.payload = Payload::command(
            &render_command(command, &BTreeMap::new()),
            Vec::new(),
            PathBuf::from("/tmp"),
            false,
            true,
        );
        app.state = PromptState::new();
        app.state.handle(DaemonMsg::Request(request));
        app
    }

    /// A window awaiting a verdict on `command`.
    fn a_window_showing(command: &str) -> PromptApp {
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
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

    /// The same window once its streamed command has finished, with `printed`
    /// on the screen.
    fn a_finished_window_showing(command: &str, printed: &str) -> PromptApp {
        let mut app = a_window_showing(command);
        app.state.decide(approved(true));
        app.state
            .handle(DaemonMsg::Output { stream: Stream::Stdout, text: printed.to_string() });
        app.state.handle(DaemonMsg::Finished(Outcome::Exit { code: 3 }));
        app
    }

    #[test]
    fn a_lingering_window_shows_the_output_the_outcome_and_how_long_it_is_staying() {
        let mut app = a_finished_window_showing("echo marker", "a line it printed\n");

        let drawn = window_text(&mut app, true);

        assert!(drawn.contains("a line it printed"), "the output is not on screen: {drawn}");
        assert!(drawn.contains("exit 3"), "the window does not say how it ended: {drawn}");
        assert!(
            drawn.contains("closing in"),
            "the window is about to take itself away without saying so: {drawn}"
        );
        assert!(drawn.contains("Keep this window"), "there is no way to keep it: {drawn}");
        assert!(drawn.contains("Copy output"), "there is no way to take the output: {drawn}");
        assert!(drawn.contains("echo marker"), "the output has nothing naming it: {drawn}");
        assert!(
            !drawn.contains("Approve") && !drawn.contains("Deny"),
            "a window with nothing to decide still offered a verdict: {drawn}"
        );
        // Two countdowns on one window is two numbers the reader has to tell
        // apart, and one of them measures time that has already been used.
        assert!(
            !drawn.contains("to decide"),
            "the approval clock is still running under a finished command: {drawn}"
        );
    }

    #[test]
    fn a_kept_window_drops_the_countdown_and_keeps_everything_else() {
        let mut app = a_finished_window_showing("echo marker", "a line it printed\n");
        assert!(app.state.keep());

        let drawn = window_text(&mut app, true);

        assert!(!drawn.contains("closing in"), "a kept window is still counting down: {drawn}");
        assert!(
            !drawn.contains("Keep this window"),
            "a kept window still offers to be kept: {drawn}"
        );
        assert!(drawn.contains("a line it printed"), "the output it was kept for: {drawn}");
        assert!(drawn.contains("Copy output"), "{drawn}");
        assert!(drawn.contains("Copy command"), "{drawn}");
        assert!(drawn.contains("Close"), "there is no way to put it away: {drawn}");
        assert!(
            !drawn.contains("Approve") && !drawn.contains("Deny"),
            "a detached viewer offered a verdict: {drawn}"
        );
    }

    #[test]
    fn a_finished_window_that_printed_nothing_says_so() {
        // Rather than an empty box, which reads as a view that failed to load.
        let mut app = a_finished_window_showing("true", "");

        let drawn = window_text(&mut app, true);

        assert!(drawn.contains("printed nothing"), "{drawn}");
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
    fn the_window_says_which_keys_decide() {
        // They always worked; nothing said so, which made them discoverable
        // by reading the source. The strings are the guard's own, so this
        // cannot pass against a label the rule does not accept.
        let drawn = window_text(&mut a_window_showing("rm -rf /var/tmp/build"), true);

        assert!(drawn.contains(guard::APPROVE_CHORD), "no key is offered for Approve: {drawn}");
        assert!(drawn.contains(guard::DENY_CHORD), "no key is offered for Deny: {drawn}");
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
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
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
        let frame = app.state.decide(approved(true));
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
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
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
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
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
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
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
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
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
    fn what_a_terminal_costs_is_drawn_beside_the_control_that_opens_one() {
        // The one thing about this control a reader cannot work out for
        // themselves: the terminal is theirs, it behaves like theirs, and
        // everything that happens in it is sent to the agent -- what they type
        // included, because the terminal echoes it. If they learn that
        // afterwards it is too late to matter.
        let mut app = a_window_showing("pacman -Syu");
        let drawn = window_text(&mut app, true);

        assert!(drawn.contains(TERMINAL_LABEL), "the control is missing: {drawn}");
        assert!(
            drawn.contains(TERMINAL_CAPTURE),
            "the control was offered without saying what it costs: {drawn}"
        );
    }

    #[test]
    fn the_cost_is_said_even_when_nobody_chose_the_terminal() {
        // The case with the most to warn about and the least reason to expect
        // a warning: the reader did not ask for a terminal, so nothing they
        // did would prompt them to wonder what one implies.
        let mut app = an_interactive_window_showing("vim /etc/hosts");
        let drawn = window_text(&mut app, true);

        assert!(drawn.contains(TERMINAL_CAPTURE), "{drawn}");
        assert!(drawn.contains(TERMINAL_ASKED), "and why the box cannot be untucked: {drawn}");
    }

    #[test]
    fn a_terminal_the_agent_asked_for_cannot_be_taken_away_at_the_window() {
        // The control grants and never withdraws. A command that needs a
        // terminal and is denied one does not fail -- it hangs, with nowhere
        // for anybody to type -- so there is no state of this window in which
        // a request that asked for one is approved without it.
        let mut app = an_interactive_window_showing("vim /etc/hosts");
        // Whatever the reader's own half says, including the default and
        // including a value nothing in the window can produce.
        for chosen in [false, true] {
            app.terminal = chosen;
            window_text(&mut app, true);
            assert!(
                matches!(app.approval(), Verdict::Approve { terminal: true, .. }),
                "the agent asked for a terminal and the window answered without one"
            );
        }
    }

    #[test]
    fn choosing_a_terminal_takes_the_stream_box_away_and_says_why() {
        // The terminal *is* the stream, so the box has nothing left to offer.
        // It is cleared rather than greyed with a tick still in it: a ticked
        // box that cannot be untucked reads as a promise to stream, and
        // nothing is going to.
        let mut app = a_window_showing("pacman -Syu");
        app.stream = true;
        app.terminal = true;
        let drawn = window_text(&mut app, true);

        assert!(!app.stream, "a terminal run has no stream to promise");
        assert!(
            drawn.contains("terminal of its own"),
            "a checkbox that went dead was left unexplained: {drawn}"
        );
        assert!(
            matches!(app.approval(), Verdict::Approve { stream: false, terminal: true, .. }),
            "got {:?}",
            app.approval()
        );
    }

    #[test]
    fn a_swap_offers_no_checkbox_for_output_it_will_never_produce() {
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
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
        // Nor a terminal to run in. A swap writes bytes and says nothing:
        // there is no command for a terminal to hold, so the control would be
        // a question with no answer -- and the warning beside it would be a
        // caution about something that cannot happen.
        assert!(!drawn.contains(TERMINAL_LABEL), "a swap offered a terminal: {drawn}");
        assert!(!drawn.contains(TERMINAL_CAPTURE), "{drawn}");
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
            caveat: None,
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
    // ---- how much of the window the reader gets ---------------------------
    //
    // The window exists to have a command read off it, so the space the panes
    // get is a claim about the product and not a detail of the layout. These
    // measure it the way a screenshot would: by finding the pane boxes egui
    // actually laid out.

    /// The whole window, drawn at `size`, as the shapes egui would send to a
    /// GPU.
    fn window_shapes(app: &mut PromptApp, size: egui::Vec2) -> Vec<egui::epaint::ClippedShape> {
        let ctx = egui::Context::default();
        theme::apply(&ctx, theme::Theme::Dark);
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        // Three frames: a panel learns its height from the frame before, so a
        // pane measured against the first frame's guess is not the pane a
        // reader sees.
        for _ in 0..2 {
            let mut out = ctx.run_ui(raw_sized(Vec::new(), size), |ui| app.window(ui, true));
            out.textures_delta.clear();
        }
        let mut out = ctx.run_ui(raw_sized(Vec::new(), size), |ui| app.window(ui, true));
        out.textures_delta.clear();
        out.shapes
    }

    /// Every rectangle filled with the pane surface: the reading boxes, and
    /// nothing else on screen is that colour.
    fn pane_boxes(shapes: &[egui::epaint::ClippedShape]) -> Vec<egui::Rect> {
        fn walk(shape: &egui::epaint::Shape, fill: egui::Color32, out: &mut Vec<egui::Rect>) {
            match shape {
                egui::epaint::Shape::Rect(rect) if rect.fill == fill => out.push(rect.rect),
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        walk(shape, fill, out);
                    }
                }
                _ => {}
            }
        }
        let fill = theme::DARK.surface;
        let mut out = Vec::new();
        for clipped in shapes {
            walk(&clipped.shape, fill, &mut out);
        }
        // The note field is drawn on the same surface, and it is not a pane.
        out.retain(|rect| rect.height() > 60.0);
        out
    }

    /// How many points of the window's height the panes cover.
    fn pane_height(app: &mut PromptApp, size: egui::Vec2) -> f32 {
        let shapes = window_shapes(app, size);
        let boxes = pane_boxes(&shapes);
        assert!(!boxes.is_empty(), "no pane was drawn at all");
        let top = boxes.iter().map(|r| r.top()).fold(f32::INFINITY, f32::min);
        let bottom = boxes.iter().map(|r| r.bottom()).fold(f32::NEG_INFINITY, f32::max);
        bottom - top
    }

    /// The size the window opens at, which is the size these claims are made
    /// about.
    fn opening_size() -> egui::Vec2 {
        egui::vec2(WINDOW_SIZE[0], WINDOW_SIZE[1])
    }

    #[test]
    fn the_panes_get_most_of_the_window_the_reader_opened() {
        // Measured, not asserted about the code: this is the number the whole
        // bundling pass exists to move. Before it, a short command at this
        // size got 360 points of pane out of 700 and the furniture took the
        // other 340. The floor here is well under what the layout actually
        // manages, so it fails on a regression rather than on a font metric.
        let mut app = a_window_showing("rm -rf /var/tmp/build && echo 'cleared'");
        let height = pane_height(&mut app, opening_size());

        assert!(
            height >= 0.6 * WINDOW_SIZE[1],
            "the panes got {height} of {} points; the furniture has grown back",
            WINDOW_SIZE[1]
        );
    }

    #[test]
    fn a_long_command_gives_the_pane_a_reader_reads_more_than_the_one_they_check() {
        // The bug: stacking is chosen *because* the command is long, and an
        // even split handed the least room to the case that needed the most.
        // The raw pane is a strip; the annotated pane gets the rest.
        let long = (0..12)
            .map(|i| format!("docker build --pull --no-cache -t registry.internal/thing:{i} ."))
            .collect::<Vec<_>>()
            .join("\n");
        let mut app = a_window_showing(&long);
        let shapes = window_shapes(&mut app, opening_size());
        let mut boxes = pane_boxes(&shapes);
        boxes.sort_by(|a, b| a.top().total_cmp(&b.top()));

        assert_eq!(boxes.len(), 2, "a stacked command did not draw two panes");
        let (strip, reading) = (boxes[0].height(), boxes[1].height());
        assert!(
            reading > 1.5 * strip,
            "the strip is {strip} and the pane a reader reads is {reading}: still a split"
        );
        // And the raw text is on screen without anyone asking for it.
        assert!(strip > 0.0, "the raw pane is not drawn at all when stacked");
    }

    // ---- the controls, bundled --------------------------------------------

    #[test]
    fn the_escape_hatches_share_the_verdict_row_without_reaching_it() {
        // They are past Deny, at the window's edge, with a full `PRIMARY_GAP`
        // between: a pointer sliding off Deny lands on the panel. The claim
        // is about rectangles, so it is asked of the rectangles.
        let ctx = egui::Context::default();
        apply_font_size(&ctx, 16.0);
        let (mut app, _sink) = an_awaiting_window();
        let mut approve = None;
        let mut hatch = None;
        let mut out = ctx.run_ui(raw_sized(Vec::new(), opening_size()), |ui| {
            egui::Panel::bottom("t").show(ui, |ui| {
                let mut note = String::new();
                approve = Some(ui.scope(|ui| app.decision_row(ui, cluster_width(ui), "", &mut None)).inner);
                hatch = Some(ui.min_rect());
                note.clear();
            });
        });
        out.textures_delta.clear();
        let approve = approve.expect("the row drew");
        let row = hatch.expect("the row drew");

        assert!(approve.rect.width() > 0.0, "Approve was not laid out");
        // One row, not two: everything the panel drew is no taller than a
        // single primary button plus the padding around it.
        assert!(
            row.height() < 2.0 * approve.rect.height(),
            "the hatches took a row of their own on a window that had space: {row:?}"
        );
    }

    #[test]
    fn a_window_too_narrow_for_them_gives_the_hatches_their_own_row_again() {
        // Never an overlap. `flanked_row` answers `None` rather than shrinking
        // anything, because the thing it would be reaching into is Approve.
        let ctx = egui::Context::default();
        apply_font_size(&ctx, 16.0);
        let (mut app, _sink) = an_awaiting_window();
        let mut approve = None;
        let mut row = None;
        let mut out = ctx.run_ui(raw_sized(Vec::new(), egui::vec2(520.0, 700.0)), |ui| {
            egui::Panel::bottom("t").show(ui, |ui| {
                approve = Some(ui.scope(|ui| app.decision_row(ui, cluster_width(ui), "", &mut None)).inner);
                row = Some(ui.min_rect());
            });
        });
        out.textures_delta.clear();
        let approve = approve.expect("the row drew");
        let row = row.expect("the row drew");

        assert!(
            row.height() > approve.rect.height(),
            "the hatches stayed on the verdict row at a width that cannot hold them"
        );
    }

    #[test]
    fn a_flank_that_would_reach_the_centre_is_refused_rather_than_squeezed() {
        // The centre of that row is Approve and Deny. A control allowed to
        // overlap them is a control that can be pressed instead of them.
        let ctx = egui::Context::default();
        let mut out = ctx.run_ui(raw_sized(Vec::new(), egui::vec2(1000.0, 200.0)), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                let width = 400.0;
                let room = ui.available_width();
                let fits = flanked_row(ui, 20.0, width, [10.0, 10.0]);
                let [Some(left), Some(right)] = fits.flanks else {
                    panic!("ten points fit on either side of a 400-point centre")
                };
                assert!(left.right() < fits.centre.left(), "the left flank touched the centre");
                assert!(right.left() > fits.centre.right(), "the right flank touched the centre");
                assert!(
                    (fits.centre.center().x - ui.min_rect().center().x).abs() < 1.0,
                    "the centre is not centred"
                );
                assert!(flanked_row(ui, 20.0, width, [room, 0.0]).flanks[0].is_none());
                assert!(flanked_row(ui, 20.0, width, [0.0, room]).flanks[1].is_none());
                // Each side is its own question. A row whose right-hand flank
                // has outgrown its place must not take the left-hand one's
                // place away with it: that coupling cost the close control its
                // seat beside Approve for as long as the two were one answer.
                let crowded = flanked_row(ui, 20.0, width, [10.0, room]);
                assert!(
                    crowded.flanks[0].is_some(),
                    "a flank lost its place because the one opposite it had"
                );
                assert!(crowded.flanks[1].is_none());
                // The boundary is inclusive on the fitting side: a flank that
                // exactly fills its side is a flank that fits, and the extra
                // row a refusal costs is not worth a fraction of a point.
                let exact = left.width();
                assert!(
                    flanked_row(ui, 20.0, width, [exact, exact]).flanks.iter().all(Option::is_some),
                    "a flank that exactly fits was sent to its own row"
                );
                assert!(
                    flanked_row(ui, 20.0, width, [exact + 1.0, 0.0]).flanks[0].is_none(),
                    "a point over was allowed to reach the centre"
                );
                assert!(
                    flanked_row(ui, 20.0, width, [0.0, exact + 1.0]).flanks[1].is_none(),
                    "a point over was allowed to reach the centre from the right"
                );
            });
        });
        out.textures_delta.clear();
    }

    #[test]
    fn the_note_its_label_and_the_stream_box_are_one_row() {
        // Three rows before. The field is still centred at exactly the
        // cluster width, so it still lines up with the buttons under it; the
        // label and the checkbox hang off its ends.
        let ctx = egui::Context::default();
        apply_font_size(&ctx, 16.0);
        let mut app = a_window_showing("sleep 1");
        let mut row = None;
        let mut out = ctx.run_ui(raw_sized(Vec::new(), opening_size()), |ui| {
            egui::Panel::bottom("t").show(ui, |ui| {
                let width = cluster_width(ui);
                app.note_row(ui, width, true, true);
                row = Some(ui.min_rect().height());
            });
        });
        out.textures_delta.clear();
        let row = row.expect("the row drew");

        assert!(
            row < 2.0 * ctx.style_of(egui::Theme::Dark).spacing.interact_size.y,
            "the note row is {row} points: it is still a stack"
        );
    }

    #[test]
    fn the_window_still_says_who_it_runs_as_and_where_after_the_merge() {
        // The run context moved into the corner of the title row. Moved, not
        // dropped: it is the answer to "on whose machine, in which tree".
        let drawn = window_text(&mut a_window_showing("ls"), true);

        assert!(drawn.contains("Runs as"), "the run context is gone: {drawn}");
        assert!(drawn.contains("/tmp"), "the working directory is gone: {drawn}");
    }

    #[test]
    fn one_caption_still_carries_what_each_pane_promises() {
        // The per-pane labels are gone; the claim they made is not.
        let drawn = window_text(&mut a_window_showing("ls -l"), true);

        assert!(drawn.contains("no colour"), "the raw pane's promise is gone: {drawn}");
        assert!(
            drawn.contains("hatch's notes, not the command"),
            "the annotated pane's warning is gone: {drawn}"
        );
    }

    /// Every galley egui laid out this frame, with where it put it.
    fn text_rects(shapes: &[egui::epaint::ClippedShape]) -> Vec<(String, egui::Rect)> {
        fn walk(shape: &egui::epaint::Shape, out: &mut Vec<(String, egui::Rect)>) {
            match shape {
                egui::epaint::Shape::Text(text) => out.push((
                    text.galley.text().to_string(),
                    egui::Rect::from_min_size(text.pos, text.galley.size()),
                )),
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        walk(shape, out);
                    }
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        for clipped in shapes {
            walk(&clipped.shape, &mut out);
        }
        out
    }

    /// Every straight line the frame painted, with the colour it was painted
    /// in: the rule beside the agent's words is one of these, and nothing
    /// else on screen is a line in that colour.
    fn line_segments(
        shapes: &[egui::epaint::ClippedShape],
    ) -> Vec<([egui::Pos2; 2], egui::Color32)> {
        fn walk(shape: &egui::epaint::Shape, out: &mut Vec<([egui::Pos2; 2], egui::Color32)>) {
            match shape {
                egui::epaint::Shape::LineSegment { points, stroke } => {
                    out.push((*points, stroke.color));
                }
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        walk(shape, out);
                    }
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        for clipped in shapes {
            walk(&clipped.shape, &mut out);
        }
        out
    }

    /// The colour the window's own panels were painted this frame.
    ///
    /// The ground, and not any of the boxes on it: a panel fill is the one
    /// rectangle that covers most of the window's width, which is what tells
    /// it from a pane, a button and the note field.
    fn ground_drawn(app: &mut PromptApp) -> egui::Color32 {
        fn walk(shape: &egui::epaint::Shape, out: &mut Vec<(egui::Rect, egui::Color32)>) {
            match shape {
                egui::epaint::Shape::Rect(rect) => out.push((rect.rect, rect.fill)),
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        walk(shape, out);
                    }
                }
                _ => {}
            }
        }
        let shapes = window_shapes(app, opening_size());
        let mut rects = Vec::new();
        for clipped in &shapes {
            walk(&clipped.shape, &mut rects);
        }
        // Wide, and actually painted: egui allocates transparent rectangles
        // for regions that only clip.
        rects.retain(|(rect, fill)| rect.width() > 0.9 * WINDOW_SIZE[0] && fill.a() > 0);
        let grounds: Vec<egui::Color32> = rects.iter().map(|(_, fill)| *fill).collect();
        let first = *grounds.first().expect("the window painted no panel at all");
        assert!(
            grounds.iter().all(|fill| *fill == first),
            "the panels of one window were painted in {} different colours: {grounds:?}",
            grounds.len()
        );
        first
    }

    #[test]
    fn a_window_that_is_asking_does_not_look_like_one_that_is_working() {
        // Three states that looked like one picture. A reader glancing over
        // has to be able to tell "this is waiting for me" from "this is
        // happening" and from "this is over" without reading a word of it,
        // and the buttons going away is not that: it is a difference they
        // have to look for.
        //
        // The colours themselves, and every meaning drawn against them, are
        // `crate::prompt_ui::theme`'s business. What is asserted here is that
        // the phase reaches the paint at all, and that no two phases arrive
        // at the same ground.
        let mut asking = a_window_showing("systemctl restart thing");
        let asking = ground_drawn(&mut asking);

        let mut running = a_window_showing("systemctl restart thing");
        running.state.decide(approved(true));
        assert_eq!(running.state.phase(), Phase::Running, "the window is not running");
        let running = ground_drawn(&mut running);

        let mut finished = a_finished_window_showing("systemctl restart thing", "done\n");
        assert!(finished.state.is_viewer(), "the window is not showing a finished run");
        let finished = ground_drawn(&mut finished);

        assert_eq!(asking, theme::DARK.chrome, "a window with a question on it moved ground");
        assert_eq!(running, theme::DARK.running, "a running window looks like one that is asking");
        assert_eq!(finished, theme::DARK.finished, "a finished window looks like a running one");
    }

    /// Every rectangle the frame filled, with the colour it filled it with.
    fn filled_rects(
        shapes: &[egui::epaint::ClippedShape],
    ) -> Vec<(egui::Rect, egui::Color32)> {
        fn walk(shape: &egui::epaint::Shape, out: &mut Vec<(egui::Rect, egui::Color32)>) {
            match shape {
                egui::epaint::Shape::Rect(rect) if rect.fill.a() > 0 => {
                    out.push((rect.rect, rect.fill));
                }
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        walk(shape, out);
                    }
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        for clipped in shapes {
            walk(&clipped.shape, &mut out);
        }
        out
    }

    /// Every rectangle the frame drew an outline around, with that outline.
    ///
    /// The root edge is one of these and nothing else in the window is: the
    /// panes are filled and framed by egui's own group stroke, which is the
    /// border colour and a single point wide.
    fn stroked_rects(
        shapes: &[egui::epaint::ClippedShape],
    ) -> Vec<(egui::Rect, egui::epaint::Stroke)> {
        fn walk(
            shape: &egui::epaint::Shape,
            out: &mut Vec<(egui::Rect, egui::epaint::Stroke)>,
        ) {
            match shape {
                egui::epaint::Shape::Rect(rect) if rect.stroke.width > 0.0 => {
                    out.push((rect.rect, rect.stroke));
                }
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        walk(shape, out);
                    }
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        for clipped in shapes {
            walk(&clipped.shape, &mut out);
        }
        out
    }

    /// Where this window drew the root edge, if it drew one.
    fn root_edge(shapes: &[egui::epaint::ClippedShape]) -> Option<egui::Rect> {
        stroked_rects(shapes)
            .into_iter()
            .find(|(_, stroke)| {
                stroke.color == theme::DARK.danger && stroke.width == theme::ROOT_EDGE
            })
            .map(|(rect, _)| rect)
    }

    #[test]
    fn a_root_command_is_marked_for_as_long_as_its_window_is_open() {
        // Root is not a phase. It is true while the window asks, true while
        // the command runs, and true while the result sits on screen — and
        // the finished window is a different layout with a different header,
        // which is exactly where a mark that lived in the header alone was
        // lost. So the claim is made once per phase, on the frame each phase
        // actually draws.
        //
        // Two marks, because one of them is a word and the other is a shape
        // that does not depend on where the reader has scrolled to: the block
        // `ROOT` is reversed out of, and the edge around the whole window. A
        // reader who cannot tell this red from this grey has the rectangle
        // and the frame either way.
        let asking = &mut a_root_window_showing("rm -rf /var/lib/thing");

        let mut running = a_root_window_showing("rm -rf /var/lib/thing");
        running.state.decide(approved(true));
        assert_eq!(running.state.phase(), Phase::Running);

        let mut finished = a_root_window_showing("rm -rf /var/lib/thing");
        finished.state.decide(approved(true));
        finished.state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));
        assert_eq!(finished.state.phase(), Phase::Lingering);

        let mut kept = a_root_window_showing("rm -rf /var/lib/thing");
        kept.state.decide(approved(true));
        kept.state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));
        assert!(kept.state.keep(), "the window would not be kept");
        assert_eq!(kept.state.phase(), Phase::Detached);

        let windows = [
            ("asking", asking),
            ("running", &mut running),
            ("finished", &mut finished),
            ("kept", &mut kept),
        ];
        for (phase, app) in windows {
            let shapes = window_shapes(app, opening_size());
            let edge = root_edge(&shapes)
                .unwrap_or_else(|| panic!("{phase}: the window is not framed as a root window"));
            assert!(
                edge.width() >= WINDOW_SIZE[0] - 1.0 && edge.height() >= WINDOW_SIZE[1] - 1.0,
                "{phase}: the frame covers {edge:?} of a {WINDOW_SIZE:?} window"
            );
            let word = text_rects(&shapes)
                .into_iter()
                .find(|(text, _)| text == panes::principal(true))
                .unwrap_or_else(|| panic!("{phase}: nothing on screen says ROOT"));
            let block = filled_rects(&shapes)
                .into_iter()
                .find(|(rect, fill)| *fill == theme::DARK.danger && rect.contains_rect(word.1))
                .map(|(rect, _)| rect);
            assert!(
                block.is_some(),
                "{phase}: ROOT at {:?} is a word in a colour and not a mark",
                word.1
            );
        }
    }

    #[test]
    fn the_frame_is_paid_for_out_of_the_margin_and_not_out_of_the_reading() {
        // The claim that makes an edge the right shape for this: it costs no
        // row. It is painted over a window the panels have already divided
        // up, in the margin every panel leaves around its contents, so
        // nothing it covers is something a reader was reading. Asserted
        // against the galleys rather than by reading `ROOT_EDGE`, because
        // what matters is where the line actually landed.
        let mut app = a_root_window_showing("rm -rf /var/lib/thing");
        let shapes = window_shapes(&mut app, opening_size());
        let window = root_edge(&shapes).expect("the window is not framed");
        let inside = window.shrink(theme::ROOT_EDGE);

        for (text, rect) in text_rects(&shapes) {
            assert!(
                inside.contains_rect(rect.intersect(window)),
                "the frame is drawn over {text:?} at {rect:?}"
            );
        }
    }

    #[test]
    fn a_command_that_runs_as_the_reader_is_not_framed() {
        // The frame is the loudest thing this window can say without taking a
        // row, and it says one thing. A window that drew it around every
        // request would be saying nothing.
        let mut app = a_window_showing("rm -rf target");
        let shapes = window_shapes(&mut app, opening_size());

        assert!(!app.state.runs_as_root(), "the fixture asked for root");
        assert_eq!(root_edge(&shapes), None, "an unprivileged command was framed as root");
    }

    #[test]
    fn a_swap_states_its_own_ownership_and_is_not_framed() {
        // A `swap_file` request has no run context — it names an absolute
        // path and the owner the plan lands on, in its own header — and a
        // frame around it would be a second claim about the same thing in a
        // second vocabulary.
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app = PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
        let mut request = a_request(90);
        request.payload = Payload::swap(
            PathBuf::from("/tmp/conf.toml"),
            crate::swap::SwapPlan {
                kind: crate::swap::PlanKind::Replace,
                landing_mode: 0o644,
                landing_owner: crate::swap::Principal { id: 0, name: Some("root".into()) },
                landing_group: crate::swap::Principal { id: 0, name: Some("root".into()) },
                hash_before: Some("aa".into()),
                size_delta: 4,
            },
            &crate::render::diff::side_by_side("port = 80\n", "port = 8080\n"),
        );
        app.state.handle(DaemonMsg::Request(request));

        assert!(!app.state.runs_as_root(), "a swap answered the command's question");
        assert_eq!(root_edge(&window_shapes(&mut app, opening_size())), None);
    }

    #[test]
    fn the_agents_words_are_marked_as_the_agents() {
        // The title is the first thing read, the most persuasive thing on
        // screen, and written by the party whose request is being judged. The
        // panes say whose each half is; the header used to say nothing at
        // all, and a reassuring title over a hostile command is the cheapest
        // lever a prompt-injected agent has.
        //
        // Two channels, neither of which costs a row: the words, and the rule
        // beside them. The rule has to reach both lines — attributing the
        // title and leaving the reason bare would be worse than saying
        // nothing, because the reader would learn that unmarked text is
        // hatch's.
        let mut app = a_window_showing("ls");
        let shapes = window_shapes(&mut app, opening_size());
        let drawn = text_rects(&shapes);
        let find = |want: &str| {
            drawn
                .iter()
                .find(|(text, _)| text == want)
                .unwrap_or_else(|| panic!("{want} is not on screen"))
                .1
        };

        let title = find(&format!("{} delete the build directory", panes::ATTRIBUTION));
        let reason = find("the last build left files the tests trip over");

        let quiet = theme::DARK.quiet;
        let rule = line_segments(&shapes)
            .into_iter()
            .filter(|([from, to], colour)| *colour == quiet && from.x == to.x)
            .min_by(|(a, _), (b, _)| a[0].x.total_cmp(&b[0].x))
            .map(|(points, _)| points)
            .expect("nothing on screen says whose words the headline is");

        assert!(rule[0].x < title.left(), "the rule is not beside the words it marks");
        assert!(
            rule[0].y <= title.top() && rule[1].y >= reason.bottom(),
            "the rule covers {:?} and the two lines run {} to {}",
            rule,
            title.top(),
            reason.bottom()
        );
        // And the run context, which is hatch's own statement and not the
        // agent's, is not what the rule is pointing at.
        assert!(find("Runs as").left() > rule[0].x, "the rule was drawn past hatch's own words");
    }

    #[test]
    fn the_run_context_sits_in_the_corner_of_the_title_row_and_inside_the_window() {
        // The row is placed by subtracting a measured width from the right
        // edge, so the measurement has two ways to be wrong and both are
        // visible: too small puts the path off the side of the window, too
        // large sends the whole thing to a row of its own for no reason.
        let mut app = a_window_showing("ls");
        let shapes = window_shapes(&mut app, opening_size());
        let drawn = text_rects(&shapes);
        let find = |want: &str| {
            drawn
                .iter()
                .find(|(text, _)| text == want)
                .unwrap_or_else(|| panic!("{want} is not on screen"))
                .1
        };

        // The title is laid out as one run with hatch's attribution leading
        // it — see `panes::draw_headline` — so this is the whole first line.
        let title = find(&format!("{} delete the build directory", panes::ATTRIBUTION));
        let runs = find("Runs as");
        let cwd = find("/tmp");
        assert!(
            cwd.right() <= WINDOW_SIZE[0],
            "the working directory runs {} points off the right of the window",
            cwd.right() - WINDOW_SIZE[0]
        );
        assert!(title.right() < runs.left(), "the title and the run context overlap");
        assert!(
            (title.center().y - cwd.center().y).abs() < title.height(),
            "the run context took a row of its own on a window with room for it"
        );
    }

    #[test]
    fn the_stream_box_sits_beside_the_field_and_stays_inside_the_window() {
        // The checkbox is the flank drawn rightwards from the note field, so
        // it is the one a short measurement pushes off the side of the
        // window. egui lays out its own checkbox; what is asserted here is
        // where the thing actually landed.
        let mut app = a_window_showing("sleep 1");
        let shapes = window_shapes(&mut app, opening_size());
        let drawn = text_rects(&shapes);
        let find = |want: &str| {
            drawn
                .iter()
                .find(|(text, _)| text == want)
                .unwrap_or_else(|| panic!("{want} is not on screen"))
                .1
        };

        let note = find("Note to the agent");
        let stream = find("Stream output to this window");
        assert!(
            stream.right() <= WINDOW_SIZE[0],
            "the stream box runs {} points off the right of the window",
            stream.right() - WINDOW_SIZE[0]
        );
        assert!(note.right() < stream.left(), "the label and the checkbox overlap");
        assert!(
            (note.center().y - stream.center().y).abs() < note.height(),
            "the label and the checkbox are not on one row after all"
        );
    }

    /// Every button face egui drew, as rectangles.
    ///
    /// Found by fill, because that is what a button *is* on screen: the
    /// question these ask is about the distance between two things a pointer
    /// can land on, and a pointer lands on a rectangle.
    fn button_rects(shapes: &[egui::epaint::ClippedShape]) -> Vec<egui::Rect> {
        fn walk(shape: &egui::epaint::Shape, fill: egui::Color32, out: &mut Vec<egui::Rect>) {
            match shape {
                egui::epaint::Shape::Rect(rect) if rect.fill == fill => out.push(rect.rect),
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        walk(shape, fill, out);
                    }
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        for clipped in shapes {
            walk(&clipped.shape, theme::DARK.button, &mut out);
        }
        out
    }

    /// The verdict row's buttons at a given window width: the two that decide
    /// and, if they are sharing the row, the escape hatches.
    ///
    /// Everything left of Approve is left out, and that is not a convenience.
    /// The other half of this row is the close control, whose box egui draws
    /// with the fill a button has, so it arrives here looking like one — and
    /// the distance *it* keeps is a claim of its own, made by
    /// `the_close_control_keeps_the_whole_gap_from_approve`. A hatch has never
    /// been drawn on that side and could not be: they are laid out from the
    /// window's right edge inwards.
    fn verdict_row(app: &mut PromptApp, width: f32) -> (Vec<egui::Rect>, Vec<egui::Rect>) {
        let shapes = window_shapes(app, egui::vec2(width, 700.0));
        let mut buttons = button_rects(&shapes);
        buttons.sort_by(|a, b| a.left().total_cmp(&b.left()));
        // The two verdicts are the tall ones; nothing else in this window is
        // `PRIMARY_BUTTON_ROWS` high.
        let tallest = buttons.iter().map(|r| r.height()).fold(0.0_f32, f32::max);
        let (primary, rest): (Vec<egui::Rect>, Vec<egui::Rect>) =
            buttons.into_iter().partition(|r| r.height() >= tallest - 0.5);
        let row = primary.first().map_or(0.0, |r| r.center().y);
        let approve = primary.first().map_or(0.0, |r| r.left());
        // On the same row means level with the verdicts, not merely near
        // them: the fallback draws its row directly underneath.
        let sharing = rest
            .into_iter()
            .filter(|r| (r.center().y - row).abs() < 0.5 * tallest && r.left() >= approve)
            .collect();
        (primary, sharing)
    }

    #[test]
    fn the_decide_countdown_belongs_to_the_decision_and_stops_with_it() {
        // The deadline bounds how long someone has to answer the question. An
        // approved command is not that question any more: it runs under
        // `exec_timeout_secs`, a clock this number is not counting down to. A
        // countdown left running beside it is a wrong number in the one part
        // of the window whose whole job is to be a right one.
        let mut app = a_window_showing("sleep 30");
        assert!(
            window_text_sized(&mut app, opening_size()).contains("left to decide"),
            "there is a decision open, so the clock on it is missing"
        );

        app.state.decide(Verdict::Approve {
            stream: false,
            note: String::new(),
            terminal: false,
            closing: false,
        });
        let running = window_text_sized(&mut app, opening_size());
        assert!(
            !running.contains("left to decide"),
            "the approval beat the clock and it kept counting: {running}"
        );
        assert!(
            running.contains("running"),
            "the row that replaces it says nothing about the command: {running}"
        );
    }

    #[test]
    fn every_escape_hatch_is_on_screen_in_both_arrangements() {
        // The small buttons are one list drawn two ways, and the measurement
        // that chooses between the two is taken over that same list. So a
        // label added to it has to turn up beside the verdicts on a window
        // with room and in the row of their own on one without — a button
        // that only the wide arrangement had space for is a button some
        // readers do not have.
        for size in [opening_size(), egui::vec2(520.0, 700.0)] {
            let mut app = a_window_showing("rm -rf /var/tmp/build");
            let drawn = window_text_sized(&mut app, size);
            for hatch in Hatch::ALL {
                assert!(
                    drawn.contains(hatch.label()),
                    "{hatch:?} is not on a {size:?} window: {drawn}"
                );
            }
        }
    }

    #[test]
    fn each_escape_hatch_sends_a_verdict_of_its_own_and_hands_over_the_note() {
        // Four buttons, four answers. Two that sent the same verdict would be
        // one answer drawn twice, and one that dropped the note would be a
        // field the window asked the reader to fill in for nothing.
        let mut sent = Vec::new();
        for hatch in Hatch::ALL {
            let verdict = hatch.verdict("say more about the second one");
            let note = match &verdict {
                Verdict::Deny { note }
                | Verdict::Revise { note, .. }
                | Verdict::SelfRun { note }
                | Verdict::StopAndSync { note } => note.as_str(),
                Verdict::Approve { .. } => panic!("{hatch:?} approves something"),
            };
            assert_eq!(note, "say more about the second one", "{hatch:?} dropped the note");
            sent.push(verdict);
        }
        sent.dedup();
        assert_eq!(sent.len(), Hatch::ALL.len(), "two hatches send the same verdict: {sent:?}");
    }

    #[test]
    fn a_slipped_pointer_still_has_the_whole_gap_to_cross_before_it_finds_a_hatch() {
        // The escape hatches moved onto the verdict row. The distance that
        // makes a misclick harmless is not decoration and did not move with
        // them, so it is asserted at *every* width where they share the row —
        // including the narrowest one, which is the only width where the
        // arithmetic that reserves the gap can be caught getting it wrong.
        let mut app = a_window_showing("rm -rf /var/tmp/build");
        let mut ever_shared = false;
        let mut ever_alone = false;
        let mut width = 700.0;
        while width <= 1400.0 {
            let (primary, sharing) = verdict_row(&mut app, width);
            assert_eq!(primary.len(), 2, "at {width} points the two verdicts were not drawn");
            let deny = primary[1];
            match sharing.is_empty() {
                true => ever_alone = true,
                false => {
                    ever_shared = true;
                    let nearest =
                        sharing.iter().map(|r| r.left()).fold(f32::INFINITY, f32::min);
                    assert!(
                        nearest - deny.right() >= PRIMARY_GAP,
                        "at {width} points a hatch is {} from Deny",
                        nearest - deny.right()
                    );
                }
            }
            width += 10.0;
        }
        assert!(ever_shared, "the hatches never shared the row at any width");
        assert!(ever_alone, "the hatches shared the row even where they cannot fit");
    }

    #[test]
    fn the_close_control_keeps_the_whole_gap_from_approve() {
        // The mirror of the claim above, on the other side of the same row.
        // The close control is a checkbox and not a verdict, but it sits where
        // a pointer travelling to Approve passes, so the distance that makes a
        // misclick harmless is the same distance — and it is asserted at every
        // width where the two share a row rather than at the one this window
        // opens at.
        let mut app = a_window_showing("rm -rf /var/tmp/build");
        let mut ever_beside = false;
        let mut ever_above = false;
        let mut width = 700.0;
        while width <= 1400.0 {
            let shapes = window_shapes(&mut app, egui::vec2(width, 700.0));
            let close = text_rects(&shapes)
                .into_iter()
                .find(|(text, _)| text == CLOSE_LABEL)
                .map(|(_, rect)| rect)
                .unwrap_or_else(|| panic!("at {width} points the close control is not drawn"));
            let mut buttons = button_rects(&shapes);
            buttons.sort_by(|a, b| a.left().total_cmp(&b.left()));
            let tallest = buttons.iter().map(|r| r.height()).fold(0.0_f32, f32::max);
            let approve = *buttons
                .iter()
                .find(|r| r.height() >= tallest - 0.5)
                .unwrap_or_else(|| panic!("at {width} points Approve is not drawn"));

            match (close.center().y - approve.center().y).abs() < 0.5 * approve.height() {
                true => {
                    ever_beside = true;
                    assert!(
                        approve.left() - close.right() >= PRIMARY_GAP,
                        "at {width} points the close control is {} from Approve",
                        approve.left() - close.right()
                    );
                }
                // Above the buttons rather than squeezed beside them. The
                // sentence under the box is never dropped for width, so the
                // row gets taller instead.
                false => {
                    ever_above = true;
                    assert!(
                        close.bottom() <= approve.top(),
                        "at {width} points the close control is neither beside nor above Approve"
                    );
                }
            }
            width += 10.0;
        }
        assert!(ever_beside, "the close control never shared the row at any width");
        assert!(ever_above, "the close control fitted beside Approve even at 700 points");
    }

    /// How tall the note row comes out at a given window width.
    fn note_row_height(app: &mut PromptApp, width: f32) -> f32 {
        let ctx = egui::Context::default();
        apply_font_size(&ctx, 16.0);
        let mut height = None;
        let mut out = ctx.run_ui(raw_sized(Vec::new(), egui::vec2(width, 700.0)), |ui| {
            egui::Panel::bottom("t").show(ui, |ui| {
                let cluster = cluster_width(ui);
                app.note_row(ui, cluster, true, !app.state.shown().unwrap().interactive());
                height = Some(ui.min_rect().height());
            });
        });
        out.textures_delta.clear();
        height.expect("the row drew")
    }

    #[test]
    fn a_checkbox_with_more_to_say_takes_a_row_rather_than_the_note_fields_place() {
        // The stream box carries a second sentence when it is dead — why it
        // cannot be ticked — and that sentence is part of what has to fit
        // beside the field. A window wide enough for the box alone is not
        // wide enough for both, and the answer is a taller row, never a
        // narrower field: the field is centred on the two buttons below it.
        let ordinary = note_row_height(&mut a_window_showing("sleep 1"), 900.0);
        let interactive =
            note_row_height(&mut an_interactive_window_showing("vim /etc/hosts"), 900.0);

        assert!(
            interactive > ordinary,
            "the dead checkbox's explanation was not measured: {interactive} against {ordinary}"
        );
        // And at the size the window opens at, the ordinary one is one row.
        let wide = note_row_height(&mut a_window_showing("sleep 1"), WINDOW_SIZE[0]);
        assert!(wide <= ordinary, "a wider window gave the note row more height, not less");
    }

}

