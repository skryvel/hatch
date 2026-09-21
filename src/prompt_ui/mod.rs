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
//! There are three things this window can do once it has been answered, and
//! which one it does is settled before the answer leaves:
//!
//! * **Go.** The reader ticked "Close when I decide" — see [`CLOSE_LABEL`] —
//!   so the approval joins the five verdicts that always ended the window on
//!   the frame that carried them. The command is authorised and runs on with
//!   nothing watching it, which is a state an approved command could always
//!   reach; the difference is that the frame just sent says the window meant
//!   to. Nothing downstream may guess at that, because a deliberate close and
//!   a crash are indistinguishable from the daemon's side and are different
//!   facts in the audit log: see [`crate::audit::PromptEnd`].
//! * **Stay and show the result.** The reader ticked the stream box, so the
//!   window lingers; the rest of this section is about that.
//! * **Stay until the outcome.** Neither box, so the window is a running
//!   indicator — with a Kill button, for a command — and on
//!   [`DaemonMsg::Finished`] it closes, unless the ending is news.
//!
//! Beside all three, a reader can tick "Show me the output before it is sent"
//! — see [`REVIEW_LABEL`] — and then the command's ending is a second
//! question rather than any of these: the window stays, whatever the ending,
//! and asks what of the output the agent may have. [`Phase::Reviewing`] is
//! that question and [`reviewing`] is the screen that asks it. It beats "Close
//! when I decide" for the reason that box's greyed sentence gives, and unlike
//! the lingering below it is not the window's own: the daemon holds that
//! deadline, as it holds the approval's.
//!
//! A window whose reader ticked "Stream output to this window" does not close
//! on [`DaemonMsg::Finished`]. The whole life of an ordinary command is
//! milliseconds, so closing there took the output away at the instant it
//! arrived — the box working exactly as built and being useless. Instead the
//! window *lingers* for [`LINGER`], showing the result with a countdown on it,
//! and a button turns it into a *detached viewer*: no countdown, no verdict,
//! just the output, a way to copy it and a way to close it.
//!
//! A window nobody asked to watch lingers the same way when, and only when,
//! its ending is news: something the reader could not have known from what
//! they approved, such as a write refused because the file moved or a run
//! hatch cut short. Otherwise it closes on the frame, at once. The one thing
//! it never does is show the result for a moment and go, which is too short
//! to read and long enough to catch the eye. [`Outcome::is_news`] is the rule
//! and says why a command's non-zero exit is not on it; the daemon reads the
//! same rule and lets go of a window that is staying, so it is not killed
//! half way through. A closing window goes on drawing what it was until it is
//! gone — see [`PromptState::drawn_phase`] — so that "at once" does not end
//! on a picture of its own either.
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
//! # Above the other windows, and then not
//!
//! The window opens on top of everything around it, because an agent is
//! stopped on the answer and a question three windows down is a question
//! nobody sees. That standing belongs to the asking and not to the window:
//! once the command is approved and running there is nothing left to answer,
//! and a window that still floated over every other one would be a progress
//! indicator that cannot be put away. A reader who approved a long run and
//! went back to work should be able to alt-tab past it like anything else.
//!
//! So the level follows the phase — [`standing`] is the rule, and
//! [`PromptState::take_standing`] is how the window is told — and a run, a
//! linger and a detached viewer are ordinary windows: raise them, lower them,
//! leave them behind. [`Phase::Reviewing`] takes the standing back, because it
//! is a second question with a deadline on it rather than part of the
//! watching, and output nobody answers for is output the agent never gets.
//!
//! That split is not a third opinion about the phases: it is the one
//! [`mood`] draws and [`PromptApp::keyboard`] types on, a window is either
//! asking something or watching something, and
//! `the_ground_the_keys_and_the_standing_read_the_same_split` holds the two
//! that are reachable without a display to it.
//!
//! On Wayland none of this does anything, there as here: a client may not
//! place itself, and the answer is a compositor rule matching [`APP_ID`].
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
pub mod reviewing;
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
use crate::prefs::PrefsFile;
use crate::prompt_ui::guard::{Action, Guard, Keyboard, intercept};
use crate::prompt_ui::panes::{Shown, Urgency, countdown_text, urgency};
use crate::protocol::{
    self, DaemonMsg, Outcome, PromptMsg, Release, Request, Review, ReviseKind, Unanswered, Verdict,
};

/// The window's application id.
///
/// Wayland has no way for a client to raise itself, so placement is the
/// compositor's job and this string is how a rule names the window. It is
/// also the name eframe reports to the desktop.
const APP_ID: &str = "hatch-prompt";

/// What an approval window is called before it knows which one it is.
///
/// Every window is built with this, because the viewport exists before the
/// request does -- the reader opens a window and then it is told what to ask.
/// A numbered one renames itself the moment the request lands; see
/// [`numbered_title`] and [`PromptState::take_title`].
pub(crate) const WINDOW_TITLE: &str = "hatch — approval";

/// What window `number` is called.
///
/// The number is in the title because the title bar is the only place a
/// window is named where a person is looking at something other than the
/// window: alt-tab, a task switcher, a dock. Two approval windows are the
/// same object there, and a reader who answered one while the next opened in
/// the same instant has no way to tell that the second is a second. It costs
/// no row inside the window, which is the other half of why it is here and
/// not on a line of its own.
pub(crate) fn numbered_title(number: u64) -> String {
    format!("{WINDOW_TITLE} #{number}")
}

/// The size the window opens at.
///
/// Wide enough for the side-by-side diff to be the view a file write
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
/// It also applies to a window nobody asked to watch whose ending is news —
/// see [`Outcome::is_news`] — for the same two reasons: long enough to read
/// what went wrong and reach the button that keeps it, short enough not to
/// collect. Every other window closes on the outcome, at once.
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
///
/// The height is a floor rather than the answer: [`primary_button`] takes
/// whichever is larger of this and what the shortcut label actually needs, so
/// a chord added to [`guard::APPROVE_CHORD`] cannot leave the two buttons
/// different sizes. The pair being the same size is the point — Approve is
/// the one that runs something, and the larger of two buttons is an
/// invitation dressed as an affordance.
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

/// The label on the control that shows the output as it arrives.
const STREAM_LABEL: &str = "Stream output to this window";

/// Why that control is dead when it is.
///
/// A terminal is a stream of its own and the reader is about to be looking at
/// it, so there is nothing for this window to show that they will not already
/// have. Also what [`REFUSAL_NOTICE`] points at when the chord asks for a
/// stream there is no room for.
const STREAM_DEAD: &str = "It runs in a terminal of its own.";

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

/// The label on the control that holds the output back for the reader.
///
/// Said as what it does for the person ticking it, in the words they would
/// use for it, rather than as a mode: the question it answers is "will I see
/// this before the agent does?".
const REVIEW_LABEL: &str = "Show me the output before it is sent";

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

/// The same greyed box, when nobody chose it in front of this command.
///
/// Stream is remembered now, so "you asked to watch this one" is a sentence
/// that can be false: a reader who ticked Stream last week and Close the week
/// before opens every window from now on with the close box greyed out and a
/// window telling them they asked for something about a command they have not
/// read yet. That is the state that reads like a fault, and it is not one —
/// it is two standing preferences that contradict each other, with the same
/// tie-break as before.
///
/// So the tie-break is unchanged and only the sentence moves. Streaming still
/// wins, because a window that has gone shows nothing and the live view is
/// the more specific of the two requests; what changes is that the window now
/// says *why* it is grey in words that are true — a standing choice, named as
/// one — and the way out is the one the reader can see from here: untick
/// Stream and the close box comes straight back, with the preference it had.
///
/// Shorter than [`CLOSE_WATCHING`] on purpose, so that [`PromptApp::close_width`]
/// is unchanged and a third sentence cannot move the two buttons that decide.
const CLOSE_WATCHING_ALWAYS: &str = "You stream every run.";

/// Why the close box is dead on a run whose output the reader asked to see
/// first.
///
/// Reviewing wins, the way streaming does and for a stronger reason: a
/// window that has gone cannot show the output, and the output then goes
/// nowhere at all rather than to the reader, so the tick would not merely lose
/// a view — it would lose the output. Only one sentence, where streaming has
/// two sentences, and it has two for the same reason they do: see
/// [`CLOSE_REVIEWING_ALWAYS`]. Measured with the others in
/// [`PromptApp::close_width`], so that ticking it cannot move the buttons.
const CLOSE_REVIEWING: &str = "You asked to see its output first.";

/// The same greyed box, when nobody chose it in front of this command.
///
/// [`CLOSE_WATCHING_ALWAYS`]'s reason, for the box beside it: reviewing is
/// remembered now, so "you asked to see its output first" is a sentence that
/// can be false about a window whose command the reader has not read yet.
/// It carries the cost as well as the choice, which its streaming
/// counterpart does not have to: a remembered stream changes what the reader
/// sees, and a remembered review puts a person back in the return path of
/// every approved run. The agent's call waits for a second answer each time.
/// That was the whole argument against remembering this box, and the answer
/// to it is that the window says so rather than that the tick is forgotten.
const CLOSE_REVIEWING_ALWAYS: &str =
    "You read every run's output first, so every run waits for you.";

/// What the running window says once the reader has kept it.
///
/// It is said where the button was, because a keypress has no click to be
/// seen and a control that simply vanished would leave the reader wondering
/// whether the key had worked. The countdown it is about never starts: see
/// [`PromptState::keep`].
const KEPT_RUNNING: &str = "Kept. It stays when this ends.";

/// What the window says while the typing guard has the buttons disabled.
///
/// Painted across the two buttons it is about rather than laid out under
/// them; [`PromptApp::verdict_area`] is where that is argued. A constant so
/// that the window which draws it and the test which reads it off a real
/// frame cannot drift apart.
const GUARD_NOTICE: &str =
    "Waiting a moment, so a keystroke meant for another window cannot answer this one…";

/// How long a refused chord is pointed at.
///
/// Alt+S on a command that is going to run in a terminal of its own has
/// nothing to tick, and a shortcut that does nothing and says nothing teaches
/// the reader that it is broken. So the window flashes the sentence it is
/// already drawing — the one that says why the box is dead — in the warning
/// colour, which answers the chord without adding a word to the window or
/// moving anything in it.
///
/// Two seconds, the same as [`COPY_NOTICE`], and for the same reason: long
/// enough for an eye to arrive, short enough not to become part of how the
/// window looks.
const REFUSAL_NOTICE: Duration = Duration::from_secs(2);

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
    let row = ui.text_style_height(&egui::TextStyle::Button);
    // Tall enough for the longest shortcut label, whatever that is now. A
    // constant would have to be re-derived by hand every time a chord is
    // added, and the way it fails is the way it failed when the third
    // approval chord was: the label outgrows the minimum, so Approve draws
    // taller than Deny, and the button that runs something becomes the
    // larger of the two. See `PRIMARY_BUTTON_ROWS`.
    let hint = text_height(ui, guard::APPROVE_CHORD, egui::TextStyle::Small)
        + 2.0 * ui.spacing().button_padding.y;
    egui::vec2(row * PRIMARY_BUTTON_ROWS.x, (row * PRIMARY_BUTTON_ROWS.y).max(hint))
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
    /// The operation has finished, and the window is holding the result up
    /// for a few seconds before taking itself away.
    ///
    /// Reachable only through [`Phase::Running`], and only for a run the
    /// reader ticked the stream box on or an ending that is news; see
    /// [`Outcome::is_news`].
    Lingering,
    /// The command has finished and its reader asked to see the output before
    /// the agent does: the window is asking what of it to send.
    ///
    /// Reachable only through [`Phase::Running`], and only on a
    /// [`DaemonMsg::Finished`] that followed a [`DaemonMsg::Review`]. It is a
    /// question, like [`Phase::AwaitingVerdict`], and the daemon holds a
    /// deadline over it the same way: nothing about it is the window's own
    /// clock. See [`PromptState::release`].
    Reviewing,
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

/// Where a window sits among the windows around it.
///
/// Egui-free, like everything else [`PromptState`] answers with: the state
/// machine says what the window should be, and the eframe app is the only
/// thing that knows the command to say it with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Above the windows around it, and not to be lost behind one. There is a
    /// question on it that something is stopped on.
    Insistent,
    /// An ordinary window. Raise it, lower it, leave it behind.
    Ordinary,
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
    shown: Vec<Shown>,
    queue_depth: u32,
    outcome: Option<Outcome>,
    output: VecDeque<(Stream, String)>,
    output_bytes: usize,
    output_dropped: bool,
    streaming: bool,
    reviewing: bool,
    review: Option<Review>,
    elevating: bool,
    was_elevated: bool,
    keeping: bool,
    linger_until: Option<Instant>,
    broken: Option<String>,
    closed_from: Phase,
    close_taken: bool,
    title_taken: bool,
    standing_sent: Standing,
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
            shown: Vec::new(),
            queue_depth: 0,
            outcome: None,
            output: VecDeque::new(),
            output_bytes: 0,
            output_dropped: false,
            streaming: false,
            reviewing: false,
            review: None,
            elevating: false,
            was_elevated: false,
            keeping: false,
            linger_until: None,
            broken: None,
            closed_from: Phase::WaitingForRequest,
            close_taken: false,
            title_taken: false,
            // What `open_window` built the viewport as. Starting anywhere
            // else would have the first frame of every window restack it to
            // where it already is.
            standing_sent: Standing::Insistent,
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

    /// The operation this window draws, as something drawable, checked when
    /// it arrived.
    ///
    /// There is never a request without one: a payload that could not be
    /// rebuilt through the real builder closed the window instead of
    /// becoming one. See [`PromptState::handle`].
    ///
    /// One, because a window draws one operation today and closes on a
    /// request for any other number of them. [`PromptState::operations`] is
    /// the list this is the only member of.
    pub fn shown(&self) -> Option<&Shown> {
        self.shown.first()
    }

    /// Every operation the request covers, drawable, in the order they run.
    ///
    /// The window's own copy of [`Request::operations`], held as a list for
    /// the reason that one is: the window that draws several is a change to
    /// how this is drawn, not to what is kept.
    pub fn operations(&self) -> &[Shown] {
        &self.shown
    }

    /// The sentence that says what happens after an operation fails, when
    /// there is an after to speak of.
    ///
    /// `None` for a request of one operation, and that is not an omission.
    /// With nothing after it there is nothing to stop and nothing to carry on
    /// to, and a line saying which of the two would not happen is a line a
    /// reader learns to skip -- which takes it down with it on the window
    /// where it matters.
    ///
    /// Worded as a fact about the sequence and not as a warning. Neither
    /// answer is the dangerous one: stopping leaves approved work undone, and
    /// carrying on runs approved work on whatever an earlier operation left.
    /// What the reader needs is to know which they are approving.
    pub fn sequencing(&self) -> Option<&'static str> {
        let request = self.request.as_ref()?;
        if request.operations.len() < 2 {
            return None;
        }
        Some(match request.stop_on_failure {
            true => "stops at the first operation that fails",
            false => "runs every operation, whichever of them fail",
        })
    }

    /// Whether what this window is showing runs, or ran, as root.
    ///
    /// Read off the payload and not off the phase, because it is not a phase:
    /// it is true from the moment the request arrives until the window goes,
    /// and every phase in between draws the mark that says so. A file write
    /// answers `false` here whatever its plan says — it states its own
    /// ownership in its own header, and a second claim about the same thing
    /// in a second vocabulary is how the two come to disagree.
    ///
    /// Asked of every operation rather than of the one drawn, so that the
    /// frame is a fact about the whole approval: one root command anywhere in
    /// a request is enough to put the window in it.
    pub fn runs_as_root(&self) -> bool {
        self.operations()
            .iter()
            .filter_map(panes::RunContext::of)
            .any(|context| context.root)
    }

    /// Windows that ended since the last one somebody answered.
    ///
    /// Read off the request rather than kept beside it: the request is
    /// already the one thing this window was opened with, and a second copy
    /// would be a second thing to keep in step with it.
    pub fn unanswered(&self) -> &[Unanswered] {
        self.request.as_ref().map_or(&[], |request| request.unanswered.as_slice())
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

    /// Whether the reader asked to see the output before the agent does.
    ///
    /// Recorded from the verdict, for the reason [`PromptState::streaming`]
    /// is.
    pub fn reviewing(&self) -> bool {
        self.reviewing
    }

    /// The output held up for review, once the daemon has sent it.
    pub fn review(&self) -> Option<&Review> {
        self.review.as_ref()
    }

    /// Seconds left before the review expires and nothing is sent, at `now`.
    ///
    /// Only while the window is asking about it, and read off the daemon's
    /// deadline for the reason [`PromptState::seconds_remaining`] is.
    pub fn review_seconds_remaining(&self, now: DateTime<Utc>) -> Option<i64> {
        if self.phase != Phase::Reviewing {
            return None;
        }
        let deadline = self.review.as_ref()?.deadline;
        Some((deadline - now).num_seconds().max(0))
    }

    /// Whether the reader has already said they want this window kept.
    ///
    /// True from the moment Keep is pressed, which can be while the command
    /// is still running. What it changes there is the ending: a run that
    /// finishes under this never starts a countdown at all. See
    /// [`PromptState::keep`].
    pub fn keeping(&self) -> bool {
        self.keeping
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

    /// The phase this window is drawn as, which is its phase — except once
    /// it is closing, when it is the phase it closed from.
    ///
    /// # Why a closing window goes on looking like what it was
    ///
    /// Closing is not the instant the state machine says so. The frame that
    /// decides to close is painted, and so is at least one more while the
    /// desktop takes the window away, and a compositor that animates a window
    /// out animates the last picture it was given. A window that drew those
    /// frames as [`Phase::Closed`] — back on the asking ground, its controls
    /// gone and the panes grown into their room — put a picture on screen at
    /// the end that had never been there before it: after a run that closed
    /// on its outcome, a flash of the question it had already answered.
    ///
    /// So the picture does not change on the way out, and the phase does:
    /// nothing drawn from this can decide, kill or keep anything, because
    /// every one of those asks [`PromptState::phase`].
    ///
    /// A window closing on its verdict is the exception in the drawing and
    /// not here. The verdict area is the one set of controls that writes
    /// preferences down, and it is not drawn a second time for a window that
    /// has answered; see [`PromptApp::controls`].
    pub fn drawn_phase(&self) -> Phase {
        match self.phase {
            Phase::Closed => self.closed_from,
            phase => phase,
        }
    }

    /// Close, remembering what the window looked like while it was open.
    ///
    /// The only way into [`Phase::Closed`], so that [`PromptState::drawn_phase`]
    /// cannot be left describing a window some other path closed.
    fn close(&mut self) {
        if self.phase != Phase::Closed {
            self.closed_from = self.phase;
        }
        self.phase = Phase::Closed;
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

    /// The name this window should be wearing, once and only once.
    ///
    /// `None` until a numbered request has arrived, and `None` for ever
    /// afterwards: the title is set from the request that named it and a
    /// window never gets a second request. The latch is here, beside
    /// [`PromptState::take_close`]'s, rather than in the eframe app, because
    /// it is a fact about what the daemon has said and not about what the
    /// event loop has drawn -- and asking the compositor to rename a window
    /// sixty times a second is sixty round trips to say the same thing.
    ///
    /// A request with no number leaves the window with the title it was
    /// opened with, which is the whole of how `hatch preview` avoids claiming
    /// to be request #1 of anything. See [`Request::number`].
    pub fn take_title(&mut self) -> Option<String> {
        if self.title_taken {
            return None;
        }
        let number = self.request.as_ref()?.number?;
        self.title_taken = true;
        Some(numbered_title(number))
    }

    /// The standing this window should have, at each moment that changes.
    ///
    /// `None` while the window already is what it should be, which on the
    /// ordinary path is its whole life up to the verdict: the viewport is
    /// built [`Standing::Insistent`] — see [`open_window`] — so the first
    /// thing this ever returns is the window letting go of the screen.
    ///
    /// Unlike [`PromptState::take_title`] this is not once and for all, and
    /// so what is latched is the last standing handed out rather than the
    /// fact of having handed one out: a reviewed run asks a second question,
    /// and asking takes the screen back. What the latch is against is sixty
    /// restack requests a second saying the same thing, not a second change.
    ///
    /// Read from [`PromptState::drawn_phase`], so a window on its way out
    /// keeps the standing it had. The last frames of a window belong to what
    /// it was, and restacking one that is already leaving is a flicker at the
    /// end for nobody's benefit.
    pub fn take_standing(&mut self) -> Option<Standing> {
        let wanted = standing(self.drawn_phase());
        if wanted == self.standing_sent {
            return None;
        }
        self.standing_sent = wanted;
        Some(wanted)
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
                //
                // And it is one operation. A window that drew the first of
                // three would be asking for an approval that covers two
                // operations nobody was shown, so a request for any other
                // number closes the window for the same reason a bad
                // rendering does. The daemon does not send one today; this is
                // what makes sending one fail towards a denial rather than
                // towards a yes.
                let [operation] = req.operations.as_slice() else {
                    self.channel_broken(format!(
                        "hatch sent a request of {} operations, and this window draws exactly one",
                        req.operations.len()
                    ));
                    return;
                };
                let shown = match Shown::of(operation) {
                    Ok(shown) => shown,
                    Err(e) => {
                        self.channel_broken(format!(
                            "hatch sent a request this window cannot draw: {e}"
                        ));
                        return;
                    }
                };
                self.queue_depth = req.queue_depth;
                self.request = Some(*req);
                self.shown = vec![shown];
                self.phase = Phase::AwaitingVerdict;
            }
            DaemonMsg::QueueDepth { depth } => self.queue_depth = depth,
            DaemonMsg::Elevating => {
                self.elevating = true;
                self.was_elevated = true;
            }
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
            DaemonMsg::Review(review) => {
                // Only for a window that asked, only while its command is
                // what it is showing, and only once. Anything else is a
                // daemon describing some other window, and a question about
                // output this window's reader never asked to see is not one
                // to put in front of them.
                if !(self.phase == Phase::Running && self.reviewing && self.review.is_none()) {
                    self.channel_broken(
                        "hatch sent output to review to a window that did not ask to review it",
                    );
                    return;
                }
                self.elevating = false;
                self.review = Some(review);
            }
            DaemonMsg::Finished(outcome) if self.review.is_some() => {
                // A question, not a result: nothing reaches the agent until
                // the reader answers it, so the window stays whatever the
                // ending and whatever was pressed while it ran. See
                // `Outcome::stays`.
                debug_assert!(outcome.stays(self.streaming, true));
                self.outcome = Some(outcome);
                self.elevating = false;
                self.phase = Phase::Reviewing;
            }
            DaemonMsg::Finished(outcome) => {
                // Two reasons to stay, and without either the window goes on
                // this frame, at once.
                //
                // The reader ticked a box that says "I want to watch this".
                // For anything but a slow command the whole run is over in
                // milliseconds, so a window that closed on this frame closed
                // at the moment the output arrived — the box working exactly
                // as built and being useless.
                //
                // Or the ending is news: something the reader could not have
                // known from what they approved. A write refused because the
                // file moved, a run hatch cut short, a command that never
                // started. See `Outcome::is_news` for the whole rule and why
                // a non-zero exit is not on it. The daemon reads the same rule
                // off the same frame and lets go of a window that is staying,
                // so a window never stays only to be killed half way through.
                let stays = outcome.stays(self.streaming, false);
                self.outcome = Some(outcome);
                self.elevating = false;
                // Three endings, and which one this is was settled before
                // the operation stopped. A reader who pressed Keep during the
                // run has already said what they want to happen now, so the
                // countdown is not started and then immediately stopped --
                // this window goes straight to being theirs.
                match (stays, self.keeping) {
                    (true, true) => self.phase = Phase::Detached,
                    (true, false) => {
                        self.linger_until = Some(Instant::now() + LINGER);
                        self.phase = Phase::Lingering;
                    }
                    (false, _) => self.close(),
                }
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
        self.close();
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
            self.close();
        }
    }

    /// Seconds until a lingering window takes itself away, at `now`.
    ///
    /// `None` in every other phase, which is what tells the drawing half that
    /// there is no countdown to say out loud. Rounded up, so the number the
    /// reader sees is the number of seconds they still have: it reads 1 for
    /// the whole of the last second and reaches 0 as the window goes.
    ///
    /// Asked of the phase the window is drawn as, so that the frames painted
    /// while a lingering window goes away say "closing now" rather than
    /// losing the countdown and reading as a kept window.
    pub fn linger_seconds_remaining(&self, now: Instant) -> Option<u64> {
        let until = self.linger_until.filter(|_| self.drawn_phase() == Phase::Lingering)?;
        let left = until.saturating_duration_since(now);
        Some(left.as_secs() + u64::from(left.subsec_nanos() > 0))
    }

    /// Keep the window: no countdown, now or later.
    ///
    /// Returns whether it did anything, which is how the drawing half knows
    /// not to arm anything twice. The phase it leads to has no way back to a
    /// question: [`PromptState::decide`] answers in [`Phase::AwaitingVerdict`]
    /// alone, and no phase returns there.
    ///
    /// # Two phases, one meaning
    ///
    /// From [`Phase::Lingering`] it stops the countdown that is already
    /// running. From [`Phase::Running`] there is no countdown yet, and what
    /// it does is decide that there will not be one: the reader has said *I
    /// already know I want a look at the end*, which is exactly the case
    /// where they have gone to do something else and will not be at the
    /// keyboard for the ten seconds after the command stops. The window then
    /// goes from running straight to being theirs. It is the same action
    /// offered one phase earlier and not a second setting; nothing about it
    /// is written down, and it says nothing about the next window.
    ///
    /// # Why it does not toggle
    ///
    /// It is a latch in both phases, and that is the answer to "a reader has
    /// a whole run to change their mind". The alternative is a key that means
    /// *keep* the first time and *stop keeping* the second, which is two
    /// meanings for one key decided by a count nobody is keeping -- and to be
    /// one action in both phases it would have to un-keep in the viewer too,
    /// where the countdown it would be handing the window back to has been
    /// gone for some time and cannot honestly be restarted. What a reader who
    /// changes their mind actually wants is the window gone, and that is
    /// Close, which is on the window from the moment the command ends and is
    /// a key of its own.
    ///
    /// # Early, only for a run that is being watched
    ///
    /// Keeping from [`Phase::Running`] is refused for a run nobody asked to
    /// stream. Nothing about it is known to be worth keeping yet: no output
    /// is being sent to this window, and whether its ending will be news is
    /// not known until it ends. The drawing half does not offer the control
    /// there, and this refuses it in any case. A window that lingers because
    /// its ending was news can be kept like any other, since what it is kept
    /// for — the ending — is on it by then.
    pub fn keep(&mut self) -> bool {
        match self.phase {
            Phase::Lingering => {
                self.phase = Phase::Detached;
                self.linger_until = None;
                self.keeping = true;
                true
            }
            // Not for a run under review. Its window does not end in a
            // viewer: it ends in a question, and once that is answered it
            // goes, so a keep pressed now would be a promise about an ending
            // this window is not going to have.
            Phase::Running if self.streaming && !self.reviewing && !self.keeping => {
                self.keeping = true;
                true
            }
            _ => false,
        }
    }

    /// End the window because the reader asked to, or because the desktop did.
    ///
    /// Deliberately not a failure and deliberately without a reason: a window
    /// somebody closed has nothing to report to the operator. Before a verdict
    /// the daemon reads the dead process as a denial, which is what a window
    /// closed from its title bar already meant.
    pub fn dismiss(&mut self) {
        self.close();
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
        if let Verdict::Approve { stream, review, .. } = verdict {
            self.streaming = stream;
            self.reviewing = review;
        }
        match verdict {
            // The reader ticked "Close when I decide", so an approval joins
            // the five verdicts that were always over on the frame that
            // carried them. The command is authorised and runs on with no
            // window, which is a state an approved command could always reach
            // — the difference is that this time somebody asked for it, and
            // the frame just written is where they said so.
            Verdict::Approve { closing: true, .. } => self.close(),
            Verdict::Approve { .. } => self.phase = Phase::Running,
            Verdict::Deny { .. }
            | Verdict::Revise { .. }
            | Verdict::SelfRun { .. }
            | Verdict::StopAndSync { .. } => self.close(),
        }
        Some(PromptMsg::Verdict(verdict))
    }

    /// Record the reader's answer to the review, and hand back the one frame
    /// to send.
    ///
    /// The review's counterpart to [`PromptState::decide`], with the same
    /// guarantee: an answer is produced only while the window is asking for
    /// one, and producing it is what stops the asking. The window goes on the
    /// frame that carries it — the reader has just seen everything there was
    /// to see, and a window that lingered afterwards would only be showing it
    /// again.
    pub fn release(&mut self, release: Release) -> Option<PromptMsg> {
        if self.phase != Phase::Reviewing {
            return None;
        }
        self.close();
        Some(PromptMsg::Release(release))
    }

    /// The Kill frame, if there is something running to kill.
    ///
    /// Kill can stop a command and can never start one, so the only reason to
    /// withhold it is honesty: a button that did nothing would be a window
    /// claiming a power over a command that has not been approved.
    ///
    /// Withheld from a write for the same reason. The window draws no Kill
    /// button for one — see [`Shown::runs`] — and this is the state machine
    /// agreeing, so a Kill frame cannot leave a write window by some path the
    /// drawing did not think of.
    pub fn request_kill(&self) -> Option<PromptMsg> {
        (self.phase == Phase::Running && self.shown().is_some_and(Shown::runs))
            .then_some(PromptMsg::Kill)
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

    /// Whether hatch ever waited on a password dialog for this window.
    ///
    /// Unlike [`PromptState::elevating`], never cleared. The one thing that
    /// reads it is the sentence a closing window replaces the waiting one
    /// with, which has to take up the lines the waiting one did.
    pub fn was_elevated(&self) -> bool {
        self.was_elevated
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
    let mut reviewing = false;
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
        // The outcome after a review is not the daemon's last word: the
        // window is about to ask a question, the daemon is waiting for the
        // answer and holds the deadline over it, so nothing about the window's
        // own clock starts here.
        reviewing |= matches!(item, Incoming::Frame(DaemonMsg::Review(_)));
        let noticed = Noticed {
            final_frame: matches!(item, Incoming::Frame(DaemonMsg::Finished(_))) && !reviewing,
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
            //
            // Where every window starts and not where it stays: this is the
            // standing of a window that is asking, and `standing` is what
            // hands it back once the window is only watching a command it
            // was given permission to run.
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
        WINDOW_TITLE,
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
    /// The Stream output checkbox, as the reader last left it.
    ///
    /// A display preference and nothing else, and — like
    /// [`PromptApp::close_on_decide`] — the *stored* answer rather than the
    /// effective one. A terminal run has no second stream to show, so the box
    /// is drawn unticked for one; storing that would turn "this command wants
    /// a terminal" into "the reader stopped wanting output", which would
    /// outlive the command that caused it. [`PromptApp::streams`] is the only
    /// thing that should be asked what this window will actually do.
    stream: bool,
    /// Whether the command area shows the exact text instead of the
    /// annotated rendering. Remembered; see [`crate::prefs::Prefs`].
    show_original: bool,
    /// Whether the tick above came out of the file rather than out of this
    /// window.
    ///
    /// Only the sentence under the close box reads it, and only to tell two
    /// true things apart: "you asked to watch this one", which is about the
    /// command on the screen, and [`CLOSE_WATCHING_ALWAYS`], which is about a
    /// standing choice made some other day. Cleared the moment the reader
    /// touches the box either way, because from then on they have asked about
    /// this one.
    stream_is_remembered: bool,
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
    ///
    /// Remembered between windows like the other two, and unlike the other
    /// two that is a standing decision about execution rather than about the
    /// view. [`crate::prefs::Prefs`] is where the difference is set out.
    terminal: bool,
    /// The Show me the output before it is sent checkbox.
    ///
    /// # Why this one is remembered, having once not been
    ///
    /// Remembered, like the other three, and this was argued the other way
    /// for a long time: whether *this* command's output might carry
    /// something that must not leave the machine is a judgement about this
    /// command, read on the screen -- `cat` on a file with a key in it, and
    /// not `ls` on the directory it is in.
    ///
    /// What settled it was use. A person who wants to read what goes back
    /// wants to read it, and a tick they have to make again on every window
    /// is the friction that ends in nobody reading anything.
    ///
    /// **Reviewing puts a person back in the return path**, and a remembered
    /// tick does that to every run: each one waits for a second answer
    /// before the agent hears anything, so each call blocks for as long as
    /// the reader takes to come back to it. That cost is real and is the
    /// reason this is drawn as loudly as it is -- see
    /// [`REVIEW_EVERY_RUN`], which is what the window says about a tick it
    /// did not get in front of this command.
    ///
    /// It cannot let anything out. See [`crate::prefs::Prefs::review`], and
    /// [`CLOSE_REVIEWING_ALWAYS`] for what the window says about a tick it
    /// did not get in front of this command.
    review: bool,
    /// Whether the tick above came out of the file rather than out of this
    /// window, on the same terms as [`PromptApp::stream_is_remembered`].
    review_is_remembered: bool,
    /// What the reader has done to the output under review, once there is
    /// one. See [`reviewing::Draft`].
    draft: reviewing::Draft,
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
    /// A screenful of paging asked for by the keyboard and not yet drawn.
    ///
    /// Set where the key is judged and spent where the output is drawn,
    /// because only the drawing knows how tall a screenful is: the panes are
    /// laid out by the window's height and the reader's font, neither of
    /// which the guard is told about.
    paging: Option<guard::Page>,
    /// The last chord this window could not carry out, and when.
    ///
    /// Read only by the control that was asked for, which flashes the reason
    /// it is dead. See [`REFUSAL_NOTICE`].
    refused: Option<(guard::Toggle, Instant)>,
    fatal: Arc<OnceLock<String>>,
}

impl PromptApp {
    pub(crate) fn new(
        inbox: Receiver<Incoming>,
        out: Box<dyn Write + Send>,
        fatal: Arc<OnceLock<String>>,
        prefs: PrefsFile,
    ) -> PromptApp {
        // Everything this window starts with that another window decided.
        // Read once, here, and not per frame: a file changing under an open
        // window would move a control somebody is looking at.
        //
        // All three default to false when there is no file, which is what
        // makes a first run and an unreadable file the same window: headless,
        // staying, and with no terminal that nobody asked for.
        let remembered = prefs.read();
        PromptApp {
            state: PromptState::new(),
            inbox,
            out,
            stream: remembered.stream,
            show_original: remembered.show_original,
            stream_is_remembered: remembered.stream,
            review_is_remembered: remembered.review,
            close_on_decide: remembered.close_on_decide,
            prefs,
            terminal: remembered.terminal,
            review: remembered.review,
            draft: reviewing::Draft::default(),
            note: String::new(),
            guard: Guard::new(Instant::now()),
            guard_open: false,
            kept: Arc::new(AtomicBool::new(false)),
            copied: None,
            paging: None,
            refused: None,
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
    ///
    /// It is also where the typing guard is told a second question has
    /// appeared, because this is where a window learns it has one: the review
    /// arrives on the channel, not from anything the reader did. See
    /// [`Guard::question_changed`].
    pub(crate) fn take_arrivals(&mut self) {
        let was_reviewing = self.state.phase() == Phase::Reviewing;
        drain(&mut self.state, &self.inbox);
        if !was_reviewing && self.state.phase() == Phase::Reviewing {
            self.guard.question_changed(Instant::now());
        }
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

    /// Whether this window is going to show the output as it arrives.
    ///
    /// The reader's stored answer, minus the one thing that makes it
    /// impossible. Streaming and a terminal are exclusive and it is not a rule
    /// this window enforces so much as a fact it reports: the terminal *is*
    /// the stream. Computed rather than written back into
    /// [`PromptApp::stream`], for the reason that field gives — a remembered
    /// "show me the output" must survive one command that happens to want a
    /// terminal.
    ///
    /// And minus a payload that has no output at all. A write prints nothing,
    /// and a remembered tick used to reach its approval anyway: the window
    /// recorded a watched run, went on to linger over a result nobody had
    /// asked to see, and was killed by the daemon half a second into it --
    /// which is a flash, and an empty viewer saying "it printed nothing"
    /// about a file.
    fn streams(&self) -> bool {
        self.stream
            && !self.in_a_terminal()
            && self.state.shown().is_some_and(Shown::streamable)
    }

    /// The approval this window would send, however it was asked for.
    ///
    /// One function rather than one expression per button, because there are
    /// two ways to approve — the button and the chord — and an approval that
    /// carried the terminal from one of them and not the other would be a
    /// window whose keyboard and mouse ran different commands.
    fn approval(&self) -> Verdict {
        Verdict::Approve {
            stream: self.streams(),
            terminal: self.in_a_terminal(),
            closing: self.closes_on_decide(),
            review: self.reviews(),
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
    /// useful there. [`PromptApp::streams`] is already false whenever there is
    /// a terminal, so a terminal run reads as true here without having to say
    /// so twice.
    ///
    /// # Not on a write
    ///
    /// A write window does not draw the box, and so it does not act on the
    /// preference either: a standing tick no control on the screen admits to
    /// would be the window doing something nobody in front of it chose. Not
    /// drawing it is also the right answer on its merits rather than only
    /// the consistent one. The box trades what a window would have shown
    /// after the verdict for getting it out of the way, and a write window
    /// already goes the instant there is nothing to show — see "After the
    /// command" — so the only thing a tick could still do there is take away
    /// the report of a write that went wrong. A preference set for commands
    /// must not do that to a file.
    ///
    /// The stored answer is untouched, so the next command window opens with
    /// the box as the reader left it. See [`PromptApp::runs`].
    ///
    /// # Not on a run whose output the reader will review
    ///
    /// For [`CLOSE_REVIEWING`]'s reason, which is stronger than streaming's: a
    /// window that has gone cannot ask, and a review nobody can answer sends
    /// nothing, so the tick would cost the agent the whole output.
    fn closes_on_decide(&self) -> bool {
        self.close_on_decide && !self.streams() && !self.reviews() && self.runs()
    }

    /// Whether approving this window will hold the output back until its
    /// reader has seen it.
    ///
    /// The box, on a payload that has output at all. A write prints nothing,
    /// and the box is not drawn on a write window any more than the stream box
    /// is; it is also never ticked there, because nothing remembers it.
    fn reviews(&self) -> bool {
        self.review && self.runs()
    }

    /// Whether approving this window leaves a run behind it, which is the
    /// question every control that exists for a run asks before it is
    /// drawn: the close box, Kill, and the sentences about output.
    ///
    /// See [`Shown::runs`]. `false` before a request has arrived, when there
    /// is nothing to draw any of them for.
    fn runs(&self) -> bool {
        self.state.shown().is_some_and(Shown::runs)
    }

    /// Which set of keys this window is willing to hear, this frame.
    ///
    /// The phase, reduced to the one thing [`guard`] has to know: whether
    /// there is anywhere on the window for a letter to be typed. A window
    /// that is asking has the note field, so its shortcuts are chords; a
    /// window that is only showing a result has nothing to type into, so
    /// bare letters are free and are used.
    ///
    /// Matched exhaustively on purpose. A new phase is a new answer to this
    /// question, and the compiler is the only thing that will insist somebody
    /// gives one.
    fn keyboard(&self, ctx: &egui::Context) -> Keyboard {
        // Asked of egui and not of the draft: a window can be in its editing
        // mode with the keyboard on a button. See
        // `reviewing::editing_has_the_keyboard`.
        if self.state.phase() == Phase::Reviewing && reviewing::editing_has_the_keyboard(ctx) {
            return Keyboard::Composing;
        }
        // Nothing on this window has the keyboard, so Space is not going
        // into a field or onto a checkbox and is free to page the output.
        // The review screen only: it is the phase with output on it and a
        // decision to make about it.
        if self.state.phase() == Phase::Reviewing
            && ctx.memory(|memory| memory.focused()).is_none()
        {
            return Keyboard::Reading;
        }
        match self.state.phase() {
            // A running window has no text field either -- the note went with
            // the question -- and `e`, `o` and Space mean there what they mean
            // afterwards: keep this window. One key, one meaning, two phases,
            // which is the opposite of a collision.
            Phase::Running | Phase::Lingering | Phase::Detached => Keyboard::Watching,
            // A review has text fields on it — the filters, and the output
            // itself once the reader edits it — so it is asking, and its keys
            // are chords.
            Phase::WaitingForRequest | Phase::AwaitingVerdict | Phase::Reviewing | Phase::Closed => {
                Keyboard::Asking
            }
        }
    }

    /// Whether a control is pointing at the reason it could not do what a
    /// chord asked of it.
    fn refusing(&self, toggle: guard::Toggle) -> bool {
        self.refused.is_some_and(|(which, at)| which == toggle && at.elapsed() < REFUSAL_NOTICE)
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
        // As soon as the request that names this window has arrived, and
        // never again: the viewport was built before there was a request to
        // name it after. `Title` is the only way to say it once the window
        // exists, and the state machine's latch is what keeps it to once.
        if let Some(title) = self.state.take_title() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(title));
        }
        // And whenever the window stops asking or starts again. Nothing is
        // sent while it is what it already is, so an ordinary window says
        // this once, on the frame that carries its verdict. See `standing`.
        if let Some(standing) = self.state.take_standing() {
            ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(match standing {
                Standing::Insistent => egui::WindowLevel::AlwaysOnTop,
                Standing::Ordinary => egui::WindowLevel::Normal,
            }));
        }
        // Before anything is drawn, and before any widget sees the frame.
        // Whatever the guard did not hand back is gone from this frame.
        let now = Instant::now();
        let keyboard = self.keyboard(ctx);
        for action in intercept(&mut self.guard, ctx, keyboard, now) {
            self.act(ctx, action);
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
        // The soonest of the three things this window has to be redrawn for.
        // Two of them are shorter than a clock tick and neither can wait for
        // one: a refusal colour that faded only when the countdown next
        // ticked would be up for as much as a second longer than it says it
        // is, and the sentence painted over the disabled buttons would
        // outlive the guard it is about and sit there over buttons that had
        // started working.
        let next = [
            Some(CLOCK_TICK),
            self.refused.map(|(_, at)| REFUSAL_NOTICE.saturating_sub(at.elapsed())),
            self.guard.opens_in(now),
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(CLOCK_TICK);
        ctx.request_repaint_after(next);
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
        theme::wear(ui, mood(self.state.drawn_phase()));
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

        let viewing = matches!(self.state.drawn_phase(), Phase::Lingering | Phase::Detached);
        let reviewing = self.state.drawn_phase() == Phase::Reviewing;
        // Set inside the panel, applied outside it: see the call.
        let mut swapped = None;
        egui::CentralPanel::default().show(ui, |ui| {
            // The command is not what the reader is deciding about any more;
            // its output is, and the output takes the room.
            if reviewing {
                self.reviewer(ui, &title);
                return;
            }
            if viewing && self.runs() {
                // The question has been answered and the command has run, so
                // the two panes arguing about what the command says are of no
                // further use. What is worth the window now is what it
                // printed.
                self.viewer(ui, &title);
                return;
            }
            // A write that is staying keeps what it drew. It stays only to say
            // it did not land as described — see `Outcome::is_news` — and the
            // description it did not land as is the diff, the mode and the
            // owner, which are exactly what the reader needs beside that
            // sentence. It is also the picture they were already looking at,
            // so the only thing that changes when the write fails is the
            // controls panel and the ground.
            // There is always one once a request has arrived: a payload that
            // could not be rebuilt closed the window instead of becoming one.
            let aside = self.state.shown().and_then(panes::RunContext::of);
            panes::draw_headline(ui, &title, &reason, aside.as_ref());
            // Above the separator, with the headline rather than with the
            // request: it is news about a window that is gone, not a fact
            // about the one being asked about now.
            panes::draw_unanswered(ui, self.state.unanswered());
            ui.separator();
            if let Some(shown) = self.state.shown() {
                // Applied after the panel closes: `shown` borrows the state
                // for as long as it is drawn, and writing the preference
                // takes the window.
                swapped = panes::draw_payload(ui, shown, self.show_original);
            }
        });
        if let Some(original) = swapped {
            self.set_show_original(original);
        }

        // Last, so it is over the panels rather than under them, and outside
        // the `if` above so that it reaches the finished window too: a root
        // command that has already run is still the thing that ran as root.
        // It is painted, not laid out, so it takes nothing from the panes.
        if self.state.runs_as_root() {
            theme::mark_root(ui, window);
        }
        // Spent, whether or not anything was drawn that could spend it. A
        // page left lying here would be applied again on the next frame, and
        // every frame after, which is a window that scrolls on its own.
        self.paging = None;
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
        // A run nobody watched sent this window no output, so there is none
        // to show and "it printed nothing" would be a claim about a command
        // this window never heard from. It is here because its ending is
        // news, and that is in the row below; this says where the output
        // went instead.
        if !self.state.streaming() {
            let went = match self.in_a_terminal() {
                true => "Its output went to the terminal it ran in.",
                false => "Its output was not streamed to this window.",
            };
            ui.label(egui::RichText::new(went).weak());
            return;
        }
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
    pub(crate) fn act(&mut self, ctx: &egui::Context, action: Action) {
        // A window asking what of the output to send. The approve chord
        // sends what is on the screen and Escape sends none of it, which are
        // the two answers the verdict's keys give in the verdict's phase; the
        // rest mean nothing here. Before everything below, because this phase
        // is neither a viewer nor the approval.
        if self.state.phase() == Phase::Reviewing {
            match action {
                Action::Approve => self.send_review(),
                Action::Deny => self.withhold_review(),
                // The one phase that acts on it. This is where a reader has
                // output in front of them and a decision to make about it,
                // which is the whole case for a key that moves it.
                Action::Scroll(page) => self.page_output(page),
                Action::Toggle(_)
                | Action::Keep
                | Action::Copy
                | Action::Ignored
                | Action::Passthrough => {}
            }
            return;
        }
        // A window that is only showing a result has nothing to decide, so
        // the keys mean the three things that are left: keep it, take what is
        // on it, or put it away. Enter still means nothing at all, and
        // nothing here reaches `decide` — which is a second lock on the same
        // door rather than the first, since `decide` answers in
        // `AwaitingVerdict` alone and no phase returns there.
        if self.state.is_viewer() {
            match action {
                Action::Deny => self.state.dismiss(),
                Action::Keep => self.keep_window(),
                // Inert where there is no output on the window to take, and
                // silently: there is no copy control there for the chord to
                // be refused by, and an empty clipboard with "copied" beside
                // it would be a window claiming to have handed something over.
                Action::Copy if self.state.streaming() => self.copy_output(ctx),
                Action::Copy => {}
                Action::Approve
                | Action::Scroll(_)
                | Action::Toggle(_)
                | Action::Ignored
                | Action::Passthrough => {}
            }
            return;
        }
        // A window whose command is running. It cannot decide anything -- the
        // verdict has been sent and `decide` answers in `AwaitingVerdict`
        // alone -- and the one thing it can be told is that the reader wants
        // it afterwards. Escape is deliberately not a close here: the command
        // is still going, and a window that vanished on a keypress would take
        // the Kill button with it.
        //
        // Copy is inert, and silently: there is no copy control on a running
        // window for a chord to be refused *by*, which is the case the box
        // chords already have on a payload that offers no box. A window
        // cannot flash a sentence it is not drawing.
        if self.state.phase() == Phase::Running {
            if action == Action::Keep {
                self.keep_window();
            }
            return;
        }
        let verdict = match action {
            // The note goes with an approval as it goes with a denial: the
            // field says "Note to the agent", and which button was pressed
            // afterwards does not change who the words were for.
            Action::Approve => self.approval(),
            Action::Deny => Verdict::Deny { note: self.note.clone() },
            Action::Toggle(toggle) => return self.flip(toggle),
            // Neither is produced outside the phases above -- see
            // [`Keyboard`] -- and a window that is still asking has neither a
            // countdown to stop nor any output to take.
            // Scroll is not produced here: `keyboard` only reports
            // `Reading` for the phase that has output to move. See
            // [`Keyboard::Reading`].
            Action::Keep
            | Action::Copy
            | Action::Scroll(_)
            | Action::Ignored
            | Action::Passthrough => return,
        };
        let frame = self.state.decide(verdict);
        answer(&mut self.out, &mut self.state, frame);
    }

    /// Remember that the reader asked for a screenful, for the drawing half
    /// of the frame to spend.
    ///
    /// The last one wins rather than accumulating. A held-down Space repeats
    /// faster than frames are drawn, and a queue of pages would carry on
    /// moving after the key came up — past the thing the reader stopped at,
    /// which is the one place paging can actually lose somebody.
    fn page_output(&mut self, page: guard::Page) {
        self.paging = Some(page);
    }

    /// Flip one of the two boxes a chord names, or say why it cannot be.
    ///
    /// The chord does exactly what the click does — the same one method
    /// writes the preference down either way — so there is no state of this
    /// window in which the keyboard and the mouse remember different things.
    ///
    /// # When there is nothing to flip
    ///
    /// Both boxes have a state in which they are drawn dead, with a sentence
    /// beside them saying why. A chord aimed at a dead box must not tick it
    /// anyway — the tick would be a promise the window cannot keep, and for
    /// Stream it would persist — and it must not be silence either, because a
    /// shortcut that does nothing and says nothing teaches the reader that it
    /// does not work. So it points at the sentence that is already there: see
    /// [`REFUSAL_NOTICE`].
    ///
    /// The one case with nothing to point at is a payload that offers no box
    /// at all. A file write prints nothing and leaves no run behind, so it
    /// has neither the stream box nor the close box, and there is no control
    /// on the window for Alt+S or Alt+C to be refused *by*. Both chords are
    /// inert there, and a window cannot flash a sentence it is not drawing —
    /// nor, which matters more for Alt+C, write down a preference through a
    /// box it is not drawing.
    fn flip(&mut self, toggle: guard::Toggle) {
        // Only while there is something to decide. In every later phase these
        // boxes are gone from the window along with the question they belonged
        // to, and a chord that changed a preference nobody could see change
        // would be the invisible write this whole design is against.
        if self.state.phase() != Phase::AwaitingVerdict {
            return;
        }
        match toggle {
            guard::Toggle::Stream => {
                let offered = self.state.shown().is_some_and(|shown| shown.streamable());
                match offered && !self.in_a_terminal() {
                    true => self.set_stream(!self.streams()),
                    // Dead, or never drawn. Either way nothing is ticked.
                    false => self.refused = Some((toggle, Instant::now())),
                }
            }
            guard::Toggle::Close => match self.runs() && !self.streams() && !self.reviews() {
                true => self.set_close_on_decide(!self.closes_on_decide()),
                // Dead, or never drawn. Either way nothing is written down.
                false => self.refused = Some((toggle, Instant::now())),
            },
            // Through the same setter the click goes through, so the
            // keyboard and the mouse cannot end up remembering different
            // things -- which is this method's whole claim.
            guard::Toggle::Review => match self.runs() {
                true => self.set_review(!self.review),
                // A write prints nothing, so there is no output to hold back
                // and no box on screen to have pressed.
                false => self.refused = Some((toggle, Instant::now())),
            },
        }
    }

    /// Keep this window: stop whatever was going to take it away.
    ///
    /// One method rather than the button doing it and the key doing it again,
    /// because the second thing it has to do is easy to leave out. The flag
    /// is read by the thread in [`arm_linger_backstop`], which is the only
    /// thing still holding a deadline over this window and is not running the
    /// state machine; a keep the state machine knew about and that thread did
    /// not is a window that would be kept for twelve seconds.
    fn keep_window(&mut self) {
        if self.state.keep() {
            // Set before anything else, so a stall between here and the next
            // frame cannot lose it.
            self.kept.store(true, Ordering::SeqCst);
        }
    }

    /// Put the output on the clipboard, and leave the window able to say so.
    ///
    /// The output as it is on screen. The command is copied elsewhere and
    /// deliberately not from here: see [`guard::COPY_CHORD`] for why only one
    /// of the two buttons has a key on it.
    fn copy_output(&mut self, ctx: &egui::Context) {
        ctx.copy_text(self.state.output_text());
        self.copied = Some(Instant::now());
    }

    /// Everything below the panes: what the clock says, and what can be
    /// pressed.
    ///
    /// One method rather than a panel closure per phase, because the phase is
    /// what decides between them and the two must never both be drawn.
    ///
    /// Chosen by the phase the window is drawn as, so that a closing window
    /// keeps the controls it had; see [`PromptState::drawn_phase`]. Every
    /// control drawn on the way out is inert, because what it would do asks
    /// the real phase. The verdict area is the exception and is not drawn
    /// again at all: its checkboxes write preferences down, and nothing may
    /// be written from a window that has already answered.
    fn controls(&mut self, ui: &mut egui::Ui, guard_open: bool) {
        ui.add_space(4.0);
        match self.state.drawn_phase() {
            Phase::AwaitingVerdict if self.state.phase() == Phase::AwaitingVerdict => {
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
            // Drawn on the way out too, like the other phases, and inert
            // then: the guard is reported shut, and both answers ask the real
            // phase before they build anything.
            Phase::Reviewing => {
                let asking = self.state.phase() == Phase::Reviewing;
                self.review_row(ui, guard_open && asking)
            }
            Phase::WaitingForRequest | Phase::AwaitingVerdict | Phase::Closed => {
                self.status_row(ui)
            }
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

        let runs = self.runs();
        ui.vertical_centered(|ui| {
            if let Some(outcome) = self.state.outcome() {
                let (text, clean) = panes::outcome_text(outcome, runs);
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
        // Only a watched run has output on this window to take. A write has
        // neither output nor a command, so it has no copy row at all.
        let has_output = self.state.streaming();
        ui.vertical_centered(|ui| {
            centred_row(ui, width, |ui| {
                if closing.is_some() {
                    keep = unfocusable(ui, primary(ui, "Keep this window", guard::KEEP_KEYS))
                        .clicked();
                    // The same gap the verdict buttons keep, for a weaker
                    // reason: nothing here is dangerous, but a pointer on its
                    // way to Keep must not find Close under it.
                    ui.add_space(PRIMARY_GAP);
                }
                close = unfocusable(ui, keyed(egui::RichText::new("Close"), guard::DENY_CHORD))
                    .clicked();
            });
            if !has_output && !has_command {
                return;
            }
            ui.add_space(4.0);
            centred_row(ui, width, |ui| {
                if has_output {
                    copy_output = unfocusable(
                        ui,
                        keyed(egui::RichText::new("Copy output").small(), guard::COPY_CHORD),
                    )
                    .clicked();
                }
                if has_command {
                    copy_command = secondary(ui, "Copy command").clicked();
                }
                if self.copied.is_some_and(|at| at.elapsed() < COPY_NOTICE) {
                    ui.label(egui::RichText::new("copied").small().color(weak));
                }
            });
        });

        if keep {
            self.keep_window();
        }
        if close {
            self.state.dismiss();
        }
        // The output as it is on screen, and the command as it really is: the
        // one-line form above is drawn with chip glyphs standing in for tabs
        // and newlines, and pasting those into a shell would be pasting a
        // different command from the one that ran.
        if copy_output {
            self.copy_output(ui.ctx());
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
        //
        // The first arm is reached only by a window on its way out, after an
        // ending it did not stay for: see `PromptState::drawn_phase`. What it
        // was saying a moment ago is no longer true, so the sentence changes
        // to one that is; what it does not do is change how many lines there
        // are, because a panel a line shorter is panes a line taller, and a
        // picture that moves as it goes is the flash the drawn phase exists to
        // prevent.
        let runs = self.runs();
        let (said, aside) = match (self.state.outcome().is_some(), self.state.elevating()) {
            (true, _) => (
                match runs {
                    true => "Approved. It has finished.",
                    false => "Approved. The file is written.",
                },
                self.state.was_elevated().then_some("The system authorised it."),
            ),
            (false, true) => (
                "Approved. Waiting for the system to authorise this.",
                Some("If a password dialog is up, dismissing it cancels this."),
            ),
            (false, false) if !runs => ("Approved. Writing the file.", None),
            (false, false) => ("Approved. It is running now.", None),
        };
        ui.vertical_centered(|ui| match aside {
            Some(aside) => {
                ui.label(egui::RichText::new(said).strong());
                ui.label(egui::RichText::new(aside).small());
            }
            None => {
                ui.label(said);
            }
        });
        // A write has nothing below its sentence. It prints nothing, so a line
        // saying its output is not being streamed would be a sentence about a
        // command; and it offers neither Keep, which exists for output, nor
        // Kill, for the reason `Shown::runs` gives. The one wait a write can
        // have is a root write's password dialog, and the sentence above
        // already names the stop for that — which ends it with nothing written,
        // where Kill on the `install` behind it would end it with hatch unable
        // to say whether the file was.
        if !runs {
            return;
        }
        if self.streams() {
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
        } else if self.state.reviewing() {
            ui.label(
                egui::RichText::new(
                    "Its output is held until it finishes, and you will see it before it is sent.",
                )
                .small(),
            );
        } else {
            ui.label(
                egui::RichText::new("Its output is not being streamed to this window.").small(),
            );
        }
        // Centred with the verdict buttons they replace. The output above
        // them is not: it is monospace text being read, and a column of it
        // down the middle of a 1280-point window is harder to follow than one
        // that starts where every other line of text in this window starts.
        //
        // Keep is here as well as at the end of the run, and it is the same
        // action rather than a new setting: a long command is exactly when
        // the reader has gone to do something else, and asking them to be at
        // the keyboard for the ten seconds after it stops is asking them to
        // wait for it. Only for a run they asked to watch -- see
        // [`PromptState::keep`] -- which is also the only kind that has
        // anything to show at the end.
        // Not for a run under review, which ends in a question rather than a
        // viewer: see `PromptState::keep`.
        let offer_keep = self.state.streaming() && !self.state.reviewing();
        let kept = self.state.keeping();
        let mut keep = false;
        let width = cluster_width(ui);
        let killed = ui
            .vertical_centered(|ui| {
                centred_row(ui, width, |ui| {
                    if offer_keep {
                        match kept {
                            // In the place the button was and at the size it
                            // was, so that pressing it moves nothing on a
                            // window somebody is in the middle of reading.
                            true => {
                                ui.allocate_ui_with_layout(
                                    primary_button(ui),
                                    egui::Layout::centered_and_justified(
                                        egui::Direction::TopDown,
                                    ),
                                    |ui| ui.label(egui::RichText::new(KEPT_RUNNING).small()),
                                );
                            }
                            false => {
                                keep = unfocusable(
                                    ui,
                                    primary(ui, "Keep this window", guard::KEEP_KEYS),
                                )
                                .clicked();
                            }
                        }
                        // The gap the verdict buttons keep, for the reason
                        // the viewer's row keeps it: a pointer on its way to
                        // Keep must not find Kill under it.
                        ui.add_space(PRIMARY_GAP);
                    }
                    unfocusable(ui, egui::Button::new("Kill")).clicked()
                })
            })
            .inner;
        if keep {
            self.keep_window();
        }
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
    ///
    /// # Why the sentence is painted and not laid out
    ///
    /// It used to be an [`egui::Ui::label`] under the buttons, and a label is
    /// a row. This is a bottom panel, and a bottom panel takes its height out
    /// of the window *before* the panes above it are laid out -- so while the
    /// guard was shut the panel was a row taller and the command a row
    /// shorter, and 750 ms later the text above it jumped up by that row. It
    /// happened on every focus gain rather than once, because that is when
    /// the clock restarts, and what it costs a reader is a moment spent
    /// looking for what moved.
    ///
    /// Reserving the row permanently is the other way out and is worse: it
    /// spends a row of every request on a sentence most requests never show.
    /// So the sentence is painted across the two buttons it is about. That
    /// costs no layout at all, and it puts the explanation where the reader
    /// is already looking -- on the controls that are not answering -- rather
    /// than below them.
    ///
    /// Three things fall out of painting rather than adding:
    ///
    /// * **It cannot take a click.** A painted shape has no [`egui::Sense`]
    ///   and allocates nothing, so there is no widget over Approve for a
    ///   pointer to find once the guard opens. What stops a click while it is
    ///   up is what stopped one before: the buttons under it are disabled,
    ///   which is the second layer described in [`guard`].
    /// * **It goes when the guard does.** It is painted only on the frames
    ///   this is called with `guard_open` false, and the event loop asks to
    ///   be woken at the instant the guard opens -- see
    ///   [`guard::Guard::opens_in`] -- rather than leaving it up until
    ///   whatever repaint comes along next, which is otherwise as much as a
    ///   second later.
    /// * **It is over the buttons and not merely near them.** The rect comes
    ///   from the row that placed them, so the two cannot drift apart.
    fn verdict_area(&mut self, ui: &mut egui::Ui, guard_open: bool) -> egui::Response {
        let (approve, buttons) =
            ui.add_enabled_ui(guard_open, |ui| self.verdict_buttons(ui)).inner;
        if !guard_open {
            paint_guard_notice(ui, buttons);
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
    /// Returns the Approve button, and the rect the two that decide share --
    /// which is what [`PromptApp::verdict_area`] paints its sentence across.
    fn verdict_buttons(&mut self, ui: &mut egui::Ui) -> (egui::Response, egui::Rect) {
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
        // stream. The box is drawn unticked rather than merely disabled,
        // because a ticked box that has been greyed out reads as a promise to
        // stream and nothing is going to — see [`PromptApp::streams`], which
        // is where the effective answer is worked out now that the stored one
        // outlives the window.
        //
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
        let (approve, buttons) = self.decision_row(ui, width, &note, &mut decided);

        if approve.clicked() {
            decided = Some(self.approval());
        }

        if let Some(verdict) = decided {
            let frame = self.state.decide(verdict);
            answer(&mut self.out, &mut self.state, frame);
        }
        (approve, buttons)
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
    ///
    /// # Why the review box is on this row
    ///
    /// Both boxes on it are about what reaches the agent, and the sentence
    /// between them is the one that says what a terminal sends. A reader who
    /// has just read that everything they type there goes to the agent is
    /// looking at the one control that lets them see it first. It sits past
    /// the sentence with the gap the verdict buttons keep, so the row reads as
    /// two controls and not as one box with a second label.
    ///
    /// It takes no row of its own, which matters on a window read at 700
    /// points high, and it goes under the rest when the row cannot hold it —
    /// on the same terms as the sentence, and never off the end.
    fn terminal_row(&mut self, ui: &mut egui::Ui, asked_for: bool) {
        let quiet = ui.visuals().weak_text_color();
        let warn = ui.visuals().warn_fg_color;
        let mut ticked = self.in_a_terminal();
        let checkbox = ui.spacing().icon_width + ui.spacing().icon_spacing;
        let width = text_width(ui, TERMINAL_LABEL, egui::TextStyle::Button)
            + checkbox
            + text_width(ui, TERMINAL_CAPTURE, egui::TextStyle::Small)
            + match asked_for {
                true => text_width(ui, TERMINAL_ASKED, egui::TextStyle::Small),
                false => 0.0,
            }
            + PRIMARY_GAP
            + checkbox
            + keyed_width(ui, REVIEW_LABEL, guard::REVIEW_CHORD)
            + 4.0 * ui.spacing().item_spacing.x;

        let mut changed = false;
        let mut review_changed = false;
        let mut reviewing_now = self.review;
        // `beside` is whether the row is one row: the gap is a distance along
        // it, and in the stacked fallback it would be a blank line instead.
        let mut controls = |ui: &mut egui::Ui, beside: bool| {
            changed |= ui
                .add_enabled(!asked_for, egui::Checkbox::new(&mut ticked, TERMINAL_LABEL))
                .changed();
            if asked_for {
                ui.label(egui::RichText::new(TERMINAL_ASKED).small().color(quiet));
            }
            ui.label(egui::RichText::new(TERMINAL_CAPTURE).small().color(warn));
            if beside {
                ui.add_space(PRIMARY_GAP);
            }
            // Not written down when it changes, unlike the box before it: see
            // `PromptApp::review` for why this one is never remembered.
            review_changed = ui
                .add(egui::Checkbox::new(
                    &mut reviewing_now,
                    with_chord(egui::RichText::new(REVIEW_LABEL), guard::REVIEW_CHORD),
                ))
                .changed();
        };
        if width <= ui.available_width() {
            centred_row(ui, width, |ui| controls(ui, true));
        } else {
            // Under the box rather than beside it. The sentence is the part
            // that must not be dropped, so the row that cannot hold it gets
            // taller instead of shorter.
            ui.vertical_centered(|ui| controls(ui, false));
        }
        // Only the reader's half is stored. `ticked` is the *effective*
        // answer, which is already true for a request the agent asked for, and
        // writing that back would turn the agent's ask into the reader's
        // choice — indistinguishable afterwards, and the wrong thing to show
        // if the payload ever changed under this window.
        //
        // The same gate is what keeps a remembered preference honest: a window
        // opened on a request the agent asked a terminal for never writes
        // anything down, so the agent's ask cannot become the reader's
        // standing decision by having been shown to them once.
        if !asked_for {
            self.terminal = ticked;
            if changed {
                self.prefs.update(|prefs| prefs.terminal = ticked);
            }
        }
        // Written down on the click, like the other three, and only on a
        // click: `set_review` is also what clears the "this came out of the
        // file" flag, and a window that called it every frame would report a
        // remembered tick as one made in front of this command.
        if review_changed {
            self.set_review(reviewing_now);
        }
    }

    /// The stream checkbox, and the reason it is dead when it is.
    ///
    /// Drawn as the effective answer and stored only when the reader is the
    /// one who settled it, exactly as the close box and the terminal box are.
    /// See [`PromptApp::streams`].
    fn stream_box(&mut self, ui: &mut egui::Ui, can_stream: bool) {
        let mut ticked = self.streams();
        let changed = ui
            .add_enabled(
                can_stream,
                egui::Checkbox::new(
                    &mut ticked,
                    with_chord(egui::RichText::new(STREAM_LABEL), guard::STREAM_CHORD),
                ),
            )
            .changed();
        if changed {
            self.set_stream(ticked);
        }
        if !can_stream {
            // The sentence that says why the box is dead, and the one thing
            // this window has to answer Alt+S with when there is nothing to
            // tick. See [`REFUSAL_NOTICE`]: the colour is the answer, and it
            // costs no width, because the sentence is drawn either way.
            let colour = match self.refusing(guard::Toggle::Stream) {
                true => ui.visuals().warn_fg_color,
                false => ui.visuals().weak_text_color(),
            };
            ui.label(egui::RichText::new(STREAM_DEAD).small().color(colour));
        }
    }

    /// Take the reader's answer about streaming, and write it down.
    ///
    /// One place, because there are two ways to give it — the box and the
    /// chord — and a preference that persisted from one and not the other
    /// would be a window whose keyboard and mouse remembered different things.
    /// Show the exact text, or the annotated rendering.
    ///
    /// Written down on the click for the reason [`PromptApp::set_stream`]'s
    /// is: this window's ordinary ending is the daemon killing the process,
    /// so there is no way out to write it on.
    fn set_show_original(&mut self, ticked: bool) {
        self.show_original = ticked;
        self.prefs.update(|prefs| prefs.show_original = ticked);
    }

    fn set_stream(&mut self, ticked: bool) {
        self.stream = ticked;
        // They have now said something about this command, so the sentence
        // under the close box is about this command again.
        self.stream_is_remembered = false;
        // On the click, and not on the way out, because there may be no way
        // out to write it on: this window's ordinary ending is the daemon
        // killing the process once the operation is over. One field, because
        // the window beside this one may be writing another; see
        // [`crate::prefs`].
        self.prefs.update(|prefs| prefs.stream = ticked);
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
        let label = keyed_width(ui, STREAM_LABEL, guard::STREAM_CHORD);
        let dead = match self.in_a_terminal() {
            true => {
                ui.spacing().item_spacing.x
                    + text_width(ui, STREAM_DEAD, egui::TextStyle::Small)
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
        let live = !self.streams() && !self.reviews();
        let mut ticked = self.closes_on_decide();
        let changed = ui
            .add_enabled(
                live,
                egui::Checkbox::new(
                    &mut ticked,
                    with_chord(egui::RichText::new(CLOSE_LABEL), guard::CLOSE_CHORD),
                ),
            )
            .changed();
        if changed {
            self.set_close_on_decide(ticked);
        }
        // Three sentences and not two: a greyed box has two different reasons
        // for being grey now, and only one of them is about the command on
        // the screen. See [`CLOSE_WATCHING_ALWAYS`].
        //
        // Reviewing is asked first. Both are grey for the same reason, and
        // this is the one chosen in front of this command every time.
        let said = match (live, self.reviews(), self.review_is_remembered) {
            (true, _, _) => CLOSE_COST,
            (false, true, true) => CLOSE_REVIEWING_ALWAYS,
            (false, true, false) => CLOSE_REVIEWING,
            (false, false, _) => match self.stream_is_remembered {
                false => CLOSE_WATCHING,
                true => CLOSE_WATCHING_ALWAYS,
            },
        };
        let colour = match self.refusing(guard::Toggle::Close) {
            true => ui.visuals().warn_fg_color,
            false => ui.visuals().weak_text_color(),
        };
        ui.label(egui::RichText::new(said).small().color(colour));
    }

    /// Take the reader's answer about reviewing, and write it down.
    ///
    /// [`PromptApp::set_stream`]'s reasons, for the third box.
    fn set_review(&mut self, ticked: bool) {
        self.review = ticked;
        // They have now said something about this command, so the sentence
        // under the close box is about this command again.
        self.review_is_remembered = false;
        self.prefs.update(|prefs| prefs.review = ticked);
    }

    /// Take the reader's answer about closing, and write it down.
    ///
    /// [`PromptApp::set_stream`]'s reasons, for the other box.
    fn set_close_on_decide(&mut self, ticked: bool) {
        self.close_on_decide = ticked;
        self.prefs.update(|prefs| prefs.close_on_decide = ticked);
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
        let label = box_ + keyed_width(ui, CLOSE_LABEL, guard::CLOSE_CHORD);
        let said = text_width(ui, CLOSE_COST, egui::TextStyle::Small)
            .max(text_width(ui, CLOSE_WATCHING, egui::TextStyle::Small))
            .max(text_width(ui, CLOSE_WATCHING_ALWAYS, egui::TextStyle::Small))
            .max(text_width(ui, CLOSE_REVIEWING, egui::TextStyle::Small));
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
    ///
    /// Hands back the Approve button, and the place the two that decide were
    /// put: the sentence the guard paints has to land on that place and
    /// nowhere else. It is the row's own centre -- see [`Places`] -- so it is
    /// where the buttons are by construction, rather than by a second
    /// measurement that could come out disagreeing with the first.
    fn decision_row(
        &mut self,
        ui: &mut egui::Ui,
        width: f32,
        note: &str,
        decided: &mut Option<Verdict>,
    ) -> (egui::Response, egui::Rect) {
        let height = primary_button(ui).y;
        let runs = self.runs();
        // `Hatch::ALL`, measured and then drawn: one list, in one order or
        // the other. Two lists is how a button ends up in one arrangement and
        // not the other.
        let needed = row_width(
            ui,
            Hatch::ALL.iter().map(|hatch| hatch.label(runs)),
            egui::TextStyle::Small,
        );
        // Past Deny on one side and short of Approve on the other, each with
        // the same gap the two of them keep between themselves: a pointer
        // sliding off either lands on the panel, never on a button and never
        // on a checkbox. The left flank was empty until the close control
        // moved into it, and that is why that control costs no row — this
        // panel is 1280 points wide and the two buttons that matter are 400 of
        // them in the middle of it.
        //
        // # On a write
        //
        // There is no close control — see [`PromptApp::closes_on_decide`] —
        // and the flank is measured as nothing and left empty rather than
        // given to something else. What that gives back is the one row the
        // control ever cost, which is the row above the buttons it takes on a
        // window too narrow to hold it beside them. What it does not do is
        // move Approve and Deny: the centre is placed from the row's own width
        // and not from its flanks, and nothing under this row changes either,
        // so the two buttons are at the same place on a write window as on a
        // command window of the same size. A reader who has learnt where
        // Approve is has learnt it for both.
        let close = match runs {
            true => self.close_width(ui) + PRIMARY_GAP,
            false => 0.0,
        };
        let flanks = [close, needed + PRIMARY_GAP];
        // Asked before anything is drawn and then asked again, because a close
        // control with nowhere to sit beside Approve goes *above* the row —
        // which moves the row. Both calls only measure; see [`Places`].
        if runs && flanked_row(ui, height, width, flanks).flanks[0].is_none() {
            // First, because it says what pressing one of the buttons under it
            // is going to do to this window.
            ui.vertical_centered(|ui| self.close_box(ui));
            ui.add_space(4.0);
        }
        let places = flanked_row(ui, height, width, flanks);
        ui.advance_cursor_after_rect(places.row);

        if runs && let Some(left) = places.flanks[0] {
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
                if secondary(ui, hatch.label(runs)).clicked() {
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
        (approve, places.centre)
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
/// How tall `text` is drawn, line breaks in it included.
///
/// The galley rather than lines multiplied by a line height: egui's own
/// arithmetic for a multi-line galley is not quite that, and the caller that
/// needs this is sizing a button around a label. A button measured with a
/// figure 1 point short of what is drawn in it is a button the label grows
/// out of.
fn text_height(ui: &egui::Ui, text: &str, style: egui::TextStyle) -> f32 {
    let font = style.resolve(ui.style());
    ui.ctx().fonts_mut(|fonts| {
        fonts.layout_no_wrap(text.to_string(), font, egui::Color32::WHITE).size().y
    })
}

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

/// Paint [`GUARD_NOTICE`] across the buttons the guard has disabled.
///
/// Painted, so it takes no room: `over` is where the two buttons already are,
/// and nothing here allocates, senses or advances a cursor. See
/// [`PromptApp::verdict_area`] for why that is the whole point.
///
/// Drawn small and on a ground of its own. The sentence is hatch's aside
/// about why nothing is answering, in the same quiet voice as the chord hints
/// on the buttons underneath it; the ground is the panel's own colour at very
/// nearly full opacity, so the buttons are still there behind it rather than
/// replaced by it, and the words are legible against one thing rather than
/// against whatever they happen to cross.
fn paint_guard_notice(ui: &egui::Ui, over: egui::Rect) {
    let pad = ui.spacing().button_padding;
    let galley = ui.painter().layout(
        GUARD_NOTICE.to_string(),
        egui::TextStyle::Small.resolve(ui.style()),
        ui.visuals().text_color(),
        // Wrapped inside the buttons rather than across the panel: this is a
        // note about those two controls, and a line of it running out past
        // them would read as a note about the window.
        over.width() - 2.0 * pad.x,
    );
    // As wide as the pair of buttons and no wider: a band across the two
    // controls that are not answering, rather than a box floating over them.
    // Only the height is measured from the words.
    let ground = egui::Rect::from_center_size(
        over.center(),
        egui::vec2(over.width(), galley.size().y + 2.0 * pad.y),
    );
    let painter = ui.painter();
    painter.rect_filled(
        ground,
        ui.visuals().widgets.inactive.corner_radius,
        ui.visuals().panel_fill.gamma_multiply(0.94),
    );
    painter.galley(
        egui::pos2(ground.left() + pad.x, ground.center().y - 0.5 * galley.size().y),
        galley,
        ui.visuals().text_color(),
    );
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

    /// What the button says, on a window whose approval would leave a run
    /// behind (`runs`) or one that would write a file.
    ///
    /// Short on purpose: all four measure against the room left beside
    /// Approve and Deny, and a label that outgrows it costs every one of them
    /// their place on that row. See [`PromptApp::verdict_buttons`].
    ///
    /// One of the four is worded for the operation. Nobody runs a file, and a
    /// button that offers to on a diff is a sentence about some other window.
    /// The verdict is the same one either way: what it tells the agent is
    /// that the person will do this themselves, whatever "this" is. The two
    /// labels differ by two letters, which is what the two hatches nearer
    /// the centre shift by between the two kinds of window; Approve and Deny
    /// are placed without reference to any of them and do not move at all.
    fn label(self, runs: bool) -> &'static str {
        match self {
            Hatch::Explain => "Explain first",
            Hatch::Simplify => "Ask for something simpler",
            Hatch::SelfRun if runs => "I'll run it myself",
            Hatch::SelfRun => "I'll write it myself",
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
/// that repainted itself on the way out would flash a colour at somebody, so
/// the window is never drawn as it: it is drawn as the phase it closed from
/// — see [`PromptState::drawn_phase`] — and `Closed` arrives here only for a
/// window that closed before it had a request, which was asking.
fn mood(phase: Phase) -> theme::Mood {
    match phase {
        Phase::Running => theme::Mood::Running,
        Phase::Lingering | Phase::Detached => theme::Mood::Finished,
        Phase::WaitingForRequest | Phase::AwaitingVerdict | Phase::Reviewing | Phase::Closed => {
            theme::Mood::Asking
        }
    }
}

/// Where a phase's window belongs among the windows around it.
///
/// The same split [`mood`] draws and [`PromptApp::keyboard`] types on: a
/// window is either asking something or watching something happen. Asking is
/// what earns a window the screen, because something is stopped until it is
/// answered; watching earns nothing, however interesting the output is.
///
/// `Closed` is grouped with the asking for [`mood`]'s reason and reaches here
/// only the same way — a window that closed before it ever had a request,
/// which was asking. Everything closing otherwise is read through
/// [`PromptState::drawn_phase`] and keeps what it had.
fn standing(phase: Phase) -> Standing {
    match phase {
        Phase::Running | Phase::Lingering | Phase::Detached => Standing::Ordinary,
        Phase::WaitingForRequest | Phase::AwaitingVerdict | Phase::Reviewing | Phase::Closed => {
            Standing::Insistent
        }
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
/// inert although both of its halves approve on their own, so a label loose
/// enough for a reader to expect it to work would be this window promising
/// something it refuses to do.
///
/// The hint is small and quiet — hatch's own voice, beside the word for what
/// the button does — and it fits inside the width the button already had, so
/// the cluster the two buttons are centred in does not move. Approve's is two
/// lines, because there are two ways to approve and the button has the height
/// to say both; see [`guard::APPROVE_CHORD`] for why neither is left out and
/// why neither is abbreviated. That it fits is
/// `the_shortcut_hints_fit_the_buttons_that_were_already_there`.
fn primary(ui: &egui::Ui, label: &str, chord: &str) -> egui::Button<'static> {
    keyed(strong(label), chord).min_size(primary_button(ui))
}

/// What a control says about itself: what it does, and the key that does the
/// same thing.
///
/// The one place a shortcut is put on a control, so nothing can acquire a key
/// and be left saying nothing about it. Two atoms rather than one string, so
/// the chord is drawn in hatch's own quiet voice beside the label rather than
/// inside it -- and so a checkbox can say it the same way a button does,
/// which is the whole reason this is not simply part of [`keyed`].
///
/// A tooltip is not an alternative. It is read by people who already suspect
/// there is something to read, and a shortcut nobody has heard of is exactly
/// the thing they do not suspect; that is the same argument the terminal
/// box's warning makes for being beside its box rather than behind a hover.
fn with_chord(label: egui::RichText, chord: &str) -> (egui::RichText, egui::RichText) {
    (label, egui::RichText::new(chord).small().weak())
}

/// How wide a control labelled `label` is once [`with_chord`] has put `chord`
/// beside it, without the control's own furniture.
///
/// The gap is egui's, read from the same figure its atom layout uses, so a
/// row measured with this and drawn by that cannot disagree. A chord written
/// over two lines is as wide as its widest.
fn keyed_width(ui: &egui::Ui, label: &str, chord: &str) -> f32 {
    let chord = chord
        .lines()
        .map(|line| text_width(ui, line, egui::TextStyle::Small))
        .fold(0.0, f32::max);
    text_width(ui, label, egui::TextStyle::Button) + ui.spacing().icon_spacing + chord
}

/// A button with the key that does the same thing printed beside what it
/// does, at whatever size the button already was.
///
/// What [`primary`] adds on top is the size: the two that decide, and the one
/// with a countdown on it, are drawn at a minimum the cluster around them is
/// measured from.
fn keyed(label: egui::RichText, chord: &str) -> egui::Button<'static> {
    egui::Button::new(with_chord(label, chord))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use chrono::Utc;

    use crate::prefs::Prefs;

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
                let least = primary_button(ui);
                for (label, chord) in
                    [("Approve", guard::APPROVE_CHORD), ("Deny", guard::DENY_CHORD)]
                {
                    let size = unfocusable(ui, primary(ui, label, chord)).rect.size();
                    measured.push((label, size, least));
                }
            });
            out.textures_delta.clear();

            assert_eq!(measured.len(), 2, "the buttons were not drawn");
            for (label, size, least) in &measured {
                assert!(
                    size.x <= least.x,
                    "{label} with its shortcut is {} wide at {points} points, past the \
                     {} the cluster is measured from",
                    size.x,
                    least.x
                );
                // The minimum has to be the answer and not merely a floor:
                // a label taller than it makes that one button taller, and
                // `PRIMARY_BUTTON_ROWS` is derived from the longest label
                // exactly so it cannot.
                assert!(
                    size.y <= least.y,
                    "{label} with its shortcut is {} tall at {points} points, past the \
                     {} the pair is measured from",
                    size.y,
                    least.y
                );
            }
            // And so the two come out the same size, which is the half of
            // this the third approval chord broke: Approve's label is three
            // lines and Deny's is one, and the larger of two buttons is an
            // invitation dressed as an affordance.
            assert_eq!(
                measured[0].1, measured[1].1,
                "Approve and Deny are different sizes at {points} points"
            );
        }
    }

    fn a_request(seconds_left: i64) -> Request {
        Request {
            title: "delete the build directory".to_string(),
            reason: "the last build left files the tests trip over".to_string(),
            deadline: Utc::now() + chrono::Duration::seconds(seconds_left),
            queue_depth: 0,
            number: Some(47),
            unanswered: Vec::new(),
            operations: vec![Payload::command(
                &render_command("rm -rf target", &BTreeMap::new()),
                Vec::new(),
                PathBuf::from("/"),
                false,
                false,
            )],
            stop_on_failure: false,
        }
    }

    // ---- the close latch ---------------------------------------------------

    #[test]
    fn output_is_not_streamed_unless_the_reader_asks_for_it() {
        // The spec makes execution headless by default; the checkbox is the
        // opt-in. Defaulting it on means every approval silently chooses the
        // mode the reader never picked.
        let (_tx, rx) = std::sync::mpsc::channel();
        let app =
            PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
        assert!(!app.stream, "streaming is opted into, not defaulted on");
    }

    #[test]
    fn the_close_is_taken_once_and_only_once() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        assert!(!state.take_close(), "there is nothing to close yet");

        state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));

        assert!(state.take_close(), "the window was never told to go");
        assert!(!state.take_close(), "it would arm a second backstop every frame");
        assert!(state.should_close(), "and it is still closing");
    }

    #[test]
    fn the_window_takes_the_number_of_the_request_it_was_given_into_its_title() {
        // Two approval windows are the same object in a task switcher, which
        // is where a reader answering one and seeing the next open read the
        // second as the first being clobbered. The number is what tells them
        // apart there.
        let mut state = PromptState::new();
        assert_eq!(state.take_title(), None, "a window with no request has nothing to be called");

        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        assert_eq!(
            state.take_title().as_deref(),
            Some("hatch — approval #47"),
            "the window is not wearing the number it was sent"
        );
        assert_eq!(state.take_title(), None, "it would rename the window on every frame");
    }

    #[test]
    fn a_request_nobody_numbered_leaves_the_window_the_name_it_opened_with() {
        // `hatch preview` builds one of these to draw the real window from,
        // and a preview is not the first request of anything. Nothing to
        // take means nothing is sent, and the title stays as `open_window`
        // set it.
        let mut state = PromptState::new();
        let mut request = a_request(90);
        request.number = None;
        state.handle(DaemonMsg::Request(Box::new(request)));
        assert_eq!(state.take_title(), None);
    }

    #[test]
    fn a_numbered_title_is_the_plain_one_with_the_number_on_the_end() {
        assert_eq!(numbered_title(1), format!("{WINDOW_TITLE} #1"));
        assert_eq!(numbered_title(47), "hatch — approval #47");
    }

    // ---- the standing ------------------------------------------------------

    #[test]
    fn an_approved_command_lets_go_of_the_screen() {
        // The bug. A window that is asking belongs over everything, because
        // an agent is stopped on the answer. A window watching a command it
        // already authorised is a progress indicator, and one that still
        // floated over every other window could not be put away: the reader
        // who approved a long run and went back to work could not alt-tab
        // past it.
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        assert_eq!(
            state.take_standing(),
            None,
            "a window that is asking would be restacked to where it already is"
        );

        state.decide(approved(true));
        assert_eq!(state.phase(), Phase::Running);
        assert_eq!(
            state.take_standing(),
            Some(Standing::Ordinary),
            "the window is still holding the screen over a command nobody has to answer"
        );
        assert_eq!(state.take_standing(), None, "it would say so on every frame");
    }

    #[test]
    fn the_question_a_review_asks_takes_the_screen_back() {
        // A review is not the watching: it is a second question, with a
        // deadline the daemon holds, and output nobody answers for is output
        // the agent never gets. A window that stayed where the run left it
        // could be behind three others when it starts asking.
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        state.decide(approved_for_review());
        assert_eq!(state.take_standing(), Some(Standing::Ordinary), "the run is not the question");

        state.handle(DaemonMsg::Review(a_review()));
        state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));
        assert_eq!(state.phase(), Phase::Reviewing);
        assert_eq!(
            state.take_standing(),
            Some(Standing::Insistent),
            "a question with a deadline on it is asking from behind other windows"
        );
    }

    #[test]
    fn a_window_on_its_way_out_is_not_restacked() {
        // `drawn_phase`'s argument, for the stack rather than the picture: a
        // closing window goes on being what it was for the frames it has
        // left, and asking the compositor to raise one that is already
        // leaving is a flicker at the end for nobody.
        let mut running = PromptState::new();
        running.handle(DaemonMsg::Request(Box::new(a_request(90))));
        running.decide(approved(true));
        assert_eq!(running.take_standing(), Some(Standing::Ordinary));
        running.dismiss();
        assert_eq!(running.phase(), Phase::Closed);
        assert_eq!(running.take_standing(), None, "it was raised on the way out");

        // And the other way: a window closing on a question it never got to
        // answer was on top, and stays there for the frames it has left.
        let mut asking = PromptState::new();
        asking.handle(DaemonMsg::Request(Box::new(a_request(90))));
        asking.dismiss();
        assert_eq!(asking.take_standing(), None, "it was let down on the way out");
    }

    #[test]
    fn the_ground_a_phase_is_drawn_on_and_the_standing_it_takes_agree() {
        // Not a third opinion about the phases. A window is either asking
        // something or watching something happen, `mood` is that split as a
        // colour and `standing` is that split as a place in the stack, and a
        // phase that changed its mind in one of them without the other would
        // be a window drawn as a question that anything can cover.
        for phase in [
            Phase::WaitingForRequest,
            Phase::AwaitingVerdict,
            Phase::Running,
            Phase::Lingering,
            Phase::Reviewing,
            Phase::Detached,
            Phase::Closed,
        ] {
            assert_eq!(
                standing(phase) == Standing::Insistent,
                mood(phase) == theme::Mood::Asking,
                "{phase:?} is drawn as one thing and stacked as another"
            );
        }
    }

    // ---- the wiring --------------------------------------------------------

    #[test]
    fn draining_hands_every_arrival_to_the_state_machine() {
        let mut state = PromptState::new();
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Incoming::Frame(DaemonMsg::Request(Box::new(a_request(90))))).unwrap();
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
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        let mut wire = Vec::new();

        // With a note in it, because an approval carries one and this is the
        // test that says what the frame looks like.
        let frame = state.decide(Verdict::Approve {
            stream: true,
            terminal: false,
            closing: false,
            review: false,
            note: "go on".to_string(),
        });
        answer(&mut wire, &mut state, frame);

        assert_eq!(
            String::from_utf8(wire).unwrap(),
            "{\"type\":\"verdict\",\"verdict\":\"approve\",\"stream\":true,\"terminal\":false,\
             \"closing\":false,\"review\":false,\"note\":\"go on\"}\n"
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
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
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
        state.handle(DaemonMsg::Request(Box::new(sent.clone())));

        assert_eq!(state.request(), Some(&sent), "the window would draw something else");
    }

    #[test]
    fn there_is_no_countdown_before_the_request_arrives() {
        assert_eq!(PromptState::new().seconds_remaining(Utc::now()), None);
    }

    #[test]
    fn the_countdown_stops_at_zero_rather_than_running_negative() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(-30))));

        assert_eq!(state.seconds_remaining(Utc::now()), Some(0));
    }

    // ---- the badge ---------------------------------------------------------

    #[test]
    fn the_badge_starts_at_the_depth_the_request_carried() {
        let mut state = PromptState::new();
        let mut req = a_request(90);
        req.queue_depth = 3;
        state.handle(DaemonMsg::Request(Box::new(req)));

        assert_eq!(state.queue_depth(), 3);
        assert_eq!(state.queue_badge(), Some(3));
    }

    #[test]
    fn nothing_waiting_is_not_a_badge() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));

        assert_eq!(state.queue_badge(), None);
    }

    #[test]
    fn a_running_window_does_not_draw_a_badge_about_someone_elses_queue() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        state.decide(approved(false));
        state.handle(DaemonMsg::QueueDepth { depth: 7 });

        assert_eq!(state.queue_depth(), 7, "the depth is still recorded");
        assert_eq!(state.queue_badge(), None, "but it is no longer about this window");
    }

    // ---- exactly one verdict ----------------------------------------------

    #[test]
    fn a_second_press_of_the_same_button_sends_nothing() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));

        assert!(state.decide(approved(true)).is_some());
        assert_eq!(state.decide(approved(true)), None);
    }

    #[test]
    fn a_verdict_pressed_while_the_command_runs_sends_nothing() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
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
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));

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
            state.handle(DaemonMsg::Request(Box::new(a_request(90))));
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

        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
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
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        state.decide(approved(false));
        state.handle(DaemonMsg::Finished(Outcome::Signal { signal: 9 }));

        assert_eq!(state.outcome(), Some(&Outcome::Signal { signal: 9 }));
        assert_eq!(state.broken(), None, "a signal is an outcome, not a failure");
    }

    #[test]
    fn the_daemon_hanging_up_after_the_outcome_does_not_rewrite_the_ending() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        state.decide(approved(false));
        state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));
        state.channel_broken("hatch closed the channel");

        assert_eq!(state.broken(), None);
        assert_eq!(state.outcome(), Some(&Outcome::Exit { code: 0 }));
    }

    #[test]
    fn nothing_arriving_after_the_close_can_reopen_the_window() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        state.decide(Verdict::Deny { note: String::new() });
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));

        assert!(state.should_close());
        assert_eq!(state.phase(), Phase::Closed);
    }

    // ---- lingering, and what it becomes ------------------------------------

    /// A window whose streamed command has just finished.
    fn a_lingering_state() -> PromptState {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
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
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
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
    fn keeping_is_only_possible_where_there_is_something_to_keep() {
        let mut fresh = PromptState::new();
        assert!(!fresh.keep());
        assert_eq!(fresh.phase(), Phase::WaitingForRequest);

        let mut awaiting = PromptState::new();
        awaiting.handle(DaemonMsg::Request(Box::new(a_request(90))));
        assert!(!awaiting.keep(), "a window with a question open is not a viewer");
        assert_eq!(awaiting.phase(), Phase::AwaitingVerdict);

        // A run nobody asked to watch has sent this window nothing, so a kept
        // one would be an empty viewer saying the command printed nothing.
        let mut unwatched = PromptState::new();
        unwatched.handle(DaemonMsg::Request(Box::new(a_request(90))));
        unwatched.decide(approved(false));
        assert!(!unwatched.keep(), "a run with no output to show was kept anyway");
        assert_eq!(unwatched.phase(), Phase::Running);

        let mut kept = a_lingering_state();
        assert!(kept.keep());
        assert!(!kept.keep(), "keeping twice is not keeping");
        assert_eq!(kept.phase(), Phase::Detached);
    }

    #[test]
    fn a_streamed_run_can_be_kept_before_it_has_finished_and_then_never_counts_down() {
        // "I already know I want a look at the end." A long run is exactly
        // when the reader has gone elsewhere, and the ten seconds after it
        // stops are ten seconds they are not at the keyboard for. So the
        // window never starts the countdown at all: it goes from running
        // straight to being theirs.
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        state.decide(approved(true));

        assert!(state.keep(), "a streamed run could not be kept while it ran");
        assert!(state.keeping());
        assert_eq!(state.phase(), Phase::Running, "keeping is not an ending");
        assert!(!state.keep(), "keeping twice is not keeping, in either phase");

        state.handle(DaemonMsg::Output { stream: Stream::Stdout, text: "hello\n".to_string() });
        state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));

        assert_eq!(state.phase(), Phase::Detached, "a kept window still lingered first");
        assert_eq!(
            state.linger_seconds_remaining(Instant::now()),
            None,
            "a window that was already kept started counting down anyway"
        );
        state.tick(Instant::now() + LINGER * 100);
        assert_eq!(state.phase(), Phase::Detached, "the clock took a window somebody kept");
        assert_eq!(state.output_text(), "hello\n", "the output it was kept for is gone");
    }

    #[test]
    fn keeping_a_run_that_is_never_watched_changes_none_of_the_three_endings() {
        // The control is not drawn for an unwatched run and the state machine
        // refuses it in any case, so nothing about the other two endings
        // moves: a streamed run still lingers, and a run nobody watched still
        // closes on the outcome.
        for (stream, ending) in [(true, Phase::Lingering), (false, Phase::Closed)] {
            let mut state = PromptState::new();
            state.handle(DaemonMsg::Request(Box::new(a_request(90))));
            state.decide(approved(stream));
            state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));

            assert_eq!(state.phase(), ending, "streaming {stream} ended as {:?}", state.phase());
            assert!(!state.keeping(), "a window nobody kept says it was kept");
        }
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
            app.act(&egui::Context::default(), action);
            assert_eq!(app.state.phase(), after, "{action:?}");
            assert!(sink.lock().unwrap().is_empty(), "{action:?} answered a request that is over");
        }

        let (mut app, sink) = a_finished_window();
        assert!(app.state.keep());
        app.act(&egui::Context::default(), Action::Approve);
        assert_eq!(app.state.phase(), Phase::Detached);
        app.act(&egui::Context::default(), Action::Deny);
        assert_eq!(app.state.phase(), Phase::Closed);
        assert!(sink.lock().unwrap().is_empty(), "a detached viewer wrote to the daemon");
    }

    #[test]
    fn what_would_be_copied_is_what_is_on_the_screen() {
        // One string, built once, so the button cannot drift from the view.
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
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
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));

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
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
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
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
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
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
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
        let request = protocol::encode(&DaemonMsg::Request(Box::new(a_request(90)))).unwrap();
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
        let request = protocol::encode(&DaemonMsg::Request(Box::new(a_request(90)))).unwrap();
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
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        state.handle(DaemonMsg::QueueDepth { depth: 4 });

        assert_eq!(state.phase(), Phase::AwaitingVerdict);
        assert_eq!(state.queue_depth(), 4);
    }

    #[test]
    fn approve_moves_to_running_and_the_window_stays_open() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));

        assert!(state.decide(approved(true)).is_some());
        assert_eq!(state.phase(), Phase::Running);
        assert!(!state.should_close());
    }

    #[test]
    fn finished_closes_the_window() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        state.decide(approved(false));
        state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));

        assert!(state.should_close());
    }

    #[test]
    fn countdown_comes_from_the_deadline_not_a_local_timer() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(42))));

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
        an_awaiting_window_remembering(PrefsFile::none())
    }

    /// The same window, with somewhere to keep its display preferences.
    ///
    /// Almost every test here wants nowhere, which is what
    /// [`an_awaiting_window`] gives: a window under test must not read or
    /// write the preferences of whoever is running the suite.
    fn an_awaiting_window_remembering(
        prefs: PrefsFile,
    ) -> (PromptApp, Arc<std::sync::Mutex<Vec<u8>>>) {
        let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app =
            PromptApp::new(rx, Box::new(Sink(Arc::clone(&sink))), Arc::new(OnceLock::new()), prefs);
        app.state.handle(DaemonMsg::Request(Box::new(a_request(90))));
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

    // ---- closing on the verdict -------------------------------------------

    /// Where the close control's label is on screen, read off a real frame.
    fn close_box_at(app: &mut PromptApp, ctx: &egui::Context) -> egui::Pos2 {
        let mut out = ctx.run_ui(raw(Vec::new()), |ui| {
            egui::CentralPanel::default().show(ui, |ui| app.verdict_area(ui, true));
        });
        let found = text_rects(&out.shapes)
            .into_iter()
            .find(|(text, _)| text == CLOSE_LABEL)
            .map(|(_, rect)| rect.center());
        out.textures_delta.clear();
        found.expect("the close control is not on screen")
    }

    /// Press and release the mouse on the close control, the way a hand would.
    fn click_close_box(app: &mut PromptApp) {
        let ctx = egui::Context::default();
        apply_font_size(&ctx, 16.0);
        let at = close_box_at(app, &ctx);
        let button = |pressed| egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        draw(app, &ctx, vec![egui::Event::PointerMoved(at)], true);
        draw(app, &ctx, vec![button(true)], true);
        draw(app, &ctx, vec![button(false)], true);
    }

    /// A state directory of our own, as the daemon would have left one.
    fn a_prefs_file() -> (tempfile::TempDir, crate::paths::Paths) {
        let root = tempfile::tempdir().expect("a scratch directory");
        let paths = crate::paths::Paths::scratch(root.path());
        std::fs::create_dir_all(paths.prefs_file().parent().expect("a parent"))
            .expect("the state directory");
        (root, paths)
    }

    #[test]
    fn ticking_the_box_writes_it_down_and_the_next_window_opens_with_it() {
        // The whole of "it persists", through the real checkbox: a pointer
        // presses it, a file is written, and the next window — a different
        // process, in the life this window actually has — starts with it
        // ticked.
        let (_root, paths) = a_prefs_file();
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));
        assert!(!app.closes_on_decide(), "a window starts by staying");

        click_close_box(&mut app);
        assert!(app.closes_on_decide(), "the click did not reach the box");
        assert!(
            PrefsFile::at(&paths).read().close_on_decide,
            "the box was ticked and nothing was written down"
        );

        let (next, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));
        assert!(next.closes_on_decide(), "the next window opened having forgotten");
    }

    #[test]
    fn unticking_it_is_written_down_too() {
        // The other direction, which a window that only ever wrote a tick
        // would get wrong: the preference would be unsettable once set.
        let (_root, paths) = a_prefs_file();
        PrefsFile::at(&paths).write(&Prefs { close_on_decide: true, ..Prefs::default() });

        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));
        assert!(app.closes_on_decide());
        click_close_box(&mut app);
        assert!(!app.closes_on_decide(), "the click did not reach the box");
        assert!(!PrefsFile::at(&paths).read().close_on_decide, "the untick was not written down");
    }

    #[test]
    fn a_window_with_nowhere_to_write_still_ticks() {
        // A prompt started somewhere the daemon has never been. The
        // preference is lost, the window is not.
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::none());
        click_close_box(&mut app);
        assert!(app.closes_on_decide(), "a window that cannot save cannot be ticked either");
    }

    #[test]
    fn the_approval_a_ticked_box_sends_says_the_window_is_going() {
        // The daemon cannot tell a deliberate close from a crash by looking,
        // so the frame has to say. See `crate::audit::PromptEnd`.
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::none());
        click_close_box(&mut app);
        assert_eq!(
            app.approval(),
            Verdict::Approve {
                stream: false,
                terminal: false,
                closing: true,
                review: false,
                note: String::new()
            }
        );
    }

    #[test]
    fn a_verdict_that_says_it_is_closing_ends_the_window_on_the_frame_it_sent() {
        // The approval still leaves — the command is authorised by the frame
        // this hands back — and the window is over as soon as it has.
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        let frame = state.decide(Verdict::Approve {
            stream: false,
            terminal: false,
            closing: true,
            review: false,
            note: String::new(),
        });
        assert!(frame.is_some(), "a closing window still has to send its approval");
        assert_eq!(state.phase(), Phase::Closed);
        assert!(state.should_close());
        assert_eq!(state.broken(), None, "a window that was asked to go has nothing to report");
    }

    #[test]
    fn a_window_that_closed_on_its_verdict_cannot_kill_or_decide_again() {
        // It is past `AwaitingVerdict` and nothing returns there, which is the
        // same guarantee every other verdict already had.
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        state.decide(Verdict::Approve {
            stream: false,
            terminal: false,
            closing: true,
            review: false,
            note: String::new(),
        });
        assert_eq!(state.request_kill(), None, "a window that has gone offered a Kill button");
        assert_eq!(state.decide(approved(false)), None, "it answered twice");
    }

    #[test]
    fn watching_a_command_beats_a_standing_order_to_close_and_says_so() {
        // Two instructions that contradict each other. The one given in front
        // of this command wins, the window says which, and the preference is
        // not quietly rewritten on the way past.
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::none());
        click_close_box(&mut app);
        app.stream = true;

        assert!(!app.closes_on_decide(), "it would have closed over the output it was asked for");
        assert!(app.close_on_decide, "the standing preference was overwritten rather than beaten");
        let said = window_text_sized(&mut app, opening_size());
        assert!(said.contains(CLOSE_WATCHING), "the window ignored one of the two in silence");

        app.stream = false;
        assert!(app.closes_on_decide(), "unticking Stream did not give the preference back");
    }

    #[test]
    fn a_terminal_run_is_not_a_reason_to_stay() {
        // The terminal is a window of its own and the reader is about to be
        // in front of it; hatch's window behind it shows them nothing.
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::none());
        click_close_box(&mut app);
        app.terminal = true;

        assert!(app.in_a_terminal());
        assert!(app.closes_on_decide(), "a terminal run kept a window nobody was going to read");
    }

    #[test]
    fn the_cost_of_closing_is_on_screen_before_it_is_incurred() {
        // Beside the control, at the window's own size, in the frame a reader
        // decides in — not in a tooltip, for the reason the terminal warning
        // gives.
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::none());
        let said = window_text_sized(&mut app, opening_size());
        assert!(said.contains(CLOSE_LABEL), "the control is not drawn: {said}");
        assert!(said.contains(CLOSE_COST), "what it costs is not said: {said}");
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
        app.act(&egui::Context::default(), Action::Approve);
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
        request.operations = vec![Payload::command(
            &render_command(command, &BTreeMap::new()),
            Vec::new(),
            PathBuf::from("/tmp"),
            true,
            false,
        )];
        app.state = PromptState::new();
        app.state.handle(DaemonMsg::Request(Box::new(request)));
        app
    }

    /// A window awaiting a verdict on `command`, which runs in a terminal of
    /// its own and so cannot be streamed to this one.
    fn an_interactive_window_showing(command: &str) -> PromptApp {
        let mut app = a_window_showing(command);
        let mut request = a_request(90);
        request.operations = vec![Payload::command(
            &render_command(command, &BTreeMap::new()),
            Vec::new(),
            PathBuf::from("/tmp"),
            false,
            true,
        )];
        app.state = PromptState::new();
        app.state.handle(DaemonMsg::Request(Box::new(request)));
        app
    }

    /// A window awaiting a verdict on `command`.
    fn a_window_showing(command: &str) -> PromptApp {
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app =
            PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
        let mut request = a_request(90);
        request.operations = vec![Payload::command(
            &render_command(command, &BTreeMap::from([("HOME".into(), "/home/u".into())])),
            Vec::new(),
            PathBuf::from("/tmp"),
            false,
            false,
        )];
        app.state.handle(DaemonMsg::Request(Box::new(request)));
        app
    }

    #[test]
    fn every_key_the_guard_takes_is_printed_on_the_control_it_works() {
        // The rule this file keeps for the buttons, kept for everything: a
        // shortcut nobody can see is discoverable by reading the source, and
        // a window whose fastest controls are secrets is one people work
        // slowly and carefully around. `guard::with_chord` is where a label
        // acquires its chord; this is what stops a control acquiring a key
        // without going through it.
        //
        // Read off drawn frames rather than from the constants, because the
        // failure being guarded against is exactly a chord that exists in
        // `guard` and reaches no screen -- which a test over the constants
        // alone would pass.
        let asking = window_text_sized(&mut a_window_showing("rm -rf target"), opening_size());
        for chord in [
            guard::APPROVE_CHORD,
            guard::DENY_CHORD,
            guard::STREAM_CHORD,
            guard::CLOSE_CHORD,
            guard::REVIEW_CHORD,
        ] {
            assert!(asking.contains(chord), "{chord:?} works here and is not on screen: {asking}");
        }

        // A dead box keeps saying which key it is. Being unavailable is not
        // being unexplained, and a chord that vanished when its box greyed
        // out would teach the reader it had stopped existing -- see
        // `REFUSAL_NOTICE`, which is what the key actually does there.
        let mut streaming = a_window_showing("rm -rf target");
        streaming.set_stream(true);
        let drawn = window_text_sized(&mut streaming, opening_size());
        assert!(
            drawn.contains(guard::CLOSE_CHORD),
            "the close box went quiet about its key when it went grey: {drawn}"
        );

        let finished = window_text(&mut a_finished_window_showing("echo marker", "printed\n"), true);
        for chord in [guard::KEEP_KEYS, guard::COPY_CHORD, guard::DENY_CHORD] {
            assert!(
                finished.contains(chord),
                "{chord:?} works on a finished window and is not on it: {finished}"
            );
        }

        let (mut app, _sink) = a_reviewing_window();
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let shapes = a_settled_frame(&mut app, &ctx, past_the_guard());
        let reviewing: String =
            text_rects(&shapes).into_iter().map(|(text, _)| text + "\n").collect();
        // Paging has no button to print its key on, so the promise is kept
        // the only way it can be here: a line beside the output it moves.
        for chord in [guard::APPROVE_CHORD, guard::DENY_CHORD, guard::PAGE_KEYS] {
            assert!(
                reviewing.contains(chord),
                "{chord:?} answers a review and is not on its screen: {reviewing}"
            );
        }
    }

    #[test]
    fn a_window_says_what_ended_without_the_reader_and_an_ordinary_one_says_nothing() {
        use chrono::TimeZone as _;

        // The ordinary window first, because the cost of this feature is a
        // row on every window that has nothing to report, and it must not
        // have one.
        let mut quiet = a_window_showing("rm -rf target");
        let drawn = window_text_sized(&mut quiet, opening_size());
        assert!(!drawn.contains("ended without you"), "an ordinary window reported a loss: {drawn}");

        // And one that has something to say. This is the report it exists
        // for: a window that vanished while the reader was elsewhere, which
        // from their side is indistinguishable from a denial they do not
        // remember making.
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app =
            PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
        let mut request = a_request(90);
        request.unanswered = vec![protocol::Unanswered {
            number: Some(46),
            at: chrono::Utc.timestamp_opt(1_770_000_000, 0).unwrap(),
            how: protocol::Unheard::AgentLeft,
        }];
        app.state.handle(DaemonMsg::Request(Box::new(request)));
        let drawn = window_text_sized(&mut app, opening_size());
        assert!(drawn.contains("Window 46 ended without you"), "{drawn}");
        assert!(drawn.contains("the agent stopped waiting"), "{drawn}");
        assert!(drawn.contains("Nothing ran."), "{drawn}");
        // It is news about a window that is gone, so it does not claim to be
        // about the one being asked about now.
        assert!(drawn.contains("rm -rf") || drawn.contains("delete"), "{drawn}");
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
    fn a_disguised_character_is_chipped_in_whichever_rendering_is_showing() {
        // Cyrillic a and a right-to-left override. One rendering is on screen
        // at a time now, and each of them chips: the original is not the one
        // that gets to be honest second.
        let mut app = a_window_showing("echo us\u{0430}r\u{202e}");
        let drawn = window_text(&mut app, true);
        assert_eq!(drawn.matches("[U+0430]").count(), 1, "not chipped annotated: {drawn}");
        assert_eq!(drawn.matches("[RLO]").count(), 1, "not chipped annotated: {drawn}");

        app.set_show_original(true);
        let drawn = window_text(&mut app, true);
        assert_eq!(drawn.matches("[U+0430]").count(), 1, "not chipped in the original: {drawn}");
        assert_eq!(drawn.matches("[RLO]").count(), 1, "not chipped in the original: {drawn}");
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
        let mut app =
            PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
        let mut request = a_request(45);
        request.queue_depth = 2;
        app.state.handle(DaemonMsg::Request(Box::new(request)));

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
        let mut app =
            PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
        let mut request = a_request(90);
        request.operations = vec![Payload::command(
            &render_command("id", &BTreeMap::new()),
            Vec::new(),
            PathBuf::from("/srv/app"),
            true,
            false,
        )];
        app.state.handle(DaemonMsg::Request(Box::new(request)));

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
        request.operations = app.state.request().expect("a request").operations.clone();
        app.state = PromptState::new();
        app.state.handle(DaemonMsg::Request(Box::new(request)));

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
        let mut app =
            PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
        let mut request = a_request(90);
        request.operations = vec![Payload::command(
            &render_command("rm -rf /", &BTreeMap::new()),
            vec!["deletes a directory tree".to_string()],
            PathBuf::from("/tmp"),
            false,
            false,
        )];
        app.state.handle(DaemonMsg::Request(Box::new(request)));

        let drawn = window_text(&mut app, true);

        assert!(
            drawn.contains("deletes a directory tree"),
            "a marker the daemon found never reached the window: {drawn}"
        );
    }

    #[test]
    fn a_swap_never_draws_an_empty_pane_that_reads_as_nothing_changing() {
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app =
            PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
        let mut request = a_request(90);
        request.operations = vec![Payload::swap(
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
        )];
        app.state.handle(DaemonMsg::Request(Box::new(request)));

        let drawn = window_text(&mut app, true);

        assert!(drawn.contains("/tmp/conf.toml"), "the file is not named: {drawn}");
        assert!(drawn.contains("0644"), "the landing mode is missing: {drawn}");
        assert!(drawn.contains("port = 8080"), "the proposed line was never drawn: {drawn}");
        assert!(drawn.contains("port = 80"), "the current line was never drawn: {drawn}");
    }

    #[test]
    fn a_command_in_its_own_terminal_says_why_it_cannot_be_streamed_here() {
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app =
            PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
        let mut request = a_request(90);
        request.operations = vec![Payload::command(
            &render_command("vim /etc/hosts", &BTreeMap::new()),
            Vec::new(),
            PathBuf::from("/tmp"),
            false,
            true,
        )];
        app.state.handle(DaemonMsg::Request(Box::new(request)));

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
        // It is drawn unticked rather than greyed with a tick still in it: a
        // ticked box that cannot be unticked reads as a promise to stream,
        // and nothing is going to.
        let mut app = a_window_showing("pacman -Syu");
        app.stream = true;
        app.terminal = true;
        let drawn = window_text(&mut app, true);

        assert!(!app.streams(), "a terminal run has no stream to promise");
        assert!(
            drawn.contains("terminal of its own"),
            "a checkbox that went dead was left unexplained: {drawn}"
        );
        assert!(
            matches!(app.approval(), Verdict::Approve { stream: false, terminal: true, .. }),
            "got {:?}",
            app.approval()
        );
        // And the reader's own answer is untouched underneath, so a command
        // that wanted a terminal has not also unticked a standing preference.
        assert!(app.stream, "the terminal took the remembered answer with it");
    }

    #[test]
    fn a_swap_offers_no_checkbox_for_output_it_will_never_produce() {
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app =
            PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
        let mut request = a_request(90);
        request.operations = vec![Payload::swap(
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
        )];
        app.state.handle(DaemonMsg::Request(Box::new(request)));

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
        let Payload::Command { spans, raw, danger, runs, cwd, root, interactive, .. } =
            request.operations.remove(0)
        else {
            panic!("not a command")
        };
        // A one-line form that does not match the spans it claims to
        // summarise: the two halves of the window would describe different
        // commands.
        request.operations = vec![Payload::Command {
            display_line: "something else entirely".to_string(),
            spans,
            raw,
            danger,
            runs,
            cwd,
            root,
            interactive,
            caveat: None,
            program: None,
        }];

        state.handle(DaemonMsg::Request(Box::new(request)));

        assert!(state.should_close(), "the window drew a frame it could not check");
        assert!(state.broken().is_some(), "and it did not say why");
        assert_eq!(state.phase(), Phase::Closed);
        assert!(state.shown().is_none(), "it kept something to draw anyway");
    }

    #[test]
    fn a_request_that_can_be_drawn_is_kept_in_its_checked_form() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));

        assert!(state.shown().is_some(), "the window has nothing to draw");
        assert_eq!(state.phase(), Phase::AwaitingVerdict);
    }

    #[test]
    fn a_request_for_more_operations_than_this_window_draws_closes_it() {
        // A window draws one operation. Handed three, the only thing it could
        // do short of closing is draw the first -- and then the approval it
        // sends would cover two operations nobody was shown. Closing is read
        // by the daemon as a denial, which is the direction every other frame
        // this window cannot believe already fails in. And none at all is not
        // a request anybody can approve either.
        for count in [0, 2, 3] {
            let mut state = PromptState::new();
            let mut request = a_request(90);
            let one = request.operations[0].clone();
            request.operations = vec![one; count];

            state.handle(DaemonMsg::Request(Box::new(request)));

            assert!(state.should_close(), "a window accepted a request of {count} operations");
            let why = state.broken().expect("and it did not say why");
            assert!(why.contains(&count.to_string()), "{why}");
            assert!(state.operations().is_empty(), "it kept something to draw anyway");
            assert!(
                state.decide(crate::protocol::approved(false)).is_none(),
                "a window that refused a request can still approve it"
            );
        }
    }

    #[test]
    fn what_happens_after_a_failure_is_stated_only_where_there_is_an_after() {
        // One operation has nothing after it, so the window says nothing
        // about stopping or carrying on -- in either policy, because a line
        // that is true of every window is a line nobody reads.
        for stop_on_failure in [true, false] {
            let mut request = a_request(90);
            request.stop_on_failure = stop_on_failure;
            let mut state = PromptState::new();
            state.handle(DaemonMsg::Request(Box::new(request)));
            assert_eq!(state.sequencing(), None, "one operation was given a sequence to state");
        }

        // Two operations have one, and each policy reads as itself and
        // neither reads as a caution. The window that draws two does not
        // exist yet; the sentence it will draw does, so it is pinned here
        // rather than written on the day the cap lifts.
        let sentence = |stop_on_failure| {
            let mut state = PromptState::new();
            let mut request = a_request(90);
            let one = request.operations[0].clone();
            request.operations = vec![one.clone(), one];
            request.stop_on_failure = stop_on_failure;
            state.request = Some(request);
            state.sequencing().expect("two operations have a sequence").to_string()
        };
        let (stops, runs_on) = (sentence(true), sentence(false));
        assert_ne!(stops, runs_on, "the two policies read as one");
        assert!(stops.contains("stops"), "{stops}");
        assert!(runs_on.contains("every operation"), "{runs_on}");
        for text in [&stops, &runs_on] {
            for alarm in ["warning", "careful", "danger", "!"] {
                assert!(!text.to_lowercase().contains(alarm), "a fact reads as a warning: {text}");
            }
        }
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
        window_shapes_while(app, size, true)
    }

    /// The same, drawn with the typing guard in a given state.
    ///
    /// `false` is what every window looks like for the first 750 ms of every
    /// focus it gains, which is a state two claims below are about: what the
    /// window says then, and what it costs the panes to say it.
    fn window_shapes_while(
        app: &mut PromptApp,
        size: egui::Vec2,
        open: bool,
    ) -> Vec<egui::epaint::ClippedShape> {
        let ctx = egui::Context::default();
        theme::apply(&ctx, theme::Theme::Dark);
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        // Three frames: a panel learns its height from the frame before, so a
        // pane measured against the first frame's guess is not the pane a
        // reader sees.
        for _ in 0..2 {
            let mut out = ctx.run_ui(raw_sized(Vec::new(), size), |ui| app.window(ui, open));
            out.textures_delta.clear();
        }
        let mut out = ctx.run_ui(raw_sized(Vec::new(), size), |ui| app.window(ui, open));
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
        // Neither is a scroll bar's track, which egui paints in the same
        // `extreme_bg_color` — it is as tall as the pane it belongs to and
        // ten points wide, so width is what tells the two apart.
        out.retain(|rect| rect.height() > 60.0 && rect.width() > 60.0);
        out
    }

    /// How many points of the window's height the panes cover.
    fn pane_height(app: &mut PromptApp, size: egui::Vec2) -> f32 {
        pane_height_while(app, size, true)
    }

    /// The same, with the guard open or shut.
    fn pane_height_while(app: &mut PromptApp, size: egui::Vec2, open: bool) -> f32 {
        let shapes = window_shapes_while(app, size, open);
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
    fn a_long_command_gets_the_whole_area_to_be_read_in() {
        // What replaced the split. Stacking existed because a long command
        // needed room and an even division handed the least of it to the case
        // that needed the most; one pane is the same argument taken to its
        // end. There is one pane and it has the area, so the worst case for
        // reading is also the best case the window can offer.
        let long = (0..12)
            .map(|i| format!("docker build --pull --no-cache -t registry.internal/thing:{i} ."))
            .collect::<Vec<_>>()
            .join("\n");
        let mut app = a_window_showing(&long);
        let shapes = window_shapes(&mut app, opening_size());
        let boxes = pane_boxes(&shapes);

        assert_eq!(boxes.len(), 1, "the command area drew more than one pane: {boxes:?}");
        assert!(
            boxes[0].height() > 0.4 * WINDOW_SIZE[1],
            "the one pane got {} of a {} window",
            boxes[0].height(),
            WINDOW_SIZE[1]
        );
    }

    // ---- the keys a finished window answers to ----------------------------

    /// Press one key on a window in the phase it is in, through the real
    /// door: [`intercept`] classifies it, [`PromptApp::act`] carries it out.
    ///
    /// Not [`PromptApp::act`] on its own, because the claim being made is
    /// about a keypress: a key the guard hands back as `Passthrough` and
    /// nothing acts on would pass every test that started at an [`Action`].
    fn press_key(app: &mut PromptApp, key: egui::Key, modifiers: egui::Modifiers) {
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        let now = past_the_guard();
        a_live_frame(app, &ctx, vec![chord(key, modifiers)], now);
    }

    #[test]
    fn three_keys_keep_the_window_and_each_of_them_stops_the_countdown() {
        // Three for one action, which nothing else here gets. It is the only
        // control in hatch with a deadline on it: ten seconds, mid-read, and
        // until now the only way to stop it was to find the mouse.
        for key in [egui::Key::E, egui::Key::O, egui::Key::Space] {
            let (mut app, sink) = a_finished_window();
            press_key(&mut app, key, egui::Modifiers::NONE);

            assert_eq!(app.state.phase(), Phase::Detached, "{key:?} did not keep the window");
            assert!(app.state.linger_seconds_remaining(Instant::now()).is_none());
            // And the thread that would otherwise end this process in twelve
            // seconds has been told, which the button is not the only way to
            // reach.
            assert!(
                app.kept.load(Ordering::SeqCst),
                "{key:?} kept a window the backstop will kill anyway"
            );
            assert!(
                sink.lock().expect("sink").is_empty(),
                "{key:?} wrote to a daemon that has gone"
            );
        }
    }

    #[test]
    fn escape_closes_the_finished_window_and_enter_still_means_nothing() {
        // Enter is deliberately unbound. Nothing in hatch answers a bare
        // Enter, and the reflex is that it confirms -- so somebody hammering
        // it at an approval would otherwise close the viewer at the instant
        // it appeared.
        let (mut app, _sink) = a_finished_window();
        press_key(&mut app, egui::Key::Enter, egui::Modifiers::NONE);
        assert_eq!(app.state.phase(), Phase::Lingering, "bare Enter did something");

        press_key(&mut app, egui::Key::Escape, egui::Modifiers::NONE);
        assert_eq!(app.state.phase(), Phase::Closed, "Escape did not put the window away");
    }

    #[test]
    fn alt_c_on_a_finished_window_takes_the_output_and_says_it_did() {
        // The output and not the command: it is what the reader stayed for,
        // and one chord may mean one thing. See `guard::COPY_CHORD`.
        let mut app = a_finished_window_showing("echo marker", "a line it printed\n");
        press_key(&mut app, egui::Key::C, egui::Modifiers::ALT);

        assert!(app.copied.is_some(), "the window said nothing about having copied anything");
        assert_eq!(app.state.phase(), Phase::Lingering, "a copy moved the window on");
    }

    #[test]
    fn the_letters_that_keep_a_finished_window_are_still_letters_while_one_is_asked() {
        // The whole reason the verdict phase is on chords: the note field
        // holds the text focus there, and a window where `e` means something
        // other than the letter `e` eats what you type into it. The keys
        // below are free afterwards only because that field has gone with the
        // question.
        let (mut app, _sink) = an_awaiting_window();
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        let now = past_the_guard();
        click_into_the_note_field(&mut app, &ctx, now);

        let typed = vec![
            chord(egui::Key::E, egui::Modifiers::NONE),
            egui::Event::Text("e".to_string()),
            chord(egui::Key::O, egui::Modifiers::NONE),
            egui::Event::Text("o".to_string()),
            chord(egui::Key::Space, egui::Modifiers::NONE),
            egui::Event::Text(" ".to_string()),
        ];
        a_live_frame(&mut app, &ctx, typed, now);

        assert_eq!(app.note, "eo ", "the viewer's keys ate what was typed into the note");
        assert_eq!(app.state.phase(), Phase::AwaitingVerdict, "a letter answered the window");
    }

    #[test]
    fn a_finished_window_says_which_keys_keep_it_take_it_and_close_it() {
        // A shortcut nobody can see is a shortcut nobody has, and these are
        // drawn from the guard's own strings, so this cannot pass against a
        // label the rule does not accept.
        let mut app = a_finished_window_showing("echo marker", "a line it printed\n");

        let drawn = window_text(&mut app, true);

        assert!(drawn.contains(guard::KEEP_KEYS), "no key is offered for Keep: {drawn}");
        assert!(drawn.contains(guard::COPY_CHORD), "no key is offered for the output: {drawn}");
        assert!(drawn.contains(guard::DENY_CHORD), "no key is offered for Close: {drawn}");
    }

    #[test]
    fn the_keys_on_the_finished_window_did_not_widen_the_row_they_are_on() {
        // Keep and Close share one centred row exactly as wide as the cluster
        // the verdict buttons were centred in, and the hints are drawn inside
        // the buttons. A pair that outgrew that row would push Close out of
        // the middle of a window the reader is looking at the middle of.
        let mut app = a_finished_window_showing("echo marker", "a line it printed\n");
        let drawn = window_shapes(&mut app, opening_size());
        let rects = text_rects(&drawn);
        let at = |want: &str| {
            rects
                .iter()
                .find(|(text, _)| text == want)
                .map(|(_, rect)| *rect)
                .unwrap_or_else(|| panic!("{want} is not on screen: {}", shapes_text(&drawn)))
        };
        let (keep, close) = (at("Keep this window"), at("Close"));

        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let mut cluster = 0.0;
        let mut out = ctx.run_ui(raw_sized(Vec::new(), opening_size()), |ui| {
            cluster = cluster_width(ui);
        });
        out.textures_delta.clear();

        assert!(
            (keep.center().y - close.center().y).abs() < 2.0,
            "Keep is at {keep:?} and Close at {close:?}: not one row"
        );
        assert!(
            keep.union(close).width() <= cluster,
            "the pair spans {} against the {cluster} the row is given",
            keep.union(close).width()
        );
    }

    // ---- keeping a window before its command has finished -----------------

    /// A window whose streamed command is still running.
    fn a_running_window() -> (PromptApp, Arc<std::sync::Mutex<Vec<u8>>>) {
        let (mut app, sink) = an_awaiting_window();
        app.state.decide(approved(true));
        assert_eq!(app.state.phase(), Phase::Running);
        (app, sink)
    }

    /// A window showing `command`, approved and streaming.
    fn a_running_window_showing(command: &str, stream: bool) -> PromptApp {
        let mut app = a_window_showing(command);
        app.state.decide(approved(stream));
        app
    }

    #[test]
    fn the_same_three_keys_keep_a_window_whose_command_is_still_running() {
        // The same action offered one phase earlier, so the same keys do it.
        // One key meaning one thing in two phases is the opposite of a
        // collision.
        for key in [egui::Key::E, egui::Key::O, egui::Key::Space] {
            let (mut app, sink) = a_running_window();
            press_key(&mut app, key, egui::Modifiers::NONE);

            assert!(app.state.keeping(), "{key:?} did not keep the running window");
            assert_eq!(app.state.phase(), Phase::Running, "{key:?} ended the run");
            assert!(
                app.kept.load(Ordering::SeqCst),
                "{key:?} kept a window the backstop will kill anyway"
            );

            app.state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));
            assert_eq!(app.state.phase(), Phase::Detached, "{key:?} left a countdown behind");
            assert!(sink.lock().expect("sink").is_empty(), "{key:?} wrote to the daemon");
        }
    }

    #[test]
    fn escape_does_not_take_away_a_running_window_or_the_kill_button_on_it() {
        // The command is still going. A window that vanished on a keypress
        // would take the only way to stop it with it.
        let (mut app, sink) = a_running_window();

        press_key(&mut app, egui::Key::Escape, egui::Modifiers::NONE);

        assert_eq!(app.state.phase(), Phase::Running, "Escape closed a window mid-run");
        assert!(sink.lock().expect("sink").is_empty(), "Escape answered something");
        assert!(window_text(&mut app, true).contains("Kill"), "the Kill button went");
    }

    #[test]
    fn a_running_window_offers_to_be_kept_only_while_somebody_is_watching_it() {
        // A run nobody asked to stream has sent this window nothing, so the
        // window it would be kept as is an empty one claiming the command
        // printed nothing.
        let watched = window_text(&mut a_running_window_showing("sleep 30", true), true);
        assert!(watched.contains("Keep this window"), "a watched run cannot be kept: {watched}");
        assert!(watched.contains("Kill"), "{watched}");

        let unwatched = window_text(&mut a_running_window_showing("sleep 30", false), true);
        assert!(
            !unwatched.contains("Keep this window"),
            "a run with nothing to show offered to be kept: {unwatched}"
        );
        assert!(unwatched.contains("Kill"), "the Kill button went with it: {unwatched}");
    }

    #[test]
    fn a_kept_running_window_says_so_where_the_button_was_and_moves_nothing_else() {
        // A keypress has no click to be seen, so a control that simply
        // vanished would leave the reader wondering whether the key worked.
        // It is said in the place the button was and at the size it was,
        // because the window is being read while this happens.
        let mut app = a_running_window_showing("sleep 30", true);
        let before = text_rects(&window_shapes(&mut app, opening_size()));
        let at = |rects: &[(String, egui::Rect)], want: &str| {
            rects
                .iter()
                .find(|(text, _)| text == want)
                .map(|(_, rect)| *rect)
                .unwrap_or_else(|| panic!("{want} is not on screen"))
        };
        let (keep, kill) = (at(&before, "Keep this window"), at(&before, "Kill"));

        assert!(app.state.keep());
        let after = text_rects(&window_shapes(&mut app, opening_size()));

        assert!(
            !after.iter().any(|(text, _)| text == "Keep this window"),
            "a window that has been kept still offers to be kept"
        );
        let said = at(&after, KEPT_RUNNING);
        assert!(
            (said.center().y - keep.center().y).abs() < 2.0,
            "the sentence is at {said:?} and the button was at {keep:?}"
        );
        assert_eq!(at(&after, "Kill"), kill, "keeping the window moved the Kill button");
    }

    // ---- what the guard says, and what saying it costs --------------------

    #[test]
    fn the_sentence_the_guard_draws_costs_the_command_no_row() {
        // The bug. The sentence was a label in the bottom panel, a bottom
        // panel takes its height out of the window before the panes above it
        // are laid out, and so the command was a row shorter for as long as
        // the guard was shut -- then jumped up by that row when it opened, on
        // every focus gain rather than once. Painted, it costs nothing, and
        // the two heights are the same number.
        let mut app = a_window_showing("rm -rf /var/tmp/build && echo 'cleared'");
        let shut = pane_height_while(&mut app, opening_size(), false);
        let open = pane_height_while(&mut app, opening_size(), true);

        assert!(
            (shut - open).abs() < 1.0,
            "the panes are {shut} points while the guard is shut and {open} after it opens, \
             so the command moves under the reader"
        );
    }

    #[test]
    fn the_sentence_is_painted_across_the_buttons_that_are_not_answering() {
        // Where the reader is already looking -- on the controls that are not
        // responding -- rather than on a line below them. Asked of the
        // rectangles egui laid out, because "over the buttons" is a claim
        // about position and not about the order two calls are made in.
        let mut app = a_window_showing("sleep 1");
        let drawn = window_shapes_while(&mut app, opening_size(), false);
        let rects = text_rects(&drawn);
        let notice = rects
            .iter()
            .find(|(text, _)| text == GUARD_NOTICE)
            .map(|(_, rect)| *rect)
            .unwrap_or_else(|| panic!("the window said nothing: {}", shapes_text(&drawn)));
        let approve = rects
            .iter()
            .find(|(text, _)| text == "Approve")
            .map(|(_, rect)| *rect)
            .expect("Approve is not on screen at all");

        assert!(
            notice.intersects(approve),
            "the sentence is at {notice:?} and Approve is at {approve:?}: not over it"
        );
    }

    #[test]
    fn the_sentence_is_gone_the_moment_the_buttons_are_live() {
        let mut app = a_window_showing("sleep 1");
        let said = window_text(&mut app, true);

        assert!(
            !said.contains(GUARD_NOTICE),
            "the window is still saying it is waiting for the guard: {said}"
        );
    }

    #[test]
    fn a_pointer_where_the_sentence_was_painted_approves_once_the_guard_opens() {
        // Painted is why it cannot eat the click: there is no widget over
        // Approve to find the pointer first, and nothing to become stale
        // either. The point pressed is inside both rectangles, which is what
        // makes this a test of the sentence rather than of the button.
        let (mut app, sink) = an_awaiting_window();
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let inside = Instant::now();

        a_settled_frame(&mut app, &ctx, inside);
        let drawn = a_live_frame(&mut app, &ctx, Vec::new(), inside);
        let rects = text_rects(&drawn);
        let notice = rects
            .iter()
            .find(|(text, _)| text == GUARD_NOTICE)
            .map(|(_, rect)| *rect)
            .expect("the sentence is not on screen while the guard is shut");
        let at = rects
            .iter()
            .find(|(text, _)| text == "Approve")
            .map(|(_, rect)| rect.center())
            .expect("Approve is not on screen");
        assert!(notice.contains(at), "the sentence is not over the point about to be pressed");

        let now = past_the_guard();
        let button = |pressed| egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        a_live_frame(&mut app, &ctx, vec![egui::Event::PointerMoved(at)], now);
        a_live_frame(&mut app, &ctx, vec![button(true)], now);
        a_live_frame(&mut app, &ctx, vec![button(false)], now);

        let out = String::from_utf8(sink.lock().expect("sink").clone()).expect("utf-8");
        assert!(out.contains("approve"), "the click did not reach Approve at all: {out:?}");
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
        let (approve, _) = approve.expect("the row drew");
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
        let (approve, _) = approve.expect("the row drew");
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
    fn each_rendering_says_what_it_promises() {
        // Two panes meant one caption naming both. One pane means the caption
        // is about the thing in front of the reader -- and the promise each
        // rendering makes has to survive the change, because the promise is
        // the reason either of them is trustworthy.
        let mut app = a_window_showing("ls -l");
        let drawn = window_text(&mut app, true);
        assert!(
            drawn.contains("hatch's notes, not the command"),
            "the annotated rendering's warning is gone: {drawn}"
        );

        app.set_show_original(true);
        let drawn = window_text(&mut app, true);
        assert!(drawn.contains("no colour"), "the original's promise is gone: {drawn}");
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
        // The window's own grounds: the full width, not merely most of it.
        // A pane is full-area now rather than half of a pair, so it clears
        // nine tenths of the window easily -- and a pane is not a panel. What
        // separates them is the panel margin the pane is drawn inside, which
        // is why this asks for the whole width rather than nearly all of it.
        //
        // And actually painted: egui allocates transparent rectangles for
        // regions that only clip.
        rects.retain(|(rect, fill)| rect.width() > 0.99 * WINDOW_SIZE[0] && fill.a() > 0);
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
        // A file write has no run context — it names an absolute
        // path and the owner the plan lands on, in its own header — and a
        // frame around it would be a second claim about the same thing in a
        // second vocabulary.
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app =
            PromptApp::new(rx, Box::new(Vec::new()), Arc::new(OnceLock::new()), PrefsFile::none());
        let mut request = a_request(90);
        request.operations = vec![Payload::swap(
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
        )];
        app.state.handle(DaemonMsg::Request(Box::new(request)));

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
            review: false,
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
                    drawn.contains(hatch.label(true)),
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

    // ---- the chords that flip the boxes ----------------------------------

    /// Run one frame the way [`eframe::App::logic`] does: every event past the
    /// guard first, and whatever it decided into [`PromptApp::act`].
    ///
    /// Through the real [`intercept`] rather than by calling `act` directly,
    /// because the claim being made is about a keypress and not about an
    /// [`Action`]: a chord the guard classified and nothing dispatched would
    /// pass every test that started at `act`.
    ///
    /// The shapes are handed back rather than the whole output, and the
    /// texture deltas are dropped before anything can fail: epaint refuses to
    /// be dropped holding deltas nobody applied, so a failing assertion made
    /// while one is alive aborts the whole run instead of naming itself.
    fn a_live_frame(
        app: &mut PromptApp,
        ctx: &egui::Context,
        events: Vec<egui::Event>,
        at: Instant,
    ) -> Vec<egui::epaint::ClippedShape> {
        let mut out = ctx.run_ui(raw_sized(events, opening_size()), |ui| {
            // The order `logic` runs them in: the guard takes what it is
            // owed out of the frame before any widget is built.
            let keyboard = app.keyboard(ui.ctx());
            let decided = intercept(&mut app.guard, ui.ctx(), keyboard, at);
            for action in decided {
                app.act(ui.ctx(), action);
            }
            let open = app.guard.is_open(at);
            app.window(ui, open);
        });
        out.textures_delta.clear();
        std::mem::take(&mut out.shapes)
    }

    /// The same, after the frames it takes for the panels to learn their
    /// size: a bottom panel measured against a zero-height guess is not the
    /// panel a reader sees, and the controls in it are not drawn yet.
    fn a_settled_frame(
        app: &mut PromptApp,
        ctx: &egui::Context,
        at: Instant,
    ) -> Vec<egui::epaint::ClippedShape> {
        a_live_frame(app, ctx, Vec::new(), at);
        a_live_frame(app, ctx, Vec::new(), at)
    }

    /// Put the keyboard focus in the note field, by clicking in it.
    ///
    /// A click and not a Tab, because Tab lands wherever egui's focus order
    /// puts it and what this has to be about is the one widget on the window
    /// that takes text. The field is centred in the panel and level with the
    /// label naming it, which is enough to find it on a real frame.
    fn click_into_the_note_field(app: &mut PromptApp, ctx: &egui::Context, at: Instant) {
        let drawn = a_settled_frame(app, ctx, at);
        let label = text_rects(&drawn)
            .into_iter()
            .find(|(text, _)| text == "Note to the agent")
            .map(|(_, rect)| rect)
            .expect("the note field is not labelled on screen");
        let place = egui::pos2(opening_size().x / 2.0, label.center().y);
        let button = |pressed| egui::Event::PointerButton {
            pos: place,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        a_live_frame(app, ctx, vec![egui::Event::PointerMoved(place)], at);
        a_live_frame(app, ctx, vec![button(true)], at);
        a_live_frame(app, ctx, vec![button(false)], at);
    }

    /// One key held down with `modifiers`.
    fn chord(key: egui::Key, modifiers: egui::Modifiers) -> egui::Event {
        egui::Event::Key { key, physical_key: None, pressed: true, repeat: false, modifiers }
    }

    /// Long enough after this window was made that the guard is open.
    fn past_the_guard() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    /// Every string the frame drew, with the colour it was drawn in.
    fn text_colours(shapes: &[egui::epaint::ClippedShape]) -> Vec<(String, egui::Color32)> {
        fn walk(shape: &egui::epaint::Shape, out: &mut Vec<(String, egui::Color32)>) {
            match shape {
                egui::epaint::Shape::Text(text) => {
                    let job = &text.galley.job;
                    for section in &job.sections {
                        out.push((
                            job.text[section.byte_range.start.0..section.byte_range.end.0]
                                .to_string(),
                            section.format.color,
                        ));
                    }
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

    /// Whether `said` was drawn in the colour this window warns in.
    ///
    /// The colour is read off the same frame rather than out of a default
    /// style, because the window wears a palette of its own — see
    /// [`theme::wear`] — and a claim made against egui's own colours would be
    /// a claim about a window nobody is looking at. The terminal's capture
    /// sentence is the warning every command window already draws, so it is
    /// what "the colour this window warns in" means here.
    fn drawn_as_a_warning(shapes: &[egui::epaint::ClippedShape], said: &str) -> bool {
        let drawn = text_colours(shapes);
        let warn = drawn
            .iter()
            .find(|(text, _)| text == TERMINAL_CAPTURE)
            .map(|(_, colour)| *colour)
            .expect("nothing on this window is drawn as a warning to compare against");
        let weak = drawn
            .iter()
            .find(|(text, _)| text == "Note to the agent")
            .map(|(_, colour)| *colour)
            .expect("the quiet label that names the note field is not on screen");
        assert_ne!(warn, weak, "this window's warning colour is its quiet one");
        drawn.iter().any(|(text, colour)| text == said && *colour == warn)
    }

    /// Every string a frame's shapes carry, for a failure to quote.
    fn shapes_text(shapes: &[egui::epaint::ClippedShape]) -> String {
        text_rects(shapes).into_iter().map(|(text, _)| text).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn the_chord_ticks_the_box_a_pointer_would_have_and_writes_the_same_thing_down() {
        // Two ways to say one thing, and they have to be one thing: a window
        // whose keyboard and mouse remembered different answers would be a
        // preference nobody could rely on.
        let (_root, paths) = a_prefs_file();
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        let now = past_the_guard();

        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::C, egui::Modifiers::ALT)], now);
        assert!(app.closes_on_decide(), "Alt+C did not reach the box");
        assert!(PrefsFile::at(&paths).read().close_on_decide, "the chord wrote nothing down");

        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::S, egui::Modifiers::ALT)], now);
        assert!(app.streams(), "Alt+S did not reach the box");
        assert!(PrefsFile::at(&paths).read().stream, "the chord wrote nothing down");

        // And back, because a chord that could only ever tick would be half a
        // control.
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::S, egui::Modifiers::ALT)], now);
        assert!(!app.streams());
        assert!(!PrefsFile::at(&paths).read().stream, "the untick was not written down");
    }

    #[test]
    fn a_window_says_what_language_a_here_document_carries() {
        let mut app = a_window_showing("python3 - <<'PY'\nprint(1)\nPY");
        let drawn = window_text_sized(&mut app, opening_size());
        assert!(drawn.contains("reads as Python"), "{drawn}");
        assert!(drawn.contains("from the program it is given to"), "{drawn}");

        // And a body nothing names says nothing: an unlabelled body is the
        // rendering bodies had before any of this, and a window that guessed
        // would be making the one claim this feature refuses to make.
        let mut quiet = a_window_showing("cat <<'EOF' > /etc/hosts\n127.0.0.1 local\nEOF");
        let drawn = window_text_sized(&mut quiet, opening_size());
        assert!(!drawn.contains("reads as"), "a window guessed at a config file: {drawn}");
    }

    #[test]
    fn the_review_chord_ticks_the_box_and_writes_it_down() {
        // The chord and the click are one control, so they go through one
        // setter. A chord that ticked the box without writing it down would
        // leave the window and the file disagreeing about a standing choice,
        // with nothing on screen saying which one the next window will get.
        let (_root, paths) = a_prefs_file();
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        let now = past_the_guard();

        assert!(!app.reviews(), "the box opens unticked");
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::R, egui::Modifiers::ALT)], now);
        assert!(app.reviews(), "Alt+R did not reach the box");
        assert_eq!(
            PrefsFile::at(&paths).read(),
            Prefs { review: true, ..Prefs::default() },
            "the chord ticked the box without writing it down, or wrote more than the one box"
        );

        // And back, because a chord that could only ever tick would be half a
        // control -- and because turning a standing choice off has to be as
        // cheap as turning it on.
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::R, egui::Modifiers::ALT)], now);
        assert!(!app.reviews(), "the untick did not reach the box");
        assert!(!PrefsFile::at(&paths).read().review, "the untick did not reach the file");
    }

    #[test]
    fn the_review_chord_says_the_same_thing_the_box_does() {
        // The chord is on the window's own hint, so a reader who finds the
        // box finds the key -- and the two cannot drift, because the label is
        // the constant.
        let mut app = a_window_showing("echo hi");
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        let now = past_the_guard();
        let box_at = drawn_at(&mut app, &ctx, REVIEW_LABEL, now).expect("the review box is drawn");
        assert!(box_at.width() > 0.0);
        assert_eq!(guard::REVIEW_CHORD, "Alt+R");
    }

    #[test]
    fn a_chord_during_the_guard_flips_nothing_and_leaves_nothing_behind() {
        // The whole of why these wait as long as Approve does. What they
        // write outlives this window, so the burst that cannot approve must
        // not be able to tick either.
        let (_root, paths) = a_prefs_file();
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        let inside = Instant::now();

        for key in [egui::Key::S, egui::Key::C, egui::Key::R] {
            a_live_frame(&mut app, &ctx, vec![chord(key, egui::Modifiers::ALT)], inside);
        }
        assert!(
            !app.streams() && !app.closes_on_decide() && !app.reviews(),
            "a burst answered the window"
        );
        assert_eq!(
            PrefsFile::at(&paths).read(),
            Prefs::default(),
            "a burst wrote a preference that outlives this window"
        );
    }

    #[test]
    fn alt_s_on_a_run_that_has_a_terminal_ticks_nothing_and_points_at_the_reason() {
        // There is no second stream to show, so the chord must not promise
        // one — and must not answer with silence either, which is what
        // teaches a reader that a shortcut does not work.
        let (_root, paths) = a_prefs_file();
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));
        app.terminal = true;
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        let now = past_the_guard();

        a_settled_frame(&mut app, &ctx, now);
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::S, egui::Modifiers::ALT)], now);
        let drawn = a_live_frame(&mut app, &ctx, Vec::new(), now);
        assert!(!app.streams(), "a terminal run promised a stream");
        assert!(!app.stream, "a refused chord was stored anyway");
        assert!(
            !PrefsFile::at(&paths).read().stream,
            "a chord that could not be obeyed was remembered"
        );
        assert!(
            drawn_as_a_warning(&drawn, STREAM_DEAD),
            "the chord was refused in silence: {}",
            shapes_text(&drawn)
        );
    }

    #[test]
    fn alt_c_while_watching_ticks_nothing_and_points_at_the_reason() {
        // The close box is showing the effective answer, which streaming has
        // already settled. A chord that changed the stored one underneath
        // would be an invisible write to a file that outlives the window.
        let (_root, paths) = a_prefs_file();
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));
        app.stream = true;
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        let now = past_the_guard();

        a_settled_frame(&mut app, &ctx, now);
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::C, egui::Modifiers::ALT)], now);
        let drawn = a_live_frame(&mut app, &ctx, Vec::new(), now);
        assert!(!app.close_on_decide, "a refused chord was stored anyway");
        assert_eq!(PrefsFile::at(&paths).read(), Prefs::default(), "and written down");
        assert!(
            drawn_as_a_warning(&drawn, CLOSE_WATCHING),
            "the chord was refused in silence: {}",
            shapes_text(&drawn)
        );
    }

    #[test]
    fn a_chord_changes_nothing_once_the_question_has_been_answered() {
        // The boxes are gone from the window with the question they belonged
        // to, so a chord that still wrote one would be a preference changing
        // where nobody could see it change.
        let (_root, paths) = a_prefs_file();
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));
        app.state.decide(approved(false));
        assert_eq!(app.state.phase(), Phase::Running);
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        let now = past_the_guard();

        for key in [egui::Key::S, egui::Key::C] {
            a_live_frame(&mut app, &ctx, vec![chord(key, egui::Modifiers::ALT)], now);
        }
        assert_eq!(PrefsFile::at(&paths).read(), Prefs::default(), "a running window saved a box");
    }

    #[test]
    fn the_note_field_still_gets_the_letters_the_chords_are_built_from() {
        // The reason these are chords and not bare keys: `s` and `c` are two
        // of the letters somebody types into the note, and a window in which
        // they mean something else is a window that eats what you write in it.
        let (mut app, _sink) = an_awaiting_window();
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        let now = past_the_guard();
        click_into_the_note_field(&mut app, &ctx, now);

        let typed = vec![
            chord(egui::Key::S, egui::Modifiers::NONE),
            egui::Event::Text("s".to_string()),
            chord(egui::Key::C, egui::Modifiers::NONE),
            egui::Event::Text("c".to_string()),
        ];
        a_live_frame(&mut app, &ctx, typed, now);
        assert_eq!(app.note, "sc", "the chords ate what was typed into the note");
        assert!(!app.streams() && !app.closes_on_decide(), "typing flipped a box");
    }

    #[test]
    fn every_chord_approves_while_the_note_field_holds_the_keyboard() {
        // The guard classifies before any widget sees the frame, so a focused
        // text field cannot swallow any of them. Asserted for all three,
        // because a rule that held for one and not the others would be
        // exactly the drift the label is pinned against.
        //
        // The note field is where the left-hand chord has most to prove: it
        // is carried by a letter, and a letter is what that field is for.
        let ctrl_alt = egui::Modifiers { ctrl: true, alt: true, ..egui::Modifiers::NONE };
        for (key, held) in [
            (egui::Key::Enter, egui::Modifiers::CTRL),
            (egui::Key::Enter, egui::Modifiers::SHIFT),
            (egui::Key::A, ctrl_alt),
        ] {
            let (mut app, sink) = an_awaiting_window();
            let ctx = egui::Context::default();
            apply_faces(&ctx);
            let now = past_the_guard();
            click_into_the_note_field(&mut app, &ctx, now);

            // Proof the field really has the keyboard, rather than a click
            // that missed and a test that would pass either way.
            a_live_frame(&mut app, &ctx, vec![egui::Event::Text("go on".to_string())], now);
            assert_eq!(app.note, "go on", "the click did not reach the note field");

            a_live_frame(&mut app, &ctx, vec![chord(key, held)], now);
            let out = String::from_utf8(sink.lock().expect("sink").clone()).expect("utf-8");
            assert!(out.contains("approve"), "{key:?} with {held:?} did not approve: {out:?}");
            assert!(
                !out.contains("go on a") && !out.contains("go ona"),
                "the chord typed its letter into the note as well: {out:?}"
            );
        }
    }

    #[test]
    fn a_letter_that_carries_an_approval_is_still_a_letter_without_its_chord() {
        // `A` approves only with Control *and* Alt. The window has a text
        // field on it, so every other way of pressing that key has to reach
        // the field -- including the near misses, which is where a rule
        // matched loosely would show up as a window that eats what you type.
        let ctrl_alt_shift =
            egui::Modifiers { ctrl: true, alt: true, shift: true, ..egui::Modifiers::NONE };
        for held in [
            egui::Modifiers::NONE,
            egui::Modifiers::ALT,
            egui::Modifiers::SHIFT,
            ctrl_alt_shift,
        ] {
            let (mut app, sink) = an_awaiting_window();
            let ctx = egui::Context::default();
            apply_faces(&ctx);
            let now = past_the_guard();
            click_into_the_note_field(&mut app, &ctx, now);
            a_live_frame(&mut app, &ctx, vec![chord(egui::Key::A, held)], now);
            assert!(
                sink.lock().expect("sink").is_empty(),
                "A with {held:?} approved a command"
            );
            assert_eq!(app.state.phase(), Phase::AwaitingVerdict, "{held:?}");
        }
    }

    // ---- what the window remembers ----------------------------------------

    #[test]
    fn a_remembered_stream_opens_the_next_window_watching() {
        let (_root, paths) = a_prefs_file();
        PrefsFile::at(&paths).write(&Prefs { stream: true, ..Prefs::default() });
        let (app, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));
        assert!(app.streams(), "the next window opened having forgotten");
        assert!(
            matches!(app.approval(), Verdict::Approve { stream: true, .. }),
            "and would have approved without the view it was asked for"
        );
    }

    #[test]
    fn two_remembered_preferences_that_contradict_each_other_say_which_is_winning() {
        // Streaming still beats closing, and the reason the box is grey is no
        // longer anything anybody said about this command — so the sentence
        // claiming they did would be false. See `CLOSE_WATCHING_ALWAYS`.
        let (_root, paths) = a_prefs_file();
        PrefsFile::at(&paths).write(&Prefs {
            stream: true,
            close_on_decide: true,
            terminal: false,
            show_original: false,
            review: false,
        });
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));
        assert!(!app.closes_on_decide(), "it would have closed over the output it was asked for");

        let said = window_text_sized(&mut app, opening_size());
        assert!(said.contains(CLOSE_WATCHING_ALWAYS), "the window said nothing about it: {said}");
        assert!(
            !said.contains(CLOSE_WATCHING),
            "the window said the reader asked about a command they have not read: {said}"
        );

        // And the way out is the one the sentence points at: the moment the
        // reader says something about this command, the window is about this
        // command again.
        app.set_stream(false);
        assert!(app.closes_on_decide(), "unticking Stream did not give the preference back");
        let said = window_text_sized(&mut app, opening_size());
        assert!(said.contains(CLOSE_COST), "the box went live without saying what it costs");
    }

    #[test]
    fn a_tick_made_in_front_of_this_command_still_says_this_one() {
        // The other half of the pair above: the old sentence is still the
        // right one when the reader is the one who just ticked the box.
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::none());
        app.set_stream(true);
        let said = window_text_sized(&mut app, opening_size());
        assert!(said.contains(CLOSE_WATCHING), "{said}");
        assert!(!said.contains(CLOSE_WATCHING_ALWAYS), "{said}");
    }

    #[test]
    fn a_remembered_terminal_arrives_with_the_sentence_that_says_what_it_costs() {
        // The one preference in the file that changes how the command runs.
        // What makes it answerable is that it is visible and that the warning
        // is drawn whether or not the box is ticked — so a remembered tick
        // never arrives without it.
        let (_root, paths) = a_prefs_file();
        PrefsFile::at(&paths).write(&Prefs { terminal: true, ..Prefs::default() });
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));

        assert!(app.in_a_terminal(), "the next window opened having forgotten");
        let said = window_text_sized(&mut app, opening_size());
        assert!(said.contains(TERMINAL_LABEL), "the control is not on screen: {said}");
        assert!(said.contains(TERMINAL_CAPTURE), "what it costs is not said: {said}");
    }

    #[test]
    fn a_remembered_terminal_cannot_withdraw_one_the_agent_asked_for() {
        // The control grants and never withdraws, and a preference is not a
        // way around that. Both directions of the remembered value, because a
        // rule that held for one of them would be an accident.
        for remembered in [false, true] {
            let (_root, paths) = a_prefs_file();
            PrefsFile::at(&paths).write(&Prefs { terminal: remembered, ..Prefs::default() });
            let (_tx, rx) = std::sync::mpsc::channel();
            let mut app = PromptApp::new(
                rx,
                Box::new(Vec::new()),
                Arc::new(OnceLock::new()),
                PrefsFile::at(&paths),
            );
            let mut request = a_request(90);
            request.operations = vec![Payload::command(
                &render_command("vim /etc/hosts", &BTreeMap::new()),
                Vec::new(),
                PathBuf::from("/tmp"),
                false,
                true,
            )];
            app.state.handle(DaemonMsg::Request(Box::new(request)));

            window_text_sized(&mut app, opening_size());
            assert!(
                matches!(app.approval(), Verdict::Approve { terminal: true, .. }),
                "the agent asked for a terminal and a preference took it away"
            );
            // And the agent's ask is not written down as the reader's: the
            // box was dead, nobody clicked it, and nothing may change.
            assert_eq!(
                PrefsFile::at(&paths).read().terminal,
                remembered,
                "the agent's ask became the reader's standing decision"
            );
        }
    }

    #[test]
    fn a_window_saving_one_box_leaves_the_ones_it_did_not_touch_alone() {
        // Several windows are open at once by design. A window that wrote its
        // own struct would undo the box its neighbour ticked a moment ago.
        let (_root, paths) = a_prefs_file();
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));

        // The window beside this one, which this one knows nothing about.
        PrefsFile::at(&paths).update(|prefs| prefs.terminal = true);

        app.set_close_on_decide(true);
        assert_eq!(
            PrefsFile::at(&paths).read(),
            Prefs {
                close_on_decide: true,
                stream: false,
                terminal: true,
                show_original: false,
                review: false,
            },
            "this window trampled what the one beside it saved"
        );
    }

    // ---- a write, and what it does not inherit from a command --------------

    /// A request to write one file, the way the daemon renders one.
    fn a_write_request() -> Request {
        let mut request = a_request(90);
        request.title = "set the port".to_string();
        request.operations = vec![Payload::swap(
            PathBuf::from("/tmp/conf.toml"),
            crate::swap::SwapPlan {
                kind: crate::swap::PlanKind::Replace,
                landing_mode: 0o644,
                landing_owner: crate::swap::Principal { id: 1000, name: Some("u".into()) },
                landing_group: crate::swap::Principal { id: 1000, name: Some("u".into()) },
                hash_before: Some("aa".into()),
                size_delta: 2,
            },
            &crate::render::diff::side_by_side("port = 80\n", "port = 8080\n"),
        )];
        request
    }

    /// A window awaiting a verdict on a file write, remembering whatever
    /// `prefs` holds.
    fn a_write_window_remembering(
        prefs: PrefsFile,
    ) -> (PromptApp, Arc<std::sync::Mutex<Vec<u8>>>) {
        let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut app =
            PromptApp::new(rx, Box::new(Sink(Arc::clone(&sink))), Arc::new(OnceLock::new()), prefs);
        app.state.handle(DaemonMsg::Request(Box::new(a_write_request())));
        assert_eq!(app.state.phase(), Phase::AwaitingVerdict);
        (app, sink)
    }

    /// The same, with nowhere to remember anything.
    fn a_write_window() -> PromptApp {
        a_write_window_remembering(PrefsFile::none()).0
    }

    #[test]
    fn a_write_window_draws_no_close_box_and_says_nothing_about_a_kill_button() {
        // The bug: "The Kill button goes with it", under a diff. A write has
        // no Kill button to lose, and a sentence about one is a sentence
        // about some other window. At both arrangements, because the narrow
        // one used to put the box on a row of its own above the buttons.
        for size in [opening_size(), egui::vec2(520.0, 700.0)] {
            let drawn = window_text_sized(&mut a_write_window(), size);
            for said in [CLOSE_LABEL, CLOSE_COST, CLOSE_WATCHING, CLOSE_WATCHING_ALWAYS, "Kill"] {
                assert!(!drawn.contains(said), "a {size:?} write window says {said:?}: {drawn}");
            }
            assert!(drawn.contains("Approve") && drawn.contains("Deny"), "{drawn}");
        }
    }

    #[test]
    fn a_write_window_neither_changes_nor_obeys_the_close_preference_it_does_not_show() {
        // The preference is the reader's and outlives this window. Not drawing
        // the box must not write to it, and must not act on it either: a
        // window that closed on a tick nobody could see would be deciding
        // something no control on it admits to.
        let (_root, paths) = a_prefs_file();
        let stored = Prefs {
            close_on_decide: true,
            stream: true,
            terminal: false,
            show_original: false,
            review: false,
        };
        PrefsFile::at(&paths).write(&stored);
        let (mut app, sink) = a_write_window_remembering(PrefsFile::at(&paths));
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        let now = past_the_guard();

        a_settled_frame(&mut app, &ctx, now);
        // The chord for the box that is not there, and the one for the other
        // box that is not there.
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::C, egui::Modifiers::ALT)], now);
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::S, egui::Modifiers::ALT)], now);
        assert_eq!(PrefsFile::at(&paths).read(), stored, "a write window wrote a preference down");

        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::Enter, egui::Modifiers::CTRL)], now);
        let out = String::from_utf8(sink.lock().expect("sink").clone()).expect("utf-8");
        assert!(out.contains("\"verdict\":\"approve\""), "the chord did not approve: {out}");
        assert!(out.contains("\"closing\":false"), "it approved as a window that is going: {out}");
        assert!(out.contains("\"stream\":false"), "it approved as a watched run: {out}");
        assert_eq!(app.state.phase(), Phase::Running, "it went on a preference it does not show");
        assert_eq!(PrefsFile::at(&paths).read(), stored, "approving wrote a preference down");

        // And the next command window still has both, as they were left.
        let (next, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));
        assert!(next.streams() && next.close_on_decide, "the next command window forgot");
    }

    #[test]
    fn a_remembered_stream_does_not_turn_a_write_into_a_run_somebody_is_watching() {
        // The other half of the flash. A stream tick remembered from commands
        // reached a write's approval, so the window recorded a watched run and
        // lingered over it — an empty viewer claiming the file "printed
        // nothing" — until the daemon, which knows a write has nothing to
        // show, killed it half a second in.
        let (_root, paths) = a_prefs_file();
        PrefsFile::at(&paths).write(&Prefs { stream: true, ..Prefs::default() });
        let (mut app, _sink) = a_write_window_remembering(PrefsFile::at(&paths));

        assert!(!app.streams(), "a write window says it will stream a write");
        let frame = app.state.decide(app.approval());
        assert!(
            matches!(frame, Some(PromptMsg::Verdict(Verdict::Approve { stream: false, .. }))),
            "{frame:?}"
        );
        assert!(!app.state.streaming(), "the window recorded a write as a watched run");
        assert!(app.stream, "and the remembered answer underneath it was lost");
    }

    #[test]
    fn a_running_write_offers_no_kill_and_says_nothing_about_output() {
        let mut app = a_write_window();
        app.state.decide(approved(false));
        assert_eq!(app.state.phase(), Phase::Running);

        let drawn = window_text_sized(&mut app, opening_size());

        assert!(drawn.contains("Writing the file"), "the window does not say what it is doing: {drawn}");
        for said in ["Kill", "streamed", "running", "Keep this window"] {
            assert!(!drawn.contains(said), "a running write says {said:?}: {drawn}");
        }
        assert_eq!(app.state.request_kill(), None, "a Kill frame could still leave a write window");
    }

    #[test]
    fn the_escape_hatch_a_write_offers_is_worded_for_a_write() {
        let drawn = window_text_sized(&mut a_write_window(), opening_size());
        assert!(drawn.contains("I'll write it myself"), "{drawn}");
        assert!(!drawn.contains("run it myself"), "a write window offers to run a file: {drawn}");

        let command = window_text_sized(&mut a_window_showing("ls"), opening_size());
        assert!(command.contains("I'll run it myself"), "{command}");
    }

    #[test]
    fn approve_and_deny_are_in_the_same_place_on_a_write_window_as_on_a_command_window() {
        // The close control's flank is left empty on a write, and on a narrow
        // window the row it used to take above the buttons is given back to
        // the panes. Neither may move the two buttons that decide: a reader
        // who has learnt where Approve is has learnt it for both windows.
        for width in [opening_size().x, 900.0, 700.0, 520.0] {
            let size = egui::vec2(width, 700.0);
            let primary = |app: &mut PromptApp| {
                let buttons = button_rects(&window_shapes(app, size));
                let tallest = buttons.iter().map(|r| r.height()).fold(0.0_f32, f32::max);
                let mut primary: Vec<egui::Rect> =
                    buttons.into_iter().filter(|r| r.height() >= tallest - 0.5).collect();
                primary.sort_by(|a, b| a.left().total_cmp(&b.left()));
                primary
            };
            let command = primary(&mut a_window_showing("rm -rf /var/tmp/build"));
            let write = primary(&mut a_write_window());
            assert_eq!(command.len(), 2, "at {width} points: {command:?}");
            assert_eq!(write, command, "at {width} points the buttons moved between the two");
        }
    }

    #[test]
    fn a_narrow_write_window_gives_back_the_row_the_close_control_took() {
        // Between the note field and the buttons is where the close control
        // goes when it cannot sit beside Approve, so on a narrow command
        // window that distance grows by a row. On a write there is no control
        // to put there, and the distance is what it is on a wide window.
        // Measured from the field itself, because the label naming it moves
        // above it on a narrow window and would be measuring that instead.
        let gap = |app: &mut PromptApp, width: f32| {
            let shapes = window_shapes(app, egui::vec2(width, 700.0));
            let buttons = button_rects(&shapes);
            let tallest = buttons.iter().map(|r| r.height()).fold(0.0_f32, f32::max);
            let approve = buttons
                .iter()
                .filter(|r| r.height() >= tallest - 0.5)
                .map(|r| r.top())
                .fold(f32::INFINITY, f32::min);
            // The note field is the one short box on the pane surface that
            // sits above the buttons.
            let field = filled_rects(&shapes)
                .into_iter()
                .filter(|(rect, fill)| {
                    *fill == theme::DARK.surface && rect.height() < 60.0 && rect.bottom() <= approve
                })
                .map(|(rect, _)| rect.bottom())
                .fold(f32::NEG_INFINITY, f32::max);
            approve - field
        };

        let grown = |app: &mut PromptApp| gap(app, 520.0) - gap(app, opening_size().x);
        let command = grown(&mut a_window_showing("ls"));
        let write = grown(&mut a_write_window());
        assert!(command > 20.0, "the close control never went above the buttons: {command}");
        assert!(
            write.abs() < 2.0,
            "a narrow write window still spends {write} points where the close control was"
        );
    }

    // ---- after the verdict: staying only for news --------------------------

    /// Every ending a window nobody asked to watch stays up for.
    fn news() -> Vec<Outcome> {
        vec![
            Outcome::Signal { signal: 9 },
            Outcome::ElevationFailed { message: "the dialog was dismissed".to_string() },
            Outcome::Unclear { message: "the run was ended at its deadline".to_string() },
            Outcome::Failed { message: "the file changed between hatch reading it and going to write it".to_string() },
        ]
    }

    #[test]
    fn a_write_that_landed_closes_on_its_outcome_at_once() {
        // It landed as the window described it, which the reader read and
        // said yes to. There is nothing to hold up, so nothing is held up —
        // not for a countdown and not for a moment.
        let mut app = a_write_window();
        app.state.decide(app.approval());
        app.state.handle(DaemonMsg::Finished(Outcome::Written));

        assert_eq!(app.state.phase(), Phase::Closed);
        assert_eq!(app.state.linger_seconds_remaining(Instant::now()), None);
        assert!(app.state.take_close(), "the process was never told to leave");
        assert_eq!(app.state.broken(), None);
    }

    #[test]
    fn a_write_that_did_not_land_stays_long_enough_to_be_read() {
        // A refusal, a dismissed dialog, an elevation hatch cannot read: the
        // file is not what the reader approved, and the tool result reaching
        // the agent is no help to the person who is not reading it.
        for outcome in news().into_iter().filter(|o| !matches!(o, Outcome::Signal { .. })) {
            let mut app = a_write_window();
            app.state.decide(app.approval());
            app.state.handle(DaemonMsg::Finished(outcome.clone()));

            assert_eq!(app.state.phase(), Phase::Lingering, "{outcome:?} closed the window");
            assert_eq!(
                app.state.linger_seconds_remaining(Instant::now()),
                Some(LINGER.as_secs()),
                "{outcome:?} did not get the whole linger"
            );
            app.state.tick(Instant::now() + LINGER);
            assert_eq!(app.state.phase(), Phase::Closed, "{outcome:?} outstayed its countdown");
        }
    }

    #[test]
    fn a_run_nobody_watched_closes_on_its_own_answer_whatever_the_status() {
        // grep finding nothing and diff finding a difference are answers,
        // and they are the agent's: a window that stayed up for every one of
        // them would teach its reader that a staying window means nothing.
        for code in [0, 1, 2, 127] {
            let mut state = PromptState::new();
            state.handle(DaemonMsg::Request(Box::new(a_request(90))));
            state.decide(approved(false));
            state.handle(DaemonMsg::Finished(Outcome::Exit { code }));
            assert_eq!(state.phase(), Phase::Closed, "exit {code} held the window up");
        }
    }

    #[test]
    fn a_run_nobody_watched_that_something_happened_to_stays_to_show_it() {
        for outcome in news() {
            let mut state = PromptState::new();
            state.handle(DaemonMsg::Request(Box::new(a_request(90))));
            state.decide(approved(false));
            state.handle(DaemonMsg::Finished(outcome.clone()));

            assert_eq!(state.phase(), Phase::Lingering, "{outcome:?} closed the window");
            assert_eq!(state.outcome(), Some(&outcome));
            // A viewer like any other, and so no more able to decide or kill.
            for verdict in every_verdict() {
                assert_eq!(state.decide(verdict.clone()), None, "{verdict:?} after {outcome:?}");
            }
            assert_eq!(state.request_kill(), None);
        }
    }

    #[test]
    fn a_window_staying_for_news_is_kept_and_put_away_by_the_keys_a_watched_one_is() {
        for key in [egui::Key::E, egui::Key::O, egui::Key::Space] {
            let mut app = a_write_window();
            app.state.decide(app.approval());
            app.state.handle(DaemonMsg::Finished(news().remove(3)));
            press_key(&mut app, key, egui::Modifiers::NONE);
            assert_eq!(app.state.phase(), Phase::Detached, "{key:?} did not keep it");
            assert!(app.kept.load(Ordering::SeqCst), "{key:?} kept a window the backstop will kill");
        }

        let mut app = a_window_showing("sleep 30");
        app.state.decide(approved(false));
        app.state.handle(DaemonMsg::Finished(Outcome::Signal { signal: 9 }));
        press_key(&mut app, egui::Key::Escape, egui::Modifiers::NONE);
        assert_eq!(app.state.phase(), Phase::Closed, "Escape did not put it away");
    }

    #[test]
    fn a_write_staying_to_say_it_did_not_land_shows_why_beside_what_was_approved() {
        let mut app = a_write_window();
        app.state.decide(app.approval());
        app.state.handle(DaemonMsg::Finished(Outcome::Failed {
            message: "the file changed between hatch reading it and going to write it".to_string(),
        }));

        let drawn = window_text_sized(&mut app, opening_size());

        assert!(
            drawn.contains("Failed — the file changed between hatch reading it and going to write it"),
            "the window does not say why: {drawn}"
        );
        assert!(drawn.contains("closing in"), "{drawn}");
        assert!(drawn.contains("Keep this window") && drawn.contains("Close"), "{drawn}");
        // What it did not land as: the diff, the path and the landing.
        assert!(drawn.contains("port = 8080") && drawn.contains("/tmp/conf.toml"), "{drawn}");
        assert!(drawn.contains("0644"), "{drawn}");
        // And nothing a command would have had.
        for said in ["printed nothing", "Copy output", "Copy command", "exit", "Kill", "Deny"] {
            assert!(!drawn.contains(said), "a failed write says {said:?}: {drawn}");
        }
    }

    #[test]
    fn a_run_nobody_watched_staying_for_news_does_not_claim_it_printed_nothing() {
        // No output was ever sent to this window, so "it printed nothing"
        // would be a claim about a command it never heard from, and a copy
        // button would hand over an empty clipboard.
        let mut app = a_window_showing("make -j8");
        app.state.decide(approved(false));
        app.state.handle(DaemonMsg::Finished(Outcome::Signal { signal: 9 }));

        let drawn = window_text_sized(&mut app, opening_size());

        assert!(drawn.contains("Ended by signal 9"), "{drawn}");
        assert!(drawn.contains("not streamed to this window"), "{drawn}");
        assert!(drawn.contains("Copy command"), "the command it ran cannot be taken: {drawn}");
        assert!(!drawn.contains("printed nothing"), "{drawn}");
        assert!(!drawn.contains("Copy output"), "{drawn}");

        press_key(&mut app, egui::Key::C, egui::Modifiers::ALT);
        assert!(app.copied.is_none(), "Alt+C said it copied output there is none of");
    }

    #[test]
    fn a_window_closing_on_its_outcome_goes_on_looking_like_the_run_it_was() {
        // The frames painted while a window goes are the ones a compositor
        // animates away. A window that drew them as the question it had
        // already answered put that picture on screen at the very end.
        let mut app = a_window_showing("systemctl restart thing");
        app.state.decide(approved(false));
        let running = window_shapes(&mut app, opening_size());
        let kill = text_rects(&running).into_iter().find(|(t, _)| t == "Kill").expect("Kill").1;
        let ground = ground_drawn(&mut app);

        app.state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));
        assert_eq!(app.state.phase(), Phase::Closed);
        let closing = window_shapes(&mut app, opening_size());

        assert_eq!(ground_drawn(&mut app), ground, "the ground changed on the way out");
        assert_eq!(
            text_rects(&closing).into_iter().find(|(t, _)| t == "Kill").map(|(_, r)| r),
            Some(kill),
            "the controls moved on the way out"
        );
        let said = shapes_text(&closing);
        assert!(said.contains("It has finished"), "{said}");
        assert!(!said.contains("running now"), "a finished command is said to be running: {said}");
        assert_eq!(app.state.request_kill(), None, "the Kill button drawn on the way out kills");
    }

    #[test]
    fn a_root_write_closing_on_its_landing_keeps_the_lines_its_waiting_took() {
        // The waiting sentence is two lines. The one that replaces it as the
        // window goes is two lines too, or the panel shrinks and the diff
        // jumps into the room as the last thing the reader sees.
        let mut app = a_write_window();
        app.state.decide(app.approval());
        app.state.handle(DaemonMsg::Elevating);
        let waiting = pane_height(&mut app, opening_size());
        assert!(window_text_sized(&mut app, opening_size()).contains("authorise"));

        app.state.handle(DaemonMsg::Finished(Outcome::Written));
        assert_eq!(app.state.phase(), Phase::Closed);

        assert_eq!(pane_height(&mut app, opening_size()), waiting, "the diff moved on the way out");
        let said = window_text_sized(&mut app, opening_size());
        assert!(said.contains("The file is written") && said.contains("authorised it"), "{said}");
        assert!(!said.contains("Waiting"), "{said}");
    }

    #[test]
    fn a_linger_running_out_says_closing_now_on_its_way_out_rather_than_kept() {
        let mut app = a_finished_window_showing("echo marker", "a line it printed\n");
        // The countdown as it is when it has really run out, since the frame
        // below reads the real clock.
        app.state.linger_until = Some(Instant::now());
        app.state.tick(Instant::now());
        assert_eq!(app.state.phase(), Phase::Closed);

        let drawn = window_text(&mut app, true);

        assert!(drawn.contains("closing now"), "{drawn}");
        assert!(!drawn.contains("Kept"), "a window going on its countdown said it was kept: {drawn}");
        assert!(drawn.contains("a line it printed"), "the output vanished before the window: {drawn}");
    }

    // ---- a run whose reader asked to review its output ---------------------

    /// What a daemon hands a reviewing window: a line on each pipe.
    fn a_review() -> Review {
        Review {
            deadline: Utc::now() + chrono::Duration::seconds(600),
            output: crate::review::Sections::Streams {
                stdout: crate::review::Captured {
                    text: "ok: one\ntoken=hunter2\nok: two\n".to_string(),
                    truncated: false,
                },
                stderr: crate::review::Captured {
                    text: "warning: slow\n".to_string(),
                    truncated: false,
                },
            },
        }
    }

    /// An approval that asks to review, and nothing else.
    fn approved_for_review() -> Verdict {
        Verdict::Approve {
            stream: false,
            terminal: false,
            closing: false,
            review: true,
            note: String::new(),
        }
    }

    /// A command window whose reader asked to review, with the run over and
    /// the question on screen.
    fn a_reviewing_state() -> PromptState {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        state.decide(approved_for_review());
        state.handle(DaemonMsg::Review(a_review()));
        state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));
        state
    }

    #[test]
    fn a_reviewed_run_stays_to_ask_even_when_its_ending_is_no_news_at_all() {
        // Exit 0, nobody watching: the ending that closes every other window
        // at once. This one has a question on it.
        let state = a_reviewing_state();
        assert_eq!(state.phase(), Phase::Reviewing);
        assert!(!state.is_viewer(), "a window with a question on it is not only showing a result");
        assert!(state.review_seconds_remaining(Utc::now()).is_some_and(|left| left > 0));
    }

    #[test]
    fn output_to_review_is_believed_only_by_a_window_that_asked_for_it() {
        let mut unasked = PromptState::new();
        unasked.handle(DaemonMsg::Request(Box::new(a_request(90))));
        unasked.decide(approved(false));
        unasked.handle(DaemonMsg::Review(a_review()));
        assert!(unasked.should_close() && unasked.broken().is_some(), "{:?}", unasked.phase());

        let mut twice = PromptState::new();
        twice.handle(DaemonMsg::Request(Box::new(a_request(90))));
        twice.decide(approved_for_review());
        twice.handle(DaemonMsg::Review(a_review()));
        twice.handle(DaemonMsg::Review(a_review()));
        assert!(twice.should_close() && twice.broken().is_some(), "a second review was believed");

        let mut early = PromptState::new();
        early.handle(DaemonMsg::Request(Box::new(a_request(90))));
        early.handle(DaemonMsg::Review(a_review()));
        assert!(early.should_close(), "a review arrived before anything was approved");
    }

    #[test]
    fn a_review_that_never_comes_leaves_the_ending_to_the_ordinary_rule() {
        // A command that could not start printed nothing, so there is no
        // output to review; the window is told why it failed like any other.
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        state.decide(approved_for_review());
        state.handle(DaemonMsg::Finished(Outcome::Exit { code: 0 }));
        assert_eq!(state.phase(), Phase::Closed);
    }

    #[test]
    fn the_answer_to_a_review_leaves_once_and_takes_the_window_with_it() {
        let mut state = a_reviewing_state();
        let first = state.release(Release::Withhold { note: String::new() });
        assert_eq!(first, Some(PromptMsg::Release(Release::Withhold { note: String::new() })));
        assert!(state.should_close());
        assert_eq!(state.broken(), None, "an answered review is not a failure");
        assert_eq!(state.release(Release::Withhold { note: String::new() }), None, "it answered twice");
        assert_eq!(state.decide(approved(false)), None, "a review became a second verdict");
    }

    #[test]
    fn nothing_but_a_review_can_be_answered_as_one() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        assert_eq!(state.release(Release::Withhold { note: String::new() }), None, "a release came out of an approval window");
        state.decide(approved_for_review());
        assert_eq!(state.release(Release::Withhold { note: String::new() }), None, "a release came out of a running window");
    }

    #[test]
    fn a_reviewed_run_cannot_be_kept_because_it_does_not_end_in_a_viewer() {
        let mut state = PromptState::new();
        state.handle(DaemonMsg::Request(Box::new(a_request(90))));
        state.decide(Verdict::Approve {
            stream: true,
            terminal: false,
            closing: false,
            review: true,
            note: String::new(),
        });
        assert!(!state.keep(), "a keep was promised for a window that ends in a question");
    }

    #[test]
    fn the_outcome_after_a_review_is_not_the_daemons_last_word() {
        // The reader thread arms the countdown that ends a lingering window
        // off the final frame. A reviewing window has no countdown of its
        // own -- the daemon holds the deadline -- and one armed anyway would
        // take the question away twelve seconds into reading it.
        let review = protocol::encode(&DaemonMsg::Review(a_review())).unwrap();
        let finished = protocol::encode(&DaemonMsg::Finished(Outcome::Exit { code: 0 })).unwrap();
        let (_, noticed) = read_noticing(&format!("{review}\n{finished}\n"));
        assert!(noticed.iter().all(|n| !n.final_frame), "{noticed:?}");

        let (_, plain) = read_noticing(&format!("{finished}\n"));
        assert!(plain.iter().any(|n| n.final_frame), "an ordinary ending stopped being noticed");
    }

    // ---- the review box, and the screen it leads to ------------------------

    /// Where a string is drawn on a settled frame of `app`, if it is.
    fn drawn_at(app: &mut PromptApp, ctx: &egui::Context, text: &str, at: Instant) -> Option<egui::Rect> {
        let shapes = a_settled_frame(app, ctx, at);
        text_rects(&shapes).into_iter().find(|(drawn, _)| drawn == text).map(|(_, rect)| rect)
    }

    /// Press and release the pointer at `place`, one frame for each half.
    fn click_at(app: &mut PromptApp, ctx: &egui::Context, place: egui::Pos2, at: Instant) {
        let button = |pressed| egui::Event::PointerButton {
            pos: place,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        a_live_frame(app, ctx, vec![egui::Event::PointerMoved(place)], at);
        a_live_frame(app, ctx, vec![button(true)], at);
        a_live_frame(app, ctx, vec![button(false)], at);
    }

    /// A command window, remembering `prefs`, with its review box clicked on
    /// a real frame.
    fn a_window_whose_review_box_was_clicked(
        prefs: PrefsFile,
    ) -> (PromptApp, Arc<std::sync::Mutex<Vec<u8>>>) {
        let (mut app, sink) = an_awaiting_window_remembering(prefs);
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let now = past_the_guard();
        let label = drawn_at(&mut app, &ctx, REVIEW_LABEL, now).expect("the review box is not drawn");
        click_at(&mut app, &ctx, label.center(), now);
        (app, sink)
    }

    #[test]
    fn a_command_window_offers_to_show_the_output_first_and_a_write_window_does_not() {
        for size in [opening_size(), egui::vec2(520.0, 700.0)] {
            let (mut command, _sink) = an_awaiting_window();
            let drawn = window_text_sized(&mut command, size);
            assert!(drawn.contains(REVIEW_LABEL), "a {size:?} command window has no review box: {drawn}");
            let drawn = window_text_sized(&mut a_write_window(), size);
            assert!(!drawn.contains(REVIEW_LABEL), "a {size:?} write window offers to review a file: {drawn}");
        }
    }

    #[test]
    fn the_review_box_fits_beside_the_terminal_box_at_the_size_the_window_opens_at() {
        // It costs no row of its own where there is room, which is the size
        // most windows are read at; the panes keep what they had.
        let (mut app, _sink) = an_awaiting_window();
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let now = past_the_guard();
        let review = drawn_at(&mut app, &ctx, REVIEW_LABEL, now).expect("drawn");
        let terminal = drawn_at(&mut app, &ctx, TERMINAL_LABEL, now).expect("drawn");
        assert!((review.center().y - terminal.center().y).abs() < 2.0, "{review:?} {terminal:?}");
        assert!(review.right() <= opening_size().x, "the box runs off the window: {review:?}");
    }

    #[test]
    fn ticking_the_review_box_is_remembered_and_unticking_it_is_too() {
        // Clicked on a real frame, so what is being tested is the box and
        // not the setter behind it.
        let (_root, paths) = a_prefs_file();
        let stored = Prefs {
            close_on_decide: false,
            stream: true,
            terminal: false,
            show_original: false,
            review: false,
        };
        PrefsFile::at(&paths).write(&stored);
        let (app, _sink) = a_window_whose_review_box_was_clicked(PrefsFile::at(&paths));

        assert!(app.reviews(), "the click did not reach the box");
        assert!(matches!(app.approval(), Verdict::Approve { review: true, .. }), "{:?}", app.approval());
        assert_eq!(
            PrefsFile::at(&paths).read(),
            Prefs { review: true, ..stored },
            "the tick reached the file, or reached more of it than the one box"
        );

        let (next, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));
        assert!(next.reviews(), "the next window did not open reviewing");

        // And back off again. A preference that could only ever be turned on
        // would be one the window offers no way out of.
        let (after, _sink) = a_window_whose_review_box_was_clicked(PrefsFile::at(&paths));
        assert!(!after.reviews(), "the second click did not untick it");
        assert!(!PrefsFile::at(&paths).read().review, "unticking it was not written down");
    }

    #[test]
    fn a_remembered_review_says_it_is_a_standing_choice_and_what_it_costs() {
        // The whole argument against remembering this box was that a tick
        // made on one sensitive command would silently put a person in the
        // return path of every call afterwards. It is remembered now, so the
        // answer has to be that the window says so -- on a window whose
        // command the reader has not read yet, in words that are true of a
        // choice made some other day.
        let (_root, paths) = a_prefs_file();
        PrefsFile::at(&paths).write(&Prefs { review: true, ..Prefs::default() });
        let (mut app, _sink) = an_awaiting_window_remembering(PrefsFile::at(&paths));
        let drawn = window_text_sized(&mut app, opening_size());

        assert!(app.reviews(), "the file's tick did not reach the window");
        assert!(drawn.contains(CLOSE_REVIEWING_ALWAYS), "{drawn}");
        assert!(
            drawn.contains("waits for you"),
            "the standing tick does not say what it costs: {drawn}"
        );
        assert!(
            !drawn.contains(CLOSE_REVIEWING),
            "it claimed the reader asked for this one: {drawn}"
        );

        // And once they touch the box, it is about this command again.
        let (mut mine, _sink) = a_window_whose_review_box_was_clicked(PrefsFile::at(&paths));
        mine.set_review(true);
        let drawn = window_text_sized(&mut mine, opening_size());
        assert!(drawn.contains(CLOSE_REVIEWING), "{drawn}");
        assert!(!drawn.contains(CLOSE_REVIEWING_ALWAYS), "{drawn}");
    }

    #[test]
    fn reviewing_beats_a_standing_order_to_close_and_the_greyed_box_says_why() {
        let (_root, paths) = a_prefs_file();
        PrefsFile::at(&paths).write(&Prefs { close_on_decide: true, ..Prefs::default() });
        let (mut app, _sink) = a_window_whose_review_box_was_clicked(PrefsFile::at(&paths));

        assert!(!app.closes_on_decide(), "it would have closed over the question it was asked to ask");
        assert!(app.close_on_decide, "the standing preference was overwritten rather than beaten");
        assert!(
            matches!(app.approval(), Verdict::Approve { closing: false, review: true, .. }),
            "{:?}",
            app.approval()
        );
        let said = window_text_sized(&mut app, opening_size());
        assert!(said.contains(CLOSE_REVIEWING), "the window ignored one of the two in silence: {said}");

        // And Alt+C cannot tick it past the review.
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::C, egui::Modifiers::ALT)], past_the_guard());
        assert!(!app.closes_on_decide());
        assert!(PrefsFile::at(&paths).read().close_on_decide, "the refused chord rewrote the file");

        app.review = false;
        assert!(app.closes_on_decide(), "unticking the review did not give the preference back");
    }

    #[test]
    fn a_run_under_review_says_its_output_is_held_and_offers_nothing_to_keep() {
        let (mut app, _sink) = an_awaiting_window();
        app.review = true;
        app.stream = true;
        app.state.decide(app.approval());
        let drawn = window_text_sized(&mut app, opening_size());
        assert!(!drawn.contains("Keep this window"), "{drawn}");

        let (mut quiet, _sink) = an_awaiting_window();
        quiet.review = true;
        quiet.state.decide(quiet.approval());
        let drawn = window_text_sized(&mut quiet, opening_size());
        assert!(drawn.contains("you will see it before it is sent"), "{drawn}");
    }

    /// A window on the review screen, with the daemon's review delivered the
    /// way a real one is: down the channel, through `take_arrivals`.
    fn a_reviewing_window_of(review: Review) -> (PromptApp, Arc<std::sync::Mutex<Vec<u8>>>) {
        let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let mut app =
            PromptApp::new(rx, Box::new(Sink(Arc::clone(&sink))), Arc::new(OnceLock::new()), PrefsFile::none());
        // Opened a minute ago, so its first guard has long been open: the
        // review arrives at a window somebody already answered, which is
        // the only kind it ever arrives at.
        let long_ago = Instant::now().checked_sub(Duration::from_secs(60)).expect("a minute of uptime");
        app.guard = Guard::new(long_ago);
        tx.send(Incoming::Frame(DaemonMsg::Request(Box::new(a_request(90))))).unwrap();
        app.take_arrivals();
        app.review = true;
        let frame = app.state.decide(app.approval());
        answer(&mut app.out, &mut app.state, frame);
        tx.send(Incoming::Frame(DaemonMsg::Review(review))).unwrap();
        tx.send(Incoming::Frame(DaemonMsg::Finished(Outcome::Exit { code: 0 }))).unwrap();
        app.take_arrivals();
        assert_eq!(app.state.phase(), Phase::Reviewing);
        sink.lock().unwrap().clear();
        (app, sink)
    }

    fn a_reviewing_window() -> (PromptApp, Arc<std::sync::Mutex<Vec<u8>>>) {
        a_reviewing_window_of(a_review())
    }

    /// What the window wrote back, as the one frame it should be.
    fn the_release(sink: &Arc<std::sync::Mutex<Vec<u8>>>) -> Option<Release> {
        let out = String::from_utf8(sink.lock().unwrap().clone()).unwrap();
        let mut lines = out.lines();
        let first = lines.next()?;
        assert!(lines.next().is_none(), "more than one frame went out: {out}");
        match protocol::read_message::<PromptMsg>(first).expect("a frame") {
            PromptMsg::Release(release) => Some(release),
            other => panic!("not a release: {other:?}"),
        }
    }

    #[test]
    fn the_review_screen_draws_each_pipe_apart_and_says_how_much_of_each_will_go() {
        let (mut app, _sink) = a_reviewing_window();
        let drawn = window_text_sized(&mut app, opening_size());

        assert!(drawn.contains(reviewing::NOTHING_SENT_YET), "{drawn}");
        assert!(drawn.contains("stdout — 3 of 3 lines will be sent"), "{drawn}");
        assert!(drawn.contains("stderr — 1 of 1 lines will be sent"), "{drawn}");
        assert!(drawn.contains("token=hunter2") && drawn.contains("warning: slow"), "{drawn}");
        assert!(drawn.contains("left to review"), "{drawn}");
        assert!(drawn.contains(reviewing::EXPIRY), "what the clock ends in is not said: {drawn}");
        assert!(drawn.contains(reviewing::SEND_LABEL) && drawn.contains(reviewing::WITHHOLD_LABEL));
        // The question it asked before is over, and its buttons with it.
        assert!(!drawn.contains("Approve") && !drawn.contains("left to decide"), "{drawn}");
    }

    #[test]
    fn a_filter_typed_on_the_screen_changes_what_is_drawn_before_anything_is_sent() {
        let (mut app, sink) = a_reviewing_window();
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let now = past_the_guard();
        let label = drawn_at(&mut app, &ctx, reviewing::DROP_LABEL, now).expect("the drop filter is not drawn");
        click_at(&mut app, &ctx, egui::pos2(label.right() + 60.0, label.center().y), now);
        a_live_frame(&mut app, &ctx, vec![egui::Event::Text("token".to_string())], now);

        let shapes = a_settled_frame(&mut app, &ctx, now);
        let drawn: String = text_rects(&shapes).into_iter().map(|(text, _)| text + "\n").collect();
        assert!(!drawn.contains("hunter2"), "the line the filter drops is still on screen: {drawn}");
        assert!(drawn.contains("stdout — 2 of 3 lines will be sent"), "{drawn}");
        assert!(sink.lock().unwrap().is_empty(), "typing a filter sent something");

        // And what goes is what was drawn.
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::Enter, egui::Modifiers::CTRL)], now);
        let Some(Release::Send { output, kept, .. }) = the_release(&sink) else {
            panic!("the chord did not send");
        };
        let crate::review::Sections::Streams { stdout, stderr } = output else { panic!() };
        assert_eq!(stdout, "ok: one\nok: two\n");
        assert_eq!(stderr, "warning: slow\n", "a filter that matched nothing on stderr took something");
        assert!(kept.is_empty());
        assert!(app.state.should_close(), "the window stayed after answering");
    }

    #[test]
    fn the_send_button_sends_and_escape_sends_nothing() {
        let (mut app, sink) = a_reviewing_window();
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let now = past_the_guard();
        let send = drawn_at(&mut app, &ctx, reviewing::SEND_LABEL, now).expect("Send is not drawn");
        click_at(&mut app, &ctx, send.center(), now);
        assert!(
            matches!(the_release(&sink), Some(Release::Send { .. })),
            "the button did not send"
        );

        let (mut app, sink) = a_reviewing_window();
        a_settled_frame(&mut app, &ctx, now);
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::Escape, egui::Modifiers::NONE)], now);
        assert_eq!(the_release(&sink), Some(Release::Withhold { note: String::new() }));
    }

    #[test]
    fn a_note_typed_at_the_review_goes_whichever_button_is_pressed() {
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let now = past_the_guard();

        // Typed into the real field on a real frame, not set on the draft:
        // the thing being tested is that the row on the screen is wired to
        // the answer, and a field nothing reaches would pass that on a
        // struct and fail on the window.
        let typed = |app: &mut PromptApp, sink: &Arc<std::sync::Mutex<Vec<u8>>>| {
            let label = drawn_at(app, &ctx, reviewing::NOTE_LABEL, now)
                .expect("the note field is not drawn on the review screen");
            click_at(app, &ctx, egui::pos2(label.right() + 60.0, label.center().y), now);
            a_live_frame(app, &ctx, vec![egui::Event::Text("ask me instead".to_string())], now);
            assert!(sink.lock().unwrap().is_empty(), "typing a note answered the review");
        };

        // Send carries it.
        let (mut app, sink) = a_reviewing_window();
        typed(&mut app, &sink);
        let send = drawn_at(&mut app, &ctx, reviewing::SEND_LABEL, now).expect("Send is not drawn");
        click_at(&mut app, &ctx, send.center(), now);
        let Some(Release::Send { note, .. }) = the_release(&sink) else { panic!("nothing sent") };
        assert_eq!(note, "ask me instead");

        // And so does the button that sends nothing, which is the arm this
        // matters most on: without the note the agent is told to ask the
        // person and given nothing to ask about.
        let (mut app, sink) = a_reviewing_window();
        typed(&mut app, &sink);
        let nothing = drawn_at(&mut app, &ctx, reviewing::WITHHOLD_LABEL, now)
            .expect("Send nothing is not drawn");
        click_at(&mut app, &ctx, nothing.center(), now);
        assert_eq!(
            the_release(&sink),
            Some(Release::Withhold { note: "ask me instead".to_string() }),
            "the words went with the output they were about"
        );
    }

    #[test]
    fn the_note_at_the_review_does_not_arrive_holding_what_was_sent_with_the_verdict() {
        // The verdict's note went when the verdict did. A field that opened
        // pre-filled with it would offer to send the same sentence twice,
        // and a reader who pressed Send without reading the field would.
        let (mut app, sink) = a_reviewing_window();
        app.note = "go on then".to_string();
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let now = past_the_guard();
        let send = drawn_at(&mut app, &ctx, reviewing::SEND_LABEL, now).expect("Send is not drawn");
        click_at(&mut app, &ctx, send.center(), now);
        let Some(Release::Send { note, .. }) = the_release(&sink) else { panic!("nothing sent") };
        assert!(note.is_empty(), "the verdict's note came back at the review: {note}");
    }

    /// A review of output long enough that a pane cannot show all of it.
    fn a_long_review() -> Review {
        let mut review = a_review();
        let text: String = (0..400).map(|n| format!("line {n}\n")).collect();
        review.output = crate::review::Sections::Streams {
            stdout: crate::review::Captured { text, truncated: false },
            stderr: crate::review::Captured { text: String::new(), truncated: false },
        };
        review
    }

    /// Which output lines are on screen in this frame.
    fn lines_on_screen(shapes: &[egui::epaint::ClippedShape]) -> Vec<String> {
        text_rects(shapes)
            .into_iter()
            .map(|(text, _)| text)
            .filter(|text| text.starts_with("line "))
            .collect()
    }

    #[test]
    fn space_pages_the_output_down_and_shift_space_pages_it_back() {
        let (mut app, sink) = a_reviewing_window_of(a_long_review());
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let now = past_the_guard();

        let first = lines_on_screen(&a_settled_frame(&mut app, &ctx, now));
        assert!(first.len() > 3, "the output does not fill a pane: {first:?}");
        assert_eq!(first.first().map(String::as_str), Some("line 0"));

        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::Space, egui::Modifiers::NONE)], now);
        let paged = lines_on_screen(&a_settled_frame(&mut app, &ctx, now));
        assert_ne!(paged.first(), first.first(), "Space did not move the output");

        // A screenful, not the whole thing, and with a line or two of the old
        // screen still there to place the new one against.
        let overlap = first.iter().filter(|line| paged.contains(line)).count();
        assert!(
            (1..=4).contains(&overlap),
            "a page kept {overlap} of the old screen: {first:?} then {paged:?}"
        );

        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::Space, egui::Modifiers::SHIFT)], now);
        let back = lines_on_screen(&a_settled_frame(&mut app, &ctx, now));
        assert_eq!(back.first(), first.first(), "Shift+Space did not come back");

        assert!(sink.lock().unwrap().is_empty(), "paging answered the review");
        assert_eq!(app.state.phase(), Phase::Reviewing);
    }

    #[test]
    fn space_is_a_space_whenever_a_field_has_the_keyboard() {
        // The whole safety of the paging key. This screen has four text
        // fields and three checkboxes on it, and Space belongs to whichever
        // of them holds the keyboard -- a window that swallowed the space bar
        // while somebody typed a filter would be unusable for the one thing
        // the filters are for.
        let (mut app, _sink) = a_reviewing_window_of(a_long_review());
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let now = past_the_guard();

        let label = drawn_at(&mut app, &ctx, reviewing::DROP_LABEL, now)
            .expect("the drop filter is not drawn");
        click_at(&mut app, &ctx, egui::pos2(label.right() + 60.0, label.center().y), now);
        let before = lines_on_screen(&a_settled_frame(&mut app, &ctx, now));

        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::Space, egui::Modifiers::NONE)], now);
        a_live_frame(&mut app, &ctx, vec![egui::Event::Text(" ".to_string())], now);
        let after = lines_on_screen(&a_settled_frame(&mut app, &ctx, now));

        assert_eq!(after.first(), before.first(), "Space paged out of a field it was typed into");
        assert_eq!(
            app.draft.field(reviewing::Filter::Drop),
            " ",
            "the space never reached the field"
        );
    }

    #[test]
    fn a_page_waits_for_the_guard_like_everything_else() {
        // A burst arriving as the window opens must not scroll the output
        // past the part the reader was meant to see first.
        let (mut app, _sink) = a_reviewing_window_of(a_long_review());
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let just_now = Instant::now();

        let first = lines_on_screen(&a_settled_frame(&mut app, &ctx, just_now));
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::Space, egui::Modifiers::NONE)], just_now);
        let after = lines_on_screen(&a_settled_frame(&mut app, &ctx, just_now));
        assert_eq!(after.first(), first.first(), "a keystroke in flight paged the output");
    }

    #[test]
    fn the_typing_guard_starts_again_when_the_review_appears() {
        // The review appears whenever the command finishes, and whoever is
        // at the keyboard may be typing somewhere else by then. A chord in
        // flight at that moment must not send the output.
        let (mut app, sink) = a_reviewing_window();
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        let just_now = Instant::now();
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::Enter, egui::Modifiers::CTRL)], just_now);
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::Escape, egui::Modifiers::NONE)], just_now);
        assert!(sink.lock().unwrap().is_empty(), "a keystroke in flight answered the review");
        assert_eq!(app.state.phase(), Phase::Reviewing);

        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::Enter, egui::Modifiers::CTRL)], past_the_guard());
        assert!(the_release(&sink).is_some(), "the guard never opened again");
    }

    #[test]
    fn a_character_that_would_hide_or_reorder_output_is_drawn_by_name() {
        let mut review = a_review();
        review.output = crate::review::Sections::Streams {
            stdout: crate::review::Captured {
                text: "pass\u{200B}word=1\nname\u{202E}txt\n".to_string(),
                truncated: true,
            },
            stderr: crate::review::Captured { text: String::new(), truncated: false },
        };
        let (mut app, _sink) = a_reviewing_window_of(review);
        let drawn = window_text_sized(&mut app, opening_size());

        assert!(drawn.contains("pass[ZWSP]word=1"), "{drawn}");
        assert!(drawn.contains("name[RLO]txt"), "{drawn}");
        assert!(!drawn.contains('\u{202E}') && !drawn.contains('\u{200B}'), "{drawn}");
        assert!(drawn.contains("output cap cut it short"), "a cut capture read as the whole: {drawn}");
        // The stream the command never wrote to is accounted for rather
        // than silently absent. One pane where there are normally two has to
        // be readable as "it printed nothing" and not as "hatch is not
        // showing you this", on a screen whose whole subject is what is and
        // is not passed on.
        assert!(drawn.contains("stderr: the command printed nothing there"), "{drawn}");
        assert!(
            !drawn.contains("stderr — 0 of 0 lines"),
            "an empty stream still took a pane's worth of screen: {drawn}"
        );
    }

    /// The same review with `stderr` never written to, which is what most
    /// commands leave behind.
    fn a_review_with_nothing_on_stderr() -> Review {
        let mut review = a_review();
        review.output = crate::review::Sections::Streams {
            stdout: crate::review::Captured {
                text: "ok: one\ntoken=hunter2\nok: two\n".to_string(),
                truncated: false,
            },
            stderr: crate::review::Captured { text: String::new(), truncated: false },
        };
        review
    }

    #[test]
    fn the_stream_a_command_never_wrote_to_gives_its_half_of_the_screen_back() {
        // Widths off real frames, because the thing being tested is a
        // layout: `ui.columns` is told how many panes there are, and a pane
        // that was merely skipped in the loop would leave its column behind
        // as empty screen.
        let widest = |review: Review| {
            let (mut app, _sink) = a_reviewing_window_of(review);
            let ctx = egui::Context::default();
            apply_faces(&ctx);
            apply_font_size(&ctx, 16.0);
            let shapes = a_settled_frame(&mut app, &ctx, past_the_guard());
            stroked_rects(&shapes)
                .into_iter()
                .map(|(rect, _)| rect.width())
                .fold(0.0_f32, f32::max)
        };

        let both = widest(a_review());
        let one = widest(a_review_with_nothing_on_stderr());
        assert!(
            one > both * 1.5,
            "the empty stream kept its column: one pane {one}, two panes {both}"
        );
    }

    #[test]
    fn hiding_an_empty_pane_changes_nothing_about_what_is_sent() {
        // The one way this could have gone wrong. The daemon reads a release
        // against the capture it is about and refuses a shape that does not
        // match -- see `Reviewed::of` -- so a window that stopped sending a
        // section because it stopped drawing it would have every review of a
        // quiet command released as nothing.
        let (mut app, sink) = a_reviewing_window_of(a_review_with_nothing_on_stderr());
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let now = past_the_guard();
        let send = drawn_at(&mut app, &ctx, reviewing::SEND_LABEL, now).expect("Send is not drawn");
        click_at(&mut app, &ctx, send.center(), now);

        let Some(Release::Send { output, .. }) = the_release(&sink) else { panic!("nothing sent") };
        let crate::review::Sections::Streams { stdout, stderr } = output else {
            panic!("the release changed shape with the drawing");
        };
        assert_eq!(stdout, "ok: one\ntoken=hunter2\nok: two\n");
        assert!(stderr.is_empty());
    }

    #[test]
    fn a_command_that_printed_nothing_at_all_still_draws_a_review() {
        // `ui.columns(0, ..)` divides the width by zero. A command that runs
        // and prints on neither stream is ordinary, and the review of it is
        // a real question: the reader still chooses whether the agent is
        // told the command ran.
        let mut review = a_review();
        review.output = crate::review::Sections::Streams {
            stdout: crate::review::Captured { text: String::new(), truncated: false },
            stderr: crate::review::Captured { text: String::new(), truncated: false },
        };
        let (mut app, _sink) = a_reviewing_window_of(review);
        let drawn = window_text_sized(&mut app, opening_size());

        assert!(drawn.contains("stdout: the command printed nothing there"), "{drawn}");
        assert!(drawn.contains("stderr: the command printed nothing there"), "{drawn}");
        assert!(drawn.contains(reviewing::SEND_LABEL), "there is nothing left to answer with: {drawn}");
    }

    #[test]
    fn a_filter_the_matcher_refuses_leaves_nothing_to_send_and_says_so() {
        let (mut app, sink) = a_reviewing_window();
        app.draft.field(reviewing::Filter::Drop).push_str(&"é".repeat(crate::review::MAX_PATTERN_BYTES));
        let drawn = window_text_sized(&mut app, opening_size());
        assert!(drawn.contains(reviewing::PATTERN_REFUSED), "{drawn}");

        let ctx = egui::Context::default();
        apply_faces(&ctx);
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::Enter, egui::Modifiers::CTRL)], past_the_guard());
        assert!(sink.lock().unwrap().is_empty(), "something was sent past a refused filter");
        assert_eq!(app.state.phase(), Phase::Reviewing);
    }

    #[test]
    fn a_redaction_is_drawn_and_sent_with_the_rest_of_its_line() {
        // The case the filters could not serve: the line is worth sending and
        // one thing on it is not.
        let (mut app, sink) = a_reviewing_window();
        app.draft.field(reviewing::Filter::Redact).push_str("hunter\\d");
        let drawn = window_text_sized(&mut app, opening_size());
        assert!(drawn.contains("token=[redacted]"), "{drawn}");
        assert!(!drawn.contains("hunter2"), "what was redacted is still on the screen: {drawn}");
        assert!(drawn.contains(reviewing::REDACT_LABEL), "{drawn}");
        // The count that answers "did that do anything", on the screen
        // without scrolling to look for a marker.
        assert!(drawn.contains("1 of them redacted"), "{drawn}");

        let ctx = egui::Context::default();
        apply_faces(&ctx);
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::Enter, egui::Modifiers::CTRL)], past_the_guard());
        let Some(Release::Send { output, kept, .. }) = the_release(&sink) else { panic!("nothing sent") };
        let crate::review::Sections::Streams { stdout, .. } = output else { panic!() };
        assert_eq!(stdout, "ok: one\ntoken=[redacted]\nok: two\n");
        assert!(kept.is_empty(), "a redaction was claimed to the agent as a keep pattern");
    }

    #[test]
    fn an_edit_made_on_the_screen_is_what_is_sent() {
        let (mut app, sink) = a_reviewing_window();
        let ctx = egui::Context::default();
        apply_faces(&ctx);
        apply_font_size(&ctx, 16.0);
        let now = past_the_guard();
        let edit = drawn_at(&mut app, &ctx, reviewing::EDIT_LABEL, now).expect("no way to edit");
        click_at(&mut app, &ctx, edit.center(), now);
        assert!(app.draft.editing(), "the button did not start an edit");
        let drawn = window_text_sized(&mut app, opening_size());
        assert!(drawn.contains(reviewing::UNEDIT_LABEL) && drawn.contains("edited by hand"), "{drawn}");

        let text = app.draft.edited(crate::review::Section::Stdout).expect("stdout is editable");
        *text = text.replace("hunter2", "[gone]");
        a_live_frame(&mut app, &ctx, vec![chord(egui::Key::Enter, egui::Modifiers::CTRL)], now);
        let Some(Release::Send { output, .. }) = the_release(&sink) else { panic!("nothing sent") };
        let crate::review::Sections::Streams { stdout, .. } = output else { panic!() };
        assert_eq!(stdout, "ok: one\ntoken=[gone]\nok: two\n");
    }
}
