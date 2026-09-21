//! The daemon ↔ prompt channel: `Request`, `Verdict`, `DaemonMsg`,
//! `PromptMsg`, and the framing that carries them.
//!
//! `hatch serve` spawns `hatch prompt` per request and talks to it over
//! line-delimited JSON on the child's stdin and stdout. One message per line,
//! in both directions:
//!
//! | Daemon → prompt | |
//! |---|---|
//! | [`DaemonMsg::Request`] | The one and only request. Always first. |
//! | [`DaemonMsg::QueueDepth`] | The "N more waiting" badge changed. |
//! | [`DaemonMsg::Output`] | A chunk of an approved command's output. |
//! | [`DaemonMsg::Review`] | The whole output, for a reader who asked to see it before it is sent. |
//! | [`DaemonMsg::Finished`] | How it ended. The last frame either way. |
//!
//! | Prompt → daemon | |
//! |---|---|
//! | [`PromptMsg::Verdict`] | Exactly one. |
//! | [`PromptMsg::Kill`] | The user pressed Kill on a running command. |
//! | [`PromptMsg::Release`] | What of the reviewed output the user will let the agent have. |
//!
//! # What the prompt is not allowed to do
//!
//! The daemon owns the clock, the rendering, and the decision to apply. The
//! shape of these types is what keeps that ownership from leaking, so each
//! piece of it is worth naming:
//!
//! * **It cannot extend its own deadline.** [`Request::deadline`] is an
//!   absolute instant, not a duration, and the window only *draws* the
//!   countdown. The timeout is enforced by the daemon killing the prompt
//!   process, so a wedged GUI that never notices its own clock is killed on
//!   time anyway. A duration would have made the deadline a thing the window
//!   restarts by being slow.
//! * **It cannot answer for a request it was not given.** A [`PromptMsg`]
//!   carries no request id, no path, no command and no deadline — nothing
//!   that names *which* operation is being decided. The daemon knows, because
//!   it holds the pipe and the child handle: identity is the channel, not a
//!   field a confused or hostile prompt could fill in. Adding an id here
//!   would be adding the ability to answer for someone else's window.
//! * **It cannot approve more than the operation it was shown.** The verdict
//!   set is closed, and what an [`Verdict::Approve`] carries besides itself is
//!   five things that cannot widen it: `stream` and `closing`, two display
//!   preferences about what this window does with itself; `terminal`, which
//!   says how the operation runs and can only ever *grant* a terminal to the
//!   command already on screen; `review`, which can only put a person between
//!   the output and the agent; and `note`, the words the person typed, which
//!   the daemon relays and never interprets. There is no field in which a
//!   command, an argument, a path or a mode could ride back.
//! * **It cannot pass off shaped output as whole.** [`PromptMsg::Release`]
//!   carries text back, which is new in this direction, and the text is what
//!   the person chose to send. What the daemon does *not* take from it is a
//!   description of that text: whether lines were removed or edited is read
//!   off the release against the output the daemon captured, so a window that
//!   is wrong about what it did still cannot make trimmed output reach the
//!   agent labelled as complete. See [`crate::review::Trimmed::of`].
//! * **[`PromptMsg::Kill`] is safe by direction.** A prompt that sends it
//!   early, twice, or for no reason can only stop a command. Everything a
//!   prompt can say unprompted fails towards deny, which is invariant 2.
//! * **It cannot draw a rendering nobody checked.** See below.
//!
//! The reverse direction is not a threat surface in the same way: the daemon
//! is the trusted party, and it is the process the user started. Everything
//! the receiving end checks below is bug containment, not defence against a
//! hostile daemon — but the checks are worth having precisely because a
//! rendering that quietly stops tiling its source is the failure this project
//! exists to prevent.
//!
//! # How a rendering crosses the pipe
//!
//! [`Spans`] is evidence: holding one means [`SpanBuilder::finish`] proved
//! those spans tile their source exactly once, and [`Span`]'s private fields
//! mean nothing since has rewritten a character. Deriving `Deserialize` on
//! [`Span`] would have handed that away — a derived impl builds spans without
//! the builder, so a deserialised `Spans` would be a rendering nobody ever
//! checked, and it would be the same type as one that was. The window would
//! then be trusting a value for its type while the type had stopped meaning
//! anything.
//!
//! So a rendering crosses as **its source text plus the offsets its spans end
//! at**, and the receiving end rebuilds it through the real
//! [`SpanBuilder`]:
//!
//! * The wire carries the text **once**. A [`WireSpan`] is an end offset, a
//!   [`SpanKind`] and a layout flag — it has no text of its own, so no frame
//!   can express a span whose text is not the substring of the source it
//!   claims. Invariant 1 is not checked on the wire; it is unrepresentable
//!   there.
//! * [`rebuild_spans`] walks those offsets through [`SpanBuilder::push_to`],
//!   which is the only constructor there is. Gaps, overlaps, out-of-order
//!   spans and an uncovered tail are refused, and so are a chip over more
//!   than one codepoint and a resolution beside text that is not one
//!   variable reference — the same two bounds the model enforces in process.
//! * Kinds are the one part that deserialises as itself, because a kind is
//!   display metadata carrying no invariant of its own. Every invariant is a
//!   relation between a kind and the text it sits on, and attaching it to
//!   text is what goes through the checks.
//!
//! **What the prompt may assume about what it receives:** that a rendering it
//! obtained from [`Payload::rendering`] or [`Payload::rows`] tiles its source
//! exactly once, that every span's text is the source's own bytes, and that
//! the one-line form it was sent agrees with those spans. Nothing weaker, and
//! nothing it did not get through those two functions.
//!
//! **What it may not assume:** that the source is the command that will run.
//! Nothing on this channel can establish that — it is the daemon's job to
//! render the argv it will execute — and it is invariant 4, not a property of
//! this module. The prompt also may not assume a frame is well-formed: every
//! rebuild returns a [`ProtocolError`] rather than panicking, because this
//! input arrives over a pipe.
//!
//! # Framing
//!
//! NDJSON needs each message to occupy exactly one line, and today
//! `serde_json::to_string` gives that for free: it escapes `\n` inside
//! strings and emits no whitespace of its own. "For free" is the problem —
//! it is a property of the serialiser rather than of this protocol, and a
//! pretty-printer, a custom `Serialize`, or a future field could take it away
//! without a single call site changing. So the check lives in [`encode`],
//! which every writer goes through, and a message that would not frame is an
//! error rather than a corrupt stream. Framing is a decision this module
//! makes, not an accident it benefits from.
//!
//! # Wire compatibility
//!
//! There is none to keep, deliberately. The daemon spawns *its own
//! executable* as the prompt, so both ends of this channel are always the
//! same build; a frame never crosses a version boundary. That is why no field
//! has a serde default and no struct is tolerant of a missing key: a decode
//! failure here means the two ends disagree about the protocol, which cannot
//! happen without a bug, and a loud failure is worth more than a field
//! silently reading as zero. It is also why adding a variant later costs
//! nothing — which is an argument about cost, not about whether a variant
//! belongs. See [`Outcome`] for one that does.

use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::exec::Stream;
use crate::render::diff::{Row, Side};
use crate::render::language::Snippet;
use crate::render::{Span, SpanBuilder, SpanKind, Spans, variable_name};
use crate::swap::SwapPlan;

// ---- framing ---------------------------------------------------------------

/// Why a message could not be encoded, decoded, or believed.
///
/// Owned strings for the serde failures rather than a `serde_json::Error`, on
/// the same reasoning as [`crate::exec::ExecError`]: the value is compared in
/// tests and may be written to the audit log, and neither wants a type that
/// is neither `Clone` nor `PartialEq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// The message could not be serialised at all.
    Encode(String),
    /// The line was not a message of the expected type.
    Decode(String),
    /// The encoding contained a newline, so writing it would have produced
    /// two frames out of one message. See the module docs on framing.
    Framing,
    /// A span ends where the previous one did or earlier: spans must tile
    /// their source left to right.
    SpanOutOfOrder {
        /// The offending end offset.
        end: usize,
        /// Where the previous span left the cursor.
        cursor: usize,
    },
    /// A span ends past the end of its source, or not on a character
    /// boundary.
    SpanBounds {
        /// The offending end offset.
        end: usize,
        /// The length of the source it was measured against.
        len: usize,
    },
    /// The spans stop short of the end of their source, so part of the text
    /// would never be drawn.
    SpansDoNotCover {
        /// How much of the source the spans reach.
        covered: usize,
        /// How much there is.
        len: usize,
    },
    /// A chip was placed over more than one codepoint — invariant 1b.
    ChipNotOneCodepoint,
    /// A resolved value was placed beside text that is not exactly one
    /// variable reference.
    NotOneVariableReference,
    /// A diff line's spans do not break where its terminator starts.
    TerminatorNotAtSpanBoundary,
    /// The one-line form disagrees with the spans it was sent beside.
    DisplayLineDisagrees,
    /// A payload was asked for something the other variant carries.
    WrongPayload {
        /// The variant the caller wanted.
        wanted: &'static str,
    },
    /// The run a payload calls a program is not a run of its command: empty,
    /// past the end, off a character boundary, or not the text of any whole
    /// sequence of spans.
    ProgramNotARun {
        /// Where the run was said to begin.
        start: usize,
        /// Where it was said to end.
        end: usize,
    },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::Encode(e) => write!(f, "the message could not be encoded: {e}"),
            ProtocolError::Decode(e) => write!(f, "the line is not a message: {e}"),
            ProtocolError::Framing => f.write_str(
                "the encoded message contains a newline, which would split it across two frames",
            ),
            ProtocolError::SpanOutOfOrder { end, cursor } => write!(
                f,
                "a span ending at {end} does not follow the one ending at {cursor}: \
                 spans must tile their source in order"
            ),
            ProtocolError::SpanBounds { end, len } => write!(
                f,
                "span end {end} is past the end of a {len}-byte source or not on a \
                 character boundary"
            ),
            ProtocolError::SpansDoNotCover { covered, len } => write!(
                f,
                "the spans cover {covered} of {len} bytes: the rest would never be drawn"
            ),
            ProtocolError::ChipNotOneCodepoint => f.write_str(
                "a chip stands for exactly one codepoint: a label may not hide more text \
                 than it replaces",
            ),
            ProtocolError::NotOneVariableReference => f.write_str(
                "a resolved value beside text that is not one variable reference is a claim \
                 about text that does not make it",
            ),
            ProtocolError::TerminatorNotAtSpanBoundary => {
                f.write_str("a diff line does not break its spans at the line terminator")
            }
            ProtocolError::DisplayLineDisagrees => {
                f.write_str("the one-line form does not match the spans it was sent beside")
            }
            ProtocolError::ProgramNotARun { start, end } => write!(
                f,
                "the payload calls {start}..{end} a program, which is not a run of its command"
            ),
            ProtocolError::WrongPayload { wanted } => {
                write!(f, "this is not a {wanted} payload")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

/// The framing rule, in one place: an encoded message is one line.
///
/// Separated from [`encode`] so it is directly testable. Nothing
/// `serde_json::to_string` produces can fail it today, which is exactly why
/// it is here rather than assumed — see the module docs.
fn check_single_line(encoded: &str) -> Result<(), ProtocolError> {
    if encoded.contains('\n') {
        return Err(ProtocolError::Framing);
    }
    Ok(())
}

/// Encode one message as a single NDJSON line, without its terminator.
///
/// The only way a message becomes text in this crate. Every writer goes
/// through it, so the framing check cannot be bypassed by a caller that
/// serialises for itself.
pub fn encode<M: Serialize>(message: &M) -> Result<String, ProtocolError> {
    let encoded =
        serde_json::to_string(message).map_err(|e| ProtocolError::Encode(e.to_string()))?;
    check_single_line(&encoded)?;
    Ok(encoded)
}

/// Write one message as a frame: the encoding, a newline, and a flush.
///
/// The flush is not optional. Both ends of this channel block waiting for the
/// other, and a request sitting in a pipe buffer is a window that never
/// opens.
pub fn write_message<W: Write, M: Serialize>(out: &mut W, message: &M) -> io::Result<()> {
    let encoded = encode(message).map_err(io::Error::other)?;
    out.write_all(encoded.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()
}

/// Decode one frame. `line` is one line off the channel, without its
/// terminator.
pub fn read_message<M: DeserializeOwned>(line: &str) -> Result<M, ProtocolError> {
    serde_json::from_str(line).map_err(|e| ProtocolError::Decode(e.to_string()))
}

// ---- daemon → prompt -------------------------------------------------------

/// What the daemon says to one prompt window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonMsg {
    /// The request. Always the first frame, and there is never a second.
    ///
    /// Boxed because it is ten times the size of every other frame on this
    /// channel, and an enum is as large as its largest variant wherever one
    /// is held: a window streaming a command's output moves one of these per
    /// chunk, and without the box each of those chunks would carry the
    /// footprint of a request that arrived once and is long since over. The
    /// allocation is paid on the one frame that has already allocated the
    /// whole rendering.
    Request(Box<Request>),
    /// The queue behind this window changed. A struct variant rather than a
    /// newtype because an internally tagged enum needs its content to be a
    /// map: `{"type":"queue_depth"}` has nowhere to put a bare number.
    QueueDepth {
        /// How many approvals are waiting behind this one.
        depth: u32,
    },
    /// A chunk of an approved command's output, for the streaming view.
    Output {
        /// Which pipe it came from. Kept apart so a diagnostic on stderr is
        /// not read as part of the answer.
        stream: Stream,
        /// The text.
        ///
        /// Text and not bytes, because JSON has no bytes and base64 would
        /// only move the problem: a chunk boundary falls wherever the kernel
        /// split the output, very often mid-character, so somebody has to
        /// reassemble before decoding. That somebody is the daemon, which
        /// already holds the whole stream — see [`crate::exec::Chunk`] on why
        /// chunks are bytes in the first place. The window is a display, and
        /// a display that decodes is a display that can show a replacement
        /// character the daemon never saw.
        text: String,
    },
    /// The elevation program has been started and the password dialog is
    /// expected; nothing the user approved has run yet.
    ///
    /// A frame of its own with no payload. No payload because the sentence
    /// belongs to the window — the daemon knows *that* a second gate is now
    /// in front of the operation, and the window knows how it words things to
    /// a reader — and a text field here would be one more place for the
    /// daemon to put a string on somebody's screen.
    ///
    /// A frame at all because of what the window is showing at that moment.
    /// It has had its verdict, it has shrunk to a running indicator, and it
    /// says the operation is running. That is not true yet: a password dialog
    /// from another process is about to appear on top of it, and a reader who
    /// has been told "it is running" has no reason to connect the two, or to
    /// know that dismissing the dialog stops something they already approved.
    Elevating,
    /// Everything the command left for the agent, held back until the reader
    /// who asked to see it has decided what of it to send.
    ///
    /// Sent only to a window whose approval carried `review`, once the run is
    /// over and immediately before its [`DaemonMsg::Finished`], so that the
    /// window reads the ending knowing it has a question to ask: see
    /// [`Outcome::stays`].
    ///
    /// The whole capture in one frame, and not the [`DaemonMsg::Output`]
    /// chunks already sent to a streaming window. Those are uncapped and the
    /// window keeps the last megabyte of them; what the agent would receive
    /// is the capture, cut at the output cap from the other end. A review of
    /// the live view would be a review of different text from the text being
    /// released.
    Review(Review),
    /// How the command ended. The last frame the daemon sends.
    ///
    /// Strictly, how one *operation* ended: the daemon sends one for each
    /// operation it attempts, in the order of [`Request::operations`], and the
    /// output and elevation frames before it belong to that operation. A
    /// request carries one operation today, so the one `Finished` is also the
    /// last frame, and the window is entitled to close on it. No index rides
    /// along because the order already is one -- operations run in sequence
    /// and never overlap.
    ///
    /// What the window does with it is decided from what the frame says and
    /// not sent alongside it: a run the reader ticked the stream box on stays
    /// for a few seconds with the result on it, and so does any operation
    /// whose ending is news — see [`Outcome::is_news`] — while the rest close
    /// here. The frame says how it ended and nothing about how long anyone
    /// looks.
    Finished(Outcome),
}

/// How an approved operation ended.
///
/// # Why `ElevationFailed` is one of these
///
/// The spec calls an elevation failure a *routine*
/// outcome — the user approves in hatch and then dismisses the polkit
/// password dialog — and [`crate::audit::LogVerdict::ElevationFailed`]
/// already records it. An enum of `Exit` and `Signal` alone would be a type
/// that cannot say what happened, and a type that cannot say what happened
/// invites the caller to say something else instead: an exit code of 1 for a
/// command that never ran is exactly the kind of plausible-looking lie this
/// project refuses everywhere else. The variant costs a line; the alternative
/// costs the window's honesty at the moment it closes.
///
/// Timed-out and killed-by-user are deliberately *not* variants. Both end the
/// command with a signal, and the distinction between them belongs to the
/// tool result and to the audit log, which is where anyone can still read it
/// after the window is gone. A window that lingers over this frame draws the
/// outcome for seconds rather than for none, which is an argument for keeping
/// the wording plain, not for a field: "ended by signal 9" is what happened,
/// and which of the two reasons it was is a sentence the tool result already
/// gives the agent and the log already gives the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Outcome {
    /// The command exited on its own.
    Exit {
        /// Its exit status.
        code: i32,
    },
    /// A signal ended it — hatch's own kill at the Kill button or the
    /// execution timeout, or something else such as a segmentation fault.
    Signal {
        /// The signal number.
        signal: i32,
    },
    /// The operation was approved, but root elevation failed or was
    /// cancelled, so nothing ran.
    ElevationFailed {
        /// What to tell the user, as text.
        message: String,
    },
    /// The operation was approved and elevation was attempted, and hatch
    /// cannot say whether it ran.
    ///
    /// The third variant exists for the reason the second one does, one step
    /// further along. [`Outcome::ElevationFailed`] stops an exit code being
    /// invented for a command that never ran; this stops *either* of the
    /// other two being drawn for a command hatch has no evidence about. The
    /// window stays up to show this frame — it is news, see
    /// [`Outcome::is_news`] — so whatever it says here is what the person who
    /// approved the operation reads about it, and "Finished — exit 1" or
    /// "Nothing ran" would both be a claim hatch cannot support. See
    /// [`crate::exec::elevate::RootOutcome::Unclear`].
    Unclear {
        /// What to tell the user, as text.
        message: String,
    },
    /// A file was written, and it is the file the window described.
    ///
    /// Its own variant rather than the `Exit { code: 0 }` it used to be sent
    /// as. A write has no process and so no status, and an exit code standing
    /// in for "it landed" is a number drawn from the vocabulary of a command
    /// onto a window about a file: "Finished — exit 0" under a diff. It also
    /// made two different facts share a spelling, and a window reading the
    /// frame could not tell a command's answer from a file's landing — which
    /// is the difference [`Outcome::is_news`] turns on.
    ///
    /// A root write hatch could not re-examine afterwards is sent as this
    /// too. That is the absence of evidence against the write, not evidence
    /// for a different one, and the tool result is where it is said.
    Written,
    /// The operation did not do what was approved, and hatch can say how in
    /// words that are neither a status nor an elevation's.
    ///
    /// For the endings the four variants above cannot state without
    /// inventing something: a write refused at the moment of writing because
    /// the file moved, a root write that landed as something other than the
    /// window described, an `install` that failed part way, a command that
    /// could not be started at all. Each of them used to be an exit code of
    /// 1 or no frame, which is the plausible-looking lie the first paragraph
    /// of this type is about.
    Failed {
        /// What to tell the user, as text: hatch's own sentence, which may
        /// quote a path or another program's diagnostic.
        message: String,
    },
}

impl Outcome {
    /// Whether this ending tells the person who approved the operation
    /// something they did not already know — which is the whole of whether a
    /// window nobody asked to watch stays up to show it.
    ///
    /// # Why a window stays only for news
    ///
    /// Between closing on the outcome and holding it up for a while, the one
    /// thing worse than either is a flash: a result on screen for half a
    /// second, too short to read and long enough to catch the eye. So a
    /// window either goes at once or stays long enough to be read, and what
    /// decides it is whether there is anything to read. The rule belongs to
    /// the frame rather than to either end of the pipe, because both ends act
    /// on it — the window by lingering, the daemon by letting go of a window
    /// that is going to — and a rule each of them wrote down separately is
    /// one they could come to disagree about, with the daemon killing a
    /// window half way through what it stayed to say.
    ///
    /// # A write
    ///
    /// [`Outcome::Written`] is not news. The window drew the diff, the mode
    /// and the owner before anybody approved them, and a write that landed
    /// as described adds nothing to what the reader already saw and said yes
    /// to. Every other ending of a write is: refused because the file moved,
    /// landed as something else, left short by a failed `install`, a password
    /// dialog dismissed or unreadable. Each means the file is not what the
    /// reader approved, and the tool result reaching the agent is no help to a
    /// person who is not reading it.
    ///
    /// # A command
    ///
    /// An [`Outcome::Exit`] is not news, whatever its status. A non-zero exit
    /// is very often the answer the command was run to get — `grep` finding
    /// nothing, `diff` finding a difference, `test` saying no — which is the
    /// same reason `stop_on_failure` is the agent's to choose rather than
    /// hatch's to impose. The status goes to the agent, which asked the
    /// question; a window that stayed up for every `grep` with no match would
    /// teach its reader that a staying window means nothing.
    ///
    /// Everything else is. A status is something a command chose to say; the
    /// other endings are things that happened to it, and none of them is an
    /// answer:
    ///
    /// * [`Outcome::Signal`] — hatch ended it at the execution deadline, the
    ///   reader pressed Kill, or it crashed. The window cannot tell the three
    ///   apart and does not need to: in each the run was cut short, what it
    ///   left is unknown, and a reader who pressed Kill is owed the sight of
    ///   it having worked.
    /// * [`Outcome::Failed`] — hatch could not start it, so nothing ran.
    /// * [`Outcome::ElevationFailed`] — nothing ran, whether because the
    ///   dialog was dismissed or because elevation was not possible. The
    ///   first is something the reader did, and it is still news that hatch
    ///   took it as a cancellation rather than as a slow answer.
    /// * [`Outcome::Unclear`] — hatch cannot say whether it ran, which is the
    ///   one ending whose next step is the reader's rather than the agent's.
    ///
    /// # A batch
    ///
    /// A request carries one operation today. When it carries several, each
    /// sends its own outcome, and the rule is: a window nobody asked to watch
    /// stays if **any** operation's ending is news. One failed write among
    /// five that landed is exactly the ending a window that closed would hide,
    /// and a window that stayed for the last operation alone would hide it
    /// whenever it was not last. What it would show then is every operation's
    /// ending, the quiet ones included, so the news is read in its place.
    ///
    /// # A run under review
    ///
    /// Not a question this function is asked. A window whose reader asked to
    /// see the output before it is sent stays whatever the ending, news or
    /// not, because it is no longer showing a result: it is asking what of
    /// the result the agent may have, and nothing reaches the agent until it
    /// is answered. That is not news in the sense above and does not pretend
    /// to be. [`Outcome::stays`] is where the two reasons and the third meet,
    /// and both ends of the pipe ask it rather than this.
    ///
    /// # What it does not touch
    ///
    /// The agent's result. The window is the person's and the tool result is
    /// the agent's; nothing here changes what the agent is told, or when.
    pub fn is_news(&self) -> bool {
        match self {
            Outcome::Exit { .. } | Outcome::Written => false,
            Outcome::Signal { .. }
            | Outcome::ElevationFailed { .. }
            | Outcome::Unclear { .. }
            | Outcome::Failed { .. } => true,
        }
    }

    /// Whether a window stays after this ending, rather than going at once.
    ///
    /// The whole rule, in the one place both ends of the pipe read it: the
    /// window by staying, the daemon by not ending a window that is going to.
    /// Three reasons, and any one is enough:
    ///
    /// * `reviewed` — the window was sent a [`DaemonMsg::Review`] and has a
    ///   question on it. It stays regardless of the ending, and it is the one
    ///   staying window the daemon keeps hold of rather than letting go,
    ///   because the answer is still to come back up the pipe.
    /// * `watched` — the reader ticked the stream box.
    /// * [`Outcome::is_news`] — the ending is something the reader could not
    ///   have known from what they approved.
    pub fn stays(&self, watched: bool, reviewed: bool) -> bool {
        reviewed || watched || self.is_news()
    }
}

/// The output of an approved command, held up for the reader to decide about.
///
/// See [`DaemonMsg::Review`] for when it is sent, and [`crate::review`] for
/// what the reader may do with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Review {
    /// When the review expires, on the daemon's clock.
    ///
    /// Absolute for the reason [`Request::deadline`] is. At this instant the
    /// daemon releases nothing and ends the window; the window only draws the
    /// countdown to it.
    pub deadline: DateTime<Utc>,
    /// The output as the agent would otherwise have received it, section by
    /// section.
    pub output: crate::review::Sections<crate::review::Captured>,
}

/// The one request a window is about.
///
/// Every field is required on the wire: no serde defaults, no
/// `skip_serializing_if`. A window that opened with a field silently defaulted
/// would be a window making a decision on less than it was sent, and the two
/// ends of this channel are the same build, so a missing key is a bug worth
/// failing on rather than a version to tolerate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// The agent's one-line summary of what it wants.
    ///
    /// Agent-controlled text, so the daemon sends it already defanged by
    /// [`crate::render::unicode::defang`]: it frames the whole decision and a
    /// bidi override in it would reorder everything the reader sees. The
    /// window draws it as text and must not undo that.
    pub title: String,
    /// Why the agent says it needs this now, defanged on the same terms as
    /// `title`.
    pub reason: String,
    /// When this window's approval expires, as an instant on the daemon's
    /// clock.
    ///
    /// Absolute and not a duration, and this is the whole point: the daemon
    /// enforces the timeout by killing the prompt process, and the window only
    /// renders the countdown. A duration would be a clock the window owns, and
    /// a wedged GUI would extend its own deadline by being slow to start it.
    pub deadline: DateTime<Utc>,
    /// How many approvals were waiting behind this one when the window
    /// opened. Later changes arrive as [`DaemonMsg::QueueDepth`].
    pub queue_depth: u32,
    /// Which window this is, counting from one: the number the window puts in
    /// its title bar, and the number the audit record carries.
    ///
    /// Two windows are otherwise the same object in a task switcher, and
    /// answering one while the next opens in the same instant reads as the
    /// first being clobbered. The number is what tells them apart there, and
    /// it is a handle a person can say out loud into a log.
    ///
    /// `None` is *not* a daemon that forgot. It means nobody is counting:
    /// [`crate::preview`] builds one of these to draw a window with, and a
    /// preview is not the first of anything. A window with no number keeps
    /// the title it was opened with. Required on the wire like every other
    /// field -- an explicit null, not an absent key. See
    /// [`crate::queue::Admission::number`] for where a real one comes from
    /// and why it starts again at one on every run of the daemon.
    pub number: Option<u64>,
    /// What is being asked for: every operation this one approval covers, in
    /// the order the daemon will carry them out.
    ///
    /// A list, and a list even while it only ever holds one. hatch takes one
    /// operation per call for now -- see [`crate::server::MAX_OPERATIONS`] --
    /// and the window draws exactly one, but the request is shaped like the
    /// batch it is. When a window learns to draw several, that is a change to
    /// the window and not to this channel.
    ///
    /// The order is a guarantee and not a presentation. The daemon runs the
    /// operations in exactly this order, so a window that draws them in this
    /// order is drawing the sequence that will happen; one that sorted them,
    /// grouped writes apart from commands, or put the root operation first
    /// would be asking for approval of a different script.
    pub operations: Vec<Payload>,
    /// Whether the daemon stops at the first operation that fails, or carries
    /// on and runs the rest.
    ///
    /// The agent's choice, carried here because it is part of what is being
    /// approved. Continuing past a failure runs approved operations in a
    /// state the reader may not have pictured -- "write the config, then
    /// reload" reloads against the old file if the write was refused for
    /// drift -- so which of the two it is has to be something a person can
    /// see before they say yes, not something decided out of their sight.
    /// With one operation there is nothing after it to stop or to run, and
    /// the window says nothing about it: see
    /// [`crate::prompt_ui::PromptState::sequencing`].
    pub stop_on_failure: bool,
    /// Windows that ended since the last one somebody answered, and how each
    /// of them ended.
    ///
    /// The agent is told when a request ends without a decision -- it
    /// expired, the call went away, the window's process died -- and until
    /// this field existed the person was told nothing at all. Their window
    /// vanished and the next thing they saw was an agent that had moved on,
    /// which is indistinguishable from having denied something by accident.
    ///
    /// Carried on the request rather than pushed as its own message because
    /// there is nothing to show it on until a window exists: a notice about a
    /// window that is gone needs a window to be drawn in, and the next one is
    /// the first place it can appear.
    ///
    /// Empty on almost every request, and an empty list draws nothing. It is
    /// required on the wire like every other field.
    pub unanswered: Vec<Unanswered>,
}

/// One window that ended without the reader deciding anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unanswered {
    /// Which window it was, by the number it wore in its title bar, so a
    /// person can find it in the log. `None` when nobody was counting.
    pub number: Option<u64>,
    /// When it ended, on the daemon's clock.
    pub at: DateTime<Utc>,
    /// How it ended.
    pub how: Unheard,
}

/// The ways a window can end with nobody having decided.
///
/// Three, and the distinction between them is the whole value of the notice:
/// "you ran out of time" and "the agent stopped waiting" are different facts
/// about different parties, and a reader who is told only that something
/// vanished cannot tell which of them to do anything about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unheard {
    /// Nobody answered before the approval timeout.
    Expired,
    /// The agent's call went away -- it disconnected, or it cancelled --
    /// while the window was still asking.
    AgentLeft,
    /// The window's own process ended before a verdict: it was closed from
    /// its title bar, or it died.
    WindowDied,
}

/// One operation, already rendered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    /// A command: the one `run_command` asks for, or one operation of a
    /// `batch`.
    Command {
        /// The rendering as one line: every span's `display_text`
        /// concatenated, so chips read as their labels and line breaks are
        /// ignored. For the title bar and the running indicator, where the
        /// full rendering does not fit.
        ///
        /// It is derivable from `spans`, which would normally be an argument
        /// against sending it — a second copy is a second thing to drift.
        /// Here it is checked instead: [`Payload::rendering`] refuses a
        /// payload whose `display_line` does not match the spans, so the
        /// duplicate is a checksum rather than a rumour. Do not construct
        /// this variant by hand; [`Payload::command`] fills all three text
        /// fields from one rendering so they cannot be made to disagree in
        /// the first place.
        display_line: String,
        /// The rendering, as end offsets and kinds over `raw`. No text of its
        /// own — see the module docs.
        spans: Vec<WireSpan>,
        /// The exact command line the approval covers, and the source the
        /// spans tile. This is the only copy of the text in this variant.
        raw: String,
        /// Danger markers found in the command, as short labels for the
        /// header list. Visual only: they never block, and an empty list is
        /// not a claim that the command is safe.
        danger: Vec<String>,
        /// What the command will run, deduplicated and resolved: the
        /// roster. Built by [`crate::render::roster::roster`] against the
        /// environment the command is going to receive, and against the
        /// filesystem as it was when the request was prepared.
        ///
        /// On the wire rather than worked out in the window because the
        /// lookup needs the child `PATH`, and the child `PATH` is the
        /// daemon's config; a window that resolved names against its own
        /// environment would name files the command will never reach.
        ///
        /// Display only, like `danger`. An empty list is not a claim that a
        /// command runs nothing — see [`Payload::with_runs`] for why it is
        /// filled in by a separate call.
        runs: Vec<crate::render::roster::Entry>,
        /// The working directory it will run in.
        ///
        /// A `PathBuf` rather than a `String`: JSON cannot carry a non-UTF-8
        /// path at all, and serialisation failing on one is a request that
        /// never opens a window, which resolves to deny. Converting lossily
        /// to a `String` would instead put a path on screen that is not the
        /// path that will be used.
        cwd: PathBuf,
        /// Whether it was requested as root. The rendering already shows the
        /// `run0` line; this is for the header.
        root: bool,
        /// Whether it runs in a terminal of its own, which disables the
        /// stream checkbox.
        interactive: bool,
        /// How this command will differ from the same command run
        /// unprivileged, when it will — [`crate::exec::elevate::Elevation::caveat`].
        ///
        /// `None` for every unelevated request, and a paragraph for a root
        /// one. It is on the wire rather than written into the window because
        /// the difference it describes belongs to whichever elevation
        /// mechanism this build has, and the window is not the place that
        /// knows which one that is.
        ///
        /// Required on the wire like every other field: `None` is an explicit
        /// null, not an absent key. See the type's own note on defaults.
        caveat: Option<String>,
        /// Which bytes of `raw` are the program hatch itself put inside
        /// quotes, and what that program is written in.
        ///
        /// `None` unless hatch built the invocation — an elevated request, or
        /// one that named an interpreter — and `None` for a program whose
        /// quoting rewrote its bytes. See
        /// [`crate::exec::elevate::ElevatedArgv::script_at`] and
        /// [`crate::exec::interpreter`].
        ///
        /// The language is the load-bearing half. A shell program is read
        /// again as shell and the spans arrive that way; a Python one is not,
        /// and a window that assumed otherwise would bracket Python `for` and
        /// `done` as shell constructs. It is also not a reading — hatch is
        /// about to spawn the interpreter named in the argv on this very
        /// line — which is why it arrives as a
        /// [`Evidence::Declared`](crate::render::language::Evidence::Declared)
        /// snippet rather than as something the window works out.
        ///
        /// Checked on arrival like everything else here: see
        /// [`Payload::program`].
        program: Option<Snippet>,
    },
    /// A file write: one operation of a `batch`.
    Swap {
        /// The file to be replaced or created.
        path: PathBuf,
        /// Where the bytes will land. Display only — the daemon re-stats and
        /// re-hashes at apply time and refuses on drift.
        plan: SwapPlan,
        /// The side-by-side diff, one row at a time.
        rows: Vec<WireRow>,
    },
}

impl Payload {
    /// Build a command payload from one rendering.
    ///
    /// The three text fields are filled from `spans` rather than passed in,
    /// so a caller cannot hand the window a one-line form, a raw command and
    /// a set of spans that describe three different things.
    pub fn command(
        spans: &Spans,
        danger: Vec<String>,
        cwd: PathBuf,
        root: bool,
        interactive: bool,
    ) -> Payload {
        Payload::Command {
            display_line: display_line(spans),
            spans: wire_spans(spans),
            raw: spans.source().to_string(),
            danger,
            runs: Vec::new(),
            cwd,
            root,
            interactive,
            caveat: None,
            program: None,
        }
    }

    /// The same payload, knowing which of its bytes hatch quoted a program
    /// into and what that program is. See [`Payload::Command::program`].
    ///
    /// Separate from [`Payload::command`] for [`Payload::with_caveat`]'s
    /// reason: the one caller that has an elevated line to describe is the
    /// one caller that says anything here, and every other call site says
    /// nothing by construction rather than by remembering to.
    ///
    /// A no-op on a swap payload, which has no command line at all.
    pub fn with_program(self, program: Option<Snippet>) -> Payload {
        match self {
            Payload::Command {
                program: _,
                display_line,
                spans,
                raw,
                danger,
                runs,
                cwd,
                root,
                interactive,
                caveat,
            } => Payload::Command {
                program,
                display_line,
                spans,
                raw,
                danger,
                runs,
                cwd,
                root,
                interactive,
                caveat,
            },
            swap => swap,
        }
    }

    /// The same payload, carrying what the window must tell a reader about how
    /// an elevated command differs from an ordinary one.
    ///
    /// Separate from [`Payload::command`] so that the eighteen call sites that
    /// build an unelevated payload keep saying `None` by construction rather
    /// than by each of them remembering to pass it, and so that the one place
    /// that has an [`crate::exec::elevate::Elevation`] to ask is the one place
    /// that sets it.
    ///
    /// A no-op on a swap payload: a swap has no command line and no elevation
    /// caveat to attach to one.
    pub fn with_caveat(self, caveat: Option<&str>) -> Payload {
        match self {
            Payload::Command { caveat: _, display_line, spans, raw, danger, runs, cwd, root, interactive, program } => {
                Payload::Command {
                    caveat: caveat.map(str::to_string),
                    display_line,
                    spans,
                    raw,
                    danger,
                    runs,
                    cwd,
                    root,
                    interactive,
                    program,
                }
            }
            swap => swap,
        }
    }

    /// The same payload, carrying the roster of what the command will run.
    ///
    /// Separate from [`Payload::command`] for the reason [`Payload::with_caveat`]
    /// is: the call sites that build a payload without one keep saying so by
    /// construction rather than by each of them remembering to pass an empty
    /// list, and the two places that have a child environment and a working
    /// directory to resolve against — [`crate::server::Daemon`] and
    /// [`crate::preview`] — are the two that set it.
    ///
    /// A no-op on a swap payload: a swap runs no command.
    pub fn with_runs(self, runs: Vec<crate::render::roster::Entry>) -> Payload {
        match self {
            Payload::Command { runs: _, display_line, spans, raw, danger, cwd, root, interactive, caveat, program } => {
                Payload::Command {
                    runs,
                    display_line,
                    spans,
                    raw,
                    danger,
                    cwd,
                    root,
                    interactive,
                    caveat,
                    program,
                }
            }
            swap => swap,
        }
    }

    /// Build a swap payload from rendered diff rows.
    pub fn swap(path: PathBuf, plan: SwapPlan, rows: &[Row]) -> Payload {
        Payload::Swap { path, plan, rows: rows.iter().map(WireRow::of).collect() }
    }

    /// The command rendering, rebuilt through [`SpanBuilder`] and checked
    /// against the one-line form.
    ///
    /// One call rather than two, so a window cannot rebuild the spans and
    /// forget to check the line it will also draw.
    pub fn rendering(&self) -> Result<Spans, ProtocolError> {
        let Payload::Command { display_line: line, spans, raw, .. } = self else {
            return Err(ProtocolError::WrongPayload { wanted: "command" });
        };
        let rebuilt = rebuild_spans(raw, spans)?;
        if display_line(&rebuilt) != *line {
            return Err(ProtocolError::DisplayLineDisagrees);
        }
        Ok(rebuilt)
    }

    /// Which bytes of the command are the shell script hatch quoted, checked
    /// against the rendering they are supposed to name.
    ///
    /// `rendering` is passed in rather than rebuilt so that the answer is
    /// about the spans the window is going to draw, and so that a window
    /// cannot check one rendering and draw another.
    ///
    /// Three things are asked, and the third is the one worth having: the run
    /// has to begin and end where spans do. A window that sliced the command
    /// at an offset no span reaches would be drawing a marker over half a
    /// word, and the parse it runs over those bytes would start mid-token.
    /// Bounds and character boundaries are checked first because the answers
    /// to them are what make the third question safe to ask.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::ScriptNotARun`], on any of the three. A frame naming
    /// a run that is not one is refused rather than drawn in part, like every
    /// other malformed rendering here.
    pub fn program(&self, rendering: &Spans) -> Result<Option<Snippet>, ProtocolError> {
        let Payload::Command { program, raw, .. } = self else {
            return Err(ProtocolError::WrongPayload { wanted: "command" });
        };
        let Some(program) = program.clone() else { return Ok(None) };
        let at = program.range();
        let refuse = Err(ProtocolError::ProgramNotARun { start: at.start, end: at.end });
        if at.start >= at.end
            || at.end > raw.len()
            || !raw.is_char_boundary(at.start)
            || !raw.is_char_boundary(at.end)
        {
            return refuse;
        }
        // Spans tile, so every edge except the last is the start of one and
        // the last is the end of the source.
        let edge = |at: usize| {
            at == raw.len() || rendering.iter().any(|span| span.range().start == at)
        };
        if !edge(at.start) || !edge(at.end) {
            return refuse;
        }
        Ok(Some(program))
    }

    /// The diff rows, each rebuilt through [`SpanBuilder`].
    pub fn rows(&self) -> Result<Vec<Row>, ProtocolError> {
        let Payload::Swap { rows, .. } = self else {
            return Err(ProtocolError::WrongPayload { wanted: "swap" });
        };
        rows.iter().map(WireRow::rebuild).collect()
    }
}

// ---- prompt → daemon -------------------------------------------------------

/// What one prompt window says back.
///
/// Note what is absent: no request id, no command, no path, no deadline.
/// Which request is being answered is decided by which pipe the frame came
/// down, and the daemon owns that pipe. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PromptMsg {
    /// The user decided. Exactly one of these is ever sent; a second is a bug
    /// in the window, and the daemon takes the first and closes the channel.
    /// That is a rule about the stream, which no type can enforce.
    Verdict(Verdict),
    /// The user pressed Kill on a running command. Only meaningful after an
    /// [`Verdict::Approve`], and harmless before one: it can stop a command
    /// and can never start one.
    Kill,
    /// The reader's answer to a [`DaemonMsg::Review`]: what of the output the
    /// agent may have.
    ///
    /// Read by the daemon only after it has sent the review, and only once. A
    /// window that sends one unasked has said something nobody is waiting
    /// for, and one that sends two has its second dropped, like a second
    /// verdict.
    Release(Release),
}

/// What a reader who reviewed a command's output lets the agent have.
///
/// # Why the text itself comes back
///
/// The alternative was to send back the filters and let the daemon apply
/// them, and it would have been the one place in hatch where what a person
/// approved was an instruction rather than a result. The reader was looking
/// at the lines that would go; those lines are what goes. A hand edit has no
/// other form anyway.
///
/// What the daemon does not take on the window's word is what the text *is*:
/// see [`crate::review::Trimmed::of`]. The only claim carried here that
/// reaches the agent is `kept`, and it is repeated only where the text bears
/// it out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "release", rename_all = "snake_case")]
pub enum Release {
    /// Send this.
    Send {
        /// The output as the reader left it, in the shape it was captured in.
        output: crate::review::Sections<String>,
        /// The keep patterns in force, which the agent may be told.
        ///
        /// Drop patterns are deliberately not a field. They would name what
        /// the reader removed, and a field is a thing that ends up in a
        /// sentence or a log line some day; a string that never crosses the
        /// pipe cannot.
        kept: Vec<String>,
        /// What the reader wants to say about the output they are releasing.
        ///
        /// On both arms, because the arm a person chose does not change who
        /// the words were for -- the same reasoning `PromptApp::act` gives
        /// for the note beside a verdict going with an approval as well as a
        /// denial. Empty when nobody typed anything.
        note: String,
    },
    /// Send none of it.
    Withhold {
        /// Why, in the reader's own words, and the one thing the agent is
        /// given when the output is not.
        ///
        /// This is the arm the note matters most on. Withholding tells the
        /// agent to stop asking and to ask the person instead -- see
        /// `crate::server::Withheld::sentence` -- and without a note that
        /// leaves them with a refusal and no way to act on it.
        note: String,
    },
}

/// The agent-facing verdict set.
///
/// Deliberately *not* [`crate::audit::LogVerdict`], which is a superset: the
/// log additionally distinguishes `timeout`, `cancelled`, `disconnected`,
/// `prompt_died`, `elevation_failed` and `refused`, none of which a user ever
/// presses. Those are outcomes the daemon decides when no verdict arrives, so
/// they have no place on a channel whose only job is to carry the one the
/// user chose. Mapping this set into that one is the daemon's, not this
/// module's.
///
/// Everything that is not `Approve` returns a *recoverable* tool error to the
/// agent carrying the note — a `CallToolResult` with `isError`, not a JSON-RPC
/// error — so the note is the whole content of those variants. `Approve`
/// carries one too, and it is the one case where the person's words arrive
/// beside hatch's own account of what happened, so the daemon labels them
/// where it joins the two rather than here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Run it.
    Approve {
        /// Whether the user ticked Stream output. A display preference and
        /// nothing more: execution is identical either way.
        stream: bool,
        /// Whether to give it a terminal of its own.
        ///
        /// Here rather than in a verdict of its own, because it is not a
        /// different answer: the person said run it, and this says how. A
        /// verdict is what the agent is told happened to its request, and
        /// "approved, in a terminal" and "approved" are the same thing having
        /// happened to it.
        ///
        /// It only ever grants. An agent that asked for `interactive` is
        /// already getting one and the window cannot take it away — a command
        /// that needs a terminal and is denied one does not fail, it hangs —
        /// so this arrives `true` for such a request whatever the person did
        /// with the control. What it is *for* is the other direction: the
        /// person at the window can often see that a command will want to be
        /// typed at when the agent could not.
        ///
        /// Unlike `stream`, this changes what runs. See
        /// [`crate::exec::interactive`].
        terminal: bool,
        /// Whether this window is closing itself the moment it has sent this.
        ///
        /// The reader ticked "Close when I decide", so there will be no
        /// running indicator, no Kill button and no result held up: the window
        /// goes and the approved command runs on without it, exactly as an
        /// approved command already runs on when a window dies.
        ///
        /// It is on the verdict rather than inferred from the window's
        /// disappearance because those two are **different facts and the
        /// audit log has to keep saying which is which**. Without it, the
        /// daemon reaches the end of a run, sees a window that is not there
        /// and records `prompt died while it ran` — a line that means
        /// "something went wrong and nobody was watching" — on every single
        /// approved command of a person who ticked a box asking for exactly
        /// this. The one line that means a real failure would become the line
        /// that appears on all of them. See [`crate::audit::PromptEnd`].
        ///
        /// Like `stream` and unlike `terminal` it changes nothing about what
        /// runs. It cannot arrive `true` alongside `stream`: streaming exists
        /// to be watched, and the window clears one when the other is asked
        /// for.
        closing: bool,
        /// Whether the reader asked to see the output before the agent does.
        ///
        /// Unlike `stream` and `closing` it changes what the agent receives —
        /// possibly nothing — and like `terminal` it changes nothing about
        /// what runs. It can only put a person between the output and the
        /// agent, never take one away, so like every other field here it
        /// cannot widen the approval.
        ///
        /// It cannot arrive `true` alongside `closing` from a working window,
        /// which clears the one when the other is asked for: a window that has
        /// gone cannot show anything. The daemon does not depend on that. A
        /// review asked for of a window that is not there is a review nobody
        /// answers, and the output is withheld, which is the direction the
        /// reader chose.
        review: bool,
        /// What the user typed, returned to the agent.
        ///
        /// The window has always had the field and an approval used to drop
        /// what was in it, which made "Note to the agent" a lie on the one
        /// button people press most. It changes nothing about what runs —
        /// the daemon relays it and never reads it — so it is a field here
        /// and not a decision.
        note: String,
    },
    /// Do not run it.
    Deny {
        /// What the user typed, returned to the agent.
        note: String,
    },
    /// Do not run it; come back with something the user can act on.
    Revise {
        /// Which of the two revisions was asked for.
        kind: ReviseKind,
        /// What the user typed, returned to the agent.
        note: String,
    },
    /// Do not carry it out; the user will do it themselves, and the agent
    /// should not retry it. What the agent is asked for depends on what was
    /// taken over: a command's output, or word that a file's change is made.
    SelfRun {
        /// What the user typed, returned to the agent.
        note: String,
    },
    /// Do not run it; stop working and wait for the person.
    ///
    /// The one verdict that says nothing about the request. Deny is a
    /// judgement — no to *this* — and an agent that has been denied is right
    /// to reconsider what it asked for and to ask for something better. This
    /// is no to *carrying on right now*: the person has something to say that
    /// a note field is too small for, and the next move is theirs. Nothing
    /// was weighed, so there is nothing to revise, and a retry or a variation
    /// is precisely the wrong reading of it.
    ///
    /// That is why it is a variant and not a note under [`Verdict::Deny`].
    /// A note is free text the agent may act on or not; the verdict is the
    /// part the daemon turns into a sentence of its own and the log records
    /// under a tag of its own, so "do not try again yet" is carried by the
    /// type rather than by the hope that somebody reads the prose. It is the
    /// same test [`ReviseKind`] is on the other side of: Explain and Simplify
    /// are one variant because they differ only in the sentence, and this is
    /// its own variant because it differs in what the agent must do next.
    StopAndSync {
        /// What the user typed, returned to the agent. Usually the whole
        /// point of this verdict, which asks for a conversation.
        note: String,
    },
}

/// The two revisions a user can ask for.
///
/// One variant with a kind rather than two verdicts, because the daemon
/// treats them identically — neither runs anything, both return the note —
/// and the difference is only which sentence the agent is told. Keeping them
/// as one verdict means no path can handle Explain and forget Simplify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviseKind {
    /// "Explain what this does before I decide."
    Explain,
    /// "Send me a more legible form of this."
    Simplify,
}

/// An approval with nothing typed in the note field.
///
/// What most of the tests in this crate mean by "approved": they are about
/// the phase machine, the wire or the daemon's flow, and the note is the one
/// thing they are not about. The ones that *are* about it say so by writing
/// the verdict out.
#[cfg(test)]
pub(crate) fn approved(stream: bool) -> Verdict {
    Verdict::Approve { stream, terminal: false, closing: false, review: false, note: String::new() }
}

/// One of every verdict, for the tests across this crate that must cover the
/// whole set.
///
/// There were four hand-written copies of this list — here, in the window,
/// and twice in the daemon — and a hand-written list is one that goes on
/// passing after a variant is added to the enum it was written from. So there
/// is one list, and [`verdict_variant`] beside it is what enforces it: that
/// match is exhaustive, so a new variant stops this module compiling, and the
/// arm its author is then made to write is what turns a sample missing from
/// here into a failing test rather than a quiet pass.
#[cfg(test)]
pub(crate) fn every_verdict() -> Vec<Verdict> {
    vec![
        Verdict::Approve {
            stream: true,
            terminal: false,
            closing: false,
            review: false,
            note: "thanks — watch the tail of it".to_string(),
        },
        Verdict::Approve {
            stream: false,
            terminal: true,
            closing: false,
            review: false,
            note: "this one is going to ask you things".to_string(),
        },
        Verdict::Approve {
            stream: false,
            terminal: false,
            closing: true,
            review: false,
            note: "get on with it, I am going back to what I was doing".to_string(),
        },
        Verdict::Approve {
            stream: true,
            terminal: false,
            closing: false,
            review: true,
            note: "show me before it goes".to_string(),
        },
        approved(false),
        Verdict::Deny { note: "not now".to_string() },
        Verdict::Revise {
            kind: ReviseKind::Explain,
            note: "which files does this touch?".to_string(),
        },
        Verdict::Revise { kind: ReviseKind::Simplify, note: "one command at a time".to_string() },
        Verdict::SelfRun { note: "I will run it here".to_string() },
        Verdict::StopAndSync { note: "hold on, I want to talk about this".to_string() },
    ]
}

/// How many variants [`Verdict`] has. Grows with the match below, and the
/// index into an array of this size is what catches it not having.
#[cfg(test)]
const VERDICT_VARIANTS: usize = 5;

/// Which variant a verdict is, as a position in an array of
/// [`VERDICT_VARIANTS`].
///
/// The exhaustive match is the point; the number it returns is only how the
/// test counts what it has seen.
#[cfg(test)]
fn verdict_variant(verdict: &Verdict) -> usize {
    match verdict {
        Verdict::Approve { .. } => 0,
        Verdict::Deny { .. } => 1,
        Verdict::Revise { .. } => 2,
        Verdict::SelfRun { .. } => 3,
        Verdict::StopAndSync { .. } => 4,
    }
}

// ---- renderings on the wire ------------------------------------------------

/// One span, as it crosses the pipe: where it ends, what it is, and whether a
/// line break precedes it.
///
/// There is no `text` field and that is the design. The text lives once, in
/// the message beside these, so a frame cannot claim a span whose text is not
/// the substring it points at. Compare [`Span`], which carries its text
/// because in process it is cut from a source it can no longer reach.
///
/// `end` is a byte offset into that source, absolute rather than a length,
/// matching [`Span::range`] and [`SpanBuilder::push_to`] so the rebuild is a
/// direct replay rather than an arithmetic reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSpan {
    /// Byte offset one past the last byte this span covers.
    pub end: usize,
    /// What the span is, for the screen.
    pub kind: SpanKind,
    /// Draw a line break before it.
    pub break_before: bool,
}

/// The one-line form of a rendering: chips read as their labels, line breaks
/// ignored.
///
/// This is the definition [`Payload::Command::display_line`] is checked
/// against, so it is a function rather than a comment.
pub fn display_line(spans: &Spans) -> String {
    spans.iter().map(Span::display_text).collect()
}

/// Take a rendering apart for the wire. Lossless: [`rebuild_spans`] against
/// the same source returns an equal [`Spans`].
pub fn wire_spans(spans: &[Span]) -> Vec<WireSpan> {
    spans
        .iter()
        .map(|span| WireSpan {
            end: span.range().end,
            kind: span.kind().clone(),
            break_before: span.break_before(),
        })
        .collect()
}

/// One codepoint and no more -- [`SpanKind::Chip`]'s bound, spelled out here
/// because the model enforces it by panicking and a frame off a pipe has to
/// be refused instead.
fn is_one_codepoint(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some() && chars.next().is_none()
}

/// Rebuild a rendering from its source and the offsets its spans end at.
///
/// Every check here duplicates one [`SpanBuilder`] already makes, on purpose
/// and in that order: the validation exists so that a malformed frame is a
/// [`ProtocolError`] instead of a panic in a window, and the builder that
/// runs afterwards is what makes the result worth having. If a check below
/// were ever wrong or missing, the builder still panics rather than returning
/// a `Spans` that does not tile its source — the failure gets worse, never
/// quieter.
pub fn rebuild_spans(source: &str, wire: &[WireSpan]) -> Result<Spans, ProtocolError> {
    let mut cursor = 0;
    for span in wire {
        if !source.is_char_boundary(span.end) {
            return Err(ProtocolError::SpanBounds { end: span.end, len: source.len() });
        }
        if span.end <= cursor {
            return Err(ProtocolError::SpanOutOfOrder { end: span.end, cursor });
        }
        let text = &source[cursor..span.end];
        // The two bounds the model enforces where a kind meets its text,
        // restated here because a frame can put a kind on any text at all.
        match &span.kind {
            SpanKind::Chip { .. } if !is_one_codepoint(text) => {
                return Err(ProtocolError::ChipNotOneCodepoint);
            }
            SpanKind::Variable { .. } if variable_name(text).is_none() => {
                return Err(ProtocolError::NotOneVariableReference);
            }
            _ => {}
        }
        cursor = span.end;
    }
    if cursor != source.len() {
        return Err(ProtocolError::SpansDoNotCover { covered: cursor, len: source.len() });
    }

    let mut builder = SpanBuilder::new(source);
    for span in wire {
        if span.break_before {
            builder.break_next();
        }
        builder.push_to(span.end, span.kind.clone());
    }
    Ok(builder.finish())
}

/// One side of one diff row on the wire: the line, and the offsets its spans
/// end at.
///
/// The content/terminator split is not here. It is recomputed by
/// [`Side::from_rendering`] from the line itself, so the wire has no way to
/// claim a terminator boundary that is not where the terminator is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSide {
    /// The line, terminator included. The only copy of the text.
    pub line: String,
    /// Its rendering, as offsets over `line`.
    pub spans: Vec<WireSpan>,
}

impl WireSide {
    fn of(side: &Side) -> WireSide {
        WireSide { line: side.text().to_string(), spans: wire_spans(side.spans()) }
    }

    fn rebuild(&self) -> Result<Side, ProtocolError> {
        let spans = rebuild_spans(&self.line, &self.spans)?;
        Side::from_rendering(spans).ok_or(ProtocolError::TerminatorNotAtSpanBoundary)
    }
}

/// One row of the side-by-side view on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRow {
    /// The current file's line, absent where this row is an insertion.
    pub left: Option<WireSide>,
    /// The proposed content's line, absent where this row is a deletion.
    pub right: Option<WireSide>,
    /// Whether the view marks this row. Carried rather than derived — see
    /// [`Row::from_sides`].
    pub changed: bool,
}

impl WireRow {
    /// Take a row apart for the wire.
    pub fn of(row: &Row) -> WireRow {
        WireRow {
            left: row.left().map(WireSide::of),
            right: row.right().map(WireSide::of),
            changed: row.changed(),
        }
    }

    /// Rebuild a row, checking both sides through [`SpanBuilder`].
    pub fn rebuild(&self) -> Result<Row, ProtocolError> {
        Ok(Row::from_sides(
            self.left.as_ref().map(WireSide::rebuild).transpose()?,
            self.right.as_ref().map(WireSide::rebuild).transpose()?,
            self.changed,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::TimeZone;

    use super::*;
    use crate::render::diff::side_by_side;
    use crate::render::{render_command, unrender};
    use crate::swap::{PlanKind, Principal};
    use crate::review::{Captured, Sections};

    fn rendering(command: &str) -> Spans {
        render_command(command, &BTreeMap::from([("HOME".to_string(), "/home/user".to_string())]))
    }

    fn sample_request() -> Request {
        Request {
            title: "clear the stale build tree".to_string(),
            reason: "the last run left root-owned files behind".to_string(),
            deadline: Utc.with_ymd_and_hms(2026, 9, 6, 12, 0, 0).unwrap(),
            queue_depth: 0,
            number: Some(47),
            unanswered: Vec::new(),
            operations: vec![Payload::command(
                &rendering("rm -rf /tmp/build"),
                vec!["rm -rf".to_string()],
                PathBuf::from("/home/user"),
                false,
                false,
            )],
            stop_on_failure: false,
        }
    }

    fn sample_plan() -> SwapPlan {
        SwapPlan {
            kind: PlanKind::Replace,
            landing_mode: 0o0644,
            landing_owner: Principal { id: 1000, name: Some("user".to_string()) },
            landing_group: Principal { id: 1000, name: None },
            hash_before: Some("e3b0c442".to_string()),
            size_delta: -12,
        }
    }

    #[test]
    fn daemon_messages_round_trip() {
        let messages = [
            DaemonMsg::Request(Box::new(sample_request())),
            DaemonMsg::QueueDepth { depth: 3 },
            DaemonMsg::Output {
                stream: Stream::Stderr,
                text: "a line\nand another\n".to_string(),
            },
            DaemonMsg::Review(Review {
                deadline: Utc.with_ymd_and_hms(2026, 9, 6, 12, 10, 0).unwrap(),
                output: Sections::Streams {
                    stdout: Captured { text: "token=abc\nok\n".to_string(), truncated: false },
                    stderr: Captured { text: String::new(), truncated: true },
                },
            }),
            DaemonMsg::Review(Review {
                deadline: Utc.with_ymd_and_hms(2026, 9, 6, 12, 10, 0).unwrap(),
                output: Sections::Transcript {
                    transcript: Captured { text: "Password: \r\n".to_string(), truncated: false },
                },
            }),
            DaemonMsg::Finished(Outcome::Exit { code: 0 }),
        ];
        for message in messages {
            let encoded = encode(&message).expect("a daemon message encodes");
            assert!(
                !encoded.contains('\n'),
                "NDJSON framing needs the payload to be one line: {encoded}"
            );
            let back: DaemonMsg = read_message(&encoded).expect("and decodes");
            assert_eq!(back, message);
        }
    }

    #[test]
    fn the_shared_list_has_one_of_every_verdict() {
        // What the four exhaustive tests in this crate rest on. `seen` is
        // indexed by `verdict_variant`, so an arm added there without room in
        // `VERDICT_VARIANTS` panics here rather than being counted quietly,
        // and a variant left out of the list fails the assertion.
        let mut seen = [false; VERDICT_VARIANTS];
        for verdict in every_verdict() {
            seen[verdict_variant(&verdict)] = true;
        }
        assert!(seen.iter().all(|&found| found), "a verdict has no sample: {seen:?}");

        // The two revisions are one variant carrying a kind, so the variant
        // being present is not the same as both sentences being reachable.
        let mut kinds = [false; 2];
        for verdict in every_verdict() {
            if let Verdict::Revise { kind, .. } = verdict {
                kinds[match kind {
                    ReviseKind::Explain => 0,
                    ReviseKind::Simplify => 1,
                }] = true;
            }
        }
        assert!(kinds.iter().all(|&found| found), "a revision has no sample: {kinds:?}");
    }

    #[test]
    fn prompt_messages_round_trip() {
        let messages: Vec<PromptMsg> = every_verdict()
            .into_iter()
            .map(PromptMsg::Verdict)
            .chain([
                PromptMsg::Kill,
                PromptMsg::Release(Release::Withhold { note: String::new() }),
                PromptMsg::Release(Release::Send {
                    output: Sections::Streams {
                        stdout: "error: one\n".to_string(),
                        stderr: String::new(),
                    },
                    kept: vec!["error".to_string()],
                    note: String::new(),
                }),
                PromptMsg::Release(Release::Send {
                    output: Sections::Transcript { transcript: "edited\n".to_string() },
                    kept: Vec::new(),
                    note: "I took the tokens out".to_string(),
                }),
            ])
            .collect();
        for message in messages {
            let encoded = encode(&message).expect("a prompt message encodes");
            assert!(
                !encoded.contains('\n'),
                "NDJSON framing needs the payload to be one line: {encoded}"
            );
            let back: PromptMsg = read_message(&encoded).expect("and decodes");
            assert_eq!(back, message);
        }
    }

    #[test]
    fn request_carries_an_absolute_deadline_not_a_duration() {
        let request = sample_request();
        // The type itself: an instant on the daemon's clock, not a span of
        // time the window could restart by being slow.
        let deadline: DateTime<Utc> = request.deadline;

        let encoded = encode(&DaemonMsg::Request(Box::new(request))).expect("a request encodes");
        let json: serde_json::Value = serde_json::from_str(&encoded).expect("valid JSON");
        let field = json["deadline"]
            .as_str()
            .expect("an instant is written as a timestamp, not as a number of seconds");
        assert_eq!(
            DateTime::parse_from_rfc3339(field).expect("RFC 3339").with_timezone(&Utc),
            deadline
        );

        // A duration could not express this at all: the deadline is already
        // past, and it is still past after the trip rather than starting over
        // at the far end.
        assert!(deadline < Utc::now(), "the sample deadline is a fixed past instant");
        let back: DaemonMsg = read_message(&encoded).expect("and decodes");
        let DaemonMsg::Request(back) = back else { panic!("a request decodes as a request") };
        assert_eq!(back.deadline, deadline);
        assert!(back.deadline < Utc::now(), "and is still in the past on arrival");
    }

    // ---- framing -----------------------------------------------------------

    #[test]
    fn framing_refuses_an_encoding_that_would_span_two_lines() {
        // The guard nothing reaches today. `serde_json::to_string` escapes
        // every newline it is given, which is why this is tested directly:
        // the check is a tripwire for a future serialiser, and a tripwire
        // nobody tests is a comment.
        assert_eq!(check_single_line("{\"type\":\"kill\"}"), Ok(()));
        assert_eq!(check_single_line("{\"a\":\n1}"), Err(ProtocolError::Framing));
        assert_eq!(check_single_line("trailing\n"), Err(ProtocolError::Framing));
    }

    #[test]
    fn every_protocol_error_says_what_went_wrong() {
        // These strings reach a log and, for a refused frame, a user. Each
        // has to name its own failure: a shared or empty message would send
        // whoever reads it to the wrong half of the protocol.
        let errors = [
            ProtocolError::Encode("bad".to_string()),
            ProtocolError::Decode("bad".to_string()),
            ProtocolError::Framing,
            ProtocolError::SpanOutOfOrder { end: 2, cursor: 3 },
            ProtocolError::SpanBounds { end: 9, len: 6 },
            ProtocolError::SpansDoNotCover { covered: 3, len: 6 },
            ProtocolError::ChipNotOneCodepoint,
            ProtocolError::NotOneVariableReference,
            ProtocolError::TerminatorNotAtSpanBoundary,
            ProtocolError::DisplayLineDisagrees,
            ProtocolError::WrongPayload { wanted: "swap" },
        ];
        let mut seen: Vec<String> = Vec::new();
        for error in &errors {
            let said = error.to_string();
            assert!(!said.is_empty(), "{error:?} says nothing");
            assert!(!seen.contains(&said), "{error:?} says what another error already said");
            seen.push(said);
        }
        assert!(seen[2].contains("newline"), "{}", seen[2]);
        assert!(seen[4].contains('9') && seen[4].contains('6'), "{}", seen[4]);
        assert!(seen[10].contains("swap"), "{}", seen[10]);
    }

    #[test]
    fn a_newline_in_agent_text_does_not_split_the_frame() {
        // The realistic route to a broken frame: a title the agent wrote with
        // a newline in it. It has to survive as data, not as framing.
        let mut request = sample_request();
        request.title = "two\nlines".to_string();
        request.reason = "and a carriage\r\nreturn".to_string();
        let encoded = encode(&DaemonMsg::Request(Box::new(request.clone()))).expect("encodes");
        assert!(!encoded.contains('\n'));
        let back: DaemonMsg = read_message(&encoded).expect("decodes");
        assert_eq!(back, DaemonMsg::Request(Box::new(request)), "and the newline is still in the text");
    }

    #[test]
    fn write_message_ends_the_frame_with_exactly_one_newline() {
        let mut out = Vec::new();
        write_message(&mut out, &PromptMsg::Kill).expect("writes");
        let approve = approved(false);
        write_message(&mut out, &PromptMsg::Verdict(approve)).expect("writes");
        let text = String::from_utf8(out).expect("utf-8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one message, one line: {text:?}");
        assert!(text.ends_with('\n'), "and every frame is terminated");
        assert_eq!(read_message::<PromptMsg>(lines[0]).expect("decodes"), PromptMsg::Kill);
    }

    // ---- what is on the wire -----------------------------------------------

    #[test]
    fn a_request_carries_every_field_the_window_needs() {
        // A field dropped from `Request` still round-trips -- both ends would
        // simply stop sending it -- so the round-trip tests cannot see it.
        // This can.
        let encoded = encode(&DaemonMsg::Request(Box::new(sample_request()))).expect("encodes");
        let json: serde_json::Value = serde_json::from_str(&encoded).expect("valid JSON");
        let mut keys: Vec<&str> =
            json.as_object().expect("an object").keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "deadline",
                "number",
                "operations",
                "queue_depth",
                "reason",
                "stop_on_failure",
                "title",
                "type",
                "unanswered"
            ]
        );

        let mut payload: Vec<&str> = json["operations"][0]
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        payload.sort_unstable();
        assert_eq!(
            payload,
            [
                "caveat",
                "cwd",
                "danger",
                "display_line",
                "interactive",
                "kind",
                "program",
                "raw",
                "root",
                "runs",
                "spans"
            ]
        );
    }

    #[test]
    fn a_missing_field_is_a_decode_error_and_not_a_default() {
        let encoded = encode(&DaemonMsg::Request(Box::new(sample_request()))).expect("encodes");
        let mut json: serde_json::Value = serde_json::from_str(&encoded).expect("valid JSON");
        for field in ["title", "reason", "deadline", "queue_depth", "operations", "stop_on_failure"] {
            let mut short = json.clone();
            short.as_object_mut().expect("an object").remove(field);
            let line = serde_json::to_string(&short).expect("re-encodes");
            assert!(
                read_message::<DaemonMsg>(&line).is_err(),
                "a request without {field} must not decode"
            );
        }
        // And the whole message, unmodified, still does -- so the loop above
        // is failing on the missing field rather than on the surgery.
        json.as_object_mut().expect("an object");
        let line = serde_json::to_string(&json).expect("re-encodes");
        assert!(read_message::<DaemonMsg>(&line).is_ok());
    }

    #[test]
    fn a_verdict_names_no_request_and_carries_no_operation() {
        // The authority test. A prompt answers the window it was given, and
        // there is no field in which it could answer for another one or
        // approve something other than what it was shown.
        //
        // The permitted set is what the window is entitled to decide: which
        // answer (`verdict`, `kind`), what to say about it (`note`), what this
        // window then does with itself (`stream`, `closing`), how an approved
        // operation should be carried out (`terminal`), and whether a person
        // stands between its output and the agent (`review`). What is not
        // in it is the whole point — no request id, no command, no path, no
        // argv. A window cannot name the thing it is answering about, so it
        // cannot name a different one.
        for message in
            every_verdict().into_iter().map(PromptMsg::Verdict).chain([PromptMsg::Kill])
        {
            let json: serde_json::Value =
                serde_json::from_str(&encode(&message).expect("encodes")).expect("valid JSON");
            for key in json.as_object().expect("an object").keys() {
                assert!(
                    ["type", "verdict", "note", "stream", "terminal", "closing", "review", "kind"]
                        .contains(&key.as_str()),
                    "a prompt message may not carry {key}: which request this is, and what it \
                     asked for, are the daemon's and not the window's"
                );
            }
        }
    }

    #[test]
    fn every_outcome_reaches_the_window_including_a_failed_elevation() {
        for outcome in [
            Outcome::Exit { code: 1 },
            Outcome::Signal { signal: 9 },
            Outcome::ElevationFailed { message: "the password dialog was cancelled".to_string() },
            Outcome::Unclear { message: "the run was ended at its deadline".to_string() },
            Outcome::Written,
            Outcome::Failed { message: "the file changed between hatch reading it and going to write it".to_string() },
        ] {
            let message = DaemonMsg::Finished(outcome);
            let encoded = encode(&message).expect("encodes");
            assert_eq!(read_message::<DaemonMsg>(&encoded).expect("decodes"), message);
        }
        // The tags a reader will grep for.
        let encoded = encode(&DaemonMsg::Finished(Outcome::ElevationFailed {
            message: "cancelled".to_string(),
        }))
        .expect("encodes");
        assert!(encoded.contains("\"type\":\"finished\""), "{encoded}");
        assert!(encoded.contains("\"reason\":\"elevation_failed\""), "{encoded}");
        let encoded = encode(&DaemonMsg::Finished(Outcome::Written)).expect("encodes");
        assert!(encoded.contains("\"reason\":\"written\""), "{encoded}");
    }

    #[test]
    fn only_an_ending_the_reader_could_not_have_known_is_news() {
        // A command's status is its answer, and a write that landed is the
        // diff the reader already approved. Everything that happened *to* the
        // operation rather than being said by it is news.
        let message = || "why".to_string();
        let quiet =
            [Outcome::Exit { code: 0 }, Outcome::Exit { code: 1 }, Outcome::Exit { code: 127 }];
        for quiet in quiet.into_iter().chain([Outcome::Written]) {
            assert!(!quiet.is_news(), "{quiet:?} would hold a window up");
        }
        for news in [
            Outcome::Signal { signal: 9 },
            Outcome::Signal { signal: 11 },
            Outcome::ElevationFailed { message: message() },
            Outcome::Unclear { message: message() },
            Outcome::Failed { message: message() },
        ] {
            assert!(news.is_news(), "{news:?} would close a window over what it has to say");
        }
    }

    #[test]
    fn a_window_under_review_stays_whatever_the_ending_and_nothing_else_changes() {
        // The one rule both ends read. A review is a question still open, so
        // the quietest ending there is keeps its window; without one, staying
        // is what it always was.
        let endings = [
            Outcome::Exit { code: 0 },
            Outcome::Exit { code: 1 },
            Outcome::Signal { signal: 9 },
            Outcome::Failed { message: "why".to_string() },
        ];
        for ending in endings {
            for watched in [false, true] {
                assert!(ending.stays(watched, true), "{ending:?} closed a window with a question on it");
                assert_eq!(ending.stays(watched, false), watched || ending.is_news(), "{ending:?}");
            }
        }
    }

    #[test]
    fn the_drop_patterns_have_nowhere_to_ride_back_on() {
        // A release names what it keeps and nothing about what it removed.
        // Written out as the JSON a window sends, because a field added later
        // for "completeness" is exactly how a removed secret would leave.
        let encoded = encode(&PromptMsg::Release(Release::Send {
            output: Sections::Streams { stdout: "ok\n".to_string(), stderr: String::new() },
            kept: Vec::new(),
            note: String::new(),
        }))
        .expect("encodes");
        let json: serde_json::Value = serde_json::from_str(&encoded).expect("JSON");
        let mut keys: Vec<&str> = json.as_object().expect("an object").keys().map(String::as_str).collect();
        keys.sort_unstable();
        // `note` is on this list deliberately, and is the only field here
        // that carries words rather than output: it is what the person typed
        // about what they are releasing, and it is theirs to send. Drop
        // patterns are still absent, and still for the reason `Release`
        // gives -- they would name what was removed.
        assert_eq!(keys, ["kept", "note", "output", "release", "type"], "{encoded}");
    }

    // ---- renderings across the pipe ----------------------------------------

    #[test]
    fn a_rendering_survives_the_pipe_exactly() {
        for command in [
            "",
            "ls -la /etc",
            "echo $HOME | tee /tmp/x && rm -rf ~/.cache",
            "printf '\u{202E}gnp.exe'",
            "ünïcödé — ✓",
            "make -j4   # then && rm -rf /tmp",
            "cat <<'EOF' > /tmp/x\nhello\nEOF",
            "make 2>&1 >| /etc/passwd",
        ] {
            let spans = rendering(command);
            let payload = Payload::command(
                &spans,
                Vec::new(),
                PathBuf::from("/home/user"),
                false,
                false,
            );
            let encoded = encode(&payload).expect("encodes");
            let back: Payload = read_message(&encoded).expect("decodes");
            let rebuilt = back.rendering().expect("rebuilds");
            assert_eq!(rebuilt, spans, "{command:?} did not survive the trip");
            assert!(rebuilt.covers_source(), "and it still tiles its source");
            assert_eq!(unrender(&rebuilt), command, "and it is still the command");
        }
    }

    #[test]
    fn a_comment_crosses_the_pipe_as_the_kind_it_is() {
        // A kind the window does not receive is a kind the window cannot
        // draw, and the round trip above would be satisfied by a comment that
        // arrived as `plain`: the text would be identical either way. So the
        // tag itself is asserted, and by the name a reader would grep the
        // frame for.
        let spans = rendering("make -j4 # not && this");
        let payload =
            Payload::command(&spans, Vec::new(), PathBuf::from("/"), false, false);
        let encoded = encode(&payload).expect("encodes");
        assert!(encoded.contains("\"kind\":\"comment\""), "{encoded}");

        let back: Payload = read_message(&encoded).expect("decodes");
        let rebuilt = back.rendering().expect("rebuilds");
        let comments: Vec<&str> = rebuilt
            .iter()
            .filter(|span| span.kind() == &SpanKind::Comment)
            .map(Span::text)
            .collect();
        assert_eq!(comments, vec!["# not && this"], "the comment did not survive the trip");
    }

    #[test]
    fn a_redirection_crosses_the_pipe_as_the_kind_it_is() {
        // Here for the reason the comment above it is: the round trip would
        // be satisfied by a redirection that arrived as `plain`, because the
        // text is identical either way, and a kind the window does not
        // receive is a kind the window cannot draw. Both halves are asserted,
        // since the destination is the half a reader is scanning for.
        let spans = rendering("echo x > /etc/passwd");
        let payload = Payload::command(&spans, Vec::new(), PathBuf::from("/"), false, false);
        let encoded = encode(&payload).expect("encodes");
        assert!(encoded.contains("\"kind\":\"redirect\""), "{encoded}");

        let back: Payload = read_message(&encoded).expect("decodes");
        let rebuilt = back.rendering().expect("rebuilds");
        let redirects: Vec<&str> = rebuilt
            .iter()
            .filter(|span| span.kind() == &SpanKind::Redirect)
            .map(Span::text)
            .collect();
        assert_eq!(
            redirects,
            vec![">", "/etc/passwd"],
            "the redirection did not survive the trip"
        );
    }

    #[test]
    fn the_wire_carries_the_text_once() {
        // The structural half of the design: a `WireSpan` has no text, so a
        // frame cannot describe a span whose text is not the substring it
        // points at. If a `text` field ever appears here, this fails.
        let payload =
            Payload::command(&rendering("ls $HOME"), Vec::new(), PathBuf::from("/"), false, false);
        let json: serde_json::Value =
            serde_json::from_str(&encode(&payload).expect("encodes")).expect("valid JSON");
        let spans = json["spans"].as_array().expect("an array");
        assert!(!spans.is_empty());
        for span in spans {
            let mut keys: Vec<&str> =
                span.as_object().expect("an object").keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(keys, ["break_before", "end", "kind"]);
        }
    }

    #[test]
    fn a_rebuild_refuses_spans_that_do_not_tile_their_source() {
        let source = "ls -la";
        let good = wire_spans(&rendering(source));
        assert!(rebuild_spans(source, &good).is_ok(), "the unmodified sequence rebuilds");

        let plain = |end: usize| WireSpan { end, kind: SpanKind::Plain, break_before: false };

        assert_eq!(
            rebuild_spans(source, &[plain(3)]),
            Err(ProtocolError::SpansDoNotCover { covered: 3, len: 6 }),
            "a dropped tail is text nobody would ever see"
        );
        assert_eq!(
            rebuild_spans(source, &[plain(3), plain(2)]),
            Err(ProtocolError::SpanOutOfOrder { end: 2, cursor: 3 }),
            "and so is a span that goes backwards"
        );
        assert_eq!(
            rebuild_spans(source, &[plain(3), plain(3)]),
            Err(ProtocolError::SpanOutOfOrder { end: 3, cursor: 3 }),
            "an empty span carries nothing and the builder would drop it"
        );
        assert_eq!(
            rebuild_spans(source, &[plain(9)]),
            Err(ProtocolError::SpanBounds { end: 9, len: 6 }),
            "a span past the end of the source"
        );
        assert_eq!(
            rebuild_spans("é", &[plain(1)]),
            Err(ProtocolError::SpanBounds { end: 1, len: 2 }),
            "and one that cuts a character in half"
        );
        assert!(rebuild_spans("", &[]).is_ok(), "an empty source has no spans and that is fine");
    }

    #[test]
    fn a_rebuild_refuses_a_chip_over_more_than_one_codepoint() {
        // Invariant 1b, which is what stops one label standing in for a whole
        // command. The model makes it unconstructible; the wire has to make
        // it unreceivable.
        let chip = |end: usize| WireSpan {
            end,
            kind: SpanKind::Chip { name: "[RLO]".into() },
            break_before: false,
        };
        assert_eq!(
            rebuild_spans("rm -rf /", &[chip(8)]),
            Err(ProtocolError::ChipNotOneCodepoint)
        );
        assert!(
            rebuild_spans("\u{202E}", &[chip(3)]).is_ok(),
            "one codepoint is three bytes and still one chip"
        );
    }

    #[test]
    fn a_rebuild_refuses_a_resolved_value_beside_text_that_is_not_a_reference() {
        let variable = |end: usize| WireSpan {
            end,
            kind: SpanKind::Variable { resolved: Some("/home/user".to_string()) },
            break_before: false,
        };
        assert_eq!(
            rebuild_spans("ls $HOME", &[variable(8)]),
            Err(ProtocolError::NotOneVariableReference),
            "a value beside a whole command line is a claim about text that does not make it"
        );
        assert!(rebuild_spans("$HOME", &[variable(5)]).is_ok());
    }

    #[test]
    fn a_display_line_that_disagrees_with_the_spans_is_refused() {
        // The one duplicated field in the payload, and why duplicating it is
        // survivable: it is checked rather than believed.
        let spans = rendering("ls\u{202E}txt");
        let payload = Payload::command(&spans, Vec::new(), PathBuf::from("/"), false, false);
        assert!(payload.rendering().is_ok());

        let Payload::Command { display_line: line, .. } = &payload else { unreachable!() };
        assert!(line.contains("[RLO]"), "the one-line form reads chips as labels: {line}");

        let mut tampered = payload.clone();
        if let Payload::Command { display_line: line, .. } = &mut tampered {
            *line = "ls txt".to_string();
        }
        assert_eq!(tampered.rendering(), Err(ProtocolError::DisplayLineDisagrees));
    }

    #[test]
    fn a_payload_is_not_asked_for_what_the_other_variant_carries() {
        let command =
            Payload::command(&rendering("ls"), Vec::new(), PathBuf::from("/"), false, false);
        let swap = Payload::swap(PathBuf::from("/etc/hosts"), sample_plan(), &[]);
        assert_eq!(command.rows(), Err(ProtocolError::WrongPayload { wanted: "swap" }));
        assert_eq!(swap.rendering(), Err(ProtocolError::WrongPayload { wanted: "command" }));
    }

    #[test]
    fn a_diff_survives_the_pipe_exactly() {
        let before = "one\ntwo\nthree\n";
        let after = "one\ntwo point five\nthree";
        let rows = side_by_side(before, after);
        let payload = Payload::swap(PathBuf::from("/etc/hosts"), sample_plan(), &rows);

        let encoded = encode(&payload).expect("encodes");
        assert!(!encoded.contains('\n'), "the diff's own newlines stay inside the frame");
        let back: Payload = read_message(&encoded).expect("decodes");
        assert_eq!(back, payload);

        let rebuilt = back.rows().expect("rebuilds");
        assert_eq!(rebuilt, rows);
        assert_eq!(
            crate::render::diff::rejoin_left(&rebuilt),
            before,
            "the left column is still the file"
        );
        assert_eq!(
            crate::render::diff::rejoin_right(&rebuilt),
            after,
            "and the right column is still what would be written"
        );
        // The terminator split was recomputed, not transmitted, and it still
        // lands in the same place.
        let first = rebuilt[0].left().expect("a left side");
        assert_eq!(unrender(first.content_spans()), "one");
        assert_eq!(unrender(first.terminator_spans()), "\n");
    }

    #[test]
    fn a_diff_row_with_a_broken_side_is_refused() {
        let rows = side_by_side("one\n", "two\n");
        let mut wire = WireRow::of(&rows[0]);
        let left = wire.left.as_mut().expect("a left side");
        left.spans.pop();
        assert!(
            matches!(wire.rebuild(), Err(ProtocolError::SpansDoNotCover { .. })),
            "a row whose line is not fully tiled is not a row anyone may draw"
        );
    }

    #[test]
    fn a_diff_side_whose_spans_run_through_the_terminator_is_refused() {
        // Tiling is not enough for a diff line. These spans cover "one\n"
        // exactly and still have no boundary where the terminator starts, so
        // the recomputed split would point into the middle of a span and the
        // view would draw part of the line in the terminator slot.
        let wire = WireSide {
            line: "one\n".to_string(),
            spans: vec![WireSpan { end: 4, kind: SpanKind::Plain, break_before: false }],
        };
        assert!(
            rebuild_spans(&wire.line, &wire.spans).is_ok(),
            "the spans do tile the line; it is the split that is wrong"
        );
        assert_eq!(wire.rebuild(), Err(ProtocolError::TerminatorNotAtSpanBoundary));
    }

    #[test]
    fn the_plan_crosses_as_itself() {
        let payload = Payload::swap(PathBuf::from("/etc/hosts"), sample_plan(), &[]);
        let back: Payload = read_message(&encode(&payload).expect("encodes")).expect("decodes");
        let Payload::Swap { plan, path, .. } = back else { panic!("a swap payload") };
        assert_eq!(plan, sample_plan());
        assert_eq!(path, PathBuf::from("/etc/hosts"));
    }

    #[test]
    fn the_operations_cross_in_the_order_they_will_run_and_with_the_policy_they_run_under() {
        // Order is a guarantee, so it is the one property of the list worth
        // asserting on its own: a write and then the command that reads it
        // must not arrive as the command and then the write. Two of each
        // kind, interleaved, so a trip that grouped them by kind would fail
        // as surely as one that reversed them.
        let write = |path: &str| Payload::swap(PathBuf::from(path), sample_plan(), &[]);
        let command = |line: &str| {
            Payload::command(&rendering(line), Vec::new(), PathBuf::from("/"), false, false)
        };
        let operations = vec![
            write("/etc/service/one.conf"),
            command("systemctl reload service"),
            write("/etc/service/two.conf"),
            command("systemctl status service"),
        ];
        for stop_on_failure in [true, false] {
            let mut request = sample_request();
            request.operations = operations.clone();
            request.stop_on_failure = stop_on_failure;

            let encoded = encode(&DaemonMsg::Request(Box::new(request))).expect("encodes");
            let DaemonMsg::Request(back) = read_message(&encoded).expect("decodes") else {
                panic!("a request decodes as a request");
            };
            assert_eq!(back.operations, operations, "the operations arrived in another order");
            assert_eq!(back.stop_on_failure, stop_on_failure, "the policy did not survive");
        }
    }
}
