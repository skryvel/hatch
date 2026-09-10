//! The `Prompter` trait, `ProcessPrompter`, and (behind a dev feature)
//! `StubPrompter`.
//!
//! This is the seam between the daemon and the human. Everything above it
//! decides *what* to ask; everything below it is one window, one decision, and
//! the streaming view of whatever the decision authorised.
//!
//! # A session, not a call
//!
//! [`Prompter::prompt`] does not return a verdict. It returns a
//! [`PromptSession`], because a window is not a function call: the verdict
//! arrives at one time, the command's output goes back at another, and the
//! Kill button can be pressed in between. Four things cross this seam and they
//! cross at four different moments, so the session hands out one handle for
//! each.
//!
//! | | |
//! |---|---|
//! | [`PromptSession::verdict`] | The one decision. `Err` means the window is gone without deciding. |
//! | [`PromptSession::outbox`] | Output and the final outcome, sent *after* an approval. |
//! | [`PromptSession::kill_requested`] | Fires when the user presses Kill. Plugs straight into [`crate::exec::RunOpts::cancel`]. |
//! | [`PromptSession::window_gone`] | Fires when the window is no longer there. |
//!
//! and two ways for the request to be done with it: [`PromptSession::close`],
//! which ends the window, and [`PromptSession::detach`], which gives it up.
//!
//! The two orders that matter, in full:
//!
//! **Approve, stream, finish.**
//!
//! ```text
//! let mut session = prompter.prompt(request, queue.subscribe_depth()).await?;
//! let Ok(Verdict::Approve { stream }) = session.verdict().await else { .. };
//! // The approval is now held; the window is a running indicator.
//! let outbox = session.outbox();
//! let (tx, rx) = mpsc::channel(..);
//! tokio::spawn(forward(rx, outbox.clone()));   // a *different* task -- see below
//! let out = exec::run(&argv, &env, &cwd, RunOpts {
//!     cancel: session.kill_requested(),        // the Kill button, wired through
//!     chunks: stream.then(|| tx),
//!     ..
//! }).await;
//! outbox.finished(outcome_of(&out)).await;
//! session.close().await;                       // the window is over
//! // -- or, when the user asked to watch it --
//! session.detach();                            // the window is theirs now
//! ```
//!
//! The forwarding task is not optional: [`crate::exec::run`] backpressures on
//! its chunk channel, so the receiver must be drained by a task other than the
//! one awaiting `run`. Sending output from inside that same task deadlocks as
//! soon as the channel fills.
//!
//! **Deny and stop.**
//!
//! ```text
//! let mut session = prompter.prompt(request, queue.subscribe_depth()).await?;
//! match session.verdict().await {
//!     Ok(Verdict::Deny { note }) => { session.close().await; deny(note) }
//!     Err(PromptGone) => { session.close().await; log(LogVerdict::PromptDied); deny(..) }
//!     ..
//! }
//! ```
//!
//! Nothing is sent to the outbox, `close` ends the window, and the tool error
//! goes back to the agent. A window that closed itself the instant it sent
//! `Deny` is not a race: the verdict is delivered through a channel that keeps
//! the value after the sender is gone, so a decision followed immediately by a
//! death is always read as the decision. [`PromptGone`] means what it says —
//! nothing was decided.
//!
//! # Who kills the child
//!
//! The daemon owns the clock, so the daemon ends the window: at the approval
//! deadline, on client cancellation, on transport disconnect, and after the
//! outcome has been sent. [`PromptSession::close`] is that call, and it does
//! not return until the child has been signalled and reaped.
//!
//! Dropping the session does the same thing, minus the waiting. That is the
//! part that is not a convenience: an approval window that outlives the request
//! it belongs to is a window a user can still click, and clicking it would
//! answer a question nobody is listening to any more. Every path out of the
//! daemon's request handler — including a panic, an early `?`, and the dropped
//! future of a client that hung up — drops the session, and the child dies with
//! it. `close` exists so the common paths are also *deterministic*, not merely
//! eventual.
//!
//! [`PromptSession::detach`] is the one exception, and it is narrow: a streamed
//! command has finished, the window has been told so, and there is no question
//! left for a click to answer. The window outlives the request on purpose,
//! showing its output to the person who asked to watch it, and from that moment
//! the daemon neither waits for it nor ends it. What keeps that from being an
//! orphan is on the window's side — a countdown, a channel that ends when the
//! daemon does, and a backstop thread — not here.
//!
//! The session deliberately does not take a [`tokio_util::sync::CancellationToken`]
//! for this. A token would make the kill something the caller has to remember to
//! wire up, and the failure of forgetting is a live window nobody owns.
//!
//! # No environment-variable bypass
//!
//! There is none, and there will not be one. A variable that skipped the GUI
//! would be readable and settable from inside the sandbox, which is the exact
//! boundary this tool exists to defend. `StubPrompter` is a cargo feature
//! instead: a compile-time choice, made by whoever builds the binary, absent
//! from a release build.
//!
//! # What the stub can and cannot express
//!
//! `StubPrompter` exists so the server's tests can drive the real request
//! flow without a display, and a stub that cannot produce a failure the real
//! prompter produces is a stub that makes those tests lie. So it can be
//! scripted to answer, to answer late, to never answer, to die before deciding,
//! to die after deciding, to press Kill while a command runs, and to fail to
//! open at all — and it records the request it was given, everything the daemon
//! streamed back, and every queue depth it was told about.
//!
//! Three real failures are deliberately *not* separate script entries, because
//! they are indistinguishable from ones that are, as seen from the daemon:
//!
//! * A window that sends an unreadable frame. [`ProcessPrompter`] ends the
//!   channel when it can no longer parse it, so the daemon sees exactly what
//!   `Reply::dies` produces.
//! * A window that sends a second verdict. Only the first is ever delivered;
//!   the rest are dropped, so there is nothing for the daemon to observe.
//! * A window that is wedged and never reads its stdin. The writer gives up on
//!   it and the window is treated as gone, which is again `Reply::dies`.
//!
//! What the stub does not model at all is the process: there is no child, so
//! `close` is instant and no test using it proves anything about reaping. That
//! is [`ProcessPrompter`]'s own tests' job.

use std::ffi::OsString;
use std::io;
use std::time::Duration;

use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader};
use tokio::process::Command;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::exec::Stream;
use crate::protocol::{self, DaemonMsg, Outcome, PromptMsg, Request, Verdict};

/// The subcommand that draws one window. The daemon spawns *itself* with it,
/// so this string and `main`'s dispatch are the same fact written twice.
const PROMPT_MODE: &str = "prompt";

/// How many messages may be queued for one window before the sender waits.
///
/// Bounded so that a window which stops reading cannot make the daemon buffer
/// an unbounded command's output on its behalf — the stream out of
/// [`crate::exec::run`] is deliberately uncapped, because the live view is the
/// thing the user watches in order to decide whether to press Kill.
const OUTBOX_CAPACITY: usize = 64;

/// How long one frame may take to reach the window before the window is
/// treated as gone.
///
/// The alternative is worse than it looks. After an approval the window is a
/// convenience and the command is authorised, so a wedged GUI that never drains
/// its stdin must not be able to stall an approved command by filling a pipe
/// and then a channel. Giving up turns that into a lost live view and a dead
/// window, which the daemon already knows how to report.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long [`PromptSession::close`] waits for the child to be reaped.
///
/// The signal has already been sent by the time this matters, so exceeding it
/// leaves at worst a zombie, never a clickable window. It is here so that a bug
/// in a prompter implementation cannot hang the daemon's request handler.
const REAP_TIMEOUT: Duration = Duration::from_secs(5);

// ---- the seam --------------------------------------------------------------

/// Ask a human, and hand back the live session that answer arrives on.
///
/// One method, and it is `async` only because opening a window is: the verdict
/// itself is awaited on the session, not here.
#[async_trait::async_trait]
pub trait Prompter: Send + Sync {
    /// Show `req` and return a live session: the verdict, plus channels for
    /// streaming output to the window and receiving a Kill from it.
    ///
    /// `depth` is the queue's live "N more waiting" figure;
    /// [`ProcessPrompter`] forwards each value it publishes as
    /// [`DaemonMsg::QueueDepth`]. The initial value travels in
    /// [`Request::queue_depth`], because the window has to draw the badge
    /// before anything changes.
    ///
    /// # Errors
    ///
    /// The window could not be opened at all. Nothing was shown to anyone, so
    /// the caller must resolve this to a denial like any other state that is
    /// not an approval.
    async fn prompt(
        &self,
        req: Request,
        depth: broadcast::Receiver<usize>,
    ) -> anyhow::Result<PromptSession>;
}

/// The window ended without deciding.
///
/// The window was closed, the process crashed, or the channel stopped making
/// sense. Before a verdict this is a denial — [`crate::audit::LogVerdict::PromptDied`]
/// — and it is deliberately not an `anyhow::Error`: it is an outcome the daemon
/// maps, not a failure it reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromptGone;

impl std::fmt::Display for PromptGone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the approval window ended without a verdict")
    }
}

impl std::error::Error for PromptGone {}

/// One live window, from the daemon's side.
///
/// Dropping it ends the window. See the module docs.
pub struct PromptSession {
    verdict: oneshot::Receiver<Verdict>,
    outbox: Outbox,
    kill: CancellationToken,
    gone: CancellationToken,
    reaped: CancellationToken,
    shutdown: CancellationToken,
    detached: CancellationToken,
}

impl PromptSession {
    /// Await the one verdict.
    ///
    /// Cancel-safe: losing a round in a `tokio::select!` against the approval
    /// deadline leaves the verdict where it was, so a decision that arrives in
    /// the same instant as the timeout is not lost by being raced.
    ///
    /// # Errors
    ///
    /// [`PromptGone`]: the window ended without deciding. Calling this again
    /// after it has already returned a verdict also reports `PromptGone` —
    /// there is exactly one verdict per window and it is delivered once.
    pub async fn verdict(&mut self) -> Result<Verdict, PromptGone> {
        (&mut self.verdict).await.map_err(|_| PromptGone)
    }

    /// A handle for sending output and the final outcome to the window.
    ///
    /// Cheap to clone, and the clone is what goes into the task draining
    /// [`crate::exec::RunOpts::chunks`].
    pub fn outbox(&self) -> Outbox {
        self.outbox.clone()
    }

    /// The Kill button, as a token that fires when it is pressed.
    ///
    /// Hand it to [`crate::exec::RunOpts::cancel`] and the button is wired.
    /// Pressing Kill twice, or before there is anything to kill, is harmless:
    /// cancellation is idempotent and can only ever stop a command.
    pub fn kill_requested(&self) -> CancellationToken {
        self.kill.clone()
    }

    /// Fires when the window is no longer there.
    ///
    /// Before a verdict this is the same news as [`PromptGone`] and resolves to
    /// a denial. After an approval it is not: the command is authorised and
    /// runs to completion, and this only records that the Kill affordance and
    /// the live view are gone — `prompt_died_after_approve` in the audit log.
    pub fn window_gone(&self) -> CancellationToken {
        self.gone.clone()
    }

    /// End the window and wait for the child to be gone.
    ///
    /// Call it on every path out of a request: after the outcome has been sent,
    /// at the approval deadline, on cancellation, on disconnect. It is
    /// immediate and unconditional — a window that should be given the chance
    /// to draw the final outcome first is one the caller awaits
    /// [`PromptSession::window_gone`] on beforehand, under a bound of its own
    /// choosing. The clock stays with the daemon; this call does not have one
    /// of its own beyond the reaping backstop.
    pub async fn close(self) {
        self.shutdown.cancel();
        let _ = tokio::time::timeout(REAP_TIMEOUT, self.reaped.cancelled()).await;
    }

    /// Give the window up: stop owning it, and stop ending it.
    ///
    /// The one exception to "the daemon ends the window", and it is narrow on
    /// purpose. A streamed run finishes and the window has been told so; the
    /// person who ticked the box to watch it is still reading the output, and
    /// the tool result must not wait for them. So the request lets go: no
    /// signal, no reap, no waiting.
    ///
    /// What makes that safe is that there is nothing left to decide. The
    /// verdict was given, the command has run, and the window's own state
    /// machine cannot produce a second verdict — see
    /// [`crate::prompt_ui::PromptState::decide`]. A frame arriving from a
    /// detached window is read by nobody, because this is the last thing the
    /// request does with the session.
    ///
    /// Whatever is already queued for the window is still delivered: dropping
    /// the session closes the outbox, and the writing task drains it before it
    /// hands the window over. If any of that fails — an unwritable pipe, a
    /// window that stopped reading — the window is killed as it would have
    /// been, because a window that never received its outcome is a window with
    /// no reason to close itself.
    ///
    /// Call it *instead of* [`PromptSession::close`], never as well: it
    /// consumes the session, so the type says which of the two happened.
    pub fn detach(self) {
        self.detached.cancel();
        // And dropped here, which closes the outbox. `Drop` sees the token and
        // leaves the shutdown alone.
    }
}

impl Drop for PromptSession {
    fn drop(&mut self) {
        // The backstop for every path that does not reach `close`, a dropped
        // handler future included. Signal only: a `Drop` cannot await, so the
        // reaping is left to the task that owns the child.
        //
        // A detached window is the one thing this must not end, and the check
        // is here rather than in `detach` so that it also covers the panic and
        // the early return *after* a hand-over: once the window has been given
        // up, no path out of the request takes it back.
        if !self.detached.is_cancelled() {
            self.shutdown.cancel();
        }
    }
}

/// The daemon's writing end of one window.
///
/// It can say two things, which is every daemon-to-window message that follows
/// a verdict. There is no way to send a [`DaemonMsg::Request`] — the request is
/// written once, by the prompter, before this handle exists — and no way to
/// send a [`DaemonMsg::QueueDepth`], which is forwarded from the queue's own
/// broadcast. The protocol's "`Request` first and exactly once" rule is
/// therefore not a rule anyone here has to remember.
#[derive(Clone)]
pub struct Outbox(mpsc::Sender<DaemonMsg>);

impl Outbox {
    /// Send a chunk of an approved command's output to the live view.
    ///
    /// `text` is already decoded and reassembled: chunk boundaries land
    /// mid-character, so the daemon decodes and the window draws.
    ///
    /// Returns whether it was delivered. `false` means the window is gone,
    /// which after an approval is not an error and must not stop the command.
    pub async fn output(&self, stream: Stream, text: String) -> bool {
        self.send(DaemonMsg::Output { stream, text }).await
    }

    /// Tell the window how the command ended. It closes on this frame.
    ///
    /// Returns whether it was delivered, on the same terms as
    /// [`Outbox::output`].
    pub async fn finished(&self, outcome: Outcome) -> bool {
        self.send(DaemonMsg::Finished(outcome)).await
    }

    async fn send(&self, msg: DaemonMsg) -> bool {
        self.0.send(msg).await.is_ok()
    }
}

/// The window's end of one session: what a [`Prompter`] implementation fills
/// in.
///
/// Every field is a promise to the daemon, and dropping this whole struct keeps
/// all of them at once — which is what makes a panicking or aborted
/// implementation task report a dead window rather than a hung one.
pub struct WindowSide {
    /// Deliver the one verdict. Dropping it without sending is how a window
    /// says it ended without deciding.
    pub verdict: oneshot::Sender<Verdict>,
    /// Output and the final outcome, in the order the daemon sent them.
    pub messages: mpsc::Receiver<DaemonMsg>,
    /// Cancel it when the user presses Kill.
    pub kill: CancellationToken,
    /// Fires when the daemon has finished with this window. Stop, and end the
    /// process.
    pub shutdown: CancellationToken,
    /// Hold it in whatever reads from the window; dropping it says the window
    /// is gone.
    pub gone: DropGuard,
    /// Hold it in whatever owns the process; dropping it says the process has
    /// been waited for. [`PromptSession::close`] returns when it does.
    pub reaped: DropGuard,
    /// Fires when the daemon has given the window up rather than ended it —
    /// see [`PromptSession::detach`]. Deliver what is already queued, then
    /// leave the window alone.
    pub detached: CancellationToken,
}

/// The two ends of one session.
///
/// Public because it is the whole of what a [`Prompter`] implementation needs;
/// there are two in this crate and both are built from here.
pub fn session_pair() -> (PromptSession, WindowSide) {
    let (verdict_tx, verdict_rx) = oneshot::channel();
    let (msg_tx, msg_rx) = mpsc::channel(OUTBOX_CAPACITY);
    let kill = CancellationToken::new();
    let gone = CancellationToken::new();
    let reaped = CancellationToken::new();
    let shutdown = CancellationToken::new();
    let detached = CancellationToken::new();

    let session = PromptSession {
        verdict: verdict_rx,
        outbox: Outbox(msg_tx),
        kill: kill.clone(),
        gone: gone.clone(),
        reaped: reaped.clone(),
        shutdown: shutdown.clone(),
        detached: detached.clone(),
    };
    let side = WindowSide {
        verdict: verdict_tx,
        messages: msg_rx,
        kill,
        shutdown,
        gone: gone.drop_guard(),
        reaped: reaped.drop_guard(),
        detached,
    };
    (session, side)
}

// ---- the real one ----------------------------------------------------------

/// Spawns `hatch prompt` and speaks NDJSON to it.
///
/// The daemon spawns its own executable, so both ends of the channel are always
/// the same build — which is what lets [`crate::protocol`] refuse a frame it
/// does not fully understand instead of tolerating one.
pub struct ProcessPrompter {
    argv: Vec<OsString>,
    write_timeout: Duration,
}

impl ProcessPrompter {
    /// The daemon's own executable, in prompt mode.
    ///
    /// # Errors
    ///
    /// The running executable could not be located, so there is nothing to
    /// spawn.
    pub fn new() -> anyhow::Result<ProcessPrompter> {
        let exe = std::env::current_exe()
            .context("hatch cannot find its own executable, so it cannot open a window")?;
        Ok(ProcessPrompter {
            argv: vec![exe.into_os_string(), OsString::from(PROMPT_MODE)],
            write_timeout: WRITE_TIMEOUT,
        })
    }

    /// What will be spawned.
    pub fn argv(&self) -> &[OsString] {
        &self.argv
    }

    /// Spawn something else instead, for a test that needs a window which does
    /// as it is told.
    ///
    /// Behind the same feature as `StubPrompter` and for the same reason:
    /// nothing outside a test build can name a different program, and nothing
    /// at all can name one through configuration or the environment.
    #[cfg(any(test, feature = "test-stub-prompter"))]
    pub fn with_argv<S: Into<OsString>>(argv: impl IntoIterator<Item = S>) -> ProcessPrompter {
        ProcessPrompter {
            argv: argv.into_iter().map(Into::into).collect(),
            write_timeout: WRITE_TIMEOUT,
        }
    }

    /// Give up on a window that will not read sooner than the module's own
    /// figure.
    ///
    /// Behind the test gate for the same reason as [`ProcessPrompter::with_argv`],
    /// and it exists for one reason: a test that proves the daemon cannot be
    /// held by a window which never reads its request has to *wait* for that,
    /// and the production figure is a wait measured in seconds on every run.
    #[cfg(any(test, feature = "test-stub-prompter"))]
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> ProcessPrompter {
        self.write_timeout = write_timeout;
        self
    }
}

#[async_trait::async_trait]
impl Prompter for ProcessPrompter {
    async fn prompt(
        &self,
        req: Request,
        depth: broadcast::Receiver<usize>,
    ) -> anyhow::Result<PromptSession> {
        let (program, args) =
            self.argv.split_first().context("the prompt program has no argv")?;

        let mut child = Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            // Standard error is inherited on purpose: a panic or a toolkit
            // warning from the window belongs on the daemon's terminal, where
            // the user who started it can see it. Capturing it would need
            // another reader, and a pipe nobody drains is a window that blocks
            // on its own diagnostics.
            .stderr(std::process::Stdio::inherit())
            // A backstop for the paths below that return before the supervisor
            // task takes ownership of the child.
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("could not start the approval window ({program:?})"))?;

        let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            anyhow::bail!("the approval window was started without pipes");
        };

        // The request goes first and exactly once, before any task exists that
        // could write anything else. A failure here is a window that never
        // opened, and the child dies with the `Command` on the way out.
        tokio::time::timeout(self.write_timeout, write_frame(&mut stdin, &DaemonMsg::Request(req)))
            .await
            .context("the approval window did not read its request")?
            .context("the request could not be written to the approval window")?;

        let (session, side) = session_pair();
        let gone = session.window_gone();
        let WindowSide { verdict, messages, kill, shutdown, gone: gone_guard, reaped, detached } =
            side;

        tokio::spawn(read_from_window(stdout, verdict, kill, gone_guard));
        tokio::spawn(write_to_window(WriteToWindow {
            child,
            stdin,
            messages,
            depth,
            shutdown,
            gone,
            reaped,
            detached,
            write_timeout: self.write_timeout,
        }));
        Ok(session)
    }
}

/// Read the window's side of the channel until there is nothing left to
/// believe.
///
/// Every way out of this function ends with `gone` dropped, and with the
/// verdict sender dropped if it was never used — so a window that crashes, is
/// closed, or stops making sense is reported as one fact rather than as
/// silence.
async fn read_from_window(
    stdout: tokio::process::ChildStdout,
    verdict: oneshot::Sender<Verdict>,
    kill: CancellationToken,
    gone: DropGuard,
) {
    let mut lines = BufReader::new(stdout).lines();
    let mut verdict = Some(verdict);
    while let Ok(Some(line)) = lines.next_line().await {
        match protocol::read_message::<PromptMsg>(&line) {
            // The first verdict is the verdict. A second one has nowhere to go
            // and is dropped rather than treated as fatal: it cannot change an
            // answer already given, and killing an approved command over a
            // window's double-click bug would be a worse outcome than ignoring
            // it.
            Ok(PromptMsg::Verdict(v)) => {
                if let Some(tx) = verdict.take() {
                    let _ = tx.send(v);
                }
            }
            Ok(PromptMsg::Kill) => kill.cancel(),
            // A frame we cannot read means the two ends no longer agree about
            // the protocol, which cannot happen without a bug -- both ends are
            // the same build. Ending the channel resolves to deny before a
            // verdict and costs only the Kill button after one; carrying on
            // would mean trusting the next line from a source that just proved
            // it is not what it claims to be.
            Err(_) => break,
        }
    }
    drop(gone);
}

/// Everything the writing half owns. One struct because a seven-argument
/// function is a call nobody can check at a glance.
struct WriteToWindow {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    messages: mpsc::Receiver<DaemonMsg>,
    depth: broadcast::Receiver<usize>,
    shutdown: CancellationToken,
    gone: CancellationToken,
    reaped: DropGuard,
    detached: CancellationToken,
    write_timeout: Duration,
}

/// What this task does with the child once there is nothing left to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// Signal it and reap it. Every ending but the one below.
    Kill,
    /// Leave it running and only reap it when it goes: the daemon detached,
    /// and everything it had queued reached the pipe first. See
    /// [`PromptSession::detach`].
    HandOver,
}

/// Write to the window until there is no more to say, then end the process.
///
/// This task owns the child, so it is also the one that kills and reaps it. The
/// kill is unconditional on every exit path but one -- including the one where
/// the window already left -- because `wait` on a process that is already dead
/// is how a zombie is collected, and a `start_kill` on one is an error we do
/// not need to hear about.
///
/// The exception is [`Ending::HandOver`]: the daemon detached and every frame
/// it queued was written, so the window is now somebody's to read and this task
/// stays only to reap it when it goes. Its stdin is deliberately held open for
/// that whole time -- closing it would reach the window as the channel ending,
/// which is one of the ways a detached window leaves.
async fn write_to_window(w: WriteToWindow) {
    let WriteToWindow {
        mut child,
        mut stdin,
        mut messages,
        mut depth,
        shutdown,
        gone,
        reaped,
        detached,
        write_timeout,
    } = w;
    let mut depth_open = true;
    let ending;

    loop {
        let msg = tokio::select! {
            _ = shutdown.cancelled() => { ending = Ending::Kill; break }
            // The window left. Nothing more can be delivered to it, and the
            // reader has already told the daemon.
            _ = gone.cancelled() => { ending = Ending::Kill; break }
            msg = messages.recv() => match msg {
                Some(msg) => msg,
                // The outbox is closed, which is the last thing `detach` does.
                // Everything it held has been written by now, so a detached
                // window has had its outcome and can be handed over.
                None => {
                    ending = match detached.is_cancelled() {
                        true => Ending::HandOver,
                        false => Ending::Kill,
                    };
                    break;
                }
            },
            // Nothing about the queue behind other windows is worth saying to
            // a window the daemon has already let go of.
            update = depth.recv(), if depth_open && !detached.is_cancelled() => match update {
                Ok(depth) => DaemonMsg::QueueDepth { depth: badge(depth) },
                // The badge is a latest-value display, so a lagged receiver has
                // missed nothing that matters: the next value it reads is the
                // truth.
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                // The queue is gone, which happens at shutdown. Stop polling
                // this arm rather than spinning on an error that repeats.
                Err(broadcast::error::RecvError::Closed) => {
                    depth_open = false;
                    continue;
                }
            },
        };
        // A window that will not read is a window that is over, and so is one
        // the daemon has finished with. Either way a half-written frame does
        // not matter: nothing will read the rest of it, because the next thing
        // that happens is the kill below.
        //
        // Shutdown has to be able to interrupt the write, not merely follow it.
        // A window that stopped reading blocks here for `WRITE_TIMEOUT`, and a
        // deadline that had to wait that out before killing anything would be a
        // window still on screen seconds after its own countdown reached zero.
        let written = tokio::time::timeout(write_timeout, write_frame(&mut stdin, &msg));
        tokio::select! {
            _ = shutdown.cancelled() => { ending = Ending::Kill; break }
            done = written => match done {
                Ok(Ok(())) => {}
                // A frame that did not land is a window that did not hear the
                // thing it would have closed itself over, so it is killed even
                // if the daemon has let go of it. This is the one path that
                // takes a hand-over back.
                Ok(Err(_)) | Err(_) => { ending = Ending::Kill; break }
            },
        }
    }

    if ending == Ending::Kill {
        let _ = child.start_kill();
    }
    let _ = child.wait().await;
    // Held until the child is gone, so a handed-over window keeps a live
    // channel to read the end of. See this function's docs.
    drop(stdin);
    drop(reaped);
}

/// The queue depth as the badge carries it.
///
/// Saturating rather than wrapping: a depth this large is not reachable, and if
/// it somehow were, a badge reading "3 more waiting" for four billion would be
/// a lie where an implausible number is merely surprising.
fn badge(depth: usize) -> u32 {
    u32::try_from(depth).unwrap_or(u32::MAX)
}

/// Write one message as one frame.
///
/// Through [`protocol::write_message`] into memory rather than serialising
/// here: the framing guard, the terminator and the single-line check are all
/// its job, and this function's only addition is that the pipe is asynchronous.
/// The flush that matters is the one on the pipe; the one into the buffer is
/// free.
async fn write_frame<W: AsyncWrite + Unpin>(out: &mut W, msg: &DaemonMsg) -> io::Result<()> {
    let mut frame = Vec::new();
    protocol::write_message(&mut frame, msg)?;
    out.write_all(&frame).await?;
    out.flush().await
}

// ---- the scriptable one ----------------------------------------------------

#[cfg(feature = "test-stub-prompter")]
pub use stub::{Recorded, Reply, StubPrompter};

#[cfg(feature = "test-stub-prompter")]
mod stub {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::sync::{broadcast, watch};

    use super::{DaemonMsg, PromptSession, Prompter, Request, Verdict, WindowSide, session_pair};

    /// A window that does what a test told it to do.
    ///
    /// Behind the `test-stub-prompter` feature, never `cfg(test)`: integration
    /// tests link the library compiled without `cfg(test)`, so a `cfg(test)`
    /// stub would not exist for the tests that need it most.
    pub struct StubPrompter {
        script: Mutex<VecDeque<Reply>>,
        log: Arc<Mutex<Vec<Recorded>>>,
        /// How many windows are still on their channel. See
        /// [`StubPrompter::settled`].
        open: watch::Sender<usize>,
    }

    /// What one window did, from the daemon's side of it.
    #[derive(Debug, Clone)]
    pub struct Recorded {
        /// What it was asked.
        pub request: Request,
        /// What the daemon sent it, in order.
        pub sent: Vec<DaemonMsg>,
        /// Every queue depth it was told about after the request.
        pub depths: Vec<usize>,
        /// Whether the daemon gave this window up rather than ending it — see
        /// [`PromptSession::detach`]. Only true once the window's channel has
        /// finished, so read it after [`StubPrompter::settled`].
        pub detached: bool,
    }

    /// One scripted window.
    ///
    /// The shape is a verdict, when it arrives, and what the window does next,
    /// because that is what varies between the cases the daemon has to handle.
    /// Build one with [`Reply::verdict`], [`Reply::silent`], [`Reply::dies`] or
    /// [`Reply::fails`], then adjust it with the `then_` methods.
    #[derive(Debug, Clone)]
    pub struct Reply {
        verdict: Option<Verdict>,
        delay: Duration,
        then: Then,
        failure: Option<String>,
    }

    /// What a window does once it has answered, or decided not to.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Then {
        /// Stay open, drawing whatever arrives, until the daemon closes it.
        Stay,
        /// End at once. Before a verdict this is a crash; after one it is the
        /// user closing a window whose command is already authorised.
        Die,
        /// Press Kill this long after answering.
        Kill(Duration),
    }

    impl Reply {
        /// Answer with this verdict, at once, and stay open.
        pub fn verdict(verdict: Verdict) -> Reply {
            Reply { verdict: Some(verdict), delay: Duration::ZERO, then: Then::Stay, failure: None }
        }

        /// Never answer. The window stays open until the daemon's deadline
        /// closes it — the approval timeout, which is not the same outcome as a
        /// denial.
        pub fn silent() -> Reply {
            Reply { verdict: None, delay: Duration::ZERO, then: Then::Stay, failure: None }
        }

        /// End without deciding: a crashed or closed window.
        pub fn dies() -> Reply {
            Reply { verdict: None, delay: Duration::ZERO, then: Then::Die, failure: None }
        }

        /// Fail to open at all, with this message. Nothing is ever shown.
        pub fn fails(message: impl Into<String>) -> Reply {
            Reply {
                verdict: None,
                delay: Duration::ZERO,
                then: Then::Die,
                failure: Some(message.into()),
            }
        }

        /// Wait this long before answering. A test that needs to win or lose a
        /// race against the approval deadline sets it deliberately.
        pub fn after(mut self, delay: Duration) -> Reply {
            self.delay = delay;
            self
        }

        /// End immediately after answering. Before an approval this denies;
        /// after one the command is authorised and runs on without a window.
        pub fn then_dies(mut self) -> Reply {
            self.then = Then::Die;
            self
        }

        /// Press Kill this long after answering.
        pub fn then_kills_after(mut self, delay: Duration) -> Reply {
            self.then = Then::Kill(delay);
            self
        }
    }

    impl From<Verdict> for Reply {
        fn from(verdict: Verdict) -> Reply {
            Reply::verdict(verdict)
        }
    }

    impl StubPrompter {
        /// A prompter that answers with these, in order, one per window.
        pub fn new<R: Into<Reply>>(script: impl IntoIterator<Item = R>) -> StubPrompter {
            StubPrompter {
                script: Mutex::new(script.into_iter().map(Into::into).collect()),
                log: Arc::new(Mutex::new(Vec::new())),
                open: watch::channel(0).0,
            }
        }

        /// Wait until every window has finished with its channel.
        ///
        /// It exists because a detached window is one the daemon deliberately
        /// stops waiting for — see [`PromptSession::detach`] — so a request
        /// returning no longer means the last frame has been taken off the
        /// pipe. A test that reads [`StubPrompter::recorded`] after a streamed
        /// run has to wait for the window rather than for the agent, and this
        /// is that wait, without a sleep in it.
        pub async fn settled(&self) {
            let mut open = self.open.subscribe();
            let _ = open.wait_for(|count| *count == 0).await;
        }

        /// Every request that reached a window, in order.
        ///
        /// A request that was refused before prompting is absent, which is the
        /// point: `seen().is_empty()` is how a test proves the user was never
        /// asked.
        pub fn seen(&self) -> Vec<Request> {
            self.log.lock().unwrap().iter().map(|r| r.request.clone()).collect()
        }

        /// Every window, with what the daemon sent it.
        pub fn recorded(&self) -> Vec<Recorded> {
            self.log.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl Prompter for StubPrompter {
        async fn prompt(
            &self,
            req: Request,
            depth: broadcast::Receiver<usize>,
        ) -> anyhow::Result<PromptSession> {
            // Taken before anything is recorded, and panicking rather than
            // failing softly: an unscripted prompt means the test does not
            // describe what the code under test does, and an invented denial
            // would let it pass for the wrong reason.
            let reply = self.script.lock().unwrap().pop_front().unwrap_or_else(|| {
                panic!(
                    "the stub prompter was asked to open a window it has no script for \
                     (request: {:?})",
                    req.title
                )
            });

            if let Some(message) = reply.failure {
                return Err(anyhow::anyhow!(message));
            }

            let index = {
                let mut log = self.log.lock().unwrap();
                log.push(Recorded {
                    request: req,
                    sent: Vec::new(),
                    depths: Vec::new(),
                    detached: false,
                });
                log.len() - 1
            };

            let (session, side) = session_pair();
            self.open.send_modify(|count| *count += 1);
            tokio::spawn(window(
                reply,
                side,
                depth,
                self.log.clone(),
                index,
                self.open.clone(),
            ));
            Ok(session)
        }
    }

    /// One scripted window, living as long as a real one would.
    async fn window(
        reply: Reply,
        side: WindowSide,
        mut depth: broadcast::Receiver<usize>,
        log: Arc<Mutex<Vec<Recorded>>>,
        index: usize,
        open: watch::Sender<usize>,
    ) {
        // Decremented on every path out, the early returns included, so
        // `settled` cannot wait for a window that has already given up.
        let _counted = Counted(open);
        // The stub has no process, so a hand-over and a close end this task the
        // same way. Which of the two it was is still worth recording: it is the
        // difference between a window the daemon ended and one it left for a
        // reader, and the server's tests have no other way to see it.
        let WindowSide { verdict, mut messages, kill, shutdown, gone, reaped, detached } = side;

        if !reply.delay.is_zero() {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(reply.delay) => {}
            }
        }
        // A window that answers gives its sender away; one that does not holds
        // it to the end. A dropped sender is how a window says it ended without
        // deciding, and a window that is merely silent has not ended.
        let _unanswered = match reply.verdict {
            Some(v) => {
                let _ = verdict.send(v);
                None
            }
            None => Some(verdict),
        };

        let kill_at = match reply.then {
            // A window that ends here was never detached: the daemon has not
            // even had the chance. The record already says so.
            Then::Die => return,
            Then::Kill(delay) => Some(tokio::time::Instant::now() + delay),
            Then::Stay => None,
        };
        let killing = async move {
            match kill_at {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::pin!(killing);
        let mut pressed = false;
        let mut depth_open = true;

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = &mut killing, if !pressed => {
                    pressed = true;
                    kill.cancel();
                }
                msg = messages.recv() => match msg {
                    Some(msg) => log.lock().unwrap()[index].sent.push(msg),
                    None => break,
                },
                update = depth.recv(), if depth_open => match update {
                    Ok(depth) => log.lock().unwrap()[index].depths.push(depth),
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => depth_open = false,
                },
            }
        }
        log.lock().unwrap()[index].detached = detached.is_cancelled();
        drop(gone);
        drop(reaped);
    }

    /// One window's place in the count `settled` waits on.
    struct Counted(watch::Sender<usize>);

    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.send_modify(|count| *count = count.saturating_sub(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use chrono::Utc;
    use tokio::time::timeout;

    use super::*;
    use crate::protocol::Payload;
    use crate::render::render_command;

    /// A hard ceiling on anything that waits for hatch to end a process.
    ///
    /// Every one of these finishes in milliseconds when the code works. When it
    /// does not, the child is one that ignores termination, and a
    /// test that can hang forever takes the whole run with it.
    const PATIENCE: Duration = Duration::from_secs(10);

    /// A hard ceiling on anything that waits on a window, a child or a channel.
    ///
    /// Every one of these finishes in milliseconds when the code works. When it
    /// does not -- which is what several mutants in this module's matrix do --
    /// the wait is on something that will never arrive, and a test that can hang
    /// forever is a test that takes the whole run with it.
    async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
        timeout(PATIENCE, fut).await.expect("this waited on something that never happened")
    }

    /// Processor time this thread has used, in kernel ticks.
    fn thread_cpu_ticks() -> u64 {
        let stat = std::fs::read_to_string("/proc/thread-self/stat").expect("this test reads /proc");
        // A command name may contain spaces and brackets, so the fixed fields
        // start after the last `)`. `utime` and `stime` are the 14th and 15th of
        // the whole line, which is the 12th and 13th of what is left.
        let fields: Vec<&str> =
            stat.rsplit_once(')').expect("a stat line").1.split_whitespace().collect();
        fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
    }

    /// What a window costs while nothing is supposed to be happening.
    ///
    /// A select arm that stays ready forever -- a closed channel, an elapsed
    /// timer -- does not fail an assertion anywhere: the loop still forwards
    /// everything it should, it just never stops running. That is invisible
    /// except as processor time, so this measures it. Every task of a window
    /// under test runs on this thread's runtime, and the rest of the suite runs
    /// on other threads of the same process, so a per-thread figure sees the
    /// window and nothing else.
    async fn ticks_while_idle(period: Duration) -> u64 {
        let before = thread_cpu_ticks();
        tokio::time::sleep(period).await;
        thread_cpu_ticks() - before
    }

    /// A tenth of the idling period, in ticks, on either plausible kernel tick
    /// rate. A spinning loop burns the whole period.
    const IDLE_TICKS: u64 = 5;

    fn sample_request() -> Request {
        Request {
            title: "sample".to_string(),
            reason: "a test asked for a window".to_string(),
            deadline: Utc::now() + chrono::Duration::seconds(90),
            queue_depth: 0,
            payload: Payload::command(
                &render_command("true", &BTreeMap::new()),
                Vec::new(),
                PathBuf::from("/"),
                false,
                false,
            ),
        }
    }

    /// A queue that never publishes anything, for a test that is not about the
    /// badge. The sender is returned because dropping it closes the channel.
    fn no_depth() -> (broadcast::Sender<usize>, broadcast::Receiver<usize>) {
        let (tx, rx) = broadcast::channel(8);
        (tx, rx)
    }

    // ---- being done with a session ----------------------------------------

    #[tokio::test]
    async fn only_detaching_leaves_the_window_running() {
        // Three ways for a request to be done with a session. Two of them end
        // the window and one hands it over, and the difference is a single
        // token: a `Drop` that cancelled the shutdown anyway would make
        // `detach` a comment rather than a behaviour.
        let (session, side) = session_pair();
        drop(session);
        assert!(side.shutdown.is_cancelled(), "a dropped session must end its window");
        assert!(!side.detached.is_cancelled());

        let (session, side) = session_pair();
        within(session.close()).await;
        assert!(side.shutdown.is_cancelled(), "a closed session must end its window");
        assert!(!side.detached.is_cancelled());

        let (session, side) = session_pair();
        session.detach();
        assert!(!side.shutdown.is_cancelled(), "a detached window was told to shut down");
        assert!(side.detached.is_cancelled(), "and was not told it had been let go");
    }

    // ---- the stub ----------------------------------------------------------

    #[cfg(feature = "test-stub-prompter")]
    mod scripted {
        use super::*;

        #[tokio::test]
        async fn stub_returns_the_scripted_verdict() {
            let p = StubPrompter::new(vec![Verdict::Deny { note: "nope".to_string() }]);
            let (_tx, rx) = no_depth();
            let mut session = within(p.prompt(sample_request(), rx)).await.unwrap();
            assert_eq!(
                within(session.verdict()).await.unwrap(),
                Verdict::Deny { note: "nope".to_string() }
            );
        }

        #[tokio::test]
        async fn stub_records_what_it_was_asked() {
            let p = StubPrompter::new(vec![Verdict::Approve { stream: false }]);
            let (_tx, rx) = no_depth();
            within(p.prompt(sample_request(), rx)).await.unwrap();
            assert_eq!(p.seen()[0].title, "sample");
        }

        #[tokio::test]
        async fn the_script_is_consumed_one_window_at_a_time() {
            let p = StubPrompter::new(vec![
                Verdict::Deny { note: "first".to_string() },
                Verdict::Approve { stream: true },
            ]);
            let (_tx, rx) = no_depth();
            let mut first = within(p.prompt(sample_request(), rx)).await.unwrap();
            let (_tx2, rx2) = no_depth();
            let mut second = within(p.prompt(sample_request(), rx2)).await.unwrap();
            assert_eq!(within(first.verdict()).await.unwrap(), Verdict::Deny { note: "first".to_string() });
            assert_eq!(within(second.verdict()).await.unwrap(), Verdict::Approve { stream: true });
            assert_eq!(p.seen().len(), 2);
        }

        #[tokio::test]
        #[should_panic(expected = "no script for")]
        async fn an_unscripted_window_is_a_broken_test_not_a_denial() {
            let p = StubPrompter::new(Vec::<Verdict>::new());
            let (_tx, rx) = no_depth();
            let _ = within(p.prompt(sample_request(), rx)).await;
        }

        #[tokio::test]
        async fn a_silent_window_never_answers_and_never_leaves() {
            let p = StubPrompter::new(vec![Reply::silent()]);
            let (_tx, rx) = no_depth();
            let mut session = within(p.prompt(sample_request(), rx)).await.unwrap();
            assert!(
                timeout(Duration::from_millis(100), session.verdict()).await.is_err(),
                "a silent window must time out, which is not the same outcome as a denial"
            );
            assert!(
                !session.window_gone().is_cancelled(),
                "a window that has not answered is not a window that died"
            );
        }

        #[tokio::test]
        async fn a_window_that_dies_before_deciding_reports_it() {
            let p = StubPrompter::new(vec![Reply::dies()]);
            let (_tx, rx) = no_depth();
            let mut session = within(p.prompt(sample_request(), rx)).await.unwrap();
            assert_eq!(within(session.verdict()).await, Err(PromptGone));
            timeout(PATIENCE, session.window_gone().cancelled()).await.unwrap();
        }

        #[tokio::test]
        async fn a_window_can_die_after_deciding_without_taking_the_approval_with_it() {
            let p = StubPrompter::new(vec![
                Reply::verdict(Verdict::Approve { stream: true }).then_dies(),
            ]);
            let (_tx, rx) = no_depth();
            let mut session = within(p.prompt(sample_request(), rx)).await.unwrap();
            assert_eq!(within(session.verdict()).await.unwrap(), Verdict::Approve { stream: true });
            timeout(PATIENCE, session.window_gone().cancelled()).await.unwrap();
            assert!(
                !within(session.outbox().output(Stream::Stdout, "late".to_string())).await,
                "a gone window must report undelivered output rather than blocking"
            );
        }

        #[tokio::test]
        async fn a_window_can_press_kill_while_the_command_runs() {
            let p = StubPrompter::new(vec![
                Reply::verdict(Verdict::Approve { stream: true })
                    .then_kills_after(Duration::from_millis(20)),
            ]);
            let (_tx, rx) = no_depth();
            let mut session = within(p.prompt(sample_request(), rx)).await.unwrap();
            within(session.verdict()).await.unwrap();
            let kill = session.kill_requested();
            assert!(!kill.is_cancelled(), "Kill must not fire before it is pressed");
            timeout(PATIENCE, kill.cancelled()).await.unwrap();
        }

        #[tokio::test]
        async fn a_window_is_still_there_after_pressing_kill() {
            // Kill does not close the window: the command is still being
            // stopped, and what the user watches next is how it ended. A window
            // that pressed the button and then stopped existing -- or one that
            // went on pressing it -- would be a worse stand-in than no stub.
            let p = StubPrompter::new(vec![
                Reply::verdict(Verdict::Approve { stream: true })
                    .then_kills_after(Duration::from_millis(10)),
            ]);
            let (_tx, rx) = no_depth();
            let session = within(p.prompt(sample_request(), rx)).await.unwrap();
            within(session.kill_requested().cancelled()).await;
            let burned = ticks_while_idle(Duration::from_millis(300)).await;
            assert!(burned <= IDLE_TICKS, "a window spun after pressing Kill: {burned} ticks");
            assert!(within(session.outbox().finished(Outcome::Signal { signal: 9 })).await);
            let seen = wait_for(&p, |r| !r.sent.is_empty()).await;
            assert_eq!(seen[0].sent, vec![DaemonMsg::Finished(Outcome::Signal { signal: 9 })]);
        }

        #[tokio::test]
        async fn a_window_can_answer_late() {
            let p = StubPrompter::new(vec![
                Reply::verdict(Verdict::Deny { note: "eventually".to_string() })
                    .after(Duration::from_millis(50)),
            ]);
            let (_tx, rx) = no_depth();
            let mut session = within(p.prompt(sample_request(), rx)).await.unwrap();
            assert!(timeout(Duration::from_millis(5), session.verdict()).await.is_err());
            assert_eq!(
                timeout(PATIENCE, session.verdict()).await.unwrap().unwrap(),
                Verdict::Deny { note: "eventually".to_string() }
            );
        }

        #[tokio::test]
        async fn a_window_can_fail_to_open() {
            let p = StubPrompter::new(vec![Reply::fails("no display")]);
            let (_tx, rx) = no_depth();
            let opened = within(p.prompt(sample_request(), rx)).await;
            assert!(opened.is_err());
            assert!(
                p.seen().is_empty(),
                "a window that never opened showed nobody anything"
            );
        }

        #[tokio::test]
        async fn the_stub_records_what_the_daemon_streamed() {
            let p = StubPrompter::new(vec![Verdict::Approve { stream: true }]);
            let (_tx, rx) = no_depth();
            let mut session = within(p.prompt(sample_request(), rx)).await.unwrap();
            within(session.verdict()).await.unwrap();
            let outbox = session.outbox();
            assert!(within(outbox.output(Stream::Stdout, "out".to_string())).await);
            assert!(within(outbox.output(Stream::Stderr, "err".to_string())).await);
            assert!(within(outbox.finished(Outcome::Exit { code: 0 })).await);
            let sent = wait_for(&p, |r| r.sent.len() == 3).await;
            assert_eq!(
                sent[0].sent,
                vec![
                    DaemonMsg::Output { stream: Stream::Stdout, text: "out".to_string() },
                    DaemonMsg::Output { stream: Stream::Stderr, text: "err".to_string() },
                    DaemonMsg::Finished(Outcome::Exit { code: 0 }),
                ]
            );
        }

        #[tokio::test]
        async fn the_stub_records_the_queue_depths_it_was_told_about() {
            let p = StubPrompter::new(vec![Reply::silent()]);
            let (tx, rx) = no_depth();
            let _session = within(p.prompt(sample_request(), rx)).await.unwrap();
            tx.send(2).unwrap();
            tx.send(1).unwrap();
            let seen = wait_for(&p, |r| r.depths.len() == 2).await;
            assert_eq!(seen[0].depths, vec![2, 1]);
        }

        #[tokio::test]
        async fn closing_a_window_that_has_not_answered_yet_does_not_wait_for_it() {
            // The deadline is the daemon's, and a window still thinking about it
            // does not get to hold the request open past it.
            let p = StubPrompter::new(vec![
                Reply::verdict(Verdict::Approve { stream: false })
                    .after(Duration::from_secs(30)),
            ]);
            let (_tx, rx) = no_depth();
            let session = within(p.prompt(sample_request(), rx)).await.unwrap();
            timeout(Duration::from_millis(500), session.close())
                .await
                .expect("close must not wait for a window that has not answered");
        }

        #[tokio::test]
        async fn closing_a_stub_session_ends_the_window() {
            let p = StubPrompter::new(vec![Reply::silent()]);
            let (_tx, rx) = no_depth();
            let session = within(p.prompt(sample_request(), rx)).await.unwrap();
            let gone = session.window_gone();
            timeout(PATIENCE, session.close()).await.unwrap();
            timeout(PATIENCE, gone.cancelled()).await.unwrap();
        }

        #[tokio::test]
        async fn dropping_a_stub_session_ends_the_window() {
            let p = StubPrompter::new(vec![Reply::silent()]);
            let (_tx, rx) = no_depth();
                let session = within(p.prompt(sample_request(), rx)).await.unwrap();
            let gone = session.window_gone();
            // Held across the drop; see the process prompter's own test.
            let _outbox = session.outbox();
            drop(session);
            timeout(PATIENCE, gone.cancelled()).await.unwrap();
        }

        /// Poll the stub's record until `done`, or give up. The window is a
        /// task of its own, so what it has recorded is not visible the instant
        /// the daemon's `send` returns.
        async fn wait_for(
            p: &StubPrompter,
            done: impl Fn(&Recorded) -> bool,
        ) -> Vec<Recorded> {
            timeout(PATIENCE, async {
                loop {
                    let recorded = p.recorded();
                    if recorded.first().is_some_and(&done) {
                        return recorded;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .expect("the stub window never recorded what it was sent")
        }
    }

    // ---- the real one ------------------------------------------------------
    //
    // No test here opens a window: there is no display in CI, and the window is
    // not written yet. What these do cover is everything on this side of the
    // pipe -- the spawn, the request going first, the reader's handling of
    // every frame a window can send, the forwarding of depth and output, and
    // the promise that no child outlives its session. What they deliberately do
    // not cover is the window itself: that `hatch prompt` draws the request,
    // answers it, and exits. That belongs to the task that writes it, and a
    // test here that asserted it would be asserting the fake.

    /// A stand-in window: a shell script speaking the same NDJSON.
    ///
    /// It gives up the standard error it inherited, and every one of these that
    /// waits does so for [`FAKE_WINDOW_LIFETIME`] rather than forever. Both are
    /// about what happens when a test *fails*: a panicking test drops its
    /// runtime without reaping, and a leaked child holding the harness's
    /// standard error keeps `cargo test` waiting long after the run itself is
    /// over. A window that cannot talk and cannot outlive the suite is one that
    /// a failing test cannot turn into a stalled run.
    fn fake_window(script: &str) -> ProcessPrompter {
        ProcessPrompter::with_argv(["sh", "-c", &format!("exec 2>/dev/null; {script}")])
    }

    /// What a fake window does when it is told to wait. Long enough that no
    /// test outlasts it, short enough that a leaked one is gone before anybody
    /// notices.
    const FAKE_WINDOW_LIFETIME: &str = "exec sleep 30";

    /// One frame, as a window would write it. Single quotes are what the shell
    /// script wraps it in, and JSON has no way to produce one.
    fn frame(msg: &PromptMsg) -> String {
        let encoded = protocol::encode(msg).unwrap();
        assert!(!encoded.contains('\''), "this frame cannot be embedded in a shell script");
        format!("printf '%s\\n' '{encoded}'")
    }

    /// A window that says these things and then waits to be killed.
    fn window_saying(messages: &[PromptMsg]) -> ProcessPrompter {
        let mut script: Vec<String> = messages.iter().map(frame).collect();
        script.push(FAKE_WINDOW_LIFETIME.to_string());
        fake_window(&script.join("; "))
    }

    /// A window that writes down every frame the daemon sends it, one line at a
    /// time.
    ///
    /// A shell read loop rather than `cat`, which buffers: the point of these
    /// tests is *when* a frame arrives, and a recorder that only writes once its
    /// buffer fills cannot show that.
    fn window_recording_to(path: &std::path::Path) -> ProcessPrompter {
        fake_window(&format!(
            "while IFS= read -r line; do printf '%s\n' \"$line\" >> \"{}\"; done",
            path.display()
        ))
    }

    /// Wait for the recording window's file to hold `lines` frames.
    ///
    /// Only complete lines count. The file is being written by another process
    /// as this reads it, and a half-written frame is not a frame the window
    /// would have acted on either.
    async fn frames(path: &std::path::Path, lines: usize) -> Vec<DaemonMsg> {
        timeout(PATIENCE, async {
            loop {
                let text = std::fs::read_to_string(path).unwrap_or_default();
                let complete: Vec<&str> =
                    text.split_inclusive('\n').filter(|l| l.ends_with('\n')).collect();
                if complete.len() >= lines {
                    return complete
                        .iter()
                        .map(|l| protocol::read_message::<DaemonMsg>(l.trim_end()).unwrap())
                        .collect();
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the window was not sent what it was supposed to be sent")
    }

    #[test]
    fn the_daemon_spawns_its_own_executable_in_prompt_mode() {
        let p = ProcessPrompter::new().unwrap();
        assert_eq!(p.argv()[0], std::env::current_exe().unwrap().into_os_string());
        assert_eq!(p.argv()[1], PROMPT_MODE);
        assert_eq!(p.argv().len(), 2);
    }

    #[tokio::test]
    async fn a_window_that_cannot_be_started_is_an_error() {
        let p = ProcessPrompter::with_argv(["/nonexistent/hatch-prompt-for-a-test"]);
        let (_tx, rx) = no_depth();
        assert!(within(p.prompt(sample_request(), rx)).await.is_err());
    }

    #[tokio::test]
    async fn the_request_is_the_first_thing_written_and_the_only_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frames");
        let p = window_recording_to(&path);
        let (_tx, rx) = no_depth();
        let session = within(p.prompt(sample_request(), rx)).await.unwrap();
        let seen = frames(&path, 1).await;
        let DaemonMsg::Request(req) = &seen[0] else { panic!("the first frame must be the request") };
        assert_eq!(req.title, "sample");
        assert_eq!(seen.len(), 1, "nothing else may be written before a verdict");
        timeout(PATIENCE, session.close()).await.unwrap();
    }

    #[tokio::test]
    async fn a_verdict_from_the_window_reaches_the_daemon() {
        let p = window_saying(&[PromptMsg::Verdict(Verdict::Approve { stream: true })]);
        let (_tx, rx) = no_depth();
        let mut session = within(p.prompt(sample_request(), rx)).await.unwrap();
        assert_eq!(
            timeout(PATIENCE, session.verdict()).await.unwrap().unwrap(),
            Verdict::Approve { stream: true }
        );
        timeout(PATIENCE, session.close()).await.unwrap();
    }

    #[tokio::test]
    async fn only_the_first_verdict_counts() {
        let p = window_saying(&[
            PromptMsg::Verdict(Verdict::Deny { note: "no".to_string() }),
            PromptMsg::Verdict(Verdict::Approve { stream: false }),
        ]);
        let (_tx, rx) = no_depth();
        let mut session = within(p.prompt(sample_request(), rx)).await.unwrap();
        assert_eq!(
            timeout(PATIENCE, session.verdict()).await.unwrap().unwrap(),
            Verdict::Deny { note: "no".to_string() }
        );
        // And the extra frame is not treated as fatal: the window is still
        // there, which after an approval is what keeps the Kill button alive.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!session.window_gone().is_cancelled());
        timeout(PATIENCE, session.close()).await.unwrap();
    }

    #[tokio::test]
    async fn kill_from_the_window_fires_the_kill_token() {
        let p = window_saying(&[
            PromptMsg::Verdict(Verdict::Approve { stream: true }),
            PromptMsg::Kill,
        ]);
        let (_tx, rx) = no_depth();
        let mut session = within(p.prompt(sample_request(), rx)).await.unwrap();
        within(session.verdict()).await.unwrap();
        timeout(PATIENCE, session.kill_requested().cancelled()).await.unwrap();
        timeout(PATIENCE, session.close()).await.unwrap();
    }

    #[tokio::test]
    async fn a_window_that_will_not_take_its_request_neither_holds_the_daemon_nor_survives_it() {
        // A request larger than a pipe holds, handed to a window that never
        // reads: the write blocks in the kernel. This is the one place the
        // daemon is at the mercy of a window before there is a session to close,
        // so it is bounded here -- and the window that never got its question
        // must not be left on screen either.
        //
        // On a shortened clock, because the wait is the whole point of it and
        // the production figure is seconds on every run of the suite.
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let p = fake_window(&format!("echo $$ > {}; {FAKE_WINDOW_LIFETIME}", pidfile.display()))
            .with_write_timeout(Duration::from_millis(200));
        let mut req = sample_request();
        req.reason = "x".repeat(128 * 1024);
        let (_tx, rx) = no_depth();
        let opened = timeout(PATIENCE, p.prompt(req, rx))
            .await
            .expect("the request write must be bounded, or the daemon waits forever");
        assert!(opened.is_err());
        until_gone(pid_of(&pidfile).await).await;
    }

    #[tokio::test]
    async fn a_window_that_leaves_on_its_own_is_reaped_without_waiting_for_the_daemon() {
        // The daemon holds the session for as long as the approved command runs,
        // which can be minutes. A window that closed itself in the meantime must
        // not sit there as a zombie until the session ends -- the daemon runs for
        // as long as the user's login does, and every request would leave one.
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let p = fake_window(&format!(
            "echo $$ > {}; IFS= read -r request; {}; exit 0",
            pidfile.display(),
            frame(&PromptMsg::Verdict(Verdict::Approve { stream: false }))
        ));
        let (_tx, rx) = no_depth();
        let mut session = within(p.prompt(sample_request(), rx)).await.unwrap();
        let pid = pid_of(&pidfile).await;
        assert_eq!(
            timeout(PATIENCE, session.verdict()).await.unwrap().unwrap(),
            Verdict::Approve { stream: false }
        );
        until_gone(pid).await;
        timeout(PATIENCE, session.window_gone().cancelled()).await.unwrap();
    }

    #[tokio::test]
    async fn a_window_that_leaves_without_deciding_is_gone() {
        // It reads its request first: a window that dies before the daemon can
        // even hand it one is the other case, and that one is an error out of
        // `prompt` rather than a session at all.
        let p = fake_window("IFS= read -r request; exit 0");
        let (_tx, rx) = no_depth();
        let mut session = within(p.prompt(sample_request(), rx)).await.unwrap();
        assert_eq!(timeout(PATIENCE, session.verdict()).await.unwrap(), Err(PromptGone));
        timeout(PATIENCE, session.window_gone().cancelled()).await.unwrap();
    }

    #[tokio::test]
    async fn a_frame_that_cannot_be_read_ends_the_channel() {
        let p = fake_window(&format!("printf '%s\\n' 'not a frame'; {FAKE_WINDOW_LIFETIME}"));
        let (_tx, rx) = no_depth();
        let mut session = within(p.prompt(sample_request(), rx)).await.unwrap();
        assert_eq!(timeout(PATIENCE, session.verdict()).await.unwrap(), Err(PromptGone));
        timeout(PATIENCE, session.window_gone().cancelled()).await.unwrap();
    }

    #[tokio::test]
    async fn an_open_window_costs_nothing_once_the_queue_is_gone() {
        let p = window_saying(&[]);
        let (tx, rx) = no_depth();
        let session = within(p.prompt(sample_request(), rx)).await.unwrap();
        // The queue's broadcast ends when the daemon does, and a window open at
        // that moment has to notice rather than ask again forever.
        drop(tx);
        let burned = ticks_while_idle(Duration::from_millis(300)).await;
        assert!(burned <= IDLE_TICKS, "a window with nothing to say spun: {burned} ticks");
        within(session.close()).await;
    }

    #[tokio::test]
    async fn queue_depth_updates_reach_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frames");
        let p = window_recording_to(&path);
        let (tx, rx) = no_depth();
        let session = within(p.prompt(sample_request(), rx)).await.unwrap();
        frames(&path, 1).await;
        tx.send(3).unwrap();
        let seen = frames(&path, 2).await;
        assert_eq!(seen[1], DaemonMsg::QueueDepth { depth: 3 });
        timeout(PATIENCE, session.close()).await.unwrap();
    }

    #[tokio::test]
    async fn a_badge_that_fell_behind_catches_up_rather_than_freezing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frames");
        let p = window_recording_to(&path);
        let (tx, rx) = no_depth();
        let session = within(p.prompt(sample_request(), rx)).await.unwrap();

        // Twelve values into an eight-deep channel, with nothing awaited in
        // between: on a current-thread runtime the writer cannot drain the
        // channel while it fills, so it wakes to a `Lagged`. The badge is a
        // latest-value display, so the four it missed were superseded before it
        // could have drawn them, and the answer is to read on -- treating
        // `Lagged` as the queue going away would freeze the badge at its
        // opening value for the life of the window.
        for depth in 0..12 {
            tx.send(depth).unwrap();
        }

        let seen = frames(&path, 9).await;
        assert_eq!(seen.last().unwrap(), &DaemonMsg::QueueDepth { depth: 11 });
        within(session.close()).await;
    }

    #[tokio::test]
    async fn output_and_the_outcome_reach_the_window_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frames");
        let p = window_recording_to(&path);
        let (_tx, rx) = no_depth();
        let session = within(p.prompt(sample_request(), rx)).await.unwrap();
        let outbox = session.outbox();
        assert!(within(outbox.output(Stream::Stderr, "half a ".to_string())).await);
        assert!(within(outbox.output(Stream::Stdout, "line\n".to_string())).await);
        assert!(within(outbox.finished(Outcome::Signal { signal: 9 })).await);
        let seen = frames(&path, 4).await;
        assert_eq!(
            seen[1..],
            [
                DaemonMsg::Output { stream: Stream::Stderr, text: "half a ".to_string() },
                DaemonMsg::Output { stream: Stream::Stdout, text: "line\n".to_string() },
                DaemonMsg::Finished(Outcome::Signal { signal: 9 }),
            ]
        );
        timeout(PATIENCE, session.close()).await.unwrap();
    }

    /// On a runtime of its own thread, because this test needs the writing task
    /// to be genuinely blocked in a system call while the test goes on to close
    /// the session -- which is exactly the state a wedged window puts it in, and
    /// a state a single-threaded runtime cannot reach.
    #[tokio::test(flavor = "multi_thread")]
    async fn closing_does_not_wait_out_a_window_that_stopped_reading() {
        // `sleep` never reads its standard input, so the pipe fills and the
        // write blocks. The deadline must still end the window now, not once
        // the write gives up on its own.
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let p = fake_window(&format!("echo $$ > {}; {FAKE_WINDOW_LIFETIME}", pidfile.display()));
        let (_tx, rx) = no_depth();
        let session = within(p.prompt(sample_request(), rx)).await.unwrap();
        let pid = pid_of(&pidfile).await;
        let outbox = session.outbox();
        // Comfortably more than a pipe holds, and under the outbox's capacity so
        // that queueing it is not itself a wait.
        for _ in 0..60 {
            assert!(within(outbox.output(Stream::Stdout, "x".repeat(16384))).await);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        timeout(WRITE_TIMEOUT / 2, session.close())
            .await
            .expect("close must not wait for a write to a window nobody is reading");
        assert!(!alive(pid));
    }

    /// A window that records its own pid and then refuses to leave.
    fn stubborn_window(pidfile: &std::path::Path) -> ProcessPrompter {
        fake_window(&format!(
            "echo $$ > {}; trap '' TERM HUP INT; {FAKE_WINDOW_LIFETIME}",
            pidfile.display()
        ))
    }

    /// The pid the stubborn window wrote down, once it has written it.
    async fn pid_of(pidfile: &std::path::Path) -> nix::unistd::Pid {
        timeout(PATIENCE, async {
            loop {
                if let Ok(text) = std::fs::read_to_string(pidfile)
                    && let Ok(pid) = text.trim().parse::<i32>()
                {
                    return nix::unistd::Pid::from_raw(pid);
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the window never started")
    }

    /// Whether the process is still there. A reaped child is not, so this is
    /// only ever asked after the session has ended.
    fn alive(pid: nix::unistd::Pid) -> bool {
        nix::sys::signal::kill(pid, None).is_ok()
    }

    async fn until_gone(pid: nix::unistd::Pid) {
        timeout(PATIENCE, async {
            while alive(pid) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the window outlived the session that owned it");
    }

    /// A window that writes down its own pid and every frame it is sent, and
    /// leaves only when something ends it.
    ///
    /// Detaching is the one path that ends nothing, so every test using this
    /// finishes by killing it: the daemon's writing task holds the child's
    /// standard input open for as long as the child lives, which is what gives
    /// a handed-over window a channel to notice the daemon going away on.
    fn detachable_window(
        pidfile: &std::path::Path,
        frames: &std::path::Path,
    ) -> ProcessPrompter {
        fake_window(&format!(
            "echo $$ > {}; while IFS= read -r line; do printf '%s\n' \"$line\" >> \"{}\"; done",
            pidfile.display(),
            frames.display()
        ))
    }

    /// End a window the test detached, and wait for it to be gone.
    async fn end(pid: nix::unistd::Pid) {
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
        until_gone(pid).await;
    }

    #[tokio::test]
    async fn a_detached_window_is_left_running() {
        // The whole of what makes a linger possible. Every other path out of a
        // request signals the window; this one must not, or the window the
        // reader asked to keep is killed at the moment it is handed to them.
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let framefile = dir.path().join("frames");
        let p = detachable_window(&pidfile, &framefile);
        let (_tx, rx) = no_depth();
        let session = within(p.prompt(sample_request(), rx)).await.unwrap();
        let pid = pid_of(&pidfile).await;

        session.detach();

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(alive(pid), "detaching killed the window it was supposed to hand over");
        end(pid).await;
    }

    #[tokio::test]
    async fn a_detached_window_is_given_everything_that_was_queued_for_it() {
        // The outcome is queued and the session is given up in the same breath,
        // so the hand-over has to drain before it lets go. A window that never
        // heard how the command ended would still be drawing "it is running",
        // with nothing left anywhere to tell it otherwise.
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let framefile = dir.path().join("frames");
        let p = detachable_window(&pidfile, &framefile);
        let (_tx, rx) = no_depth();
        let session = within(p.prompt(sample_request(), rx)).await.unwrap();
        let pid = pid_of(&pidfile).await;
        let outbox = session.outbox();
        assert!(within(outbox.output(Stream::Stdout, "hello\n".to_string())).await);
        assert!(within(outbox.finished(Outcome::Exit { code: 0 })).await);
        drop(outbox);

        session.detach();

        let seen = frames(&framefile, 3).await;
        assert_eq!(
            seen[1..],
            [
                DaemonMsg::Output { stream: Stream::Stdout, text: "hello\n".to_string() },
                DaemonMsg::Finished(Outcome::Exit { code: 0 }),
            ]
        );
        end(pid).await;
    }

    /// On a runtime of its own thread, for the reason
    /// `closing_does_not_wait_out_a_window_that_stopped_reading` gives: the
    /// writing task has to be genuinely blocked in a system call.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_window_that_would_not_take_its_last_frame_is_ended_even_after_a_detach() {
        // The hand-over is conditional on the window actually having been told.
        // `sleep` never reads its standard input, so the pipe fills and the
        // write gives up -- and a window that was told nothing has no reason to
        // close itself, which is exactly the orphan this must not leave.
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let p = fake_window(&format!("echo $$ > {}; {FAKE_WINDOW_LIFETIME}", pidfile.display()))
            .with_write_timeout(Duration::from_millis(200));
        let (_tx, rx) = no_depth();
        let session = within(p.prompt(sample_request(), rx)).await.unwrap();
        let pid = pid_of(&pidfile).await;
        let outbox = session.outbox();
        // Comfortably more than a pipe holds, and under the outbox's capacity
        // so that queueing it is not itself a wait.
        for _ in 0..60 {
            assert!(within(outbox.output(Stream::Stdout, "x".repeat(16384))).await);
        }
        drop(outbox);

        session.detach();

        until_gone(pid).await;
    }

    #[tokio::test]
    async fn closing_the_session_ends_a_window_that_will_not_leave() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let p = stubborn_window(&pidfile);
        let (_tx, rx) = no_depth();
        let session = within(p.prompt(sample_request(), rx)).await.unwrap();
        let pid = pid_of(&pidfile).await;
        assert!(alive(pid));
        timeout(PATIENCE, session.close()).await.unwrap();
        assert!(!alive(pid), "close must not return while the window is still there");
    }

    #[tokio::test]
    async fn dropping_the_session_ends_the_window_too() {
        // Every path out of a request drops the session, including the ones
        // that never reach `close`: a panic, an early return, the dropped
        // future of a client that hung up. An approval window that survives one
        // of those is a window a user can still click.
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let p = stubborn_window(&pidfile);
        let (_tx, rx) = no_depth();
        let session = within(p.prompt(sample_request(), rx)).await.unwrap();
        let pid = pid_of(&pidfile).await;
        // Held across the drop, because the daemon's forwarding task holds one
        // exactly like it. A session that ended its window only by being the
        // last owner of the outbox would leave this window open.
        let outbox = session.outbox();
        drop(session);
        until_gone(pid).await;
        assert!(
            !within(outbox.output(Stream::Stdout, "late".to_string())).await,
            "a window that is gone must not still be accepting output"
        );
    }

    #[test]
    fn a_window_that_ended_without_deciding_says_so() {
        assert_eq!(PromptGone.to_string(), "the approval window ended without a verdict");
    }

    #[test]
    fn the_badge_saturates_rather_than_wrapping() {
        assert_eq!(badge(0), 0);
        assert_eq!(badge(7), 7);
        assert_eq!(badge(usize::MAX), u32::MAX);
    }
}

