//! The rmcp server: tools, auth layer, verdict mapping.
//!
//! # Why HTTP on loopback, and why the token is load-bearing
//!
//! The daemon has to live *outside* the sandbox: it is the thing that shows a
//! human what the agent asked for and applies it only if they agree. So stdio
//! transport is unusable — an MCP client speaking stdio spawns the server
//! itself, which would place the daemon inside the very sandbox it exists to
//! guard. That leaves a socket, and loopback HTTP is the transport every MCP
//! client already speaks.
//!
//! Loopback, though, is shared. The sandboxed agent can reach it, and so can
//! every other process running as any user on the machine. Nothing about
//! `127.0.0.1` restricts who may connect. The bearer token is therefore not
//! decoration: it is the only thing separating "the agent hatch was configured
//! for" from "anything else on this machine that can open a socket". It is 32
//! bytes of OS entropy, it lives in a 0600 file, and it is checked on every
//! request before any request body is parsed.
//!
//! Three further defences sit alongside it:
//!
//! * The listener binds `127.0.0.1` explicitly, never `0.0.0.0`, so the port
//!   is not exposed to the network at all.
//! * `allowed_hosts` rejects requests whose `Host` header is not a loopback
//!   name, which is what stops a web page in the user's browser from being
//!   used to reach the daemon by a rebound DNS name.
//! * The agent-controlled strings are capped in bytes *before* anything
//!   renders them, so a hostile size cannot stall the approval window.
//!
//! And behind all of it: reaching the tools is not the same as getting
//! anything to happen. Every operation still has to be rendered to a person
//! and approved.
//!
//! # One request, in order
//!
//! `Daemon::decide` is the whole of it, and the order of its steps is the
//! design rather than an implementation detail.
//!
//! 1. **Validate and render.** Everything hatch can refuse without asking
//!    anybody is refused here: a protected path, a symlink, a missing parent,
//!    a working directory that is not one, a request for something this build
//!    cannot do. Prompting for a request that is going to be refused spends
//!    the scarcest resource in the design — a person's attention — on nothing,
//!    so no refusal ever reaches the queue.
//! 2. **Take the approval lock.** One window at a time on this machine, in
//!    arrival order. The wait here is bounded only by the client: see below.
//! 3. **Open the window, and only now start the clock.** The approval deadline
//!    runs from the moment the window is spawned, so a request that spent ten
//!    minutes queued still gets a full window rather than one that is already
//!    expiring.
//! 4. **Wait for a verdict, or for one of the four ways there will never be
//!    one.** The window is answered, the deadline passes, the client cancels,
//!    or the client's connection dies — and the window can also end without
//!    deciding, which arrives on the same await as the verdict. Every one of
//!    those denies.
//! 5. **Release the lock at the verdict**, not at completion, and then carry
//!    the operation out. From here the deny rule no longer applies: a window
//!    that dies now costs the Kill button and the live view, and nothing else.
//! 6. **Write exactly one audit line.**
//!
//! ## The second gate, and the three things it can leave behind
//!
//! A `root: true` operation has a gate step 5 does not: after the approval,
//! polkit asks for a password in a dialog of its own. That wait sits inside
//! the execution timeout, because the dialog lives inside the lifetime of the
//! process hatch spawned, and that process is what the execution deadline
//! kills. Nothing is added to the bound the tool description advertises, and
//! there is no path on which a dialog nobody answers blocks the call past it.
//!
//! What comes back is not a second verdict. It is one of three facts, and the
//! daemon has to keep them apart:
//!
//! * **It ran.** The status is the command's, and this is an ordinary
//!   approval.
//! * **Nothing ran** — the dialog was dismissed, or there was no way to ask.
//!   That is [`LogVerdict::ElevationFailed`], never a nonzero exit code: a
//!   refusal and a failing command end with the same status, so reporting the
//!   number would send the agent off to fix a command that never started. It
//!   is also not a denial by the user; they approved this, and something
//!   after them did not.
//! * **hatch cannot tell.** That is [`LogVerdict::ElevationUnclear`], and it
//!   is not a softer version of either of the others. Both of those are
//!   claims; this is the absence of one, and the only honest answer when the
//!   evidence that separates them is missing.
//!
//! ## Why there is exactly one audit line
//!
//! Not because every exit path remembers to write one. `Outcome` is the
//! return type of the flow, so a path that ends without saying how it ended
//! does not compile, and `Daemon::serve` is the single place that turns one
//! into a record. Seven exit paths that each remember to log would be seven
//! chances to forget.
//!
//! ## What the agent is told
//!
//! Everything that is not an approval is a *recoverable* tool error: an
//! `Ok(CallToolResult)` with `isError` and the reason in its content, never
//! `Err(ErrorData)`. Clients render a protocol error opaquely, so `Err` would
//! tell an agent the server is broken where a person merely said no. The
//! wording of each is chosen so the agent can tell a decision from a
//! non-decision: a denial names the user, a timeout says nobody answered, a
//! size cap and an unsupported request both say plainly that nobody was asked.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Context as _;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use chrono::{Local, Utc};
use rmcp::ErrorData;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    ProtocolVersion,
    CallToolResult, ClientJsonRpcMessage, ClientNotification, ContentBlock, GetExtensions,
    ListToolsResult, PaginatedRequestParams, ProgressNotificationParam, ProgressToken, RequestId,
    ServerJsonRpcMessage, Tool,
};
use rmcp::service::{Peer, RequestContext};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::session::{
    RestoreOutcome, ServerSseMessage, SessionId, SessionManager,
};
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{RoleServer, ServerHandler, tool, tool_handler, tool_router};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::audit::{AuditLog, AuditRecord, LogDetail, LogVerdict, RunDetail, SwapDetail};
use crate::config::{self, Config};
use crate::denylist::Denylist;
use crate::exec::elevate::{Elevation, RootOutcome};
use crate::exec::env::build_child_env;
use crate::exec::{Chunk, Env, Output, RunOpts};
use crate::paths::Paths;
use crate::prompter::{Outbox, ProcessPrompter, PromptSession, Prompter};
use crate::protocol::{Payload, Request as PromptRequest, ReviseKind, Verdict};
use crate::render::diff::{FileDiff, diff_files};
use crate::render::render_command;
use crate::render::unicode::defang;
use crate::queue::ApprovalQueue;
use crate::swap::{ApplyError, PlanKind, RootWrite, SwapPlan};
use crate::{exec, protocol, swap};

/// Caps on the agent-controlled strings, in **bytes** of UTF-8, not
/// characters.
///
/// Bytes, because the cost these caps exist to bound is per byte: the
/// rendering passes walk the string, and some of them are super-linear, so
/// 100 KB of `$A` measured at 940 ms in a single pass. A character count
/// would also be ambiguous — scalar values or grapheme clusters? — and the
/// cheaper reading of it is trivially inflated with astral characters.
///
/// The command gets a larger allowance than the one-line fields because a
/// legitimate command can be a small inline script. `content` gets the
/// largest because it is a whole file, and matches the cap on captured
/// output for the same reason: past that size a human is no longer reading a
/// diff, they are scrolling past one.
pub const MAX_FIELD_BYTES: usize = 4 * 1024;
/// Cap on `run_command`'s `command`. See [`MAX_FIELD_BYTES`].
pub const MAX_COMMAND_BYTES: usize = 16 * 1024;
/// Cap on `swap_file`'s `content`. See [`MAX_FIELD_BYTES`].
pub const MAX_CONTENT_BYTES: usize = 256 * 1024;

/// Parameters of `run_command`.
///
/// Every field is agent-controlled and every one of them except `root` and
/// `interactive` is rendered to a human, so each is length-checked at the
/// boundary before it reaches a renderer.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunCommandParams {
    /// The one-line intent, as the user should read it.
    pub title: String,
    /// The command, as a shell would run it.
    pub command: String,
    /// Why this is needed now.
    pub reason: String,
    /// Request root. Accepted because it is part of the tool contract;
    /// refused for now.
    #[serde(default)]
    pub root: bool,
    /// Absolute working directory. Defaults to the child environment's
    /// `HOME`, which is the one the command will actually see.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Whether the command needs a terminal. Accepted because it is part of
    /// the tool contract; refused for now.
    #[serde(default)]
    pub interactive: bool,
}

/// Parameters of `swap_file`. See [`RunCommandParams`].
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SwapFileParams {
    /// The one-line intent, as the user should read it.
    pub title: String,
    /// Absolute path of the file to write.
    pub path: String,
    /// The complete new contents.
    pub content: String,
    /// Why this is needed now.
    pub reason: String,
    /// Request root. Accepted because it is part of the tool contract;
    /// refused for now.
    #[serde(default)]
    pub root: bool,
}

/// Refuse a field that is over its cap, with the text the agent will read.
///
/// Nothing is truncated. A truncated command is a command the user did not
/// approve, and a truncated file is not the file the agent meant to write;
/// silently shrinking either would make the rendered window a lie. So the
/// call is refused whole.
///
/// The wording matters as much as the refusal. An agent that reads this as a
/// human saying "no" will report a denial that never happened and stop
/// trying. So the message says plainly that nobody was asked, that nothing
/// ran, and that the fix is a smaller input.
fn within_cap(field: &str, value: &str, cap: usize) -> Result<(), String> {
    let len = value.len();
    if len <= cap {
        return Ok(());
    }
    Err(format!(
        "hatch refused this call at its own boundary: `{field}` is {len} bytes, over the \
         {cap}-byte limit for that field. Nothing was rendered, nobody was asked, and nothing \
         ran — this is a size limit, not a decision by the user. Send a smaller `{field}`: put a \
         long script in a file and run the file, or write a large file in pieces you can each \
         justify."
    ))
}

/// Length-check every agent-controlled string of a `run_command` call.
fn check_run_command(params: &RunCommandParams) -> Result<(), String> {
    within_cap("title", &params.title, MAX_FIELD_BYTES)?;
    within_cap("command", &params.command, MAX_COMMAND_BYTES)?;
    within_cap("reason", &params.reason, MAX_FIELD_BYTES)?;
    if let Some(cwd) = &params.cwd {
        within_cap("cwd", cwd, MAX_FIELD_BYTES)?;
    }
    Ok(())
}

/// Length-check every agent-controlled string of a `swap_file` call.
fn check_swap_file(params: &SwapFileParams) -> Result<(), String> {
    within_cap("title", &params.title, MAX_FIELD_BYTES)?;
    within_cap("path", &params.path, MAX_FIELD_BYTES)?;
    within_cap("content", &params.content, MAX_CONTENT_BYTES)?;
    within_cap("reason", &params.reason, MAX_FIELD_BYTES)?;
    Ok(())
}


// ---- what the transport knows and a tool handler cannot --------------------

/// One in-flight call's connection, as the transport sees it.
///
/// # Why this exists at all
///
/// A request has two ways to be abandoned and the daemon has to tell them
/// apart, because a window left on a person's screen for a client that is
/// already gone is exactly the failure the approval flow exists to prevent,
/// and because a log that cannot distinguish them cannot show that both are
/// handled.
///
/// * **Cancellation.** The client sends `notifications/cancelled`. rmcp routes
///   that to the injected [`CancellationToken`], which is the arm the flow
///   selects on.
/// * **Disconnect.** The client's process dies and its HTTP connection drops.
///   Nothing in rmcp reports this to a tool handler, and the obvious guess is
///   wrong in a way worth writing down: **a dropped connection does not drop
///   the handler future.** rmcp spawns every request handler as a detached
///   task, so a drop guard held for the lifetime of the handler never fires;
///   the injected token stays uncancelled; and a progress notification sent
///   into the dead stream still reports success, because the session layer
///   swallows the send error. Measured, not assumed.
///
/// What *is* observable is the response stream. The transport builds one SSE
/// stream per request, hands it to the HTTP layer as the response body, and
/// the body is dropped when the connection dies. [`WatchedSessions`] wraps the
/// session manager so that stream's end cancels `Hangup::gone`, and puts
/// this handle in the request's extensions where the flow can find it.
///
/// # Why the two stay distinguishable
///
/// A cancellation *also* ends the response stream — the session worker closes
/// the request-wise channel the moment it sees the notification — so `gone`
/// fires for both, and it fires for a cancellation slightly *before* the
/// injected token does. Whichever wakes the flow first, the classification is
/// the flag: `WatchedSessions::accept_message` sets `cancelled` when it sees
/// the notification, strictly before it hands the notification on to the
/// session that closes the stream. So a call whose stream ended and whose flag
/// is set was cancelled, and one whose stream ended with no flag was dropped.
#[derive(Clone)]
pub struct Hangup(Arc<HangupState>);

#[derive(Default)]
struct HangupState {
    gone: CancellationToken,
    cancelled: AtomicBool,
}

impl Hangup {
    fn new() -> Hangup {
        Hangup(Arc::new(HangupState::default()))
    }

    /// Fires when the response stream carrying this call is dropped.
    fn gone(&self) -> CancellationToken {
        self.0.gone.clone()
    }

    /// Record that the client asked for this call to be cancelled.
    fn note_cancelled(&self) {
        self.0.cancelled.store(true, Ordering::SeqCst);
    }

    /// Whether a `notifications/cancelled` named this call.
    fn was_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }
}

/// The calls whose response streams are still open, by request id.
///
/// Small and self-emptying: an entry is made when a request's stream is
/// created and removed when that stream is dropped, which for every request is
/// exactly once. It exists only so that a `notifications/cancelled` arriving
/// on a *different* HTTP connection can find the call it names.
#[derive(Default)]
pub struct Calls(Mutex<HashMap<RequestId, Hangup>>);

impl Calls {
    fn begin(&self, id: RequestId) -> Hangup {
        let hangup = Hangup::new();
        locked(&self.0).insert(id, hangup.clone());
        hangup
    }

    fn forget(&self, id: &RequestId) {
        locked(&self.0).remove(id);
    }

    /// Flag the call `id` as cancelled, if it is still open.
    fn note_cancelled(&self, id: &RequestId) {
        if let Some(hangup) = locked(&self.0).get(id) {
            hangup.note_cancelled();
        }
    }

    /// How many calls are open. Diagnostics, and the test that proves an entry
    /// is not left behind.
    #[cfg(test)]
    fn open(&self) -> usize {
        locked(&self.0).len()
    }
}

/// A poisoned lock here means a thread panicked while holding it, which cannot
/// leave the map in a state worth protecting: every operation on it is a whole
/// insert or a whole remove. Take the map back rather than propagating a panic
/// into a request that has nothing to do with it.
fn locked<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The response stream for one call, with the end of it wired to a token.
///
/// The inner stream is boxed rather than projected because it is an opaque
/// `impl Stream` from the wrapped manager: boxing costs one allocation per
/// request and buys a `Drop` this type can write for itself.
struct Watched {
    inner: Pin<Box<dyn futures_core::Stream<Item = ServerSseMessage> + Send + Sync>>,
    _end: Option<StreamEnd>,
}

impl futures_core::Stream for Watched {
    type Item = ServerSseMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

/// Says the connection is over, however the stream it lives in ended.
///
/// A separate type rather than a `Drop` on [`Watched`] so that the field can
/// be `Option`: a message that is not a request gets no token and no entry.
struct StreamEnd {
    id: RequestId,
    hangup: Hangup,
    calls: Arc<Calls>,
}

impl Drop for StreamEnd {
    fn drop(&mut self) {
        self.calls.forget(&self.id);
        self.hangup.0.gone.cancel();
    }
}

/// [`LocalSessionManager`], plus the one fact it does not pass on.
///
/// Every method but two is a straight delegation. `create_stream` mints a
/// [`Hangup`] for the request, puts it in the request's extensions — which
/// rmcp carries all the way into [`RequestContext::extensions`] — and wraps
/// the stream so its end cancels the token. `accept_message` watches for a
/// cancellation notification and flags the call it names before passing it on.
///
/// Wrapping the *session manager* rather than the HTTP layer is what makes
/// this cheap: the manager is handed the already-parsed JSON-RPC message, so
/// the request id and the request's extensions are both in hand, and nothing
/// has to re-read or buffer a body.
pub struct WatchedSessions {
    inner: LocalSessionManager,
    calls: Arc<Calls>,
}

impl WatchedSessions {
    /// A session manager that reports its disconnects into `calls`.
    pub fn new(calls: Arc<Calls>) -> WatchedSessions {
        WatchedSessions { inner: LocalSessionManager::default(), calls }
    }
}

impl SessionManager for WatchedSessions {
    type Error = <LocalSessionManager as SessionManager>::Error;
    type Transport = <LocalSessionManager as SessionManager>::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        self.inner.create_session().await
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        self.inner.initialize_session(id, message).await
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        self.inner.has_session(id).await
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.inner.close_session(id).await
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl futures_core::Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error>
    {
        let mut message = message;
        // The token is registered and planted *before* the message is pushed
        // into the session, so the handler cannot start without it, and a
        // client that hangs up in the same instant finds it already cancelled.
        let end = match &mut message {
            ClientJsonRpcMessage::Request(request) => {
                let hangup = self.calls.begin(request.id.clone());
                request.request.extensions_mut().insert(hangup.clone());
                Some(StreamEnd { id: request.id.clone(), hangup, calls: Arc::clone(&self.calls) })
            }
            _ => None,
        };
        let inner = self.inner.create_stream(id, message).await?;
        Ok(Watched { inner: Box::pin(inner), _end: end })
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        if let ClientJsonRpcMessage::Notification(notification) = &message
            && let ClientNotification::CancelledNotification(cancelled) =
                &notification.notification
            && let Some(request_id) = &cancelled.params.request_id
        {
            // Before the delegation, not after: passing it on is what closes
            // the response stream, and the flag has to be readable by the time
            // the flow wakes up to find the stream gone.
            self.calls.note_cancelled(request_id);
        }
        self.inner.accept_message(id, message).await
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl futures_core::Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error>
    {
        self.inner.create_standalone_stream(id).await
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl futures_core::Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error>
    {
        self.inner.resume(id, last_event_id).await
    }

    async fn restore_session(
        &self,
        id: SessionId,
    ) -> Result<RestoreOutcome<Self::Transport>, Self::Error> {
        self.inner.restore_session(id).await
    }
}

/// The tool descriptions the client actually sees.
///
/// They cannot be `#[tool(description = ...)]` string literals, because the
/// number that calibrates the agent — how long a call may block — comes from
/// the user's config and is only known at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDescriptions {
    run_command: String,
    swap_file: String,
}

impl ToolDescriptions {
    /// The runtime description for `name`, or `None` if the tool has none.
    pub fn for_tool(&self, name: &str) -> Option<&str> {
        match name {
            "run_command" => Some(&self.run_command),
            "swap_file" => Some(&self.swap_file),
            _ => None,
        }
    }
}

/// Build the tool descriptions for `config`.
///
/// Prior experiments with tools like these failed on *calibration*: agents
/// either reached for them constantly or never. So these say four things
/// explicitly.
///
/// 1. Use them only when the work must happen on the host. Anything doable in
///    the workspace belongs in the workspace.
/// 2. Each call interrupts a person and may block for the **whole** bound —
///    the approval wait *plus* the command's own runtime. Quoting the
///    approval timeout alone understates it by more than three times and
///    teaches the agent that these calls are cheap.
/// 3. Batch related work into one call.
/// 4. `title` is the intent a human reads first, not the syntax; `reason` is
///    why it is needed now.
pub fn tool_descriptions(config: &Config) -> ToolDescriptions {
    let total = config.client_timeout_secs();
    let approval = config.timeout_secs;
    let exec = config.exec_timeout_secs;

    let run_command = format!(
        "Run a shell command on the host machine, outside your sandbox.\n\
         \n\
         Use this only when the work has to happen on the host: installing a system package, \
         restarting a service, reading or changing something outside your workspace, inspecting \
         the machine itself. Anything you can do inside your own workspace with your ordinary \
         tools, do it there — that is faster and it interrupts nobody.\n\
         \n\
         Every call opens a window on a person's screen and waits for them to read the command \
         and decide. One call can block for up to {total} seconds: up to {approval}s waiting for \
         that decision, then up to {exec}s while the command runs. Plan for that. Batch related \
         work into a single command — chain it with `&&`, or write a short script — instead of \
         making a run of separate calls, because each extra call is another interruption.\n\
         \n\
         The person may refuse the command, ask you to explain it, ask for a form of it that \
         is easier to read, or decide to run it themselves. You get back what actually \
         happened, which is not always what you asked for.\n\
         \n\
         Fields:\n\
         - title: the intent in one plain line. It is the first thing the person reads, so write \
         \"Install ripgrep\", not \"pacman -S ripgrep\". The point, not the syntax.\n\
         - command: the exact command, run through a shell.\n\
         - reason: why this is needed now, in a sentence or two.\n\
         - cwd: absolute working directory. Optional.\n\
         - interactive: true if the command needs a terminal — a full-screen program, a pager, a \
         prompt that expects typing.\n\
         - root: true runs it as root. Ask for this only when the work genuinely needs it — a \
         permission error without it is a normal result you may retry with it. It costs the \
         person a second interruption: after they approve in hatch's window, the system asks \
         them for a password in a dialog of its own, and dismissing that dialog stops the \
         command. Both of those waits are inside the {total} seconds above. A root command may \
         also be given a terminal where an ordinary one is not, so it may colour its output.\n\
         \n\
         Two answers mean the command did not run and you may ask again: the person refused it, \
         or the password dialog was dismissed. A third says hatch could not tell whether it ran. \
         That one is not a failure to retry — running it again may run it a second time — so ask \
         the person to check instead."
    );

    let swap_file = format!(
        "Write a file on the host machine, outside your sandbox, replacing it whole or creating \
         it.\n\
         \n\
         Use this only when the file has to live on the host: a config under /etc, a dotfile in \
         the person's home directory, a service unit. For files inside your own workspace, write \
         them directly — never through this tool.\n\
         \n\
         The person sees a diff of the change before anything is written, and approves or \
         rejects it. One call can block for up to {total} seconds while they read and decide, so \
         gather related edits into as few calls as you can.\n\
         \n\
         There is no partial edit: send the complete new contents. Read the file first — \
         `run_command` with `cat` — so what you send is an edit of what is really there and the \
         diff shows your change and nothing else.\n\
         \n\
         Fields:\n\
         - title: the intent in one plain line. It is the first thing the person reads, so write \
         \"Point the editor at the new font\", not the path and the bytes. The point, not the \
         syntax.\n\
         - path: absolute path of the file to write.\n\
         - content: the complete new contents of the file.\n\
         - reason: why this is needed now, in a sentence or two.\n\
         - root: true writes the file as root, for a path this user cannot write. The person \
         approves the same diff either way, and then the system asks them for a password in a \
         dialog of its own; dismissing it means nothing is written. A root write keeps the \
         file's existing owner and mode, or creates it owned by root — the window states which, \
         and the write either matches what it stated or does not happen."
    );

    ToolDescriptions { run_command, swap_file }
}

/// The MCP server. One is built per client session by the transport's
/// factory; they all share the one daemon behind them.
pub struct Hatch {
    daemon: Arc<Daemon>,
    tool_router: ToolRouter<Hatch>,
}

#[tool_router]
impl Hatch {
    /// A server in front of `daemon`.
    pub fn new(daemon: Arc<Daemon>) -> Hatch {
        Hatch { daemon, tool_router: Hatch::tool_router() }
    }

    /// The declared tools, with their static descriptions replaced by the
    /// ones built from the running config.
    ///
    /// A tool with no runtime description keeps its static one rather than
    /// losing it; `every_tool_has_a_runtime_description` is what makes sure
    /// that fallback is never actually taken.
    fn described_tools(&self) -> Vec<Tool> {
        let descriptions = tool_descriptions(self.daemon.config());
        self.tool_router
            .list_all()
            .into_iter()
            .map(|mut declared| {
                if let Some(text) = descriptions.for_tool(&declared.name) {
                    declared.description = Some(text.to_string().into());
                }
                declared
            })
            .collect()
    }

    // The `description` here is a placeholder the macro requires as a string
    // literal. `list_tools` replaces it with the runtime text, which is the
    // one a client ever sees.
    //
    // `RequestContext` is taken and not ignored: it carries the cancellation
    // token, the progress token and the connection this call arrived on, which
    // between them are three of the four ways a request ends without a
    // verdict.
    #[tool(description = "Run a shell command on the host, outside the sandbox.")]
    async fn run_command(
        &self,
        Parameters(params): Parameters<RunCommandParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        // `Ok`, always: every outcome a person or a clock can produce is a
        // recoverable tool error the agent can read. `Err(ErrorData)` is
        // reserved for parameters rmcp could not deserialise at all, which it
        // rejects before reaching here.
        Ok(self.daemon.run_command(params, Caller::of(&context)).await)
    }

    // See the note on `run_command`: this description is a placeholder.
    #[tool(description = "Write a file on the host, outside the sandbox.")]
    async fn swap_file(
        &self,
        Parameters(params): Parameters<SwapFileParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.daemon.swap_file(params, Caller::of(&context)).await)
    }
}

// ---- the daemon ------------------------------------------------------------

/// How long the daemon gives a window to draw the final outcome before it is
/// killed.
///
/// The window closes on the `Finished` frame by itself, so this is the time it
/// takes to read one line and exit, not a period anybody looks at anything.
/// It is bounded because [`PromptSession::close`] is unconditional and a
/// wedged window must not be able to hold a finished request open.
///
/// It is not the linger. A streamed run's window stays on screen for as long
/// as [`crate::prompt_ui`] says it does, and this daemon waits none of it: see
/// [`Windup`].
const FINAL_FRAME_GRACE: Duration = Duration::from_millis(500);

/// How often the client is told the request is still alive.
///
/// The whole request is covered — the queue wait, the approval wait and the
/// execution — because the longest silence is in the middle and a client that
/// hears nothing for ninety seconds is a client that gives up on a window
/// somebody is still reading.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

/// How many output chunks may be queued for the live view before the reader
/// waits.
///
/// Bounded, and drained by a task of its own: the task awaiting
/// [`exec::run`] must never be the task forwarding its output, or a window
/// that stops reading stalls the command it is watching.
const OUTPUT_QUEUE: usize = 64;

/// Everything one daemon shares across every session and every request.
///
/// One of these exists per `hatch serve`. The queue in particular has to be
/// shared: an approval window at a time means *at a time on this machine*, not
/// per MCP session, and several sandboxed agents can hold sessions at once.
pub struct Daemon {
    config: Arc<Config>,
    prompter: Arc<dyn Prompter>,
    queue: ApprovalQueue,
    audit: AuditLog,
    denylist: Denylist,
    /// How this build runs an approved operation as root.
    ///
    /// A `dyn` and not `Run0`, because the whole of hatch's knowledge about
    /// `run0`, polkit and systemd is meant to sit behind this one value and
    /// the daemon is meant never to learn which implementation it is holding
    /// — see [`crate::exec::elevate`]. It is also what makes every root
    /// outcome reachable from a test: the four things a password dialog can
    /// do cannot be produced on demand, and a fake implementation returning
    /// each of them in turn can.
    elevation: Arc<dyn Elevation>,
    /// Where approved bytes wait between the approval and a root write.
    stage_dir: PathBuf,
}

impl Daemon {
    /// A daemon over the directories `paths` names, asking `prompter` for
    /// decisions.
    ///
    /// The denylist is built from [`Paths::protected`] and [`Paths::home`]
    /// together, so the set of directories it protects cannot fall out of step
    /// with the set the daemon writes to, and the home it anchors the
    /// `~/.claude*` entries on is the real one rather than one inferred from a
    /// directory that no longer sits inside it.
    pub fn new(paths: &Paths, config: Config, prompter: Arc<dyn Prompter>) -> Daemon {
        let denylist = Denylist::new(&paths.protected(), paths.home(), &config.denylist_extra);
        // Not swept here. `run_serve` empties the staging directory once, at
        // startup, before it binds anything — which is the only moment a
        // sweep is safe, because at any later one it would delete the staged
        // bytes of a request somebody is deciding on in another window.
        let stage_dir = paths.stage_dir();
        Daemon {
            config: Arc::new(config),
            prompter,
            queue: ApprovalQueue::new(),
            audit: AuditLog::new(&paths.log_dir()),
            denylist,
            elevation: Arc::from(crate::exec::elevate::platform()),
            stage_dir,
        }
    }

    /// The same daemon, elevating through `elevation` instead of through the
    /// platform's mechanism.
    ///
    /// Behind the test feature and not `cfg(test)`, for the reason
    /// [`crate::prompter::StubPrompter`] is: the integration tests link the
    /// library compiled without `cfg(test)`. There is no production caller —
    /// a build that could be handed an elevation of somebody else's choosing
    /// is a build where "this ran as root" means whatever that choice says.
    #[cfg(any(test, feature = "test-stub-prompter"))]
    pub fn with_elevation(mut self, elevation: Arc<dyn Elevation>) -> Daemon {
        self.elevation = elevation;
        self
    }

    /// The running config, for the tool descriptions.
    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }
}

/// What the request flow needs from the client's side of one call.
///
/// A plain struct rather than [`RequestContext`] itself, so that the flow is
/// reachable from a test without building an rmcp peer, and so that the two
/// abandonment signals arrive as two named fields instead of as one context
/// whose behaviour has to be remembered.
pub struct Caller {
    /// Fires when the client sends `notifications/cancelled` for this call.
    cancelled: CancellationToken,
    /// The call's connection, when it has one. Absent only for a call that did
    /// not arrive over the streamable-HTTP transport, which in production is
    /// nothing and in tests is most things.
    hangup: Option<Hangup>,
    /// Where progress goes, and only when the client asked for it: a progress
    /// notification with no token from the request's `_meta` is one no client
    /// can associate with anything.
    progress: Option<(Peer<RoleServer>, ProgressToken)>,
}

impl Caller {
    /// The caller behind one rmcp request.
    fn of(context: &RequestContext<RoleServer>) -> Caller {
        Caller {
            cancelled: context.ct.clone(),
            hangup: context.extensions.get::<Hangup>().cloned(),
            progress: context
                .meta
                .get_progress_token()
                .map(|token| (context.peer.clone(), token)),
        }
    }

    /// A caller that never cancels, never hangs up and wants no progress.
    #[cfg(test)]
    fn quiet() -> Caller {
        Caller { cancelled: CancellationToken::new(), hangup: None, progress: None }
    }

    /// Resolves when the client's connection ends.
    ///
    /// Pending forever when there is no connection to watch, which is the
    /// right answer rather than a missing one: an arm that is never ready
    /// simply never wins its select.
    async fn hung_up(&self) {
        match &self.hangup {
            Some(hangup) => hangup.gone().cancelled().await,
            None => std::future::pending().await,
        }
    }

    /// Which of the two abandonments this was.
    ///
    /// Asked only once the connection is known to be gone. See [`Hangup`] for
    /// why the flag decides it and the timing does not.
    fn abandonment(&self) -> LogVerdict {
        let cancelled =
            self.cancelled.is_cancelled() || self.hangup.as_ref().is_some_and(Hangup::was_cancelled);
        if cancelled { LogVerdict::Cancelled } else { LogVerdict::Disconnected }
    }
}

// ---- one request, from arrival to audit line -------------------------------

/// Which of the long waits a request is in, for the progress ticker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Phase {
    Queued = 0,
    AwaitingApproval = 1,
    Executing = 2,
    Elevating = 3,
}

impl Phase {
    fn message(self) -> &'static str {
        match self {
            Phase::Queued => "queued behind another approval",
            Phase::AwaitingApproval => "awaiting the user's decision",
            Phase::Executing => "approved; running",
            // One message covering the whole elevated run rather than two,
            // because hatch is never told that the password was typed: there
            // is no moment at which it could honestly switch to "running".
            // This sentence is true from the spawn to the end either way.
            Phase::Elevating => "approved; waiting for the system password dialog, then running",
        }
    }

    fn of(value: u8) -> Phase {
        match value {
            0 => Phase::Queued,
            1 => Phase::AwaitingApproval,
            2 => Phase::Executing,
            _ => Phase::Elevating,
        }
    }
}

/// The progress ticker for one request.
///
/// Dropping it stops the ticker, which is the only reason it is a value at
/// all: "stopped when the request ends" then holds on every path out of the
/// flow, including the ones that return early, rather than on the paths
/// somebody remembered.
struct Progress {
    phase: Arc<AtomicU8>,
    stop: CancellationToken,
}

impl Progress {
    /// Start ticking for `caller`, if the client asked for progress.
    fn start(caller: &Caller) -> Progress {
        let phase = Arc::new(AtomicU8::new(Phase::Queued as u8));
        let stop = CancellationToken::new();
        if let Some((peer, token)) = caller.progress.clone() {
            let (phase, stop) = (Arc::clone(&phase), stop.clone());
            tokio::spawn(async move {
                let started = tokio::time::Instant::now();
                loop {
                    // Before the first wait, not after it: a client learns
                    // that its call is alive and queued at once rather than
                    // one interval later, and that first frame is also what
                    // says the request was accepted at all.
                    let message = Phase::of(phase.load(Ordering::Relaxed)).message();
                    let sent = peer
                        .notify_progress(
                            ProgressNotificationParam::new(
                                token.clone(),
                                started.elapsed().as_secs_f64(),
                            )
                            .with_message(message),
                        )
                        .await;
                    // A send that fails says the peer is no longer taking
                    // notifications, and says nothing at all about whether the
                    // request should continue: the transport reports a dead
                    // stream as a successful send anyway, so this is not a
                    // disconnect signal and is deliberately not treated as
                    // one. Stop ticking; the request goes on being decided by
                    // the user, the deadline and `Hangup`.
                    if sent.is_err() {
                        return;
                    }
                    tokio::select! {
                        _ = stop.cancelled() => return,
                        _ = tokio::time::sleep(PROGRESS_INTERVAL) => {}
                    }
                }
            });
        }
        Progress { phase, stop }
    }

    fn enter(&self, phase: Phase) {
        self.phase.store(phase as u8, Ordering::Relaxed);
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// How one request ended: the line for the log and the answer for the agent,
/// as one value.
///
/// This type is why there is exactly one audit record per request. Every exit
/// from the flow — a refusal, a denial, a timeout, a cancellation, a dropped
/// client, a dead window, a command that ran — is a `return` of one of these,
/// so the flow cannot end without saying how it ended, and
/// `Daemon::serve` appends in the single place that receives it. Seven exit
/// paths that each remember to log would be seven chances to forget; a return
/// type cannot be forgotten.
struct Outcome {
    verdict: LogVerdict,
    /// What the user typed, when a user typed anything.
    note: Option<String>,
    /// The tool-specific half of the record, as complete as this outcome
    /// knows how to make it.
    detail: LogDetail,
    /// What the agent gets back.
    result: CallToolResult,
}

impl Outcome {
    /// An outcome that carries a recoverable tool error.
    ///
    /// Every non-approval is one of these. Never `Err(ErrorData)`: that is a
    /// protocol error, and MCP clients render protocol errors opaquely, so an
    /// agent would be told the server is broken instead of being told what the
    /// person decided.
    fn refusing(
        verdict: LogVerdict,
        note: Option<String>,
        detail: LogDetail,
        message: String,
    ) -> Outcome {
        Outcome {
            verdict,
            note,
            detail,
            result: CallToolResult::error(vec![ContentBlock::text(message)]),
        }
    }
}

/// One request as it arrived, before anything has been validated.
enum Asked {
    Run(RunCommandParams),
    Swap(SwapFileParams),
}

impl Asked {
    /// The two agent-written lines every window and every log record carries,
    /// defanged: the agent chooses this text and it frames the whole decision,
    /// so a bidi override in it would reorder everything the reader sees.
    fn headline(&self) -> (String, String) {
        match self {
            Asked::Run(p) => (defang(&p.title), defang(&p.reason)),
            Asked::Swap(p) => (defang(&p.title), defang(&p.reason)),
        }
    }
}

/// A request that has passed validation and been rendered: everything needed
/// to show it, and everything needed to carry it out if it is approved.
struct Job {
    payload: Payload,
    detail: LogDetail,
    work: Work,
}

/// What an approval authorises.
enum Work {
    Run(RunPlan),
    Swap { path: PathBuf, content: Vec<u8>, plan: SwapPlan, root: bool },
}

/// Everything an approved command needs in order to run, and to be read
/// afterwards.
///
/// One struct rather than four parameters, for the reason [`RunOpts`] is one:
/// the four travel together from the moment they are built to the moment they
/// are used, and a signature that spreads them out is a signature whose call
/// sites can put two booleans in the wrong order.
struct RunPlan {
    argv: Vec<String>,
    env: Env,
    cwd: PathBuf,
    /// Whether `argv` elevates.
    ///
    /// Carried rather than re-derived from the argv, because "does this start
    /// with run0" is exactly the kind of platform knowledge the elevation
    /// module exists to keep out of the daemon. It decides how the finished
    /// run is *read* — an elevated run's exit status may not be the command's
    /// at all — so getting it wrong is not a cosmetic error.
    elevated: bool,
}

impl Daemon {
    /// Run one `run_command` call to its end.
    pub async fn run_command(&self, params: RunCommandParams, caller: Caller) -> CallToolResult {
        // The caps run before anything else touches these strings. Rendering
        // is where the super-linear work lives, so checking afterwards would
        // check nothing.
        //
        // A call refused here is deliberately *not* an audit line. It never
        // became a request: nothing was rendered, no window was opened, and
        // the record would have to carry the very field that is too large to
        // handle in the first place.
        match check_run_command(&params) {
            Ok(()) => self.serve(Asked::Run(params), caller).await,
            Err(refusal) => CallToolResult::error(vec![ContentBlock::text(refusal)]),
        }
    }

    /// Run one `swap_file` call to its end.
    pub async fn swap_file(&self, params: SwapFileParams, caller: Caller) -> CallToolResult {
        // See `run_command` on why this is here and why it is not logged.
        match check_swap_file(&params) {
            Ok(()) => self.serve(Asked::Swap(params), caller).await,
            Err(refusal) => CallToolResult::error(vec![ContentBlock::text(refusal)]),
        }
    }

    /// One request, and the one place an audit record is written.
    async fn serve(&self, asked: Asked, caller: Caller) -> CallToolResult {
        let (title, reason) = asked.headline();
        let outcome = self.decide(asked, caller, &title, &reason).await;

        // The only `append` in the crate's request path. See `Outcome`.
        let record = AuditRecord {
            ts: Local::now(),
            title,
            reason,
            verdict: outcome.verdict,
            note: outcome.note,
            detail: outcome.detail,
        };
        if let Err(error) = self.audit.append(&record) {
            // The operation has already happened, or has already been refused.
            // Turning a log failure into a tool error would report an outcome
            // that is not the one the user got; the honest thing is to say so
            // where the daemon's own output goes and answer the agent with
            // what actually happened.
            eprintln!("hatch could not write an audit record: {error:#}");
        }
        outcome.result
    }

    /// Everything between arrival and the outcome.
    ///
    /// The order is the whole design: refuse before queueing, queue before
    /// prompting, start the clock at the window and not at the queue, and stop
    /// applying the deny rule the moment a verdict arrives.
    async fn decide(
        &self,
        asked: Asked,
        caller: Caller,
        title: &str,
        reason: &str,
    ) -> Outcome {
        // Step 1. Validate and render. A refusal never reaches a person:
        // prompting for something that is going to be refused spends the
        // scarcest resource in the design on nothing.
        let job = match self.prepare(asked) {
            Prepared::Ready(job) => job,
            Prepared::Refused(refused) => return refused,
        };
        let Job { payload, mut detail, work } = job;

        // Started here and stopped by its own `Drop`, so it covers the queue
        // wait, the approval wait and the execution, and cannot outlive any
        // path out of this function.
        let progress = Progress::start(&caller);

        // Step 2. The approval lock, in arrival order. The wait is bounded by
        // the client and by nothing else: the approval deadline has not
        // started, because a request that spent its window queueing would open
        // one that is already expiring.
        let admission = tokio::select! {
            admission = self.queue.acquire() => admission,
            () = caller.cancelled.cancelled() => {
                return abandoned(LogVerdict::Cancelled, detail);
            }
            () = caller.hung_up() => {
                return abandoned(caller.abandonment(), detail);
            }
        };
        let badge = admission.queue_depth();
        let (permit, depths) = admission.into_parts();

        // Step 3. The window, and only now the clock. The deadline is computed
        // before the window is opened so that the countdown it draws and the
        // timer that enforces it are the same instant.
        progress.enter(Phase::AwaitingApproval);
        let window = Duration::from_secs(self.config.timeout_secs);
        let expires_at = tokio::time::Instant::now() + window;
        let request = PromptRequest {
            title: title.to_string(),
            reason: reason.to_string(),
            deadline: Utc::now() + chrono::Duration::seconds(self.config.timeout_secs as i64),
            queue_depth: badge,
            payload,
        };
        let mut session = match self.prompter.prompt(request, depths).await {
            Ok(session) => session,
            Err(error) => {
                return Outcome::refusing(
                    LogVerdict::PromptDied,
                    None,
                    detail,
                    format!(
                        "hatch could not open the approval window, so nobody was asked and \
                         nothing ran: {error:#}. This is not a decision by the user."
                    ),
                );
            }
        };

        // Step 4. The verdict, or one of the four ways there is never going to
        // be one. Every one of those four denies.
        let ending = tokio::select! {
            // Biased, and the verdict first: a decision that arrives in the
            // same instant as the deadline is a decision, not a timeout.
            biased;
            verdict = session.verdict() => Ending::Decided(verdict),
            () = caller.cancelled.cancelled() => Ending::Cancelled,
            () = caller.hung_up() => Ending::HungUp,
            () = tokio::time::sleep_until(expires_at) => Ending::Expired,
        };
        let verdict = match ending {
            Ending::Decided(Ok(verdict)) => verdict,
            Ending::Decided(Err(gone)) => {
                session.close().await;
                return Outcome::refusing(
                    LogVerdict::PromptDied,
                    None,
                    detail,
                    format!(
                        "{gone}, so nothing ran. The window was closed or its process died \
                         before anyone decided; this is not a decision by the user, and you may \
                         ask again."
                    ),
                );
            }
            Ending::Expired => {
                session.close().await;
                return Outcome::refusing(
                    LogVerdict::Timeout,
                    None,
                    detail,
                    format!(
                        "timed out awaiting the user after {}s. Nobody answered the window, so \
                         nothing ran and nobody decided anything. You may ask again, or find \
                         another way to make progress without them.",
                        self.config.timeout_secs
                    ),
                );
            }
            Ending::Cancelled => {
                session.close().await;
                return abandoned(LogVerdict::Cancelled, detail);
            }
            Ending::HungUp => {
                session.close().await;
                return abandoned(caller.abandonment(), detail);
            }
        };

        // Step 5. A verdict has arrived, so the lock is released now — not
        // when the command it authorised finishes. A five-minute upgrade must
        // not hold every other agent behind it.
        drop(permit);

        let (stream, note) = match verdict {
            Verdict::Approve { stream, note } => (stream, note),
            other => {
                session.close().await;
                return declined(other, detail);
            }
        };

        // From here the deny rule no longer applies. The command is
        // authorised: a window that dies now loses the Kill button and the
        // live view, and nothing else. Killing it could leave a half-finished
        // state the user never asked for.
        // Still step 5, and for a root operation there is a second gate
        // inside it: the user has approved, and the system is about to ask
        // them for a password in a dialog of its own. That wait can be the
        // longest part of the whole call, so the client's ticker has to
        // describe it rather than claim the command is running.
        progress.enter(match work.elevated() {
            true => Phase::Elevating,
            false => Phase::Executing,
        });
        let (verdict, result, windup) = match work {
            Work::Run(run) => self.run_it(&run, stream, &session, &mut detail).await,
            Work::Swap { path, content, plan, root } => {
                self.swap_it(&path, &content, &plan, root, &session, &mut detail).await
            }
        };

        note_prompt_death(&session, &mut detail);
        match windup {
            Windup::Close => {
                // The window closes on the frame that was just sent; this
                // waits for it to do so, under a bound of the daemon's own,
                // and then ends it.
                let _ =
                    tokio::time::timeout(FINAL_FRAME_GRACE, session.window_gone().cancelled())
                        .await;
                session.close().await;
            }
            // Nothing is waited for here, and that is the point: the agent's
            // result must not depend on how long a person reads a window.
            Windup::Detach => session.detach(),
        }

        // Not `LogVerdict::Approve` unconditionally. An approval that hit a
        // dismissed password dialog is an approval whose operation never
        // happened, and one whose elevation hatch could not read is an
        // approval it cannot report either way; both are their own verdicts,
        // and the log is where anyone later asks what actually ran as root.
        //
        // The note goes to both places it goes for every other verdict: into
        // the result the agent reads, and onto the audit line. `None` rather
        // than an empty string when nobody typed anything, because the field
        // means "what the user typed, if anything" and a run of empty notes
        // down the log would say they typed nothing five different ways.
        Outcome {
            verdict,
            note: (!note.is_empty()).then(|| note.clone()),
            detail,
            result: with_note(result, &note),
        }
    }
}

impl Work {
    /// Whether carrying this out will ask for a password.
    fn elevated(&self) -> bool {
        match self {
            Work::Run(run) => run.elevated,
            Work::Swap { root, .. } => *root,
        }
    }
}

/// The two ways preparation can end.
///
/// An enum rather than a `Result`, because both arms are ordinary and neither
/// is an error: a refusal is a complete outcome with its own audit line, and
/// it is as large as a success, which `Result` would make every caller pay for
/// on the way past.
enum Prepared {
    /// Validated and rendered, ready to be shown to a person.
    Ready(Job),
    /// Refused before anyone was interrupted.
    Refused(Outcome),
}

/// What becomes of the window once the operation it authorised is over.
///
/// Two arms rather than a `bool` because the difference is not a flag on one
/// behaviour: one of them waits for the window and ends it, and the other
/// stops owning it entirely. The step that reads this is the last thing the
/// request does, so the name is what says which of the two happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Windup {
    /// End it. The window closes itself on the outcome frame; the daemon
    /// gives it [`FINAL_FRAME_GRACE`] to do so and then kills and reaps it.
    Close,
    /// Let it go. A streamed run has finished and the window is showing the
    /// output to the person who asked to watch it, so the request stops
    /// waiting for it and stops ending it — see
    /// [`crate::prompter::PromptSession::detach`].
    Detach,
}

/// Which of the four things happened while the window was open.
enum Ending {
    Decided(Result<Verdict, crate::prompter::PromptGone>),
    Expired,
    Cancelled,
    HungUp,
}

// ---- step 1: validate and render, before anybody is interrupted ------------

/// What the agent is told when it asks for something this build cannot do.
///
/// Worded as a limit and not as a decision, for the same reason the size caps
/// are: an agent that reads this as a person saying no will report a denial
/// that never happened.
fn not_yet(what: &str, instead: &str) -> String {
    format!(
        "hatch cannot {what} yet: this build does not carry that path. Nothing was rendered, \
         nobody was asked and nothing ran — this is a missing feature, not a decision by the \
         user. {instead}"
    )
}

/// What the agent is told when hatch refuses a request outright.
fn refusal_text(reason: &str) -> String {
    format!(
        "hatch refused this before showing it to anyone: {reason}. Nothing was rendered, nobody \
         was asked and nothing ran — this is hatch's own rule, not a decision by the user."
    )
}

impl Daemon {
    /// Validate and render one request, or refuse it.
    ///
    /// Every refusal that can be known without asking a person is known here:
    /// an unsupported request, a working directory that is not one, a path
    /// hatch protects, a symlink, a missing parent, content nothing can draw
    /// a diff of. All of them return an outcome carrying
    /// [`LogVerdict::Refused`], and all of them return it before the queue is
    /// touched.
    fn prepare(&self, asked: Asked) -> Prepared {
        match asked {
            Asked::Run(params) => self.prepare_run(params),
            Asked::Swap(params) => self.prepare_swap(params),
        }
    }

    fn prepare_run(&self, params: RunCommandParams) -> Prepared {
        let env = build_child_env(&self.config);
        // `$HOME` as the child will see it, not as the daemon sees it: the
        // window states the directory, and a directory taken from a different
        // environment than the one the command runs in would be a stated fact
        // that is not true.
        let cwd = match &params.cwd {
            Some(given) => PathBuf::from(given),
            None => PathBuf::from(env.get("HOME").map_or("/", String::as_str)),
        };
        let detail = |cwd: &Path| {
            LogDetail::RunCommand(RunDetail {
                command: params.command.clone(),
                root: params.root,
                cwd: cwd.display().to_string(),
                exit_code: None,
                duration_ms: None,
                killed_by_user: None,
                timed_out: None,
                prompt_died_after_approve: None,
            })
        };
        let refuse = |message: String| {
            Prepared::Refused(Outcome::refusing(LogVerdict::Refused, None, detail(&cwd), message))
        };

        if params.interactive {
            return refuse(not_yet(
                "run a command in a terminal",
                "Ask for a form that does not need a terminal — a non-interactive flag, or a \
                 command whose output you can read.",
            ));
        }
        // Absolute, because a relative directory is resolved against hatch's
        // own working directory, which is not the one the request was written
        // against and is not the one the window would be describing.
        if !cwd.is_absolute() {
            return refuse(refusal_text(&format!(
                "the working directory {} is not absolute",
                cwd.display()
            )));
        }
        // Checked here rather than inside `exec::run`, so a directory that
        // does not exist costs the user no attention at all.
        match std::fs::metadata(&cwd) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => {
                return refuse(refusal_text(&format!(
                    "the working directory {} is not a directory",
                    cwd.display()
                )));
            }
            Err(error) => {
                return refuse(refusal_text(&format!(
                    "the working directory {} cannot be used: {error}",
                    cwd.display()
                )));
            }
        }

        // Everything below is decided twice, once for each path, and the two
        // halves have to agree on three things: the argv that runs, the
        // environment it runs with, and the line the window draws. They are
        // built together here so that they cannot be made to disagree.
        //
        // For an elevated request the environment splits in two. `run0` is
        // spawned with a forced locale so that hatch can read its
        // diagnostics; the command receives the constructed environment plus
        // hatch's pager defaults, passed explicitly as `--setenv`. The window
        // resolves variables against the *command's* environment, because
        // that is the one the command will actually have — resolving against
        // the spawner's would put a value on screen that the command never
        // sees. See `crate::exec::elevate::Run0::spawner_env`.
        let (argv, spawn_env, line, caveat) = if params.root {
            let elevated = match self.elevation.argv(&params.command, &env) {
                Ok(elevated) => elevated,
                // Nothing was rendered and nobody was asked: this build
                // cannot elevate here at all, which is a fact about the
                // machine rather than a decision anybody made.
                Err(unavailable) => return refuse(refusal_text(&unavailable.to_string())),
            };
            (
                elevated.as_slice().to_vec(),
                self.elevation.spawner_env(&env),
                // The whole line, `run0` and every `--setenv` included. The
                // reader is approving a root command, and the parts of a root
                // command line somebody would most want folded away are the
                // parts that decide what it does.
                elevated.display_line(),
                self.elevation.caveat(),
            )
        } else {
            (
                // A direct argv, never a string handed to another shell: the
                // rendering below is a rendering *of these three arguments*.
                vec!["bash".to_string(), "-c".to_string(), params.command.clone()],
                env.clone(),
                params.command.clone(),
                None,
            )
        };
        let render_env = match params.root {
            true => self.elevation.child_env(&env),
            false => env.clone(),
        };

        let spans = render_command(&line, &render_env);
        // Danger markers are display-only and land with the marker heuristics;
        // an empty list has never been a claim that a command is safe.
        let payload = Payload::command(&spans, Vec::new(), cwd.clone(), params.root, false)
            .with_caveat(caveat);
        Prepared::Ready(Job {
            detail: detail(&cwd),
            payload,
            work: Work::Run(RunPlan { argv, env: spawn_env, cwd, elevated: params.root }),
        })
    }

    fn prepare_swap(&self, params: SwapFileParams) -> Prepared {
        let path = PathBuf::from(&params.path);
        let content = params.content.into_bytes();
        let detail = |hash_before: Option<String>| {
            LogDetail::SwapFile(SwapDetail {
                path: params.path.clone(),
                root: params.root,
                hash_before,
                hash_after: None,
                mode: None,
                owner: None,
                bytes: None,
            })
        };
        let refuse = |message: String| {
            Prepared::Refused(Outcome::refusing(LogVerdict::Refused, None, detail(None), message))
        };

        // Before the denylist and before the filesystem, because it is the
        // one refusal here that is about the machine rather than about the
        // request: a build with no way to elevate cannot honour this whatever
        // the path turns out to be, and finding that out after the user has
        // read a diff spends their attention on a write that was never going
        // to happen.
        if params.root && let Err(unavailable) = self.elevation.available(&build_child_env(&self.config)) {
            return refuse(refusal_text(&unavailable.to_string()));
        }
        if let Err(refusal) = swap::validate(&path, &self.denylist) {
            return refuse(refusal_text(&refusal.to_string()));
        }

        let plan = match swap::plan(&path, &content, params.root) {
            Ok(plan) => plan,
            Err(error) => return refuse(refusal_text(&format!("{error:#}"))),
        };
        let before = match plan.kind {
            PlanKind::Create => Vec::new(),
            PlanKind::Replace => match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return Prepared::Refused(Outcome::refusing(
                        LogVerdict::Refused,
                        None,
                        detail(plan.hash_before.clone()),
                        refusal_text(&format!("{} cannot be read: {error}", path.display())),
                    ));
                }
            },
        };

        let rows = match diff_files(&before, &content, self.config.output_cap_bytes) {
            FileDiff::Rows(rows) => rows,
            // Binary or oversized: there is no diff to draw, and the window's
            // wire format has no way yet to say "here is a summary instead of
            // a comparison". Drawing an empty diff would tell the reader
            // nothing changes, which is the one thing it must never say, so
            // the request is refused until the summary form exists.
            FileDiff::Unrenderable { .. } => {
                return Prepared::Refused(Outcome::refusing(
                    LogVerdict::Refused,
                    None,
                    detail(plan.hash_before.clone()),
                    not_yet(
                        "show a diff of this file",
                        "One side of it is binary or larger than the display cap, and hatch will \
                         not ask anyone to approve a change it cannot draw. Send a smaller, \
                         textual replacement.",
                    ),
                ));
            }
        };

        Prepared::Ready(Job {
            detail: detail(plan.hash_before.clone()),
            payload: Payload::swap(path.clone(), plan.clone(), &rows),
            work: Work::Swap { path, content, plan, root: params.root },
        })
    }
}

// ---- step 5: what an approval authorises -----------------------------------

impl Daemon {
    /// Run an approved command to completion and describe what happened.
    ///
    /// The second half of the answer is what to do with the window, which only
    /// this function knows: it is the one that sent the outcome frame, and
    /// whether the window has a reason to stay depends on whether that frame
    /// was sent at all and on whether anybody asked to watch.
    async fn run_it(
        &self,
        run: &RunPlan,
        stream: bool,
        session: &PromptSession,
        detail: &mut LogDetail,
    ) -> (LogVerdict, CallToolResult, Windup) {
        let RunPlan { argv, env, cwd, elevated } = run;
        let elevated = *elevated;
        // The live view is a display preference and nothing else: execution is
        // identical either way, so the only difference is whether a sink is
        // wired at all.
        let (chunks, pump) = if stream {
            let (tx, rx) = mpsc::channel(OUTPUT_QUEUE);
            // A task of its own. The task awaiting `run` must not be the one
            // forwarding output, or a window that stops reading stalls the
            // command it is watching.
            (Some(tx), Some(tokio::spawn(pump_output(rx, session.outbox()))))
        } else {
            (None, None)
        };

        // Immediately before the spawn, because that is when the dialog
        // appears and there is nothing between the two. The window has its
        // verdict and has shrunk to a running indicator; without this it
        // would say the operation is running while a password dialog it
        // cannot see sits on top of it, unexplained.
        if elevated {
            session.outbox().elevating().await;
        }

        let started = std::time::Instant::now();
        let ran = exec::run(
            argv,
            env,
            cwd,
            RunOpts {
                timeout: Some(Duration::from_secs(self.config.exec_timeout_secs)),
                cancel: session.kill_requested(),
                cap_bytes: self.config.output_cap_bytes,
                chunks,
            },
        )
        .await;
        let elapsed = started.elapsed();
        if let Some(pump) = pump {
            let _ = pump.await;
        }

        let output = match ran {
            Ok(output) => output,
            // Nothing was executed. The user approved and hatch could not
            // carry it out, which is neither an approval that happened nor a
            // decision anybody made, so the agent is told plainly and may
            // retry without wondering what already ran.
            Err(error) => {
                // No `Finished` frame: the wire can only say "exited" or
                // "was signalled", and both would be a plausible-looking lie
                // about a command that never started. The window is closed
                // instead, and the agent is told the truth.
                return (
                    // The elevation program failing to start is an elevation
                    // failure and nothing else: nothing was elevated, so
                    // nothing ran, and the log has a verdict that says so.
                    match elevated {
                        true => LogVerdict::ElevationFailed,
                        false => LogVerdict::Approve,
                    },
                    CallToolResult::error(vec![ContentBlock::text(format!(
                        "the user approved this, but hatch could not start it, so nothing ran: \
                         {error}"
                    ))]),
                    // No outcome frame means a window still drawing "it is
                    // running". Nothing will ever tell it otherwise, so it is
                    // closed here rather than handed to a reader who would be
                    // watching a command that never started.
                    Windup::Close,
                );
            }
        };

        // What the run means. For an unelevated command that is the exit
        // status and nothing else; for an elevated one the status may not be
        // the command's at all, so it is read through the elevation that
        // produced it. `None` here is "no interpretation needed", not "it
        // worked".
        let root = elevated.then(|| self.read_root(&output, env));

        if let LogDetail::RunCommand(run) = detail {
            // The exit code is recorded only when it is the command's. An
            // elevated run that was refused ends with a status too — the same
            // 1 a failing command produces — and writing that number under
            // `exit_code` would put a command's result in the log for a
            // command that never ran.
            run.exit_code = match &root {
                Some(RootOutcome::Ran { exit }) => *exit,
                Some(_) => None,
                None => output.exit_code,
            };
            run.duration_ms = Some(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX));
            run.killed_by_user = Some(output.killed_by_user);
            run.timed_out = Some(output.timed_out);
        }
        let (verdict, result, frame) = match root {
            // Unelevated, or elevated and the command demonstrably ran: the
            // status is the command's and is reported as it always was.
            None | Some(RootOutcome::Ran { .. }) => (
                LogVerdict::Approve,
                CallToolResult::success(vec![ContentBlock::text(describe_run(&output, elapsed))]),
                finished_frame(&output),
            ),
            Some(outcome) => {
                let (verdict, message, frame) = elevation_ending(&outcome);
                // What goes with the message depends on what the outcome
                // claims, and the difference is the whole point of the three
                // being separate.
                //
                // `Denied` and `Failed` say **nothing ran**. There is no
                // exit code, no stdout and no stderr belonging to a command
                // that never started, and printing `describe_run`'s "exit
                // code: 1 / stdout: (empty)" underneath them would hand the
                // agent the one number this module exists to keep it away
                // from — the status a refusal and a failing command share.
                // Only the elevation program's own first line goes with it.
                //
                // `Unclear` says hatch does not know, and there the captured
                // output is the evidence: it is what anybody deciding whether
                // the command ran would look at, and withholding it would
                // leave the question unanswerable as well as unanswered.
                let text = match &outcome {
                    RootOutcome::Unclear { .. } => {
                        format!("{message}\n\n{}", describe_run(&output, elapsed))
                    }
                    _ => match first_line(&output.stderr) {
                        "" => message,
                        line => format!("{message}\n\n{line}"),
                    },
                };
                (verdict, CallToolResult::error(vec![ContentBlock::text(text)]), Some(frame))
            }
        };
        // A streamed run's window stays: the reader ticked a box asking to
        // watch this command, and for anything short of a slow one the whole
        // run is over before they have read a line. Only when the outcome
        // actually reached the window, though — a window that was not told the
        // command ended has no reason to close itself, and handing that one
        // over would be leaving it for the reader to explain.
        let windup = match frame {
            Some(frame) => {
                let told = session.outbox().finished(frame).await;
                match told && stream {
                    true => Windup::Detach,
                    false => Windup::Close,
                }
            }
            None => Windup::Close,
        };
        (verdict, result, windup)
    }

    /// What an elevated run that has finished actually means.
    ///
    /// A wrapper around [`Elevation::classify`] holding the one thing that
    /// function cannot see: whether hatch ended the run itself.
    ///
    /// `classify` is a pure function of how the process ended, and a process
    /// hatch killed ended with a signal and an empty standard error — which
    /// reads exactly like a command that ran and was killed. On this path it
    /// is not: the password dialog lives inside `run0`'s lifetime, so a run
    /// killed at the execution deadline may be a command hatch stopped, or
    /// may be a dialog nobody ever answered with nothing behind it at all.
    /// hatch has no way to tell those apart — nothing reports that a password
    /// was typed — so it says so, and the captured output is returned
    /// alongside for whoever can tell.
    ///
    /// This is deliberately not [`RootOutcome::Denied`]. A dialog nobody
    /// answered is not a person refusing: the agent must be able to
    /// distinguish an absent user from a refusing one here for the same
    /// reason the approval timeout is distinct from a denial.
    ///
    /// One thing this does not know and nothing in hatch currently does:
    /// `run0` runs the command as a transient systemd unit rather than as a
    /// child in its own process group, so hatch's kill may end the client
    /// that was watching and leave the unit running. That is one more reason
    /// the answer here is "unclear" rather than "killed", and it wants
    /// measuring.
    fn read_root(&self, output: &Output, spawned_with: &Env) -> RootOutcome {
        if output.timed_out || output.killed_by_user {
            let how = match output.timed_out {
                true => format!(
                    "hatch ended it at the {}s execution deadline",
                    self.config.exec_timeout_secs
                ),
                false => "the user pressed Kill".to_string(),
            };
            return RootOutcome::Unclear {
                exit: output.exit_code,
                message: format!(
                    "{how}, and the password dialog sits inside the elevated run, so hatch \
                     cannot tell a command it stopped from a dialog nobody answered"
                ),
            };
        }
        self.elevation.classify(output.exit_code, &output.stderr, spawned_with)
    }

    /// Apply an approved file replacement and describe what happened.
    async fn swap_it(
        &self,
        path: &Path,
        content: &[u8],
        plan: &SwapPlan,
        root: bool,
        session: &PromptSession,
        detail: &mut LogDetail,
    ) -> (LogVerdict, CallToolResult, Windup) {
        if root {
            return self.swap_as_root(path, content, plan, session, detail).await;
        }
        // Re-validated and re-hashed inside `apply`, which is what makes every
        // error here a guarantee that the file on disk was not touched.
        let applied = swap::apply(path, content, plan, &self.denylist);
        let landed = applied.is_ok();

        if landed {
            record_landing(detail, content, plan);
        }

        // The window closes on this frame. A swap has no process and so no
        // exit code of its own; zero for "it landed" and one for "it did not"
        // is the whole of what the wire can carry today, and it is the same
        // fact the tool result states.
        let _ = session
            .outbox()
            .finished(protocol::Outcome::Exit { code: i32::from(!landed) })
            .await;

        let result = match applied {
            Ok(()) => CallToolResult::success(vec![ContentBlock::text(format!(
                "wrote {}: {} bytes, mode {:04o}, owner {}:{}",
                path.display(),
                content.len(),
                plan.landing_mode,
                plan.landing_owner,
                plan.landing_group,
            ))]),
            Err(error) => CallToolResult::error(vec![ContentBlock::text(describe_apply(&error))]),
        };
        // A swap writes a file and says nothing. There is no output to hold up
        // and no stream checkbox to have ticked, so its window closes on the
        // outcome as every window used to.
        (LogVerdict::Approve, result, Windup::Close)
    }

    /// Apply an approved file replacement as root: stage the bytes, then let
    /// `install` land them.
    ///
    /// The shape is deliberately the same as the unelevated path's and the
    /// differences are all in one direction. The checks are the same checks
    /// in the same order — [`swap::stage_root`] runs them — and what changes
    /// is only who does the writing and how long the gap between the last
    /// check and the write is. See that function for where the residual
    /// window is and why it is wider here.
    async fn swap_as_root(
        &self,
        path: &Path,
        content: &[u8],
        plan: &SwapPlan,
        session: &PromptSession,
        detail: &mut LogDetail,
    ) -> (LogVerdict, CallToolResult, Windup) {
        let env = build_child_env(&self.config);

        // Re-check, then stage. Nothing is written anywhere until both checks
        // have passed, so a refusal here leaves the target untouched and
        // leaves no approved bytes on disk either.
        let staged = match swap::stage_root(path, content, plan, &self.denylist, &self.stage_dir) {
            Ok(staged) => staged,
            Err(error) => {
                let _ = session
                    .outbox()
                    .finished(protocol::Outcome::Exit { code: 1 })
                    .await;
                return (
                    LogVerdict::Approve,
                    CallToolResult::error(vec![ContentBlock::text(describe_apply(&error))]),
                    Windup::Close,
                );
            }
        };
        // Destructured, not consumed: `staged.staged` is the drop guard that
        // removes the approved bytes, and it has to outlive the command that
        // reads them. Holding it in a binding until the end of this function
        // is what makes "removed on every exit path" true without a cleanup
        // call on each of them.
        let RootWrite { staged, argv } = staged;

        let elevated = match self.elevation.elevate(argv, &env) {
            Ok(elevated) => elevated,
            Err(unavailable) => {
                return self
                    .elevation_ended(session, &RootOutcome::from(unavailable), "")
                    .await;
            }
        };

        // After the re-check, not before it. A swap that is about to be
        // refused for drift asks for no password at all, and a window that
        // had already been told to expect one would be describing a dialog
        // that never appears.
        session.outbox().elevating().await;

        let ran = exec::run(
            elevated.as_slice(),
            // The spawner's environment, not the command's. `install` is not
            // the approved command — it is hatch's own way of landing bytes a
            // human approved — but `run0` is still the process whose
            // diagnostics decide what this outcome means, so it gets the
            // forced locale for the same reason a root `run_command` does.
            &self.elevation.spawner_env(&env),
            // `/` because every path in the argv is absolute and nothing here
            // resolves a relative one. The request named a file, not a
            // working directory, so there is none to honour.
            Path::new("/"),
            RunOpts {
                timeout: Some(Duration::from_secs(self.config.exec_timeout_secs)),
                cancel: session.kill_requested(),
                cap_bytes: self.config.output_cap_bytes,
                chunks: None,
            },
        )
        .await;

        let output = match ran {
            Ok(output) => output,
            Err(error) => {
                return self
                    .elevation_ended(
                        session,
                        &RootOutcome::Failed {
                            message: format!(
                                "hatch could not start {}, so nothing was written: {error}",
                                self.elevation.mechanism()
                            ),
                        },
                        "",
                    )
                    .await;
            }
        };

        // The staged bytes have been read by now if they were ever going to
        // be. Dropped here rather than at the end of the function so that the
        // approved content is gone before anything is reported about it.
        drop(staged);

        match self.read_root(&output, &self.elevation.spawner_env(&env)) {
            RootOutcome::Ran { exit: Some(0) } => {
                // `install` said it did the work. The unelevated path proves
                // the file is what the window described *before* writing, by
                // examining the descriptor it is about to rename; this path
                // cannot, because the writing was done under a privilege
                // hatch does not have. So it looks afterwards. That cannot
                // refuse anything, and it is not there to: it is there so
                // that hatch does not report "mode 0640, owner alice" for a
                // file that came out some other way.
                let landed = swap::landed_as_approved(path, plan);
                let described = format!(
                    "{}: {} bytes, mode {:04o}, owner {}:{}",
                    path.display(),
                    content.len(),
                    plan.landing_mode,
                    plan.landing_owner,
                    plan.landing_group,
                );
                if let swap::Landed::Different { found } = &landed {
                    // The bytes went somewhere, and not to a file matching
                    // what anybody approved. Reported as an error even though
                    // the write happened, because the agent's next move —
                    // and the user's — depends on knowing that the thing on
                    // disk is not the thing on the screen.
                    let _ = session
                        .outbox()
                        .finished(protocol::Outcome::Exit { code: 1 })
                        .await;
                    return (
                        LogVerdict::Approve,
                        CallToolResult::error(vec![ContentBlock::text(format!(
                            "the write happened, but what is on disk is not what was approved. \
                             The window said {described}, and {} is now {found}. Something \
                             changed the target between the check and the write, or the owner \
                             the window named resolved to a different one. Look at the file \
                             before doing anything else.",
                            path.display(),
                        ))]),
                        Windup::Close,
                    );
                }
                record_landing(detail, content, plan);
                let _ = session
                    .outbox()
                    .finished(protocol::Outcome::Exit { code: 0 })
                    .await;
                (
                    LogVerdict::Approve,
                    CallToolResult::success(vec![ContentBlock::text(format!(
                        "wrote {described} as root{}",
                        confirmation_note(&landed)
                    ))]),
                    Windup::Close,
                )
            }
            // Elevation succeeded and `install` itself failed: a read-only
            // mount, an immutable attribute, an owner that does not resolve.
            // An ordinary failed write, reported as one — the user gave a
            // password and it was used, so this is not an elevation outcome.
            RootOutcome::Ran { exit } => {
                let _ = session
                    .outbox()
                    .finished(protocol::Outcome::Exit { code: exit.unwrap_or(1) })
                    .await;
                (
                    LogVerdict::Approve,
                    CallToolResult::error(vec![ContentBlock::text(format!(
                        "the user approved this and the elevation succeeded, but the write \
                         failed: {} exited {}. {} Read the file before asking again — unlike \
                         an unelevated write, a root write is not a rename, so a write that \
                         failed part way through can leave the file short rather than \
                         untouched.",
                        self.elevation.mechanism(),
                        match exit {
                            Some(code) => code.to_string(),
                            None => "on a signal".to_string(),
                        },
                        first_line(&output.stderr),
                    ))]),
                    Windup::Close,
                )
            }
            outcome => {
                let note = root_write_note(&outcome, path, &output.stderr);
                self.elevation_ended(session, &outcome, &note).await
            }
        }
    }

    /// Tell the window, the log and the agent the same thing about an
    /// elevation that did not end in a command running.
    ///
    /// One function for all three so that they cannot disagree, which on this
    /// path is the failure worth designing against: a window that closes
    /// saying "nothing ran" over a log line saying `approve` is worse than
    /// either being wrong on its own.
    async fn elevation_ended(
        &self,
        session: &PromptSession,
        outcome: &RootOutcome,
        tail: &str,
    ) -> (LogVerdict, CallToolResult, Windup) {
        let (verdict, message, frame) = elevation_ending(outcome);
        let _ = session.outbox().finished(frame).await;
        let text = match tail.trim().is_empty() {
            true => message,
            false => format!("{message}\n\n{}", tail.trim()),
        };
        (verdict, CallToolResult::error(vec![ContentBlock::text(text)]), Windup::Close)
    }
}

/// Fill in the half of a swap record that only a completed write knows.
///
/// Shared by the two apply paths rather than written twice, because the two
/// have to record the same facts about the same plan: a root write whose log
/// line said something different from an unelevated one would make the audit
/// log's own answer to "what landed here" depend on how it got there.
fn record_landing(detail: &mut LogDetail, content: &[u8], plan: &SwapPlan) {
    if let LogDetail::SwapFile(swap) = detail {
        swap.hash_after = Some(sha256_hex(content));
        swap.mode = Some(format!("{:04o}", plan.landing_mode));
        swap.owner = Some(format!("{}:{}", plan.landing_owner, plan.landing_group));
        swap.bytes = Some(content.len() as u64);
    }
}

/// What a successful root write adds about hatch's own confidence in it.
///
/// Empty when hatch looked and the file is what the window described, which
/// is the ordinary case and needs no sentence. The other answer is not folded
/// into that silence: hatch being unable to look is a smaller thing than a
/// mismatch and a larger one than nothing, and an agent told only "wrote it"
/// would have no way to know the difference.
///
/// [`swap::Landed::Different`] never reaches here — the caller returns an
/// error before it — so this function is about the two endings that are still
/// a successful write.
fn confirmation_note(landed: &swap::Landed) -> String {
    match landed {
        swap::Landed::Unchecked { why } => {
            format!("\nhatch could not re-examine the file to confirm this: {why}")
        }
        _ => String::new(),
    }
}

/// What goes with an elevation outcome that ended a root *write* rather than
/// a root command.
///
/// The difference is [`RootOutcome::Unclear`], and it matters because of what
/// `install` is. A root command hatch cannot account for leaves the machine
/// in an unknown state; a root *write* hatch cannot account for leaves a
/// named file in one, and `install` truncates its destination rather than
/// renaming onto it — so "hatch cannot say whether it ran" has to carry "and
/// that file may be neither version". Naming the path is the whole value: it
/// is the one thing the reader can act on.
///
/// Every other outcome means nothing was written, and the elevation
/// program's own first line is all there is to add.
fn root_write_note(outcome: &RootOutcome, path: &Path, stderr: &str) -> String {
    match outcome {
        RootOutcome::Unclear { .. } => format!(
            "{}\n\nRead {} before anything else: a root write is not a rename, so one that was \
             cut short can leave the file neither as it was nor as it was going to be.",
            first_line(stderr),
            path.display(),
        ),
        _ => first_line(stderr).to_string(),
    }
}

/// The first line of `text`, trimmed. What a diagnostic's useful part is, and
/// the only part of another program's standard error hatch puts in a sentence
/// of its own.
fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or("").trim()
}

/// The verdict, the sentence and the closing frame for an elevation that did
/// not end in a command running.
///
/// The three answers are produced together because they are three renderings
/// of one fact and the whole design here is that they agree. Each arm is a
/// different claim about the world and the difference between them is the
/// point:
///
/// * [`RootOutcome::Denied`] and [`RootOutcome::Failed`] both mean **nothing
///   ran**, which is a positive statement hatch can make and which tells the
///   agent it is safe to ask again.
/// * [`RootOutcome::Unclear`] means hatch does not know, which is not a
///   weaker version of either. It gets its own log verdict for that reason:
///   somebody auditing what ran as root has to be able to find the lines
///   where the answer is unknown, and neither `approve` nor
///   `elevation_failed` would bring them back.
fn elevation_ending(outcome: &RootOutcome) -> (LogVerdict, String, protocol::Outcome) {
    match outcome {
        RootOutcome::Denied | RootOutcome::Failed { .. } => {
            // `elevation_failure` answers `Some` for exactly these two and
            // `None` for the other two, so this is not a default: it is the
            // module that owns the distinction being asked for its own words.
            let message = outcome
                .elevation_failure()
                .unwrap_or_else(|| "the elevation did not happen".to_string());
            (
                LogVerdict::ElevationFailed,
                format!(
                    "approved, but root elevation failed or was cancelled: {message}. This is \
                     not a refusal by the user — they approved this in hatch's window, and the \
                     system then asked for a password separately. Nothing ran and nothing \
                     changed, so asking again is safe."
                ),
                protocol::Outcome::ElevationFailed { message },
            )
        }
        RootOutcome::Unclear { exit, message } => {
            let exit = match exit {
                Some(code) => format!("status {code}"),
                None => "a signal".to_string(),
            };
            (
                LogVerdict::ElevationUnclear,
                format!(
                    "approved, and hatch cannot say whether it ran: {message} (it ended with \
                     {exit}). Do not retry this — if it did run, a retry runs it a second \
                     time. Ask the user to check the machine and tell you what they find."
                ),
                protocol::Outcome::Unclear { message: message.clone() },
            )
        }
        // `Ran` is matched out by both callers before they get here, so
        // reaching this is hatch having lost track of an elevated run. Fail
        // towards saying so: a run reported as unclear costs a question, and
        // one reported as having succeeded costs the guarantee.
        RootOutcome::Ran { .. } => {
            let message =
                "hatch mishandled the result of an elevated run and cannot say whether it ran"
                    .to_string();
            (
                LogVerdict::ElevationUnclear,
                message.clone(),
                protocol::Outcome::Unclear { message },
            )
        }
    }
}

/// The tool error for an apply that did not happen.
///
/// Every [`ApplyError`] guarantees the file on disk is untouched, so every one
/// of them is safe to retry — and saying so is the difference between an agent
/// that re-reads the file and asks again and one that gives up.
fn describe_apply(error: &ApplyError) -> String {
    format!(
        "the user approved this, but the write did not happen: {error}. The file on disk is \
         exactly as it was, so reading it again and asking again is safe."
    )
}

/// How the window is told the command ended, or `None` when nothing true can
/// be said about it.
///
/// A child that neither exited nor was signalled is not a state Linux reports,
/// so this arm is unreachable — and it answers `None` rather than picking a
/// number, because the window closes on this frame and an invented exit code
/// is the last thing a person would see.
fn finished_frame(output: &Output) -> Option<protocol::Outcome> {
    match (output.exit_code, output.signal) {
        (Some(code), _) => Some(protocol::Outcome::Exit { code }),
        (None, Some(signal)) => Some(protocol::Outcome::Signal { signal }),
        (None, None) => None,
    }
}

/// What the agent reads about a command that ran.
///
/// The two streams are kept apart, because a diagnostic the command wrote to
/// stderr is not part of its answer, and every way the run was cut short is
/// named: a truncated result that reads as a complete one is the failure this
/// whole project is built to avoid.
fn describe_run(output: &Output, elapsed: std::time::Duration) -> String {
    let mut text = String::new();
    match output.exit_code {
        Some(code) => text.push_str(&format!("exit code: {code}\n")),
        None => match output.signal {
            Some(signal) => text.push_str(&format!("ended by signal {signal}\n")),
            None => text.push_str("ended without an exit code\n"),
        },
    }
    text.push_str(&format!("duration: {}ms\n", elapsed.as_millis()));
    if output.timed_out {
        text.push_str("timed out: hatch killed it at the execution deadline\n");
    }
    if output.killed_by_user {
        text.push_str("killed: the user pressed Kill while it ran\n");
    }
    for (name, body, truncated) in [
        ("stdout", &output.stdout, output.stdout_truncated),
        ("stderr", &output.stderr, output.stderr_truncated),
    ] {
        text.push_str(&format!("\n{name}:\n"));
        if body.is_empty() {
            text.push_str("(empty)\n");
        } else {
            text.push_str(body);
            if !body.ends_with('\n') {
                text.push('\n');
            }
        }
        if truncated {
            text.push_str(&format!("({name} was truncated at hatch's output cap)\n"));
        }
    }
    text
}

/// Lowercase hex SHA-256, the same form `sha256sum` prints.
fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(bytes).iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// What the user's own words are labelled with where they reach the agent
/// beside hatch's.
///
/// Trailing space included: it is a prefix, and the one place it is written
/// is the one place it can be got wrong.
const USER_NOTE_PREFIX: &str = "the user's note: ";

/// Put the user's note at the end of an approved operation's result, in their
/// name.
///
/// A result is hatch's own account of what happened — an exit status, the
/// bytes written, the mode the file was left at, the sentence saying hatch
/// could not re-examine it afterwards. The note is the one part of the answer
/// a *person* wrote. Run together they read as one voice, and both misreadings
/// are bad in the same way: the agent takes "do the other one first" for
/// hatch's instruction, or takes hatch's "only 3 of 40 lines changed" for
/// something the user said. So the prefix names whose words follow, and it is
/// put on the user's text and on nothing else.
///
/// It is a block of its own after a blank line rather than an interpolation
/// into a sentence, because the person's text ends the result: everything
/// after the prefix is theirs, which is the simplest boundary to state and
/// the only one that survives a note with a line break in it.
///
/// The note is relayed exactly as it was typed. It is a person's own message
/// to their own agent, and the escaping that the agent-written fields get
/// exists to stop *those* forging a line in hatch's log — a separate problem,
/// still solved separately: the log renders every string through
/// [`crate::audit`]'s `visible`, this note included.
///
/// An empty note adds nothing at all. A blank line with a label over nothing
/// is hatch reporting that somebody spoke when nobody did.
fn with_note(mut result: CallToolResult, note: &str) -> CallToolResult {
    if note.trim().is_empty() {
        return result;
    }
    result.content.push(ContentBlock::text(format!("\n\n{USER_NOTE_PREFIX}{note}")));
    result
}

// ---- the outcomes that are not an approval ---------------------------------

/// The tool error for a request whose client stopped waiting.
///
/// Both forms deny and both close the window; only the log tells them apart.
/// The agent very often never reads this at all — for a disconnect its
/// connection is gone by definition — so it is written for the case where it
/// does: a cancelled call whose client is still there.
fn abandoned(verdict: LogVerdict, detail: LogDetail) -> Outcome {
    let how = match verdict {
        LogVerdict::Cancelled => "your client cancelled this call",
        _ => "the connection carrying this call was lost",
    };
    Outcome::refusing(
        verdict,
        None,
        detail,
        format!(
            "{how} before anyone decided, so the approval window was closed and nothing ran. \
             Nobody refused this."
        ),
    )
}

/// The tool error for each verdict that is not an approval.
///
/// The note the user typed is returned verbatim in the text *and* stored on
/// the audit line, so the person's own words are what the agent acts on.
fn declined(verdict: Verdict, detail: LogDetail) -> Outcome {
    let (log_verdict, note, message) = match verdict {
        Verdict::Deny { note } => (
            LogVerdict::Deny,
            note.clone(),
            format!("denied by user: {note}"),
        ),
        Verdict::Revise { kind: ReviseKind::Explain, note } => (
            LogVerdict::Explain,
            note.clone(),
            format!("not run — the user asks you to explain: {note}"),
        ),
        Verdict::Revise { kind: ReviseKind::Simplify, note } => (
            LogVerdict::Simplify,
            note.clone(),
            format!("not run — the user asks for a more legible form: {note}"),
        ),
        Verdict::SelfRun { note } => (
            LogVerdict::SelfRun,
            note.clone(),
            format!(
                "not run — the user will run this themselves; ask them for the output rather \
                 than retrying: {note}"
            ),
        ),
        // The one refusal that refuses nothing. Everything above is about
        // the request; this is about the work, so the sentence has to say so
        // in the same breath as it says stop, or an agent reads "not run" as
        // a denial and does what a denial invites — ask for a better version
        // of the same thing.
        Verdict::StopAndSync { note } => (
            LogVerdict::StopAndSync,
            note.clone(),
            format!(
                "not run — the user has stopped to sync with you: nothing was judged about \
                 the request itself, so do not retry it or a variation of it and do not pick \
                 up something else instead; stop here and wait for them: {note}"
            ),
        ),
        // `decide` matches `Approve` out before calling this, so reaching here
        // would mean an approval was about to be reported as a refusal. Fail
        // closed and say so rather than silently denying an approved request.
        Verdict::Approve { .. } => (
            LogVerdict::Deny,
            String::new(),
            "hatch mishandled an approval and did not run it; nothing happened".to_string(),
        ),
    };
    Outcome::refusing(log_verdict, Some(note), detail, message)
}

/// Record whether the window died while the approved operation ran.
///
/// Not a verdict of its own: the verdict was already given, and what was lost
/// is the Kill button and the live view rather than the authorisation.
fn note_prompt_death(session: &PromptSession, detail: &mut LogDetail) {
    let died = session.window_gone().is_cancelled();
    if let LogDetail::RunCommand(run) = detail {
        run.prompt_died_after_approve = Some(died);
    }
}

// ---- the live view ---------------------------------------------------------

/// Forward an approved command's output to the window, decoding across chunk
/// boundaries.
///
/// The daemon decodes and the window draws. A chunk boundary falls wherever
/// the kernel split the output, very often mid-character, so a window that
/// decoded for itself would draw a replacement character for a character that
/// was never broken.
///
/// # Decoded, and nothing else — including for a root command
///
/// `run0 --pipe` gives the command a terminal, so a root command sees `isatty`
/// true where the same command run unelevated sees a pipe. It may therefore
/// colour its output, and a command that redraws a line with a carriage
/// return will do that too. Those escapes arrive here and are passed on.
///
/// Stripping them was considered and refused, and the reason is not that the
/// escapes are harmless. It is that this function feeds the *live view* and
/// nothing else: the same bytes are captured separately and go back to the
/// agent as the tool result. Cleaning one copy and not the other would leave
/// the window and the result disagreeing about what the command printed, and
/// a reader who compares the two would be right to trust neither. The
/// alternative — stripping both — is hatch editing a root command's output
/// before anybody sees it, which is the same class of thing as editing its
/// command line.
///
/// So the difference is disclosed instead of hidden:
/// [`crate::exec::elevate::Elevation::caveat`] says a root command may be
/// given a terminal and may colour its output, and the approval window draws
/// that sentence *before* the reader approves. The cost is a live view that
/// can show escape characters as glyphs for a colourful root command. That is
/// a legibility cost, paid by the reader who asked to watch, and it is the
/// cheaper of the two.
///
/// If this is ever revisited, the thing to change is both copies together and
/// the caveat with them — not this function on its own.
async fn pump_output(mut chunks: mpsc::Receiver<Chunk>, outbox: Outbox) {
    let mut tails: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
    while let Some(chunk) = chunks.recv().await {
        let slot = usize::from(chunk.stream == exec::Stream::Stderr);
        tails[slot].extend_from_slice(&chunk.bytes);
        if let Some(text) = take_decodable(&mut tails[slot]) {
            // A window that has gone is not an error after an approval and
            // must not stop the command, so the answer is ignored.
            outbox.output(chunk.stream, text).await;
        }
    }
    // Whatever is left is all there is ever going to be, so a partial
    // character at the end is drawn as the replacement it is.
    for (slot, stream) in [(0, exec::Stream::Stdout), (1, exec::Stream::Stderr)] {
        if !tails[slot].is_empty() {
            outbox.output(stream, String::from_utf8_lossy(&tails[slot]).into_owned()).await;
        }
    }
}

/// Split off the longest prefix of `buffer` that is text, leaving the rest.
///
/// A tail that is an *unfinished* character is kept for the next chunk; a
/// sequence that is simply wrong is taken now, because no later byte will ever
/// make it valid and holding it back would stall the view forever.
fn take_decodable(buffer: &mut Vec<u8>) -> Option<String> {
    let take = match std::str::from_utf8(buffer) {
        Ok(_) => buffer.len(),
        Err(error) => match error.error_len() {
            Some(bad) => error.valid_up_to() + bad,
            None => error.valid_up_to(),
        },
    };
    if take == 0 {
        return None;
    }
    let head: Vec<u8> = buffer.drain(..take).collect();
    Some(String::from_utf8_lossy(&head).into_owned())
}

#[tool_handler(
    name = "hatch",
    instructions = "hatch performs operations on the host machine, outside your sandbox, and \
                    only after a person has seen the operation rendered and approved it. Reach \
                    for these tools only when the work cannot be done in your own workspace: \
                    every call interrupts someone and can block for minutes."
)]
impl ServerHandler for Hatch {
    /// The generated `list_tools` would serve the macro's static
    /// descriptions. This serves the ones built from the running config,
    /// which is the only place the blocking bound is known.
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(self.described_tools()))
    }

    /// Speak only the protocol version this build actually implements.
    ///
    /// The default advertises every version the SDK knows the *name* of,
    /// including ones whose semantics it does not implement. A client that
    /// negotiates one of those gets answers in the older shape and rejects
    /// them — observed as `tools/list` failing validation on `ttlMs` and
    /// `cacheScope`, fields that belong to the newer discovery result and
    /// that nothing here produces.
    ///
    /// Claiming a version is a promise about the whole protocol, not about
    /// the parts that happen to overlap. Narrowing this to what is
    /// implemented makes a client negotiate down and work, instead of
    /// negotiating up and failing.
    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        std::borrow::Cow::Borrowed(&[ProtocolVersion::V_2025_11_25])
    }
}

/// SHA-256 of `bytes`.
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Compare two digests without letting the time taken depend on where they
/// differ.
///
/// The loop always runs all 32 bytes: no `==`, no early return, no `?`.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut differing = 0u8;
    for i in 0..32 {
        differing |= a[i] ^ b[i];
    }
    // `black_box` keeps the optimiser from noticing it could bail out of the
    // fold as soon as `differing` is non-zero.
    std::hint::black_box(differing) == 0
}

/// Extract the credential from an `Authorization: Bearer <token>` header.
///
/// Per RFC 7235 the scheme is case-insensitive. The scheme is not a secret,
/// so parsing it may short-circuit; only the credential comparison has to be
/// constant-time.
fn bearer_credential(value: &[u8]) -> Option<&[u8]> {
    let (scheme, credential) = value.split_at_checked("Bearer ".len())?;
    scheme.eq_ignore_ascii_case(b"Bearer ").then_some(credential)
}

/// Reject anything that does not carry the configured bearer token.
///
/// **What is compared, and why it is sound.** Comparing the presented
/// credential against the expected one byte by byte leaks its length through
/// the early exit, and leaks a prefix match through where the loop stops. So
/// both sides are hashed first and the fixed-width 32-byte digests are
/// compared instead: SHA-256 runs in time that depends on the input's length
/// but never on its content, the digests are always the same size whatever
/// the inputs were, and recovering a token from timing on the digest
/// comparison would mean finding a preimage. That is why `subtle` is not a
/// dependency here — hashing removes the length channel that a byte-wise
/// constant-time compare would still have to be paired with.
///
/// **401, not 403, and not a dropped connection.** 401 is what RFC 7235 says
/// for a request whose credentials are missing or wrong, and it is what makes
/// an MCP client report a configuration problem rather than a broken server.
/// 403 would mean the credentials were understood and *accepted*, and the
/// principal was merely not permitted — which tells a prober that the token
/// it guessed was real. Dropping the connection hides nothing (the port
/// already answered the TCP handshake) and costs the legitimate user their
/// only diagnostic. The missing-header case and the wrong-token case return
/// byte-identical responses, so the reply distinguishes "you sent nothing"
/// from "you sent the wrong thing" not at all.
///
/// **What the body says: as little as possible.** No product name, no token
/// length, no hint about the format. A user who has misconfigured their
/// client has `hatch token` to consult; an unauthenticated prober learns only
/// that something here wants a bearer token.
async fn require_bearer(
    State(expected): State<Arc<[u8; 32]>>,
    request: Request,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| bearer_credential(value.as_bytes()))
        // An empty credential is never right, whatever is configured. Without
        // this, a config carrying an empty token — which `load_or_create`
        // will not produce, but which `app` cannot refuse — would let
        // `Authorization: Bearer ` through and leave the daemon open to
        // everything on the machine.
        .filter(|credential| !credential.is_empty())
        .map(digest);

    match presented {
        Some(presented) if constant_time_eq(&presented, &expected) => next.run(request).await,
        _ => unauthorized(),
    }
}

/// The single response every unauthenticated request gets, whatever it asked
/// for and whatever it presented.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        "Unauthorized\n",
    )
        .into_response()
}

/// The `Host` values a request may carry.
///
/// This is DNS-rebinding protection. Without it, a page in the user's browser
/// could point a name it controls at `127.0.0.1` and have the *browser* — a
/// process that is allowed to reach loopback — make requests to the daemon.
/// It would still need the token, but it should not get as far as the
/// transport. Only names that genuinely mean "this machine" are accepted.
/// Entries without a port match any port, which is what lets a user change
/// `port` in the config without editing this list.
///
/// Reaching the server by any other name — a `/etc/hosts` alias, a second
/// loopback address such as `127.0.0.2`, the machine's own hostname — gets a
/// 403 from the transport, after the token check has already passed. The fix
/// is to use the URL exactly as `hatch token` prints it.
fn loopback_hosts() -> Vec<String> {
    vec!["127.0.0.1".to_string(), "localhost".to_string(), "::1".to_string()]
}

/// The whole HTTP surface: the MCP endpoint, behind the auth layer.
///
/// The layer goes on the router, not on the route, so it also covers the
/// fallback: an unauthenticated request to any path at all gets the same 401
/// and cannot be used to map what this daemon serves.
pub fn app(daemon: Arc<Daemon>) -> Router {
    let expected = Arc::new(digest(daemon.config().token.as_bytes()));

    // The registry is shared between the transport, which fills it in, and
    // every `Hatch` the factory builds, which read out of it through the
    // request extensions the transport plants. See `Hangup`.
    let calls = Arc::new(Calls::default());
    let service = StreamableHttpService::new(
        move || Ok(Hatch::new(Arc::clone(&daemon))),
        Arc::new(WatchedSessions::new(Arc::clone(&calls))),
        StreamableHttpServerConfig::default().with_allowed_hosts(loopback_hosts()),
    );

    Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn_with_state(expected, require_bearer))
}

/// Bind the loopback listener.
///
/// `Ipv4Addr::LOCALHOST`, never `0.0.0.0`: the daemon approves operations on
/// this machine on behalf of the person sitting at it, and there is no reason
/// for it to be reachable from the network. Port 0 asks the OS for a free
/// port, which is how the tests get one.
async fn bind(port: u16) -> anyhow::Result<TcpListener> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    TcpListener::bind(addr).await.with_context(|| {
        format!(
            "binding {addr}. Another hatch may already be running, or something else holds the \
             port; stop it, or set a different `port` in config.toml, which lives under \
             $XDG_CONFIG_HOME/hatch — by default ~/.config/hatch"
        )
    })
}

/// Delete whatever the last run left in `stage`.
///
/// Staged bytes are approved-but-unwritten file contents. A run that died
/// between approval and the write leaves them there, and nothing that comes
/// later has any way to tell them apart from its own. They are not a cache to
/// reuse: an operation the user approved yesterday is not one they approved
/// now.
///
/// A `$XDG_RUNTIME_DIR` stage is already empty here, because the login session
/// that held the crashed run took it away. This is what stands in for that on
/// the machines and the fallbacks where it is not.
fn sweep_stage(stage: &Path) -> anyhow::Result<()> {
    let entries = std::fs::read_dir(stage)
        .with_context(|| format!("reading {} to sweep it", stage.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("listing {}", stage.display()))?;
        let path = entry.path();
        let removed = if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        removed.with_context(|| format!("removing the stale staged file {}", path.display()))?;
    }
    Ok(())
}

/// Run the daemon (MCP server on loopback) for `hatch serve`.
///
/// Order: load the config, sweep the stage, **bind**, then print the
/// registration line, then serve.
///
/// Binding before printing is the part that matters. The registration line is
/// an instruction to the user — paste this and your client will reach the
/// daemon — and printing it before knowing the port is ours would make it a
/// false one: the commonest startup failure by far is a second `hatch serve`
/// against a port the first already holds, and there the user would be handed
/// a working-looking line for a daemon that is about to exit. Bound first, the
/// failure surfaces as one error naming the address and what to do about it,
/// and no registration line is printed at all.
pub fn run_serve() -> anyhow::Result<()> {
    let paths = Paths::from_env()?;
    paths.report();
    let config = Config::load_or_create(&paths)?;
    sweep_stage(&paths.stage_dir())?;

    // Located before the listener is bound, so a build that cannot find its
    // own executable fails at startup rather than on the first request, when
    // the failure would be a window that never opens.
    let prompter = Arc::new(ProcessPrompter::new()?);
    let port = config.port;
    let daemon = Arc::new(Daemon::new(&paths, config, prompter));

    let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;
    runtime.block_on(async move {
        let listener = bind(port).await?;
        config::print_client_line_for(daemon.config())?;
        axum::serve(listener, app(daemon)).await.context("serving MCP")
    })
}

#[cfg(test)]
mod tests {

    #[test]
    fn only_the_protocol_version_this_build_implements_is_offered() {
        // Advertising a version whose semantics are not implemented makes a
        // newer client negotiate up and then reject the answers: observed as
        // tools/list failing validation on ttlMs and cacheScope, fields of a
        // discovery result nothing here produces. Narrow beats optimistic.
        let offered = ServerHandler::supported_protocol_versions(&Hatch::new(bare_daemon(test_config())));
        assert_eq!(&*offered, &[ProtocolVersion::V_2025_11_25]);
        assert!(
            !offered.contains(&ProtocolVersion::V_2026_07_28),
            "a version is a promise about the whole protocol, not the overlapping parts"
        );
    }
    use super::*;
    use crate::config::Config;
    use std::sync::Arc;
    use std::time::Duration;

    /// Every test here waits on a socket, a task, a channel or a child. None
    /// may outlive this.
    const CEILING: Duration = Duration::from_secs(10);

    /// A hard ceiling on anything that waits for a decision that may never
    /// come. A test that can hang forever takes the whole run with it.
    async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(CEILING, fut)
            .await
            .expect("this waited on something that never happened")
    }

    /// A daemon for the tests that only need a server to answer, and never
    /// reach a tool: the hatch directory is therefore never touched, and the
    /// window is a program that exits at once.
    fn bare_daemon(config: Config) -> Arc<Daemon> {
        Arc::new(Daemon::new(
            &Paths::scratch(Path::new("/nonexistent-hatch-directory")),
            config,
            Arc::new(crate::prompter::ProcessPrompter::with_argv(["false"])),
        ))
    }

    /// Bind a server on an ephemeral loopback port and return its address.
    async fn spawn(config: Config) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = bind(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = app(bare_daemon(config));
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (addr, handle)
    }

    fn test_config() -> Config {
        Config { token: "test-token".to_string(), ..Config::default() }
    }

    /// A daemon over a real, temporary hatch directory, for the tests that do
    /// reach a tool but are not about the verdict.
    fn scratch_daemon() -> (tempfile::TempDir, Arc<Daemon>) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::scratch(dir.path());
        Config::load_or_create(&paths).unwrap();
        let daemon = Arc::new(Daemon::new(
            &paths,
            test_config(),
            Arc::new(crate::prompter::ProcessPrompter::with_argv(["false"])),
        ));
        (dir, daemon)
    }

    #[tokio::test]
    async fn rejects_a_request_with_no_token() {
        tokio::time::timeout(CEILING, async {
            let (addr, task) = spawn(test_config()).await;
            let response = reqwest::Client::new()
                .post(format!("http://{addr}/mcp"))
                .body("{}")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 401);
            task.abort();
        })
        .await
        .expect("the server must answer well inside the ceiling");
    }

    #[tokio::test]
    async fn rejects_a_request_with_a_wrong_token() {
        tokio::time::timeout(CEILING, async {
            let (addr, task) = spawn(test_config()).await;
            let response = reqwest::Client::new()
                .post(format!("http://{addr}/mcp"))
                .header("Authorization", "Bearer wrong")
                .body("{}")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 401);
            task.abort();
        })
        .await
        .expect("the server must answer well inside the ceiling");
    }

    #[tokio::test]
    async fn binds_only_to_loopback() {
        tokio::time::timeout(CEILING, async {
            let listener = bind(0).await.unwrap();
            let addr = listener.local_addr().unwrap();
            assert!(addr.ip().is_loopback(), "bound to {addr}, which is reachable off-box");
        })
        .await
        .expect("binding must not hang");
    }

    #[test]
    fn tool_descriptions_state_the_full_blocking_bound() {
        let config = Config::default();
        let text = tool_descriptions(&config).for_tool("run_command").unwrap().to_string();
        assert!(text.contains("900"), "the blocking bound must be the full one: {text}");
        assert_eq!(config.client_timeout_secs(), 900, "the bound the description quotes");
        assert!(text.contains("only when"), "the description must narrow when to reach for it");
    }

    // --- the auth layer -------------------------------------------------

    #[tokio::test]
    async fn accepts_the_configured_token() {
        tokio::time::timeout(CEILING, async {
            let (addr, task) = spawn(test_config()).await;
            let response = reqwest::Client::new()
                .post(format!("http://{addr}/mcp"))
                .header("Authorization", "Bearer test-token")
                .body("{}")
                .send()
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                401,
                "the configured token must get past the layer; the transport may then complain \
                 about the body, which is its business and not ours"
            );
            task.abort();
        })
        .await
        .expect("the server must answer well inside the ceiling");
    }

    #[tokio::test]
    async fn a_path_the_router_does_not_serve_is_also_behind_the_layer() {
        // The layer is on the router, not on the route: an unauthenticated
        // request must not be able to tell a served path from an unserved one
        // and map what this daemon exposes.
        tokio::time::timeout(CEILING, async {
            let (addr, task) = spawn(test_config()).await;
            let response =
                reqwest::Client::new().get(format!("http://{addr}/")).send().await.unwrap();
            assert_eq!(response.status(), 401);
            task.abort();
        })
        .await
        .expect("the server must answer well inside the ceiling");
    }

    #[tokio::test]
    async fn the_two_rejections_are_byte_identical() {
        tokio::time::timeout(CEILING, async {
            let (addr, task) = spawn(test_config()).await;
            let client = reqwest::Client::new();
            let url = format!("http://{addr}/mcp");

            let absent = client.post(&url).body("{}").send().await.unwrap();
            let wrong = client
                .post(&url)
                .header("Authorization", "Bearer wrong")
                .body("{}")
                .send()
                .await
                .unwrap();

            assert_eq!(absent.status(), wrong.status());
            assert_eq!(absent.headers(), wrong.headers());
            assert_eq!(
                absent.text().await.unwrap(),
                wrong.text().await.unwrap(),
                "the reply must not say which of the two went wrong"
            );
            task.abort();
        })
        .await
        .expect("the server must answer well inside the ceiling");
    }

    #[tokio::test]
    async fn a_prefix_of_the_token_is_not_enough() {
        tokio::time::timeout(CEILING, async {
            let (addr, task) = spawn(test_config()).await;
            let client = reqwest::Client::new();
            let url = format!("http://{addr}/mcp");
            let near_misses =
                ["Bearer test-toke", "Bearer test-tokenx", "Bearer  test-token", "test-token"];
            for near_miss in near_misses {
                let response = client
                    .post(&url)
                    .header("Authorization", near_miss)
                    .body("{}")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), 401, "{near_miss:?} must not authenticate");
            }
            task.abort();
        })
        .await
        .expect("the server must answer well inside the ceiling");
    }

    #[tokio::test]
    async fn an_empty_token_authenticates_nothing() {
        // The daemon never runs with one, but `app` cannot refuse a config,
        // and "no token configured" must not mean "no token needed".
        tokio::time::timeout(CEILING, async {
            let (addr, task) = spawn(Config { token: String::new(), ..Config::default() }).await;
            let client = reqwest::Client::new();
            let url = format!("http://{addr}/mcp");
            for header in ["Bearer ", "Bearer", ""] {
                let response = client
                    .post(&url)
                    .header("Authorization", header)
                    .body("{}")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), 401, "{header:?} must not authenticate");
            }
            task.abort();
        })
        .await
        .expect("the server must answer well inside the ceiling");
    }

    #[test]
    fn the_unauthorized_reply_names_the_scheme_and_nothing_else() {
        let response = unauthorized();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer",
            "RFC 7235 wants the scheme; a client with no token needs to know which kind"
        );
    }

    #[test]
    fn the_bearer_scheme_is_case_insensitive_but_the_credential_is_not() {
        assert_eq!(bearer_credential(b"Bearer abc"), Some(&b"abc"[..]));
        assert_eq!(bearer_credential(b"bearer abc"), Some(&b"abc"[..]));
        assert_eq!(bearer_credential(b"BEARER abc"), Some(&b"abc"[..]));
        assert_eq!(bearer_credential(b"Bearer "), Some(&b""[..]));
        assert_eq!(bearer_credential(b"Basic  abc"), None);
        assert_eq!(bearer_credential(b"Bearerabc"), None);
        assert_eq!(bearer_credential(b"Bear"), None, "a short header must not panic");
        assert_eq!(bearer_credential(b""), None);
    }

    #[test]
    fn constant_time_eq_still_answers_the_question() {
        // It is a comparison first and a timing property second; if it stops
        // being a correct comparison the timing does not matter.
        let a = digest(b"a");
        let b = digest(b"b");
        assert!(constant_time_eq(&a, &a));
        assert!(!constant_time_eq(&a, &b));

        let mut nearly = a;
        nearly[31] ^= 1;
        assert!(!constant_time_eq(&a, &nearly), "a difference in the last byte must be seen");
        let mut early = a;
        early[0] ^= 1;
        assert!(!constant_time_eq(&a, &early), "a difference in the first byte must be seen");
    }

    // --- the length cap -------------------------------------------------

    fn run_params(field: &str, value: String) -> RunCommandParams {
        let mut p = RunCommandParams {
            title: "t".to_string(),
            command: "c".to_string(),
            reason: "r".to_string(),
            root: false,
            cwd: None,
            interactive: false,
        };
        match field {
            "title" => p.title = value,
            "command" => p.command = value,
            "reason" => p.reason = value,
            "cwd" => p.cwd = Some(value),
            other => panic!("no such field {other}"),
        }
        p
    }

    fn swap_params(field: &str, value: String) -> SwapFileParams {
        let mut p = SwapFileParams {
            title: "t".to_string(),
            path: "/p".to_string(),
            content: "c".to_string(),
            reason: "r".to_string(),
            root: false,
        };
        match field {
            "title" => p.title = value,
            "path" => p.path = value,
            "content" => p.content = value,
            "reason" => p.reason = value,
            other => panic!("no such field {other}"),
        }
        p
    }

    #[test]
    fn every_capped_field_of_run_command_is_checked() {
        for (field, cap) in [
            ("title", MAX_FIELD_BYTES),
            ("command", MAX_COMMAND_BYTES),
            ("reason", MAX_FIELD_BYTES),
            ("cwd", MAX_FIELD_BYTES),
        ] {
            assert!(
                check_run_command(&run_params(field, "a".repeat(cap))).is_ok(),
                "exactly at the cap is allowed: {field}"
            );
            let refusal = check_run_command(&run_params(field, "a".repeat(cap + 1)))
                .expect_err(&format!("one byte over the cap must be refused: {field}"));
            assert!(refusal.contains(field), "the refusal must name the field: {refusal}");
        }
    }

    #[test]
    fn every_capped_field_of_swap_file_is_checked() {
        for (field, cap) in [
            ("title", MAX_FIELD_BYTES),
            ("path", MAX_FIELD_BYTES),
            ("content", MAX_CONTENT_BYTES),
            ("reason", MAX_FIELD_BYTES),
        ] {
            assert!(
                check_swap_file(&swap_params(field, "a".repeat(cap))).is_ok(),
                "exactly at the cap is allowed: {field}"
            );
            let refusal = check_swap_file(&swap_params(field, "a".repeat(cap + 1)))
                .expect_err(&format!("one byte over the cap must be refused: {field}"));
            assert!(refusal.contains(field), "the refusal must name the field: {refusal}");
        }
    }

    #[test]
    fn the_caps_leave_room_for_ordinary_work() {
        // A cap that refuses ordinary work is not a cap, it is an outage. The
        // sizes are part of the tool contract, so they are pinned here rather
        // than left to drift.
        assert!(
            check_run_command(&run_params("command", "a".repeat(8 * 1024))).is_ok(),
            "an 8 KB inline script is ordinary work"
        );
        assert!(
            check_run_command(&run_params("title", "a".repeat(2 * 1024))).is_ok(),
            "a long but sane title is ordinary work"
        );
        assert!(
            check_swap_file(&swap_params("content", "a".repeat(100 * 1024))).is_ok(),
            "a 100 KB config file is ordinary work"
        );
        assert!(
            check_swap_file(&swap_params("path", "a".repeat(2 * 1024))).is_ok(),
            "a deep path is ordinary work"
        );
    }

    #[test]
    fn the_cap_counts_bytes_not_characters() {
        // Four bytes each, one character each. A cap that counted characters
        // would let four times as much through.
        let astral = "\u{1f600}".repeat(MAX_FIELD_BYTES / 4);
        assert_eq!(astral.chars().count(), MAX_FIELD_BYTES / 4);
        assert!(check_run_command(&run_params("title", astral.clone())).is_ok());
        let one_over = format!("{astral}\u{1f600}");
        assert!(check_run_command(&run_params("title", one_over)).is_err());
    }

    #[test]
    fn an_over_cap_call_is_told_it_was_not_a_decision() {
        let refusal = within_cap("command", &"a".repeat(MAX_COMMAND_BYTES + 1), MAX_COMMAND_BYTES)
            .expect_err("over the cap");
        // The agent has to be able to tell this apart from a human saying no,
        // or it will report a denial nobody made.
        assert!(refusal.contains("nothing ran"), "{refusal}");
        assert!(refusal.contains("nobody was asked"), "{refusal}");
        assert!(refusal.contains("not a decision by the user"), "{refusal}");
        assert!(refusal.contains(&MAX_COMMAND_BYTES.to_string()), "{refusal}");
    }

    #[test]
    fn nothing_is_truncated() {
        // The cap refuses; it never shortens. A command the user approved must
        // be the command the agent sent.
        let long = "a".repeat(MAX_COMMAND_BYTES + 1);
        let params = run_params("command", long.clone());
        assert!(check_run_command(&params).is_err());
        assert_eq!(params.command, long, "the input must be left exactly as it came in");
    }

    #[tokio::test]
    async fn the_cap_refuses_before_the_tool_body_runs() {
        let (_dir, daemon) = scratch_daemon();
        let over = run_params("command", "a".repeat(MAX_COMMAND_BYTES + 1));
        let result = within(daemon.run_command(over, Caller::quiet())).await;
        assert_eq!(result.is_error, Some(true));
        let text = result_text(&result);
        assert!(text.contains("`command` is"), "the cap must answer, not the body: {text}");
    }

    #[tokio::test]
    async fn a_call_within_the_cap_reaches_the_body() {
        // The window here is a program that exits at once, so reaching the
        // body reads as a dead prompt — which is the point: it is not the
        // cap's refusal.
        let (_dir, daemon) = scratch_daemon();
        let at_the_cap = run_params("command", "a".repeat(MAX_COMMAND_BYTES));
        let text = result_text(&within(daemon.run_command(at_the_cap, Caller::quiet())).await);
        assert!(!text.contains("byte limit"), "the cap must not answer: {text}");

        let at_the_cap = swap_params("content", "a".repeat(MAX_CONTENT_BYTES));
        let text = result_text(&within(daemon.swap_file(at_the_cap, Caller::quiet())).await);
        assert!(!text.contains("byte limit"), "the cap must not answer: {text}");
    }

    fn result_text(result: &CallToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(|block| block.as_text().map(|t| t.text.clone()))
            .collect::<Vec<_>>()
            .join("")
    }

    // --- the declared tools ---------------------------------------------

    #[test]
    fn declares_exactly_the_two_tools() {
        let names: Vec<String> = Hatch::new(bare_daemon(test_config()))
            .described_tools()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        assert_eq!(names, ["run_command", "swap_file"]);
    }

    #[test]
    fn every_tool_has_a_runtime_description() {
        let config = test_config();
        let descriptions = tool_descriptions(&config);
        for tool in Hatch::new(bare_daemon(config)).described_tools() {
            assert!(
                descriptions.for_tool(&tool.name).is_some(),
                "{} would ship the macro's placeholder",
                tool.name
            );
        }
    }

    #[test]
    fn the_listed_descriptions_are_the_runtime_ones() {
        let config = test_config();
        let descriptions = tool_descriptions(&config);
        for tool in Hatch::new(bare_daemon(config)).described_tools() {
            assert_eq!(
                tool.description.as_deref(),
                descriptions.for_tool(&tool.name),
                "{} kept a description that is not the runtime one",
                tool.name
            );
        }
    }

    #[test]
    fn each_tool_gets_its_own_description() {
        let descriptions = tool_descriptions(&Config::default());
        assert_ne!(descriptions.for_tool("run_command"), descriptions.for_tool("swap_file"));
        assert_eq!(descriptions.for_tool("nothing_of_the_sort"), None);
    }

    #[test]
    fn the_blocking_bound_follows_the_config() {
        // Guards against interpolating the approval timeout alone, which
        // understates the bound by more than three times.
        let config = Config { timeout_secs: 11, exec_timeout_secs: 700, ..Config::default() };
        for name in ["run_command", "swap_file"] {
            let text = tool_descriptions(&config).for_tool(name).unwrap().to_string();
            assert!(text.contains("711"), "{name} must state the full bound: {text}");
        }
        let text = tool_descriptions(&config).for_tool("run_command").unwrap().to_string();
        assert!(text.contains("11s"), "the approval half must be named too: {text}");
        assert!(text.contains("700s"), "the execution half must be named too: {text}");
    }

    #[test]
    fn both_descriptions_narrow_when_to_reach_for_the_tool() {
        let descriptions = tool_descriptions(&Config::default());
        for name in ["run_command", "swap_file"] {
            let text = descriptions.for_tool(name).unwrap();
            assert!(text.contains("only when"), "{name} must say when not to: {text}");
            assert!(text.contains("workspace"), "{name} must point at the workspace: {text}");
        }
        assert!(
            descriptions.for_tool("run_command").unwrap().contains("Batch"),
            "run_command must ask for one command rather than a chain of calls"
        );
    }

    // --- the tools over the wire -----------------------------------------

    /// One JSON-RPC POST to `/mcp`, authenticated, returning the response
    /// headers and the decoded result.
    ///
    /// The transport answers in SSE by default, so the body is a stream of
    /// `data:` lines rather than a bare JSON object.
    async fn rpc(
        addr: std::net::SocketAddr,
        session: Option<&str>,
        body: serde_json::Value,
    ) -> (reqwest::header::HeaderMap, Option<serde_json::Value>) {
        let mut request = reqwest::Client::new()
            .post(format!("http://{addr}/mcp"))
            .header("Authorization", "Bearer test-token")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .body(body.to_string());
        if let Some(id) = session {
            request = request.header("Mcp-Session-Id", id);
        }
        let response = request.send().await.unwrap();
        assert!(response.status().is_success(), "{:?} for {body}", response.status());
        let headers = response.headers().clone();
        let text = response.text().await.unwrap();
        // The stream opens with a priming event carrying an empty `data:`,
        // so take the first one that actually holds a message.
        let decoded = text
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim)
            .find(|payload| payload.starts_with('{'))
            .or(if text.starts_with('{') { Some(text.as_str()) } else { None })
            .map(|json| serde_json::from_str(json).unwrap());
        (headers, decoded)
    }

    #[tokio::test]
    async fn an_authenticated_client_is_served_the_runtime_descriptions() {
        // The whole path a real client walks: the token gets it in, the
        // handshake completes, and `tools/list` answers with the descriptions
        // built from the running config rather than the macro's placeholders.
        tokio::time::timeout(CEILING, async {
            let (addr, task) = spawn(test_config()).await;

            let (headers, initialized) = rpc(
                addr,
                None,
                serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": { "name": "test", "version": "0" },
                    },
                }),
            )
            .await;
            let initialized = initialized.expect("initialize must answer");
            assert_eq!(initialized["result"]["serverInfo"]["name"], "hatch");
            let session = headers
                .get("mcp-session-id")
                .map(|v| v.to_str().unwrap().to_string());

            rpc(
                addr,
                session.as_deref(),
                serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            )
            .await;

            let (_, listed) = rpc(
                addr,
                session.as_deref(),
                serde_json::json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
            )
            .await;
            let tools = listed.expect("tools/list must answer")["result"]["tools"]
                .as_array()
                .expect("a tool list")
                .clone();

            let names: Vec<&str> =
                tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
            assert_eq!(names, ["run_command", "swap_file"], "both tools must be offered");
            for tool in &tools {
                let description = tool["description"].as_str().unwrap();
                assert!(
                    description.contains("900"),
                    "{} shipped a description without the blocking bound: {description}",
                    tool["name"]
                );
            }

            task.abort();
        })
        .await
        .expect("the handshake must finish well inside the ceiling");
    }

    // --- startup ---------------------------------------------------------

    #[test]
    fn only_loopback_names_are_accepted_as_hosts() {
        let hosts = loopback_hosts();
        for name in ["127.0.0.1", "localhost", "::1"] {
            assert!(hosts.iter().any(|h| h == name), "{name} must be reachable");
        }
        assert!(
            !hosts.iter().any(|h| h == "0.0.0.0" || h.is_empty()),
            "an entry that means \"anything\" would undo the protection"
        );
    }

    #[test]
    fn a_write_hatch_could_not_confirm_says_so_rather_than_reading_as_confirmed() {
        // The ordinary ending adds nothing: hatch looked, it matched.
        assert_eq!(confirmation_note(&crate::swap::Landed::AsApproved), "");
        // Not looking is a different answer from looking and agreeing, and
        // the agent is told which one it got. Folding this into silence would
        // make "wrote it" mean two different things.
        let note = confirmation_note(&crate::swap::Landed::Unchecked {
            why: "/etc/secret could not be examined afterwards: Permission denied".to_string(),
        });
        assert!(note.contains("could not re-examine"), "{note}");
        assert!(note.contains("Permission denied"), "{note}");
    }

    #[test]
    fn an_unaccountable_root_write_names_the_file_a_reader_has_to_look_at() {
        let path = Path::new("/etc/systemd/zram-generator.conf");
        let unclear = RootOutcome::Unclear {
            exit: None,
            message: "hatch ended it at the deadline".to_string(),
        };

        let note = root_write_note(&unclear, path, "");
        // `install` truncates rather than renaming, so an unaccountable root
        // write leaves a named file possibly neither version. Naming it is
        // the one thing the reader can act on.
        assert!(note.contains("zram-generator.conf"), "{note}");
        assert!(note.contains("not a rename"), "{note}");

        // Every other outcome means nothing was written, so there is no file
        // to send anybody to look at — only what the elevation said.
        let denied = root_write_note(&RootOutcome::Denied, path, "Access denied
rest");
        assert_eq!(denied, "Access denied");
        assert!(!denied.contains("zram-generator.conf"), "{denied}");
    }

    #[test]
    fn the_first_line_is_what_reaches_a_reader_from_another_programs_diagnostics() {
        // This decides which part of the elevation program's standard error
        // is quoted back to the agent and drawn in the window, so an empty
        // answer is a message that says a root operation failed and does not
        // say why.
        assert_eq!(
            first_line("Failed to start transient service unit: Access denied
more
"),
            "Failed to start transient service unit: Access denied"
        );
        assert_eq!(first_line("  padded  
second"), "padded");
        // Nothing to quote is an empty answer, which the callers test for
        // before they build a message around it.
        assert_eq!(first_line(""), "");
        assert_eq!(first_line("

later"), "");
    }

    #[test]
    fn only_an_elevated_operation_makes_the_ticker_mention_a_password() {
        let run = |elevated| {
            Work::Run(RunPlan {
                argv: Vec::new(),
                env: Env::new(),
                cwd: PathBuf::from("/"),
                elevated,
            })
        };
        let swap = |root| Work::Swap {
            path: PathBuf::from("/etc/hosts"),
            content: Vec::new(),
            plan: SwapPlan {
                kind: PlanKind::Create,
                landing_mode: 0o644,
                landing_owner: crate::swap::Principal::user(0),
                landing_group: crate::swap::Principal::group(0),
                hash_before: None,
                size_delta: 0,
            },
            root,
        };
        assert!(run(true).elevated());
        assert!(!run(false).elevated());
        assert!(swap(true).elevated());
        assert!(!swap(false).elevated());
    }

    #[test]
    fn the_elevated_phase_says_something_the_others_do_not() {
        // The ticker is what keeps a long wait alive: each notification
        // resets the client's idle timer, and the longest silence on a root
        // request is the one where a password dialog is sitting unanswered.
        // So the phase has to survive the round trip through the atomic, and
        // it has to say something an ordinary run does not.
        for phase in
            [Phase::Queued, Phase::AwaitingApproval, Phase::Executing, Phase::Elevating]
        {
            assert_eq!(Phase::of(phase as u8), phase, "{phase:?} did not survive the ticker");
        }
        let elevating = Phase::Elevating.message();
        assert!(elevating.contains("password"), "{elevating}");
        assert_ne!(elevating, Phase::Executing.message());
        // And it stays true for the whole elevated run, because hatch is
        // never told the password was typed: there is no moment at which it
        // could honestly change to "running".
        assert!(elevating.contains("running"), "{elevating}");
    }

    #[test]
    fn the_sweep_clears_what_a_crashed_run_left_staged() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::scratch(dir.path());
        Config::load_or_create(&paths).unwrap();
        let stage = paths.stage_dir();
        std::fs::write(stage.join("leftover"), b"approved yesterday, never written").unwrap();
        std::fs::create_dir(stage.join("nested")).unwrap();
        std::fs::write(stage.join("nested").join("deeper"), b"more of it").unwrap();

        sweep_stage(&stage).unwrap();

        assert_eq!(std::fs::read_dir(&stage).unwrap().count(), 0, "the stage must be empty");
        assert!(stage.is_dir(), "the sweep must leave the directory itself");
    }

    #[tokio::test]
    async fn binding_a_held_port_says_which_address_and_what_to_do() {
        tokio::time::timeout(CEILING, async {
            let held = bind(0).await.unwrap();
            let port = held.local_addr().unwrap().port();
            let error = bind(port).await.expect_err("the port is held");
            let text = format!("{error:#}");
            assert!(text.contains(&port.to_string()), "{text}");
            assert!(text.contains("config.toml"), "the user needs the way out: {text}");
        })
        .await
        .expect("binding must not hang");
    }

    // --- the request flow -------------------------------------------------

    /// The verdict mapping, the deadline, the two abandonments and the
    /// post-approval rule, driven against a scripted window.
    ///
    /// Behind the feature and not `cfg(test)` for the same reason
    /// `StubPrompter` is: the integration tests link the library compiled
    /// without `cfg(test)`.
    #[cfg(feature = "test-stub-prompter")]
    mod flow {
        use super::*;
        use crate::audit::LogVerdict;
        use crate::exec::elevate::Rehearsed;
        use crate::prompter::{ProcessPrompter, Reply, StubPrompter};
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        use crate::protocol::{Verdict, approved};

        /// One daemon over a temporary hatch directory, with a scripted
        /// window in front of it.
        struct Harness {
            /// The temporary root the three directories sit under, held so
            /// that they outlive the harness.
            dir: tempfile::TempDir,
            paths: Paths,
            daemon: Arc<Daemon>,
            prompter: Arc<StubPrompter>,
        }

        /// A config whose two clocks are short enough for a test to wait out
        /// and long enough that a working path never hits them.
        fn quick(paths: &Paths) -> Config {
            let mut config = Config::load_or_create(paths).unwrap();
            config.timeout_secs = 1;
            config.exec_timeout_secs = 8;
            // The default `cwd`. A directory that exists, and one this test
            // owns, so nothing depends on the machine's real home.
            std::fs::create_dir_all(paths.home()).unwrap();
            config.exec_env.insert("HOME".to_string(), paths.home().display().to_string());
            config
        }

        impl Harness {
            fn new(script: Vec<Reply>) -> Harness {
                let dir = tempfile::tempdir().unwrap();
                let paths = Paths::scratch(dir.path());
                let config = quick(&paths);
                let prompter = Arc::new(StubPrompter::new(script));
                let daemon =
                    Arc::new(Daemon::new(&paths, config, Arc::clone(&prompter) as Arc<_>));
                Harness { dir, paths, daemon, prompter }
            }

            /// Every audit record written so far, decoded.
            fn logged(&self) -> Vec<serde_json::Value> {
                let path = AuditLog::new(&self.paths.log_dir()).current_path();
                let text = std::fs::read_to_string(path).unwrap_or_default();
                text.lines().map(|line| serde_json::from_str(line).unwrap()).collect()
            }

            /// The one record this request produced. Exactly one: the count is
            /// asserted here so that every test which reads a verdict also
            /// proves the record was not written twice or not at all.
            fn only_record(&self) -> serde_json::Value {
                let records = self.logged();
                assert_eq!(records.len(), 1, "exactly one record per request: {records:?}");
                records.into_iter().next().unwrap()
            }

            fn verdict(&self) -> String {
                self.only_record()["verdict"].as_str().unwrap().to_string()
            }
        }

        fn run_of(command: &str) -> RunCommandParams {
            RunCommandParams {
                title: "a test".to_string(),
                command: command.to_string(),
                reason: "because a test asked".to_string(),
                root: false,
                cwd: None,
                interactive: false,
            }
        }

        fn approve() -> Reply {
            Reply::verdict(approved(false))
        }

        // --- verdict mapping ----------------------------------------------

        #[tokio::test]
        async fn every_non_approve_verdict_is_a_recoverable_tool_error() {
            for verdict in refusing_verdicts() {
                let (needle, logged) = expected_of(&verdict);
                let harness = Harness::new(vec![Reply::verdict(verdict.clone())]);
                let result = within(harness.daemon.run_command(run_of("true"), Caller::quiet()))
                    .await;

                // A recoverable tool error, never a protocol error: the flow's
                // return type is a `CallToolResult` and not a `Result`, so
                // `Err(ErrorData)` is unreachable by construction. What has to
                // be asserted is that it is marked as an error and carries the
                // note.
                assert_eq!(result.is_error, Some(true), "{verdict:?}");
                let text = result_text(&result);
                assert!(text.contains(needle), "{verdict:?} produced {text}");
                assert_eq!(harness.verdict(), logged.as_str(), "{verdict:?}");
                assert_eq!(
                    harness.only_record()["note"].as_str(),
                    Some(match &verdict {
                        Verdict::Deny { note }
                        | Verdict::Revise { note, .. }
                        | Verdict::SelfRun { note }
                        | Verdict::StopAndSync { note } => note.as_str(),
                        Verdict::Approve { .. } => unreachable!(),
                    }),
                    "the user's own words belong on the line"
                );
            }
        }

        #[tokio::test]
        async fn an_approval_relays_what_the_person_typed_to_both_tools() {
            // The window's field is called "Note to the agent", and an
            // approval was the one press that threw away what was in it.
            // Both tools, because the sentence the note lands after is
            // different in each and the landing must not be.
            let typed = "fine — but check the mount afterwards";
            let approve =
                || Reply::verdict(Verdict::Approve { stream: false, note: typed.to_string() });
            let tail = format!("{USER_NOTE_PREFIX}{typed}");

            let harness = Harness::new(vec![approve()]);
            let result =
                within(harness.daemon.run_command(run_of("true"), Caller::quiet())).await;
            let text = result_text(&result);
            assert_ne!(result.is_error, Some(true), "{text}");
            assert!(text.contains("exit code: 0"), "hatch's own report went missing: {text}");
            assert!(text.ends_with(&tail), "the run said nothing for the user: {text}");
            assert_eq!(harness.only_record()["note"].as_str(), Some(typed));

            let harness = Harness::new(vec![approve()]);
            let elsewhere = tempfile::tempdir().unwrap();
            let target = elsewhere.path().join("target.conf");
            std::fs::write(&target, b"before\n").unwrap();
            let result = within(
                harness.daemon.swap_file(swap_of(&target, "after\n", false), Caller::quiet()),
            )
            .await;
            let text = result_text(&result);
            assert_ne!(result.is_error, Some(true), "{text}");
            assert!(text.contains("wrote "), "hatch's own report went missing: {text}");
            assert!(text.ends_with(&tail), "the write said nothing for the user: {text}");
            assert_eq!(harness.only_record()["note"].as_str(), Some(typed));
        }

        #[tokio::test]
        async fn an_approval_with_an_empty_field_speaks_for_nobody() {
            // Silence is not a message. A label over nothing would have the
            // agent looking for words the person did not write, and an empty
            // string on every approved line would bury the ones they did.
            let harness = Harness::new(vec![approve()]);
            let result =
                within(harness.daemon.run_command(run_of("true"), Caller::quiet())).await;

            let text = result_text(&result);
            assert!(!text.contains("the user's note"), "an empty field spoke: {text}");
            assert!(text.ends_with("(empty)\n"), "and nothing was appended at all: {text}");
            assert_eq!(harness.verdict(), "approve");
            assert!(
                harness.only_record().get("note").is_none(),
                "an empty note belongs on no line: {}",
                harness.only_record()
            );
        }

        #[tokio::test]
        async fn timeout_is_distinguishable_from_denial() {
            // A window nobody answers. The agent has to be able to tell an
            // absent user from a refusing one, or it reports a decision that
            // was never made.
            let harness = Harness::new(vec![Reply::silent()]);
            let result =
                within(harness.daemon.run_command(run_of("true"), Caller::quiet())).await;

            assert_eq!(result.is_error, Some(true));
            let text = result_text(&result);
            assert!(text.contains("timed out awaiting the user"), "{text}");
            assert!(!text.contains("denied"), "a timeout must not read as a denial: {text}");
            assert_eq!(harness.verdict(), "timeout");
            assert!(harness.prompter.seen().len() == 1, "the window was shown, just unanswered");
        }

        #[tokio::test]
        async fn a_decision_in_the_same_instant_as_the_deadline_is_still_a_decision() {
            // The select is biased with the verdict first, so a verdict that
            // is ready in the same poll as the timer wins it.
            let harness = Harness::new(vec![Reply::verdict(Verdict::Deny {
                note: "just in time".to_string(),
            })
            .after(Duration::from_secs(1))]);
            let result =
                within(harness.daemon.run_command(run_of("true"), Caller::quiet())).await;
            let text = result_text(&result);
            assert!(
                text.contains("denied by user") || text.contains("timed out"),
                "one or the other, never something else: {text}"
            );
        }

        #[tokio::test]
        async fn a_dead_prompt_before_a_verdict_denies() {
            let harness = Harness::new(vec![Reply::dies()]);
            let result =
                within(harness.daemon.run_command(run_of("true"), Caller::quiet())).await;

            assert_eq!(result.is_error, Some(true));
            assert_eq!(harness.verdict(), LogVerdict::PromptDied.as_str());
        }

        #[tokio::test]
        async fn a_window_that_never_opens_denies_too() {
            let harness = Harness::new(vec![Reply::fails("no display")]);
            let result =
                within(harness.daemon.run_command(run_of("true"), Caller::quiet())).await;

            assert_eq!(result.is_error, Some(true));
            assert!(result_text(&result).contains("no display"));
            assert_eq!(harness.verdict(), LogVerdict::PromptDied.as_str());
        }

        // --- the deny rule stops at Approve -------------------------------

        #[tokio::test]
        async fn a_dead_prompt_after_approve_still_runs_the_command() {
            // Invariant 3. Killing an authorised command could leave a
            // half-finished state the user never asked for.
            let harness = Harness::new(vec![approve().then_dies()]);
            let marker = harness.dir.path().join("marker");
            let command = format!("sleep 0.3; echo done > {}", marker.display());

            let result =
                within(harness.daemon.run_command(run_of(&command), Caller::quiet())).await;

            assert_ne!(result.is_error, Some(true), "an approved command is not an error");
            assert_eq!(std::fs::read_to_string(&marker).unwrap().trim(), "done");

            let record = harness.only_record();
            assert_eq!(record["verdict"], "approve");
            assert_eq!(
                record["prompt_died_after_approve"],
                serde_json::Value::Bool(true),
                "the lost live view is recorded: {record}"
            );
            assert_eq!(record["exit_code"], 0);
        }

        #[tokio::test]
        async fn a_window_that_lives_records_that_it_did() {
            let harness = Harness::new(vec![approve()]);
            within(harness.daemon.run_command(run_of("true"), Caller::quiet())).await;
            assert_eq!(
                harness.only_record()["prompt_died_after_approve"],
                serde_json::Value::Bool(false)
            );
        }

        #[tokio::test]
        async fn an_approved_command_returns_what_actually_happened() {
            let harness = Harness::new(vec![approve()]);
            let result = within(
                harness
                    .daemon
                    .run_command(run_of("echo out; echo err 1>&2; exit 3"), Caller::quiet()),
            )
            .await;

            assert_ne!(result.is_error, Some(true));
            let text = result_text(&result);
            assert!(text.contains("exit code: 3"), "{text}");
            assert!(text.contains("out"), "{text}");
            assert!(text.contains("err"), "{text}");
            let record = harness.only_record();
            assert_eq!(record["exit_code"], 3);
            assert_eq!(record["timed_out"], serde_json::Value::Bool(false));
            assert_eq!(record["killed_by_user"], serde_json::Value::Bool(false));
        }

        #[tokio::test]
        async fn the_approval_lock_is_released_at_the_verdict_not_at_completion() {
            // A five-minute upgrade must not hold every other agent behind it.
            let harness = Harness::new(vec![approve(), approve()]);
            let daemon = Arc::clone(&harness.daemon);
            let slow = tokio::spawn(async move {
                daemon.run_command(run_of("sleep 2"), Caller::quiet()).await
            });

            // Wait until the slow command is past its verdict and running.
            let started = tokio::time::Instant::now();
            while harness.prompter.seen().is_empty() && started.elapsed() < CEILING {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            let quick = within(harness.daemon.run_command(run_of("true"), Caller::quiet())).await;
            assert_ne!(quick.is_error, Some(true), "the second request must not wait for the first");
            assert!(started.elapsed() < Duration::from_secs(2), "it waited for the sleep");
            within(slow).await.unwrap();
        }

        // --- abandonment ---------------------------------------------------

        /// Whether any process on this machine has `marker` in its command
        /// line. The prompt is a child process of the daemon's, so this is how
        /// a test asks whether one is still on screen.
        fn any_process_named(marker: &str) -> bool {
            let Ok(entries) = std::fs::read_dir("/proc") else {
                return false;
            };
            entries.filter_map(Result::ok).any(|entry| {
                std::fs::read(entry.path().join("cmdline"))
                    .is_ok_and(|line| String::from_utf8_lossy(&line).contains(marker))
            })
        }

        /// A daemon whose windows are real processes: a shell that swallows
        /// the request and then sits there, exactly as an unanswered window
        /// does, with a marker in its command line so a test can find it.
        fn harness_with_real_windows(marker: &str) -> Harness {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::scratch(dir.path());
            let config = quick(&paths);
            let prompter =
                ProcessPrompter::with_argv(["sh", "-c", "cat >/dev/null", marker]);
            let daemon = Arc::new(Daemon::new(&paths, config, Arc::new(prompter)));
            // The stub is unused on this path; the script is empty because
            // nothing consults it.
            Harness {
                dir,
                paths,
                daemon,
                prompter: Arc::new(StubPrompter::new(Vec::<Reply>::new())),
            }
        }

        #[tokio::test]
        async fn client_cancellation_kills_the_pending_prompt() {
            let marker = format!("hatch-cancel-{}", uuid::Uuid::new_v4());
            let harness = harness_with_real_windows(&marker);
            // Long enough that the deadline cannot be what ends this.
            let mut config = quick(&harness.paths);
            config.timeout_secs = 600;
            let daemon = Arc::new(Daemon::new(
                &harness.paths,
                config,
                Arc::new(ProcessPrompter::with_argv(["sh", "-c", "cat >/dev/null", &marker])),
            ));

            let cancelled = CancellationToken::new();
            let caller = Caller {
                cancelled: cancelled.clone(),
                hangup: None,
                progress: None,
            };
            let call = {
                let daemon = Arc::clone(&daemon);
                tokio::spawn(async move { daemon.run_command(run_of("true"), caller).await })
            };

            let waited = tokio::time::Instant::now();
            while !any_process_named(&marker) && waited.elapsed() < CEILING {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(any_process_named(&marker), "the window must be on screen to be killed");

            cancelled.cancel();
            let result = within(call).await.unwrap();

            assert_eq!(result.is_error, Some(true));
            assert!(!any_process_named(&marker), "the window outlived the call that opened it");

            let path = AuditLog::new(&harness.paths.log_dir()).current_path();
            let text = std::fs::read_to_string(path).unwrap();
            let record: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
            assert_eq!(record["verdict"], LogVerdict::Cancelled.as_str());
        }

        #[tokio::test]
        async fn cancellation_while_queued_never_opens_a_window() {
            // A request waiting its turn has no window yet, so abandoning it
            // must cost nobody anything and must still leave a record.
            let harness = Harness::new(vec![Reply::silent(), Reply::silent()]);
            let holder = {
                let daemon = Arc::clone(&harness.daemon);
                tokio::spawn(async move {
                    daemon.run_command(run_of("first"), Caller::quiet()).await
                })
            };
            while harness.prompter.seen().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            let cancelled = CancellationToken::new();
            let caller =
                Caller { cancelled: cancelled.clone(), hangup: None, progress: None };
            let queued = {
                let daemon = Arc::clone(&harness.daemon);
                tokio::spawn(async move { daemon.run_command(run_of("second"), caller).await })
            };
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancelled.cancel();

            let result = within(queued).await.unwrap();
            assert_eq!(result.is_error, Some(true));
            assert_eq!(harness.prompter.seen().len(), 1, "the queued request never got a window");
            within(holder).await.unwrap();

            let verdicts: Vec<String> = harness
                .logged()
                .iter()
                .map(|r| r["verdict"].as_str().unwrap().to_string())
                .collect();
            assert!(verdicts.contains(&"cancelled".to_string()), "{verdicts:?}");
        }

        #[tokio::test]
        async fn a_lost_connection_denies_and_is_not_a_cancellation() {
            // The unit half of the disconnect story; the wire half is
            // `transport_disconnect_is_logged_separately_from_cancellation`.
            let harness = Harness::new(vec![Reply::silent()]);
            let hangup = Hangup::new();
            let caller = Caller {
                cancelled: CancellationToken::new(),
                hangup: Some(hangup.clone()),
                progress: None,
            };
            let call = {
                let daemon = Arc::clone(&harness.daemon);
                tokio::spawn(async move { daemon.run_command(run_of("true"), caller).await })
            };
            while harness.prompter.seen().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            hangup.0.gone.cancel();

            let result = within(call).await.unwrap();
            assert_eq!(result.is_error, Some(true));
            assert_eq!(harness.verdict(), LogVerdict::Disconnected.as_str());
        }

        #[tokio::test]
        async fn a_cancelled_call_whose_stream_dies_first_is_still_a_cancellation() {
            // A cancellation closes the response stream *before* rmcp's own
            // token fires, so the flag and not the timing is what decides.
            let harness = Harness::new(vec![Reply::silent()]);
            let hangup = Hangup::new();
            let caller = Caller {
                cancelled: CancellationToken::new(),
                hangup: Some(hangup.clone()),
                progress: None,
            };
            let call = {
                let daemon = Arc::clone(&harness.daemon);
                tokio::spawn(async move { daemon.run_command(run_of("true"), caller).await })
            };
            while harness.prompter.seen().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            hangup.note_cancelled();
            hangup.0.gone.cancel();

            within(call).await.unwrap();
            assert_eq!(harness.verdict(), LogVerdict::Cancelled.as_str());
        }

        // --- refusals -------------------------------------------------------

        #[tokio::test]
        async fn refusals_happen_before_any_prompt_is_shown() {
            let harness = Harness::new(Vec::new());
            let protected = harness.paths.config_file();
            let result = within(harness.daemon.swap_file(
                SwapFileParams {
                    title: "take hatch over".to_string(),
                    path: protected.display().to_string(),
                    content: "x".to_string(),
                    reason: "because a test asked".to_string(),
                    root: false,
                },
                Caller::quiet(),
            ))
            .await;

            assert_eq!(result.is_error, Some(true));
            assert!(harness.prompter.seen().is_empty(), "a refused request reached the user");
            assert_eq!(harness.verdict(), LogVerdict::Refused.as_str());
        }

        #[tokio::test]
        async fn a_working_directory_that_is_not_one_is_refused_before_prompting() {
            for cwd in ["/no/such/directory/anywhere", "not-absolute"] {
                let harness = Harness::new(Vec::new());
                let mut params = run_of("true");
                params.cwd = Some(cwd.to_string());
                let result =
                    within(harness.daemon.run_command(params, Caller::quiet())).await;

                assert_eq!(result.is_error, Some(true), "{cwd}");
                assert!(harness.prompter.seen().is_empty(), "{cwd} cost the user attention");
                assert_eq!(harness.verdict(), LogVerdict::Refused.as_str(), "{cwd}");
            }
            // A directory that exists but is a file is the third shape of the
            // same refusal.
            let harness = Harness::new(Vec::new());
            let file = harness.dir.path().join("a-file");
            std::fs::write(&file, b"not a directory").unwrap();
            let mut params = run_of("true");
            params.cwd = Some(file.display().to_string());
            within(harness.daemon.run_command(params, Caller::quiet())).await;
            assert!(harness.prompter.seen().is_empty());
            assert_eq!(harness.verdict(), LogVerdict::Refused.as_str());
        }

        // --- the root path ----------------------------------------------------

        /// A harness whose daemon elevates through `elevation` instead of
        /// through the platform's mechanism.
        ///
        /// This is what makes every root outcome reachable. A password dialog
        /// cannot be driven from a test, nothing in this file may invoke
        /// `run0`, and the four things that dialog can do are exactly what the
        /// mapping under test has to get right — so the dialog's seam is
        /// replaced and everything on this side of it is the real flow.
        fn rooted(script: Vec<Reply>, elevation: Arc<dyn Elevation>) -> Harness {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::scratch(dir.path());
            let config = quick(&paths);
            let prompter = Arc::new(StubPrompter::new(script));
            let daemon = Arc::new(
                Daemon::new(&paths, config, Arc::clone(&prompter) as Arc<_>)
                    .with_elevation(elevation),
            );
            Harness { dir, paths, daemon, prompter }
        }

        fn root_run(command: &str) -> RunCommandParams {
            let mut params = run_of(command);
            params.root = true;
            params
        }

        fn swap_of(path: &Path, content: &str, root: bool) -> SwapFileParams {
            SwapFileParams {
                title: "change it".to_string(),
                path: path.display().to_string(),
                content: content.to_string(),
                reason: "because a test asked".to_string(),
                root,
            }
        }

        /// Every frame the one window was sent.
        fn frames(harness: &Harness) -> Vec<crate::protocol::DaemonMsg> {
            harness.prompter.recorded()[0].sent.clone()
        }

        #[tokio::test]
        async fn a_root_command_runs_through_the_elevation_and_is_recorded_as_approved() {
            let elevation = Arc::new(Rehearsed::running(RootOutcome::Ran { exit: Some(0) }));
            let harness = rooted(vec![approve()], Arc::clone(&elevation) as Arc<_>);

            let result =
                within(harness.daemon.run_command(root_run("echo hi"), Caller::quiet())).await;

            assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
            assert!(result_text(&result).contains("hi"), "{}", result_text(&result));
            let record = harness.only_record();
            assert_eq!(record["verdict"], "approve");
            assert_eq!(record["root"], true);
            assert_eq!(record["exit_code"], 0);
            // The command went through the elevation rather than round it.
            assert_eq!(elevation.seen(), vec![vec!["bash".to_string(), "-c".to_string(), "echo hi".to_string()]]);
        }

        #[tokio::test]
        async fn the_window_shows_the_whole_elevated_line_and_the_caveat() {
            let harness = rooted(
                vec![Reply::verdict(Verdict::Deny { note: "no".to_string() })],
                Arc::new(Rehearsed::running(RootOutcome::Ran { exit: Some(0) })),
            );
            within(harness.daemon.run_command(root_run("echo hi"), Caller::quiet())).await;

            let shown = harness.prompter.seen().into_iter().next().expect("a window");
            let Payload::Command { raw, root, caveat, .. } = shown.payload else {
                panic!("not a command payload");
            };
            // The elevation program is in the line the reader approves, not
            // folded away behind a flag. A window showing `echo hi` for a
            // request that runs `<something> bash -c 'echo hi'` would be the
            // rendering-fidelity failure this whole tool exists to avoid.
            assert!(raw.contains("bash -c"), "the wrapper is not on screen: {raw}");
            assert!(raw.ends_with("'echo hi'"), "{raw}");
            assert!(root, "the header would not say ROOT");
            // And the reader is told, before approving, that a root command
            // may behave differently from the same command run as them.
            let caveat = caveat.expect("a root request drew no caveat");
            assert!(caveat.contains("terminal"), "{caveat}");
        }

        #[tokio::test]
        async fn an_unelevated_command_draws_neither_the_wrapper_nor_a_caveat() {
            let harness =
                Harness::new(vec![Reply::verdict(Verdict::Deny { note: "no".to_string() })]);
            within(harness.daemon.run_command(run_of("echo hi"), Caller::quiet())).await;

            let shown = harness.prompter.seen().into_iter().next().expect("a window");
            let Payload::Command { raw, root, caveat, .. } = shown.payload else {
                panic!("not a command payload");
            };
            assert_eq!(raw, "echo hi");
            assert!(!root);
            assert_eq!(caveat, None, "an ordinary command was given a root warning");
        }

        #[tokio::test]
        async fn a_dismissed_password_dialog_is_an_elevation_failure_and_never_an_exit_code() {
            // The command exits 1 *and* the dialog was dismissed, which is the
            // collision the whole classifier exists for: both produce status 1.
            let harness = rooted(
                vec![approve()],
                Arc::new(Rehearsed::running(RootOutcome::Denied)),
            );

            let result =
                within(harness.daemon.run_command(root_run("exit 1"), Caller::quiet())).await;

            assert_eq!(result.is_error, Some(true));
            let text = result_text(&result);
            assert!(text.contains("elevation failed or was cancelled"), "{text}");
            assert!(text.contains("not a refusal by the user"), "{text}");
            assert!(text.contains("asking again is safe"), "{text}");
            // The number a refusal and a failing command share must not be
            // reported as the command's. This is the mutant worth catching:
            // saying "exit code: 1" sends the agent off to fix a command that
            // never ran.
            assert!(!text.contains("exit code"), "a refusal was reported as an exit code: {text}");

            let record = harness.only_record();
            assert_eq!(record["verdict"], "elevation_failed");
            assert_eq!(record["exit_code"], serde_json::Value::Null, "{record}");
            // And the window closed saying nothing ran, rather than drawing a
            // status for a command that never started.
            assert!(
                frames(&harness).iter().any(|f| matches!(
                    f,
                    crate::protocol::DaemonMsg::Finished(protocol::Outcome::ElevationFailed { .. })
                )),
                "{:?}",
                frames(&harness)
            );
        }

        #[tokio::test]
        async fn an_elevation_that_could_not_happen_is_a_failure_and_not_a_denial() {
            let harness = rooted(
                vec![approve()],
                Arc::new(Rehearsed::running(RootOutcome::Failed {
                    message: "no authentication agent is running".to_string(),
                })),
            );

            let result =
                within(harness.daemon.run_command(root_run("true"), Caller::quiet())).await;

            assert_eq!(result.is_error, Some(true));
            assert!(
                result_text(&result).contains("no authentication agent"),
                "{}",
                result_text(&result)
            );
            assert_eq!(harness.verdict(), "elevation_failed");
        }

        #[tokio::test]
        async fn an_unclear_elevation_is_reported_as_neither_a_success_nor_a_command_failure() {
            let harness = rooted(
                vec![approve()],
                Arc::new(Rehearsed::running(RootOutcome::Unclear {
                    exit: Some(1),
                    message: "hatch cannot read this mechanism's diagnostics".to_string(),
                })),
            );

            let result =
                within(harness.daemon.run_command(root_run("echo out; exit 1"), Caller::quiet()))
                    .await;

            let text = result_text(&result);
            // Not a success.
            assert_eq!(result.is_error, Some(true), "{text}");
            // Not "nothing ran" either — that is a claim, and the point of
            // this outcome is that hatch has no evidence for either claim.
            assert!(!text.contains("Nothing ran"), "{text}");
            assert!(!text.contains("asking again is safe"), "{text}");
            assert!(text.contains("cannot say whether it ran"), "{text}");
            assert!(text.contains("Do not retry"), "{text}");
            // The output goes with it: it is the evidence anyone deciding
            // what happened would actually look at.
            assert!(text.contains("out"), "{text}");

            let record = harness.only_record();
            assert_eq!(
                record["verdict"], "elevation_unclear",
                "an unknown outcome was filed as something known: {record}"
            );
            assert_eq!(record["exit_code"], serde_json::Value::Null, "{record}");
            assert!(
                frames(&harness).iter().any(|f| matches!(
                    f,
                    crate::protocol::DaemonMsg::Finished(protocol::Outcome::Unclear { .. })
                )),
                "the window closed on a claim: {:?}",
                frames(&harness)
            );
        }

        #[tokio::test]
        async fn a_root_run_hatch_ended_itself_is_unclear_rather_than_killed() {
            // The elevation would have said the command ran. It cannot know:
            // the password dialog lives inside the elevated process, so a run
            // hatch killed may be a command it stopped or a dialog nobody
            // answered. This is the timeout case the tool description
            // promises is bounded.
            let harness = rooted(
                vec![approve().then_kills_after(Duration::from_millis(150))],
                Arc::new(Rehearsed::running(RootOutcome::Ran { exit: Some(0) })),
            );

            let result =
                within(harness.daemon.run_command(root_run("sleep 30"), Caller::quiet())).await;

            let text = result_text(&result);
            assert_eq!(result.is_error, Some(true), "{text}");
            assert!(text.contains("cannot say whether it ran"), "{text}");
            assert!(text.contains("Kill"), "{text}");
            assert_eq!(harness.verdict(), "elevation_unclear");
        }

        #[tokio::test]
        async fn an_unelevated_run_hatch_ended_itself_is_still_a_plain_killed_run() {
            // The other half of the rule above: nothing changes for a command
            // with no second gate in front of it, because there is nothing
            // hatch does not know about it.
            let harness =
                Harness::new(vec![approve().then_kills_after(Duration::from_millis(150))]);

            let result =
                within(harness.daemon.run_command(run_of("sleep 30"), Caller::quiet())).await;

            assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
            assert!(result_text(&result).contains("killed"), "{}", result_text(&result));
            assert_eq!(harness.verdict(), "approve");
        }

        #[tokio::test]
        async fn the_window_is_told_a_password_dialog_is_coming_before_it_is() {
            let harness = rooted(
                vec![approve()],
                Arc::new(Rehearsed::running(RootOutcome::Ran { exit: Some(0) })),
            );
            within(harness.daemon.run_command(root_run("true"), Caller::quiet())).await;

            let sent = frames(&harness);
            let elevating = sent
                .iter()
                .position(|f| matches!(f, crate::protocol::DaemonMsg::Elevating))
                .expect("the window was never told: {sent:?}");
            let finished = sent
                .iter()
                .position(|f| matches!(f, crate::protocol::DaemonMsg::Finished(_)))
                .expect("no outcome frame");
            // Before, not after. A reader told about the dialog once it is
            // gone has been told nothing: the whole value of the frame is
            // that the window stops claiming the operation is running while a
            // dialog they have to answer is sitting on top of it.
            assert!(elevating < finished, "{sent:?}");
        }

        #[tokio::test]
        async fn an_unelevated_run_never_says_a_password_dialog_is_coming() {
            let harness = Harness::new(vec![approve()]);
            within(harness.daemon.run_command(run_of("true"), Caller::quiet())).await;
            assert!(
                !frames(&harness)
                    .iter()
                    .any(|f| matches!(f, crate::protocol::DaemonMsg::Elevating)),
                "{:?}",
                frames(&harness)
            );
        }

        #[tokio::test]
        async fn a_build_that_cannot_elevate_refuses_before_anybody_is_asked() {
            for root in [true, false] {
                let harness = rooted(
                    vec![approve()],
                    Arc::new(Rehearsed::unavailable("there is no way to elevate here")),
                );
                let mut params = run_of("true");
                params.root = root;
                let result = within(harness.daemon.run_command(params, Caller::quiet())).await;

                if root {
                    assert_eq!(result.is_error, Some(true));
                    assert!(
                        result_text(&result).contains("no way to elevate"),
                        "{}",
                        result_text(&result)
                    );
                    assert!(harness.prompter.seen().is_empty(), "it cost the user attention");
                    assert_eq!(harness.verdict(), LogVerdict::Refused.as_str());
                } else {
                    // The refusal is about elevation and nothing else: an
                    // ordinary command on a machine with no `run0` still runs.
                    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
                }
            }
        }

        // --- the root file path ------------------------------------------------

        #[tokio::test]
        async fn a_root_swap_installs_with_the_mode_and_owner_the_window_stated() {
            let elevation = Arc::new(Rehearsed::recording(RootOutcome::Ran { exit: Some(0) }));
            let harness = rooted(vec![approve()], Arc::clone(&elevation) as Arc<_>);
            let elsewhere = tempfile::tempdir().unwrap();
            let target = elsewhere.path().join("target.conf");
            std::fs::write(&target, b"before\n").unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();

            let result = within(
                harness.daemon.swap_file(swap_of(&target, "after\n", true), Caller::quiet()),
            )
            .await;

            assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
            let argv = elevation.seen().into_iter().next().expect("nothing was elevated");
            assert_eq!(argv[0], "install");
            // The mode and owner the window drew, and not any other ones. A
            // write at 0644 where the window said 0640 is a different file
            // from the one that was approved.
            assert_eq!(after(&argv, "-m"), Some("0640".to_string()));
            assert_eq!(
                after(&argv, "-o"),
                Some(crate::swap::Principal::user(nix::unistd::geteuid().as_raw()).to_string())
            );
            assert_eq!(argv.last().unwrap(), &target.display().to_string());

            let record = harness.only_record();
            assert_eq!(record["verdict"], "approve");
            assert_eq!(record["root"], true);
            assert_eq!(record["mode"], "0640");
        }

        /// The argument after `flag`.
        fn after(argv: &[String], flag: &str) -> Option<String> {
            argv.iter().position(|a| a == flag).and_then(|at| argv.get(at + 1)).cloned()
        }

        #[tokio::test]
        async fn a_root_swap_lands_the_exact_approved_bytes() {
            // `Rehearsed::running` really runs the `install` it is handed, as
            // whoever runs the test — so this exercises the argv end to end
            // against a real `install`, with no privilege and no dialog.
            let harness = rooted(
                vec![approve()],
                Arc::new(Rehearsed::running(RootOutcome::Ran { exit: Some(0) })),
            );
            let elsewhere = tempfile::tempdir().unwrap();
            let target = elsewhere.path().join("target.conf");
            std::fs::write(&target, b"before\n").unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();

            let result = within(
                harness.daemon.swap_file(swap_of(&target, "after\n", true), Caller::quiet()),
            )
            .await;

            assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "after\n");
            assert_eq!(
                std::fs::metadata(&target).unwrap().mode() & 0o7777,
                0o640,
                "the mode the window stated is not the mode that landed"
            );
            // And nothing approved is left lying about afterwards.
            assert_eq!(staged_files(&harness), 0);
        }

        /// How many approved-but-unwritten files are sitting in the staging
        /// directory.
        fn staged_files(harness: &Harness) -> usize {
            std::fs::read_dir(harness.paths.stage_dir()).map(|d| d.count()).unwrap_or(0)
        }

        #[tokio::test]
        async fn a_root_swap_that_landed_differently_from_the_plan_says_so() {
            // `recording`, so nothing writes: the test is about what hatch
            // does when the file it re-examines is not the file the window
            // described, and the cheapest way to produce that is to change
            // the target's mode while the window is up. The content is left
            // alone, so the hash re-check passes and the write proceeds —
            // which is exactly the shape of the real risk, because the mode
            // is the part of the plan the content hash cannot see.
            let harness = rooted(
                vec![approve().after(Duration::from_millis(250))],
                Arc::new(Rehearsed::recording(RootOutcome::Ran { exit: Some(0) })),
            );
            let elsewhere = tempfile::tempdir().unwrap();
            let target = elsewhere.path().join("target.conf");
            std::fs::write(&target, b"before\n").unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();

            let moved = target.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(80)).await;
                std::fs::set_permissions(&moved, std::fs::Permissions::from_mode(0o600)).unwrap();
            });

            let result = within(
                harness.daemon.swap_file(swap_of(&target, "after\n", true), Caller::quiet()),
            )
            .await;

            let text = result_text(&result);
            assert_eq!(result.is_error, Some(true), "{text}");
            assert!(text.contains("not what was approved"), "{text}");
            assert!(text.contains("0640"), "the approved landing is not named: {text}");
            assert!(text.contains("0600"), "what is actually there is not named: {text}");
            // It happened, so it is logged as an approval that ran — but
            // without a landing record, because the landing is the thing that
            // did not match.
            let record = harness.only_record();
            assert_eq!(record["verdict"], "approve");
            assert_eq!(record["mode"], serde_json::Value::Null, "{record}");
        }

        #[tokio::test]
        async fn the_staged_bytes_are_gone_after_a_dismissed_password_dialog() {
            // `recording`, because a dismissed dialog means the `install`
            // never ran: the double that runs what it is handed would write
            // the file and then report that nothing had.
            let harness = rooted(
                vec![approve()],
                Arc::new(Rehearsed::recording(RootOutcome::Denied)),
            );
            let elsewhere = tempfile::tempdir().unwrap();
            let target = elsewhere.path().join("target.conf");
            std::fs::write(&target, b"before\n").unwrap();

            let result = within(
                harness.daemon.swap_file(swap_of(&target, "after\n", true), Caller::quiet()),
            )
            .await;

            assert_eq!(result.is_error, Some(true));
            assert_eq!(harness.verdict(), "elevation_failed");
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "before\n");
            // The file the user approved must not outlive the request that
            // approved it. This is the mutant worth catching: a drop guard
            // that stops removing leaves approved content on disk after every
            // refusal.
            assert_eq!(staged_files(&harness), 0, "approved bytes survived a denial");
            let record = harness.only_record();
            assert_eq!(record["hash_after"], serde_json::Value::Null, "{record}");
        }

        #[tokio::test]
        async fn a_root_swap_that_drifted_under_review_never_asks_for_a_password() {
            let elevation = Arc::new(Rehearsed::running(RootOutcome::Ran { exit: Some(0) }));
            let harness = rooted(
                vec![approve().after(Duration::from_millis(250))],
                Arc::clone(&elevation) as Arc<_>,
            );
            let elsewhere = tempfile::tempdir().unwrap();
            let target = elsewhere.path().join("target.conf");
            std::fs::write(&target, b"before\n").unwrap();

            // Somebody else writes the file while the window is up.
            let drifting = target.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(80)).await;
                std::fs::write(&drifting, b"somebody else got there first\n").unwrap();
            });

            let result = within(
                harness.daemon.swap_file(swap_of(&target, "after\n", true), Caller::quiet()),
            )
            .await;

            assert_eq!(result.is_error, Some(true));
            assert!(result_text(&result).contains("changed after the request was approved"), "{}", result_text(&result));
            assert_eq!(
                std::fs::read_to_string(&target).unwrap(),
                "somebody else got there first\n"
            );
            // The re-check runs before the elevation, so a write that is
            // going to be refused never spends a password the user would have
            // had to type first.
            assert!(elevation.seen().is_empty(), "a password was asked for a refused write");
            assert_eq!(staged_files(&harness), 0);
        }

        #[tokio::test]
        async fn a_root_swap_whose_install_failed_is_a_failed_write_and_not_an_elevation_outcome() {
            // The password was given and used; `install` then could not do
            // the work. That is an ordinary failed write and must not be
            // filed as an elevation problem.
            let harness = rooted(
                vec![approve()],
                Arc::new(Rehearsed::running(RootOutcome::Ran { exit: Some(1) })),
            );
            let elsewhere = tempfile::tempdir().unwrap();
            let target = elsewhere.path().join("target.conf");
            std::fs::write(&target, b"before\n").unwrap();
            // An owner this process cannot give the file, so the real
            // `install` the double runs fails the way a read-only mount would.
            let mut params = swap_of(&target, "after\n", true);
            params.path = target.display().to_string();
            std::fs::set_permissions(elsewhere.path(), std::fs::Permissions::from_mode(0o500))
                .unwrap();

            let result = within(harness.daemon.swap_file(params, Caller::quiet())).await;
            std::fs::set_permissions(elsewhere.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();

            assert_eq!(result.is_error, Some(true));
            let text = result_text(&result);
            assert!(text.contains("the write failed"), "{text}");
            // And it does not claim the file is untouched. `install`
            // truncates its destination, so a write that failed part way
            // through can leave it short — the unelevated path's "nothing was
            // written" guarantee does not hold here and must not be repeated.
            assert!(!text.contains("exactly as it was"), "{text}");
            assert!(text.contains("not a rename"), "{text}");
            assert_eq!(harness.verdict(), "approve", "a failed write was filed as an elevation problem");
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "before\n");
            assert_eq!(staged_files(&harness), 0);
        }

        #[tokio::test]
        async fn a_denied_root_swap_stages_nothing_and_writes_nothing() {
            let elevation = Arc::new(Rehearsed::running(RootOutcome::Ran { exit: Some(0) }));
            let harness = rooted(
                vec![Reply::verdict(Verdict::Deny { note: "not that".to_string() })],
                Arc::clone(&elevation) as Arc<_>,
            );
            let elsewhere = tempfile::tempdir().unwrap();
            let target = elsewhere.path().join("target.conf");
            std::fs::write(&target, b"before\n").unwrap();

            within(harness.daemon.swap_file(swap_of(&target, "after\n", true), Caller::quiet()))
                .await;

            assert_eq!(std::fs::read_to_string(&target).unwrap(), "before\n");
            assert!(elevation.seen().is_empty());
            assert_eq!(staged_files(&harness), 0);
            assert_eq!(harness.verdict(), "deny");
        }

        #[tokio::test]
        async fn a_root_swap_is_refused_on_a_protected_path_like_any_other() {
            let harness = rooted(
                vec![approve()],
                Arc::new(Rehearsed::running(RootOutcome::Ran { exit: Some(0) })),
            );
            let protected = harness.paths.config_file();

            let result = within(
                harness.daemon.swap_file(swap_of(&protected, "x", true), Caller::quiet()),
            )
            .await;

            // Root does not buy a way past hatch's own denylist. It is the
            // one set of paths where the answer does not depend on privilege.
            assert_eq!(result.is_error, Some(true));
            assert!(harness.prompter.seen().is_empty());
            assert_eq!(harness.verdict(), LogVerdict::Refused.as_str());
        }

        #[tokio::test]
        async fn the_advertised_ceiling_still_bounds_a_root_call() {
            // The password wait sits inside the execution timeout, because
            // the dialog lives inside the elevated process and that process
            // is what the execution deadline kills. So the number the tool
            // description quotes — the approval wait plus the execution
            // wait — still bounds the whole call, with nothing added for the
            // dialog and nothing unbounded anywhere in it.
            let harness = rooted(
                vec![approve()],
                Arc::new(Rehearsed::running(RootOutcome::Ran { exit: Some(0) })),
            );
            let ceiling = harness.daemon.config().client_timeout_secs();
            assert_eq!(
                ceiling,
                harness.daemon.config().timeout_secs + harness.daemon.config().exec_timeout_secs
            );

            let started = tokio::time::Instant::now();
            // A command that outlasts the execution deadline stands in for a
            // dialog nobody answers: both are the elevated process failing to
            // finish, and hatch ends both the same way.
            let result =
                within(harness.daemon.run_command(root_run("sleep 60"), Caller::quiet())).await;

            assert!(
                started.elapsed() < Duration::from_secs(ceiling),
                "a root call blocked past the ceiling the agent was told"
            );
            assert_eq!(result.is_error, Some(true));
            assert!(
                result_text(&result).contains("execution deadline"),
                "{}",
                result_text(&result)
            );
            assert_eq!(harness.verdict(), "elevation_unclear");
        }

        // --- the file path ---------------------------------------------------

        #[tokio::test]
        async fn an_approved_swap_writes_the_file_and_records_it() {
            let harness = Harness::new(vec![approve()]);
            let elsewhere = tempfile::tempdir().unwrap();
            let target = elsewhere.path().join("target.conf");
            std::fs::write(&target, b"before\n").unwrap();

            let result = within(harness.daemon.swap_file(
                SwapFileParams {
                    title: "change it".to_string(),
                    path: target.display().to_string(),
                    content: "after\n".to_string(),
                    reason: "because a test asked".to_string(),
                    root: false,
                },
                Caller::quiet(),
            ))
            .await;

            assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "after\n");
            let record = harness.only_record();
            assert_eq!(record["verdict"], "approve");
            assert_eq!(record["bytes"], 6);
            assert_eq!(
                record["hash_before"],
                "9160d4be34c8695bd172a76c7c7966587ea5a4d991ad22c87b2b91af54aa9ebb",
                "the hash of what was there: {record}"
            );
            assert_eq!(
                record["hash_after"],
                "7b9a72466d3960eb2aacccfc848939453490db0678bd4725def3f789b891c919",
                "the hash of what was written: {record}"
            );
            assert!(
                harness.prompter.recorded()[0].sent.contains(
                    &crate::protocol::DaemonMsg::Finished(protocol::Outcome::Exit { code: 0 })
                ),
                "the window must be told it landed: {:?}",
                harness.prompter.recorded()[0].sent
            );
        }

        #[tokio::test]
        async fn a_denied_swap_leaves_the_file_alone() {
            let harness = Harness::new(vec![Reply::verdict(Verdict::Deny {
                note: "not that".to_string(),
            })]);
            let elsewhere = tempfile::tempdir().unwrap();
            let target = elsewhere.path().join("target.conf");
            std::fs::write(&target, b"before\n").unwrap();

            within(harness.daemon.swap_file(
                SwapFileParams {
                    title: "change it".to_string(),
                    path: target.display().to_string(),
                    content: "after\n".to_string(),
                    reason: "because a test asked".to_string(),
                    root: false,
                },
                Caller::quiet(),
            ))
            .await;

            assert_eq!(std::fs::read_to_string(&target).unwrap(), "before\n");
        }

        // --- the live view ----------------------------------------------------

        #[tokio::test]
        async fn transport_disconnect_is_logged_separately_from_cancellation() {
            // Two distinct forms of client abandonment. Both deny; the log
            // must still tell them apart, or `LogVerdict::Disconnected` is a
            // variant nothing can reach.
            //
            // This one has to go over a real socket. A dropped connection is
            // not something the handler can be told about in process: rmcp
            // spawns handlers detached, so the future is not dropped, the
            // injected token does not fire, and even a progress notification
            // into the dead stream reports success. What the daemon watches
            // instead is the response stream itself — see `Hangup`.
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::scratch(dir.path());
            let mut config = quick(&paths);
            config.token = "test-token".to_string();
            // Long, so that nothing but the disconnect can end this request.
            config.timeout_secs = 600;
            let prompter = Arc::new(StubPrompter::new(vec![Reply::silent()]));
            let daemon =
                Arc::new(Daemon::new(&paths, config, Arc::clone(&prompter) as Arc<_>));

            let listener = bind(0).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let served = app(Arc::clone(&daemon));
            let task = tokio::spawn(async move {
                let _ = axum::serve(listener, served).await;
            });

            let (headers, _) = rpc(
                addr,
                None,
                serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": { "name": "test", "version": "0" },
                    },
                }),
            )
            .await;
            let session = headers
                .get("mcp-session-id")
                .expect("a session")
                .to_str()
                .unwrap()
                .to_string();
            rpc(
                addr,
                Some(&session),
                serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            )
            .await;

            // A raw socket, so that dropping it is unambiguously a dropped
            // connection rather than a client library returning it to a pool.
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let body = serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": { "name": "run_command", "arguments": {
                    "title": "a test", "command": "true", "reason": "because a test asked"
                }},
            })
            .to_string();
            let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
            socket
                .write_all(
                    format!(
                        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer \
                         test-token\r\nMcp-Session-Id: {session}\r\nContent-Type: \
                         application/json\r\nAccept: application/json, \
                         text/event-stream\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut buffer = [0u8; 256];
            let _ = tokio::time::timeout(CEILING, socket.read(&mut buffer)).await;

            // The window is on screen and nobody has answered it.
            let waited = tokio::time::Instant::now();
            while prompter.seen().is_empty() && waited.elapsed() < CEILING {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(prompter.seen().len(), 1, "the request must reach a window first");

            drop(socket);

            let log = AuditLog::new(&paths.log_dir()).current_path();
            let waited = tokio::time::Instant::now();
            let record = loop {
                assert!(waited.elapsed() < CEILING, "no record was written for the lost client");
                if let Ok(text) = std::fs::read_to_string(&log)
                    && let Some(line) = text.lines().next()
                {
                    break serde_json::from_str::<serde_json::Value>(line).unwrap();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            };
            assert_eq!(
                record["verdict"], "disconnected",
                "a dropped connection is not a cancellation: {record}"
            );
            task.abort();
        }

        #[tokio::test]
        async fn a_denial_arrives_over_the_wire_as_a_tool_error_not_a_protocol_error() {
            // The whole point of the verdict mapping, checked where the agent
            // actually reads it: `result.isError`, never a JSON-RPC `error`.
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::scratch(dir.path());
            let mut config = quick(&paths);
            config.token = "test-token".to_string();
            let prompter = Arc::new(StubPrompter::new(vec![Reply::verdict(Verdict::Deny {
                note: "wrong host".to_string(),
            })]));
            let daemon =
                Arc::new(Daemon::new(&paths, config, Arc::clone(&prompter) as Arc<_>));

            let listener = bind(0).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let served = app(daemon);
            let task = tokio::spawn(async move {
                let _ = axum::serve(listener, served).await;
            });

            let (headers, _) = rpc(
                addr,
                None,
                serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": { "name": "test", "version": "0" },
                    },
                }),
            )
            .await;
            let session =
                headers.get("mcp-session-id").unwrap().to_str().unwrap().to_string();
            rpc(
                addr,
                Some(&session),
                serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            )
            .await;

            let (_, answered) = rpc(
                addr,
                Some(&session),
                serde_json::json!({
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": { "name": "run_command", "arguments": {
                        "title": "a test", "command": "true",
                        "reason": "because a test asked"
                    }},
                }),
            )
            .await;
            let answered = answered.expect("the call must answer");
            assert!(
                answered.get("error").is_none(),
                "a denial must not look like a broken server: {answered}"
            );
            assert_eq!(answered["result"]["isError"], true, "{answered}");
            assert!(
                answered["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("denied by user: wrong host"),
                "{answered}"
            );
            task.abort();
        }

        #[tokio::test]
        async fn progress_covers_the_approval_wait_and_not_only_the_queue() {
            // The longest silence in a request is the ninety seconds a person
            // spends reading, so a client that hears nothing during it gives
            // up on a window somebody is still looking at.
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::scratch(dir.path());
            let mut config = quick(&paths);
            config.token = "test-token".to_string();
            config.timeout_secs = 600;
            let prompter = Arc::new(StubPrompter::new(vec![Reply::silent()]));
            let daemon =
                Arc::new(Daemon::new(&paths, config, Arc::clone(&prompter) as Arc<_>));

            let listener = bind(0).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let served = app(daemon);
            let task = tokio::spawn(async move {
                let _ = axum::serve(listener, served).await;
            });

            let (headers, _) = rpc(
                addr,
                None,
                serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": { "name": "test", "version": "0" },
                    },
                }),
            )
            .await;
            let session =
                headers.get("mcp-session-id").unwrap().to_str().unwrap().to_string();
            rpc(
                addr,
                Some(&session),
                serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            )
            .await;

            // The stream stays open while the window waits, so the body is
            // read incrementally rather than to completion.
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let body = serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {
                    "name": "run_command",
                    "arguments": {
                        "title": "a test", "command": "true",
                        "reason": "because a test asked"
                    },
                    "_meta": { "progressToken": 7 },
                },
            })
            .to_string();
            let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
            socket
                .write_all(
                    format!(
                        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer \
                         test-token\r\nMcp-Session-Id: {session}\r\nContent-Type: \
                         application/json\r\nAccept: application/json, \
                         text/event-stream\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

            let mut seen = String::new();
            let waited = tokio::time::Instant::now();
            while !seen.contains("notifications/progress") && waited.elapsed() < CEILING {
                let mut buffer = [0u8; 4096];
                let read = tokio::time::timeout(CEILING, socket.read(&mut buffer)).await;
                match read {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => seen.push_str(&String::from_utf8_lossy(&buffer[..n])),
                    Ok(Err(_)) => break,
                }
            }
            assert!(
                seen.contains("notifications/progress"),
                "the client heard nothing while the window was open: {seen}"
            );
            assert!(
                seen.contains("awaiting the user") || seen.contains("queued"),
                "the progress frame must say which wait this is: {seen}"
            );
            drop(socket);
            task.abort();
        }

        #[test]
        fn every_phase_has_its_own_message() {
            let messages: Vec<&str> = [Phase::Queued, Phase::AwaitingApproval, Phase::Executing]
                .into_iter()
                .map(Phase::message)
                .collect();
            let mut unique = messages.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(unique.len(), messages.len(), "a phase that reads as another one: {messages:?}");
            for (index, message) in messages.iter().enumerate() {
                assert_eq!(
                    Phase::of(u8::try_from(index).unwrap()).message(),
                    *message,
                    "the phase a ticker reads back is not the one that was stored"
                );
            }
        }

        #[tokio::test]
        async fn the_ticker_stops_when_the_request_ends() {
            // Its `Drop` is the whole reason it is a value: "stopped at the
            // end" then holds on every path out, including the early ones.
            let progress = Progress::start(&Caller::quiet());
            let stop = progress.stop.clone();
            assert!(!stop.is_cancelled());
            progress.enter(Phase::Executing);
            assert_eq!(Phase::of(progress.phase.load(Ordering::Relaxed)), Phase::Executing);
            drop(progress);
            assert!(stop.is_cancelled(), "a ticker outlived the request it was ticking for");
        }

        /// The daemon, served on a loopback port, with the session already
        /// handshaken. Everything the over-the-wire tests need and nothing
        /// they have to repeat.
        struct Served {
            addr: std::net::SocketAddr,
            session: String,
            task: tokio::task::JoinHandle<()>,
        }

        async fn serve(daemon: Arc<Daemon>) -> Served {
            let listener = bind(0).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let served = app(daemon);
            let task = tokio::spawn(async move {
                let _ = axum::serve(listener, served).await;
            });

            let (headers, initialized) = rpc(
                addr,
                None,
                serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": { "name": "test", "version": "0" },
                    },
                }),
            )
            .await;
            initialized.expect("initialize must answer");
            let session =
                headers.get("mcp-session-id").expect("a session").to_str().unwrap().to_string();
            rpc(
                addr,
                Some(&session),
                serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            )
            .await;
            Served { addr, session, task }
        }

        /// A daemon whose token is the one `rpc` presents, over a temporary
        /// hatch directory, answering with `script`.
        fn wired(timeout_secs: u64, script: Vec<Reply>) -> (Harness, Arc<StubPrompter>) {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::scratch(dir.path());
            let mut config = quick(&paths);
            config.token = "test-token".to_string();
            config.timeout_secs = timeout_secs;
            let prompter = Arc::new(StubPrompter::new(script));
            let daemon =
                Arc::new(Daemon::new(&paths, config, Arc::clone(&prompter) as Arc<_>));
            (Harness { dir, paths, daemon, prompter: Arc::clone(&prompter) }, prompter)
        }

        /// One raw HTTP POST whose connection the caller keeps, so the request
        /// can be left in flight or dropped mid-call.
        async fn raw_call(
            served: &Served,
            body: &serde_json::Value,
        ) -> tokio::net::TcpStream {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let body = body.to_string();
            let mut socket = tokio::net::TcpStream::connect(served.addr).await.unwrap();
            socket
                .write_all(
                    format!(
                        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer \
                         test-token\r\nMcp-Session-Id: {}\r\nContent-Type: \
                         application/json\r\nAccept: application/json, \
                         text/event-stream\r\nContent-Length: {}\r\n\r\n{body}",
                        served.session,
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut buffer = [0u8; 256];
            let _ = tokio::time::timeout(CEILING, socket.read(&mut buffer)).await;
            socket
        }

        fn call_of(id: u32, name: &str, arguments: serde_json::Value) -> serde_json::Value {
            serde_json::json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": { "name": name, "arguments": arguments },
            })
        }

        /// Wait for the first audit record, or say that none was written.
        async fn first_record(paths: &Paths) -> serde_json::Value {
            let log = AuditLog::new(&paths.log_dir()).current_path();
            let waited = tokio::time::Instant::now();
            loop {
                assert!(waited.elapsed() < CEILING, "no audit record was ever written");
                if let Ok(text) = std::fs::read_to_string(&log)
                    && let Some(line) = text.lines().next()
                {
                    return serde_json::from_str(line).unwrap();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        #[tokio::test]
        async fn a_cancellation_notification_over_the_wire_cancels_the_call() {
            // The other half of the abandonment story, end to end: a client
            // that hits its own tool timeout usually cancels and keeps the
            // session open, which is not the same event as its process dying.
            let (harness, prompter) = wired(600, vec![Reply::silent()]);
            let served = serve(Arc::clone(&harness.daemon)).await;

            let socket = raw_call(
                &served,
                &call_of(
                    2,
                    "run_command",
                    serde_json::json!({
                        "title": "a test", "command": "true",
                        "reason": "because a test asked"
                    }),
                ),
            )
            .await;

            let waited = tokio::time::Instant::now();
            while prompter.seen().is_empty() && waited.elapsed() < CEILING {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(prompter.seen().len(), 1, "the window must be open to be cancelled");

            rpc(
                served.addr,
                Some(&served.session),
                serde_json::json!({
                    "jsonrpc": "2.0", "method": "notifications/cancelled",
                    "params": { "requestId": 2, "reason": "the client gave up" },
                }),
            )
            .await;

            let record = first_record(&harness.paths).await;
            assert_eq!(
                record["verdict"], "cancelled",
                "a cancellation the client sent is not a lost connection: {record}"
            );
            drop(socket);
            served.task.abort();
        }

        #[tokio::test]
        async fn both_tools_are_reachable_over_the_wire() {
            // `swap_file` has its own body, and a body that answers with
            // nothing at all would still leave every unit test green.
            let (harness, _) = wired(60, vec![approve()]);
            let served = serve(Arc::clone(&harness.daemon)).await;
            let elsewhere = tempfile::tempdir().unwrap();
            let target = elsewhere.path().join("written.conf");

            let (_, answered) = rpc(
                served.addr,
                Some(&served.session),
                call_of(
                    2,
                    "swap_file",
                    serde_json::json!({
                        "title": "write it", "path": target.display().to_string(),
                        "content": "hello\n", "reason": "because a test asked"
                    }),
                ),
            )
            .await;
            let answered = answered.expect("the call must answer");
            assert!(answered.get("error").is_none(), "{answered}");
            assert_ne!(answered["result"]["isError"], true, "{answered}");
            assert!(
                answered["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("written.conf"),
                "{answered}"
            );
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello\n");
            served.task.abort();
        }

        #[tokio::test]
        async fn a_session_that_was_never_opened_is_not_served() {
            // The session id is what ties a call to its connection, so a
            // server that answered for one it never issued would be answering
            // for a call it cannot watch.
            let (harness, _) = wired(60, Vec::new());
            let served = serve(Arc::clone(&harness.daemon)).await;

            let response = reqwest::Client::new()
                .post(format!("http://{}/mcp", served.addr))
                .header("Authorization", "Bearer test-token")
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .header("Mcp-Session-Id", "not-a-session-anyone-issued")
                .body(serde_json::json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/list" })
                    .to_string())
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 404);
            served.task.abort();
        }

        #[tokio::test]
        async fn a_deleted_session_stops_being_served() {
            let (harness, _) = wired(60, Vec::new());
            let served = serve(Arc::clone(&harness.daemon)).await;
            let client = reqwest::Client::new();
            let url = format!("http://{}/mcp", served.addr);

            let deleted = client
                .delete(&url)
                .header("Authorization", "Bearer test-token")
                .header("Mcp-Session-Id", &served.session)
                .send()
                .await
                .unwrap();
            assert!(deleted.status().is_success(), "{:?}", deleted.status());

            let after = client
                .post(&url)
                .header("Authorization", "Bearer test-token")
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .header("Mcp-Session-Id", &served.session)
                .body(serde_json::json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/list" })
                    .to_string())
                .send()
                .await
                .unwrap();
            assert_eq!(after.status(), 404, "a closed session must stop answering");
            served.task.abort();
        }

        #[tokio::test]
        async fn the_deadline_starts_at_the_window_and_not_at_the_queue() {
            // A request that waited its turn still gets a whole window. The
            // discriminator is the queue wait: measured from when the second
            // request arrived, its deadline has to be a full timeout *plus*
            // however long it spent waiting.
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::scratch(dir.path());
            let mut config = quick(&paths);
            config.timeout_secs = 90;
            let prompter = Arc::new(StubPrompter::new(vec![
                approve().after(Duration::from_secs(1)),
                Reply::silent(),
            ]));
            let daemon =
                Arc::new(Daemon::new(&paths, config, Arc::clone(&prompter) as Arc<_>));

            let holder = {
                let daemon = Arc::clone(&daemon);
                tokio::spawn(async move {
                    daemon.run_command(run_of("true"), Caller::quiet()).await
                })
            };
            while prompter.seen().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            let arrived = Utc::now();
            let cancelled = CancellationToken::new();
            let caller =
                Caller { cancelled: cancelled.clone(), hangup: None, progress: None };
            let queued = {
                let daemon = Arc::clone(&daemon);
                tokio::spawn(async move { daemon.run_command(run_of("true"), caller).await })
            };

            let waited = tokio::time::Instant::now();
            while prompter.seen().len() < 2 && waited.elapsed() < CEILING {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(prompter.seen().len(), 2, "the second window never opened");

            let from_arrival =
                (prompter.seen()[1].deadline - arrived).num_milliseconds();
            assert!(
                from_arrival > 90_500,
                "the second window's clock started while it was queued: {from_arrival}ms"
            );
            assert!(
                from_arrival < 95_000,
                "the deadline is not a full timeout from the window: {from_arrival}ms"
            );

            cancelled.cancel();
            within(queued).await.unwrap();
            within(holder).await.unwrap();
        }

        #[tokio::test]
        async fn the_window_and_the_log_carry_the_agents_own_words_defanged() {
            // The title frames the whole decision, and a bidi override in it
            // would reorder everything the reader sees — including the command
            // underneath it.
            let harness = Harness::new(vec![Reply::verdict(Verdict::Deny {
                note: "no".to_string(),
            })]);
            let mut params = run_of("true");
            params.title = "Install \u{202E}gnp.exe".to_string();
            params.reason = "the build needs it".to_string();
            within(harness.daemon.run_command(params, Caller::quiet())).await;

            let shown = &harness.prompter.seen()[0];
            assert!(shown.title.starts_with("Install "), "{:?}", shown.title);
            assert!(
                shown.title.contains("[RLO]"),
                "the override must be drawn, not obeyed: {:?}",
                shown.title
            );
            assert!(!shown.title.contains('\u{202E}'), "{:?}", shown.title);
            assert_eq!(shown.reason, "the build needs it");

            let record = harness.only_record();
            assert_eq!(record["title"], shown.title, "the log and the window agree: {record}");
            assert_eq!(record["reason"], "the build needs it", "{record}");
        }

        #[tokio::test]
        async fn a_write_that_did_not_happen_says_so_and_leaves_the_file_alone() {
            // Drift: the file moved between the diff the user read and the
            // write. Every `ApplyError` guarantees the file is untouched, so
            // the answer has to say that reading and asking again is safe.
            let harness = Harness::new(vec![approve().after(Duration::from_millis(300))]);
            let elsewhere = tempfile::tempdir().unwrap();
            let target = elsewhere.path().join("target.conf");
            std::fs::write(&target, b"before\n").unwrap();

            let call = {
                let daemon = Arc::clone(&harness.daemon);
                let path = target.display().to_string();
                tokio::spawn(async move {
                    daemon
                        .swap_file(
                            SwapFileParams {
                                title: "change it".to_string(),
                                path,
                                content: "after\n".to_string(),
                                reason: "because a test asked".to_string(),
                                root: false,
                            },
                            Caller::quiet(),
                        )
                        .await
                })
            };
            while harness.prompter.seen().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            std::fs::write(&target, b"somebody else got there first\n").unwrap();

            let result = within(call).await.unwrap();
            assert_eq!(result.is_error, Some(true));
            let text = result_text(&result);
            assert!(text.contains("changed after the request was approved"), "{text}");
            assert!(text.contains("asking again is safe"), "{text}");
            assert_eq!(
                std::fs::read_to_string(&target).unwrap(),
                "somebody else got there first\n",
                "a refused write must not touch the file"
            );
            assert!(
                harness.prompter.recorded()[0].sent.contains(
                    &crate::protocol::DaemonMsg::Finished(protocol::Outcome::Exit { code: 1 })
                ),
                "the window must be told it did not land: {:?}",
                harness.prompter.recorded()[0].sent
            );
            // Still one record, and still an approval: the user did approve.
            assert_eq!(harness.verdict(), "approve");
        }

        #[tokio::test]
        async fn approved_output_reaches_the_window_when_streaming_was_ticked() {
            let harness =
                Harness::new(vec![Reply::verdict(approved(true))]);
            within(harness.daemon.run_command(run_of("echo hello"), Caller::quiet())).await;
            // A streamed run detaches its window rather than closing it, so
            // the request returning is no longer the moment the pipe is
            // drained. See `StubPrompter::settled`.
            harness.prompter.settled().await;

            let recorded = harness.prompter.recorded();
            let sent = &recorded[0].sent;
            let of = |want: exec::Stream| -> String {
                sent.iter()
                    .filter_map(|msg| match msg {
                        crate::protocol::DaemonMsg::Output { stream, text } if *stream == want => {
                            Some(text.clone())
                        }
                        _ => None,
                    })
                    .collect()
            };
            assert_eq!(of(exec::Stream::Stdout), "hello\n", "{sent:?}");
            assert_eq!(of(exec::Stream::Stderr), "", "{sent:?}");
            assert!(
                !sent.iter().any(|msg| matches!(
                    msg,
                    crate::protocol::DaemonMsg::Output { text, .. } if text.is_empty()
                )),
                "a stream with nothing left over must not send an empty frame: {sent:?}"
            );
            assert!(
                sent.iter().any(|msg| matches!(
                    msg,
                    crate::protocol::DaemonMsg::Finished(protocol::Outcome::Exit { code: 0 })
                )),
                "the window is told how it ended: {sent:?}"
            );
        }

        // --- what becomes of the window ------------------------------------

        /// Which of the two things the daemon did with the window, once its
        /// channel has finished.
        async fn windup_of(harness: &Harness) -> bool {
            harness.prompter.settled().await;
            harness.prompter.recorded()[0].detached
        }

        #[tokio::test]
        async fn a_run_the_reader_asked_to_watch_leaves_its_window_with_them() {
            // The window outlives the request on purpose: it is showing the
            // output to the person who ticked the box, and the agent's result
            // must not wait for them to finish reading it.
            let harness = Harness::new(vec![Reply::verdict(approved(true))]);
            let result =
                within(harness.daemon.run_command(run_of("echo hello"), Caller::quiet())).await;

            assert_eq!(result.is_error, Some(false), "{result:?}");
            assert!(
                windup_of(&harness).await,
                "the window was killed at the moment it had something to show"
            );
            assert_eq!(harness.verdict(), "approve");
        }

        #[tokio::test]
        async fn a_run_nobody_asked_to_watch_has_its_window_ended_as_before() {
            let harness = Harness::new(vec![approve()]);
            within(harness.daemon.run_command(run_of("echo hello"), Caller::quiet())).await;

            assert!(!windup_of(&harness).await, "a headless run left a window behind");
        }

        #[tokio::test]
        async fn a_swap_has_its_window_ended_whatever_the_stream_box_said() {
            // A swap writes a file and prints nothing, so there is nothing to
            // linger over. The checkbox is not even offered for one, and a
            // window that stayed anyway would be an empty viewer.
            let harness = Harness::new(vec![Reply::verdict(approved(true))]);
            let target = harness.dir.path().join("swapped");
            within(harness.daemon.swap_file(
                SwapFileParams {
                    title: "write a file".to_string(),
                    path: target.display().to_string(),
                    content: "hello\n".to_string(),
                    reason: "because a test asked".to_string(),
                    root: false,
                },
                Caller::quiet(),
            ))
            .await;

            assert!(!windup_of(&harness).await, "a swap left a window behind");
        }

        #[tokio::test]
        async fn a_command_that_could_not_be_started_leaves_no_window_behind() {
            // No outcome frame is sent on this path, so the window is still
            // drawing "it is running" and nothing will ever tell it otherwise.
            // Handing that one to a reader would be handing them an orphan.
            let harness = Harness::new(vec![Reply::verdict(approved(true))]);
            let mut params = run_of("echo hello");
            // A working directory that is one, so it passes validation, and
            // that cannot be entered, so the spawn fails. Nothing ran and
            // nobody decided anything.
            let shut = harness.dir.path().join("shut");
            std::fs::create_dir_all(&shut).unwrap();
            std::fs::set_permissions(&shut, std::os::unix::fs::PermissionsExt::from_mode(0o000))
                .unwrap();
            params.cwd = Some(shut.display().to_string());
            let result = within(harness.daemon.run_command(params, Caller::quiet())).await;
            // Put it back, or the temporary directory cannot be cleaned up.
            std::fs::set_permissions(&shut, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .unwrap();

            assert_eq!(result.is_error, Some(true), "{result:?}");
            assert!(!windup_of(&harness).await, "a window that was told nothing was left open");
        }

        #[tokio::test]
        async fn a_character_left_unfinished_is_flushed_to_the_stream_it_came_from() {
            // Two bytes of a three-byte character on stdout and nothing after
            // them: the pump holds them waiting for a third byte that never
            // arrives, and the final flush has to draw them as what they are —
            // on the stream they were written to, not the other one.
            let harness =
                Harness::new(vec![Reply::verdict(approved(true))]);
            within(harness.daemon.run_command(
                run_of("printf '\\342\\202' ; printf 'e' 1>&2"),
                Caller::quiet(),
            ))
            .await;

            let outputs: Vec<(exec::Stream, String)> = harness.prompter.recorded()[0]
                .sent
                .iter()
                .filter_map(|msg| match msg {
                    crate::protocol::DaemonMsg::Output { stream, text } => {
                        Some((*stream, text.clone()))
                    }
                    _ => None,
                })
                .collect();
            assert!(
                outputs.contains(&(exec::Stream::Stdout, "\u{fffd}".to_string())),
                "the unfinished character belongs to stdout: {outputs:?}"
            );
            assert!(
                outputs.contains(&(exec::Stream::Stderr, "e".to_string())),
                "and stderr keeps its own byte: {outputs:?}"
            );
        }

        #[tokio::test]
        async fn output_is_not_streamed_when_the_box_was_not_ticked() {
            let harness = Harness::new(vec![approve()]);
            within(harness.daemon.run_command(run_of("echo hello"), Caller::quiet())).await;

            let sent = &harness.prompter.recorded()[0].sent;
            assert!(
                !sent
                    .iter()
                    .any(|msg| matches!(msg, crate::protocol::DaemonMsg::Output { .. })),
                "streaming is a display preference, and it was off: {sent:?}"
            );
        }
    }

    // --- the calls the transport is watching ---------------------------------

    #[test]
    fn a_call_is_watched_until_its_stream_ends_and_then_forgotten() {
        // The registry exists only so a cancellation arriving on another
        // connection can find the call it names. An entry that outlived its
        // stream would be a slow leak in a daemon that runs for weeks.
        let calls = Arc::new(Calls::default());
        let id = RequestId::Number(7);
        let hangup = calls.begin(id.clone());
        assert_eq!(calls.open(), 1);
        assert!(!hangup.gone().is_cancelled());
        assert!(!hangup.was_cancelled());

        calls.note_cancelled(&id);
        assert!(hangup.was_cancelled(), "the flag must reach the handle the flow holds");

        let end = StreamEnd { id: id.clone(), hangup: hangup.clone(), calls: Arc::clone(&calls) };
        drop(end);
        assert!(hangup.gone().is_cancelled(), "the end of the stream is the end of the call");
        assert_eq!(calls.open(), 0, "the entry outlived the stream it belonged to");

        // A notification for a call nobody is watching is not a panic.
        calls.note_cancelled(&id);
    }

    #[test]
    fn a_call_that_was_never_cancelled_reads_as_a_disconnect() {
        let caller = Caller {
            cancelled: CancellationToken::new(),
            hangup: Some(Hangup::new()),
            progress: None,
        };
        assert_eq!(caller.abandonment(), LogVerdict::Disconnected);

        let hangup = Hangup::new();
        hangup.note_cancelled();
        let flagged = Caller {
            cancelled: CancellationToken::new(),
            hangup: Some(hangup),
            progress: None,
        };
        assert_eq!(flagged.abandonment(), LogVerdict::Cancelled);

        let token = CancellationToken::new();
        token.cancel();
        let told = Caller { cancelled: token, hangup: None, progress: None };
        assert_eq!(told.abandonment(), LogVerdict::Cancelled);
    }

    // --- what each outcome says ---------------------------------------------

    /// Every verdict that refuses, which is every verdict but the one that
    /// runs something.
    ///
    /// Off [`crate::protocol::every_verdict`] rather than written out, so a
    /// verdict added to the protocol is a verdict these tests start asking
    /// about on their own.
    fn refusing_verdicts() -> Vec<crate::protocol::Verdict> {
        crate::protocol::every_verdict()
            .into_iter()
            .filter(|verdict| !matches!(verdict, crate::protocol::Verdict::Approve { .. }))
            .collect()
    }

    /// What the agent must be told, and what the log must say, for one
    /// refusing verdict.
    ///
    /// The match is exhaustive on purpose: a new verdict does not compile
    /// until somebody has decided what it says to an agent, which is the one
    /// thing about it that must not be arrived at by accident.
    fn expected_of(verdict: &crate::protocol::Verdict) -> (&'static str, LogVerdict) {
        use crate::protocol::{ReviseKind, Verdict};
        match verdict {
            Verdict::Deny { .. } => ("denied by user", LogVerdict::Deny),
            Verdict::Revise { kind: ReviseKind::Explain, .. } => {
                ("asks you to explain", LogVerdict::Explain)
            }
            Verdict::Revise { kind: ReviseKind::Simplify, .. } => {
                ("more legible form", LogVerdict::Simplify)
            }
            Verdict::SelfRun { .. } => ("will run this themselves", LogVerdict::SelfRun),
            Verdict::StopAndSync { .. } => ("stopped to sync with you", LogVerdict::StopAndSync),
            // `refusing_verdicts` filters it out, and `declined` refuses to
            // treat it as a refusal at all.
            Verdict::Approve { .. } => unreachable!("an approval is not a refusal"),
        }
    }

    fn a_run_detail() -> LogDetail {
        LogDetail::RunCommand(RunDetail {
            command: "true".to_string(),
            root: false,
            cwd: "/".to_string(),
            exit_code: None,
            duration_ms: None,
            killed_by_user: None,
            timed_out: None,
            prompt_died_after_approve: None,
        })
    }

    #[test]
    fn the_users_own_words_are_labelled_as_theirs_and_hatchs_are_left_alone() {
        // A result is hatch's account of what happened with one person's
        // sentence at the end of it, and an agent reading them as one voice
        // is wrong in both directions at once.
        let hatchs = "wrote /etc/hosts: 42 bytes, mode 0644, owner root:root\n\
                      hatch could not re-examine the file to confirm this";
        let plain = CallToolResult::success(vec![ContentBlock::text(hatchs.to_string())]);

        let labelled = result_text(&with_note(plain.clone(), "put the old one back after"));
        assert!(labelled.starts_with(hatchs), "hatch's own report was rewritten: {labelled}");
        assert_eq!(
            labelled,
            format!("{hatchs}\n\nthe user's note: put the old one back after"),
            "the label goes on the person's text and on nothing else"
        );
        assert!(
            labelled[hatchs.len()..].contains(USER_NOTE_PREFIX),
            "the prefix must sit between the two voices, not inside hatch's"
        );

        // Nothing typed, nothing said -- not a label over an empty line.
        for silence in ["", "   ", "\n"] {
            assert_eq!(
                result_text(&with_note(plain.clone(), silence)),
                hatchs,
                "{silence:?} was reported as something the person said"
            );
        }

        // An approval whose operation failed still carries it: the person
        // spoke to the agent, not to the exit status.
        let failed = CallToolResult::error(vec![ContentBlock::text("the write failed".to_string())]);
        let failed = with_note(failed, "leave it, I will look");
        assert_eq!(failed.is_error, Some(true), "a note must not turn a failure into a success");
        assert!(result_text(&failed).contains("the user's note: leave it, I will look"));
    }

    #[test]
    fn each_verdict_maps_to_its_own_sentence_and_its_own_log_line() {
        use crate::protocol::Verdict;

        let refusing = refusing_verdicts();
        let mut sentences = Vec::new();
        for verdict in &refusing {
            let (needle, logged) = expected_of(verdict);
            let outcome = declined(verdict.clone(), a_run_detail());
            assert_eq!(outcome.verdict, logged, "{verdict:?}");
            assert_eq!(outcome.result.is_error, Some(true), "{verdict:?}");
            let text = result_text(&outcome.result);
            assert!(text.contains(needle), "{verdict:?} said {text}");
            // The user's own words, wherever the sentence puts them.
            let note = match verdict {
                Verdict::Deny { note }
                | Verdict::Revise { note, .. }
                | Verdict::SelfRun { note }
                | Verdict::StopAndSync { note } => note.as_str(),
                Verdict::Approve { .. } => unreachable!("an approval is not a refusal"),
            };
            assert!(text.contains(note), "{verdict:?} dropped the note: {text}");
            sentences.push(text);
        }
        sentences.sort();
        sentences.dedup();
        assert_eq!(
            sentences.len(),
            refusing.len(),
            "two verdicts that read the same are one verdict"
        );

        // An approval must never be reported as a refusal. It cannot arrive
        // here, and if it ever did the answer says so rather than inventing a
        // denial nobody made.
        let stray = declined(crate::protocol::approved(false), a_run_detail());
        assert_eq!(stray.result.is_error, Some(true));
        assert!(result_text(&stray.result).contains("mishandled"));
    }

    #[test]
    fn a_lost_client_and_a_cancelled_call_read_differently() {
        use crate::audit::LogVerdict;
        let cancelled = abandoned(LogVerdict::Cancelled, a_run_detail());
        let dropped = abandoned(LogVerdict::Disconnected, a_run_detail());
        assert_eq!(cancelled.verdict, LogVerdict::Cancelled);
        assert_eq!(dropped.verdict, LogVerdict::Disconnected);
        assert_eq!(cancelled.result.is_error, Some(true));
        assert_eq!(dropped.result.is_error, Some(true));
        assert!(result_text(&cancelled.result).contains("cancelled"));
        assert!(result_text(&dropped.result).contains("connection"));
        for outcome in [&cancelled, &dropped] {
            assert!(
                result_text(&outcome.result).contains("Nobody refused this"),
                "an abandonment is not a decision anybody made"
            );
        }
    }

    #[test]
    fn a_run_that_was_cut_short_never_reads_as_a_complete_one() {
        let full = Output {
            stdout: "hello\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            signal: None,
            timed_out: false,
            killed_by_user: false,
            stdout_truncated: false,
            stderr_truncated: false,
        };
        let text = describe_run(&full, Duration::from_millis(12));
        assert!(text.contains("exit code: 0"), "{text}");
        assert!(text.contains("12ms"), "{text}");
        assert!(
            text.contains("stdout:\nhello\n\nstderr:"),
            "a stream that already ends in a newline must not gain another: {text}"
        );
        assert!(!text.contains("timed out"), "{text}");
        assert!(!text.contains("killed"), "{text}");
        assert!(text.contains("stderr:\n(empty)"), "an empty stream says so: {text}");

        let cut = Output {
            stdout: "part".to_string(),
            stderr: "noise".to_string(),
            exit_code: None,
            signal: Some(9),
            timed_out: true,
            killed_by_user: true,
            stdout_truncated: true,
            stderr_truncated: true,
        };
        let text = describe_run(&cut, Duration::from_secs(1));
        assert!(text.contains("signal 9"), "{text}");
        assert!(text.contains("timed out"), "{text}");
        assert!(text.contains("killed"), "{text}");
        assert_eq!(text.matches("truncated").count(), 2, "each stream reports for itself: {text}");
    }

    #[test]
    fn the_window_is_only_told_something_that_is_true() {
        let exited = Output {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(7),
            signal: None,
            timed_out: false,
            killed_by_user: false,
            stdout_truncated: false,
            stderr_truncated: false,
        };
        assert_eq!(finished_frame(&exited), Some(protocol::Outcome::Exit { code: 7 }));

        let signalled = Output { exit_code: None, signal: Some(9), ..exited.clone() };
        assert_eq!(finished_frame(&signalled), Some(protocol::Outcome::Signal { signal: 9 }));

        // Neither: nothing true can be said about how it ended, so nothing is
        // said. An invented exit code is exactly the plausible-looking lie
        // this project refuses everywhere else.
        let neither = Output { exit_code: None, signal: None, ..exited };
        assert_eq!(finished_frame(&neither), None);
    }

    #[test]
    fn a_write_that_did_not_happen_says_the_file_is_untouched() {
        // Every `ApplyError` guarantees it, so saying so is the difference
        // between an agent that re-reads and asks again and one that gives up.
        let text = describe_apply(&ApplyError::Collision);
        assert!(text.contains("the write did not happen"), "{text}");
        assert!(text.contains("exactly as it was"), "{text}");
        assert!(text.contains("asking again is safe"), "{text}");
        assert!(
            text.contains(&ApplyError::Collision.to_string()),
            "the reason itself must survive: {text}"
        );
    }

    #[test]
    fn the_recorded_hash_is_the_hash_of_the_bytes() {
        // `sha256sum` prints this form, so a user can check the log line
        // against the file by eye.
        assert_eq!(
            sha256_hex(b"hello\n"),
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
        assert_eq!(sha256_hex(b"").len(), 64);
    }

    #[test]
    fn an_unsupported_request_is_worded_as_a_limit_and_not_as_a_decision() {
        for text in [
            not_yet("do the thing", "Try the other thing."),
            refusal_text("this path is protected"),
        ] {
            assert!(text.contains("nothing ran"), "{text}");
            assert!(text.contains("not a decision by the user"), "{text}");
            assert!(text.contains("nobody was asked"), "{text}");
        }
    }

    // --- decoding across chunk boundaries -----------------------------------

    #[test]
    fn a_character_split_across_chunks_is_held_until_it_is_whole() {
        let mut buffer = Vec::new();
        // The first two bytes of a three-byte character.
        buffer.extend_from_slice("ok\u{20ac}".as_bytes()[..4].as_ref());
        assert_eq!(take_decodable(&mut buffer).as_deref(), Some("ok"));
        assert_eq!(buffer.len(), 2, "the unfinished character stays");

        buffer.extend_from_slice(&"\u{20ac}".as_bytes()[2..]);
        assert_eq!(take_decodable(&mut buffer).as_deref(), Some("\u{20ac}"));
        assert!(buffer.is_empty());
    }

    #[test]
    fn a_sequence_that_can_never_be_valid_is_not_held_forever() {
        let mut buffer = vec![b'a', 0xff, b'b'];
        let taken = take_decodable(&mut buffer).unwrap();
        assert!(taken.starts_with('a'), "{taken:?}");
        assert!(taken.contains('\u{fffd}'), "the bad byte is drawn as what it is: {taken:?}");
        assert!(buffer.is_empty() || buffer == b"b");
    }

    #[test]
    fn nothing_decodable_yet_sends_nothing() {
        let mut buffer = vec![0xe2];
        assert_eq!(take_decodable(&mut buffer), None);
        assert_eq!(buffer, vec![0xe2]);
        assert_eq!(take_decodable(&mut Vec::new()), None);
    }
}
