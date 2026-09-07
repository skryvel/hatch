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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use rmcp::ErrorData;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ListToolsResult, PaginatedRequestParams, Tool};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{RoleServer, ServerHandler, tool, tool_handler, tool_router};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

use crate::config::{self, Config};

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
    // Read by the request flow, which lands next.
    #[allow(dead_code)]
    pub root: bool,
    /// Absolute working directory.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Whether the command needs a terminal.
    #[serde(default)]
    // Read by the request flow, which lands next.
    #[allow(dead_code)]
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
    // Read by the request flow, which lands next.
    #[allow(dead_code)]
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
         The person may reject the command, or edit it before it runs. You get back what \
         actually happened, which is not always what you asked for.\n\
         \n\
         Fields:\n\
         - title: the intent in one plain line. It is the first thing the person reads, so write \
         \"Install ripgrep\", not \"pacman -S ripgrep\". The point, not the syntax.\n\
         - command: the exact command, run through a shell.\n\
         - reason: why this is needed now, in a sentence or two.\n\
         - cwd: absolute working directory. Optional.\n\
         - interactive: true if the command needs a terminal — a full-screen program, a pager, a \
         prompt that expects typing.\n\
         - root: leave it false. Root is not available yet and asking for it fails the call."
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
         - root: leave it false. Root is not available yet and asking for it fails the call."
    );

    ToolDescriptions { run_command, swap_file }
}

/// The MCP server. One is built per client session by the transport's
/// factory; they share the daemon's config.
pub struct Hatch {
    config: Arc<Config>,
    tool_router: ToolRouter<Hatch>,
}

#[tool_router]
impl Hatch {
    /// A server bound to `config`.
    pub fn new(config: Arc<Config>) -> Hatch {
        Hatch { config, tool_router: Hatch::tool_router() }
    }

    /// The declared tools, with their static descriptions replaced by the
    /// ones built from the running config.
    ///
    /// A tool with no runtime description keeps its static one rather than
    /// losing it; `every_tool_has_a_runtime_description` is what makes sure
    /// that fallback is never actually taken.
    fn described_tools(&self) -> Vec<Tool> {
        let descriptions = tool_descriptions(&self.config);
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
    #[tool(description = "Run a shell command on the host, outside the sandbox.")]
    async fn run_command(
        &self,
        Parameters(params): Parameters<RunCommandParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // The cap runs before anything else touches these strings. Rendering
        // is where the super-linear work lives, so checking afterwards would
        // check nothing.
        if let Err(refusal) = check_run_command(&params) {
            return Ok(CallToolResult::error(vec![ContentBlock::text(refusal)]));
        }
        Ok(not_implemented_yet("run a command"))
    }

    // See the note on `run_command`: this description is a placeholder.
    #[tool(description = "Write a file on the host, outside the sandbox.")]
    async fn swap_file(
        &self,
        Parameters(params): Parameters<SwapFileParams>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(refusal) = check_swap_file(&params) {
            return Ok(CallToolResult::error(vec![ContentBlock::text(refusal)]));
        }
        Ok(not_implemented_yet("write a file"))
    }
}

/// The stand-in body every tool returns until the request flow exists.
///
/// The request flow — queue admission, the approval window, the verdict and
/// the execution it authorises — lands next. It is a tool error, not a
/// protocol error, so the agent reads the sentence instead of being told the
/// server is broken.
fn not_implemented_yet(what: &str) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(format!(
        "hatch cannot {what} yet: this build declares the tool but does not carry the approval \
         flow behind it. Nothing was shown to anyone and nothing ran."
    ))])
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
pub fn app(config: Arc<Config>) -> Router {
    let expected = Arc::new(digest(config.token.as_bytes()));

    let service = StreamableHttpService::new(
        {
            let config = Arc::clone(&config);
            move || Ok(Hatch::new(Arc::clone(&config)))
        },
        Arc::new(LocalSessionManager::default()),
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
             port; stop it, or set a different `port` in config.toml"
        )
    })
}

/// Delete whatever the last run left in `<dir>/stage`.
///
/// Staged bytes are approved-but-unwritten file contents. A run that died
/// between approval and the write leaves them there, and nothing that comes
/// later has any way to tell them apart from its own. They are not a cache to
/// reuse: an operation the user approved yesterday is not one they approved
/// now.
fn sweep_stage(dir: &Path) -> anyhow::Result<()> {
    let stage = dir.join("stage");
    let entries = std::fs::read_dir(&stage)
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
    let dir = config::default_dir()?;
    let config = Config::load_or_create(&dir)?;
    sweep_stage(&dir)?;

    let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;
    runtime.block_on(async move {
        let listener = bind(config.port).await?;
        config::print_client_line_for(&config)?;
        axum::serve(listener, app(Arc::new(config))).await.context("serving MCP")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::sync::Arc;
    use std::time::Duration;

    /// Every test here waits on a socket or a task. None may outlive this.
    const CEILING: Duration = Duration::from_secs(10);

    /// Bind a server on an ephemeral loopback port and return its address.
    async fn spawn(config: Config) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let config = Arc::new(config);
        let listener = bind(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = app(config);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (addr, handle)
    }

    fn test_config() -> Config {
        Config { token: "test-token".to_string(), ..Config::default() }
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
        assert!(text.contains("390"), "the blocking bound must be the full one: {text}");
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
        let hatch = Hatch::new(Arc::new(test_config()));
        let over = run_params("command", "a".repeat(MAX_COMMAND_BYTES + 1));
        let result = hatch.run_command(Parameters(over)).await.unwrap();
        assert_eq!(result.is_error, Some(true));
        let text = result_text(&result);
        assert!(text.contains("`command` is"), "the cap must answer, not the body: {text}");
    }

    #[tokio::test]
    async fn a_call_within_the_cap_reaches_the_body() {
        let hatch = Hatch::new(Arc::new(test_config()));
        let within = run_params("command", "a".repeat(MAX_COMMAND_BYTES));
        let text = result_text(&hatch.run_command(Parameters(within)).await.unwrap());
        assert!(text.contains("cannot run a command yet"), "{text}");

        let within = swap_params("content", "a".repeat(MAX_CONTENT_BYTES));
        let text = result_text(&hatch.swap_file(Parameters(within)).await.unwrap());
        assert!(text.contains("cannot write a file yet"), "{text}");
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
        let names: Vec<String> = Hatch::new(Arc::new(test_config()))
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
        for tool in Hatch::new(Arc::new(config)).described_tools() {
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
        for tool in Hatch::new(Arc::new(config)).described_tools() {
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
                    description.contains("390"),
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
    fn the_sweep_clears_what_a_crashed_run_left_staged() {
        let dir = tempfile::tempdir().unwrap();
        Config::load_or_create(dir.path()).unwrap();
        let stage = dir.path().join("stage");
        std::fs::write(stage.join("leftover"), b"approved yesterday, never written").unwrap();
        std::fs::create_dir(stage.join("nested")).unwrap();
        std::fs::write(stage.join("nested").join("deeper"), b"more of it").unwrap();

        sweep_stage(dir.path()).unwrap();

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
}
