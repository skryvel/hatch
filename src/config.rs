//! Config load/create, token generation, client registration line.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::Context;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::paths::Paths;
use crate::prompt_ui::theme::Theme;

/// Bytes of entropy behind the bearer token.
const TOKEN_BYTES: usize = 32;

/// How long a request waits for a human decision unless the config says
/// otherwise.
///
/// Ten minutes, where this was ninety seconds. The old number was caution
/// about the MCP client giving up on a call while a window was still open,
/// and the caution was misplaced: nothing downstream enforces anything near
/// it. A client's ceiling is its own setting and is hours rather than
/// minutes, and the idle timer that would otherwise fire under a window is
/// reset by the progress notification hatch already sends every few seconds
/// for the whole life of a request — see `PROGRESS_INTERVAL`.
///
/// What ninety seconds did bound was the reader. It is the time a person gets
/// to read a command **from the moment the window appears**, not from when
/// they notice it, and for anything longer than one line it ran out while
/// they were still reading. A timeout resolves as a denial, so the cost of
/// the low number was landing on the agent as a refusal nobody made.
///
/// The bound that still matters is the sum of this,
/// [`Config::exec_timeout_secs`] and [`Config::review_timeout_secs`], which the
/// tool descriptions state and `hatch serve` prints. Raising this raises that
/// twice over, because the review deadline is this number too, and the README
/// says so.
const DEFAULT_TIMEOUT_SECS: u64 = 600;

/// How long an approved command may run unless the config says otherwise.
///
/// Five minutes. A runaway-process guard rather than a budget: an approved
/// command that is still going after this is more likely wedged than slow,
/// and the result it has produced so far is returned with a marker saying it
/// was cut short. A package upgrade or a long build is the case that wants
/// this raised, and raising it is a line in the config.
const DEFAULT_EXEC_TIMEOUT_SECS: u64 = 300;

/// Point size the approval window draws at unless the config says otherwise.
///
/// Larger than egui's own default, which is tuned for dense tool windows. This
/// one is a window a person is asked to *read* — a command they are about to
/// let run unsandboxed on their machine — on a 1280-point window on a desktop
/// display, and at egui's default it reads as cramped.
const DEFAULT_FONT_SIZE: u32 = 16;

/// The range a font size is held to.
///
/// Not a safety boundary; a legibility one. Below the floor the window has
/// text nobody can read and above the ceiling it has two words in it, and
/// both are ways for a config typo to produce a window that cannot be used
/// rather than an error anyone would see.
const FONT_SIZE_RANGE: std::ops::RangeInclusive<u32> = 8..=48;

/// On-disk settings, read from and written to
/// `$XDG_CONFIG_HOME/hatch/config.toml` — `~/.config/hatch/config.toml` unless
/// the variable says otherwise. See [`crate::paths`] for the other two
/// directories, which are not here and not next to this one.
///
/// Every field has a default and the struct carries `#[serde(default)]`, so a
/// config file written by an older build keeps loading unchanged after new
/// fields are added.
///
/// `exec_env` is declared last only so the written file reads scalars first;
/// the serializer emits tables after plain values whatever the field order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Loopback port the MCP server listens on.
    pub port: u16,
    /// Bearer token the client must present. Empty in `Config::default()`;
    /// `load_or_create` generates one and writes it back. It is the reason
    /// this file is 0600 and re-tightened on every load.
    pub token: String,
    /// How long a request waits for a human decision. See
    /// [`DEFAULT_TIMEOUT_SECS`] for why the default is what it is.
    pub timeout_secs: u64,
    /// How long an approved command may run.
    pub exec_timeout_secs: u64,
    /// Cap on captured command output.
    pub output_cap_bytes: usize,
    /// `PATH` handed to approved commands.
    ///
    /// hatch **constructs** the child environment rather than inheriting one
    /// — see [`crate::exec::env`] for why — so this is the whole of where an
    /// approved command's names are looked up. A program the person can run
    /// in their own shell is not on this `PATH` unless this key says so, and
    /// the window says as much before anybody approves anything: the roster
    /// resolves every name against exactly this value and reports the ones
    /// nothing answers to.
    ///
    /// The default is per-platform for that reason, and per-platform is still
    /// only a starting point: see [`default_exec_path`].
    pub exec_path: String,
    /// The terminal an interactive run opens, as argv with the program first.
    ///
    /// **The approved command's runner is appended to this list**, so what is
    /// written here is everything up to but not including the program the
    /// terminal is being asked to start. That is the whole contract, and the
    /// two terminals this has been tested against want different things from
    /// it:
    ///
    /// | Terminal | Value | Why |
    /// |---|---|---|
    /// | konsole | `["konsole", "--nofork", "-e"]` | `-e` takes the command and every argument after it |
    /// | kitty | `["kitty"]` | the program is a positional argument; kitty has no `-e`, and passing one makes it parse the line as something else entirely |
    ///
    /// **Empty is a valid value and the default on every platform but Linux.**
    /// It means this build has no terminal it has been tested against, and
    /// the interactive path says so rather than naming a program that is not
    /// there: see [`default_terminal`] and
    /// [`crate::exec::interactive::unavailable`].
    ///
    /// `--nofork` on konsole is not decoration. Without it a konsole started
    /// while the "run all Konsole windows in a single process" setting is on
    /// hands its arguments to the konsole that is already running and returns
    /// immediately, which puts the command in a process hatch did not start
    /// and cannot reach: the Kill button would stop nothing, and hatch would
    /// have to give up on the run and say it could not tell how it ended. The
    /// flag says "run in a separate process", which is the arrangement
    /// everything on this path depends on.
    ///
    /// Nothing here is asked for the command's exit status, so a terminal that
    /// does not report one — kitty exits `0` whatever its program did — is
    /// still a usable terminal. See [`crate::exec::interactive`].
    pub terminal: Vec<String>,
    /// Extra denylist patterns, appended to the built-in ones. Each entry must
    /// be an **absolute, literal path prefix**: `~` is not expanded and a
    /// relative entry can never match, so either one silently protects nothing.
    pub denylist_extra: Vec<String>,
    /// Point size the approval window draws body and monospace text at.
    ///
    /// A genuine per-user preference — display DPI, eyesight, viewing
    /// distance — and nothing about it is a safety property, which is what
    /// separates it from the typing guard's 750 ms. That interval is
    /// deliberately not a key here, because a setting inviting it to be
    /// lowered to zero is a liability; a font size cannot be set to a value
    /// that approves anything.
    ///
    /// Whole points rather than a float, so that the natural thing to write
    /// in the file — `font_size = 16` — parses. TOML does not widen an
    /// integer into a float, so an `f32` field would reject exactly what a
    /// reader would type, and a config that fails to parse is a daemon that
    /// does not start.
    ///
    /// Read through [`Config::font_size_points`], never directly: it is the
    /// clamp, and an unclamped 0 is a window with no text in it.
    pub font_size: u32,
    /// Which palette the approval window draws in: `dark` or `light`.
    ///
    /// A preference on exactly the same terms as `font_size`, and here for
    /// the same reason: how well a person reads off a screen is about the
    /// screen and the room it is in, and nothing in either palette decides
    /// anything. Both carry every meaning the window has — see
    /// [`crate::prompt_ui::theme`], where the claim that they do is a test.
    ///
    /// A word rather than a boolean, so the file says what it means and so a
    /// third palette would be a value rather than a schema change.
    pub theme: Theme,
    /// The complete child environment, on top of `exec_path` as `PATH`.
    pub exec_env: BTreeMap<String, String>,
}

/// The `PATH` an approved command is given, on the platform this build is for.
///
/// Linux gets the three directories a distribution puts programs in. macOS
/// gets those and both Homebrew prefixes in front — `/opt/homebrew/bin` on
/// Apple silicon, `/usr/local/bin` on Intel — because on macOS the system
/// ships almost nothing a person installs for themselves, and a `PATH`
/// without Homebrew on it is one where a name the person types every day
/// resolves to nothing.
///
/// Both prefixes unconditionally rather than whichever exists. Nothing is
/// probed and no architecture is guessed: a directory that is not there costs
/// a failed `stat` per lookup and changes no answer, and a default that
/// depended on what was installed at the moment the config was written would
/// be a default that silently meant different things on two machines.
///
/// Still a starting point rather than an answer. Nothing here can know where
/// somebody keeps their own tools — a version manager, `~/.local/bin`, a
/// language toolchain — and the window is what makes the gap visible: the
/// roster resolves against this value and names what it could not find.
pub fn default_exec_path() -> String {
    exec_path_for_os(std::env::consts::OS)
}

/// The whole of [`default_exec_path`] except for asking which platform this
/// is, so the arm that is not selected here is still covered by tests here.
/// See [`terminal_for_os`], which is split for the same reason.
fn exec_path_for_os(os: &str) -> String {
    match os {
        "macos" => "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin".to_string(),
        _ => "/usr/local/bin:/usr/bin:/bin".to_string(),
    }
}

/// The terminal an interactive run opens, on the platform this build is for.
///
/// Linux gets konsole; every other platform gets nothing, and nothing is the
/// honest answer rather than a gap. A default is a claim that the program
/// named works here, and the only terminals this path has been run against
/// are Linux ones — a macOS build that wrote `konsole` into a fresh config
/// would be telling its owner to go and start a KDE program.
///
/// The absence is not a dead end: [`Config::terminal`] is a config key, and a
/// machine with a terminal hatch has never heard of is one line away from
/// using it. What the empty default buys is that the window and the refusal
/// can say *"no terminal is configured"*, which is true and actionable,
/// instead of *"konsole could not be started"*, which sends the reader after
/// a program they were never going to have.
pub fn default_terminal() -> Vec<String> {
    terminal_for_os(std::env::consts::OS)
}

/// The whole of [`default_terminal`] except for asking which platform this
/// is, so the arm that is not selected here is still covered by tests here.
///
/// The same argument [`crate::exec::elevate::platform`] makes: a branch whose
/// only test run is on the platform where it is never taken is a branch with
/// no test at all.
fn terminal_for_os(os: &str) -> Vec<String> {
    match os {
        "linux" => ["konsole", "--nofork", "-e"].map(str::to_string).to_vec(),
        _ => Vec::new(),
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut exec_env = BTreeMap::new();
        exec_env.insert("HOME".to_string(), default_home());
        exec_env.insert("TERM".to_string(), "xterm-256color".to_string());

        Self {
            port: 8787,
            token: String::new(),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            exec_timeout_secs: DEFAULT_EXEC_TIMEOUT_SECS,
            output_cap_bytes: 262144,
            exec_path: default_exec_path(),
            terminal: default_terminal(),
            denylist_extra: Vec::new(),
            font_size: DEFAULT_FONT_SIZE,
            theme: Theme::default(),
            exec_env,
        }
    }
}

impl Config {
    /// Load the config file, creating every directory hatch needs if absent:
    /// the config, state and runtime ones and the `log/` and `stage/` inside
    /// the last two. A config with no token — a brand new one, or an existing
    /// file that never had the key — gets a fresh token written back, so
    /// `hatch serve` and `hatch token` agree across restarts.
    ///
    /// Each directory is created at 0700 and, if it was already there at a
    /// laxer mode, brought back to 0700. The XDG spec asks for exactly this of
    /// anything an application creates under the base directories, and here it
    /// is load-bearing rather than tidy: `log/` records full command text and
    /// `stage/` holds file content that has been approved but not yet written.
    pub fn load_or_create(paths: &Paths) -> anyhow::Result<Config> {
        create_private_dir(paths.config_dir())?;
        create_private_dir(&paths.log_dir())?;
        create_private_dir(&paths.stage_dir())?;

        let path = paths.config_file();
        let existed = path.exists();
        let mut config = if existed { read_private(&path)? } else { Config::default() };

        if config.token.is_empty() {
            config.token = generate_token();
            if existed {
                // The file is there but carries no token — someone wrote a
                // config by hand, or upgraded from a build that had no such
                // key. Ours replaces it.
                write_private(&path, &config)?;
            } else if !create_private(&path, &config)? {
                // First run, and another process got there first. Its token
                // is the one on disk and the one `hatch token` will print;
                // ours never landed. Adopt theirs rather than authenticating
                // against a token nobody was ever shown.
                config = read_private(&path)?;
            }
        }
        Ok(config)
    }

    /// The point size the window draws at, clamped to something legible.
    ///
    /// Clamped rather than rejected: a font size is a preference and a typo in
    /// one is not worth refusing to open a window over, which on this path
    /// would resolve as a denial of the request the user was about to read.
    pub fn font_size_points(&self) -> f32 {
        self.font_size.clamp(*FONT_SIZE_RANGE.start(), *FONT_SIZE_RANGE.end()) as f32
    }

    /// How long a reader who asked to see a command's output before the agent
    /// does has to decide what of it to send.
    ///
    /// # The approval deadline, again
    ///
    /// Not a key of its own, and not a shorter number. A review is the same
    /// person making the same kind of decision about the same command — read
    /// something, then say what may go — and what [`DEFAULT_TIMEOUT_SECS`]
    /// says about the approval is true here word for word: the time is
    /// counted from when the screen appears and not from when it is noticed,
    /// and a deadline that ran out while somebody was still reading five
    /// hundred lines would be the review deciding instead of the reader. So
    /// it is that number, and a person who has raised one has raised both.
    ///
    /// What happens at it is not what happens at the approval deadline, and
    /// that is deliberate too: an unanswered review sends nothing. See
    /// `crate::server`, where the output is withheld.
    pub fn review_timeout_secs(&self) -> u64 {
        self.timeout_secs
    }

    /// The longest a client call can block: the approval wait followed by a
    /// full-length execution, and a full-length review, of every operation
    /// the largest batch may carry.
    pub fn client_timeout_secs(&self) -> u64 {
        self.blocking_bound_secs(crate::server::MAX_OPERATIONS)
    }

    /// The longest a call carrying `operations` operations can block.
    ///
    /// The approval deadline is counted once, and the execution timeout and
    /// the review deadline once per operation, because that is how each is
    /// enforced: one window covers the whole batch, every operation that runs
    /// a process runs it under a deadline of its own, and every command whose
    /// reader asked to review it is reviewed on its own. A description that
    /// multiplied the approval wait would overstate the bound, and one that
    /// counted a single execution for a batch would understate it by every
    /// operation after the first.
    ///
    /// The review term is counted whether or not anybody ticks the box. The
    /// bound is what an agent plans around and what a client's timeout is set
    /// from, and neither can know in advance which call a person will choose
    /// to read; a number that left the review out would be one the first
    /// reviewed call overran.
    pub fn blocking_bound_secs(&self, operations: usize) -> u64 {
        self.timeout_secs
            + operations as u64 * (self.exec_timeout_secs + self.review_timeout_secs())
    }
}

/// Create `path` and its parents, and hold it at 0700. `stage/` holds the
/// approved bytes of files about to be written as root and `log/` records full
/// command text, so neither may be readable by other local users.
///
/// The parents matter now that the three directories are in three places:
/// creating `~/.local/state/hatch/log` creates `~/.local/state/hatch` on the
/// way, and it is created at 0700 too.
fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .with_context(|| format!("creating {}", path.display()))?;
    // `DirBuilder` sets the mode only on directories it creates; this also
    // brings one that already exists at a laxer mode back to 0700.
    set_mode(path, 0o700)
}

/// Read the config at `path`, tightening the file's mode first.
///
/// This file holds the bearer token, and an editor that saves by rename
/// recreates it at the umask default. Tighten every load, the same way the
/// directories are tightened.
fn read_private(path: &Path) -> anyhow::Result<Config> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    set_mode(path, 0o600)?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Write the config to `path` at mode 0600, replacing whatever was there.
///
/// The file is built alongside the target and renamed over it, so a concurrent
/// reader sees either the old file or the complete new one — never a truncated
/// file, and never the token sitting at a laxer mode mid-write.
fn write_private(path: &Path, config: &Config) -> anyhow::Result<()> {
    staged(path, config)?
        .persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// Write the config to `path` only if `path` does not exist. Returns whether
/// this call is the one that created it.
///
/// A rename is atomic, which is why `write_private` is safe against a torn
/// read — but atomic is not the same as exclusive, and a plain rename would
/// leave the first-run token race open. Two processes starting at once
/// against a config with no token both generate one and both rename; the
/// second overwrites the first, and the first still returns *its* token. The
/// daemon would then authenticate against a token `hatch token` never
/// printed, and no amount of re-reading afterwards fixes it: the loser can
/// read the file back before the winner's rename lands.
///
/// `RENAME_NOREPLACE` closes it. Exactly one process creates the file; every
/// other one is told so and reads the winner's token instead. This is only
/// reachable on a true first run — which is exactly the moment the user is
/// copying the registration line and would notice nothing wrong.
fn create_private(path: &Path, config: &Config) -> anyhow::Result<bool> {
    match staged(path, config)?.persist_noclobber(path) {
        Ok(_) => Ok(true),
        Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => {
            Err(anyhow::Error::new(e.error).context(format!("creating {}", path.display())))
        }
    }
}

/// The config, serialized into a 0600 temporary file beside `path`.
fn staged(path: &Path, config: &Config) -> anyhow::Result<tempfile::NamedTempFile> {
    let text = toml::to_string(config)?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));

    let mut tmp = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o600))
        .tempfile_in(dir)
        .with_context(|| format!("creating a temporary file in {}", dir.display()))?;
    tmp.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(tmp)
}

/// Set `path` to exactly `mode`, whatever it was before.
fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("securing {}", path.display()))
}

/// The point size the approval window should draw at, read without creating
/// or writing anything.
///
/// Read-only and infallible on purpose. The prompt process draws a window and
/// owns nothing — not the config file, not the directories — and a missing,
/// unreadable or unparseable config here must cost a font size and nothing
/// else: refusing to open the window would resolve as a denial of the request
/// the user was about to be shown, which is a far worse answer to a typo in a
/// preference than drawing it at the default.
pub fn display_font_size() -> f32 {
    display_style().0
}

/// The config as a window should read it: read-only, and defaulted rather
/// than refused on anything it cannot make sense of.
///
/// The counterpart to [`Config::load_or_create`], which creates directories,
/// writes a token back and fails loudly. Nothing here does any of that. A
/// process that only draws owns nothing — not the file, not the directories —
/// and the two callers both have something better to do with a typo in a
/// preference than to stop: `hatch prompt` would resolve the request it was
/// about to show as a denial, and `hatch preview` would refuse to show
/// anybody the window they asked to look at.
pub fn display_config() -> Config {
    match Paths::from_env() {
        Ok(paths) => display_config_at(&paths),
        Err(_) => Config::default(),
    }
}

/// The whole of [`display_config`] except for reading the environment, so
/// every case is testable without one.
pub fn display_config_at(paths: &Paths) -> Config {
    fs::read_to_string(paths.config_file())
        .ok()
        .and_then(|text| toml::from_str::<Config>(&text).ok())
        .unwrap_or_default()
}

/// The point size and the palette the approval window should draw in, read
/// without creating or writing anything.
///
/// Both from one read of one file: two reads could see two files, and a
/// window drawn at one config's size in another config's colours would be a
/// window nobody configured.
pub fn display_style() -> (f32, Theme) {
    let config = display_config();
    (config.font_size_points(), config.theme)
}

/// The whole of [`display_style`] except for reading the environment, so
/// every case is testable without one.
pub fn display_style_at(paths: &Paths) -> (f32, Theme) {
    let config = display_config_at(paths);
    (config.font_size_points(), config.theme)
}

/// The point size alone, for callers that want nothing else.
pub fn font_size_at(paths: &Paths) -> f32 {
    display_style_at(paths).0
}

/// Print the client registration line for `hatch token`.
///
/// Also reports anything unusual about where the directories ended up, which
/// on this path is the point as much as the line is: a user with a leftover
/// `~/.hatch` is a user who may be holding a token nothing accepts any more.
pub fn print_client_line() -> anyhow::Result<()> {
    let paths = Paths::from_env()?;
    paths.report();
    print_client_line_for(&Config::load_or_create(&paths)?)
}

/// Print the client registration line for a config already in hand.
///
/// The daemon prints the line for the config it is actually serving, so the
/// port and the token in it cannot drift from the ones in use.
pub fn print_client_line_for(config: &Config) -> anyhow::Result<()> {
    println!("{}\n", client_line(config));
    println!("{}", client_timeout_note(config));
    Ok(())
}

/// The name the server is registered under, in every spelling of the
/// registration.
///
/// One constant rather than a literal per spelling: the CLI form and the JSON
/// form below describe the same server, and a user who pasted both under two
/// names would have two entries, one of which authenticates against nothing.
const CLIENT_NAME: &str = "hatch";

/// The URL a client posts to.
///
/// An address rather than a name, and the same address the listener binds.
/// `localhost` would resolve through the resolver, and the server checks the
/// `Host` header against a fixed list precisely so that a name somebody else
/// controls cannot be pointed here.
pub fn client_url(config: &Config) -> String {
    format!("http://127.0.0.1:{}/mcp", config.port)
}

/// The value of the `Authorization` header the client must send.
pub fn authorization_header(config: &Config) -> String {
    format!("Bearer {}", config.token)
}

/// The `claude mcp add` line, with no trailing newline.
///
/// Split out from the printing so that everything which shows a user how to
/// register — `hatch token`, `hatch serve`, `hatch setup mcp` — shows the
/// same line rather than its own rendering of one.
pub fn client_line(config: &Config) -> String {
    format!(
        "claude mcp add --transport http {CLIENT_NAME} {} \\\n  --header \"Authorization: {}\"",
        client_url(config),
        authorization_header(config)
    )
}

/// The same registration as a `mcpServers` entry, for clients configured by
/// file rather than by command.
///
/// Built through `serde_json` and pretty-printed rather than written out as
/// text, so what a user is invited to paste is something that parsed at least
/// once.
///
/// `"type"` is carried explicitly. It is not decoration: a client reading an
/// entry that has a `url` and no type takes it for a stdio server and skips
/// it, which fails as a server that never appears rather than as an error.
pub fn client_json(config: &Config) -> String {
    /// One server's entry. Serialized from a struct rather than assembled as
    /// a `serde_json::Value`, because a `Value`'s object is a sorted map and
    /// would print `headers` above `type` and `url` — valid, and not the
    /// order anyone writes an entry in. Field order here is the printed
    /// order.
    #[derive(Serialize)]
    struct Entry {
        #[serde(rename = "type")]
        transport: &'static str,
        url: String,
        headers: BTreeMap<&'static str, String>,
    }

    #[derive(Serialize)]
    struct Registration {
        #[serde(rename = "mcpServers")]
        servers: BTreeMap<&'static str, Entry>,
    }

    let entry = Entry {
        transport: "http",
        url: client_url(config),
        headers: BTreeMap::from([("Authorization", authorization_header(config))]),
    };
    let registration = Registration { servers: BTreeMap::from([(CLIENT_NAME, entry)]) };
    serde_json::to_string_pretty(&registration).expect("a tree of strings always serialises")
}

/// The tool timeout the client has to be set to, and what the number is made
/// of.
///
/// The sum is [`Config::client_timeout_secs`] rather than a number written
/// here, and both terms are named alongside it: a reader who has raised one
/// of them in `config.toml` can see their own number in the arithmetic and
/// knows the total is theirs and not the default.
///
/// The execution term is per operation, so where a batch may carry more than
/// one the arithmetic says so; at one operation it reads as it always did.
pub fn client_timeout_note(config: &Config) -> String {
    let (exec, review) = (config.exec_timeout_secs, config.review_timeout_secs());
    let per_operation = match crate::server::MAX_OPERATIONS {
        1 => format!("execution {exec}s + review {review}s"),
        n => format!("execution {exec}s and review {review}s for each of up to {n} operations"),
    };
    format!(
        "Set your client's MCP tool timeout to at least {}s\n(approval {}s + {per_operation}).",
        config.client_timeout_secs(),
        config.timeout_secs,
    )
}

/// 32 bytes of OS entropy, base64url without padding: 43 characters.
fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::fill(&mut bytes[..]);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The invoking user's home directory, for the child environment. `/tmp` is a
/// last resort for environments that report no home at all.
fn default_home() -> String {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary root, and the three directories under it. Distinct
    /// directories rather than one: everything below would still pass if
    /// `log/` were created inside the config directory, and that is exactly
    /// the mistake the move to XDG makes possible.
    fn scratch() -> (tempfile::TempDir, Paths) {
        let root = tempfile::tempdir().unwrap();
        let paths = Paths::scratch(root.path());
        (root, paths)
    }

    // ---- the font size ---------------------------------------------------

    #[test]
    fn the_default_font_size_is_the_one_this_window_is_read_at() {
        assert_eq!(Config::default().font_size, DEFAULT_FONT_SIZE);
        assert_eq!(Config::default().font_size_points(), DEFAULT_FONT_SIZE as f32);
    }

    #[test]
    fn a_font_size_is_clamped_rather_than_refused() {
        // A typo in a preference must not close the window: on this path
        // that resolves as a denial of the request the reader was about to
        // see, which is a very expensive answer to a stray zero.
        let sized = |font_size| Config { font_size, ..Config::default() }.font_size_points();
        assert_eq!(sized(0), *FONT_SIZE_RANGE.start() as f32);
        assert_eq!(sized(1), *FONT_SIZE_RANGE.start() as f32);
        assert_eq!(sized(10_000), *FONT_SIZE_RANGE.end() as f32);
        assert_eq!(sized(20), 20.0, "an ordinary size is left alone");
        assert_eq!(sized(8), 8.0, "and so are the ends of the range");
        assert_eq!(sized(48), 48.0);
    }

    #[test]
    fn a_font_size_is_written_and_read_back_as_a_whole_number() {
        // TOML does not widen an integer into a float, so `font_size = 16` --
        // the only thing a reader would type -- has to be what the field
        // accepts.
        let parsed: Config = toml::from_str("font_size = 22").unwrap();
        assert_eq!(parsed.font_size, 22);
        assert!(toml::to_string(&Config::default()).unwrap().contains("font_size = 16"));
    }

    #[test]
    fn the_window_reads_the_size_without_creating_or_writing_anything() {
        let (_root, paths) = scratch();

        // No config at all: the default, and nothing appears on disk.
        assert_eq!(font_size_at(&paths), DEFAULT_FONT_SIZE as f32);
        assert!(!paths.config_file().exists(), "reading a font size created a config file");

        fs::create_dir_all(paths.config_dir()).unwrap();
        fs::write(paths.config_file(), "font_size = 24
").unwrap();
        assert_eq!(font_size_at(&paths), 24.0);

        // A file that does not parse costs a font size and nothing else.
        fs::write(paths.config_file(), "font_size = 'large'\n").unwrap();
        assert_eq!(font_size_at(&paths), DEFAULT_FONT_SIZE as f32);
    }

    #[test]
    fn the_window_reads_its_size_and_its_palette_from_one_look_at_one_file() {
        // One read, because two reads could see two files and a window drawn
        // at one config's size in another config's colours is a window nobody
        // configured.
        let (_root, paths) = scratch();

        assert_eq!(display_style_at(&paths), (DEFAULT_FONT_SIZE as f32, Theme::Dark));
        assert!(!paths.config_file().exists(), "reading a preference created a config file");

        fs::create_dir_all(paths.config_dir()).unwrap();
        fs::write(paths.config_file(), "font_size = 20\ntheme = 'light'\n").unwrap();
        assert_eq!(display_style_at(&paths), (20.0, Theme::Light));

        // A config written before the key existed keeps working and keeps the
        // palette the window has always had.
        fs::write(paths.config_file(), "font_size = 20\n").unwrap();
        assert_eq!(display_style_at(&paths), (20.0, Theme::Dark));

        // And a palette nobody has heard of costs both preferences rather
        // than the window: the file does not parse, so the defaults stand.
        fs::write(paths.config_file(), "theme = 'chartreuse'\n").unwrap();
        assert_eq!(display_style_at(&paths), (DEFAULT_FONT_SIZE as f32, Theme::Dark));
    }

    #[test]
    fn a_written_config_names_its_palette_in_a_word() {
        let written = toml::to_string(&Config::default()).unwrap();
        assert!(written.contains("theme = \"dark\""), "{written}");
        assert_eq!(toml::from_str::<Config>("theme = 'light'").unwrap().theme, Theme::Light);
    }

    #[test]
    fn generates_a_token_on_first_load() {
        let (_root, paths) = scratch();
        let c = Config::load_or_create(&paths).unwrap();
        assert_eq!(c.token.len(), 43); // 32 bytes base64url, unpadded
    }

    #[test]
    fn second_load_returns_the_same_token() {
        let (_root, paths) = scratch();
        let a = Config::load_or_create(&paths).unwrap();
        let b = Config::load_or_create(&paths).unwrap();
        assert_eq!(a.token, b.token);
    }

    #[test]
    fn config_file_is_not_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let (_root, paths) = scratch();
        Config::load_or_create(&paths).unwrap();
        let mode = std::fs::metadata(paths.config_file()).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "config.toml must be 0600");
    }

    #[test]
    fn the_three_directories_are_created_where_they_were_asked_for() {
        // The config file goes in one, the log in the second, the stage in the
        // third, and none of them is created next to another.
        let (_root, paths) = scratch();
        Config::load_or_create(&paths).unwrap();
        assert!(paths.config_file().is_file(), "no config.toml");
        assert!(paths.log_dir().is_dir(), "no log directory");
        assert!(paths.stage_dir().is_dir(), "no stage directory");
        assert!(
            !paths.config_dir().join("log").exists(),
            "the log must not be created beside the config"
        );
        assert!(
            !paths.config_dir().join("stage").exists(),
            "nor the stage"
        );
    }

    #[test]
    fn client_blocking_bound_is_approval_plus_execution_plus_review() {
        let c = Config::default();
        // One approval wait, and one execution and one review per operation
        // the largest batch may carry.
        let per = c.exec_timeout_secs + c.review_timeout_secs();
        assert_eq!(
            c.client_timeout_secs(),
            c.timeout_secs + crate::server::MAX_OPERATIONS as u64 * per
        );
        assert_eq!(c.blocking_bound_secs(1), c.timeout_secs + per);
        assert_eq!(
            c.blocking_bound_secs(3),
            c.timeout_secs + 3 * per,
            "the approval wait is paid once however many operations there are"
        );
    }

    #[test]
    fn a_review_gets_the_time_an_approval_gets() {
        let c = Config { timeout_secs: 1234, ..Config::default() };
        assert_eq!(c.review_timeout_secs(), 1234, "raising one did not raise the other");
    }

    // ---- the registration, in both of its spellings ----------------------

    /// A config that names a port and a token no default could produce.
    fn registered() -> Config {
        Config { port: 9191, token: "a-test-token".to_string(), ..Config::default() }
    }

    #[test]
    fn the_url_is_loopback_and_the_configured_port() {
        // Loopback as an address, because that is what the listener binds and
        // what the `Host` check accepts. A name here would be a name somebody
        // else's DNS could answer for.
        assert_eq!(client_url(&registered()), "http://127.0.0.1:9191/mcp");
    }

    #[test]
    fn the_command_line_carries_the_url_and_the_bearer_header_and_continues_cleanly() {
        // Two lines, and the first ends in a continuation: a user who copies
        // only the visible first line gets a command that is obviously
        // unfinished rather than one that registers without a token.
        let line = client_line(&registered());
        let (first, second) = line.split_once('\n').expect("the line continues");

        assert!(first.starts_with("claude mcp add --transport http hatch "), "{line}");
        assert!(first.ends_with(" \\"), "the first line must continue: {line}");
        assert!(first.contains("http://127.0.0.1:9191/mcp"), "{line}");
        assert_eq!(second, "  --header \"Authorization: Bearer a-test-token\"");
        assert!(!line.ends_with('\n'), "the caller owns the trailing newline: {line:?}");
    }

    #[test]
    fn the_json_form_parses_and_registers_one_http_server_at_the_same_url_and_token() {
        // The risk of a second spelling is that it drifts from the first and
        // somebody pastes the stale one. Both are built from this config, and
        // this is what says they still agree.
        let config = registered();
        let json: serde_json::Value =
            serde_json::from_str(&client_json(&config)).expect("what is printed must parse");

        let servers = json["mcpServers"].as_object().expect("an mcpServers map");
        assert_eq!(servers.len(), 1, "one server, not a template with extras: {servers:?}");

        let entry = &servers["hatch"];
        assert_eq!(entry["type"], "http", "a url with no type is read as stdio and skipped");
        assert_eq!(entry["url"], client_url(&config));
        assert_eq!(entry["headers"]["Authorization"], authorization_header(&config));
    }

    #[test]
    fn the_json_form_reads_in_the_order_somebody_would_write_it_in() {
        // A `serde_json::Value` sorts its keys, which would put `headers`
        // above `type` and `url`. Correct, and not how anyone writes an entry;
        // the struct in `client_json` is there to keep the printed order.
        let printed = client_json(&registered());
        let transport = printed.find("\"type\"").expect("a type");
        let url = printed.find("\"url\"").expect("a url");
        let headers = printed.find("\"headers\"").expect("headers");
        assert!(transport < url && url < headers, "{printed}");
    }

    #[test]
    fn both_spellings_name_the_same_server() {
        let config = registered();
        let json: serde_json::Value = serde_json::from_str(&client_json(&config)).unwrap();
        let name = json["mcpServers"].as_object().unwrap().keys().next().unwrap().clone();
        assert!(
            client_line(&config).contains(&format!(" {name} ")),
            "the command must register the name the file registers: {name}"
        );
    }

    #[test]
    fn the_timeout_note_states_the_sum_and_the_terms_it_is_made_of() {
        // Every term, so that a reader who has raised one of them in their
        // own config can see their own arithmetic rather than wondering
        // whether the total is the default.
        let config = Config { timeout_secs: 1200, exec_timeout_secs: 600, ..registered() };
        let note = client_timeout_note(&config);

        assert!(note.contains("at least 3000s"), "{note}");
        assert!(note.contains("approval 1200s + execution 600s + review 1200s"), "{note}");
        assert!(!note.contains("1500"), "the default must not survive a raised config: {note}");
    }

    #[test]
    fn the_default_wait_is_long_enough_to_read_a_command_in() {
        // Pinned rather than left implicit. The number reaches the agent --
        // the tool descriptions quote the sum, and an agent that believes the
        // ceiling is lower than it is will mis-plan around it -- so moving it
        // should be a deliberate edit here and not a side effect somewhere
        // else. Ninety seconds was the old value and is the one mistake this
        // test exists to catch a return to.
        let c = Config::default();
        assert_eq!(c.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert_eq!(c.timeout_secs, 600);
        assert_eq!(c.exec_timeout_secs, DEFAULT_EXEC_TIMEOUT_SECS);
        assert_eq!(c.exec_timeout_secs, 300);
        assert_eq!(c.client_timeout_secs(), 1500, "what the tool descriptions state");
    }

    #[test]
    fn state_directories_are_not_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let (_root, paths) = scratch();
        Config::load_or_create(&paths).unwrap();
        // Every directory hatch made, including the two it created on the way
        // to `log/` and `stage/`.
        let made = [
            paths.config_dir().to_path_buf(),
            paths.log_dir(),
            paths.log_dir().parent().unwrap().to_path_buf(),
            paths.stage_dir(),
            paths.stage_dir().parent().unwrap().to_path_buf(),
        ];
        for dir in made {
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{} must be 0700", dir.display());
        }
    }

    #[test]
    fn the_default_path_carries_homebrew_on_the_platform_that_needs_it() {
        // The system ships almost nothing a person installs for themselves,
        // so a macOS `PATH` without Homebrew on it is one where a name the
        // person types every day resolves to nothing -- `fish`, `rg`, `jq`,
        // anything. Both prefixes, because which one is right is an
        // architecture question this has deliberately not asked.
        let mac = exec_path_for_os("macos");
        assert!(mac.starts_with("/opt/homebrew/bin:"), "{mac}");
        assert!(mac.contains(":/usr/local/bin:"), "{mac}");

        // And the system directories are still on it, after them.
        for directory in ["/usr/bin", "/bin"] {
            assert!(mac.split(':').any(|entry| entry == directory), "{directory} is not on {mac}");
        }
    }

    #[test]
    fn the_default_path_is_unchanged_where_there_is_no_homebrew_to_add() {
        // Linux distributions put programs in these three and a person's own
        // tools are their own business, so there is nothing to add and adding
        // something would be this default guessing.
        assert_eq!(exec_path_for_os("linux"), "/usr/local/bin:/usr/bin:/bin");
        assert_eq!(exec_path_for_os("freebsd"), "/usr/local/bin:/usr/bin:/bin");
        assert_eq!(Config::default().exec_path, exec_path_for_os(std::env::consts::OS));
    }

    #[test]
    fn every_default_path_entry_is_absolute() {
        // An empty or relative entry on a `PATH` is the one lookup nobody
        // wants: `exec::lookup` skips empty entries rather than reading them
        // as `.`, and a relative directory would resolve a program out of
        // whatever directory a request happened to name.
        for os in ["linux", "macos"] {
            for entry in exec_path_for_os(os).split(':') {
                assert!(entry.starts_with('/'), "{entry:?} on {os} is not absolute");
            }
        }
    }

    #[test]
    fn the_default_terminal_starts_a_process_hatch_can_reach() {
        // `--nofork` is the whole of it. A konsole started without it, on a
        // desktop where "run all Konsole windows in a single process" is on,
        // hands the command to a konsole that is already running and returns:
        // the command is then in a process hatch never started, the Kill
        // button reaches nothing, and the run has to be reported as one hatch
        // could not follow. The flag is what makes the default a terminal
        // rather than a message to one.
        //
        // Asked of the Linux arm by name rather than of `Config::default()`,
        // so that the claim is about konsole wherever this test is run and
        // not about whatever platform happened to run it.
        assert_eq!(terminal_for_os("linux"), ["konsole", "--nofork", "-e"]);
        assert_eq!(Config::default().terminal, terminal_for_os(std::env::consts::OS));
    }

    #[test]
    fn a_platform_with_no_tested_terminal_is_given_no_terminal() {
        // The whole point of the empty default. A macOS build that wrote
        // konsole into a fresh config would be a build telling its owner to
        // start a KDE program, and every message afterwards -- the dead
        // control, the refusal -- would name that program rather than the
        // fact that this machine has no terminal hatch knows of.
        //
        // Testable here because the arm is chosen by value: on this machine
        // the macOS branch is never taken, and a branch whose only test runs
        // where it is never taken is a branch with no test at all. The same
        // argument `exec::elevate::platform` makes.
        assert!(terminal_for_os("macos").is_empty());
        assert!(terminal_for_os("freebsd").is_empty());
    }

    #[test]
    fn a_configured_terminal_survives_a_platform_that_has_no_default() {
        // The empty default is a default and not a rule: naming a terminal in
        // the file is the whole way out of it, and the file wins on every
        // platform.
        let parsed: Config = toml::from_str(r#"terminal = ["wezterm", "start", "--"]"#).unwrap();
        assert_eq!(parsed.terminal, ["wezterm", "start", "--"]);
    }

    #[test]
    fn a_config_missing_its_token_gets_one_written_back() {
        let (_root, paths) = scratch();
        std::fs::create_dir_all(paths.config_dir()).unwrap();
        let path = paths.config_file();
        std::fs::write(&path, "port = 9000\nterminal = [\"foot\", \"-e\"]\n").unwrap();

        let a = Config::load_or_create(&paths).unwrap();
        let b = Config::load_or_create(&paths).unwrap();

        assert_eq!(a.token.len(), 43);
        assert_eq!(a.token, b.token, "token must survive a restart");
        assert_eq!(a.port, 9000, "backfill must not discard settings");
        assert_eq!(a.terminal, ["foot", "-e"], "backfill must not discard settings");

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains(&a.token), "token must reach the file");
        assert!(on_disk.contains("port = 9000"), "rewrite must keep settings");
        assert!(on_disk.contains("\"foot\""), "rewrite must keep settings");
    }

    #[test]
    fn a_lax_config_file_is_tightened_on_load() {
        use std::os::unix::fs::PermissionsExt;
        let (_root, paths) = scratch();
        // The first load writes a token, so the second takes the steady-state
        // path that does not rewrite the file.
        Config::load_or_create(&paths).unwrap();
        let path = paths.config_file();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        Config::load_or_create(&paths).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "config.toml must be tightened back to 0600");
    }

    #[test]
    fn a_lax_directory_of_any_of_the_three_is_tightened_on_load() {
        // A directory that already exists — from an older hatch, from a
        // restore, or from a user who made it by hand at the umask default —
        // is brought back to 0700 rather than left as found. All three, not
        // just the config one: the log and the stage are the two that hold
        // command text and approved bytes.
        use std::os::unix::fs::PermissionsExt;
        let (_root, paths) = scratch();
        for dir in [paths.config_dir().to_path_buf(), paths.log_dir(), paths.stage_dir()] {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        Config::load_or_create(&paths).unwrap();

        for dir in [paths.config_dir().to_path_buf(), paths.log_dir(), paths.stage_dir()] {
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{} must be tightened to 0700", dir.display());
        }
    }

    #[test]
    fn simultaneous_first_runs_all_return_the_token_that_reached_disk() {
        // Two `hatch serve` starts against a brand new config used to be able
        // to each keep their own token, leaving the daemon authenticating
        // against one `hatch token` never printed.
        let (_root, paths) = scratch();
        let start = std::sync::Barrier::new(8);
        let tokens: Vec<String> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        Config::load_or_create(&paths).unwrap().token
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        let on_disk = std::fs::read_to_string(paths.config_file()).unwrap();
        for token in &tokens {
            assert_eq!(token, &tokens[0], "the starts disagreed on the token");
            let reached_disk = on_disk.contains(token.as_str());
            assert!(reached_disk, "a token that never reached disk was returned");
        }
    }

    #[test]
    fn create_private_reports_who_created_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let config = Config::default();
        assert!(create_private(&path, &config).unwrap(), "the first call creates it");
        assert!(!create_private(&path, &config).unwrap(), "the second must not clobber it");
    }

    #[test]
    fn a_write_that_failed_for_another_reason_is_not_mistaken_for_a_lost_race() {
        // Treating every failed create as "someone else won" would send the
        // caller off to read a file that is not there, and report the wrong
        // thing when the write really did fail.
        let dir = tempfile::tempdir().unwrap();
        let unwritable = dir.path().join("n".repeat(300)); // longer than NAME_MAX
        let error = create_private(&unwritable, &Config::default())
            .expect_err("a name that long cannot be created");
        assert!(format!("{error:#}").contains("creating"), "{error:#}");
        assert!(!unwritable.exists());
    }

    #[test]
    fn each_token_is_different() {
        assert_ne!(generate_token(), generate_token());
    }

    #[test]
    fn the_child_home_is_an_absolute_path() {
        // It is handed to approved commands as `HOME`. A relative or empty
        // one would send every tool that expands `~` somewhere unexpected.
        let home = Config::default().exec_env.get("HOME").unwrap().clone();
        assert!(home.starts_with('/'), "HOME must be absolute, got {home:?}");
    }

    #[test]
    fn a_default_config_round_trips_through_toml() {
        let c = Config::default();
        let text = toml::to_string(&c).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back, c);
    }
}
