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
    /// How long a request waits for a human decision.
    pub timeout_secs: u64,
    /// How long an approved command may run.
    pub exec_timeout_secs: u64,
    /// Cap on captured command output.
    pub output_cap_bytes: usize,
    /// `PATH` handed to approved commands.
    pub exec_path: String,
    /// Terminal command used for interactive runs; argv, program first.
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

impl Default for Config {
    fn default() -> Self {
        let mut exec_env = BTreeMap::new();
        exec_env.insert("HOME".to_string(), default_home());
        exec_env.insert("TERM".to_string(), "xterm-256color".to_string());

        Self {
            port: 8787,
            token: String::new(),
            timeout_secs: 90,
            exec_timeout_secs: 300,
            output_cap_bytes: 262144,
            exec_path: "/usr/local/bin:/usr/bin:/bin".to_string(),
            terminal: vec!["konsole".to_string(), "-e".to_string()],
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

    /// The longest a client call can block: the approval wait followed by a
    /// full-length execution.
    pub fn client_timeout_secs(&self) -> u64 {
        self.timeout_secs + self.exec_timeout_secs
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

/// The point size and the palette the approval window should draw in, read
/// without creating or writing anything.
///
/// Both from one read of one file: two reads could see two files, and a
/// window drawn at one config's size in another config's colours would be a
/// window nobody configured.
pub fn display_style() -> (f32, Theme) {
    match Paths::from_env() {
        Ok(paths) => display_style_at(&paths),
        Err(_) => (Config::default().font_size_points(), Config::default().theme),
    }
}

/// The whole of [`display_style`] except for reading the environment, so
/// every case is testable without one.
pub fn display_style_at(paths: &Paths) -> (f32, Theme) {
    let config = fs::read_to_string(paths.config_file())
        .ok()
        .and_then(|text| toml::from_str::<Config>(&text).ok())
        .unwrap_or_default();
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
    println!(
        "claude mcp add --transport http hatch http://127.0.0.1:{}/mcp \\\n  --header \"Authorization: Bearer {}\"\n",
        config.port, config.token
    );
    println!(
        "Set your client's MCP tool timeout to at least {}s\n(approval {}s + execution {}s).",
        config.client_timeout_secs(),
        config.timeout_secs,
        config.exec_timeout_secs
    );
    Ok(())
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
    fn client_blocking_bound_is_approval_plus_execution() {
        let c = Config::default();
        assert_eq!(c.client_timeout_secs(), c.timeout_secs + c.exec_timeout_secs);
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
