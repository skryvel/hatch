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

/// Bytes of entropy behind the bearer token.
const TOKEN_BYTES: usize = 32;

/// On-disk settings. Every field has a default and the struct carries
/// `#[serde(default)]`, so a config file written by an older build keeps
/// loading unchanged after new fields are added.
///
/// `exec_env` is declared last only so the written file reads scalars first;
/// the serializer emits tables after plain values whatever the field order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Loopback port the MCP server listens on.
    pub port: u16,
    /// Bearer token the client must present. Empty in `Config::default()`;
    /// `load_or_create` generates one and writes it back.
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
            exec_env,
        }
    }
}

impl Config {
    /// Load `<dir>/config.toml`, creating `dir` (with its `log/` and `stage/`
    /// subdirectories) if absent. A config with no token — a brand new one, or
    /// an existing file that never had the key — gets a fresh token written
    /// back, so `hatch serve` and `hatch token` agree across restarts.
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Config> {
        create_private_dir(dir)?;
        create_private_dir(&dir.join("log"))?;
        create_private_dir(&dir.join("stage"))?;

        let path = dir.join("config.toml");
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

    /// The longest a client call can block: the approval wait followed by a
    /// full-length execution.
    pub fn client_timeout_secs(&self) -> u64 {
        self.timeout_secs + self.exec_timeout_secs
    }
}

/// Create `path` and its parents, and hold it at 0700. `stage/` holds the
/// approved bytes of files about to be written as root and `log/` records full
/// command text, so neither may be readable by other local users.
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

/// The real config directory, `~/.hatch`.
pub fn default_dir() -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().context("no home directory to place ~/.hatch in")?;
    Ok(home.join(".hatch"))
}

/// Print the client registration line for `hatch token`.
pub fn print_client_line() -> anyhow::Result<()> {
    print_client_line_for(&Config::load_or_create(&default_dir()?)?)
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

    #[test]
    fn generates_a_token_on_first_load() {
        let dir = tempfile::tempdir().unwrap();
        let c = Config::load_or_create(dir.path()).unwrap();
        assert_eq!(c.token.len(), 43); // 32 bytes base64url, unpadded
    }

    #[test]
    fn second_load_returns_the_same_token() {
        let dir = tempfile::tempdir().unwrap();
        let a = Config::load_or_create(dir.path()).unwrap();
        let b = Config::load_or_create(dir.path()).unwrap();
        assert_eq!(a.token, b.token);
    }

    #[test]
    fn config_file_is_not_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        Config::load_or_create(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join("config.toml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "config.toml must be 0600");
    }

    #[test]
    fn client_blocking_bound_is_approval_plus_execution() {
        let c = Config::default();
        assert_eq!(c.client_timeout_secs(), c.timeout_secs + c.exec_timeout_secs);
    }

    #[test]
    fn state_directories_are_not_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        Config::load_or_create(dir.path()).unwrap();
        for sub in ["log", "stage"] {
            let mode = std::fs::metadata(dir.path().join(sub))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "{sub}/ must be 0700");
        }
    }

    #[test]
    fn a_config_missing_its_token_gets_one_written_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "port = 9000\nterminal = [\"foot\", \"-e\"]\n").unwrap();

        let a = Config::load_or_create(dir.path()).unwrap();
        let b = Config::load_or_create(dir.path()).unwrap();

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
        let dir = tempfile::tempdir().unwrap();
        // The first load writes a token, so the second takes the steady-state
        // path that does not rewrite the file.
        Config::load_or_create(dir.path()).unwrap();
        let path = dir.path().join("config.toml");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        Config::load_or_create(dir.path()).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "config.toml must be tightened back to 0600");
    }

    #[test]
    fn a_lax_config_dir_is_tightened_on_load() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("hatch");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();

        Config::load_or_create(&root).unwrap();

        let mode = std::fs::metadata(&root).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "the config directory must be 0700");
    }

    #[test]
    fn simultaneous_first_runs_all_return_the_token_that_reached_disk() {
        // Two `hatch serve` starts against a brand new config used to be able
        // to each keep their own token, leaving the daemon authenticating
        // against one `hatch token` never printed.
        let dir = tempfile::tempdir().unwrap();
        let start = std::sync::Barrier::new(8);
        let tokens: Vec<String> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        Config::load_or_create(dir.path()).unwrap().token
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        let on_disk = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
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
