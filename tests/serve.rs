//! `hatch serve`, end to end, as a real process.
//!
//! Everything else about the server is exercised in-process, which cannot see
//! the one thing a user meets first: running the binary and pasting what it
//! prints. This drives the whole startup — resolve the XDG directories, read
//! the config, sweep the stage, bind loopback, print the registration line,
//! serve MCP behind the token — against the actual executable.
//!
//! Every child gets its `XDG_*` variables set or removed explicitly. Inheriting
//! the developer's would put the daemon's config, log and stage on the machine
//! running the test.
//!
//! The child is killed by a guard on every exit path, including the timeout.
//! A daemon that outlives its test holds the harness's pipes open and stalls
//! everything after it.

use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// No test here may take longer than this, whatever goes wrong.
const CEILING: Duration = Duration::from_secs(10);

/// Kills the daemon and reaps it, however the test ends.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A loopback listener on a port the OS picked, and that port.
///
/// Holding it is what makes the port ours: a test that only asked for a free
/// port and let go of it can have the port taken by the next test that asks.
fn held_port() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// A port nothing holds right now. There is a window between releasing it and
/// the daemon claiming it; losing that race shows up as a failure to connect,
/// not as a silent pass.
fn free_port() -> u16 {
    held_port().1
}

/// `hatch`, with a home of its own and no inherited `XDG_*` variables, so the
/// defaults are what the child resolves.
fn hatch(home: &Path, mode: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hatch"));
    command.arg(mode).env("HOME", home);
    for var in ["XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"] {
        command.env_remove(var);
    }
    command
}

/// Where each directory lands with nothing but `HOME` set.
fn config_file(home: &Path) -> PathBuf {
    home.join(".config/hatch/config.toml")
}
fn stage_dir(home: &Path) -> PathBuf {
    home.join(".local/state/hatch/stage")
}

/// Write a config the daemon will load unchanged, and leave a stale file in
/// the stage directory for it to sweep.
fn prepare(home: &Path, port: u16, token: &str) {
    let config = config_file(home);
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::create_dir_all(stage_dir(home)).unwrap();
    std::fs::write(config, format!("port = {port}\ntoken = \"{token}\"\n")).unwrap();
    std::fs::write(stage_dir(home).join("leftover"), b"never written").unwrap();
}

#[tokio::test]
async fn the_daemon_starts_sweeps_prints_and_serves_only_to_the_token() {
    let home = tempfile::tempdir().unwrap();
    let port = free_port();
    let token = "integration-token";
    prepare(home.path(), port, token);

    let started = tokio::time::timeout(CEILING, async {
        let mut daemon = Daemon(
            hatch(home.path(), "serve")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("the binary must be runnable"),
        );

        // Wait for the listener rather than sleeping a guessed interval.
        let url = format!("http://127.0.0.1:{port}/mcp");
        let client = reqwest::Client::new();
        loop {
            if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            if let Ok(Some(status)) = daemon.0.try_wait() {
                panic!("the daemon exited before it listened: {status}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Loopback is shared, so the port answering is not the same as the
        // port serving: without the token there is nothing here.
        let anonymous = client.post(&url).body("{}").send().await.unwrap();
        assert_eq!(anonymous.status(), 401, "the port must be useless without the token");

        // With it, a real client completes the handshake.
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .body(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                    "protocolVersion":"2025-06-18","capabilities":{},
                    "clientInfo":{"name":"integration","version":"0"}}}"#,
            )
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "{:?}", response.status());
        let body = response.text().await.unwrap();
        assert!(body.contains("\"serverInfo\""), "the handshake must complete: {body}");

        // The stage the daemon inherited held a file from a run that died
        // before writing it. Nothing later may reuse it.
        assert!(!stage_dir(home.path()).join("leftover").exists(), "startup must sweep the stage");

        drop(daemon.0.kill());
        let _ = daemon.0.wait();
        let mut printed = String::new();
        daemon.0.stdout.take().unwrap().read_to_string(&mut printed).unwrap();
        printed
    })
    .await
    .expect("the daemon must start and answer well inside the ceiling");

    // The registration line is printed only once the port is genuinely ours,
    // and it carries the token and port the daemon is actually serving.
    assert!(started.contains(token), "the registration line must carry the token: {started}");
    assert!(started.contains(&port.to_string()), "and the port: {started}");
    assert!(started.contains("claude mcp add"), "and be pasteable: {started}");
}

#[tokio::test]
async fn a_second_daemon_on_the_same_port_refuses_to_start() {
    let home = tempfile::tempdir().unwrap();
    // Held for the whole test: this is the port the daemon must find taken.
    let (held, port) = held_port();
    prepare(home.path(), port, "integration-token");

    tokio::time::timeout(CEILING, async {
        let output = hatch(home.path(), "serve").output().expect("the binary must be runnable");

        assert!(!output.status.success(), "it must not pretend to be serving");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("claude mcp add"),
            "no registration line for a daemon that is not listening: {stdout}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(&port.to_string()), "the error must name the port: {stderr}");
        drop(held);
    })
    .await
    .expect("a failed start must fail fast");
}

#[test]
fn hatch_token_prints_the_line_for_the_config_it_creates() {
    // `hatch token` is what the user actually runs, and on a first run it is
    // also what creates the config. The line it prints has to match the file
    // it just wrote, or the client is registered with a token the daemon does
    // not hold.
    let home = tempfile::tempdir().unwrap();

    let output = hatch(home.path(), "token").output().expect("the binary must be runnable");

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let printed = String::from_utf8(output.stdout).unwrap();
    let written = std::fs::read_to_string(config_file(home.path())).unwrap();

    let token = written
        .lines()
        .find_map(|line| line.strip_prefix("token = "))
        .expect("a token must have been written")
        .trim_matches('"');
    assert_eq!(token.len(), 43, "32 bytes, base64url, unpadded");
    assert!(printed.contains("claude mcp add"), "the line must be pasteable: {printed}");
    assert!(printed.contains(token), "and carry the token that reached disk: {printed}");
    assert!(printed.contains("390s"), "and the timeout the client has to be set to: {printed}");
}

#[test]
fn with_nothing_set_the_three_directories_land_where_the_xdg_spec_says() {
    // The layout a user gets on a machine that sets none of the variables.
    // Written out in full rather than asked of the binary, because "wherever
    // it put them" is not a contract.
    let home = tempfile::tempdir().unwrap();

    let output = hatch(home.path(), "token").output().expect("the binary must be runnable");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    assert!(home.path().join(".config/hatch/config.toml").is_file(), "no config.toml");
    assert!(home.path().join(".local/state/hatch/log").is_dir(), "no log directory");
    assert!(home.path().join(".local/state/hatch/stage").is_dir(), "no stage directory");
    assert!(!home.path().join(".hatch").exists(), "the old directory must not be recreated");

    for dir in [".config/hatch", ".local/state/hatch/log", ".local/state/hatch/stage"] {
        let mode = std::fs::metadata(home.path().join(dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{dir} must be 0700");
    }
    let mode = std::fs::metadata(home.path().join(".config/hatch/config.toml"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "config.toml must be 0600");
}

#[test]
fn the_xdg_variables_are_honoured_over_the_defaults() {
    // Each of the three is read from its own variable, and the runtime one is
    // used for staging when it is a private directory of ours.
    let home = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let (config, state, runtime) = (
        elsewhere.path().join("cfg"),
        elsewhere.path().join("state"),
        elsewhere.path().join("run"),
    );
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_hatch"))
        .arg("token")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_RUNTIME_DIR", &runtime)
        .output()
        .expect("the binary must be runnable");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    assert!(config.join("hatch/config.toml").is_file(), "the config must follow its variable");
    assert!(state.join("hatch/log").is_dir(), "and the log its own");
    assert!(runtime.join("hatch/stage").is_dir(), "and the stage its own");
    assert!(!state.join("hatch/stage").exists(), "staging must not also fall back");
    assert!(!home.path().join(".config").exists(), "no default may be used as well");
    assert!(!home.path().join(".local").exists());
}

#[test]
fn a_leftover_hatch_directory_is_named_and_nothing_is_moved_out_of_it() {
    // Detect, do not migrate. The old directory keeps its token and its log,
    // and the user is told where things are now and that it can go.
    let home = tempfile::tempdir().unwrap();
    let old = home.path().join(".hatch");
    std::fs::create_dir_all(old.join("log")).unwrap();
    std::fs::write(old.join("config.toml"), "token = \"an-old-dead-token\"\n").unwrap();

    let output = hatch(home.path(), "token").output().expect("the binary must be runnable");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains(".hatch"), "the old directory must be named: {said}");
    assert!(said.contains(".config/hatch/config.toml"), "and where the config is now: {said}");
    assert!(said.contains(".local/state/hatch/log"), "and the log: {said}");
    assert!(said.contains("remove"), "and that it can be removed: {said}");

    // Untouched, and not consulted: the token printed is the new one.
    assert_eq!(
        std::fs::read_to_string(old.join("config.toml")).unwrap(),
        "token = \"an-old-dead-token\"\n",
        "the old config must be left exactly as it was"
    );
    assert!(old.join("log").is_dir(), "and so must the old log");
    let printed = String::from_utf8_lossy(&output.stdout);
    assert!(
        !printed.contains("an-old-dead-token"),
        "the registration line must carry the live token, not the old one: {printed}"
    );
}

#[test]
fn a_hatch_with_no_leftovers_says_nothing_about_where_it_lives() {
    // The notice is for the one start after an upgrade, not for every start.
    let home = tempfile::tempdir().unwrap();
    let output = hatch(home.path(), "token").output().expect("the binary must be runnable");
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.is_empty(), "a clean start must be quiet: {said}");
}

#[test]
fn an_unusable_runtime_directory_falls_back_to_the_state_directory_and_says_so() {
    // Not a directory at all. Staging approved file content into it is
    // impossible, and refusing to start would leave the user without the
    // approval window entirely, so hatch stages under the state directory and
    // names the variable it could not use.
    let home = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let runtime = elsewhere.path().join("not-a-directory");
    std::fs::write(&runtime, b"").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_hatch"))
        .arg("token")
        .env("HOME", home.path())
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env("XDG_RUNTIME_DIR", &runtime)
        .output()
        .expect("the binary must be runnable");

    assert!(output.status.success(), "it must still start: {}", String::from_utf8_lossy(&output.stderr));
    assert!(
        home.path().join(".local/state/hatch/stage").is_dir(),
        "staging must fall back to the state directory"
    );
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("XDG_RUNTIME_DIR"), "a silent fallback is the one thing not allowed: {said}");
    assert!(said.contains(".local/state/hatch/stage"), "and it must say where instead: {said}");
}

#[test]
fn a_relative_xdg_variable_is_ignored_rather_than_resolved_against_the_cwd() {
    // The spec calls a relative value invalid. Resolving it against whatever
    // directory hatch happens to be started from would scatter config files
    // wherever the user ran it.
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_hatch"))
        .arg("token")
        .current_dir(cwd.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", "relative-config")
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .expect("the binary must be runnable");

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(home.path().join(".config/hatch/config.toml").is_file(), "the default must be used");
    assert!(!cwd.path().join("relative-config").exists(), "nothing may be written beside the cwd");
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("XDG_CONFIG_HOME"), "and the variable must be named: {said}");
}
