//! `hatch serve`, end to end, as a real process.
//!
//! Everything else about the server is exercised in-process, which cannot see
//! the one thing a user meets first: running the binary and pasting what it
//! prints. This drives the whole startup — read the config, sweep the stage,
//! bind loopback, print the registration line, serve MCP behind the token —
//! against the actual executable.
//!
//! The child is killed by a guard on every exit path, including the timeout.
//! A daemon that outlives its test holds the harness's pipes open and stalls
//! everything after it.

use std::io::Read as _;
use std::net::TcpListener;
use std::path::Path;
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

/// Write a config the daemon will load unchanged, and leave a stale file in
/// the stage directory for it to sweep.
fn prepare(home: &Path, port: u16, token: &str) {
    let dir = home.join(".hatch");
    std::fs::create_dir_all(dir.join("stage")).unwrap();
    std::fs::write(dir.join("config.toml"), format!("port = {port}\ntoken = \"{token}\"\n"))
        .unwrap();
    std::fs::write(dir.join("stage").join("leftover"), b"never written").unwrap();
}

#[tokio::test]
async fn the_daemon_starts_sweeps_prints_and_serves_only_to_the_token() {
    let home = tempfile::tempdir().unwrap();
    let port = free_port();
    let token = "integration-token";
    prepare(home.path(), port, token);

    let started = tokio::time::timeout(CEILING, async {
        let mut daemon = Daemon(
            Command::new(env!("CARGO_BIN_EXE_hatch"))
                .arg("serve")
                .env("HOME", home.path())
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
        assert!(
            !home.path().join(".hatch/stage/leftover").exists(),
            "startup must sweep the stage"
        );

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
        let output = Command::new(env!("CARGO_BIN_EXE_hatch"))
            .arg("serve")
            .env("HOME", home.path())
            .output()
            .expect("the binary must be runnable");

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

    let output = Command::new(env!("CARGO_BIN_EXE_hatch"))
        .arg("token")
        .env("HOME", home.path())
        .output()
        .expect("the binary must be runnable");

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let printed = String::from_utf8(output.stdout).unwrap();
    let written = std::fs::read_to_string(home.path().join(".hatch/config.toml")).unwrap();

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
