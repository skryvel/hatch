//! A message sent somewhere else when a window has waited half its time.
//!
//! # Why
//!
//! A window on the screen does nothing for a reader who is away from it, and
//! a phone is usually nearer. The simple push services turn a POST to a URL
//! into a notification on one: `https://ntfy.sh/<topic>` is the one this was
//! written for. So with `notify_url` set, a window that is still asking when
//! half its deadline has gone sends one message there. Half, so that a reader
//! who gets it has as long to come back as the window has already waited.
//!
//! # Why curl and not an HTTP client
//!
//! Every Rust HTTP client that speaks TLS links C or assembly to do it, and
//! this is the process that reads agent requests. curl is on every Linux and
//! macOS this runs on. It is the decision [`crate::prompt_ui::sound`] makes
//! for a sound, for the same reason.
//!
//! # What it says
//!
//! Nothing of the request. The title, the reason and the command are the
//! agent's words, and a public push service is a place they would be
//! published: the topic in an ntfy.sh URL is its only password. So the
//! message names the machine, the window's number and how long is left, and
//! that is all anyone holding the topic learns.
//!
//! # It decides nothing
//!
//! It is sent at most once per window, nothing waits for it, and a failure is
//! a line in the log. A window decided before the halfway mark sends nothing.

use std::process::Stdio;
use std::time::Duration;

/// What is run to send the message.
pub const PROGRAM: &str = "curl";

/// How long curl is given, connecting included. Short, because a message
/// that arrives after the window has closed tells the reader nothing true.
const MAX_SECS: u64 = 15;

/// How far into a window of `window` the message is sent.
pub fn after(window: Duration) -> Duration {
    window / 2
}

/// The message for window `number`, with `left` to go.
pub fn message(host: &str, number: u64, left: Duration) -> String {
    format!("Window {number} on {host} is waiting for you: {} left to decide.", spoken(left))
}

/// A duration as a person would say it: minutes when there are a few of them.
fn spoken(left: Duration) -> String {
    match left.as_secs() {
        1 => "1 second".to_string(),
        secs if secs < 120 => format!("{secs} seconds"),
        secs => format!("{} minutes", secs / 60),
    }
}

/// This machine's name, or `this machine` when it has none hatch can read.
pub fn host() -> String {
    nix::unistd::gethostname()
        .ok()
        .and_then(|name| name.into_string().ok())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "this machine".to_string())
}

/// The arguments that POST `message` to `url`.
///
/// `--data-raw` rather than `--data`, which reads a file when its value
/// starts with `@`. `--proto` keeps the URL, and any redirect it answers
/// with, to HTTP and HTTPS: curl also speaks `file://` and a dozen others.
/// The URL goes after `--url`, so nothing in it is read as an option.
pub fn argv(url: &str, message: &str) -> Vec<String> {
    let max = MAX_SECS.to_string();
    [
        "--silent", "--show-error", "--fail", "--max-time", &max, "--proto", "=http,https",
        "--proto-redir", "=http,https", "--header", "Title: hatch", "--data-raw", message,
        "--url", url,
    ]
    .iter()
    .map(|arg| arg.to_string())
    .collect()
}

/// Send `message` to `url`, and log what went wrong if anything did.
pub async fn send(url: String, message: String) {
    let ran = tokio::process::Command::new(PROGRAM)
        .args(argv(&url, &message))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await;
    match ran {
        Ok(out) if out.status.success() => {}
        Ok(out) => eprintln!(
            "hatch could not send its notification: {PROGRAM} {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(error) => eprintln!("hatch could not run {PROGRAM} to send its notification: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_names_the_window_and_the_time_left_and_nothing_else() {
        assert_eq!(
            message("desk", 3, Duration::from_secs(300)),
            "Window 3 on desk is waiting for you: 5 minutes left to decide."
        );
        assert_eq!(
            message("desk", 1, Duration::from_secs(45)),
            "Window 1 on desk is waiting for you: 45 seconds left to decide."
        );
    }

    #[test]
    fn it_is_sent_at_half_the_window() {
        assert_eq!(after(Duration::from_secs(600)), Duration::from_secs(300));
    }

    #[test]
    fn the_url_and_the_message_cannot_be_read_as_options_or_files() {
        let argv = argv("-K/etc/passwd", "@/etc/passwd");
        let at = |flag: &str| argv.iter().position(|arg| arg == flag).expect(flag);
        assert_eq!(argv[at("--url") + 1], "-K/etc/passwd");
        assert_eq!(argv[at("--data-raw") + 1], "@/etc/passwd");
        assert!(!argv.iter().any(|arg| arg == "--data" || arg == "-d"), "{argv:?}");
        assert_eq!(argv[at("--proto") + 1], "=http,https");
        assert_eq!(argv[at("--proto-redir") + 1], "=http,https");
    }
}
