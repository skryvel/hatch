//! A message sent somewhere else when a window has waited half its time.
//!
//! # Why
//!
//! A window on the screen does nothing for a reader who is away from it, and
//! a phone is usually nearer. The push services turn a POST to a URL into a
//! notification on one. So with `notify_url` set, a window that is still
//! asking when half its deadline has gone sends one message there. Half, so
//! that a reader who gets it has as long to come back as the window has
//! already waited.
//!
//! # Two shapes of POST
//!
//! ntfy reads the body as the message, so with nothing else configured the
//! body is the message. Pushover, and Gotify, read form fields, and want
//! credentials among them: Pushover's `token` and `user`. So `notify_form`
//! is a table of fields, and when it has any the body is those fields
//! form-encoded with `title` and `message` added. See [`body`].
//!
//! The body reaches curl on its stdin, never in its arguments. Arguments are
//! readable by every process on the machine for as long as curl runs, and a
//! Pushover token is a credential.
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
//! agent's words, and a push service is a third party: the topic in an
//! ntfy.sh URL is its only password. So the message names the machine, the
//! window's number and how long is left, and that is all it tells anyone.
//!
//! # It decides nothing
//!
//! It is sent at most once per window, nothing waits for it, and a failure is
//! a line in the log. A window decided before the halfway mark sends nothing.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt as _;

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

/// What is posted: the message itself, or with `form` the form's fields and
/// the message, form-encoded.
///
/// A `message` field in the form is left out, because the message is what
/// this is for. A `title` field is kept, and `hatch` is the title when there
/// is none.
pub fn body(message: &str, form: &BTreeMap<String, String>) -> String {
    if form.is_empty() {
        return message.to_string();
    }
    let mut fields: Vec<(&str, &str)> = form
        .iter()
        .filter(|(name, _)| name.as_str() != "message")
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    if !form.contains_key("title") {
        fields.push(("title", "hatch"));
    }
    fields.push(("message", message));
    fields
        .iter()
        .map(|(name, value)| format!("{}={}", encoded(name), encoded(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// `text` percent-encoded for a form: every byte but the unreserved ones.
fn encoded(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The arguments that POST curl's stdin to `url`.
///
/// `--data-binary @-` sends stdin as it is. `--proto` keeps the URL, and any
/// redirect it answers with, to HTTP and HTTPS: curl also speaks `file://`
/// and a dozen others. The URL goes after `--url`, so nothing in it is read
/// as an option. A plain body gets its title as ntfy's header; a form carries
/// its own.
pub fn argv(url: &str, form: bool) -> Vec<String> {
    let max = MAX_SECS.to_string();
    let mut argv = vec![
        "--silent", "--show-error", "--fail", "--max-time", &max, "--proto", "=http,https",
        "--proto-redir", "=http,https", "--data-binary", "@-",
    ];
    if !form {
        argv.extend(["--header", "Title: hatch"]);
    }
    argv.extend(["--url", url]);
    argv.into_iter().map(str::to_string).collect()
}

/// Send `message` to `url`, as `form` says, and log what went wrong if
/// anything did.
pub async fn send(url: String, form: BTreeMap<String, String>, message: String) {
    let spawned = tokio::process::Command::new(PROGRAM)
        .args(argv(&url, !form.is_empty()))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            eprintln!("hatch could not run {PROGRAM} to send its notification: {error}");
            return;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        // Dropped at the end of this block, which is the end of the body. A
        // curl that exits without reading it says why below.
        let _ = stdin.write_all(body(&message, &form).as_bytes()).await;
    }
    match child.wait_with_output().await {
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
    fn the_url_cannot_be_read_as_an_option_and_the_body_comes_from_stdin() {
        for form in [false, true] {
            let argv = argv("-K/etc/passwd", form);
            let at = |flag: &str| argv.iter().position(|arg| arg == flag).expect(flag);
            assert_eq!(argv[at("--url") + 1], "-K/etc/passwd");
            assert_eq!(argv[at("--data-binary") + 1], "@-");
            assert_eq!(argv[at("--proto") + 1], "=http,https");
            assert_eq!(argv[at("--proto-redir") + 1], "=http,https");
            assert_eq!(argv.contains(&"Title: hatch".to_string()), !form, "{argv:?}");
        }
    }

    #[test]
    fn a_plain_body_is_the_message() {
        assert_eq!(body("Window 1 is waiting.", &BTreeMap::new()), "Window 1 is waiting.");
    }

    #[test]
    fn a_form_is_its_fields_then_a_title_then_the_message_encoded() {
        // Pushover's shape: the two credentials, then what to say.
        let form = BTreeMap::from([
            ("token".to_string(), "a&b=c".to_string()),
            ("user".to_string(), "u1".to_string()),
        ]);
        assert_eq!(
            body("Window 1 on desk: é.", &form),
            "token=a%26b%3Dc&user=u1&title=hatch&message=Window%201%20on%20desk%3A%20%C3%A9."
        );
        // A title of its own is kept; a message of its own is not.
        let form = BTreeMap::from([
            ("message".to_string(), "not this".to_string()),
            ("title".to_string(), "desk".to_string()),
        ]);
        assert_eq!(body("this", &form), "title=desk&message=this");
    }
}
