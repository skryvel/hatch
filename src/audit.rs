//! `AuditRecord`, `LogVerdict`, append-only audit writer.
//!
//! One JSON object per line, one line per outcome. A timeout, a client that
//! hung up and a prompt window that died are outcomes too: they are written
//! with their own verdicts, so a failure nobody was watching still leaves a
//! record. The file is opened, appended to and flushed per record, so the log
//! survives a crash of the process that wrote it.
//!
//! The verdict set here is a superset of the one the agent sees. A user
//! denial, a cancelled call, a dropped transport and a dead prompter all
//! answer the agent with "denied"; the log keeps them apart.
//!
//! Files are named `hatch-YYYY-MM.jsonl` and are never rotated or pruned —
//! a new month simply starts a new file, and old ones stay until the user
//! deletes them.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

/// How a request ended.
///
/// Every variant is a terminal outcome: exactly one is written per request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogVerdict {
    /// The user approved; the operation ran.
    Approve,
    /// The user pressed Deny.
    Deny,
    /// The user asked the agent to explain itself.
    Explain,
    /// The user asked the agent for a simpler request.
    Simplify,
    /// The user took the operation over and ran it themselves.
    SelfRun,
    /// The user stopped the work to talk to the agent, without saying
    /// anything about the request itself.
    StopAndSync,
    /// The approval window expired unanswered.
    Timeout,
    /// The user approved, but the polkit password dialog was cancelled or
    /// failed, so the operation never ran.
    ElevationFailed,
    /// The user approved, the elevation was attempted, and hatch cannot say
    /// whether the operation ran.
    ///
    /// Its own verdict rather than a shade of [`LogVerdict::Approve`] or of
    /// [`LogVerdict::ElevationFailed`], because both of those are claims and
    /// this is the absence of one. A cancelled password dialog and a command
    /// that ran and failed end with the same exit status — see
    /// [`crate::exec::elevate::RootOutcome::Unclear`] — and when the evidence
    /// that separates them is missing, the log has to be able to say so. A
    /// reader auditing what ran as root can then find these lines and check
    /// the machine, which is exactly what neither of the other two verdicts
    /// would prompt them to do.
    ElevationUnclear,
    /// The MCP client sent `notifications/cancelled`.
    Cancelled,
    /// The client's transport dropped.
    Disconnected,
    /// The approval window process died before returning a verdict.
    PromptDied,
    /// hatch rejected the request before showing it to the user: a symlinked
    /// target, a missing parent directory, a denylist hit, a nonexistent cwd.
    Refused,
}

impl LogVerdict {
    /// Every verdict, once. A new variant belongs here as well as in the
    /// exhaustive match below, so that callers and tests which must cover the
    /// whole set have one list to read rather than a copy of their own.
    pub const ALL: [LogVerdict; 13] = [
        LogVerdict::Approve,
        LogVerdict::Deny,
        LogVerdict::Explain,
        LogVerdict::Simplify,
        LogVerdict::SelfRun,
        LogVerdict::StopAndSync,
        LogVerdict::Timeout,
        LogVerdict::ElevationFailed,
        LogVerdict::ElevationUnclear,
        LogVerdict::Cancelled,
        LogVerdict::Disconnected,
        LogVerdict::PromptDied,
        LogVerdict::Refused,
    ];

    /// The verdict as it is written to the log. `Display` and the serialized
    /// tag are the same string, so a line printed by `hatch log` can be
    /// grepped for out of the file it came from.
    pub fn as_str(self) -> &'static str {
        match self {
            LogVerdict::Approve => "approve",
            LogVerdict::Deny => "deny",
            LogVerdict::Explain => "explain",
            LogVerdict::Simplify => "simplify",
            LogVerdict::SelfRun => "self_run",
            LogVerdict::StopAndSync => "stop_and_sync",
            LogVerdict::Timeout => "timeout",
            LogVerdict::ElevationFailed => "elevation_failed",
            LogVerdict::ElevationUnclear => "elevation_unclear",
            LogVerdict::Cancelled => "cancelled",
            LogVerdict::Disconnected => "disconnected",
            LogVerdict::PromptDied => "prompt_died",
            LogVerdict::Refused => "refused",
        }
    }
}

impl std::fmt::Display for LogVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `pad`, not `write_str`: the log listing puts verdicts in a column.
        f.pad(self.as_str())
    }
}

/// One outcome.
///
/// The tool-specific half is flattened in, so the record is one flat JSON
/// object and `tool` names which fields to expect beside the common ones.
///
/// A field that has no value is left out of the line rather than written as
/// null: `tool` already says which fields the record can carry, so a null
/// says nothing an absent key does not, and this file is read by eye as
/// often as by `jq`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// When the outcome was recorded, local time, to the second.
    #[serde(with = "rfc3339_secs")]
    pub ts: DateTime<Local>,
    /// The agent's one-line summary of what it wanted.
    pub title: String,
    /// The agent's justification, as it was shown to the user.
    pub reason: String,
    /// How it ended.
    pub verdict: LogVerdict,
    /// What the user typed into the prompt window, if anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// `tool` and the fields that go with it.
    #[serde(flatten)]
    pub detail: LogDetail,
}

/// The tool-specific fields, tagged by `tool`.
///
/// The tag is what puts `tool` in the record, and it is what decides which
/// variant a line is read back as. Leaving the variants untagged would make
/// that decision by trial and error over whichever fields happen to be
/// required, and every field a future variant adds could quietly change it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tool", rename_all = "snake_case")]
pub enum LogDetail {
    RunCommand(RunDetail),
    SwapFile(SwapDetail),
}

/// A `run_command` request. The first three fields are known when the request
/// arrives; the rest exist only once the command has actually run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDetail {
    /// The command line, exactly as it was rendered for approval.
    pub command: String,
    /// Whether it was requested as root.
    pub root: bool,
    /// The working directory it was to run in.
    pub cwd: String,
    /// Whether it ran in a terminal of its own, once it is known.
    ///
    /// Not known when the request arrives, which is what separates it from
    /// `root`: the agent may ask for a terminal and so may the person at the
    /// window, so the answer is settled by the verdict rather than by the
    /// call. `None` on every line for an operation that never ran.
    ///
    /// Recorded because it changes what is true of the run afterwards. A
    /// terminal run's output is one interleaved transcript that includes
    /// whatever the person typed, and somebody reading this log later to work
    /// out what reached the agent needs to know which kind of run they are
    /// looking at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interactive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// The user stopped a command that was already running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub killed_by_user: Option<bool>,
    /// The command outlived `exec_timeout_secs`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timed_out: Option<bool>,
    /// The prompt window died after the approval, while the command ran, so
    /// nobody was watching the output it produced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_died_after_approve: Option<bool>,
}

/// A `swap_file` request. `path` and `root` are known when the request
/// arrives; the rest describe the file as it ended up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapDetail {
    /// The file that was to be replaced.
    pub path: String,
    /// Whether the write was requested as root.
    pub root: bool,
    /// The target's hash before the write; absent when it did not exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_after: Option<String>,
    /// The mode the file was left at, as it is written, e.g. `0644`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// The owner the file was left at, as `user:group`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Bytes written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

/// The append-only writer over a log directory.
///
/// The directory is `$XDG_STATE_HOME/hatch/log` — `~/.local/state/hatch/log`
/// unless the variable says otherwise — created at 0700 by
/// [`crate::config::Config::load_or_create`]; this type only writes into it.
pub struct AuditLog {
    dir: PathBuf,
}

impl AuditLog {
    /// A writer over `dir`, which must already exist.
    pub fn new(dir: &Path) -> Self {
        Self { dir: dir.to_path_buf() }
    }

    /// The file the next record goes to: the current month's.
    pub fn current_path(&self) -> PathBuf {
        self.dir.join(format!("hatch-{}.jsonl", Local::now().format("%Y-%m")))
    }

    /// Append one record and flush it.
    ///
    /// The file is opened per record and never truncated, so a restart, a
    /// second writer or a month boundary all just continue the history.
    pub fn append(&self, record: &AuditRecord) -> anyhow::Result<()> {
        let path = self.current_path();
        let mut line = serde_json::to_string(record).context("serializing an audit record")?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        file.write_all(line.as_bytes())
            .with_context(|| format!("appending to {}", path.display()))?;
        file.flush().with_context(|| format!("flushing {}", path.display()))
    }

    /// Print the current month's file, one line per record.
    fn print_current(&self) -> anyhow::Result<()> {
        let path = self.current_path();
        if !path.exists() {
            println!("no entries yet in {}", path.display());
            return Ok(());
        }
        let content =
            std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        for line in content.lines() {
            println!("{}", render_line(line));
        }
        Ok(())
    }
}

/// One stored line, rendered for a human.
///
/// A line this build cannot parse is printed as it stands. The whole point of
/// the log is that nothing that happened is invisible, so a record written by
/// another version is shown raw rather than skipped.
fn render_line(line: &str) -> String {
    match serde_json::from_str::<AuditRecord>(line) {
        Ok(record) => record.summary(),
        Err(_) => visible(line),
    }
}

/// Text that reaches the terminal, with the characters that command a
/// terminal turned into the characters that name them.
///
/// Every string in a record is chosen by the agent, and the threat model is an
/// agent that has been talked into lying. A newline in a `title` would let one
/// record print as two, forging a benign entry and shifting the real one out
/// of place; an ANSI escape would let it clear the line, recolour it or move
/// the cursor. So C0, DEL and C1 are rendered rather than obeyed.
///
/// They are shown, not dropped: a title that contains an escape is itself
/// worth seeing, and deleting it would hide the attempt. A literal backslash
/// is left alone, because `\n` typed into a title is as harmless on screen as
/// a real newline now is, and doubling every backslash would make the common
/// case -- a command full of them -- harder to read. The stored JSONL is the
/// record of what was actually written; this is only its rendering.
fn visible(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // The rest of C0, DEL, and C1 -- everything else that can start an
            // escape sequence or move the cursor.
            c if (c as u32) < 0x20 || ('\u{7f}'..='\u{9f}').contains(&c) => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

impl AuditRecord {
    /// One human-readable line: when, how it ended, what it was, and the
    /// operation itself.
    fn summary(&self) -> String {
        let mut line = format!(
            "{}  {:<16}  {}  |  {}",
            self.ts.format("%Y-%m-%d %H:%M:%S"),
            self.verdict,
            visible(&self.title),
            self.detail.summary()
        );
        if let Some(note) = &self.note {
            line.push_str(&format!("  |  note: {}", visible(note)));
        }
        line
    }
}

impl LogDetail {
    fn summary(&self) -> String {
        match self {
            LogDetail::RunCommand(run) => {
                let mut s =
                    format!("{} {}", if run.root { "#" } else { "$" }, visible(&run.command));
                if let Some(code) = run.exit_code {
                    s.push_str(&format!("  (exit {code}"));
                    if let Some(ms) = run.duration_ms {
                        s.push_str(&format!(", {ms}ms"));
                    }
                    s.push(')');
                }
                if run.timed_out == Some(true) {
                    s.push_str("  (timed out)");
                }
                if run.killed_by_user == Some(true) {
                    s.push_str("  (killed)");
                }
                if run.prompt_died_after_approve == Some(true) {
                    s.push_str("  (prompt died while it ran)");
                }
                s
            }
            LogDetail::SwapFile(swap) => {
                let mut s =
                    format!("{} {}", if swap.root { "#" } else { "$" }, visible(&swap.path));
                if let Some(bytes) = swap.bytes {
                    s.push_str(&format!("  ({bytes} bytes"));
                    if let Some(mode) = &swap.mode {
                        s.push_str(&format!(", {}", visible(mode)));
                    }
                    if let Some(owner) = &swap.owner {
                        s.push_str(&format!(", {}", visible(owner)));
                    }
                    s.push(')');
                }
                s
            }
        }
    }
}

/// RFC 3339 with a local offset and no sub-second part, because a human reads
/// this file. `chrono`'s own serde support is not compiled in, and second
/// granularity is what the log format specifies.
mod rfc3339_secs {
    use chrono::{DateTime, Local, SecondsFormat};
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(ts: &DateTime<Local>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&ts.to_rfc3339_opts(SecondsFormat::Secs, false))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Local>, D::Error> {
        let text = String::deserialize(d)?;
        DateTime::parse_from_rfc3339(&text)
            .map(|ts| ts.with_timezone(&Local))
            .map_err(D::Error::custom)
    }
}

/// Tail the audit log for `hatch log`.
pub fn tail() -> anyhow::Result<()> {
    let paths = crate::paths::Paths::from_env()?;
    paths.report();
    AuditLog::new(&paths.log_dir()).print_current()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record with every field a real one carries, so a serialization test
    /// exercises the whole shape rather than the two fields it asserts on.
    fn sample_record(verdict: LogVerdict) -> AuditRecord {
        AuditRecord {
            ts: fixed_ts(),
            title: "Fix DNS resolution".to_string(),
            reason: "resolved is stale after the netctl change".to_string(),
            verdict,
            note: None,
            detail: LogDetail::RunCommand(RunDetail {
                command: "systemctl restart systemd-resolved".to_string(),
                root: true,
                cwd: "/home/user".to_string(),
                interactive: Some(false),
                exit_code: Some(0),
                duration_ms: Some(2140),
                killed_by_user: Some(false),
                timed_out: Some(false),
                prompt_died_after_approve: None,
            }),
        }
    }

    fn fixed_ts() -> DateTime<Local> {
        DateTime::parse_from_rfc3339("2026-08-30T18:42:11+02:00")
            .unwrap()
            .with_timezone(&Local)
    }

    #[test]
    fn every_log_verdict_serializes_to_a_distinct_tag() {
        // Off `ALL` rather than a copy of it. This test had its own list, and
        // a list written out beside the one it is meant to check is a test
        // that goes on passing about a set that has moved on without it — it
        // would have said "every verdict" while asking about twelve of
        // thirteen.
        let tags: std::collections::HashSet<_> =
            LogVerdict::ALL.iter().map(|v| serde_json::to_string(v).unwrap()).collect();
        assert_eq!(tags.len(), LogVerdict::ALL.len(), "two verdicts share a tag");
    }

    #[test]
    fn appends_one_line_per_record() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path());
        log.append(&sample_record(LogVerdict::Approve)).unwrap();
        log.append(&sample_record(LogVerdict::Cancelled)).unwrap();
        let content = std::fs::read_to_string(log.current_path()).unwrap();
        assert_eq!(content.lines().count(), 2);
        for line in content.lines() {
            serde_json::from_str::<serde_json::Value>(line).unwrap();
        }
    }

    #[test]
    fn a_fresh_log_appends_to_what_the_previous_one_wrote() {
        // A restart must not lose the history: the writer opens the file for
        // every record, and it may never truncate one that already exists.
        let dir = tempfile::tempdir().unwrap();
        AuditLog::new(dir.path())
            .append(&sample_record(LogVerdict::Approve))
            .unwrap();
        AuditLog::new(dir.path())
            .append(&sample_record(LogVerdict::Refused))
            .unwrap();

        let log = AuditLog::new(dir.path());
        let content = std::fs::read_to_string(log.current_path()).unwrap();
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 2, "the second instance must not truncate");
        assert!(lines[0].contains("\"approve\""), "the first record must survive");
        assert!(lines[1].contains("\"refused\""), "the second record must follow it");
    }

    #[test]
    fn the_current_file_is_this_month_in_the_log_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = AuditLog::new(dir.path()).current_path();
        assert_eq!(path.parent().unwrap(), dir.path());
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(
            regex::Regex::new(r"^hatch-\d{4}-\d{2}\.jsonl$").unwrap().is_match(name),
            "month-granular name, got {name}"
        );
        assert_eq!(name, format!("hatch-{}.jsonl", Local::now().format("%Y-%m")));
    }

    #[test]
    fn absent_detail_is_omitted_rather_than_written_as_null() {
        // `hatch log` is read by a human and grepped with jq. A denied swap
        // never produced an after-hash, a mode or a byte count; the keys are
        // absent, not present-and-null.
        let record = AuditRecord {
            ts: fixed_ts(),
            title: "Add staging host".to_string(),
            reason: "the deploy target moved".to_string(),
            verdict: LogVerdict::Deny,
            note: Some("wrong IP, it's .12 not .21".to_string()),
            detail: LogDetail::SwapFile(SwapDetail {
                path: "/etc/hosts".to_string(),
                root: true,
                hash_before: Some("9f3a".to_string()),
                hash_after: None,
                mode: None,
                owner: None,
                bytes: None,
            }),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("null"), "no null values: {json}");
        for absent in ["hash_after", "mode", "owner", "bytes"] {
            assert!(!json.contains(absent), "{absent} must be omitted: {json}");
        }
        assert!(json.contains("\"hash_before\":\"9f3a\""), "present fields stay: {json}");
        assert!(json.contains("\"note\":"), "the user's note stays: {json}");
    }

    #[test]
    fn a_record_round_trips_with_its_tool_and_detail_intact() {
        // The tool tag and the flattened detail must agree: reading a swap
        // record back as an empty run record would be a silent data loss.
        for record in [sample_record(LogVerdict::Approve), swap_record()] {
            let json = serde_json::to_string(&record).unwrap();
            let back: AuditRecord = serde_json::from_str(&json).unwrap();
            assert_eq!(back, record, "round trip changed the record: {json}");
        }
    }

    #[test]
    fn the_tool_name_is_written_on_every_record() {
        let run = serde_json::to_string(&sample_record(LogVerdict::Approve)).unwrap();
        assert!(run.contains("\"tool\":\"run_command\""), "{run}");
        let swap = serde_json::to_string(&swap_record()).unwrap();
        assert!(swap.contains("\"tool\":\"swap_file\""), "{swap}");
    }

    #[test]
    fn the_timestamp_is_second_granular_rfc3339() {
        let json = serde_json::to_string(&sample_record(LogVerdict::Approve)).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let ts = value["ts"].as_str().unwrap();
        assert!(
            regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\+|-)\d{2}:\d{2}$")
                .unwrap()
                .is_match(ts),
            "sub-second noise in a human-read log: {ts}"
        );
    }

    #[test]
    fn a_printed_verdict_is_the_tag_it_was_logged_under() {
        // `hatch log` output must be greppable against the file it came from.
        for v in LogVerdict::ALL {
            let tag = serde_json::to_string(&v).unwrap();
            assert_eq!(format!("\"{v}\""), tag);
        }
    }

    #[test]
    fn every_verdict_is_listed_once_in_all() {
        let tags: std::collections::HashSet<_> =
            LogVerdict::ALL.iter().map(|v| v.as_str()).collect();
        assert_eq!(tags.len(), LogVerdict::ALL.len(), "a verdict is listed twice in ALL");
    }

    #[test]
    fn the_human_line_carries_the_verdict_the_title_and_the_operation() {
        let mut record = sample_record(LogVerdict::Deny);
        record.note = Some("not while the VPN is up".to_string());
        let line = record.summary();
        assert_eq!(line.lines().count(), 1, "one line per record: {line}");
        for part in [
            "2026-08-30",
            "deny",
            "Fix DNS resolution",
            "systemctl restart systemd-resolved",
            "not while the VPN is up",
        ] {
            assert!(line.contains(part), "{part} missing from: {line}");
        }
        assert!(line.contains("# systemctl"), "root must be visible: {line}");
        assert!(line.contains("deny            "), "verdicts must be padded into a column: {line}");
    }

    #[test]
    fn a_line_this_build_cannot_parse_is_still_shown() {
        let known = serde_json::to_string(&sample_record(LogVerdict::Approve)).unwrap();
        assert!(render_line(&known).contains("Fix DNS resolution"));

        let alien = r#"{"ts":"2027-01-01T00:00:00+00:00","tool":"summon_daemon"}"#;
        assert_eq!(render_line(alien), alien, "an unreadable record must not vanish");

        // A line this build cannot parse is a line it cannot vouch for
        // either, so it is defanged on the way to the terminal like any other.
        let hostile = "not json \u{1b}[2K\u{1b}[31m";
        let shown = render_line(hostile);
        assert!(!shown.contains('\u{1b}'), "no raw ESC: {shown:?}");
        assert!(shown.contains("\\x1b[2K"), "shown, not dropped: {shown}");
    }

    #[test]
    fn a_newline_in_a_title_cannot_forge_a_second_line() {
        // The agent writes the title. If it could put a newline in one, a
        // single refused record could print as two, inventing a benign entry
        // and pushing the real one out of the position a reader expects.
        let mut record = sample_record(LogVerdict::Refused);
        record.title = "harmless\n2026-09-06 12:00:01  approve           Routine cleanup".into();
        let line = record.summary();
        assert_eq!(line.lines().count(), 1, "one record is one line: {line}");
        assert!(!line.contains('\n'), "no raw newline: {line:?}");
        assert!(line.contains("harmless\\n2026-09-06"), "shown, not dropped: {line}");
    }

    #[test]
    fn an_ansi_escape_in_a_note_is_printed_not_obeyed() {
        let mut record = sample_record(LogVerdict::Deny);
        record.note = Some("\u{1b}[2K\u{1b}[31mnothing to see here\u{9b}0m".into());
        let line = record.summary();
        assert!(!line.contains('\u{1b}'), "no raw ESC: {line:?}");
        assert!(!line.contains('\u{9b}'), "no raw C1 control: {line:?}");
        assert!(line.contains("\\x1b[2K"), "the escape must still be visible: {line}");
        assert!(line.contains("\\x9b"), "the C1 control must still be visible: {line}");
    }

    #[test]
    fn control_characters_in_a_command_or_a_path_are_defanged() {
        // The other two agent-controlled strings that reach the terminal.
        let mut run = sample_record(LogVerdict::Approve);
        if let LogDetail::RunCommand(detail) = &mut run.detail {
            detail.command = "echo ok\r\u{1b}[Aeverything is fine".into();
        }
        let mut swap = swap_record();
        if let LogDetail::SwapFile(detail) = &mut swap.detail {
            detail.path = "/etc/hosts\n2026-09-06 12:00:01  approve".into();
        }
        for record in [run, swap] {
            let line = record.summary();
            assert_eq!(line.lines().count(), 1, "one record is one line: {line}");
            assert!(!line.contains('\u{1b}'), "no raw ESC: {line:?}");
            assert!(!line.contains('\r'), "no raw carriage return: {line:?}");
        }
    }

    fn swap_record() -> AuditRecord {
        AuditRecord {
            ts: fixed_ts(),
            title: "Add staging host".to_string(),
            reason: "the deploy target moved".to_string(),
            verdict: LogVerdict::Approve,
            note: None,
            detail: LogDetail::SwapFile(SwapDetail {
                path: "/etc/hosts".to_string(),
                root: true,
                hash_before: Some("9f3a".to_string()),
                hash_after: Some("11bc".to_string()),
                mode: Some("0644".to_string()),
                owner: Some("root:root".to_string()),
                bytes: Some(412),
            }),
        }
    }
}
