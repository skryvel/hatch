//! `AuditRecord`, `LogVerdict`, append-only audit writer.
//!
//! One JSON object per line, one line per operation. A timeout, a client that
//! hung up and a prompt window that died are outcomes too: they are written
//! with their own verdicts, so a failure nobody was watching still leaves a
//! record. The file is opened, appended to and flushed per record, so the log
//! survives a crash of the process that wrote it.
//!
//! # One decision, several lines
//!
//! A `batch` is one approval covering several operations, and it is written
//! as one line for each of them rather than as one line holding a list. The
//! two questions this file exists to answer are *what wrote to this file* and
//! *what ran as root*, and both are asked with `grep` or `jq` a line at a
//! time. A line holding three operations matches a search for one path with
//! two other effects riding along on it, and it matches `"root":true` when
//! one of the three was root and the other two were not -- so the answer to
//! "what ran as root" would come back with things that did not. One line per
//! effect keeps every line a true answer about exactly one thing.
//!
//! The decision is what the lines share, and they share it visibly: the same
//! `ts`, the same `number`, the same title, reason and note, and an
//! `operation` of `operations` that places each one. A request of one
//! operation is one line, as it always was.
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

/// How one operation of a request ended.
///
/// Every variant is a terminal outcome: exactly one is written per operation.
/// A decision that was never made about an operation -- a denial, a timeout,
/// a refusal -- is the same verdict on every operation the request carried.
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
    /// The user took the operation over to do themselves: to run the command
    /// or to make the change to the file.
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
    /// The user approved the request this operation was part of, and the run
    /// ended before it was reached.
    ///
    /// Its own verdict and not an [`LogVerdict::Approve`] with nothing filled
    /// in, because the difference is the whole of what somebody reading the
    /// file later is asking. An approved write with no `hash_after` could be a
    /// write that was refused for drift; this is a write that was never tried,
    /// and the operation before it on the same `number` says why.
    NotAttempted,
    /// hatch rejected the request before showing it to the user: a symlinked
    /// target, a missing parent directory, a denylist hit, a nonexistent cwd.
    Refused,
}

impl LogVerdict {
    /// Every verdict, once. A new variant belongs here as well as in the
    /// exhaustive match below, so that callers and tests which must cover the
    /// whole set have one list to read rather than a copy of their own.
    pub const ALL: [LogVerdict; 14] = [
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
        LogVerdict::NotAttempted,
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
            LogVerdict::NotAttempted => "not_attempted",
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
    /// Which approval window this was, counting from one, if it ever became
    /// one.
    ///
    /// The same number the window wore in its title bar, so a person who says
    /// *I denied forty-seven* has said something this file can be searched
    /// for. Absent on a line for a request hatch refused before anybody was
    /// asked: there was no window, so there is no number, and writing a zero
    /// would invent one.
    ///
    /// It is a handle and not an identity. The counter is the running
    /// daemon's and starts again at one when it restarts -- see
    /// [`crate::queue::Admission::number`] -- so a month's file can hold two
    /// `#3`s. `ts` is what tells them apart, which is why the number is
    /// beside it rather than instead of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<u64>,
    /// The agent's one-line summary of what it wanted.
    pub title: String,
    /// The agent's justification, as it was shown to the user.
    pub reason: String,
    /// Which operation of the request this line is about, counting from one.
    ///
    /// Written on every line, including the lines of a request that only ever
    /// had one, for the reason [`SwapForm`] is: the JSON is what gets parsed,
    /// and a key that is absent on most lines is a question on most lines. A
    /// line from a build that predates batches reads back as the first of
    /// one, which is what every request then was.
    #[serde(default = "first")]
    pub operation: usize,
    /// How many operations the request carried.
    #[serde(default = "first")]
    pub operations: usize,
    /// Whether the request was to stop at its first failed operation, or to
    /// run every operation whichever of them failed.
    ///
    /// The agent's choice, written down because it decides what a
    /// `not_attempted` line further down the same request means. A line from
    /// before the choice existed reads back as `false`, the default; it had
    /// one operation, and with one operation the two policies are the same.
    #[serde(default)]
    pub stop_on_failure: bool,
    /// How it ended.
    pub verdict: LogVerdict,
    /// How long the approval window was on screen before this ended it, in
    /// milliseconds.
    ///
    /// Absent when there was never a window: a request refused before the
    /// queue was never on anybody's screen, and a zero there would claim it
    /// was and was answered instantly.
    ///
    /// # What it is for
    ///
    /// The file already says *what* ended a request. It could not say whether
    /// a person was there. A denial after four seconds is somebody reading
    /// and deciding; a denial after eighty milliseconds is not a decision at
    /// all, whatever the verdict column says, and the two were written down
    /// identically.
    ///
    /// That gap is why a report of windows closing on their own could not be
    /// checked against anything. It is recorded on every line, including the
    /// approvals, because a number that only appears on the lines somebody
    /// already suspects is a number they cannot calibrate: knowing that an
    /// ordinary approval takes seconds is what makes eighty milliseconds mean
    /// something.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_ms: Option<u64>,
    /// What the user typed into the prompt window, if anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// `tool` and the fields that go with it.
    #[serde(flatten)]
    pub detail: LogDetail,
}

/// The fields of one kind of operation, tagged by `tool`.
///
/// The tag is what puts `tool` in the record, and it is what decides which
/// variant a line is read back as. Leaving the variants untagged would make
/// that decision by trial and error over whichever fields happen to be
/// required, and every field a future variant adds could quietly change it.
///
/// The key is still called `tool` and it no longer names one. It dates from
/// when each tool did one kind of thing; a write now arrives inside a
/// `batch`, and a command may arrive through `batch` or through its shortcut,
/// so what the tag names is the kind of operation. The key kept its name so
/// that every line already in somebody's log parses the way it did, and the
/// old values are read as aliases for the same reason: `swap_file` names a
/// tool that is gone, and a month's file written before it went still has to
/// say what was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tool")]
pub enum LogDetail {
    #[serde(rename = "command", alias = "run_command")]
    RunCommand(RunDetail),
    #[serde(rename = "write", alias = "swap_file")]
    SwapFile(SwapDetail),
}

/// The count a line from before batches reads back with: the first of one.
fn first() -> usize {
    1
}

/// A command. The first three fields are known when the request arrives; the
/// rest exist only once the command has actually run.
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
    /// Where the approval window was while the command ran.
    ///
    /// `None` on every line for an operation that never ran, for the same
    /// reason `exit_code` is: there was no run for a window to be absent from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<PromptEnd>,
    /// What became of the output of a run its reader asked to review.
    ///
    /// `None` for every run nobody asked to review, and for a reviewed run
    /// that left no output to review — a command that could not start, an
    /// elevation that ran nothing.
    ///
    /// # What it does not record
    ///
    /// The output, or any part of it, and nothing about what was removed:
    /// not the lines, not the drop patterns, not an edit. This file has never
    /// held a command's output — it holds the command, which the person read
    /// and approved — and a review exists to keep text away from somewhere it
    /// would otherwise go. A log that kept what the person removed would be
    /// the one copy of it that survives, in a file whose whole purpose is to
    /// be read back later. What is here is only which of the endings it was,
    /// which is what somebody working out what reached the agent needs.
    ///
    /// The note the reader writes at the review is not here either, and that
    /// is a decision rather than an omission. The note beside a *verdict* is
    /// recorded -- see `note` on the record itself -- because it is written
    /// about a command, before anybody has seen a byte of output. This one is
    /// written while reading output the person may be about to withhold, which
    /// makes it the likeliest place in hatch for somebody to quote the very
    /// thing they are keeping back. It already reached the agent; a second
    /// copy in this file would be the durable one, in the file the review
    /// exists to keep such text out of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<ReviewEnd>,
}

/// What became of reviewed output.
///
/// The five endings a review has, told apart by what the agent received.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewEnd {
    /// The reader sent it without taking anything out or changing anything.
    Released,
    /// The reader sent some of its lines, unchanged: a filter, or lines
    /// deleted by hand, which the agent cannot tell apart and neither can
    /// this.
    Filtered,
    /// The reader changed the text before sending it.
    Edited,
    /// The reader chose to send none of it.
    Withheld,
    /// Nobody answered the review — its deadline passed, the window went,
    /// or the call was abandoned — and none of it was sent.
    ///
    /// Apart from [`ReviewEnd::Withheld`] because that one is a decision and
    /// this is the absence of one, which is the difference between a timeout
    /// and a denial one step later.
    Unreviewed,
}

/// Where the approval window was while the operation it authorised ran.
///
/// Three facts and not a boolean, because a window that went away on purpose
/// and a window that died are not the same news and the log is the one place
/// that has to keep saying which. This was `prompt_died_after_approve: bool`,
/// which had exactly two states and therefore had to file a deliberate close
/// under "died" — putting `(prompt died while it ran)` on every approved
/// command belonging to anybody who had ticked the box asking for one. The
/// single line that means *something went wrong* would then have appeared on
/// every line, which is strictly worse than not recording it at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptEnd {
    /// It was there for the whole run: the live view and the Kill button
    /// existed for as long as there was something to use them on.
    Held,
    /// It closed itself the instant the verdict was given, because the reader
    /// had ticked "Close when I decide". Nobody watched the run and nobody
    /// could have killed it — and both of those are what was asked for, which
    /// is why this prints nothing.
    Dismissed,
    /// It went away while the command ran without being asked to. The command
    /// was authorised and ran to completion regardless; what was lost is the
    /// Kill button and the live view, and losing them unasked is worth a
    /// reader's attention.
    Died,
}

/// A file write. `path` and `root` are known when the request arrives; the
/// rest describe the file as it ended up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapDetail {
    /// The file that was to be replaced.
    pub path: String,
    /// Whether the write was requested as root.
    pub root: bool,
    /// Which of the two forms of a write the request arrived in.
    ///
    /// Not a fact about the change — a patch is applied before anybody is
    /// asked, so the bytes, the plan and the diff on screen are the same
    /// either way — but a fact about the *request*, and this file is where
    /// facts about requests live. Somebody reading a line back needs to know
    /// what the agent actually sent, not least because the two forms fail
    /// differently: only one of them can be refused for not applying.
    #[serde(default)]
    pub form: SwapForm,
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

/// How a write said what the file should contain.
///
/// Written on every record rather than only when it is news, because the JSON
/// is what a later reader parses and a missing key there is a question rather
/// than an answer. [`Default`] is the whole-file form, so a line from a build
/// that predates the patch form reads back as what it was.
///
/// The *rendered* line is the other way round and mentions only the patch, on
/// the rule the rest of this file follows: a note that appears on every line
/// is read by nobody, which would take the one that matters down with it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapForm {
    /// `content`: the complete new contents of the file.
    #[default]
    Content,
    /// `patch`: a unified diff, applied at render time. See [`crate::patch`].
    Patch,
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

/// How long a window was on screen, at the precision a reader needs.
///
/// Milliseconds below a second and tenths of a second above it. The whole
/// question this answers is *was somebody there*, and the answer turns on the
/// difference between eighty milliseconds and four seconds rather than on the
/// difference between 4.2 and 4.3.
fn on_screen(ms: u64) -> String {
    match ms {
        ms if ms < 1_000 => format!("{ms}ms"),
        ms => format!("{:.1}s", ms as f64 / 1_000.0),
    }
}

impl AuditRecord {
    /// One human-readable line: when, how it ended, what it was, and the
    /// operation itself.
    fn summary(&self) -> String {
        let mut line = format!(
            "{}  {:<5}{:<16}  {}  |  {}{}",
            self.ts.format("%Y-%m-%d %H:%M:%S"),
            // A column of its own, left empty rather than skipped for a
            // refusal that never got a number: the verdicts below it stay in
            // line, which is what makes a file read by eye readable at all.
            match self.number {
                Some(number) => format!("#{number}"),
                None => String::new(),
            },
            self.verdict,
            visible(&self.title),
            self.position(),
            self.detail.summary()
        );
        // Before the note, so a note stays the last thing on the line, and on
        // every line rather than only the suspicious ones: an abnormal
        // lifetime can only be recognised by somebody who has seen the
        // ordinary ones in the same column.
        if let Some(ms) = self.window_ms {
            line.push_str(&format!("  |  window {}", on_screen(ms)));
        }
        if let Some(note) = &self.note {
            line.push_str(&format!("  |  note: {}", visible(note)));
        }
        line
    }

    /// Where this line's operation sits in its request, when it has company.
    ///
    /// Empty for a request of one operation, which is every request today and
    /// most requests afterwards: the JSON says `1` of `1` because a parser
    /// wants an answer, and the line a person reads says nothing because a
    /// note on every line is read by nobody. A line that is one of several
    /// says which, and says the policy the several ran under, because that is
    /// what explains a `not_attempted` two lines further down.
    fn position(&self) -> String {
        if self.operations <= 1 {
            return String::new();
        }
        format!(
            "[{} of {}, {}]  ",
            self.operation,
            self.operations,
            match self.stop_on_failure {
                true => "stopping at a failure",
                false => "running on past a failure",
            }
        )
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
                // Only the one that is news. A window that was there is the
                // ordinary case and a window that was asked to go is what its
                // reader chose; a suffix on either would be a note on every
                // line, and a note on every line is read by nobody — which
                // would take the one that matters down with it.
                if run.prompt == Some(PromptEnd::Died) {
                    s.push_str("  (prompt died while it ran)");
                }
                // Every one of them, unlike the prompt's three. A review is
                // asked for one command at a time and never by default, so
                // this is not a note on every line; and the question a reader
                // of this file brings to one — what reached the agent — has a
                // different answer for each.
                match run.review {
                    None => {}
                    Some(ReviewEnd::Released) => s.push_str("  (output reviewed, sent in full)"),
                    Some(ReviewEnd::Filtered) => s.push_str("  (output reviewed, lines removed)"),
                    Some(ReviewEnd::Edited) => s.push_str("  (output reviewed, edited)"),
                    Some(ReviewEnd::Withheld) => s.push_str("  (output reviewed, withheld)"),
                    Some(ReviewEnd::Unreviewed) => {
                        s.push_str("  (output withheld, not reviewed in time)")
                    }
                }
                s
            }
            LogDetail::SwapFile(swap) => {
                let mut s =
                    format!("{} {}", if swap.root { "#" } else { "$" }, visible(&swap.path));
                if swap.form == SwapForm::Patch {
                    s.push_str("  (from a patch)");
                }
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
            number: Some(47),
            title: "Fix DNS resolution".to_string(),
            reason: "resolved is stale after the netctl change".to_string(),
            operation: 1,
            operations: 1,
            window_ms: Some(4_200),
            stop_on_failure: false,
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
                prompt: None,
                review: None,
            }),
        }
    }

    fn fixed_ts() -> DateTime<Local> {
        DateTime::parse_from_rfc3339("2026-08-30T18:42:11+02:00")
            .unwrap()
            .with_timezone(&Local)
    }

    #[test]
    fn how_long_a_window_was_on_screen_is_on_the_readable_line() {
        // The number is useless in the file if reading it needs a JSON tool:
        // the person who wants it is scanning for a denial that happened too
        // fast to have been one.
        let mut record = sample_record(LogVerdict::Deny);
        record.window_ms = Some(4_210);
        assert!(record.summary().contains("window 4.2s"), "{}", record.summary());

        record.window_ms = Some(80);
        assert!(record.summary().contains("window 80ms"), "{}", record.summary());

        // A request nobody was shown says nothing, rather than `0ms`, which
        // would read as answered-instantly.
        record.window_ms = None;
        assert!(!record.summary().contains("window"), "{}", record.summary());
    }

    #[test]
    fn a_window_lifetime_is_written_at_the_precision_that_answers_the_question() {
        assert_eq!(on_screen(0), "0ms");
        assert_eq!(on_screen(999), "999ms");
        assert_eq!(on_screen(1_000), "1.0s");
        assert_eq!(on_screen(4_210), "4.2s");
        assert_eq!(on_screen(600_000), "600.0s");
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
            number: Some(2),
            title: "Add staging host".to_string(),
            reason: "the deploy target moved".to_string(),
            operation: 1,
            operations: 1,
            window_ms: Some(4_200),
            stop_on_failure: false,
            verdict: LogVerdict::Deny,
            note: Some("wrong IP, it's .12 not .21".to_string()),
            detail: LogDetail::SwapFile(SwapDetail {
                path: "/etc/hosts".to_string(),
                root: true,
                form: SwapForm::Content,
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
    fn which_form_a_swap_arrived_in_is_written_down_and_shown_only_when_it_is_news() {
        // The JSON says it either way, because a reader of the file needs an
        // answer rather than an absence. The line a person reads says it only
        // for the patch: a note on every line is read by nobody.
        let content = swap_record();
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"form\":\"content\""), "{json}");
        assert!(!content.summary().contains("patch"), "{}", content.summary());

        let mut patched = swap_record();
        if let LogDetail::SwapFile(detail) = &mut patched.detail {
            detail.form = SwapForm::Patch;
        }
        let json = serde_json::to_string(&patched).unwrap();
        assert!(json.contains("\"form\":\"patch\""), "{json}");
        assert!(patched.summary().contains("(from a patch)"), "{}", patched.summary());
    }

    #[test]
    fn a_record_written_before_there_was_a_patch_form_reads_back_as_the_form_it_was() {
        // `hatch log` parses every line of a file that outlives the build that
        // wrote it. A line from before the second form existed was a whole-file
        // write, and the default has to say so rather than inventing a third
        // state for it.
        let line = r#"{"ts":"2026-09-06T12:00:00+02:00","title":"t","reason":"r",
            "verdict":"approve","tool":"swap_file","path":"/etc/hosts","root":false}"#;
        let record: AuditRecord = serde_json::from_str(line).expect("an older line still parses");
        let LogDetail::SwapFile(detail) = record.detail else { panic!("a swap record") };
        assert_eq!(detail.form, SwapForm::Content);
    }

    #[test]
    fn the_kind_of_operation_is_written_on_every_record() {
        let run = serde_json::to_string(&sample_record(LogVerdict::Approve)).unwrap();
        assert!(run.contains("\"tool\":\"command\""), "{run}");
        let swap = serde_json::to_string(&swap_record()).unwrap();
        assert!(swap.contains("\"tool\":\"write\""), "{swap}");
    }

    #[test]
    fn a_line_written_under_the_old_tool_names_still_reads_as_what_it_recorded() {
        // The user's log already holds months of `run_command` and
        // `swap_file` lines, and `swap_file` names a tool that no longer
        // exists. `hatch log` must go on reading them as the command and the
        // write they were -- not as lines it cannot parse and prints raw, and
        // not as lines from a request of zero operations.
        let run = r#"{"ts":"2026-09-06T12:00:00+02:00","title":"t","reason":"r",
            "verdict":"approve","tool":"run_command","command":"true","root":false,"cwd":"/"}"#;
        let swap = r#"{"ts":"2026-09-06T12:00:00+02:00","title":"t","reason":"r",
            "verdict":"approve","tool":"swap_file","path":"/etc/hosts","root":true}"#;

        let run: AuditRecord = serde_json::from_str(run).expect("an old command line parses");
        let LogDetail::RunCommand(detail) = &run.detail else { panic!("not a command") };
        assert_eq!(detail.command, "true");
        let swap: AuditRecord = serde_json::from_str(swap).expect("an old write line parses");
        let LogDetail::SwapFile(detail) = &swap.detail else { panic!("not a write") };
        assert_eq!(detail.path, "/etc/hosts");

        for old in [&run, &swap] {
            assert_eq!((old.operation, old.operations), (1, 1), "an old line is the first of one");
            assert!(!old.stop_on_failure, "{old:?}");
            assert!(!old.summary().contains(" of "), "an old line was placed in a batch");
        }
    }

    #[test]
    fn every_line_of_a_batch_says_where_it_sits_and_under_which_policy() {
        // The JSON says it on every line, a request of one included, because
        // that is what gets parsed. The line a person reads says it only when
        // there is company: `1 of 1` on every line is read by nobody.
        let alone = sample_record(LogVerdict::Approve);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&alone).unwrap()).unwrap();
        assert_eq!(json["operation"], 1);
        assert_eq!(json["operations"], 1);
        assert_eq!(json["stop_on_failure"], false);
        assert!(!alone.summary().contains("of 1"), "{}", alone.summary());

        for (stop_on_failure, policy) in
            [(true, "stopping at a failure"), (false, "running on past a failure")]
        {
            let mut second = swap_record();
            second.operation = 2;
            second.operations = 3;
            second.stop_on_failure = stop_on_failure;
            second.verdict = LogVerdict::NotAttempted;
            let json: serde_json::Value =
                serde_json::from_str(&serde_json::to_string(&second).unwrap()).unwrap();
            assert_eq!(json["operation"], 2);
            assert_eq!(json["operations"], 3);
            assert_eq!(json["stop_on_failure"], stop_on_failure);
            assert_eq!(json["verdict"], "not_attempted");

            let line = second.summary();
            assert!(line.contains("[2 of 3, "), "{line}");
            assert!(line.contains(policy), "{line}");
            // And the effect is still on the line with its own path, which
            // is what a search for the file finds.
            assert!(line.contains("/etc/hosts"), "{line}");
            assert_eq!(
                serde_json::from_str::<AuditRecord>(&serde_json::to_string(&second).unwrap())
                    .unwrap(),
                second,
                "a line of a batch did not survive the file"
            );
        }
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
        assert!(line.contains("#47"), "the number the window wore is missing from: {line}");
    }

    #[test]
    fn the_number_the_window_wore_is_written_down_and_is_absent_when_there_was_none() {
        // The number is a handle: a person says "I denied forty-seven" and
        // this file is what they say it into. A request hatch refused before
        // anybody was asked never became a window, so it has no number -- and
        // an absent key says that, where a zero would invent one.
        let numbered = sample_record(LogVerdict::Deny);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&numbered).unwrap()).unwrap();
        assert_eq!(json["number"], 47);

        let mut refused = sample_record(LogVerdict::Refused);
        refused.number = None;
        let text = serde_json::to_string(&refused).unwrap();
        assert!(!text.contains("number"), "a request nobody saw carries no number: {text}");

        // And the column is still a column, so the verdicts below a refusal
        // stay in line with the ones above it.
        let (with, without) = (numbered.summary(), refused.summary());
        assert_eq!(
            with.find("deny"),
            without.find("refused"),
            "the verdict column moved:\n{with}\n{without}"
        );
    }

    #[test]
    fn only_a_window_that_died_unasked_is_worth_a_suffix() {
        // The line `(prompt died while it ran)` means something went wrong.
        // It was a boolean, so a window closing because its reader had ticked
        // "Close when I decide" had to be filed under the same word — and the
        // suffix would then have appeared under every approved command that
        // person ever ran, which is how the one line that matters stops being
        // read at all.
        let line = |end| {
            let mut record = sample_record(LogVerdict::Approve);
            if let LogDetail::RunCommand(run) = &mut record.detail {
                run.prompt = end;
            }
            record.summary()
        };
        let suffix = "(prompt died while it ran)";
        assert!(line(Some(PromptEnd::Died)).contains(suffix), "a real death says nothing");
        assert!(!line(Some(PromptEnd::Dismissed)).contains(suffix), "a close was called a death");
        assert!(!line(Some(PromptEnd::Held)).contains(suffix));
        assert!(!line(None).contains(suffix), "an operation that never ran lost no window");
    }

    #[test]
    fn where_the_window_went_survives_a_round_trip_through_the_file() {
        // The suffix is deliberately silent for two of the three, so the
        // record is the only place the difference is kept. It has to come back
        // out of the file as the thing that went in.
        for end in [PromptEnd::Held, PromptEnd::Dismissed, PromptEnd::Died] {
            let mut record = sample_record(LogVerdict::Approve);
            if let LogDetail::RunCommand(run) = &mut record.detail {
                run.prompt = Some(end);
            }
            let line = serde_json::to_string(&record).expect("a record encodes");
            assert_eq!(
                serde_json::from_str::<AuditRecord>(&line).expect("and decodes"),
                record
            );
        }
        let tags: std::collections::HashSet<_> =
            [PromptEnd::Held, PromptEnd::Dismissed, PromptEnd::Died]
                .iter()
                .map(|end| serde_json::to_string(end).expect("a tag"))
                .collect();
        assert_eq!(tags.len(), 3, "two of them are written down as the same word");
    }

    #[test]
    fn a_review_is_named_on_its_line_and_survives_the_file_without_any_of_the_output() {
        let ends = [
            ReviewEnd::Released,
            ReviewEnd::Filtered,
            ReviewEnd::Edited,
            ReviewEnd::Withheld,
            ReviewEnd::Unreviewed,
        ];
        let mut said = std::collections::HashSet::new();
        for end in ends {
            let mut record = sample_record(LogVerdict::Approve);
            if let LogDetail::RunCommand(run) = &mut record.detail {
                run.review = Some(end);
            }
            let line = serde_json::to_string(&record).expect("a record encodes");
            assert_eq!(serde_json::from_str::<AuditRecord>(&line).expect("decodes"), record);
            let summary = record.summary();
            assert!(summary.contains("(output"), "{end:?} left no trace on its line: {summary}");
            said.insert(summary);
        }
        assert_eq!(said.len(), ends.len(), "two endings read as the same line");

        // A line from before reviews reads back as a run nobody reviewed, and
        // a run nobody reviewed says nothing about it.
        let plain = sample_record(LogVerdict::Approve);
        let line = serde_json::to_string(&plain).unwrap();
        assert!(!line.contains("review"), "{line}");
        assert!(!plain.summary().contains("(output"));
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
            number: Some(3),
            title: "Add staging host".to_string(),
            reason: "the deploy target moved".to_string(),
            operation: 1,
            operations: 1,
            window_ms: Some(4_200),
            stop_on_failure: false,
            verdict: LogVerdict::Approve,
            note: None,
            detail: LogDetail::SwapFile(SwapDetail {
                path: "/etc/hosts".to_string(),
                root: true,
                form: SwapForm::Content,
                hash_before: Some("9f3a".to_string()),
                hash_after: Some("11bc".to_string()),
                mode: Some("0644".to_string()),
                owner: Some("root:root".to_string()),
                bytes: Some(412),
            }),
        }
    }
}
