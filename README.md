# hatch

An MCP server that lets a sandboxed AI coding agent ask for a shell command or
a file replacement on the host machine. Every request is drawn in a GUI window,
in a form built to be read, and nothing happens until the person at the
keyboard approves it.

The agent is in a sandbox for a reason, and the reason does not go away because
the agent now needs to restart a service or edit a file under `/etc`. hatch is
a door rather than a hole in the wall: the agent may knock, and a human decides
each time.

Written in Rust. One binary, two modes: a daemon speaking MCP over streamable
HTTP on loopback, and a short-lived egui window spawned once per request.

![The hatch approval window. The agent's title and reason are at the top; below
them a three-line shell command appears twice, raw on the left and annotated on
the right, with a countdown, a note field and Approve, Deny and three narrower
buttons along the bottom.](media/approval-command.png)

*One request, waiting. The left pane is exactly the text being approved — no
reflow, no colour. The right is the same text annotated: numbered segments,
`$HOME` shown with the value the command will actually receive, the `&&` that
ends each segment still on screen, and each line break drawn as a quiet `↵`
rather than silently swallowed. The header counts what it found and the
countdown says how long is left before the window denies on its own.*

---

## Contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Install and run](#install-and-run)
- [Required for root: the polkit drop-in](#required-for-root-the-polkit-drop-in)
- [The approval window](#the-approval-window)
- [Threat model](#threat-model)
- [Known limits](#known-limits)
- [Configuration](#configuration)
- [The audit log](#the-audit-log)
- [Not built yet](#not-built-yet)
- [Development](#development)
- [Licence](#licence)

---

## What it does

hatch exposes two MCP tools. Both block until a human answers.

| Tool | Parameters | On approval |
|------|-----------|-------------|
| `run_command` | `title`, `command`, `reason`, `cwd?`, `root?`, `interactive?` | Runs the command and returns `exit_code`, `stdout`, `stderr`, `duration_ms`, and `killed_by_user`, `signal` or `timed_out` where they apply |
| `swap_file` | `title`, `path` (absolute), `content`, `reason`, `root?` | Replaces or creates the file and returns the final `mode`, `owner` and `bytes` |

`title` and `reason` are required on both. `title` is the first thing the
person reads, so the tool descriptions ask the agent for the intent, not the
syntax.

Commands run through a shell, spawned as a direct argv — `bash -c '<command>'`
— never as a string handed to a second shell. With `root: true` the argv
becomes `run0 --pipe --setenv=… -- bash -c '<command>'`, and the window shows
that whole line, wrapper and `--setenv` pairs included.

Deletes and renames are deliberately not file operations. They are
`run_command("rm …")` and `run_command("mv …")`, so the destructive verb is on
screen as a verb rather than hidden in a JSON field.

There are five answers a person can give: approve, deny, ask the agent to
explain first, ask for a form that is easier to read, or take the job over and
run it themselves. The last four all return a non-fatal tool error carrying a
free-text note, so the agent can read the note and come back with something
better instead of seeing a broken server.

## Requirements

- **Linux with a graphical session.** The approval window is an egui window; a
  headless machine cannot show it, and hatch has no non-graphical approval
  path by design.
- **systemd, for root operations only.** Elevation is `run0`. Without it,
  `root: true` requests are refused with a message naming what is missing;
  everything else works.
- **A Rust toolchain for edition 2024** (Rust 1.85 or newer; the dependency
  tree may want a newer one still), plus whatever your distribution needs to
  build `eframe`/`egui`: a C toolchain, `pkg-config`, and the usual X11 or
  Wayland client libraries.
- **An MCP client** that speaks streamable HTTP and lets you set a bearer
  header and a per-tool timeout.

Everything except `run0` and the window-raising hints is portable in
principle. In practice it has only been run on Linux, and "portable in
principle" is not a claim that it works.

## Install and run

```sh
cargo build --release
install -Dm755 target/release/hatch ~/.local/bin/hatch
```

Start the daemon **outside** the sandbox, as your ordinary user:

```sh
hatch serve
```

It creates its directories, generates a bearer token on first run, and prints
the client registration line along with the tool timeout the client needs.
`hatch token` prints the same line again later.

The daemon must live outside the sandbox. An MCP client speaking stdio would
spawn the server itself, which would put the approval mechanism inside the very
sandbox it exists to supervise. That is why the transport is a loopback socket.

Register it with your client. For Claude Code:

```sh
claude mcp add --transport http hatch http://127.0.0.1:8787/mcp \
  --header "Authorization: Bearer <token>"
```

`hatch setup mcp` is the fuller path: the same line with your real port and
token, the same registration as a `mcpServers` JSON entry for clients
configured by file, the tool timeout below with the number taken from your
config, and a note on what it checked — whether *something* is listening on
the port, which is not the same as hatch being up — and what it cannot see
from this side. It prints; it never edits your client's configuration.

### Set the client's tool timeout

One call can block for the approval wait *plus* the command's own runtime —
900 seconds with the defaults, which are 600 s to decide and 300 s to run. Set
your client's MCP tool timeout to at least that. If the client gives up first,
the agent sees an opaque transport failure instead of a clean verdict — and the
request you were part way through reading vanishes from under you, because a
cancellation and a dropped connection both close the window and log a denial.
`hatch serve` prints the required number on startup, so it cannot drift away
from your config.

Queued requests stretch the total further: one approval window is open at a
time, machine-wide, and further requests wait in arrival order.

Ten minutes to decide is deliberate and the reasoning is in
[Why the wait is ten minutes](#why-the-wait-is-ten-minutes).

### Make the window hard to miss

On Wayland a client cannot raise or focus itself, so the always-on-top hint
hatch sets is a no-op there. The window sets the application id
`hatch-prompt`, which is what a compositor rule can match on. Under KWin, a
window rule matching that class with *keep above: force* and focus-stealing
prevention disabled is worth adding by hand.

A window you did not notice is not dangerous on its own — see the typing guard
below — but it is a request that will time out and deny.

## Required for root: the polkit drop-in

**If you use `root: true` at all, read this section. Skipping it leaves you
with a tool that looks like it is working.**

hatch's approval window is one gate. The polkit password dialog is meant to be
a second, independent one. The second gate only fires if polkit is asked afresh
every time — and by default it is not.

`run0` authenticates against `org.freedesktop.systemd1.manage-units`, which
systemd ships as `auth_admin_keep`. That suffix is the problem: polkit
**caches** the authorisation for the session, so a second root command inside
the cache window runs with **no password prompt at all**. hatch's window is
then the only gate on root, and nothing on screen says so.

Install this drop-in, as root — `hatch setup polkit` prints it, with this
section's reasoning and the check below:

```
// /etc/polkit-1/rules.d/49-hatch-run0.rules
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units") {
        return polkit.Result.AUTH_ADMIN;
    }
});
```

### Check that it took effect

```sh
run0 true; sleep 5; run0 true
```

This must ask for a password **twice**. If it asks once, the drop-in is not in
effect and your root operations have one gate instead of two.

hatch cannot verify this for you. There is no way to ask polkit "would you have
cached that", and a probe command that found out by running would itself pop a
password dialog. So it rests on the operator, and the check above is the whole
of the verification.

Note what the rule costs: it makes `systemctl` and everything else using that
action prompt every time too, for every user on the machine. That is the trade
being made deliberately.

## The approval window

Top to bottom: what the agent said it wants and why, then the request itself in
two panes side by side, then the controls.

**Two panes, same bytes.** The left pane is raw: monospace, no reflow, no
segmentation, drawn from the same string that becomes the shell's argument. The
right pane is annotated: numbered segments, highlighting, and `$VAR` references
with the value the command will actually receive shown beside the reference,
never in place of it. A reader can use whichever they trust in the moment, and
a disagreement between them is visible at a glance because the two sit at the
same height.

**The face is part of the argument.** The panes are set in Hack, chosen rather
than inherited, for three reasons that are requirements and not preferences: it
has **no ligatures**, so `&&` is never drawn as one glyph and `!=` never as
`≠` — a display rendering something that is not the characters is the thing
this program refuses everywhere else; every glyph has the same advance, which
is what the side-by-side fit rule measures a column in; and `l`/`1`/`I`,
`0`/`O`, `,`/`.` and the three quotes are told apart, because a misread quote
is a different command. All three are tests, the last of them against what is
actually rasterised.

**The annotation never removes anything.** Splitting a command at a `;` leaves
the `;` on screen, dimmed, at the end of its segment. Earlier tools of this
shape replaced separators with newlines, which deletes a character — and a
display that can silently delete one character can in principle delete any of
them.

Two properties hold this down, and both are property-tested over arbitrary
input:

1. Concatenating the rendered spans reproduces the original string exactly.
2. Every span is either drawn as its own text, or is a chip standing for
   exactly one codepoint.

The first says the text survives; the second says it is actually *seen*. A
single chip covering `; rm -rf /` would satisfy the first and hide the payload,
so the second is what makes the pretty view trustworthy.

**Unicode cannot lie about itself.** Bidirectional controls and zero-width or
invisible characters are always escaped, never drawn raw — that is Trojan
Source, closed. Every other non-ASCII codepoint becomes a visible chip carrying
its code point and name, so a Cyrillic `а` cannot pass as an ASCII `a`. LF, CR
and TAB get a compact dim glyph instead, because uniform alarm is no alarm: if
a newline in a heredoc shouts as loudly as a right-to-left override, readers
learn to skip both. This applies to `title` and `reason` too, which frame the
whole decision.

![Two lines of a copy command. The second line contains a filename with a
right-to-left override and a path with a non-breaking space; both are drawn as
orange bracketed labels, while the ordinary line break between the two commands
is a small dim arrow.](media/rendering-chips.png)

*The whole argument for the rendering, in one window. `[RLO]` is a Trojan
Source filename: the second `cp` copies something that reads as `gnp.txt.exe`
and is not, and without the chip the two lines look like the same kind of
thing. `[NBSP]` is a non-breaking space inside a path that appears to be
`staging/archive`. The ordinary newline ending the first line stays a quiet
`↵`, because if it shouted as loudly as those two nobody would keep reading
either. The header counts what it found.*

A file replacement gets the same treatment, plus a statement of exactly where
the bytes will land:

![A file replacement request. A metadata panel lists the target path, that the
whole file is being replaced, the resulting mode and owner and the size change;
below it a left/right diff shows the old and new YAML with changed lines
marked.](media/approval-swap.png)

*The metadata panel is the part a diff cannot show: which file, create or
replace, at what mode, owned by whom, and how much larger. A replacement
inherits the existing mode and owner, and the write either matches what the
window said or does not happen. The tinted cell on the left is a row that side
has no line for, which is not the same as a blank line.*

**The typing guard.** Every input is inert for 750 ms after the window gains
focus, and events delivered during that interval are dropped rather than
buffered and replayed. Enter is never a default-activate: approving takes a
click or Ctrl+Enter, and Esc is guarded on the same terms. A person mid-burst
at another window cannot approve something that appeared under their hands.
The 750 ms is hardcoded and deliberately not a config key — it is a safety
property, and a setting inviting it to be lowered to zero is a liability.

**After Approve the window stays.** It becomes a running indicator with elapsed
time and a Kill button, and the output pane if streaming was ticked. Kill
signals the whole process group, not just the shell, so a `make -j8` that left
children actually stops.

## Threat model

**The primary threat is the agent itself** — confused, prompt-injected, or
rogue. An attacker who already holds your session or root is out of scope;
there is nothing left for hatch to protect at that point.

**The guarantee is: nothing happens on the host that you did not see rendered
and approve.**

It is **not** "the agent is contained". `run_command` can reach anything you
can reach. That is deliberate, and it is why the rendering is the security
control rather than any denylist — which in turn is why the two invariants
above are property-tested rather than asserted in a comment.

For root operations there is a second, independent factor: the polkit password
dialog, which hatch cannot satisfy on your behalf. See the section above for
the part of that which rests on you.

**Alongside the window:**

- **The bearer token is load-bearing.** Loopback is not a boundary. The
  sandboxed agent can reach `127.0.0.1`, and so can every other process running
  as any user on the machine — nothing about the address restricts who may
  connect. The token is 32 bytes of OS entropy, lives in a 0600 file, is
  compared in constant time, and is checked before any request body is parsed.
  The listener binds `127.0.0.1` explicitly and never `0.0.0.0`, and requests
  whose `Host` header is not a loopback name are rejected, which is what stops
  a page in your browser reaching the daemon by a rebound DNS name.
- **Reaching the tools is not getting anything to happen.** An attacker holding
  the token still has to get a human to read a request and approve it.
- **The child environment is constructed, never inherited.** `PATH` and every
  other variable come from your config file, not from the daemon's environment
  and not from the sandbox. This is a display decision before it is an
  execution decision: the window can only claim a variable's value if it knows
  which environment the command will actually get. The default `PATH` contains
  no directory under `$HOME`, so a binary the agent wrote is not on it.
- **No rc files are sourced.** A non-interactive `bash -c` with a constructed
  environment reads no `~/.bashrc`, so an agent-writable dotfile cannot
  redefine a command after you have read it.
- **Every outcome is logged**, including the ones nobody was watching.

## Known limits

All of these are real. They are stated here rather than discovered later.

**Files a command reads are not shown.** `python script.py` is approved without
the reader ever seeing `script.py`. The same goes for `bash deploy.sh`,
`make install`, anything with `-f config`. hatch renders the *command* and then
claims that nothing happens which you did not see — and for any file-reading
command that claim is currently incomplete. This is the largest known gap. The
second-order problem, that the file could change between approval and
execution, is smaller than the first-order one that you never saw it at all.

**Segmentation models quoting and escaping only, and errs in both
directions.** It splits on `;`, `&&`, `||`, `|` and newlines, outside quotes.
It **under-reports** where real structure is not one of those: `&`
backgrounding, subshells, command substitution — `sleep 60 & wait` draws as one
segment, and `(cd /tmp; rm -rf x)` splits at the `;` without showing what nests
it. It **over-reports** where unmodelled syntax puts a separator character in
data: comments, `$(( ))`, `[[ ]]`, the `>|` operator, `$'…\'…'`, here-document
bodies, and `;;` in a `case` — each draws a boundary the shell does not have.
Neither direction breaks an invariant: every byte is still on screen, drawn as
itself. **Segment numbering is a reading aid, not an execution plan.** A fuller
answer needs a real shell grammar.

**A TOCTOU window remains on file writes.** The target is hashed when the diff
is drawn and re-hashed immediately before the write; drift re-prompts with the
fresh diff rather than applying stale content. But between that last check and
the `rename`, an attacker who can already write to a *directory* in the path
can replace it with a symlink. Re-checking narrows the window from human time
to syscall time; it does not close it. (`rename(2)` never follows its final
component, so swapping the target file itself cannot redirect the bytes.) For a
root write the polkit password wait sits inside the remaining window, which
widens it to however long the dialog stays up.

**A root command runs on a terminal where an unprivileged one runs on pipes.**
`run0` may allocate a pty, so the same command can behave differently as root —
colouring its output, or stopping to ask something. The window says so, and
hatch sets `PAGER` and `SYSTEMD_PAGER` so a root command cannot wait forever on
a pager, but the difference is real and hatch does not paper over it.

**The denylist is not containment.** `swap_file` refuses to write to hatch's
own three directories and its binary, your firejail profiles
(`~/.config/firejail`, `/etc/firejail`), your MCP client configuration
(`~/.claude.json`, `~/.claude`), and anything you add in `denylist_extra`.
What that closes is narrow: a diff is read by skimming, and
burying a changed token or a new sandbox exception in forty plausible lines is
an easier sell than typing the command that does the same thing. A
`run_command` doing exactly that is displayed in full in the window, which is
the actual control. Read the denylist as closing the *file* route, never as a
boundary.

**The window does not yet resolve what a command will invoke.** There is no
list of binaries a pipeline runs, no absolute-path resolution of the first
word, no warning when a name resolves somewhere agent-writable, and no danger
markers for shapes like `rm -rf` or `curl … | sh`. The fixed `PATH` above is
the mitigation that exists; reading the command is the rest of it.

**Approved output reaches the agent whole.** There is no way to approve `cat`
on a file with one secret in it and hold the secret back — approving a command
today means its entire output goes to the agent, and through it to whatever
model provider the agent uses. Trimming before the result returns is a privacy
control hatch does not currently have.

**A root outcome can be unknown.** A cancelled password dialog and a command
that ran and exited 1 can end with the same status, and the only thing telling
them apart is `run0`'s own message — which systemd translates. hatch forces the
locale for `run0` itself so it can read that message, and when the evidence is
missing it reports and logs *unclear* rather than guessing. An unclear outcome
is not a failure to retry; something may have run. Check the machine.

**The config file is trusted.** It is created 0600 and re-tightened on every
load, but anything that can write it can change the child `PATH`, add
`denylist_extra` entries or remove them, and read the bearer token. `swap_file`
refuses to touch it; `run_command` is shown to you in full.

## Configuration

`$XDG_CONFIG_HOME/hatch/config.toml`, which is `~/.config/hatch/config.toml`
unless you have set the variable. Mode 0600, because it holds the token.

A worked example first — this is closer to what a config looks like after a
week of use than the defaults are:

```toml
# ~/.config/hatch/config.toml

port = 8787
token = "…"          # generated on first run; the client is registered against it

timeout_secs = 600       # the default; see below for why it is ten minutes
exec_timeout_secs = 900  # raised: a system upgrade takes longer than five minutes
output_cap_bytes = 524288

# sbin included, because half of what gets asked for as root lives there
exec_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

font_size = 18
theme = "light"

# Things swap_file must not rewrite behind a diff. Absolute, literal prefixes.
denylist_extra = [
    "/etc/ssh",
    "/etc/sudoers.d",
    "/home/alex/.ssh",
    "/home/alex/.gnupg",
    "/home/alex/.local/share/systemd/user",
]

[exec_env]
HOME = "/home/alex"
TERM = "xterm-256color"
LANG = "en_GB.UTF-8"
GIT_PAGER = "cat"      # nothing here can talk to a terminal
SYSTEMD_PAGER = ""
DEBIAN_FRONTEND = "noninteractive"
```

`[exec_env]` is the complete environment an approved command receives, laid on
top of `exec_path` as `PATH`. Nothing else is added and nothing is inherited —
not from the daemon's own environment, not from the sandbox — so whatever you
write here is the whole of what the command sees, and it is what the window
resolves `$VAR` against when it shows you a value. The keys are ordinary
environment pairs: hatch does not interpret them, and the last three are
there because a command that stops to page its output is a command that hangs
until the execution timeout kills it. If you spell `PATH` out here it wins over
`exec_path`.

`denylist_extra` entries must be absolute literal path prefixes. `~` is not
expanded and a relative entry can never match, so either one silently protects
nothing — and nothing warns you, because there is no channel to warn on from
where that list is read.

### Why the wait is ten minutes

`timeout_secs` is the time you get to read a command **from the moment the
window appears** — not from when you notice it. It was ninety seconds until
recently, and ninety seconds ran out while people were still reading. A
timeout is not a neutral outcome: it resolves as a denial and reaches the
agent as a refusal nobody made.

The ninety was caution about an MCP client giving up on a call while a window
was still open. The caution was misplaced. Nothing downstream enforces
anything near it: a client's own ceiling is a setting measured in hours, and
the idle timer that would otherwise fire under an open window is reset by the
progress notification hatch sends every five seconds for the whole life of a
request — queued, awaiting a decision, running, waiting on the password dialog
— whenever the client supplies a progress token. For Claude Code specifically,
at the time of writing, `MCP_TOOL_TIMEOUT` defaults to about 28 hours and its
five-minute idle timer is reset by those notifications.

The bound that does bind is the one in
[Set the client's tool timeout](#set-the-clients-tool-timeout):
`timeout_secs + exec_timeout_secs` has to stay under whatever ceiling your
client actually enforces. `hatch serve` prints that sum on startup — 900 s with
the defaults, 1500 s for the config above, which raises the execution half.

### Every key

| Key | Default | What it is |
|---|---|---|
| `port` | `8787` | Loopback port the MCP server listens on |
| `token` | generated | Bearer token the client must present |
| `timeout_secs` | `600` | How long a window waits for a decision |
| `exec_timeout_secs` | `300` | How long an approved command may run |
| `output_cap_bytes` | `262144` | Cap on captured output |
| `exec_path` | `/usr/local/bin:/usr/bin:/bin` | `PATH` handed to approved commands |
| `terminal` | `["konsole", "-e"]` | Terminal for interactive runs, which this build refuses |
| `denylist_extra` | `[]` | Extra paths `swap_file` must refuse |
| `font_size` | `16` | Point size, clamped to 8–48 |
| `theme` | `"dark"` | `"dark"` or `"light"` |
| `[exec_env]` | `HOME`, `TERM` | The complete child environment |

Every key is optional and has the default above, so a config written by an
older build keeps loading unchanged after new keys appear.

Both palettes carry every meaning the window has; neither decides anything.
`theme = "light"` is the same window as the one at the top of this page:

![The same approval window in the light palette: dark text on a pale ground,
with the same two panes, the same annotations and the same
buttons.](media/approval-command-light.png)

Three directories, in three places, following the XDG base directory spec:

| What | Where | Default |
|---|---|---|
| `config.toml` | `$XDG_CONFIG_HOME/hatch` | `~/.config/hatch` |
| `log/` | `$XDG_STATE_HOME/hatch` | `~/.local/state/hatch` |
| `stage/` | `$XDG_RUNTIME_DIR/hatch` | the state directory |

All three are held at 0700. The staging directory is the one placed carefully:
it holds file content a human has approved but that has not been written yet,
and the runtime directory is emptied at logout, so a run that dies between
approval and the write cannot leave approved bytes readable after the session
that approved them ended. If `$XDG_RUNTIME_DIR` is unset, or names something
this process does not own at 0700, hatch falls back to the state directory and
says so at startup.

## The audit log

Append-only JSONL at `$XDG_STATE_HOME/hatch/log/hatch-YYYY-MM.jsonl` — by
default `~/.local/state/hatch/log/`. One line per outcome, flushed per record,
a new file each month, never rotated or pruned. `hatch log` renders the current
month readably.

Every outcome reaches it, including the ones the agent cannot tell apart. The
log's verdicts are a superset of the agent-facing ones — `approve`, `deny`,
`explain`, `simplify`, `self_run`, `timeout`, `elevation_failed`,
`elevation_unclear`, `cancelled`, `disconnected`, `prompt_died`, `refused` —
because a user denial, a client that gave up and a window that crashed all
answer the agent with "denied", and conflating them here would hide exactly the
quiet failures the log exists to catch.

`hatch log` escapes what it prints. `title`, `reason`, `note`, `command` and
`path` all come from the agent, and a newline interpolated raw would split one
record into two plausible-looking lines while ANSI escapes took over the
terminal. Control characters are rendered visibly instead — a title containing
a newline is itself worth seeing.

## Not built yet

Stated so you do not go looking:

- **`interactive: true`** is accepted by the schema and refused by this build,
  with a message saying it is a missing feature rather than a decision by the
  user. There is no terminal path yet.
- **Binary or oversized file content** is refused rather than summarised.
  hatch will not ask anyone to approve a change it cannot draw, and an empty
  diff would say "nothing changes", which is the one thing it must never say.
- **Editing a command in the window** before approving it. Today the answers
  are deny, or ask for something simpler and wait.
- **Trimming output** before it returns to the agent.
- **Unwrapping nested commands** — `sh -c '…'`, `ssh host '…'`,
  `docker exec … '…'` — into a readable tree. The payload of a wrapper is
  currently drawn as an inert string, correctly and unhelpfully.
- **Marking redirections** as structure. `> /etc/passwd` is drawn as ordinary
  argument text.
- **macOS and anything else.** Elevation and the window hints sit behind a
  small platform seam with a refusing implementation for other systems, so a
  port is a port and not a rewrite. It has not been done.

## Development

```sh
cargo test --features test-stub-prompter
```

The integration tests drive the real HTTP MCP endpoint end to end against a
scriptable prompter stub. The stub is behind a dev-only cargo feature rather
than `#[cfg(test)]`, because integration tests link the library compiled
*without* `cfg(test)` and a `cfg(test)` hook would not exist for them. There is
no environment-variable bypass: a build that does not enable the feature does
not contain the stub, so an ordinary `cargo build --release` cannot be talked
into skipping the window.

Two checks cannot be automated and are worth running by hand after any change
near them: the polkit re-authentication check above, and holding Enter down
while a prompt window appears to confirm nothing gets approved.

## Licence

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 licence, shall
be dual licensed as above, without any additional terms or conditions.
