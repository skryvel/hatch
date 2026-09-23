# hatch

**Let an agent do host work without approval fatigue.**

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
`hatch preview` opens that same window on a sample, so you can look at it
without an agent asking for anything.

![The hatch approval window. The agent's title and reason are at the top,
marked as the agent's own words; below them a line saying where each program
the command names was found, and a three-line shell command, annotated, with a
bracket down its left edge. Along the bottom: a countdown, a terminal checkbox
carrying a warning that a transcript captures what is typed into it, a box to
read the output before it is sent, a note field, a stream checkbox, a box that
closes the window once a decision is made, a sound checkbox, Approve and Deny
with their keyboard shortcuts, and four narrower buttons.](media/approval-command.png)

*One request, waiting. The header is the agent's own words, marked as such: a
rule down the side and "The agent says" in front of them. Under it, where each
program the command names was found, looked up on the `PATH` the command will
actually get. The pane is the command annotated: `$HOME` shown with the value
the command will receive, the `&&` joining the three steps still on screen
with the line break after it drawn as a quiet `↵` rather than silently
swallowed, and a bracket and indentation showing that the three lines are one
statement. **Show the original text** swaps it for the bytes exactly as sent.
The countdown says how long is left before the window denies on its own, and
every control with a key prints that key on itself.*

<sub>`hatch preview command --shot media/approval-command.png` — see
[Look at it yourself](#look-at-it-yourself-hatch-preview).</sub>

---

## Contents

- [What you get](#what-you-get)
- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Install and run](#install-and-run)
- [Required for root: the polkit drop-in](#required-for-root-the-polkit-drop-in)
- [The approval window](#the-approval-window)
  - [Reviewing the output before it goes](#reviewing-the-output-before-it-goes)
  - [Look at it yourself: `hatch preview`](#look-at-it-yourself-hatch-preview)
- [Terminals](#terminals)
- [Threat model](#threat-model)
- [Known limits](#known-limits)
- [Configuration](#configuration)
- [The audit log](#the-audit-log)
- [Not built yet](#not-built-yet)
- [Development](#development)
- [Licence](#licence)

---

## What you get

- **You read it before it runs.** The command appears twice: exactly as it will
  be executed, and annotated beside it — segments numbered, `$HOME` shown with
  the value the command will really receive, the binary that runs underlined. A
  file write arrives as a diff, with the mode and owner it will land at.
- **What it runs, in one place, before you start reading.** A line above the
  panes lists every distinct thing the command puts in command position, with a
  repeat count and the file each name reaches — `grep ×10, sed in /usr/bin;
  bash's own cd`. Wrappers are unwrapped, so `sudo foo` is two programs and not
  one, and a wrapper hatch cannot read past says so instead of guessing. A name
  that leads nowhere, or to somewhere anyone can write, is said out loud.
- **Nothing hides.** Invisible characters, right-to-left overrides and
  non-breaking spaces are drawn as labels rather than rendered, so a filename
  that reads `gnp.txt.exe` cannot pretend to be one. A command taller or wider
  than its pane says so in words, and says how much is out of sight.
- **A window that opens under your hands cannot be answered by them.** The
  approval keys are dead for 750 ms — measured not from when the window appears
  but from when it *gains focus*, because that is the dangerous instant: the
  click that granted it, and every key already travelling towards whatever held
  focus before, all land right then. Blocked events are dropped before any
  widget sees them, so nothing arrives late. Escape denies only when pressed
  bare. The interval is deliberately not a config key.
- **One keystroke, and the window gets out of the way.** `Ctrl+Enter`,
  `Shift+Enter` or `Ctrl+Alt+A` approves — the last of those reachable by the
  left hand alone, for when the right one is on the mouse — `Esc` denies, and
  `Alt+S`, `Alt+C` and `Alt+R` work the three boxes.
  Tick *Close when I decide* once and it is remembered, along with whether you
  stream, whether you want a terminal and whether you read the output first. Once the command is running the note
  field is gone and bare letters are free, so `e`, `o` or Space keeps the
  window — during the run or after it — `Alt+C` takes the output and `Esc`
  closes the window when there is nothing left running in it.
- **Answers other than yes and no.** Ask the agent to explain itself, ask for a
  version you can actually read, take the job and run it yourself, or stop the
  whole line of work to talk. Each returns your own words to the agent rather
  than a broken-server error — and an approval carries your note too.
- **You decide what the agent reads back.** Tick *Show me the output before it
  is sent* and a finished command's output waits on your screen instead of
  going to the agent. Keep only the lines containing `error`, drop the ones
  containing `token`, or edit a line by hand; what is drawn is what goes. The
  agent is told its view was trimmed — which keep filter, if one was used, but
  never what was dropped or what an edit changed. There is a note field on that
  screen too, and it goes whichever button you press: sending nothing is the
  case where the agent most needs your words, because all it is otherwise told
  is to stop asking and ask you. If you do not answer in time, nothing is
  sent.
- **You can watch it, and stop it.** Output streams into the window while the
  command runs, with a Kill button. A command that needs a keyboard gets a real
  terminal, and the window says plainly that everything typed in there goes
  back to the agent.
- **Root is systemd's job.** `root: true` runs through `run0`, so the
  elevation is a transient unit and the password dialog is the system's own —
  hatch never sees your password. The whole `run0` line is on screen, not just
  the command inside it, and `hatch setup polkit` writes the rule that stops a
  second request within five minutes from skipping the prompt.
- **It writes down what happened.** Every request lands in an append-only log
  with the verdict, how it ended, and whether it ran as root — including the
  ones nobody answered.

## What it does

hatch exposes two MCP tools. Both block until a human answers.

| Tool | Parameters | On approval |
|------|-----------|-------------|
| `batch` | `title`, `reason`, `operations`, `stop_on_failure?` | Carries the operations out in order and reports each as done, failed or not attempted |
| `run_command` | `title`, `command`, `reason`, `cwd?`, `root?`, `interactive?` | Runs the command and returns `exit_code`, `stdout`, `stderr`, `duration_ms`, and `killed_by_user`, `signal` or `timed_out` where they apply. A run in a terminal returns one `transcript` instead of the two streams — see [Terminals](#terminals). Output the person reviewed first comes back labelled as trimmed, or withheld — see [Reviewing the output](#reviewing-the-output-before-it-goes) |

Each operation of a batch is one of two kinds:

| Operation | Fields | On approval |
|-----------|--------|-------------|
| file write | `path` (absolute), `content` **or** `patch`, `root?` | Writes the file and returns the final `mode`, `owner` and `bytes` |
| command | `command`, `cwd?`, `root?`, `interactive?` | What `run_command` returns |

`title` and `reason` are required on both tools. `title` is the first thing the
person reads, so the tool descriptions ask the agent for the intent, not the
syntax.

**A batch is one approval over several operations** — or it will be: this
version's window draws one operation, so a longer list comes back unrun, with
a message that calls it a temporary limit rather than a refusal. The tool
description does *not* say so. It used to, agents sent one operation per batch
as told, and that left no way to learn whether they would group work if they
could. So the description asks for related operations in one batch, and a list
of up to 32 that comes back unrun is written to the log first — one `refused`
line per operation, with no `number`, since no window opened — so `hatch log`
shows what an agent tried to put together. The point of the shape is the incentive it
removes. Three file writes used to cost three interruptions and one shell
command with a here-document cost one, so an agent was pushed towards the form
that shows the person a wall of shell instead of a diff, and skips the symlink
check, the drift refusal and the stated mode and owner. `run_command` stays,
as the shortcut for a batch of exactly one command: it is converted into one
before its first field is checked, and goes through the same path.

Operations run in the order they are listed, which is the order the window
shows. What follows a failed operation is the agent's choice: by default the
batch carries on, and `stop_on_failure` stops it at the first failure. The
default is there because "failed" has no reliable meaning for a command —
`grep` finding nothing and `diff` finding a difference both exit non-zero as
answers — and hatch cannot tell those from real failures. Two things are not
the agent's choice. An operation that ends in a state hatch cannot account for
— killed, cut off at the execution deadline, an elevation whose result it
could not read, a root write that may have left its file short — ends the run
whatever was asked, and the rest are reported as not attempted. And nothing is
ever rolled back: a command cannot be un-run, and restoring a file while a
command's effects stayed would describe a state that never existed.

A file write takes what the file should contain in one of two forms, and exactly
one: `content` is the complete new contents, for creating a file or replacing
one wholesale, and `patch` is a unified diff against the file as it is now, for
editing one — which costs an agent the lines it touches instead of the whole
file. **A patch is a wire encoding and nothing more.** hatch applies it itself,
before anybody is asked, and what the person approves is the bytes it produced:
by the time the window opens there is no difference at all between a request
that arrived as a patch and one that arrived as full contents. It is applied
where its hunk headers say and nowhere else — no fuzz, no searching a line
either way — because a hunk that applied *nearly* would have written bytes
somewhere the agent did not mean, under an approval whose whole subject was
where the change goes. A hunk whose context does not match is refused whole,
naming the hunk, the line and what was found there; nothing is rendered and
nobody is interrupted.

Commands run through a shell, spawned as a direct argv — `bash -c '<command>'`
— never as a string handed to a second shell. A request can name something
else in `run_with` — `python3`, `node`, `ruby`, `perl`, `lua`, `bb`, `clojure`,
`clj`, `bash`, `sh`, `zsh` — and then `command` is a program for that
interpreter, handed to it as one argument. The window draws the invocation with the program under it,
names the language, and draws a box around the program. A shell program is read
again as shell; the others are drawn exactly as they were sent, with nothing
read — except that a build with `--features highlight` marks the strings and
comments of a Python or Clojure program (see [Install and run](#install-and-run)).

The program is drawn **unquoted**, so what is on screen is byte for byte what
the interpreter receives. Quoting it would buy the argument boundary and cost
the program: `shell_quote` rewrites every `'` as `'\''`, and a Clojure program
— where `'` is the quote form — comes out riddled with four-character
sequences that are not in it. A reader cannot check text like that, and
checking it is the whole of what the window is for. So the boundary is shown
instead by a box around the program and a line above the pane saying the run
is one argument. The box is closed on all four sides, not a rule down the
gutter like the brackets inside it: it says *this is one argument, in another
language*, so the colours inside it read as being about that language, and it
does the job quotes would do without drawing a character the command does not
contain. Nothing about what runs changes either way: an argv is a list
and `execve` takes a list, so quoting never reached it. **Copy command** quotes
the program back, because that is the one control that hands the line to
something other than a reader. A name that is not on the list is
refused with the list, because hatch has to know how a given interpreter takes
a program (`-c` here, `-e` there, `-M -e` for `clojure`) and a guessed flag
builds an argv that fails after somebody has approved it. Every one of those
was spawned as the argv hatch builds — no shell in between, stdin closed — and
checked for a clean exit and an empty standard error before it was written
down. With `root: true` the argv
becomes `run0 --pipe --setenv=… -- bash -c '<command>'`, and the window shows
that whole line, wrapper and `--setenv` pairs included. The command inside
those quotes is one word to `bash -c` and is drawn as the shell it is about to
be run as — separators, command names, resolved variables and block brackets
all inside a single shell argument — with a line above the panes saying that
the quotes are hatch's and the reading is hatch's. A command containing a `'`
is drawn as the string it is: quoting rewrites those bytes, so there is
nothing honest to read.

Deletes and renames are deliberately not file operations. They are
`run_command("rm …")` and `run_command("mv …")`, so the destructive verb is on
screen as a verb rather than hidden in a JSON field.

There are six answers a person can give: approve, deny, ask the agent to
explain first, ask for a form that is easier to read, take the job over and do
it themselves, or stop the work to talk. The last five all return a non-fatal
tool error carrying a free-text note, so the agent can read the note and come
back with something better instead of seeing a broken server. An approval
carries the note too, after what hatch has to say about what happened and
labelled `the user's note:` — the agent is never left to guess which half of an
answer a person wrote.

A review has a note of its own, labelled `the user's note, written while
reading this output:`. Two labels rather than one because a person can write
both on the same command and they are about different moments: the first
before anybody knew what it would print, the second while reading it. The
verdict's note is recorded in the log; this one deliberately is not, because it
is written while reading output the person may be about to withhold, and a copy
in the log would outlive the decision to keep it back.

"Stop, let's sync" is the one answer that says nothing about the request. Deny
is a judgement and invites a better version of the same idea; this says the
person has something to talk about and the next move is theirs, so the agent is
told not to retry it, not to send a variation of it, and not to pick up
something else instead.

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
mkdir -p ~/.local/bin
install -m755 target/release/hatch ~/.local/bin/hatch
```

`mkdir -p` rather than `install -D`: `-D` means *make the leading directories*
to GNU install and *set DESTDIR* to the BSD one macOS ships, so the one line
that looked portable was the line that was not.

**`--features highlight`** is an experiment, off by default. A Python or
Clojure program handed to an interpreter (`run_with`, or a here-document hatch
names) has its strings and comments marked, read by a TextMate grammar from
[syntaxmate](https://crates.io/crates/syntaxmate) — pure Rust, its own regex
engine, pinned to one version. Nothing else in the program is marked; keywords
and names are an editor's taste, not a claim a reader needs. A grammar cannot
tell when it is wrong, so the window says so in the sentence above the
program, and every mark is dropped when the grammar reports that it stopped
short, when its tokens fail to cover a line exactly, or — per string — when a
string's closing delimiter never comes. Without the feature the program is
drawn as it always was: every byte as itself, nothing read.

```sh
cargo build --release --features highlight
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

One call can block for the approval wait *plus* the operations' own runtime
*plus* the time you may take to review a command's output before it is sent —
1500 seconds with the defaults, which are 600 s to decide, 300 s to run and
600 s to review. The approval wait is counted once, because one window covers a
whole batch, and the execution time and the review once per operation; at one
operation per batch that is the same 1500. The review term is counted whether
or not you ever tick the box, because neither the agent nor the client can know
in advance which call you will choose to read. Set your client's MCP tool
timeout to at least that. If the client gives up first,
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
the command in one pane, then the controls.

**The header is the agent talking, and says so.** The title is the first thing
read, the most persuasive thing on screen, and written by the party whose
request is being judged — a reassuring title over a hostile command is the
cheapest lever a prompt-injected agent has. So the title and the reason are
drawn as a quotation: a rule down the left of both, and "The agent says" in
hatch's own small grey italic in front of the first line. Nothing is dimmed or
hedged; the words keep their size and their contrast. The reader is being told
whose words these are, not being told to disbelieve them.

**Each window has a number, and wears it in its title bar.** The first window
a running hatch opens is `hatch — approval #1`, the next is `#2`. Two approval
windows are otherwise the same object in alt-tab and in a task switcher, which
is where answering one and seeing the next open in the same instant reads as
the first being clobbered. The number costs no row inside the window, and the
audit log carries it too, so "I denied forty-seven" is something the file can
be searched for. It counts the windows of the *running* daemon: restart hatch
and the next window is `#1` again, which is why the log keeps the timestamp
beside the number rather than instead of it.

**A root request is a differently shaped window.** When the command will run as
root the header says `ROOT` reversed out of a filled block, and the whole window
is framed in the same colour. Both are shapes and not only colours — a block
where the header has none, a frame where the window has none — so the mark
survives a reader who cannot tell red from grey, and a screenshot printed in
black and white. Neither costs a row: the block is the height of the line it
sits on, and the frame is painted in the margin the panels already leave. It is
drawn while the window asks, while the command runs and while the result sits on
screen, because a command that has already run as root is still the thing that
ran as root.

![A root approval window. The whole window is enclosed in a red frame; in the
header the word ROOT is reversed out of a filled red block, and above the panes
a warning explains that a root command may be given a terminal where an
ordinary one gets a pipe. The command is the run0 line: run0's own options,
then `bash -c`, then the approved script on lines of its own, unquoted, framed
down the left edge and drawn as shell — commands underlined, the loop
bracketed and indented.](media/approval-root.png)

<sub>`hatch preview root --shot media/approval-root.png`</sub>

**Two renderings, same bytes, one at a time.** The annotated rendering is what
a window opens on: segmentation, highlighting, indentation that follows the
structure the parse found, and `$VAR` references with the value the command
will actually receive shown beside the reference, never in place of it. **Show
the original text** swaps it for the raw one — monospace, no reflow, no
grouping, no colour, drawn from the same string that becomes the shell's
argument. The box is remembered, so a reader who wants the bytes unannotated
gets them on every window.

Both draw every byte of the command, so the original is not showing anything
its neighbour hid; it is showing the same bytes without hatch's reading of
them, for a reader who wants to check the reading rather than use it. That is
worth a click and it was not worth half the width of every window, on every
request, for everybody. The switch keeps your place: a line number means
different things in the two renderings, but a byte offset means the same thing
in both, so swapping lands on the line holding the place you were at.

**A comment is not a command, and is not drawn as one.** A `#` at the start of
a word begins a comment, and everything from it to the end of the line is drawn
in a colour of its own, quieter than the text around it and still held above
the contrast floor everything else in the window is held to. That is a
correctness fix before it is a colour: hatch used to segment
`echo hi   # then && rm -rf /tmp` at that `&&`, drawing a boundary the shell
does not have, and a `$HOME` in a comment used to be resolved to a value the
shell never substitutes. Neither happens now. The rules are bash's own, for the
non-interactive shell hatch actually runs — `echo a#b`, `curl http://x/#frag`,
`${#var}` and a `#` inside quotes are not comments — and where the scanner
cannot tell, it finds no comment rather than inventing one, because a quiet
colour over text that *will* run is the only way this could mislead a reader.
`hatch preview comment` is a sample with one of each.

**A redirection is drawn as structure, and so is the word it points at.**
`> /etc/passwd` changes where a command's effects land, and it used to be drawn
with exactly the emphasis `-l` was drawn with. Both halves are marked now, in a
violet of their own: the operator — `>`, `2>>`, `&>`, `>|`, `2>&1` — and the
word it points at, because the thing a reader is scanning for is the
destination and not the arrow. The rules are bash's, from the redirection
section of its manual, including the file descriptor that belongs to the
operator when it is written against it. It is a **lexical** claim and not a
verdict: `> /dev/null` and `> /etc/passwd` get the same colour, because which
of them should alarm you is a question about the path. Recognising them fixed a
segmentation bug on the way — `>|` is one operator, and hatch used to split the
command at the `|` inside it. `hatch preview redirect` is the sample.

**A here-document body is data, and hatch stops reading it as a program.** In

```sh
cat <<'EOF' > /tmp/x
hello
EOF
```

the line above the panes used to read *"nothing on the command's PATH answers
to hello, EOF"* — an alarm on one of the plainest things an agent writes, which
is how an alarm stops being read anywhere. Every first word of every body line
was a program, a `;` in a body was a segment boundary, a `#` in one began a
comment, and a `$HOME` in one was resolved to a value the shell never
substitutes. None of that happens now. The rules are bash's: the body starts
after the newline that ends the operator's line and not at the operator, so
`cat <<EOF | grep x` still pipes; it ends on a line that is *exactly* the
delimiter; `<<-` strips leading tabs and not spaces; several can open on one
line and their bodies follow in order; and quoting the delimiter — `<<'EOF'`,
`<<"EOF"`, `<<\EOF`, even `<<EO'F'` — turns expansion off for the whole body,
while leaving it unquoted keeps `$HOME` real and worth showing. A body that is
never terminated runs to the end of the command, because that is what bash does
with it. The body itself is drawn plain, at full contrast and in no colour of
its own: it is usually the whole point of the command, so it is the last text
that should be dimmed, and the delimiter at each end is what says where it
stops. `hatch preview heredoc` is the sample.

**One line says what the command runs.** Ten `grep`s in a pipeline means
reading the whole command to learn what it invokes, and asking "what does this
run" of `sudo foo` used to get the answer `sudo`. So above the panes, before
you start on the command itself: *"Resolved when this window opened: git ×5,
cargo ×4, rsync, curl ×2 in /usr/bin; bash's own set, cd, echo."* Deduplicated,
counted, and resolved against the `PATH` the command will actually be given —
which for a root request is the one travelling through `run0 --setenv=`.

Sixteen wrappers are unwrapped — `sudo`, `doas`, `env`, `nice`, `ionice`,
`nohup`, `setsid`, `stdbuf`, `timeout`, `xargs`, `time`, `command`, `exec`,
`run0`, and `bash`/`sh` with `-c`, which is how a root request's own command is
read — each with its own option grammar. The grammars are whitelists: an option
hatch has not heard of might take a value, and skipping one word where two were
wanted names an argument as a program. So `sudo -X ls` gives up rather than
guessing, and the window says *"hatch could not read the arguments of sudo, so
what it runs is not in this list."*

Builtins are the trap this is shaped around. `cd` is on no `PATH` anywhere, and
a list that called it missing would draw a warning on the most ordinary command
there is — so bash's builtins and reserved words are recognised, `echo` and
`test` and `[` are reported as the builtins bash actually runs rather than as
the files of the same name in `/usr/bin`, and a function the command defines
for itself resolves to the command. What does earn a second line, in orange, is
a name nothing answers to, a word hatch will not expand, a wrapper it could not
read, or a binary sitting where anyone can write it. That last one is a fact
about a mode bit and not a verdict: whether a particular writable directory
should alarm you is a question hatch does not answer.

The line is a **snapshot** and says so. It is what a lookup found while the
window was being drawn; the binary can be replaced before the command runs,
because the lookup that decides that is bash's own at exec time. The label
carries the honest version so there is no other version to read.

**What is off the end of a pane is said in words.** Everything else here
assumes the reader saw the text, and a pane showing twenty-four rows of a
sixty-three-row command used to say so through its scroll bar alone — a bar
that took no column and faded to nothing whenever the pointer was elsewhere. A
command can be written for that: blank lines to the height of the pane, and the
payload under them. So the bars take a column and stay on screen, and the line
under the caption says it outright — *"Only 24 of the command's 63 rows fit the
pane below, so 39 of them are out of sight; scroll for the rest."* — along with
how far the lines run past the right edge of the raw pane, which deliberately
does not reflow. Both figures are the pane's own measurements. Words and not an
affordance alone: they survive a reader who has never learned what a scroll bar
means, and a screenshot printed in black and white. `hatch preview long` is a
sample that does not fit, so this is something you can look at.

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
either. The header counts what it found — and counts two, not three: the
newline carries no ink, but it has been drawn in the place it occupies rather
than hidden, so it is not what that number is about.*

<sub>`hatch preview chips --shot media/rendering-chips.png`</sub>

A file replacement gets the same treatment, plus a statement of exactly where
the bytes will land:

![A file replacement request. A metadata panel lists the target path, that the
whole file is being replaced, the resulting mode and owner and the size change;
below it a left/right diff shows the old and new YAML with changed lines
marked.](media/approval-swap.png)

*The metadata panel is the part a diff cannot show: which file, create or
replace, at what mode, owned by whom, and how much larger. A replacement
inherits the existing mode and owner, and the write either matches what the
window said or does not happen. The blank rows here are blank lines in both
files; a row one side has no line for is tinted instead, which the line above
the diff says.*

<sub>`hatch preview swap --shot media/approval-swap.png`</sub>

**The typing guard.** Every input is inert for 750 ms after the window gains
focus, and events delivered during that interval are dropped rather than
buffered and replayed. Enter is never a default-activate: approving takes a
click, Ctrl+Enter, Shift+Enter or Ctrl+Alt+A, and Esc is guarded on the same
terms. All of them are printed on the buttons, and printed exactly:
`Ctrl+Shift+Enter` is
deliberately inert although each of its halves approves on its own, so a label
loose enough for a reader to expect it to work would be the window promising
something it refuses. A person mid-burst at another window cannot approve
something that appeared under their hands. The 750 ms is hardcoded and
deliberately not a config key — it is a safety property, and a setting inviting
it to be lowered to zero is a liability.

**Alt+S, Alt+C and Alt+R** tick **Stream output to this window**, **Close when
I decide** and **Show me the output before it is sent**. Chords rather than
bare letters, because the note field has the keyboard and a window where `s`
means something other than the letter `s` eats what you type into it. They
wait out the same guard as Approve does, which is not because a checkbox is
dangerous but because all three are remembered: what they write outlives the
window, and the undo for a file is a box in a request nobody has made yet. A
chord writes down exactly what a click on the same box would — see
[Reviewing the output](#reviewing-the-output-before-it-goes). Aimed at a box that is dead — Alt+S on a command that is getting a terminal of
its own, Alt+R on a write, which prints nothing — they tick nothing and flash
the sentence saying why instead.

**After Approve the window stays.** It becomes a running indicator with elapsed
time and a Kill button, and the output pane if streaming was ticked. Kill
signals the whole process group, not just the shell, so a `make -j8` that left
children actually stops. **Keep this window** is beside it while you are
streaming, and what it does is below. A file write has no Kill button, because
it has no run to stop: an unelevated write is over in the frame it starts, and
the one wait a root write has is the password dialog, whose own Cancel ends it
with nothing written.

**Unless you have told it not to.** Tick **Close when I decide**, left of the
buttons, and the window goes as soon as you answer instead of staying to show
the run — because the point of answering is getting back to what you were
doing, and a window you have to dismiss every time is a window you alt-tab away
from every time. It is a preference rather than a per-request tick: it is
remembered in `prefs.toml`, and the next window opens with it already set.

A file write's window does not have the box. Its window already goes the
instant there is nothing to show, so the only thing a tick could still do there
is take away the report of a write that went wrong — and a preference ticked
for commands must not do that to a file. The window does not act on the
remembered tick either, and the next command window has it exactly as you left
it.

The control says what it costs, because it costs something real: **the Kill
button goes with it**. Nothing can stop an approved command from a window that
is not there, so `exec_timeout_secs` becomes the only backstop — and a terminal
run, which deliberately has no execution deadline at all, has only the terminal
itself. That is a choice worth making once rather than a reason to refuse it.

It is named for deciding and not for approving because five of the six verdicts
already closed the window on the spot; approving is the only one it changes.
And it loses to **Stream output to this window**: streaming exists to be
watched, so ticking it greys the close box out and says why, without disturbing
the preference — untick Stream and it comes straight back. A terminal run is
not a conflict at all. The terminal is a window of its own that you are about
to be sitting in front of, and hatch's window standing behind it is showing you
nothing.

In the audit log a window that was asked to go is recorded as `dismissed` and a
window that died unasked as `died`, and only the second prints
`(prompt died while it ran)`. They used to be one boolean, which would have put
that suffix under every approved command belonging to anyone who ticked the
box — and the one line that means something went wrong would have become the
line that appears on all of them.

**A streamed window stays when the command ends, and you can keep it.** The
whole life of an ordinary command is milliseconds, so a window that closed on
the outcome closed at the moment the output it was asked to show arrived. It
lingers for ten seconds instead, with the result on it and a countdown saying
so, and **Keep this window** stops the countdown for good: no verdict, no
deadline, just the output, a way to copy it and a way to close it.

**A window nobody asked to watch stays only when there is news.** Otherwise it
closes on the outcome at once, because a result that is on screen for half a
second before the window goes is the worst of both: too short to read, long
enough to catch the eye. A write that landed as the diff described is not news
— you read it and said yes — and neither is a command's exit status, whatever
the number: `grep` finding nothing and `diff` finding a difference exit
non-zero as answers, and the status goes to the agent that asked. What is news
is what happened *to* the operation rather than what it said: a write refused
because the file changed, or landed as something other than the window said; a
command ended by a signal — the deadline, Kill, a crash — or one that could not
start; a password dialog dismissed, or an elevation hatch cannot read. Those
linger with the same countdown, Keep and Close, and a failed write keeps its
diff on screen with the reason beside it. When a request carries several
operations, the window stays if any one of them is news.

**Keep is pressable before the command has finished, too.** A long run is
exactly when you have gone to do something else, and asking you to be back at
the keyboard for the ten seconds after it stops is asking you to wait for it.
Pressed during the run, the window never starts a countdown at all: it goes
from running straight to *Kept. It stays when this ends.* It is the same
action one phase earlier and not a second setting — nothing is written down,
and the next window opens exactly as it would have. It is offered only while
you are streaming, because a run nobody watched has sent the window nothing to
be kept for.

Keeping does not toggle, in either phase. A key that means *keep* once and
*stop keeping* twice is two meanings decided by a count nobody is keeping, and
what somebody who changes their mind actually wants is the window gone — which
is Close, on the window from the moment the command ends.

Keeping is the only control in hatch with a clock running against it, so it has
the widest target: `e`, `o` and Space all do it, in both phases. `Esc` closes
the finished window, `Alt+C` copies the output. These are bare letters where
approving is a chord, and the difference is the note field — it holds the
keyboard while the window is asking, and it is gone by the time these mean
anything. `Alt+C` means the close box while there is a box and the output
afterwards; the two windows look nothing alike and neither meaning can be
regretted. Enter is deliberately unbound: the reflex is that it confirms, and
somebody hammering it at an approval must not close the window that opened
under it.

**Asking, running and finished do not look alike.** The ground the panels are
drawn on changes with what the window is doing — grey while it has a question
on it, blue while the command runs, violet once it is over — so a glance says
which without reading a word. The three are the same lightness and differ only
in hue, because every colour this window uses to mean something is pinned to a
contrast ratio against that ground, and a ground that moved in lightness would
push one of them under. The hue claims nothing about the outcome: a failed run
is the same violet as a clean one, and what happened is said in words.

### Reviewing the output before it goes

Approving a command used to mean its whole output reached the agent, and
through the agent whatever model provider it talks to. There was no way to
approve `cat` on a file with one secret in it. **Show me the output before it
is sent**, on the row beside the terminal box, is that way.

**It is off by default and remembered once you tick it**, like its three
neighbours. It was not, for a long time, and the argument against was a good
one: whether *this* command's output might carry something that must not leave
the machine is a judgement about this command — `cat` on a file with a key in
it, not `ls` on its directory — and a reviewed run waits for a second answer
before the agent hears anything, so a tick that persisted would put a person in
the return path of every call afterwards.

What changed is use. Somebody who wants to read what goes back wants to read
it, and a tick they must make again on every window is the friction that ends
in nobody reading anything. The cost is real and the window says it rather than
hiding it: a remembered tick greys **Close when I decide** with *You read every
run's output first, so every run waits for you.* — different words from the
*You asked to see its output first.* you get when you ticked it here, because
only one of those is true about a window you have not read yet.

What a remembered tick cannot do is let anything out. It only ever puts more
output in front of a person, and every ending that is not an answer — the
review deadline included — sends nothing. It applies to commands only: a write
returns no output. A run under review offers no Keep, because it does not end
in a viewer.

**When the command finishes, the window shows its output as it will go.**
stdout and stderr are two panes, side by side, each captioned with how many of
its lines will be sent. A stream the command printed nothing on gets no pane —
one quiet line says so, and the other takes the width. A terminal run's
transcript is one pane, and is
reviewed like any other output — it can hold what you typed into the terminal,
which is the strongest case there is for reading it first. Two filters sit
above them:

- **Keep only lines containing** — only lines that contain one of these stay.
- **Drop lines containing** — lines that contain one of these go.

A pattern is **plain text, not a regular expression**: a dot is a dot, because
somebody in a hurry who types `a.b` means three characters, and a pattern
language would keep or drop lines they never meant. Case is ignored, because
`password`, `Password:` and `PASSWORD=` are one secret. Keep applies first,
then drop. What is in a field counts as you type it; *Add another* moves it
into a list so a second can be typed, and each added pattern is a button that
takes it back out. Matching goes through the `regex` crate on the escaped
pattern, so it is linear in the output and nothing typed can hang the window.
A character that draws as nothing or reorders its line — a zero-width space
inside `password`, a right-to-left override, a carriage return, an escape
sequence — is drawn by name, so the text on the screen is the text that goes.

**Edit the text by hand** turns the filtered result into text you can change,
for the password in the middle of a line that has to stay. The filters are set
aside while you edit and come back when you undo; the caption counts any
invisible characters left in what you are editing, since the editor is the one
place they do not draw; and Enter never reaches the field, so an edit can take
text out but cannot type new lines in.

`Space` pages the output down and `Shift+Space` pages it back up, whenever no
field on the screen has the keyboard — so the space bar is still a space while
you are typing a filter. **Send this** (`Ctrl+Enter`, `Shift+Enter` or
`Ctrl+Alt+A`) sends what is on the screen.
**Send nothing** (`Esc`) sends none of it. Both wait out the typing guard,
which starts again when the review appears: it appears whenever the command
finishes, and you may be typing somewhere else by then.

**What the agent is told.** Trimmed output is always labelled as trimmed, and
the label is worked out by the daemon from what it captured and what you sent,
never taken from the window's word:

```
reviewed: the user read this output before it was released to you and trimmed it, so what follows is not everything the command printed

stdout (trimmed by the user: only lines containing "error", ignoring case, are shown; the other lines were removed):
stdout (trimmed by the user: lines were removed):
stdout (trimmed by the user: edited by hand, so lines may be missing or changed):
```

A keep pattern is named, because "lines containing `error`" says nothing about
what else there was. A drop pattern is not: "lines containing `password` were
removed" would announce exactly the lines you removed them to hide. An edit is
called an edit and nothing more. A section you did not change keeps its plain
heading.

**If you walk away, nothing is sent.** The review has a deadline of its own —
`timeout_secs` again, ten minutes by default, for the same reason the approval
has it — and when it passes, or the window is closed, the agent is told the
command ran, gets its exit status and duration, and none of its output:

```
output withheld: the command ran, but the user asked to read its output before it reached you and did not do so within 600s, so none of it was released. Its status above is all you are told about it. Do not run it again to see the output; ask the user for what you need.
```

You asked to see it first; sending it because you stopped answering would
override that in exactly the case it exists for.

### Look at it yourself: `hatch preview`

```sh
hatch preview                     # the window above, from your own config
hatch preview root                # the root window: the ROOT block and the frame
hatch preview long                # a command taller and wider than the window
hatch preview comment             # comments, beside the separators they are not
hatch preview redirect            # redirections, and the two things that look like one
hatch preview heredoc             # a here-document body, drawn as the data it is
hatch preview --theme light       # the other palette, for this window only
```

`hatch preview [command|chips|swap|root|long|comment|redirect|heredoc]` opens the real approval
window on a sample request, reading the same config `hatch prompt` reads. It is
how you see what your `font_size`, `theme` and `terminal` settings actually
render as without having to get an agent to knock on the door. The `long` sample is
the one that does not fit: it is there so the line that says how many rows are
out of sight, and — under **Show the original text**, which does not reflow —
a line that runs off to the right, are something you can look at rather than
read about. The `comment` sample puts an
`&&` inside a comment two rows above an `&&` that really is a boundary, so the
difference is something you can see rather than take on trust. The `redirect`
sample does the same for a `>|`, which is one operator, and the `|` three rows
above it, which is a boundary.

**It cannot run anything.** There is no daemon behind a preview, and that is
structural rather than circumstantial: the window's one way to act on a
decision is to write a verdict down a channel, and the only channel a preview
ever gives it discards what it is handed. Pressing Approve closes the window
and runs nothing. The one thing a preview writes to disk is its own sample file
under `$TMPDIR/hatch-preview`, because a file replacement is planned against a
file that exists. It reads `prefs.toml` so the sample is drawn with the
preferences a real request would be drawn with, and never writes it: a
documentation tool that changed your settings would be a surprising thing for a
screenshot to do.

Each sample is built through the calls the daemon makes — the same renderer,
the same payload constructors, the same plan — and handed to the same window
code, which is checked by a test that asks a real daemon for the same request
and compares the two payloads field for field. A preview that looked right
while the daemon drifted underneath it would be worse than no preview.

`--shot PATH` waits for the window to settle, photographs its own viewport and
exits, writing a PNG at the window's native size. That is how every image on
this page is made, and the command for each one is printed under it. It needs a
display but no compositor screenshot permission — egui reads its own
framebuffer — and two runs produce byte-identical files, because the countdown
is stamped to a round figure for a shot. It exits non-zero if no picture
reached the disk.

On a machine with no `run0` — a container, a non-systemd distribution — the
root preview still draws, and says on standard error that hatch would have
refused the real request there. The line in the window is composed by the code
that composes the real one, given the same child environment; what that machine
lacks is permission to run it, not the ability to describe it.

## Terminals

Some commands do not fail without a terminal, they hang: a `pacman`
confirmation, an editor, a pager, anything that reads standard input. hatch
runs those in a terminal of your own.

**Either side can ask for one.** The agent sets `interactive: true` when it
knows its command wants typing at. You can tick **Run it in a terminal** in the
window when you can see that it does and the agent could not — `pacman -S foo`
is the everyday case. The control only ever *grants*: a request that asked for
a terminal shows the box ticked and dead, because a command that needs one and
is denied it hangs with nowhere for anyone to type.

**Everything in that terminal is sent to the agent, including what you type
into it.** The terminal is recorded with `script(1)`, and a terminal echoes
what is typed at it, so a password typed at a prompt inside that window ends up
in the agent's context. The window says so beside the control, before you
choose. Treat that terminal as a place the agent is watching, because it is.

**The result has a different shape, and the agent is told so.** A pty is a
single stream: what the command wrote to standard output, what it wrote to
standard error and what you typed all arrive interleaved with nothing marking
which was which. So a terminal run returns one `transcript` — escape sequences
stripped, capped at `output_cap_bytes` like any other output — and `stdout` and
`stderr` are absent rather than empty. **Show me the output before it is sent**
works on a transcript as it does on two streams, and a transcript is the output
most worth reading first. Splitting it into two streams it never
had would be hatch inventing a distinction for the agent to rely on.

**There is no execution deadline.** `exec_timeout_secs` is a runaway-process
guard, and in a terminal the guard is you. Cutting the run off at five minutes
would end your session mid-keystroke. **Kill still works** and still takes down
the command and everything it started.

**Configuring it.** `terminal` is an argv with the program first, and the
runner's path is appended to it, so what goes in the list is everything up to
but not including the program the terminal is asked to start:

```toml
terminal = ["konsole", "--nofork", "-e"]   # the default, on Linux
terminal = ["kitty"]                       # kitty has no -e
```

**The default is empty on every platform but Linux**, because konsole and
kitty are the only terminals this path has been run against. A build that
wrote `konsole` into a fresh config on macOS would be telling its owner to go
and start a KDE program. Name a terminal in the file and it is used on any
platform.

Where there is no terminal to be had — nothing configured, or the program
named is not installed — hatch says so before anybody approves anything: the
**Run it in a terminal** box is drawn dead with a sentence beside it naming
the cause, and a request that *asked* for a terminal is refused at the
boundary rather than run without one. A command that needs a terminal and is
denied one does not fail, it hangs.

`--nofork` on konsole is not decoration. Without it, a konsole started while
KDE's "run all Konsole windows in a single process" setting is on hands its
arguments to the konsole already running and returns immediately, which puts
the command in a process hatch never started: Kill would reach nothing.

Nothing here reads the terminal's own exit status — kitty exits `0` whatever
its program did — so a small runner inside the terminal writes the command's
status to a file and that file is the answer.

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
  redefine a command after you have read it. A run in a terminal is still
  `bash -c` and still sources nothing, but the terminal around it is another
  program with settings of its own — see [Known limits](#known-limits).
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
data: `$(( ))`, `[[ ]]`, `$'…\'…'` and `;;` in a `case` — each draws a
boundary the shell does not have. Comments, here-document bodies and the `>|`
operator used to be on that list and are not any more.
Neither direction breaks an invariant: every byte is still on screen, drawn as
itself. **Segment numbering is a reading aid, not an execution plan.** A fuller
answer needs a real shell grammar.

**A TOCTOU window remains on file writes.** The target is hashed when the diff
is drawn and re-hashed immediately before the write. If the two differ, the
write is refused and nothing is written: the agent is told the file changed and
has to read it again and send a new request, which opens a new window with a
new diff. hatch does not ask again by itself. But between that last check and
the `rename`, an attacker who can already write to a *directory* in the path
can replace it with a symlink. Re-checking narrows the window from human time
to syscall time; it does not close it. (`rename(2)` never follows its final
component, so swapping the target file itself cannot redirect the bytes.) For a
root write the polkit password wait sits inside the remaining window, which
widens it to however long the dialog stays up.

**A terminal run's environment is constructed and then added to.** Everywhere
else the child environment comes from your config file and nothing else. An
interactive run goes through a terminal emulator, which is another program with
settings of its own: a konsole profile that exports variables exports them into
the command too, and hatch cannot see that happen. The working directory is the
one exception it takes back rather than concedes — the runner enters the
directory the window stated before it starts anything, so a profile's initial
directory cannot move a command somewhere the window did not say.

**A root command runs on a terminal where an unprivileged one runs on pipes.**
`run0` may allocate a pty, so the same command can behave differently as root —
colouring its output, or stopping to ask something. The window says so, and
hatch sets `PAGER` and `SYSTEMD_PAGER` so a root command cannot wait forever on
a pager, but the difference is real and hatch does not paper over it.

**The denylist is not containment.** A file write refuses to touch hatch's
own three directories and its binary, your firejail profiles
(`~/.config/firejail`, `/etc/firejail`), your MCP client configuration
(`~/.claude.json`, `~/.claude`), and anything you add in `denylist_extra`.
What that closes is narrow: a diff is read by skimming, and
burying a changed token or a new sandbox exception in forty plausible lines is
an easier sell than typing the command that does the same thing. A
`run_command` doing exactly that is displayed in full in the window, which is
the actual control. Read the denylist as closing the *file* route, never as a
boundary.

**The roster is a snapshot, and there are no danger markers.** The list of
what a command runs is what a `stat` said while the window was being drawn, and
the binary behind a name can be replaced between that lookup and the moment the
command runs — the lookup that decides what really runs is bash's, at exec
time, and hatch is not in that path. The window says *when* it looked rather
than implying it knows what will happen. The roster also states facts and never
verdicts: it says a binary sits in a directory anyone can write to, and it does
not say whether that should alarm you. There are still no danger markers for
shapes like `rm -rf` or `curl … | sh`.

**Approved output reaches the agent whole unless you ask to review it.**
Reviewing is per command and off by default, so a secret in the output of a
command you did not tick it for goes to the agent, and through it to whatever
model provider the agent uses. And a review hides text from the agent, not
from the machine: the command ran, and anything it wrote elsewhere is where it
wrote it.

**The live output view draws what the command printed as it is.** Streamed
output, and the window a finished streamed run stays as, show escape sequences
and invisible characters however the font draws them — often as nothing. The
review screen names every one of them; the live view does not, and it is not a
place to judge whether a secret is there.

**A root outcome can be unknown.** A cancelled password dialog and a command
that ran and exited 1 can end with the same status, and the only thing telling
them apart is `run0`'s own message — which systemd translates. hatch forces the
locale for `run0` itself so it can read that message, and when the evidence is
missing it reports and logs *unclear* rather than guessing. An unclear outcome
is not a failure to retry; something may have run. Check the machine.

**The config file is trusted.** It is created 0600 and re-tightened on every
load, but anything that can write it can change the child `PATH`, add
`denylist_extra` entries or remove them, and read the bearer token. A file write
refuses to touch it; a command is shown to you in full. `prefs.toml` is
trusted on much narrower terms — it holds three checkboxes and no secret — but
it is worth knowing what something able to write it could do: set
`close_on_decide` and take Kill off every command window, or set `terminal`
so that the next command opens with a tty ticked, which is the one of the three
that changes how a command runs rather than what you see. Neither is silent —
both boxes are on screen in the window that is asking, and the terminal's
capture warning is drawn whether or not its box is ticked — but a preference
is a standing answer, and this file is where the standing answers live. Both
files sit in directories held at 0700, and a file write refuses both.

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

# Things a file write must not rewrite behind a diff. Absolute, literal prefixes.
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

**`exec_path` is the whole of where a command's names are looked up**, and it
is the one setting most likely to surprise you: a program you run in your own
shell every day is not on it unless this key says so. The default is
`/usr/local/bin:/usr/bin:/bin` on Linux, and on macOS the same with both
Homebrew prefixes in front — `/opt/homebrew/bin` for Apple silicon,
`/usr/local/bin` for Intel — since macOS ships almost nothing you install
yourself. A version manager, `~/.local/bin` or a language toolchain is yours
to add.

Nothing is silent about it: the window resolves every name in the command
against this exact value and says *"Nothing on the command's PATH answers to
…"* above the panes, before you approve anything.

Note that the whole config is written out on first run, so **an installation
made before a default changed keeps the old value in its file**. Changing it
is one line in `config.toml`; nothing re-derives it for you.

**Sound when a window opens** is a checkbox under *Close when I decide*, and
it is remembered: it is for the person who is not looking at the screen, so
nothing drawn on the screen could tell them to look. It does nothing to the
window it is ticked on — by the time the box is readable, that window has
already opened — and everything to the next one.

`sound` is argv, like `terminal`: hatch spawns a program that can already make
a noise rather than opening an audio device itself, because every Rust crate
that opens one links C, and this is the process that draws agent-chosen bytes.
Where the program named is not installed, the box is dead and says so, exactly
as the terminal box does. A sound that does not play costs you the prompt and
nothing else — the window, the deadline and every control are unaffected.

**`tools = "batch"`** offers `batch` and nothing else. The two tools overlap
rather than divide the work — `run_command` is a batch of exactly one command,
and a test of that name keeps it so — and only `batch` can write a file. An
agent offered both reaches for the simpler one, and then writes files through
it with a here-document, which hatch renders as the command it is rather than
as a diff of the bytes that will land. Withdrawing the smaller spelling closes
that route and takes nothing away: every `run_command` call has an exact
`batch` one. A client that calls the hidden tool anyway is refused and told
how to spell it.

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
`timeout_secs + exec_timeout_secs`, plus `timeout_secs` again for the time a
review may take, has to stay under whatever ceiling your client actually
enforces. `hatch serve` prints that sum on startup — 1500 s with the defaults,
2100 s for the config above, which raises the execution term.

### Every key

| Key | Default | What it is |
|---|---|---|
| `port` | `8787` | Loopback port the MCP server listens on |
| `token` | generated | Bearer token the client must present |
| `timeout_secs` | `600` | How long a window waits for a decision, and how long a review of a command's output waits before nothing is sent |
| `exec_timeout_secs` | `300` | How long an approved command may run |
| `output_cap_bytes` | `262144` | Cap on captured output |
| `exec_path` | `/usr/local/bin:/usr/bin:/bin`; on macOS `/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin` | `PATH` handed to approved commands. Nothing is inherited, so a program not on this list is not found |
| `terminal` | `["konsole", "--nofork", "-e"]` on Linux, `[]` elsewhere | Terminal for interactive runs; the runner's path is appended to it. kitty wants `["kitty"]` with no `-e`. Empty means interactive runs are refused, with a reason |
| `sound` | `afplay …` on macOS, `paplay …` on Linux, `[]` elsewhere | Played when a window opens, as argv. Off until the box is ticked |
| `tools` | `both` | Which tools an agent is offered: `both`, or `batch` alone |
| `denylist_extra` | `[]` | Extra paths a file write must refuse |
| `font_size` | `16` | Point size, clamped to 8–48 |
| `theme` | `"dark"` | `"dark"` or `"light"` |
| `[exec_env]` | `HOME`, `TERM` | The complete child environment |

Every key is optional and has the default above, so a config written by an
older build keeps loading unchanged after new keys appear.

Both palettes carry every meaning the window has; neither decides anything.
`hatch preview` draws a sample window from this file, which is the quickest way
to see what a `font_size` or a `theme` actually looks like before an agent
does. `theme = "light"` is the same window as the one at the top of this page:

![The same approval window in the light palette: dark text on a pale ground,
with the same pane, the same annotations and the same
buttons.](media/approval-command-light.png)

<sub>`hatch preview command --theme light --shot media/approval-command-light.png`</sub>

`hatch preview --theme light` draws one window in the other palette without
writing anything: the config file says what it said before, and the next real
request is drawn in whatever that is.

### `prefs.toml`, which hatch writes and you do not

`$XDG_STATE_HOME/hatch/prefs.toml`, by default
`~/.local/state/hatch/prefs.toml`. One file, one job: the choices the window
writes down because you ticked them in it. Six keys —

| Key | What ticking it remembers |
|---|---|
| `close_on_decide` | A command's window goes as soon as you answer, instead of staying to show the run |
| `stream` | The window shows the output as it arrives |
| `review` | You read a command's output before any of it is sent |
| `terminal` | The command gets a terminal of its own |
| `show_original` | The window opens on the original text instead of the annotated one |
| `sound` | A window opening plays a sound |

— and there is nothing to hand-edit: ticking the box in the window is how each
one is set, and Alt+C, Alt+S and Alt+R are how the first three are set without
the mouse. Every default is off, so a first run and a file hatch cannot read are
the same window.

Most of them change what you see or hear. `review` changes what the agent is
sent, and only ever in the direction of less: every run waits for you, and a
window that ends without an answer sends nothing — see
[Reviewing the output](#reviewing-the-output-before-it-goes). `terminal` is
the one to know about: it changes how the command runs, and everything in that
terminal — including what you type into it — goes back to the agent. A tick
made today therefore decides how a request next week executes. It is still one
box, on screen, in the window that is asking, and the capture warning is drawn
beside it whether or not it is ticked.

`stream` beats `close_on_decide` when both are on, because a window that has
gone shows nothing. The close box is then greyed with *You stream every run.*
under it, which is the window naming the standing choice that is winning
rather than claiming you asked for it about this command. Unticking Stream
gives the close box straight back.

It is a separate file from `config.toml`, in a separate directory, and the
separation is the point rather than tidiness. `config.toml` is what you wrote
and hatch reads: it holds your comments, your key order and your token, and
nothing has ever rewritten it but the one line that puts a generated token in
it on a first run. A checkbox that persists has to be written every time it is
clicked, and doing that to `config.toml` would eventually eat a comment or
reorder your keys. So what you write and what hatch writes down live apart,
which is also what the XDG spec asks for: state that persists between restarts
belongs under the state directory.

Nothing about it can stop a window opening. A missing, unreadable or malformed
`prefs.toml` is a window with every box at its default — refusing to open one
would resolve as a denial of a request nobody was ever shown — and the next tick
rewrites the file. Several windows can be open at once and two of them saving in
the same instant is ordinary; each write reads the file, changes the one box
that was clicked and renames a complete file over the old one, so a reader sees
one whole file or the other and never a torn one, ticking one box never undoes
another, and the later click on the same box wins.

### Where everything lives

Three directories, in three places, following the XDG base directory spec:

| What | Where | Default |
|---|---|---|
| `config.toml` | `$XDG_CONFIG_HOME/hatch` | `~/.config/hatch` |
| `log/`, `prefs.toml` | `$XDG_STATE_HOME/hatch` | `~/.local/state/hatch` |
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
default `~/.local/state/hatch/log/`. One line per operation, flushed per record,
a new file each month, never rotated or pruned. `hatch log` renders the current
month readably, with each line led by the number the window wore. A request
hatch refused before anybody was asked never became a window, so it has no
number and the key is absent rather than zero.

Every outcome reaches it, including the ones the agent cannot tell apart. The
log's verdicts are a superset of the agent-facing ones — `approve`, `deny`,
`explain`, `simplify`, `self_run`, `stop_and_sync`, `timeout`,
`elevation_failed`, `elevation_unclear`, `cancelled`, `disconnected`,
`prompt_died`, `not_attempted`, `refused` —
because a user denial, a client that gave up and a window that crashed all
answer the agent with "denied", and conflating them here would hide exactly the
quiet failures the log exists to catch.

Every line says how long the approval window was on screen before the outcome
that ended it, as `window_ms` in the JSON and `window 4.2s` on the readable
line. It is the one thing the file could not say before: what ended a request
was recorded exactly, and whether a person was there to do it was not. A
denial after four seconds is somebody reading and deciding; a denial after
eighty milliseconds is not a decision at all, and the two used to be written
down identically. It is on every line, including the approvals, because an
abnormal lifetime can only be recognised next to ordinary ones. A request
refused before anybody was asked never reached a screen, so the key is absent
rather than zero — a zero would say the window was there and was answered at
once, which is the exact reading this is here to make possible.

A batch of several operations is several lines, not one line holding a list,
because the questions this file is for — what wrote to this file, what ran as
root — are asked a line at a time, and a line carrying three operations would
answer `"root":true` with the two that were not. The lines share what the
decision owns: the same time, number, title, reason and note, an `operation`
of `operations` placing each one, and `stop_on_failure`, the policy the batch
ran under. `tool` names the kind of operation, `command` or `write`; lines
written before batches say `run_command` or `swap_file`, and still read back as
what they recorded.

A write's line records which of the two forms the request arrived in. The
change itself is the same either way — a patch is applied before anybody is
asked — but what the agent sent is a fact about the request, and this is where
facts about requests live. A line rendered for a person says `(from a patch)`
only when it was one; the JSON says either way, so a reader parsing the file
gets an answer rather than an absence.

A command whose output was reviewed says how the review ended — `review` is
`released`, `filtered`, `edited`, `withheld` (you sent nothing) or `unreviewed`
(nobody answered in time, or the window went) — and `hatch log` prints the same
at the end of the line. It records none of the output and nothing about what
was removed: no lines, no drop patterns, no edits. The log has never held a
command's output, and a copy of what you took out would be the one that
survives.

`hatch log` escapes what it prints. `title`, `reason`, `note`, `command` and
`path` all come from the agent, and a newline interpolated raw would split one
record into two plausible-looking lines while ANSI escapes took over the
terminal. Control characters are rendered visibly instead — a title containing
a newline is itself worth seeing.

## Not built yet

Stated so you do not go looking:

- **Binary or oversized file content** is refused rather than summarised.
  hatch will not ask anyone to approve a change it cannot draw, and an empty
  diff would say "nothing changes", which is the one thing it must never say.
- **Editing a command in the window** before approving it. Today the answers
  are deny, or ask for something simpler and wait.
- **Drawing a nested command as a tree.** The roster above the panes reads
  through `bash -c '…'` and `sh -c '…'` to name what is inside, and reads
  through the fourteen other wrappers it knows; `ssh host '…'` and
  `docker exec … '…'` it does not. Either way the payload is still *drawn* as
  one inert string in the panes, correctly and unhelpfully — the panes have no
  nesting in them.
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
