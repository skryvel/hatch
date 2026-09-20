//! `hatch preview`: the real approval window, on a request nobody asked for.
//!
//! Two things want this, and both of them shape it.
//!
//! **Somebody has to be able to look at the window.** After `hatch setup`
//! there was no way to see what `font_size`, `theme` and `terminal` actually
//! render as without persuading an agent to make a request — which means
//! tuning a display preference by asking a language model to knock on the
//! door. `hatch preview` opens the window on a built-in sample, reading the
//! same config `hatch prompt` reads, and that is the reason it ships.
//!
//! **The README's images have to be reproducible.** They were taken by hand,
//! and by hand turned out to mean: unset `WAYLAND_DISPLAY` so the window
//! lands on X11, find its id, and `import -window` it, because the desktop
//! portal kills `spectacle` and `ffmpeg -f x11grab` of the root window comes
//! back black under rootless Xwayland. None of that is a procedure anyone
//! else can follow. egui will photograph its own viewport —
//! [`egui::ViewportCommand::Screenshot`], answered with an
//! [`egui::Event::Screenshot`] carrying a [`egui::ColorImage`] — which is
//! pixel-exact, needs no compositor and is the same on any machine with a
//! GPU context. `--shot` is that, and the README records the exact command
//! that regenerates each image.
//!
//! # The property this module exists to keep
//!
//! **A preview is built through the path the daemon uses.** If it had a route
//! of its own then a preview that looked right would be no evidence that the
//! real window looks right, and the pictures in the README would be pictures
//! of something that does not exist. So every sample here is a
//! [`protocol::Request`] assembled from [`render::render_command_reinterpreting`],
//! [`Payload::command`], [`Payload::swap`] and [`swap::plan`] — the calls
//! [`crate::server::Daemon::prepare`](crate::server) makes, in the order it
//! makes them — and it is handed to [`crate::prompt_ui::PromptApp`], which is
//! the window `hatch prompt` runs. The two are held together by a test rather
//! than by this paragraph: [`Sample::asked`] keeps the words the sample was
//! built from, so the daemon can be given the very same request and the two
//! payloads compared field for field. See
//! `a_preview_is_the_payload_the_daemon_would_have_sent` in
//! [`crate::server`].
//!
//! # Nothing here can run anything
//!
//! A preview has no daemon behind it, and that is a fact about this module
//! rather than an accident of how it happens to be started. The window's one
//! way to act on a decision is the frame it writes to its `out`, and the only
//! `out` a preview ever constructs is [`Nobody`] — see that type for the
//! argument, and `approving_a_preview_reaches_nobody` for the test. What this
//! process holds is a [`protocol::Request`]: a title, a reason, a deadline
//! and a rendering. There is no argv in it, no content to write and no
//! `Work`; the half of hatch that turns an approval into something happening
//! is [`crate::server`], and `hatch preview` never builds one.
//!
//! # The root scenario
//!
//! The one sample that needed a decision, because `run0` is not reachable
//! everywhere `hatch preview` is. The root window is the most distinctive
//! thing hatch draws — a filled `ROOT` block and a danger frame around the
//! whole window — and a preview that cannot show it on a developer's machine
//! is not much use; a preview that made the line up would be a picture of
//! something hatch would never render. So it does neither: it asks the real
//! [`Elevation`] for the real line through [`Elevation::compose_argv`], which
//! is [`Elevation::argv`] without the "can this machine elevate" gate in
//! front of it. Same function, same child environment, same argv, same break
//! offset — see [`Elevation::compose`] for why splitting the gate off is not
//! a hole. Where the gate would have refused, the preview says so on standard
//! error before it opens the window, because the reader is then looking at a
//! window this machine would never have been shown.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use chrono::Utc;
use eframe::egui;

use crate::config::Config;
use crate::exec::elevate::{Elevation, platform};
use crate::exec::env::build_child_env;
use crate::prompt_ui::theme::Theme;
use crate::prompt_ui::{Incoming, Phase, PromptApp};
use crate::protocol::{DaemonMsg, Payload, Request};
use crate::render::diff::{FileDiff, diff_files};
use crate::render::render_command_reinterpreting;
use crate::render::roster::roster;
use crate::swap;

/// How many frames are drawn after the request lands before the viewport is
/// photographed.
///
/// Not decoration. The two command panes decide between side by side and
/// stacked from measurements they leave in egui's temporary memory for the
/// next frame to read — see [`crate::prompt_ui::panes`] — a scroll area needs
/// a frame to learn how tall its contents are, and the font atlas is built
/// lazily on first use. A picture taken on the first frame is a picture of a
/// window mid-thought. Eight is several times more than any of those need and
/// costs milliseconds.
const SETTLE_FRAMES: u32 = 8;

/// How long the window is left alone before it is photographed, on top of
/// [`SETTLE_FRAMES`].
///
/// A frame count is not on its own enough, because one of the things settling
/// is measured on the clock rather than in frames: a solid scroll bar animates
/// its column in over the style's animation time, and until that has finished
/// the pane beside it is still narrowing. These frames are asked for as fast
/// as the window will draw them — see [`PreviewApp::photograph`] — so eight of
/// them can go by in a fraction of it, and two runs of the same command then
/// photograph the same window at two widths a pixel apart. Three times egui's
/// own default animation time, and still a fifth of a second.
const SETTLE_TIME: Duration = Duration::from_millis(250);

/// How long `--shot` waits for a picture before giving up.
///
/// The window has to be created, gain or fail to gain focus, open its typing
/// guard and draw [`SETTLE_FRAMES`], so a few seconds is normal and this is
/// only the backstop for a compositor that never maps the window at all.
/// Failing here exits non-zero with a reason, which is better than a
/// screenshot tool that hangs in somebody's build script.
const SHOT_DEADLINE: Duration = Duration::from_secs(30);

/// What `--shot` adds to the configured timeout when it stamps the deadline.
///
/// The countdown is `deadline - now` truncated to whole seconds, so a
/// deadline of exactly `timeout_secs` away reads as one second less the
/// instant any time passes: two runs of the same command would differ, and
/// "9 min 59 s" is a worse thing to have in a README than a round number. One
/// second ahead makes the drawn figure exactly the configured timeout —
/// `10 min left to decide` at the default — for the whole of the first second
/// after the stamp.
///
/// That budget is why `--shot` sends the request *after* the guard has opened
/// rather than as the window is created: everything slow about opening a
/// window happens before the stamp, and what follows it is
/// [`SETTLE_FRAMES`] frames, which take milliseconds. A machine slow enough
/// to lose the race gets a correct picture with an odd number on it, not a
/// wrong one.
const SHOT_SLACK: i64 = 1;

/// The directory a sample writes its own files into.
///
/// A file write is planned against the filesystem — [`swap::plan`] stats the
/// target, inherits its mode and owner and hashes it — so the swap sample
/// needs a file that really exists, or it would be previewing a *create* and
/// the metadata panel a replacement fills in would be empty. The file is the
/// preview's own and lives under the temporary directory, at a fixed name
/// rather than a randomised one so that two runs produce the same picture.
///
/// It is also the honest path to have on screen. A sample that claimed to be
/// replacing `/etc/service/config.yaml` would be naming a file hatch had not
/// looked at.
fn staging_dir() -> PathBuf {
    std::env::temp_dir().join("hatch-preview")
}

/// Which sample window to draw.
///
/// The ones the README documents. Adding one is a variant here and an arm in
/// [`build`], and the agreement test in [`crate::server`] then covers it
/// without being edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Scenario {
    /// A plain multi-line command with a resolved variable in it.
    Command,
    /// Two `cp` lines, the second carrying a Trojan Source filename and a
    /// non-breaking space, with something waiting behind it.
    Chips,
    /// A file replacement: the metadata panel and the side-by-side diff.
    Swap,
    /// A command that runs as root: the `ROOT` block and the danger frame.
    Root,
    /// A command longer and wider than the window: the stacked panes, and the
    /// line that says how much of it is out of sight.
    Long,
    /// A command with comments in it, including one that contains every
    /// separator hatch knows.
    ///
    /// Its own sample rather than a comment added to [`Scenario::Command`],
    /// because the thing to look at is a comparison: the `&&` on the second
    /// line starts a new segment and the `&&` inside the comment does not,
    /// and both are on screen at once.
    Comment,
    /// A command whose lines redirect: the operators, the words they point
    /// at, and the two things that look like them and are not.
    ///
    /// Its own sample for the reason [`Scenario::Comment`] is, and it is the
    /// same kind of comparison. A `>|` and a real `|` are two rows apart, a
    /// `>` inside quotes sits between them and is an argument, and a
    /// destination that resolves out of the environment is directly below one
    /// that does not.
    Redirect,
    /// A command that writes a file with a here-document: the body drawn as
    /// the data it is, between the two lines that delimit it.
    ///
    /// Its own sample for the reason [`Scenario::Comment`] is, and it is the
    /// same kind of comparison. Everything in the body would have been read as
    /// shell before: a `&&`, a `#`, a `$HOME` and a first word that is not a
    /// program. Each has a live one within a row or two of it -- a real `&&`
    /// on the last line, a real command word at the top, and a `$HOME` that
    /// resolves above one that does not -- so the two readings are on screen
    /// at once and the difference between them is what the sample is for.
    Heredoc,
    /// A command whose lines belong together in four nested ways: the gutter
    /// brackets, and how far in they step.
    ///
    /// Its own sample because the thing to look at is depth. One bracket says
    /// little that indentation would not; four, stepping in from the same
    /// left edge while the text stays where it is, is the claim the treatment
    /// is actually making, and the only way to tell whether it reads is to
    /// look at it. The pipeline at the bottom is there so a block that is not
    /// a loop is on screen beside ones that are, and the `if` is there
    /// because it deliberately draws nothing -- see
    /// [`crate::render::blocks`].
    Blocks,
}

impl Scenario {
    /// All of them, so a test that must cover every scenario cannot be
    /// written to cover three.
    #[cfg(test)]
    pub(crate) fn all() -> [Scenario; 9] {
        [
            Scenario::Command,
            Scenario::Chips,
            Scenario::Swap,
            Scenario::Root,
            Scenario::Long,
            Scenario::Comment,
            Scenario::Redirect,
            Scenario::Heredoc,
            Scenario::Blocks,
        ]
    }
}

/// What one sample asks for, in the words an agent's own request would use:
/// the one operation of a batch.
///
/// Kept beside the payload rather than thrown away once the payload is built,
/// and that is the whole warrant for this subcommand: a test can hand these
/// same words to a real [`crate::server::Daemon`] and compare what comes back
/// with what is below. Without it "the preview is built the way the daemon
/// builds one" would be a sentence in a doc comment, which is exactly the
/// shape of claim this project has been bitten by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Asked {
    /// A command, as `run_command` or a batch would send it.
    Command {
        command: String,
        cwd: PathBuf,
        root: bool,
        interactive: bool,
    },
    /// A file write in the whole-file form, as a batch would send it.
    Write { path: PathBuf, content: String, root: bool },
}

/// One sample, complete except for when it is sent.
///
/// The deadline is not in here on purpose. It is an instant on a clock, and
/// which instant depends on when the window is ready to be photographed; see
/// [`SHOT_SLACK`].
#[derive(Debug, Clone)]
pub(crate) struct Sample {
    pub(crate) title: String,
    pub(crate) reason: String,
    pub(crate) queue_depth: u32,
    /// What this sample would look like arriving at the daemon.
    ///
    /// Read by the agreement test and by nothing that ships, which is exactly
    /// what it is for: see [`Asked`].
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) asked: Asked,
    pub(crate) payload: Payload,
}

impl Sample {
    /// The request as the daemon would write it down the channel.
    fn request(&self, timeout_secs: u64, slack: i64) -> Request {
        Request {
            title: self.title.clone(),
            reason: self.reason.clone(),
            deadline: Utc::now() + chrono::Duration::seconds(timeout_secs as i64 + slack),
            queue_depth: self.queue_depth,
            // A preview is not the first request of anything. Nobody is
            // counting windows here, so this one has no number to put in its
            // title bar -- see `Request::number`.
            number: None,
            // One operation, because a sample is one. The list is the
            // request's shape and not the sample's.
            operations: vec![self.payload.clone()],
            stop_on_failure: false,
            // A preview stands alone: there is no daemon behind it that has
            // watched other windows end, so there is nothing it could
            // honestly report having missed.
            unanswered: Vec::new(),
        }
    }
}

// ---- building a sample the way the daemon builds a request -----------------

/// The payload for a command sample.
///
/// A transcription of `Daemon::prepare_run`'s second half, in its order and
/// with its comments' reasoning intact: the elevated case draws the whole
/// `run0` line with a break where the approved command begins and resolves
/// variables against the *command's* environment, and the unelevated case
/// draws the command the agent wrote and nothing else. The one difference is
/// [`Elevation::compose_argv`] in place of [`Elevation::argv`] — the same
/// line, without the question about this machine that a caller who is going
/// to spawn it has to ask first.
fn command_payload(
    elevation: &dyn Elevation,
    env: &std::collections::BTreeMap<String, String>,
    asked: &Asked,
) -> anyhow::Result<Payload> {
    let Asked::Command { command, cwd, root, interactive } = asked else {
        anyhow::bail!("a command payload was asked for a swap");
    };
    let (line, break_at, script_at, render_env, caveat) = match root {
        true => {
            let elevated = elevation
                .compose_argv(command, env)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            (
                elevated.display_line(),
                elevated.inner_at(),
                elevated.script_at(),
                elevation.child_env(env),
                elevation.caveat(),
            )
        }
        false => (command.clone(), None, None, env.clone(), None),
    };
    let spans = render_command_reinterpreting(&line, &render_env, break_at, script_at.clone());
    // The roster, off the same line and the same environment the daemon uses
    // -- which means a preview of a sample resolves the sample's own names
    // against this machine, exactly as a real request would. A sample that
    // named something this machine does not have draws the window that says
    // so, which is the honest picture of what hatch would have shown.
    let runs = roster(&line, &render_env, cwd);
    // Danger markers are display-only and land with the marker heuristics; an
    // empty list has never been a claim that a command is safe. The daemon
    // passes an empty one too, and a sample that invented markers would be
    // showing a header the daemon cannot currently produce.
    Ok(Payload::command(&spans, Vec::new(), cwd.clone(), *root, *interactive)
        .with_caveat(caveat)
        .with_script(script_at)
        .with_runs(runs))
}

/// The payload for a file write sample.
///
/// `Daemon::prepare_swap`'s order, minus the two refusals that are about the
/// request rather than the rendering: the denylist and the working directory
/// have nothing to say about a file this module wrote itself.
fn swap_payload(asked: &Asked, cap: usize) -> anyhow::Result<Payload> {
    let Asked::Write { path, content, root } = asked else {
        anyhow::bail!("a swap payload was asked for a command");
    };
    let content = content.as_bytes();
    let plan = swap::plan(path, content, *root)
        .with_context(|| format!("planning the sample write to {}", path.display()))?;
    let before = fs::read(path)
        .with_context(|| format!("reading the sample file at {}", path.display()))?;
    let FileDiff::Rows(rows) = diff_files(&before, content, cap) else {
        anyhow::bail!(
            "the sample at {} could not be diffed, which means this module wrote something it \
             cannot draw",
            path.display()
        );
    };
    Ok(Payload::swap(path.clone(), plan, &rows))
}

/// The `before` side of the swap sample, written where the sample says it is.
///
/// Written on every run and at an explicit mode, because both are on screen:
/// the metadata panel states the mode the replacement will inherit and the
/// size it will change by, and a file left over from a previous run at
/// whatever the umask allowed would put a different number there each time.
fn stage_sample_file(staging: &Path) -> anyhow::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;

    let path = staging.join("etc/service/config.yaml");
    let dir = path.parent().expect("the sample path has a parent");
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    fs::write(&path, SWAP_BEFORE).with_context(|| format!("writing {}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("securing {}", path.display()))?;
    Ok(path)
}

/// The file the swap sample replaces.
const SWAP_BEFORE: &str = "server:\n  listen: 127.0.0.1:8080\n  workers: 4\n  timeout: 30\n\n\
                           logging:\n  level: info\n  file: /var/log/service.log\n";

/// What it is replaced with: three changed lines out of eight, one byte
/// larger.
const SWAP_AFTER: &str = "server:\n  listen: 127.0.0.1:8080\n  workers: 8\n  timeout: 90\n\n\
                          logging:\n  level: debug\n  file: /var/log/service.log\n";

/// Build one sample, through the daemon's own calls.
///
/// `staging` is where a sample that needs a file on disk puts one; only
/// [`Scenario::Swap`] does. Everything else here is a string and a rendering.
pub(crate) fn build(
    scenario: Scenario,
    config: &Config,
    elevation: &dyn Elevation,
    staging: &Path,
) -> anyhow::Result<Sample> {
    let env = build_child_env(config);
    // The daemon's own default for a request that names no working directory,
    // which is the commonest real case and the only one a sample can be sure
    // exists: `$HOME` as the *child* will see it. A sample that named a
    // directory this machine does not have would be a request the daemon
    // would have refused before drawing anything.
    let cwd = PathBuf::from(env.get("HOME").map_or("/", String::as_str));

    let sample = match scenario {
        Scenario::Command => {
            let asked = Asked::Command {
                command: "cd $HOME/src/service &&\ncargo build --release --locked &&\n\
                          systemctl --user restart service"
                    .to_string(),
                cwd,
                root: false,
                interactive: false,
            };
            Sample {
                title: "Rebuild the service and restart it".to_string(),
                reason: "The unit is still running last week's binary. The fix is in the \
                         working tree and the toolchain only exists on the host."
                    .to_string(),
                queue_depth: 0,
                payload: command_payload(elevation, &env, &asked)?,
                asked,
            }
        }
        Scenario::Comment => {
            let asked = Asked::Command {
                // Three things to look at, in the order they appear. The
                // first comment holds every separator hatch knows and not one
                // of them starts a segment -- while the `&&` on the line
                // below it does, two rows away, in the same colours. The `#`
                // in `service#2` is not at the start of a word and is not a
                // comment, which is the rule that keeps a URL fragment out of
                // this. And the `$HOME` in the last comment is drawn without
                // a value while the one above it has one, because the shell
                // expands one of them and never reads the other.
                command: COMMENT_SAMPLE.to_string(),
                cwd,
                root: false,
                interactive: false,
            };
            Sample {
                title: "Build the service and install it".to_string(),
                reason: "The notes in the command are the author's; hatch draws them as the \
                         one part of the line that will not run."
                    .to_string(),
                queue_depth: 0,
                payload: command_payload(elevation, &env, &asked)?,
                asked,
            }
        }
        Scenario::Redirect => {
            let asked = Asked::Command {
                // Four things to look at. The `>|` on the last line is one
                // operator and the `|` two rows above it is a segment
                // boundary, in the same colours and three rows apart. The
                // `' > '` between them is quoted and is an argument to
                // `grep`, not a redirection. The `2>&1` and the `2>>` carry
                // the file descriptor bash reads as part of the operator. And
                // every destination is marked as loudly as the arrow in front
                // of it, which is the half of a redirection a reader is
                // actually scanning for.
                command: REDIRECT_SAMPLE.to_string(),
                cwd,
                root: false,
                interactive: false,
            };
            Sample {
                title: "Rebuild the service and file the warnings".to_string(),
                reason: "The nightly build has been failing since Tuesday and the log is                          the only copy of why. The report generator reads the two files                          this writes."
                    .to_string(),
                queue_depth: 0,
                payload: command_payload(elevation, &env, &asked)?,
                asked,
            }
        }
        Scenario::Heredoc => {
            let asked = Asked::Command {
                // Four things to look at, and each of them is a pair. The
                // `&&` and the `#` in the body are data and the `&&` on the
                // last line is a boundary; the `$HOME` on the first line
                // resolves and the one in the body does not, because the
                // delimiter is quoted; `cat` and `nginx` are words that name
                // programs and `server` at the start of a body line is a word
                // in a config file. The line that ends the body is drawn as
                // the delimiter it is rather than as a program called
                // `NGINXCONF`, which is what the roster above the panes used
                // to call it.
                command: HEREDOC_SAMPLE.to_string(),
                cwd,
                root: false,
                interactive: false,
            };
            Sample {
                title: "Write the reverse-proxy site file and reload nginx".to_string(),
                reason: "The new service is listening on 8080 and nothing in front of it \
                         routes there yet."
                    .to_string(),
                queue_depth: 0,
                payload: command_payload(elevation, &env, &asked)?,
                asked,
            }
        }
        Scenario::Blocks => {
            let asked = Asked::Command {
                command: BLOCKS_SAMPLE.to_string(),
                cwd,
                root: false,
                interactive: false,
            };
            Sample {
                title: "Check every dump against its checksum and prune the old ones".to_string(),
                reason: "The restore drill needs a checksum for every dump, and the backup \
                         volume is at 91%."
                    .to_string(),
                queue_depth: 0,
                payload: command_payload(elevation, &env, &asked)?,
                asked,
            }
        }
        Scenario::Chips => {
            let asked = Asked::Command {
                // The second line is the whole argument for the rendering.
                // U+202E reverses everything after it inside the quotes, so
                // the filename reads as `gnp.txt.exe` and is not one; U+00A0
                // is a non-breaking space in a path that appears to be
                // `staging/archive`. Both are chipped, and the ordinary
                // newline between the two commands stays a quiet arrow,
                // because if it shouted as loudly as those two nobody would
                // keep reading either.
                command: "cp notes.md staging/\ncp 'gnp\u{202E}txt.exe' staging/\u{00A0}archive"
                    .to_string(),
                cwd,
                root: false,
                interactive: false,
            };
            Sample {
                title: "Stage the release notes".to_string(),
                reason: "Two lines, and the second is not the filename it looks like."
                    .to_string(),
                // So the badge is in the picture. Two more requests waiting is
                // an ordinary state for a busy agent and the one state the
                // badge has to be legible in.
                queue_depth: 2,
                payload: command_payload(elevation, &env, &asked)?,
                asked,
            }
        }
        Scenario::Swap => {
            let asked = Asked::Write {
                path: stage_sample_file(staging)?,
                content: SWAP_AFTER.to_string(),
                root: false,
            };
            Sample {
                title: "Raise the worker count and turn on debug logging".to_string(),
                reason: "The service is saturating four workers under the new load, and the \
                         logs at info do not say which request is stalling."
                    .to_string(),
                queue_depth: 0,
                payload: swap_payload(&asked, config.output_cap_bytes)?,
                asked,
            }
        }
        Scenario::Root => {
            let asked = Asked::Command {
                // `systemctl status` is the reason the elevated line carries
                // `--setenv=PAGER=cat`: a root command can find itself on a
                // terminal, and a pager with nothing to read from waits until
                // hatch kills it. The sample that shows the `--setenv` list
                // off should be the command the list exists for.
                //
                // It is a script and not a one-liner because the thing worth
                // looking at on this window is what happens *inside* the
                // quotes. hatch puts the whole of an elevated command into
                // one argument of `bash -c`, and a sample short enough to
                // read as a string would not show that the pane reads it as
                // shell -- the separators, the words that name what runs, the
                // resolved variables, and the brackets down the gutter are
                // all drawn inside a single shell word. See
                // `render::render_command_reinterpreting`.
                command: ROOT_SAMPLE.to_string(),
                cwd,
                root: true,
                interactive: false,
            };
            Sample {
                title: "Restart the service and read its status".to_string(),
                reason: "The watchdog has restarted it three times since the deploy, and the \
                         unit's own status is the only place that says why."
                    .to_string(),
                queue_depth: 0,
                payload: command_payload(elevation, &env, &asked)?,
                asked,
            }
        }
        Scenario::Long => {
            let asked = Asked::Command {
                command: LONG_COMMAND.to_string(),
                cwd,
                root: false,
                interactive: false,
            };
            Sample {
                title: "Cut the 0.9.2 release and push it".to_string(),
                reason: "Everything in the milestone is merged and the tag has to go out \
                         before the freeze tonight."
                    .to_string(),
                queue_depth: 0,
                payload: command_payload(elevation, &env, &asked)?,
                asked,
            }
        }
    };
    Ok(sample)
}

/// The command behind [`Scenario::Comment`].
///
/// Written as a block rather than as one escaped line, because what the
/// scenario is for is the comparison between two `&&`s two rows apart, and a
/// sample whose line breaks are `\n` escapes in a source file is a sample
/// nobody can see the shape of while they are editing it.
///
/// Every separator hatch knows is in the first comment -- `&&`, `||`, `;`,
/// `|`, and a bare `&` for good measure -- and none of them is a boundary,
/// because the shell stops reading at the `#`. The `#` in `service#2` is not
/// at the start of a word, so it is not a comment; and `$HOME` appears twice,
/// once where the shell will expand it and once where it will not.
const COMMENT_SAMPLE: &str = "\
cargo build --release   # then && rm -rf /tmp || true ; ls | wc & done
cp target/release/service $HOME/bin/service#2 &&
systemctl --user restart service   # leaves $HOME alone";

/// The command behind [`Scenario::Redirect`].
///
/// Written as a block for the reason [`COMMENT_SAMPLE`] is: the scenario is a
/// comparison between rows, and a sample whose line breaks are `\n` escapes
/// in a source file is a sample nobody can see the shape of while they are
/// editing it.
///
/// Five operators, and each is there for a case. `>` and `2>&1` on the first
/// line are the pair everybody writes, and the `2>&` is the one whose file
/// descriptor bash reads as part of the operator. The `' > '` on the second
/// line is an argument to `grep` and not a redirection, which is the rule
/// that keeps an arrow inside a string out of this -- and the `|` beside it
/// really is a segment boundary. The `2>>` appends. The `>|` on the last line
/// is one operator, so the `|` in it is not the boundary the `|` two rows
/// above it is, and that pair is the whole reason the sample is four lines
/// rather than two.
///
/// The destinations are the point. `$HOME/reports/service.txt` resolves out
/// of the environment the command will really run in and `build.log` does
/// not, and both are drawn as loudly as the arrow in front of them, because
/// in `> /etc/passwd` the word a reader is scanning for is never the arrow.
///
/// It is still a script somebody might really write. hatch says nothing about
/// whether any of these destinations is a good idea -- that is a question
/// about the path, and a different pass's to answer.
const REDIRECT_SAMPLE: &str = "\
make -j4 > build.log 2>&1
grep -F ' > ' build.log | tee warnings.txt
install -m 0644 warnings.txt /srv/reports/ 2>> install.log
printf 'done\\n' >| $HOME/reports/service.txt";

/// The command behind [`Scenario::Heredoc`].
///
/// Written as a block for the reason [`COMMENT_SAMPLE`] is, and here it is not
/// even a choice: a here-document *is* its line breaks. The body ends on a line
/// that is exactly the delimiter, so a sample written with `\n` escapes would
/// be a sample whose one load-bearing property nobody could see.
///
/// It is a file somebody might really write, and every line of the body is a
/// line that used to be read as shell. `server {` put `server` in the roster as
/// a program nothing answers to; the `&&` in the comment was a segment
/// boundary the shell does not have; the `#` began a comment over data; and the
/// `$HOME` was resolved to this machine's home directory although the
/// delimiter is quoted and the shell substitutes nothing in the body at all.
/// The `$HOME` on the first line is the control: it is on the operator's line,
/// it really does expand, and it is drawn with its value two rows above the one
/// that is not.
///
/// The last line is the other control. Its `&&` is a real boundary and its
/// `systemctl` is a real command, both a row under a body that contains the
/// same shapes and means none of them.
const HEREDOC_SAMPLE: &str = "\
cat <<'NGINXCONF' > $HOME/sites/service.conf
server {
    listen 80;
    # proxy_pass && upstream are set by the deploy, not $HOME
    location / { proxy_pass http://127.0.0.1:8080; }
}
NGINXCONF
nginx -t && systemctl --user reload nginx";

/// The command behind [`Scenario::Blocks`].
///
/// Four constructs inside one another -- a loop, a subshell, a second loop
/// and a case -- so the gutter is four columns wide at its deepest, and a
/// pipeline broken across three lines at the bottom, which is a block of a
/// different kind at the outermost column. The `if` in the middle is drawn
/// with no bracket at all, on purpose.
const BLOCKS_SAMPLE: &str = "\
cd $HOME/backups
for db in app analytics audit; do
  (
    while read -r dump; do
      case $dump in
        *.tmp) continue;;
        *) sha256sum \"$dump\" >> SHA256SUMS;;
      esac
    done
  )
done
if [ ! -s SHA256SUMS ]; then
  echo 'no checksums written' >&2
fi
find . -name '*.sql.gz' -mtime +30 -print0 |
  xargs -0 --no-run-if-empty rm -v |
  tee -a prune.log";

/// The command behind [`Scenario::Root`].
///
/// Short enough to read in one go and structured enough to have something to
/// say: a loop, a conditional inside it, and a variable the child environment
/// answers for. Every one of those is drawn inside the quotes `bash -c` will
/// receive as one word.
const ROOT_SAMPLE: &str = "\
systemctl restart service &&
for unit in service service-worker; do
  systemctl is-active --quiet $unit ||
    journalctl -u $unit -n 20 --no-pager
done
systemctl status service";

/// The command behind [`Scenario::Long`].
///
/// This scenario exists because the ones above it all fit. A sample that fits
/// its panes exercises nothing about the window's account of what is off the
/// end of them — the stacked arrangement, the strip that scrolls sideways,
/// and the line under the caption that says how many rows are out of sight —
/// and those are the parts a reader most needs to be able to look at, because
/// they are the parts that exist for a command written to hide something.
///
/// So it is long in both directions on purpose. More lines than a window of
/// any ordinary height can show, and one line — the `rsync` — far wider than
/// a full-width pane, which is what sends the panes into the stacked
/// arrangement and runs the raw strip off its right edge.
///
/// It is still a command somebody might really write. A sample of padding
/// would demonstrate the same rectangles and teach nobody what the window is
/// for.
///
/// The backslashes in the `rsync` are Rust's line continuations and not the
/// shell's: they are folded here so this file stays readable, and what the
/// window is handed is one line of some two hundred and thirty characters.
/// A sample that really carried a `\` and a newline would be a sample of the
/// shell's own folding, which is a different thing to look at and not this
/// one.
const LONG_COMMAND: &str = "\
set -euo pipefail

cd $HOME/src/service
git fetch --all --tags --prune
git switch main
git pull --ff-only

cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --locked
cargo build --release --locked

target/release/service --version
sha256sum target/release/service | tee dist/service-0.9.2.sha256

git tag -a v0.9.2 -m 'release 0.9.2'
git push origin v0.9.2

rsync -avz --delete --checksum --partial --human-readable --exclude '*.tmp' --exclude '.git/' \
--rsh 'ssh -o StrictHostKeyChecking=yes -o ConnectTimeout=10' target/release/service \
deploy@build.internal:/srv/releases/service/0.9.2/service

ssh deploy@build.internal 'systemctl --user restart service'
sleep 5
ssh deploy@build.internal 'systemctl --user is-active service'

curl -fsS https://service.internal/healthz
curl -fsS https://service.internal/version

echo 'released 0.9.2'";

// ---- where a preview's verdicts go -----------------------------------------

/// Nobody, and that is the point.
///
/// The approval window acts on a decision in exactly one way: it writes one
/// [`crate::protocol::PromptMsg`] to the `out` it was given, and a daemon on
/// the other end of that pipe is what turns the frame into a command running
/// or a file being written. `hatch prompt` is given this process's stdout,
/// which the daemon is holding. A preview is given this.
///
/// It is a named type rather than [`io::sink`] because the claim is worth
/// being able to point at and worth being able to test. It counts what it
/// swallows, so `approving_a_preview_reaches_nobody` can press the button on
/// a real window, watch the state machine produce a real approval, and then
/// show that the frame went here and nowhere a daemon could be. The claim
/// does not rest on a pipe happening to be absent: this process never
/// constructs the other kind of `out` at all.
///
/// It swallows rather than failing. A write error is how the window learns
/// its channel is broken, and a preview's channel is not broken — there was
/// never one to break, and reporting an error would make pressing Approve in
/// a preview look like a fault. What happens instead is
/// [`PreviewApp::logic`]: the window leaves the phase in which it is asking
/// anything, so the preview closes and says nothing ran.
pub(crate) struct Nobody {
    swallowed: Arc<AtomicUsize>,
}

impl Nobody {
    fn new() -> (Nobody, Arc<AtomicUsize>) {
        let swallowed = Arc::new(AtomicUsize::new(0));
        (Nobody { swallowed: Arc::clone(&swallowed) }, swallowed)
    }
}

impl Write for Nobody {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.swallowed.fetch_add(buf.len(), Ordering::SeqCst);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---- the window ------------------------------------------------------------

/// The screenshot half of a preview, when there is one.
struct Shot {
    /// Where the PNG goes.
    path: PathBuf,
    /// Frames drawn since the request landed.
    settled: u32,
    /// When the first of them was drawn, for the wall-clock half of the wait.
    /// See [`SETTLE_TIME`].
    settling_since: Option<Instant>,
    /// Whether the viewport has been asked for its picture.
    asked: bool,
}

/// The real approval window, plus the two things a preview does around it:
/// decide when to hand it the sample, and photograph it.
///
/// A wrapper and not a fork. Every frame of what a reader sees is
/// [`PromptApp`]'s, drawn by [`PromptApp::ui`]; nothing here draws anything.
struct PreviewApp {
    inner: PromptApp,
    /// The sample, until it is handed over. The channel is this process's
    /// half of what the daemon would be doing.
    pending: Option<Sample>,
    to_window: Sender<Incoming>,
    /// The configured approval timeout, which is what the countdown counts.
    timeout_secs: u64,
    shot: Option<Shot>,
    /// When the window was created, for [`SHOT_DEADLINE`].
    opened_at: Instant,
    /// Set when something went wrong that the process should exit non-zero
    /// for. A window that could not be photographed must not look like one
    /// that was.
    failure: Arc<OnceLock<String>>,
    /// Set when the PNG has been written.
    captured: Arc<OnceLock<PathBuf>>,
}

impl PreviewApp {
    /// Hand the window its request, if it is time.
    ///
    /// Immediately for a person, who is waiting to look at it. For `--shot`,
    /// once the typing guard has opened: the buttons are drawn disabled until
    /// then, and this is also what buys the deadline stamp its second — see
    /// [`SHOT_SLACK`].
    fn maybe_send(&mut self) {
        let ready = match self.shot {
            Some(_) => self.inner.guard_open(),
            None => true,
        };
        if !ready {
            return;
        }
        let Some(sample) = self.pending.take() else { return };
        let slack = match self.shot {
            Some(_) => SHOT_SLACK,
            None => 0,
        };
        let request = sample.request(self.timeout_secs, slack);
        // The receiver lives in the window this struct owns, so this cannot
        // fail; if it somehow did, the window would sit on "waiting for
        // hatch" and the shot deadline would end the process with a reason.
        let _ = self.to_window.send(Incoming::Frame(DaemonMsg::Request(Box::new(request))));
    }

    /// Ask for the picture, take it, and write it.
    ///
    /// The event is read before [`PromptApp::logic`] runs, because that is
    /// where [`crate::prompt_ui::guard::intercept`] empties the frame: every
    /// event the guard has not been taught to keep is dropped where it is
    /// judged, and a screenshot reply is not something the guard has heard
    /// of. Reading it here is not sneaking past the guard — the guard is
    /// about what a *widget* may act on, and nothing here is a widget.
    fn photograph(&mut self, ctx: &egui::Context) {
        let Some(shot) = self.shot.as_mut() else { return };
        // Frames do not arrive on their own once the window is idle: the
        // approval window asks for a repaint a second out, and waiting a
        // second per settling frame would make a screenshot take ten.
        ctx.request_repaint();

        let delivered = ctx.input(|i| {
            i.events.iter().find_map(|event| match event {
                egui::Event::Screenshot { image, .. } => Some(Arc::clone(image)),
                _ => None,
            })
        });
        if let Some(image) = delivered {
            match write_png(&shot.path, &image) {
                Ok(()) => {
                    let _ = self.captured.set(shot.path.clone());
                }
                Err(e) => {
                    let _ = self.failure.set(format!("{e:#}"));
                }
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        if !shot.asked {
            if self.pending.is_some() {
                // Still waiting for the guard. Nothing has been drawn that is
                // worth a picture yet.
            } else {
                let since = *shot.settling_since.get_or_insert_with(Instant::now);
                match shot.settled >= SETTLE_FRAMES && since.elapsed() >= SETTLE_TIME {
                    true => {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(
                            egui::UserData::default(),
                        ));
                        shot.asked = true;
                    }
                    false => shot.settled += 1,
                }
            }
        }

        if self.opened_at.elapsed() > SHOT_DEADLINE {
            let _ = self.failure.set(format!(
                "the window did not produce a picture within {} s, so {} was not written",
                SHOT_DEADLINE.as_secs(),
                shot.path.display(),
            ));
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

impl eframe::App for PreviewApp {
    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.photograph(ctx);
        self.maybe_send();
        eframe::App::logic(&mut self.inner, ctx, frame);
        // A preview that has been decided has nothing left to be. The real
        // window would now be showing a command running, because a daemon
        // read the approval and started one; here the frame went to
        // [`Nobody`], so a window that stayed would be claiming a run that
        // does not exist.
        if !matches!(
            self.inner.state().phase(),
            Phase::WaitingForRequest | Phase::AwaitingVerdict
        ) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        eframe::App::ui(&mut self.inner, ui, frame);
    }
}

/// Write one [`egui::ColorImage`] out as an 8-bit RGBA PNG.
///
/// The image arrives at the viewport's size in physical pixels, which is what
/// `read_screen_rgba` reads off the framebuffer, so the file lands at the
/// window's native size whatever the display's scale factor is.
///
/// `Color32` is premultiplied, so the channels are unmultiplied on the way
/// out: a half-transparent pixel written premultiplied is a pixel darkened by
/// its own alpha.
fn write_png(path: &Path, image: &egui::ColorImage) -> anyhow::Result<()> {
    let [width, height] = image.size;
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let file = fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut encoder =
        png::Encoder::new(io::BufWriter::new(file), width as u32, height as u32);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().with_context(|| format!("{}", path.display()))?;
    let mut bytes = Vec::with_capacity(width * height * 4);
    for pixel in &image.pixels {
        bytes.extend_from_slice(&pixel.to_srgba_unmultiplied());
    }
    writer.write_image_data(&bytes).with_context(|| format!("{}", path.display()))?;
    writer.finish().with_context(|| format!("{}", path.display()))?;
    Ok(())
}

/// Which palette this run draws in.
///
/// `--theme` is for this window and this window only: nothing here writes the
/// config, and the next `hatch prompt` draws in whatever the file still says.
/// Without it the configured palette is used, which is the whole point of
/// being able to look at the window at all.
fn palette(configured: Theme, asked: Option<Theme>) -> Theme {
    asked.unwrap_or(configured)
}

/// Open the approval window on a sample.
///
/// # Errors
///
/// The sample could not be built, the window could not be opened, or `--shot`
/// was given and no picture reached the disk. Each of those exits non-zero,
/// because a tool that regenerates documentation images must not report
/// success for an image it did not write.
pub fn run(scenario: Scenario, shot: Option<PathBuf>, theme: Option<Theme>) -> anyhow::Result<()> {
    // Read-only, and one read of one file: the size, the palette and the
    // child environment the command's `$HOME` resolves against all have to
    // come from the same config, or the window is drawn at one config's size
    // in another config's colours.
    let config = crate::config::display_config();
    let elevation = platform();

    // Said before the window opens, not in it. The window is a picture of
    // what hatch draws and must not grow a caption; the person running the
    // command is the one who needs to know that this machine would have
    // refused the request they are looking at.
    if scenario == Scenario::Root
        && let Err(unavailable) = elevation.available(&build_child_env(&config))
    {
        eprintln!(
            "hatch preview: {unavailable}\n\
             The window below is the line hatch composes for a root command, drawn by the code \
             that draws the real one. On this machine hatch would have refused the request \
             instead of opening it."
        );
    }

    let sample = build(scenario, &config, elevation.as_ref(), &staging_dir())?;

    // Before a window is opened rather than after it has been drawn. A
    // screenshot that fails on the write is a window somebody watched appear
    // and disappear for nothing, and the commonest way for it to fail is a
    // directory that is not there.
    if let Some(dir) = shot.as_deref().and_then(Path::parent).filter(|d| !d.as_os_str().is_empty())
    {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }

    let failure: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
    let captured: Arc<OnceLock<PathBuf>> = Arc::new(OnceLock::new());
    let (font_size, theme) = (config.font_size_points(), palette(config.theme, theme));

    let app_failure = Arc::clone(&failure);
    let app_captured = Arc::clone(&captured);
    let timeout_secs = config.timeout_secs;
    let wanted = shot.clone();
    crate::prompt_ui::open_window(
        // The one thing a preview says differently, and deliberately the one
        // thing outside the picture: a window that says "approval" in the
        // taskbar while nobody has asked for anything is a window that can be
        // mistaken for a request.
        "hatch — preview",
        font_size,
        theme,
        Box::new(move |_cc| {
            let (to_window, inbox) = std::sync::mpsc::channel();
            let (nobody, _swallowed) = Nobody::new();
            Box::new(PreviewApp {
                inner: PromptApp::new(
                    inbox,
                    Box::new(nobody),
                    // A preview's window has no fatal state of its own to
                    // report: the channel it would report about is this
                    // process's own channel to itself.
                    Arc::new(OnceLock::new()),
                    // Read, so the sample is drawn with the preference a real
                    // request would be drawn with; never written, because a
                    // documentation tool that changed somebody's settings
                    // would be a surprising thing for a screenshot to do.
                    crate::prefs::PrefsFile::from_env().read_only(),
                ),
                pending: Some(sample),
                to_window,
                timeout_secs,
                shot: shot
                    .map(|path| Shot { path, settled: 0, settling_since: None, asked: false }),
                opened_at: Instant::now(),
                failure: Arc::clone(&app_failure),
                captured: Arc::clone(&app_captured),
            })
        }),
    )?;

    if let Some(why) = failure.get() {
        anyhow::bail!("{why}");
    }
    match (wanted, captured.get()) {
        // The one ending that must not be quiet: a window that opened, closed
        // and wrote no file. A documentation tool reporting success for an
        // image it did not write is how a README comes to show last month's
        // window.
        (Some(path), None) => anyhow::bail!(
            "the preview window closed before it was photographed, so {} was not written",
            path.display()
        ),
        (Some(_), Some(path)) => println!("{}", path.display()),
        (None, _) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::prompt_ui::guard::Action;
    use crate::prompt_ui::panes::{Shown, countdown_text};
    use crate::protocol::{PromptMsg, every_verdict};

    /// A config that does not depend on the machine the test runs on.
    fn a_config() -> Config {
        let mut config = Config::default();
        config.exec_env.insert("HOME".to_string(), "/home/someone".to_string());
        config
    }

    /// A preview's window, wired exactly as [`run`] wires one: the sample in
    /// its inbox and [`Nobody`] as the only thing it can answer to.
    ///
    /// Built by this helper rather than by each test, so that no test can
    /// accidentally prove something about a window a preview would never
    /// open.
    fn a_preview_window(scenario: Scenario) -> (PromptApp, Arc<AtomicUsize>, tempfile::TempDir) {
        let staging = tempfile::tempdir().expect("a staging directory");
        let sample = build(scenario, &a_config(), platform().as_ref(), staging.path())
            .expect("the sample builds");
        let (to_window, inbox) = std::sync::mpsc::channel();
        let (nobody, swallowed) = Nobody::new();
        to_window
            .send(Incoming::Frame(DaemonMsg::Request(Box::new(sample.request(600, 0)))))
            .expect("the window has its request");
        // Dropped on purpose: a preview writes one request and nothing else,
        // and a window whose channel has ended is a window the daemon has
        // gone from, which is the truth here.
        drop(to_window);
        let mut app = PromptApp::new(
            inbox,
            Box::new(nobody),
            Arc::new(OnceLock::new()),
            crate::prefs::PrefsFile::none(),
        );
        app.take_arrivals();
        (app, swallowed, staging)
    }

    #[test]
    fn every_scenario_builds_a_request_this_window_can_draw() {
        // The check `PromptState::handle` makes when a request arrives: a
        // payload whose spans do not tile their source, or whose one-line
        // form disagrees with them, closes the window instead of being drawn.
        // A scenario that failed it would open a window saying "waiting for
        // hatch" and nothing else, which is the one failure a screenshot tool
        // must not have.
        let staging = tempfile::tempdir().unwrap();
        for scenario in Scenario::all() {
            let sample = build(scenario, &a_config(), platform().as_ref(), staging.path())
                .unwrap_or_else(|e| panic!("{scenario:?}: {e:#}"));
            Shown::of(&sample.payload)
                .unwrap_or_else(|e| panic!("{scenario:?} cannot be drawn: {e}"));
        }
    }

    #[test]
    fn the_heredoc_sample_reads_its_body_as_data_and_the_lines_around_it_as_shell() {
        // The point of that scenario, and the regression it exists to hold
        // down. Every shape in the body has a live twin within two rows of it,
        // and the roster is the loudest half: it used to name `server`,
        // `location`, `}` and `NGINXCONF` as programs nothing on the `PATH`
        // answers to, on a command that writes a config file and reloads a
        // service.
        let staging = tempfile::tempdir().expect("a staging directory");
        let sample = build(Scenario::Heredoc, &a_config(), platform().as_ref(), staging.path())
            .expect("the heredoc sample builds");
        let Payload::Command { runs, .. } = &sample.payload else {
            panic!("the heredoc sample is a command");
        };
        let rendering = sample.payload.rendering().expect("the sample is a drawable command");

        let named: Vec<&str> = runs.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(named, vec!["cat", "nginx", "systemctl"], "the body names nothing");

        let of_kind = |kind: &crate::render::SpanKind| -> Vec<&str> {
            rendering.iter().filter(|span| span.kind() == kind).map(|s| s.text()).collect()
        };
        assert_eq!(
            of_kind(&crate::render::SpanKind::Separator),
            vec!["&&"],
            "the only boundary is the one on the last line"
        );
        assert!(
            of_kind(&crate::render::SpanKind::Comment).is_empty(),
            "the `#` in the body is data"
        );
        // One `$HOME` resolved and one left alone, which is the pair the
        // sample is built around: the delimiter is quoted, so the shell
        // substitutes nothing in the body.
        let values: Vec<Option<String>> = rendering
            .iter()
            .filter_map(|span| span.variable().map(|(_, value)| value.map(str::to_string)))
            .collect();
        assert_eq!(values.len(), 1, "only the reference on the operator's line expands");
        assert!(values[0].is_some(), "and it is shown with the value the command will get");
    }

    #[test]
    fn the_redirect_sample_puts_the_two_pipes_on_screen_together() {
        // The point of that scenario. A `>|` that is one operator and a `|`
        // that is a segment boundary, both drawn, three rows apart -- a
        // sample missing either of them would demonstrate nothing, and would
        // go on looking like a perfectly good sample while doing so. The
        // descriptor form and a destination are asserted beside them, because
        // the destination is the half of a redirection a reader is scanning
        // for.
        let staging = tempfile::tempdir().unwrap();
        let sample = build(Scenario::Redirect, &a_config(), platform().as_ref(), staging.path())
            .expect("the redirect sample builds");
        let rendering = sample.payload.rendering().expect("the sample is a drawable command");
        let of_kind = |kind: &crate::render::SpanKind| -> Vec<&str> {
            rendering.iter().filter(|span| span.kind() == kind).map(|s| s.text()).collect()
        };

        assert_eq!(
            of_kind(&crate::render::SpanKind::Separator),
            vec!["|"],
            "the sample has one boundary in it, and it is not the `|` inside the `>|`"
        );
        let redirects = of_kind(&crate::render::SpanKind::Redirect);
        for wanted in [">|", "2>&", "2>>", "build.log"] {
            assert!(redirects.contains(&wanted), "{wanted:?} is not marked: {redirects:?}");
        }
        assert!(
            of_kind(&crate::render::SpanKind::Quoted).contains(&"' > '"),
            "the arrow inside the quotes was read as a redirection"
        );
    }

    #[test]
    fn the_long_sample_really_is_longer_and_wider_than_a_pane() {
        // The point of the scenario. A sample that fitted its panes would
        // exercise none of what it is there for -- the stacked arrangement,
        // a strip with text off to the right of it, and the line that says
        // how many rows are out of sight -- and it would go on looking like
        // a perfectly good sample while doing so.
        let staging = tempfile::tempdir().unwrap();
        let sample = build(Scenario::Long, &a_config(), platform().as_ref(), staging.path())
            .expect("the long sample builds");
        let Shown::Command { longest, .. } = Shown::of(&sample.payload).expect("drawable") else {
            panic!("the long sample is not a command")
        };
        // Wider than any full-width pane a 1280-point window has: a column of
        // that window holds about sixty characters and the whole of it about
        // a hundred and thirty.
        assert!(longest >= 200, "the longest line is {longest} characters, which a pane holds");
        // And taller than the panes of a window of any ordinary height.
        let rows = LONG_COMMAND.lines().count();
        assert!(rows >= 25, "the sample is {rows} rows, which a 700-point window shows");
    }

    #[test]
    fn the_root_sample_is_the_root_window_and_names_the_mechanism() {
        // That the root scenario really is elevated -- the flag the `ROOT`
        // block and the danger frame are read off -- and that the line is the
        // elevation program's rather than a bare command with a word in front
        // of it. What makes it the *same* line the daemon builds is the
        // agreement test in `crate::server`; this is the half that says the
        // scenario is about root at all.
        let staging = tempfile::tempdir().unwrap();
        let sample = build(Scenario::Root, &a_config(), platform().as_ref(), staging.path())
            .expect("a root sample is composable without run0 being installed");
        let Payload::Command { root, display_line, caveat, .. } = &sample.payload else {
            panic!("the root scenario is not a command");
        };
        assert!(*root, "the window would draw it as an ordinary command");
        assert!(
            display_line.starts_with(platform().mechanism()),
            "the elevated line does not start with the elevation program: {display_line}"
        );
        assert!(caveat.is_some(), "the window has nothing to say about how a root run differs");
    }

    #[test]
    fn approving_a_preview_reaches_nobody() {
        // Pressing Approve, through the door every approval goes through:
        // the guard hands back `Action::Approve` and the window turns it into
        // one frame on its `out`. In a preview that `out` is `Nobody`, so the
        // frame is produced -- the window really did decide -- and then
        // swallowed by this process. There is no daemon to read it, and there
        // is no other kind of `out` this module ever constructs.
        let (mut app, swallowed, _staging) = a_preview_window(Scenario::Command);
        assert_eq!(app.state().phase(), Phase::AwaitingVerdict, "the sample never arrived");

        app.act(&egui::Context::default(), Action::Approve);

        assert_eq!(
            app.state().phase(),
            Phase::Running,
            "the window did not decide, so this test proves nothing about where a decision goes"
        );
        assert!(swallowed.load(Ordering::SeqCst) > 0, "no frame was produced to lose");
        assert_eq!(app.state().broken(), None, "a preview's channel is not broken, it is absent");
    }

    #[test]
    fn every_verdict_a_preview_can_produce_reaches_nobody() {
        // Approve is the one that would run something, and it is covered
        // above through the real button path. This is the rest of the set,
        // driven through the state machine: a verdict a preview can produce
        // that this test does not know about is a verdict nobody has checked
        // the destination of.
        let staging = tempfile::tempdir().unwrap();
        let sample = build(Scenario::Command, &a_config(), platform().as_ref(), staging.path())
            .unwrap();
        for verdict in every_verdict() {
            let (mut nobody, swallowed) = Nobody::new();
            let mut state = crate::prompt_ui::PromptState::new();
            state.handle(DaemonMsg::Request(Box::new(sample.request(600, 0))));
            let frame = state.decide(verdict.clone());
            assert!(matches!(frame, Some(PromptMsg::Verdict(_))), "{verdict:?} produced nothing");
            crate::prompt_ui::answer(&mut nobody, &mut state, frame);
            assert!(swallowed.load(Ordering::SeqCst) > 0, "{verdict:?} was never written");
            assert_eq!(state.broken(), None, "{verdict:?} looked like a broken channel");
        }
    }

    #[test]
    fn a_decided_preview_is_no_longer_a_window() {
        // What `PreviewApp::logic` closes on. The real window stays open
        // after an approval because a daemon is starting a command and will
        // stream it back; a preview has nobody doing that, so a window that
        // stayed would be showing a run that does not exist.
        let (mut app, _swallowed, _staging) = a_preview_window(Scenario::Command);
        assert!(
            matches!(app.state().phase(), Phase::WaitingForRequest | Phase::AwaitingVerdict),
            "a preview that has not been decided must stay open to be looked at"
        );

        app.act(&egui::Context::default(), Action::Deny);

        assert!(
            !matches!(app.state().phase(), Phase::WaitingForRequest | Phase::AwaitingVerdict),
            "the preview would sit there with a question nobody can answer"
        );
    }

    #[test]
    fn a_shot_stamps_a_deadline_that_reads_as_a_round_number() {
        // Why `SHOT_SLACK` is a second and not nothing. The countdown is
        // `deadline - now` truncated to whole seconds, so a deadline exactly
        // `timeout_secs` away reads one second short the instant any time
        // passes and two runs of the same command differ. A second ahead
        // holds the drawn figure at the configured timeout for the whole of
        // the first second after the stamp, which is far longer than the
        // frames between the stamp and the photograph take.
        let staging = tempfile::tempdir().unwrap();
        let sample =
            build(Scenario::Command, &a_config(), platform().as_ref(), staging.path()).unwrap();
        let request = sample.request(600, SHOT_SLACK);
        for after_ms in [0, 1, 250, 500, 999] {
            let at = Utc::now() + chrono::Duration::milliseconds(after_ms);
            let left = (request.deadline - at).num_seconds();
            assert_eq!(
                countdown_text(left),
                "10 min left to decide",
                "{after_ms} ms after the stamp the countdown reads something else"
            );
        }
        // And without the slack it does not, which is what makes the constant
        // load-bearing rather than decorative.
        let unstamped = sample.request(600, 0);
        assert_ne!(
            countdown_text((unstamped.deadline - (Utc::now() + chrono::Duration::milliseconds(1)))
                .num_seconds()),
            "10 min left to decide",
        );
    }

    #[test]
    fn a_theme_asked_for_on_the_command_line_wins_for_this_run_only() {
        assert_eq!(palette(Theme::Dark, None), Theme::Dark, "the config is what is previewed");
        assert_eq!(palette(Theme::Light, None), Theme::Light);
        assert_eq!(palette(Theme::Dark, Some(Theme::Light)), Theme::Light);
        assert_eq!(palette(Theme::Light, Some(Theme::Dark)), Theme::Dark);
    }

    #[test]
    fn previewing_reads_the_config_and_does_not_touch_it() {
        // `--theme` overrides the palette for one window. The file it
        // overrides must be exactly as it was afterwards: a preview that
        // wrote the palette back would be a display tool quietly editing the
        // settings it exists to show.
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::scratch(dir.path());
        std::fs::create_dir_all(paths.config_dir()).unwrap();
        let file = paths.config_file();
        let written = "font_size = 21\ntheme = \"dark\"\n";
        std::fs::write(&file, written).unwrap();

        let config = crate::config::display_config_at(&paths);
        assert_eq!(config.font_size_points(), 21.0, "the preview did not read the config at all");
        assert_eq!(palette(config.theme, Some(Theme::Light)), Theme::Light);

        assert_eq!(std::fs::read_to_string(&file).unwrap(), written, "the config was rewritten");
    }

    #[test]
    fn a_sample_writes_only_inside_the_directory_it_was_given() {
        // The swap scenario is the one thing here that touches the
        // filesystem, because `swap::plan` stats the target and a
        // replacement with no file behind it is a create. Everything it
        // writes is its own, under the directory it was handed.
        let staging = tempfile::tempdir().unwrap();
        let path = stage_sample_file(staging.path()).unwrap();
        assert!(path.starts_with(staging.path()), "{} escaped the staging directory", path.display());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), SWAP_BEFORE);

        // And it is stable: the mode and the size are on screen in the
        // metadata panel, so a second run must not produce a second picture.
        let again = stage_sample_file(staging.path()).unwrap();
        assert_eq!(again, path);
        assert_eq!(std::fs::read_to_string(&again).unwrap(), SWAP_BEFORE);
    }

    #[test]
    fn the_swap_sample_replaces_a_file_rather_than_creating_one() {
        // What the metadata panel in the README's image is of. A create has
        // no mode to inherit, no owner to keep and no earlier hash, so a
        // sample that quietly became one would leave that panel saying
        // nothing while still looking like a screenshot of it.
        use crate::swap::PlanKind;
        let staging = tempfile::tempdir().unwrap();
        let sample = build(Scenario::Swap, &a_config(), platform().as_ref(), staging.path())
            .unwrap();
        let Payload::Swap { plan, rows, .. } = &sample.payload else {
            panic!("the swap scenario is not a swap");
        };
        assert_eq!(plan.kind, PlanKind::Replace);
        assert_eq!(plan.landing_mode, 0o644, "the mode in the panel is whatever the umask gave");
        assert_eq!(plan.size_delta, 1, "the panel's size line stopped saying `1 byte larger`");
        assert!(!rows.is_empty(), "there is no diff to draw");
    }
}

