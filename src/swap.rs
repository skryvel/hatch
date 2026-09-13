//! `swap_file`: everything decided before a human is asked anything, and
//! everything decided again before a byte is written.
//!
//! [`validate`] is the set of refusals, and every one of them happens *before*
//! a prompt exists. That placement is the point. Prompting for a request that
//! will be refused anyway spends the user's attention, which is the scarcest
//! resource in this design, and worse, it teaches the reader that refusals are
//! routine — the habit that gets the one refusal that mattered clicked
//! through. A refusal here reaches the agent as a tool error and the audit log
//! as `refused`, and nothing appears on screen.
//!
//! [`plan`] is the other half: given a target that survived validation, what
//! the window has to state about where the bytes will land. It decides
//! nothing about the *content* — that is [`crate::render::diff`] — only about
//! the file: create or replace, at what mode, owned by whom, over what.
//!
//! [`apply`] is what happens after a human says yes: the same checks again,
//! because everything the other two established was established before a
//! person spent time reading, and then one `rename` that either happened or
//! did not.
//!
//! # The order of the checks, and what each one buys
//!
//! 1. **Absolute.** Everything after it is meaningless otherwise. A relative
//!    path would be resolved against *hatch's* working directory, which is not
//!    the agent's and is not anything the user chose, so the file the daemon
//!    would stat is not the file the agent named. It also fails
//!    [`Denylist::is_denied`]'s precondition.
//! 2. **No `..` component.** Refused rather than resolved, for the reason
//!    [`crate::denylist`] gives: with a symlink anywhere in the path, `a/b/..`
//!    is not `a`, so resolving it lexically is wrong in exactly the case that
//!    matters. The denylist would also refuse it, but as
//!    [`Refusal::Denied`] — "this path is protected" — which for
//!    `/etc/../etc/hosts` is simply untrue. The check is here so the message
//!    is honest.
//! 3. **Denylist**, on the spelling supplied, before the filesystem is touched
//!    at all. See below.
//! 4. **The target's own metadata**, via `symlink_metadata`, which does *not*
//!    follow the final component.
//! 5. **The parent**, via `metadata`, which does.
//! 6. **Denylist again**, on the resolved spelling. See below.
//!
//! Steps 1 and 2 are pure and can be reordered with each other harmlessly (a
//! relative path with a `..` in it is refused either way, only the wording
//! differs). Steps 4 and 5 commute in outcome — a target that is a symlink
//! necessarily has a parent directory, so the two can never both fire — but
//! they are written in this order because 4 is the security check and 5 is the
//! usability one. **Steps 3 and 4 do not commute, and that is deliberate.**
//!
//! # Why the denylist runs before the filesystem
//!
//! Validation is an existence oracle. A [`Refusal::MissingParent`] tells the
//! agent that a directory it named does not exist; an `Ok` followed by a plan
//! tells it a file does. That is accepted: hatch's guarantee is that nothing
//! *happens* without approval, not that the agent learns nothing, and an agent
//! that wants to know whether a path exists can ask for `ls` and be told yes
//! or no by a human.
//!
//! What is not accepted is that oracle reaching the protected set. If the stat
//! ran first, the two refusals would differ — "protected" for
//! `~/.config/hatch/config.toml`, "no such directory" for
//! `~/.config/hatch/nope/x` — and
//! `swap_file` would become a way to map hatch's own state, the user's
//! sandbox profiles and every `denylist_extra` entry without a single prompt.
//! Consulting the denylist first collapses all of that to one answer that
//! depends on nothing but the path. The cheap syscall-free check is also the
//! one that fails closed, which is the right order for a second reason.
//!
//! # Symlinks: the link is refused, never followed
//!
//! `symlink_metadata` rather than `metadata` is the single most load-bearing
//! line in this module. `metadata` follows the link, so it would report the
//! *target's* type, mode and owner while the write went through the link to
//! somewhere else entirely: a plan that says "replace this 0644 file you own"
//! while the bytes land on whatever the link points at. A dangling link is
//! worse still — `metadata` fails with `NotFound`, which reads as "a new
//! file", and the apply would then create the target the link names.
//!
//! So a symlinked target is refused outright, and the refusal names what the
//! link says. See [`Refusal::Symlink`] for why naming it is the right trade.
//!
//! The *parent* is a different question and gets the opposite answer: step 5
//! follows it, because a symlinked directory is an ordinary thing to write
//! into and refusing it would break honest requests for no gain. That is what
//! step 6 is for. The lexical denylist judges the spelling the agent supplied,
//! and a symlinked ancestor makes that spelling and the file two different
//! things — `/tmp/x/config.toml` where `/tmp/x` points at `~/.config/hatch` is
//! not
//! lexically protected, but it is the same file. Once the parent is known to
//! exist it can be canonicalised, and the protected set is asked again about
//! the resolved spelling. Step 3 alone would leave the denylist bypassable by
//! anyone able to leave a symlink lying around; step 6 alone would give the
//! oracle above. Both are needed, and they share one variant so the answer
//! looks the same from outside.
//!
//! # What is not checked here
//!
//! Whether the write will succeed. Directory permissions, immutable
//! attributes, a full disk and a read-only mount are all discovered at apply
//! time, and a prompt that promised otherwise would be lying. Validation
//! refuses what is *knowably* wrong, not everything that could fail.
//!
//! # Applying: everything is re-checked, and one window stays open
//!
//! [`apply`] runs after a human has said yes, and the gap between the plan the
//! human read and the write it authorises is a human-sized one: seconds while
//! they read the diff, minutes if they went to look something up. Everything
//! [`validate`] and [`plan`] established was established at the start of that
//! gap. So none of it is trusted, and [`apply`] establishes all of it again,
//! in this order:
//!
//! 1. **[`validate`] in full**, not the hash alone. This is what re-closes the
//!    symlinked-ancestor bypass: `/tmp/x/config.toml` where `/tmp/x` became a
//!    link to `~/.config/hatch` while the prompt was up is a *different file*
//!    under
//!    the same name, and a content hash cannot see that, because the hash only
//!    ever describes whichever file the name currently means — which for a
//!    create is quite legitimately no file at all. It also re-closes the
//!    target itself becoming a symlink, the parent being replaced by a file,
//!    and the parent being removed.
//! 2. **The content hash**, compared as [`Option`] against
//!    [`SwapPlan::hash_before`]. Step 1 defends the path; this defends the
//!    human's decision. They approved a diff against particular bytes, and if
//!    those bytes moved — edited, replaced, deleted, or created where nothing
//!    was — the diff they read is not the change this would make. Comparing
//!    the options rather than the strings is what makes "a file appeared under
//!    an approved create" visible; see [`SwapPlan::hash_before`].
//! 3. **The staged file's own mode, uid and gid**, by `fstat` on the
//!    descriptor, against what the window said. See "What a rename does not
//!    preserve" below.
//! 4. **`RENAME_NOREPLACE` for a create**, which is the kernel making check 2
//!    again, atomically, for the microseconds after hatch made it.
//!
//! Nothing is created on disk until all of 1 and 2 have passed, which is why a
//! refusal leaves the directory byte-for-byte as it was rather than a
//! half-written neighbour to explain.
//!
//! ## The residual
//!
//! Between the last syscall of step 1 and the `rename` of step 4 there is a
//! window of microseconds, and it is not closed. An attacker who already has
//! write access to a *directory* in the path can, in that window, replace that
//! directory with a symbolic link, and the rename will resolve the new one and
//! land the file somewhere hatch did not check.
//!
//! Two things bound it. The first is that it is microseconds rather than
//! minutes: re-running the checks does not close the window, it collapses it
//! from human time to syscall time, which is the whole reason step 1 exists.
//! The second is that `rename(2)` never follows a symbolic link in its *final*
//! component — it replaces the link itself — so the final component being
//! swapped, which is the easy half of the attack, cannot redirect the bytes
//! anywhere; the worst it achieves is that the approved content lands under
//! the approved name and a link is gone.
//!
//! Closing the directory half properly means never naming the parent twice:
//! opening it once with `O_DIRECTORY` during validation and using `openat` and
//! `renameat` against that descriptor thereafter, so that the write goes to an
//! inode rather than to a path that can be re-pointed. That is a worthwhile
//! change and it is not made here, because it means abandoning
//! [`tempfile::NamedTempFile`]'s staging and writing the `openat`/`linkat`
//! dance by hand, which is a larger and more dangerous piece of code than the
//! one it protects. It is recorded as the way in, not waved away.
//!
//! ## What a rename does not preserve
//!
//! A swap is not an edit. `rename` replaces the target's directory entry with
//! *this process's* file, and that file has this process's uid and gid — so a
//! replacement of a file belonging to somebody else, in a directory hatch can
//! write to, silently transfers the file to whoever hatch runs as. The window
//! said `owner: www-data`; the file would come out owned by the user.
//!
//! So step 3 `fstat`s the staged descriptor and refuses
//! ([`ApplyError::NotAsApproved`]) unless its mode, uid and gid are the ones
//! the window stated. The same check catches the kernel silently dropping a
//! setgid bit from an `fchmod` by a user who is not in the file's group. A
//! request that genuinely has to keep another owner is a root request, and
//! root requests are `install`'s, not this function's.
//!
//! The mirror of that check lives in `created_group`: a directory with the
//! setgid bit gives its own group to files created inside it, so the plan has
//! to say so, or step 3 would refuse every create in `/srv` and every shared
//! project tree forever.
//!
//! # The root path is a different write, and says so
//!
//! Everything above describes [`apply`], which writes as whoever runs hatch.
//! A `root: true` request cannot use it — the landing check in step 3 refuses
//! any plan whose owner this process cannot produce, which is every plan that
//! needed root in the first place — so it goes through [`stage_root`]
//! instead: the same two re-checks, then the approved bytes written to
//! [`crate::paths::Paths::stage_dir`], then an `install` argv for the caller
//! to elevate.
//!
//! The two paths differ in three ways that are properties of `install` rather
//! than choices made here, and all three are written out at [`stage_root`]
//! rather than left to be discovered:
//!
//! * The gap between the last check and the write is human-sized, not
//!   microseconds, because the password dialog sits inside it.
//! * `install` truncates its destination; it is not a `rename`, so an
//!   interrupted root write can leave the target short.
//! * `install` follows a symbolic link at the destination, where `rename`
//!   replaces it.
//!
//! ## Durability
//!
//! The staged file is `fsync`ed before the rename. The directory is not
//! `fsync`ed after it.
//!
//! The asymmetry is deliberate and it is about which crash costs the user
//! something. Without the first, a machine that loses power just after the
//! rename can come back with the directory entry pointing at a file whose data
//! never reached the disk: the old contents gone and the new contents not
//! there either, which is the one outcome that is worse than both of the
//! honest ones. It costs one flush of bytes a human is already waiting on, in
//! a workflow gated on a human clicking a button, so it is bought without
//! hesitation.
//!
//! Without the second, the same crash can lose the rename itself, and the user
//! comes back to the old file with the change simply not applied — safe, and
//! recoverable by asking again. What it costs instead is honesty: `fsync` on
//! the directory can only be issued *after* the rename has already happened,
//! so a failure there would have to be reported as a failure of a write that
//! in fact succeeded, or swallowed silently. Neither is worth having in
//! exchange for turning one safe outcome into another safe outcome. The
//! accepted residual is that hatch's audit log can record `applied` for a swap
//! a crash then loses; a caller that needs more than that can `fsync` the
//! directory itself.

use std::fmt;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, bail};
use nix::unistd::{Gid, Group, Uid, User, getegid, geteuid};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use sha2::{Digest, Sha256};

use crate::denylist::Denylist;

/// The mode a newly created file lands at.
///
/// Not the process umask: the umask describes what *this* process happens to
/// be running under, and the window states a mode the user reads and approves.
/// A number that changes with how the daemon was started would make the same
/// request land differently on two machines.
const CREATE_MODE: u32 = 0o644;

/// Bytes read at a time when hashing the existing file.
///
/// The target is whatever is on disk and may be enormous, so it is streamed
/// rather than read whole; the plan needs one hash, not a copy.
const HASH_CHUNK: usize = 64 * 1024;

/// Why `swap_file` will not proceed, decided before any prompt is drawn.
///
/// Every variant is a user-facing message as much as a control-flow value: it
/// is returned to the agent as the tool error, and recorded in the audit log
/// as a `refused` outcome. The [`fmt::Display`] text is the message, and it
/// states the reason only — the caller has the requested path and prefixes it.
///
/// A variant carries a path only when it is one the caller does *not* already
/// have: what a link points at, or which ancestor is missing. Echoing the
/// requested path back into the payload would discover nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The path is relative, and so names a different file depending on who
    /// resolves it.
    NotAbsolute,
    /// The path contains a `..` component. Refused rather than resolved: with
    /// a symlink in the path, resolving it lexically gives the wrong file.
    DotDot,
    /// The path is protected: hatch's own state, the sandbox profiles, the MCP
    /// client configuration, the binary, or a `denylist_extra` entry.
    ///
    /// Deliberately says nothing about whether the file exists. The protected
    /// set is exactly the set that must not be mappable by an agent probing
    /// with requests it never intends a human to see.
    Denied,
    /// The path is a symbolic link. The link is refused; it is never followed.
    ///
    /// `target` is the link's own text, verbatim — relative if that is what it
    /// says, and named even when it dangles, because a dangling link has
    /// nothing to canonicalise and is exactly the case a reader most needs
    /// told.
    ///
    /// **Naming it is a deliberate disclosure.** The agent may have no other
    /// way to read that path: it is sandboxed, and `readlink` on the host is
    /// itself a request a human would have to approve. Three things make the
    /// trade come out in favour of naming it. The refusal is only actionable
    /// with the name — "ask again for the target itself" is not advice you can
    /// take without knowing the target. What leaks is one string, for a path
    /// the agent had to name exactly to get here; it is not an enumeration and
    /// it says nothing about the target's contents, mode, or existence. And
    /// the protected set never reaches this check, because the denylist runs
    /// first, so the one region worth hiding is not what gets disclosed.
    ///
    /// The argument the other way is real: an injected agent can probe for
    /// symlinks and read the host's layout out of the error text. It loses on
    /// weight, not on principle — the same agent can ask a human to approve
    /// `readlink -f`, and refusing to say why a request failed would push
    /// every honest agent toward exactly that.
    Symlink {
        /// What the link says it points at.
        target: PathBuf,
    },
    /// The path exists but is not a regular file — a directory, a device node,
    /// a socket, a fifo. `swap_file` replaces the contents of a file; a rename
    /// over any of these either fails after the user has already answered, or,
    /// for a device node, succeeds and destroys it.
    NotARegularFile {
        /// What it is instead, as it appears in the message.
        what: &'static str,
    },
    /// The parent directory does not exist. `swap_file` never creates
    /// directories: choosing a mode and an owner for an implied directory is a
    /// decision the user should see, and `run_command("mkdir -p …")` shows it.
    MissingParent {
        /// The directory that is missing — the target's immediate parent, not
        /// the highest missing ancestor.
        parent: PathBuf,
    },
    /// The parent exists but is not a directory, so nothing can be written
    /// inside it.
    ParentNotADirectory {
        /// The path that is in the way.
        parent: PathBuf,
    },
    /// The target or its parent could not be examined for a reason other than
    /// absence — a permission denied, a symlink loop, an I/O error.
    ///
    /// Distinct from [`Refusal::MissingParent`] on purpose: reporting "no such
    /// directory" for a directory that exists but cannot be read would send a
    /// caller off to create something that is already there.
    Unreadable {
        /// Which path could not be examined; it may be the parent rather than
        /// the target.
        path: PathBuf,
        /// The operating system's reason, as text.
        error: String,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NotAbsolute => f.write_str(
                "the path must be absolute: a relative path would be resolved against hatch's \
                 working directory, which is not the one the request was written against",
            ),
            Refusal::DotDot => f.write_str(
                "the path must not contain a `..` component: with a symlink anywhere in it, `..` \
                 does not mean the directory above, so hatch refuses it rather than guessing",
            ),
            Refusal::Denied => f.write_str(
                "hatch protects this path and will not write to it",
            ),
            Refusal::Symlink { target } => write!(
                f,
                "the path is a symbolic link to {}: hatch never writes through a symlink; ask \
                 again for the target itself if that is what was meant",
                target.display()
            ),
            Refusal::NotARegularFile { what } => write!(
                f,
                "the path is {what}: a file write replaces the contents of a regular file"
            ),
            Refusal::MissingParent { parent } => write!(
                f,
                "the directory {} does not exist, and a file write never creates directories",
                parent.display()
            ),
            Refusal::ParentNotADirectory { parent } => {
                write!(f, "{} is not a directory, so nothing can be written inside it", parent.display())
            }
            Refusal::Unreadable { path, error } => {
                write!(f, "{} could not be examined: {error}", path.display())
            }
        }
    }
}

impl std::error::Error for Refusal {}

/// Refuse everything that is knowably wrong about `path`, before a prompt is
/// drawn for it.
///
/// The checks and their order are the module documentation's; the short
/// version is absolute, no `..`, not protected, not a symlink, parent is a
/// real directory, still not protected once resolved.
///
/// `Ok(())` means a prompt may be drawn, not that the write will succeed.
pub fn validate(path: &Path, deny: &Denylist) -> Result<(), Refusal> {
    if !path.is_absolute() {
        return Err(Refusal::NotAbsolute);
    }
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(Refusal::DotDot);
    }
    if deny.is_denied(path) {
        return Err(Refusal::Denied);
    }

    // The final component is never followed. See the module docs: `metadata`
    // here would describe one file while the write went to another.
    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => {
            let target = fs::read_link(path).map_err(|e| Refusal::Unreadable {
                path: path.to_path_buf(),
                error: e.to_string(),
            })?;
            return Err(Refusal::Symlink { target });
        }
        Ok(md) if !md.is_file() => {
            return Err(Refusal::NotARegularFile { what: describe(&md) });
        }
        // An existing regular file, or nothing there yet: both are ordinary,
        // and both still have to answer for their parent below.
        Ok(_) => {}
        Err(e) if is_absent(&e) => {}
        Err(e) => {
            return Err(Refusal::Unreadable {
                path: path.to_path_buf(),
                error: e.to_string(),
            });
        }
    }

    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        // Only `/` has neither, and `/` is a directory that always exists, so
        // the arm above has already refused it. Fail closed rather than reason
        // about a case that cannot arrive.
        return Err(Refusal::MissingParent { parent: path.to_path_buf() });
    };

    // The parent *is* followed: a symlinked directory is an ordinary place to
    // write, and refusing it would cost honest requests for nothing.
    if let Some(refusal) = parent_refusal(parent, fs::metadata(parent)) {
        return Err(refusal);
    }

    // Because the parent was followed, the spelling judged above and the file
    // about to be written are not necessarily the same place. Ask the
    // protected set again about the resolved one.
    let resolved = fs::canonicalize(parent).map_err(|e| Refusal::Unreadable {
        path: parent.to_path_buf(),
        error: e.to_string(),
    })?;
    if deny.is_denied(&resolved.join(name)) {
        return Err(Refusal::Denied);
    }

    Ok(())
}

/// What the parent's stat says about whether anything may be written inside
/// it: `None` to carry on.
///
/// Split out from [`validate`] rather than inlined so that its last arm can be
/// tested. Reaching that arm for real needs the parent to stop being
/// examinable *between* the target's stat and this one — a race, since a
/// parent that could not be searched would already have failed the target's
/// stat — and a branch that cannot be reached from outside is a branch nothing
/// pins. Taking the `Result` as an argument makes it reachable from a test
/// without inventing a filesystem that misbehaves on demand.
fn parent_refusal(parent: &Path, stat: std::io::Result<fs::Metadata>) -> Option<Refusal> {
    match stat {
        Ok(md) if md.is_dir() => None,
        Ok(_) => Some(Refusal::ParentNotADirectory { parent: parent.to_path_buf() }),
        Err(e) if is_absent(&e) => Some(Refusal::MissingParent { parent: parent.to_path_buf() }),
        Err(e) => Some(Refusal::Unreadable {
            path: parent.to_path_buf(),
            error: e.to_string(),
        }),
    }
}

/// Whether an error means "there is nothing there", as opposed to "it could
/// not be looked at".
///
/// `NotADirectory` counts: `/etc/hosts/x` has nothing at it either, and the
/// kernel's way of saying so depends on which component is not a directory.
fn is_absent(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory)
}

/// What to call a target that is not a regular file, in a sentence beginning
/// "the path is".
fn describe(md: &fs::Metadata) -> &'static str {
    if md.is_dir() { "a directory" } else { "not a regular file" }
}

/// Whether the target exists already, which is the difference between a diff
/// against a file and a diff against nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanKind {
    /// Nothing is there; the file will be brought into existence.
    Create,
    /// A regular file is there; its entire contents will be replaced.
    Replace,
}

/// A user or a group, as both the kernel knows it and a human reads it.
///
/// Both halves are kept because they answer different questions and neither
/// substitutes for the other. The numeric id is the ground truth — it is what
/// the file actually carries, it cannot fail to be determined, and it is what
/// a comparison against the file after the write has to use. The name is a
/// lookup that may not resolve: a uid with no `passwd` entry is perfectly
/// legal on a system with a container-mapped or an LDAP-backed directory, and
/// a prompt that panicked or refused because a numeric owner had no name would
/// fail at the one moment it is meant to be informative.
///
/// So the name is an [`Option`], resolution failure is not an error, and
/// [`fmt::Display`] falls back to the number. That fallback is also what makes
/// the value usable as [`install_argv`]'s `-o` argument: `install` accepts
/// a name or a numeric id in the same position. The residual ambiguity — a
/// system with a *user literally named* `1000` whose uid is not 1000 — is
/// noted and accepted; `install` would resolve the name, which is the same
/// thing every other tool on the system does with that string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// The uid or gid itself.
    pub id: u32,
    /// The name it resolves to, if it resolves.
    pub name: Option<String>,
}

impl Principal {
    /// The user with this uid, named if `passwd` knows it.
    pub fn user(uid: u32) -> Self {
        let name = User::from_uid(Uid::from_raw(uid)).ok().flatten().map(|u| u.name);
        Self { id: uid, name }
    }

    /// The group with this gid, named if `group` knows it.
    pub fn group(gid: u32) -> Self {
        let name = Group::from_gid(Gid::from_raw(gid)).ok().flatten().map(|g| g.name);
        Self { id: gid, name }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(name) => f.write_str(name),
            None => write!(f, "{}", self.id),
        }
    }
}

/// Where the bytes will land, as the window states it and as the apply uses
/// it.
///
/// # Why this crosses the pipe as itself
///
/// Unlike a rendering, a plan carries no invariant that construction
/// enforces: every field is a fact about the target read off the filesystem,
/// and nothing about the *shape* of the value could be wrong in a way a
/// constructor would have caught. Deserialising one therefore gives up
/// nothing, and there is nothing for the window to re-derive.
///
/// It is also advisory. The window states the plan; [`apply`] re-stats and
/// re-hashes the target and refuses on drift, so the copy the prompt holds
/// never decides anything. It travels daemon-to-prompt only — no message in
/// the other direction carries a plan — so a prompt cannot hand a plan of its
/// own back to be applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapPlan {
    /// Create or replace.
    pub kind: PlanKind,
    /// The mode the file will be left at, all twelve bits.
    ///
    /// A replacement inherits, which includes setuid, setgid and the sticky
    /// bit: dropping them silently would break the file, and keeping them
    /// silently would be worse, so they are kept and the window must render
    /// the mode as four octal digits where a reader can see them.
    pub landing_mode: u32,
    /// The user the file will be owned by. A replacement inherits the current
    /// owner; a create is the running user, or `root` when `root` was asked
    /// for.
    pub landing_owner: Principal,
    /// The group the file will belong to, on the same rule.
    pub landing_group: Principal,
    /// Lowercase hex SHA-256 of the file as it is right now, or `None` when
    /// there is no file.
    ///
    /// `None` rather than the hash of no bytes, and the distinction is
    /// load-bearing for [`apply`]. The re-check before writing has to catch
    /// "the file appeared between the plan and the apply", and an empty file
    /// hashes to `e3b0c442…` — the same value a hash-of-nothing convention
    /// would store for absence. The two would then be indistinguishable, and a
    /// file created under the target's name after the user approved a *create*
    /// would be silently overwritten by a plan that never saw it, at a mode
    /// and owner chosen for a file that did not exist. With `Option`, absence
    /// compares equal only to absence.
    pub hash_before: Option<String>,
    /// How many bytes the file grows by, negative when it shrinks.
    pub size_delta: i64,
}

/// Work out where the proposed bytes would land.
///
/// `content` is what the agent proposes, and is measured but not stored: the
/// plan is about the file, not about the payload.
///
/// **Precondition: [`validate`] returned `Ok` for this path.** `plan` re-stats
/// rather than trusting a previous answer, and fails closed on a target that
/// is a symlink or is not a regular file — those are validation's refusals,
/// with validation's wording, and reaching them here means the caller skipped
/// a step. It is an error rather than a [`Refusal`] because it is a bug in
/// hatch, not a thing the agent asked for.
///
/// # On unbounded content
///
/// `content.len()` is used and nothing else; the payload is never copied here.
/// The cap on how much an agent may send belongs at the MCP boundary, and this
/// module agrees with the plan on that for a concrete reason: by the time
/// `plan` is called the bytes have already been received, deserialised and
/// allocated, so a limit enforced here would reject a request whose whole cost
/// was already paid. A limit is only a limit where the input arrives.
///
/// What this function does owe is not to add a second, larger cost of its own,
/// and that is why the *existing* file is streamed through a fixed buffer
/// instead of being read into memory to be hashed. A 4 GB target costs one
/// buffer here however large it is. The display cap —
/// [`crate::render::diff::render_content`]'s — is a third thing again, and
/// belongs to the window.
pub fn plan(path: &Path, content: &[u8], root: bool) -> anyhow::Result<SwapPlan> {
    let existing = match fs::symlink_metadata(path) {
        Ok(md) => Some(md),
        Err(e) if is_absent(&e) => None,
        Err(e) => {
            return Err(e).with_context(|| format!("examining {}", path.display()));
        }
    };

    match existing {
        Some(md) if md.file_type().is_symlink() => bail!(
            "{} is a symbolic link; a write to it must be refused in validation rather than \
             planned through it",
            path.display()
        ),
        Some(md) if !md.is_file() => bail!(
            "{} is {}; a write to it must be refused in validation rather than planned over it",
            path.display(),
            describe(&md)
        ),
        Some(md) => Ok(SwapPlan {
            kind: PlanKind::Replace,
            // Inherited, not recomputed: replacing a file's contents is not a
            // reason to change who may read it. `root` deliberately has no say
            // here — a root-elevated write to a file owned by someone else
            // leaves it owned by them.
            landing_mode: md.permissions().mode() & 0o7777,
            landing_owner: Principal::user(md.uid()),
            landing_group: Principal::group(md.gid()),
            hash_before: Some(
                hash_file(path).with_context(|| format!("reading {}", path.display()))?,
            ),
            size_delta: delta(content.len(), md.len()),
        }),
        None => {
            let (uid, gid) = if root {
                (0, 0)
            } else {
                // What the kernel will stamp on a file this process creates
                // here — which is not simply the effective ids, see
                // `created_group`.
                (geteuid().as_raw(), created_group(path))
            };
            Ok(SwapPlan {
                kind: PlanKind::Create,
                landing_mode: CREATE_MODE,
                landing_owner: Principal::user(uid),
                landing_group: Principal::group(gid),
                hash_before: None,
                size_delta: delta(content.len(), 0),
            })
        }
    }
}

/// How much larger `after` is than `before`, signed.
///
/// Widened to `i64` before subtracting, so a file shrinking from 3 bytes to 0
/// is `-3` and not an enormous positive number.
fn delta(after: usize, before: u64) -> i64 {
    after as i64 - before as i64
}

/// The group a file created at `path` would belong to.
///
/// Normally the process's effective gid, but a directory carrying the setgid
/// bit hands its own group to everything created inside it, and `/srv`,
/// `/var/www` and shared project trees are routinely set up that way. Stating
/// the effective gid there would put a group in the window that the file does
/// not end up with, and [`apply`]'s landing check — which refuses to write
/// anything the window did not describe — would then refuse every create in
/// such a directory, permanently and for no reason the user could act on.
///
/// A parent that cannot be examined falls back to the effective gid rather
/// than failing: [`validate`] has already established that it is a directory,
/// and a plan is not the place to relitigate that.
fn created_group(path: &Path) -> u32 {
    let egid = getegid().as_raw();
    let Some(parent) = path.parent() else { return egid };
    match fs::metadata(parent) {
        Ok(md) if md.mode() & 0o2000 != 0 => md.gid(),
        _ => egid,
    }
}

/// Lowercase hex SHA-256 of the file at `path`, streamed.
///
/// The same form and the same algorithm as
/// [`crate::render::diff::render_content`]'s summary hash, so a user comparing
/// the metadata panel against the diff panel — or against `sha256sum` in a
/// terminal — sees one number and not two.
///
/// The error is the operating system's, unwrapped: [`plan`] wants it as
/// context on an `anyhow` chain and [`hash_now`] wants to ask it whether the
/// file was simply absent, and only one of those survives a `with_context`.
fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex(hasher.finalize()))
}

/// Lowercase hex, the spelling `sha256sum` prints.
fn hex(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write;
    bytes.as_ref().iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

// ---- applying -------------------------------------------------------------

/// Why an approved swap did not happen.
///
/// Every variant carries the same fact about the filesystem: **nothing was
/// written, and the file that is there was not touched.** That is the property
/// the whole module exists to hold, so it is stated once here rather than
/// re-derived at each call site, and every [`fmt::Display`] text says it in
/// words as well, because the sentence reaches a human and an agent that both
/// have to know whether to retry.
///
/// Like [`Refusal`], this is a message as much as a control-flow value, and it
/// carries owned strings rather than an [`std::io::Error`] so that it can be
/// compared and logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyError {
    /// The path stopped being one hatch will write to, between the approval
    /// and the write. [`validate`] is re-run immediately before the swap and
    /// this is whatever it said the second time.
    ///
    /// The interesting member is [`Refusal::Denied`]: a directory in the path
    /// having become a symbolic link into the protected set is the one attack
    /// the content hash cannot see, because the file at the resolved path is a
    /// *different* file that may perfectly well be absent, exactly as a create
    /// expects.
    Refused(Refusal),
    /// The bytes on disk are not the bytes the plan was made against, so the
    /// diff the human read is not the change that would happen.
    ///
    /// Both fields are [`Option`] and the comparison is between the options,
    /// not between the strings: `None` against `Some` is a file that appeared
    /// under an approved create, and `Some` against `None` is one that was
    /// deleted under an approved replacement. Reducing either to "the hash
    /// differs" would let a file the user never saw be destroyed by a plan
    /// that was made when nothing was there.
    ///
    /// # On naming the hashes
    ///
    /// The message states both. That is a disclosure — it tells the agent the
    /// SHA-256 of bytes it was never shown — and the trade is the same shape
    /// as [`Refusal::Symlink`]'s and comes out the same way. It is reachable
    /// only for a path a human has already approved a write to, of a file
    /// hatch could read as the user it runs as; the plan's own hash was
    /// already on the screen that human approved; and without both numbers
    /// neither the human nor the agent can tell which version is on disk, so
    /// the message would be unactionable at the one moment it matters.
    Drift {
        /// The hash the plan was made against, `None` if the file did not
        /// exist then.
        expected: Option<String>,
        /// The hash of what is there now, `None` if nothing is.
        found: Option<String>,
    },
    /// A create lost the last instant: between the drift check and the rename,
    /// a file appeared at the path, and the rename refused to overwrite it.
    ///
    /// Distinct from [`ApplyError::Drift`] because it is a different mechanism
    /// answering at a different time — the kernel's, inside `renameat2`, with
    /// no chance to look at what it found. To a caller both mean "the world
    /// moved, ask again"; to a reader of the audit log the difference says how
    /// narrow the race was.
    Collision,
    /// The staged file cannot be made into the file the window described.
    ///
    /// The window states a mode and an owner, and a rename replaces the target
    /// with *this process's* file, at this process's uid and gid. So a
    /// replacement of a file belonging to somebody else does not preserve
    /// their ownership — it silently transfers the file to whoever hatch runs
    /// as. Rather than do that, hatch refuses and says so.
    NotAsApproved {
        /// What the approved plan said the file would be.
        approved: String,
        /// What this process can actually produce.
        staged: String,
    },
    /// The write failed for an ordinary operating-system reason: a directory
    /// that cannot be written into, a read-only mount, a full disk, a
    /// directory that has since been removed.
    ///
    /// [`validate`] deliberately does not check writability — a prompt that
    /// promised the write would succeed would be lying — so these first appear
    /// here, after a human has already said yes. The text therefore has to be
    /// worth reading: what was being attempted, what the system said, and
    /// where that leaves the reader.
    Failed {
        /// What was being attempted, naming the path it was attempted on.
        doing: String,
        /// The operating system's reason, as text.
        error: String,
        /// What the reader can do about it, when the error kind is one with a
        /// known answer.
        remedy: Option<&'static str>,
    },
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplyError::Refused(refusal) => write!(
                f,
                "hatch re-checked the path immediately before writing and refused it, so \
                 nothing was written: {refusal}"
            ),
            ApplyError::Drift { expected: None, found: Some(found) } => write!(
                f,
                "a file appeared at this path after the request was approved (it is now sha256 \
                 {found}); nothing was written and it was not touched"
            ),
            ApplyError::Drift { expected: Some(expected), found: None } => write!(
                f,
                "the file was deleted after the request was approved (it was sha256 {expected}); \
                 nothing was written"
            ),
            ApplyError::Drift { expected: Some(expected), found: Some(found) } => write!(
                f,
                "the file changed after the request was approved: it was sha256 {expected} and is \
                 now sha256 {found}; nothing was written, because the diff that was approved is \
                 not the change this would make"
            ),
            // Not reachable while the only constructor is a comparison that
            // found a difference, since `None` and `None` are equal. Worded so
            // that it still says the true and useful thing if it ever is.
            ApplyError::Drift { expected: None, found: None } => f.write_str(
                "the file changed after the request was approved; nothing was written",
            ),
            ApplyError::Collision => f.write_str(
                "a file appeared at this path in the instant before the write; nothing was \
                 written and it was not touched",
            ),
            ApplyError::NotAsApproved { approved, staged } => write!(
                f,
                "the window said the file would land as {approved}, and a write from this process \
                 would leave it as {staged}; nothing was written, because hatch will not apply \
                 something other than what was approved — a change that keeps another owner has \
                 to be applied as root"
            ),
            ApplyError::Failed { doing, error, remedy } => {
                write!(f, "{doing} failed: {error}; nothing was written")?;
                match remedy {
                    Some(remedy) => write!(f, " — {remedy}"),
                    None => Ok(()),
                }
            }
        }
    }
}

impl std::error::Error for ApplyError {}

/// Write `content` to `path` as `plan` described it, or write nothing at all.
///
/// The steps are the module documentation's "Applying" section; the short
/// version is validate again, hash again, stage a neighbour, set its mode,
/// check it is what was promised, flush it, rename it into place.
///
/// **Preconditions: `plan` came from [`plan`] for this same `path`, and a human
/// approved what it described.** `apply` re-establishes what it can of that on
/// its own — it never trusts the earlier [`validate`] — but it cannot know
/// whether anybody was asked, and it applies a plan it is given.
///
/// This is the unelevated write, performed as whoever runs hatch. A request
/// that needs root is a different mechanism (`install` under the elevation
/// path), and a plan whose landing owner this process cannot produce is
/// refused here rather than quietly applied as somebody else.
pub fn apply(
    path: &Path,
    content: &[u8],
    plan: &SwapPlan,
    deny: &Denylist,
) -> Result<(), ApplyError> {
    // 1. The path, again, in full. Not the hash alone: the hash cannot see a
    //    path that has become a symlink or an ancestor that now resolves into
    //    the protected set, because those change *which file* the name means,
    //    and the hash only ever describes whichever file that is.
    validate(path, deny).map_err(ApplyError::Refused)?;

    // 2. The bytes, again. This is the check that defends the human's
    //    decision rather than the path: they approved a diff against a
    //    specific file, and if those bytes moved, the diff they read is not
    //    the change this would make.
    let found = hash_now(path)?;
    if found != plan.hash_before {
        return Err(ApplyError::Drift { expected: plan.hash_before.clone(), found });
    }

    // Nothing has been created yet and nothing will be if either check above
    // refused, which is what makes a refusal leave the directory exactly as it
    // was.
    let Some(parent) = path.parent() else {
        // Only `/` has no parent, and validation has already refused it as a
        // directory. Fail closed rather than reason about a case that cannot
        // arrive, exactly as `validate` does with the same shape.
        return Err(ApplyError::Refused(Refusal::MissingParent { parent: path.to_path_buf() }));
    };

    // 3. Stage a neighbour: the same directory, therefore the same filesystem,
    //    therefore a `rename` that is a rename. `NamedTempFile::new()` would
    //    put it under $TMPDIR, and a rename across filesystems does not
    //    silently copy — it fails with EXDEV, after the user has already said
    //    yes. `tempfile` creates it 0600 and O_EXCL.
    let mut staged = NamedTempFile::new_in(parent)
        .map_err(|e| failed(format!("creating a temporary file in {}", parent.display()), &e))?;

    // 4. All of the content, before the mode is widened. The order matters:
    //    between the temporary file's creation and the `fchmod` it is readable
    //    only by hatch's own user, so no half-written prefix is ever visible
    //    at the mode the finished file will carry — which for a 0644 target is
    //    a partial read by anybody and for a setuid one is a partial
    //    *executable*.
    staged
        .as_file_mut()
        .write_all(content)
        .map_err(|e| failed(format!("writing a temporary file in {}", parent.display()), &e))?;

    // 5. The mode the window stated, all twelve bits, on the file descriptor
    //    rather than on the path. `fchmod` cannot be pointed at another file
    //    by anything that happens to the temporary name in the meantime, which
    //    `fs::set_permissions` on the path could be.
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(plan.landing_mode))
        .map_err(|e| {
            failed(format!("setting the mode of a temporary file in {}", parent.display()), &e)
        })?;

    // 6. Confirm, on the same descriptor, that the thing about to be renamed
    //    into place is the thing the window described. The kernel is entitled
    //    to disagree with both of the previous steps: a setgid bit is dropped
    //    on an `fchmod` by a user who is not in the file's group, and the uid
    //    and gid of the staged file are this process's, which are not the
    //    owner of a file that belongs to somebody else.
    //
    //    Compared as numbers and only *printed* as names: a uid that resolves
    //    to a name in one moment and not the next — a directory service that
    //    blinked, a container-mapped id — must not be able to turn a correct
    //    write into a refusal.
    let md = staged
        .as_file()
        .metadata()
        .map_err(|e| failed(format!("examining a temporary file in {}", parent.display()), &e))?;
    if md.mode() & 0o7777 != plan.landing_mode
        || md.uid() != plan.landing_owner.id
        || md.gid() != plan.landing_group.id
    {
        return Err(ApplyError::NotAsApproved {
            approved: landing(plan.landing_mode, &plan.landing_owner, &plan.landing_group),
            staged: landing(
                md.mode() & 0o7777,
                &Principal::user(md.uid()),
                &Principal::group(md.gid()),
            ),
        });
    }

    // 7. Durability, as far as it is worth paying for. See the module docs:
    //    the data is flushed, the directory entry is not.
    staged
        .as_file()
        .sync_all()
        .map_err(|e| failed(format!("flushing a temporary file in {}", parent.display()), &e))?;

    // 8. One rename, which either happened or did not.
    land(staged, path, plan.kind)
}

/// The rename, and the difference between a replacement and a create.
///
/// Split out from [`apply`] because it is the one step that is not a check,
/// and because the choice of syscall here is the difference between replacing
/// the file the user was shown and destroying one they never saw: a create
/// must not overwrite, a replacement must.
///
/// `persist` is `rename(2)` and clobbers. `persist_noclobber` is
/// `renameat2(RENAME_NOREPLACE)`, falling back to `link(2)`, and fails with
/// `EEXIST` instead. [`ApplyError::Drift`] has already refused the create whose
/// file appeared while a human was reading; this is the same refusal for the
/// microseconds after that check, made by the kernel, atomically.
fn land(staged: NamedTempFile, path: &Path, kind: PlanKind) -> Result<(), ApplyError> {
    let landed = match kind {
        PlanKind::Replace => staged.persist(path),
        PlanKind::Create => staged.persist_noclobber(path),
    };
    match landed {
        Ok(_) => Ok(()),
        // The temporary file is inside the error and is deleted when it drops,
        // so a failed rename leaves the directory as it found it.
        Err(e) if kind == PlanKind::Create && e.error.kind() == ErrorKind::AlreadyExists => {
            Err(ApplyError::Collision)
        }
        Err(e) => Err(failed(
            format!("renaming a temporary file into place at {}", path.display()),
            &e.error,
        )),
    }
}

/// The hash of whatever is at `path` right now, `None` when nothing is.
///
/// The `None` is the whole reason this is not [`hash_file`]: absence has to
/// survive as absence all the way to the comparison, or a file appearing under
/// an approved create is indistinguishable from an empty one.
fn hash_now(path: &Path) -> Result<Option<String>, ApplyError> {
    match hash_file(path) {
        Ok(hash) => Ok(Some(hash)),
        Err(e) if is_absent(&e) => Ok(None),
        Err(e) => Err(failed(format!("re-reading {}", path.display()), &e)),
    }
}

/// A mode and an owner as one sentence, so that what was approved and what
/// would land are compared and printed as the same kind of thing.
///
/// Four octal digits, because a setuid or sticky file that quietly lost a bit
/// is exactly what a reader has to be able to see.
fn landing(mode: u32, owner: &Principal, group: &Principal) -> String {
    format!("mode {mode:04o}, owned by {owner}:{group}")
}

/// An [`ApplyError::Failed`] with the operating system's reason and, where
/// there is one, what to do about it.
fn failed(doing: String, e: &std::io::Error) -> ApplyError {
    ApplyError::Failed { doing, error: e.to_string(), remedy: remedy(e.kind()) }
}

/// What a reader can do about an error kind, for the four or five that a swap
/// actually meets.
///
/// A bare `Permission denied (os error 13)` is true and useless: hatch knows
/// something the reader may not, which is that it writes as the user it runs
/// as and that the same request applied as root is a different question. The
/// kinds with no honest advice get none rather than a guess.
fn remedy(kind: ErrorKind) -> Option<&'static str> {
    match kind {
        ErrorKind::PermissionDenied => Some(
            "hatch writes as the user it runs as; either the directory's permissions have to \
             change or the request has to be made again as a root request",
        ),
        ErrorKind::ReadOnlyFilesystem => Some(
            "the filesystem is mounted read-only, so nothing can be written there until it is \
             remounted",
        ),
        ErrorKind::StorageFull => {
            Some("the filesystem is full; free some space and ask again")
        }
        ErrorKind::QuotaExceeded => {
            Some("the disk quota for the user hatch runs as is exhausted")
        }
        ErrorKind::NotFound => Some(
            "the directory was there when the request was approved and is not now; ask again if \
             it is meant to be recreated",
        ),
        // EXDEV. Unreachable while the temporary file is a neighbour of the
        // target, and worth saying plainly if it ever is reached, because it
        // means the swap stopped being atomic.
        ErrorKind::CrossesDevices => Some(
            "the temporary file was not on the target's filesystem, which is a bug in hatch: the \
             swap is only atomic when the two are the same",
        ),
        _ => None,
    }
}

// ---- the root path: stage the approved bytes, then let `install` land them -

/// The program that lands a root swap, and the whole of hatch's dependence on
/// it.
///
/// `install` rather than `cp` or a shell redirection because it is the one
/// standard tool that takes the mode, the owner and the group as arguments and
/// applies all three to the file it creates. Doing it in three steps — copy,
/// `chmod`, `chown` — would put the file on disk at the wrong mode first, and
/// the file being written here is one a user has already been told will land
/// at a particular mode.
const INSTALL: &str = "install";

/// Approved bytes on disk, waiting for something to land them, removed when
/// this value is dropped.
///
/// The guard is the whole of the type. The spec requires the staged file to be
/// gone on *every* exit path — the write succeeding, the elevation being
/// refused, the execution deadline, a panic — and a `remove_file` call at each
/// of those sites is a list somebody eventually fails to extend. `Drop` is the
/// list the compiler keeps: the file goes when the value does, including out
/// of an `?` in the middle of a function nobody has written yet.
///
/// What it cannot cover is the process dying without unwinding. `hatch serve`
/// empties the staging directory at startup for that case, before it binds
/// anything or accepts a request.
#[derive(Debug)]
pub struct Staged {
    path: PathBuf,
}

impl Staged {
    /// Where the bytes are, for the argv that reads them.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        // Deliberately ignored. This runs on paths that are already reporting
        // something else — a denial, a deadline, an unwind — and a failure to
        // remove a file in a 0700 directory is not the fact any of those
        // callers are trying to tell anybody. The sweep at the next startup
        // catches whatever this misses.
        let _ = fs::remove_file(&self.path);
    }
}

/// Write `content` to a new file in `stage_dir` and return the guard that
/// removes it.
///
/// The bytes are written exactly as given and are never transformed: the
/// diff a human approved and the file `install` copies have to be the same
/// bytes, and a normalisation applied on the way past here — line endings, a
/// trailing newline, an encoding — would make the approved diff a description
/// of something else.
///
/// The file is created `0600` and `O_EXCL`, inside a directory that is already
/// 0700. Both matter for the same reason and neither is redundant: the
/// directory stops another local user from reading approved content that has
/// not been written yet, and the mode stops it being readable if the directory
/// is ever loosened. `O_EXCL` on a v4 UUID is belt and braces over a name that
/// will not collide.
pub fn stage_content(stage_dir: &Path, content: &[u8]) -> Result<Staged, ApplyError> {
    fs::create_dir_all(stage_dir)
        .map_err(|e| failed(format!("creating the staging directory {}", stage_dir.display()), &e))?;
    let path = stage_dir.join(uuid::Uuid::new_v4().to_string());
    // The guard is taken before the write, so a write that fails part way
    // through still removes what it managed to put there.
    let staged = Staged { path: path.clone() };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| failed(format!("staging approved content at {}", path.display()), &e))?;
    file.write_all(content)
        .map_err(|e| failed(format!("staging approved content at {}", path.display()), &e))?;
    // Flushed for the same reason the unelevated path flushes: the bytes are
    // about to be read by another process, and on this side of the copy the
    // cost is one flush of content a human is already waiting on.
    file.sync_all()
        .map_err(|e| failed(format!("flushing approved content at {}", path.display()), &e))?;
    Ok(staged)
}

/// `install -m <mode> -o <owner> -g <group> -T -- <staged> <target>`.
///
/// Every part of it is the plan the window drew, in the same order the window
/// states it, and nothing is inferred:
///
/// * `-m` takes all twelve bits as four octal digits, so a setuid or setgid
///   target keeps the bits the window showed instead of silently losing them.
/// * `-o` and `-g` take [`Principal`]'s `Display`, which is the name when
///   there is one and the number when there is not — `install` accepts either
///   in that position, and a uid with no `passwd` entry is an ordinary thing
///   on a container-mapped or directory-backed system.
/// * `-T` is not optional. Without it, `install src dir` puts the file
///   *inside* `dir`, so a target that became a directory between the approval
///   and the write would land the bytes at a path nobody was shown. The
///   re-check refuses a directory target a moment earlier; this is the same
///   refusal made by the tool that does the writing.
/// * `--` so a path beginning with a dash is a path.
///
/// There is no shell. The two paths are `execve` arguments from here to
/// `install`, so nothing re-parses a filename hatch has already committed to.
pub fn install_argv(staged: &Path, target: &Path, plan: &SwapPlan) -> Vec<String> {
    vec![
        INSTALL.to_string(),
        "-m".to_string(),
        format!("{:04o}", plan.landing_mode),
        "-o".to_string(),
        plan.landing_owner.to_string(),
        "-g".to_string(),
        plan.landing_group.to_string(),
        "-T".to_string(),
        "--".to_string(),
        staged.display().to_string(),
        target.display().to_string(),
    ]
}

/// Everything a root swap needs in order to be run: the bytes, and the argv
/// that lands them.
///
/// The two travel together because the argv names the staged file, so an argv
/// that outlived its [`Staged`] would name a path that has been removed. Held
/// as one value, the guard cannot be dropped while the command that reads it
/// is still to run.
#[derive(Debug)]
pub struct RootWrite {
    /// The approved bytes, removed when this value is dropped.
    pub staged: Staged,
    /// The unelevated `install` argv. The caller wraps it — see
    /// [`crate::exec::elevate::Elevation::elevate`].
    pub argv: Vec<String>,
}

/// Re-check everything, then stage the bytes and build the `install` argv.
///
/// This is [`apply`]'s first half for the root path, and it makes the same two
/// checks in the same order and for the same reasons: [`validate`] in full,
/// because only that can see the path having become a different file, and then
/// the content hash, because only that defends the decision the human actually
/// made. Neither is inherited from before the prompt.
///
/// **Preconditions: `plan` came from [`plan`] for this same `path` with
/// `root` true, and a human approved what it described.**
///
/// # Where the residual window is, and why it is wider here
///
/// The unelevated [`apply`] narrows the gap between its last check and its
/// write to the microseconds a `rename` takes. This path cannot: between the
/// hash check here and `install` writing anything, the polkit password dialog
/// goes up and stays up until a person answers it. The whole of that wait is
/// inside the window — it is human-sized, and it is bounded only by hatch's
/// execution deadline killing `run0`.
///
/// It is in this order anyway, and the alternative is worse rather than
/// better. Checking *after* the password would mean spending an
/// authentication a person has already given and then refusing to use it,
/// and — the part that decides it — hatch has no way to check after the
/// password at all: the wait and the write are inside one `run0` process,
/// with no point between them where hatch runs. The only way to hold a check
/// on the far side of the dialog would be to elevate a *script* that
/// re-checks and then installs, and the window for a swap draws a diff and a
/// landing plan, not a command line, so that script would be code running as
/// root that nobody was shown. Between a stated residual and an unshown
/// script, this project takes the stated residual.
///
/// Two further facts about this path that the unelevated one does not have,
/// recorded here rather than discovered later:
///
/// * `install` opens the destination and truncates it; it is not a `rename`.
///   So a crash or a kill part way through a root write can leave the target
///   short, where the unelevated path leaves it either old or new.
/// * `install` follows a symbolic link at the destination, where `rename`
///   replaces it. The [`validate`] call below refuses a symlinked target, so
///   the exposure is the password wait and not longer — but within that wait,
///   a target replaced by a link is a root write through it.
///
/// Both are consequences of landing the file with `install`, which is what the
/// window's plan describes. Neither is prevented here.
///
/// The second one is at least *detected*: [`landed_as_approved`] examines the
/// target afterwards without following it, so a name that became a link comes
/// back with the link's own mode and owner and does not match the plan. That
/// turns a silent root write through somebody else's link into a reported
/// one. It is worth saying plainly that detecting is not preventing — the
/// bytes have already gone wherever the link pointed — and the value is that
/// the user finds out in the same minute rather than never.
pub fn stage_root(
    path: &Path,
    content: &[u8],
    plan: &SwapPlan,
    deny: &Denylist,
    stage_dir: &Path,
) -> Result<RootWrite, ApplyError> {
    // 1. The path, again, in full. See `apply`.
    validate(path, deny).map_err(ApplyError::Refused)?;

    // 2. The bytes, again. See `apply`.
    let found = hash_now(path)?;
    if found != plan.hash_before {
        return Err(ApplyError::Drift { expected: plan.hash_before.clone(), found });
    }

    // 3. Only now are the approved bytes written anywhere. Staging before the
    //    checks would leave a file to clean up on every refusal, and would put
    //    approved content on disk for a request that is about to be refused.
    let staged = stage_content(stage_dir, content)?;
    let argv = install_argv(staged.path(), path, plan);
    Ok(RootWrite { staged, argv })
}

/// What a finished root write left behind, against what the window promised.
///
/// The unelevated path proves this before the write: it `fstat`s the staged
/// descriptor and refuses unless the mode, uid and gid are the approved ones,
/// which it can do because it is the process doing the writing. The root path
/// cannot — the writing is done by `install`, under a privilege hatch does
/// not have — so the same question is asked afterwards instead. Asking late
/// cannot refuse, but it can stop hatch reporting a write as having matched a
/// plan it did not match.
///
/// Two cases make this more than a formality:
///
/// * `install -o` takes a *name* where the plan carries a number, and on a
///   system with a user literally named `1000` whose uid is not 1000 those are
///   different users. [`Principal`] records that ambiguity as accepted; this
///   is what notices when it bites.
/// * A target replaced by a symbolic link during the password wait is
///   followed by `install`, which is the one exposure the re-check cannot
///   close. `symlink_metadata` does not follow it, so the link's own mode is
///   what comes back and does not match the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Landed {
    /// The file is what the window said it would be.
    AsApproved,
    /// It is not, and this is what is there instead.
    Different {
        /// The mode, owner and group the file actually carries.
        found: String,
    },
    /// hatch could not look, and says so rather than assuming either answer.
    ///
    /// A root write can land in a directory this user cannot traverse, which
    /// makes the check impossible without the privilege that did the writing.
    /// That is not evidence of a bad write and must not be reported as one;
    /// it is the absence of evidence, and the caller says so.
    Unchecked {
        /// Why not.
        why: String,
    },
}

/// Compare the file at `path` against the plan the window drew.
///
/// Numbers are compared and names are only printed, exactly as [`apply`]'s
/// pre-write check does: a `passwd` lookup that blinks must not be able to
/// turn a correct write into a complaint.
pub fn landed_as_approved(path: &Path, plan: &SwapPlan) -> Landed {
    // `symlink_metadata`, not `metadata`. If the target is a link, the link
    // is what `install` wrote through and the link is what this has to
    // describe — following it here would report the mode of whatever it
    // points at and agree with a plan that was never applied to this name.
    let md = match fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(e) => {
            return Landed::Unchecked {
                why: format!("{} could not be examined afterwards: {e}", path.display()),
            };
        }
    };
    if md.mode() & 0o7777 == plan.landing_mode
        && md.uid() == plan.landing_owner.id
        && md.gid() == plan.landing_group.id
    {
        return Landed::AsApproved;
    }
    Landed::Different {
        found: landing(
            md.mode() & 0o7777,
            &Principal::user(md.uid()),
            &Principal::group(md.gid()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 of `old`, `new`, the empty input and 200 000 `a` bytes, from
    /// `sha256sum`. Written out rather than computed here, so that a test of
    /// the hash is a test of the hash and not of this module agreeing with
    /// itself.
    const SHA_OLD: &str = "cba06b5736faf67e54b07b561eae94395e774c517a7d910a54369e1263ccfbd4";
    const SHA_NEW: &str = "11507a0e2f5e69d5dfa40a62a1bd7b6ee57e6bcd85c67c9b8431b36fff21c437";
    const SHA_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA_200K_A: &str = "2287d207f24a941ff3b56c04c8a25ad56b63e3023207b3bb5b4ac0c9869d74be";

    /// A denylist over a fictional home directory, for the cases that never
    /// touch the disk.
    fn deny() -> Denylist {
        Denylist::new(&["/home/user/.config/hatch"], Path::new("/home/user"), &[])
    }

    /// A denylist that protects a real directory, for the cases that do.
    fn deny_dir(dir: &Path) -> Denylist {
        Denylist::new(
            &["/home/user/.config/hatch"],
            Path::new("/home/user"),
            &[dir.to_string_lossy().into_owned()],
        )
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }


    // ---- the root path: staging, the install argv, and the re-check --------

    /// A target that exists, its plan, a staging directory and a denylist
    /// that protects neither. The four things every root case needs.
    fn root_fixture(content: &[u8]) -> (tempfile::TempDir, PathBuf, PathBuf, SwapPlan) {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.conf");
        fs::write(&target, b"before\n").unwrap();
        let stage = dir.path().join("stage");
        let plan = plan(&target, content, true).unwrap();
        (dir, target, stage, plan)
    }

    #[test]
    fn staged_bytes_are_byte_identical_to_the_approved_content() {
        let dir = tempfile::tempdir().unwrap();
        // Every byte a diff can carry and a string cannot: a NUL, an invalid
        // UTF-8 byte, a lone carriage return. The whole promise of staging is
        // that the file `install` copies is the file the human approved, so
        // the one thing this must not do is normalise anything.
        let bytes = b"exact\x00bytes\xff\r no newline";
        let staged = stage_content(dir.path(), bytes).unwrap();
        assert_eq!(fs::read(staged.path()).unwrap(), bytes);
    }

    #[test]
    fn the_staged_file_is_private_and_inside_the_staging_directory() {
        let dir = tempfile::tempdir().unwrap();
        let staged = stage_content(&dir.path().join("stage"), b"x").unwrap();
        let mode = fs::metadata(staged.path()).unwrap().mode() & 0o7777;
        assert_eq!(mode, 0o600, "approved content was readable by someone else");
        assert_eq!(staged.path().parent().unwrap(), dir.path().join("stage"));
    }

    #[test]
    fn the_stage_file_is_removed_on_drop_even_without_a_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = {
            let staged = stage_content(dir.path(), b"x").unwrap();
            assert!(staged.path().exists());
            staged.path().to_path_buf()
        };
        assert!(!path.exists(), "approved bytes survived a path that never wrote them");
    }

    #[test]
    fn the_install_argv_carries_the_planned_mode_owner_and_group() {
        let mut plan = plan(Path::new("/no/such/file"), b"x", true).unwrap();
        plan.landing_mode = 0o4755;
        plan.landing_owner = Principal { id: 0, name: Some("root".to_string()) };
        plan.landing_group = Principal { id: 42, name: None };
        let argv = install_argv(Path::new("/stage/abc"), Path::new("/etc/hosts"), &plan);

        assert_eq!(argv[0], "install");
        // All twelve bits, four digits. A setuid target whose mode arrived as
        // "755" would land executable-by-all and not setuid, which is a
        // different file from the one the window described.
        assert_eq!(pair(&argv, "-m"), Some("4755".to_string()));
        assert_eq!(pair(&argv, "-o"), Some("root".to_string()));
        // A gid with no group entry is passed as its number, which `install`
        // takes in the same position. Losing it would be a write with the
        // wrong group.
        assert_eq!(pair(&argv, "-g"), Some("42".to_string()));
        assert!(argv.contains(&"-T".to_string()), "install could put the file inside a directory");
        assert_eq!(argv[argv.len() - 2], "/stage/abc");
        assert_eq!(argv[argv.len() - 1], "/etc/hosts");
        // The two paths are operands, not options, whatever they start with.
        assert!(
            argv.iter().position(|a| a == "--").unwrap() == argv.len() - 3,
            "the operands are not fenced off: {argv:?}"
        );
    }

    /// The argument after `flag` in `argv`.
    fn pair(argv: &[String], flag: &str) -> Option<String> {
        argv.iter().position(|a| a == flag).and_then(|at| argv.get(at + 1)).cloned()
    }

    #[test]
    fn a_root_write_stages_the_exact_bytes_and_names_them_in_the_argv() {
        let bytes = b"after\xff\n";
        let (_dir, target, stage, plan) = root_fixture(bytes);
        let write = stage_root(&target, bytes, &plan, &deny(), &stage).unwrap();

        assert_eq!(fs::read(write.staged.path()).unwrap(), bytes);
        assert_eq!(write.argv[write.argv.len() - 2], write.staged.path().display().to_string());
        assert_eq!(write.argv[write.argv.len() - 1], target.display().to_string());
    }

    #[test]
    fn a_root_write_re_checks_the_hash_before_anything_is_staged() {
        let (_dir, target, stage, plan) = root_fixture(b"after\n");
        // The world moves while the human reads: the file is not what the
        // plan was made against any more.
        fs::write(&target, b"somebody else got there first\n").unwrap();

        let error = stage_root(&target, b"after\n", &plan, &deny(), &stage).unwrap_err();

        assert!(matches!(error, ApplyError::Drift { .. }), "{error}");
        // Nothing staged, which is the half that matters. Staging first and
        // checking after would put approved content on disk for a request
        // that is about to be refused — and, since the caller elevates what
        // this returns, would spend a password on a write it then refuses.
        assert_eq!(
            fs::read_dir(&stage).map(|d| d.count()).unwrap_or(0),
            0,
            "approved bytes were staged for a write that was refused"
        );
    }

    #[test]
    fn a_root_write_re_checks_the_path_before_it_re_checks_the_bytes() {
        let (dir, target, stage, plan) = root_fixture(b"after\n");
        // The target became a link while the human read the diff. The hash
        // cannot see this: it describes whichever file the name now means.
        fs::remove_file(&target).unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), &target).unwrap();

        let error = stage_root(&target, b"after\n", &plan, &deny(), &stage).unwrap_err();

        assert!(
            matches!(error, ApplyError::Refused(Refusal::Symlink { .. })),
            "a root write followed a link: {error}"
        );
        assert_eq!(fs::read_dir(&stage).map(|d| d.count()).unwrap_or(0), 0);
    }

    #[test]
    fn a_root_write_to_a_protected_path_is_refused_at_the_re_check_too() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.conf");
        fs::write(&target, b"before\n").unwrap();
        let plan = plan(&target, b"after\n", true).unwrap();

        let error =
            stage_root(&target, b"after\n", &plan, &deny_dir(dir.path()), &dir.path().join("stage"))
                .unwrap_err();

        assert!(matches!(error, ApplyError::Refused(Refusal::Denied)), "{error}");
    }

    #[test]
    fn a_root_plan_keeps_an_existing_files_owner_rather_than_giving_it_to_root() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.conf");
        fs::write(&target, b"before\n").unwrap();
        set_mode(&target, 0o640);

        let plan = plan(&target, b"after\n", true).unwrap();

        // `root: true` says who does the writing, not who ends up owning the
        // file. A replacement that quietly re-owned the file to root would be
        // a change the window never described.
        assert_eq!(plan.landing_owner.id, geteuid().as_raw());
        assert_eq!(plan.landing_mode, 0o640);
        assert_eq!(pair(&install_argv(Path::new("/s"), &target, &plan), "-m"), Some("0640".into()));
    }

    #[test]
    fn what_landed_is_compared_against_the_plan_and_not_assumed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.conf");
        fs::write(&target, b"after\n").unwrap();
        set_mode(&target, 0o640);
        let plan = plan(&target, b"after\n", true).unwrap();

        assert_eq!(landed_as_approved(&target, &plan), Landed::AsApproved);

        // The same file at a mode nobody approved. `install` is told what to
        // do and is not watched doing it, so this is the only thing standing
        // between "the window said 0640" and a file that is not 0640.
        set_mode(&target, 0o600);
        let Landed::Different { found } = landed_as_approved(&target, &plan) else {
            panic!("a file at the wrong mode was reported as approved");
        };
        assert!(found.contains("0600"), "{found}");
    }

    #[test]
    fn a_target_that_became_a_link_does_not_pass_by_having_the_links_mode_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.conf");
        let elsewhere = dir.path().join("elsewhere.conf");
        fs::write(&target, b"after\n").unwrap();
        set_mode(&target, 0o640);
        let plan = plan(&target, b"after\n", true).unwrap();

        // What the password wait exposes: the name now means a link, and
        // `install` wrote through it. Following the link here would report
        // the mode of the file at the other end and agree with a plan that
        // was never applied to this name.
        fs::write(&elsewhere, b"after\n").unwrap();
        set_mode(&elsewhere, 0o640);
        fs::remove_file(&target).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &target).unwrap();

        assert!(
            matches!(landed_as_approved(&target, &plan), Landed::Different { .. }),
            "a link was reported as the approved file"
        );
    }

    #[test]
    fn a_file_that_cannot_be_examined_is_unchecked_and_not_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let plan = plan(&dir.path().join("target.conf"), b"x", true).unwrap();

        // Absence of evidence. A root write can land somewhere this user
        // cannot look, and reporting that as a bad write would cry wolf on
        // every correct write into a directory hatch cannot traverse.
        let Landed::Unchecked { why } = landed_as_approved(&dir.path().join("gone"), &plan) else {
            panic!("a file hatch could not look at was judged anyway");
        };
        assert!(why.contains("could not be examined"), "{why}");
    }

    #[test]
    fn a_root_create_lands_as_root_where_an_unelevated_one_lands_as_the_user() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("new.conf");

        let elevated = plan(&target, b"x", true).unwrap();
        let plain = plan(&target, b"x", false).unwrap();

        assert_eq!(elevated.kind, PlanKind::Create);
        assert_eq!((elevated.landing_owner.id, elevated.landing_group.id), (0, 0));
        assert_eq!(plain.landing_owner.id, geteuid().as_raw());
    }

    // ---- validate: the order of the checks -------------------------------

    #[test]
    fn absoluteness_is_answered_before_the_path_is_looked_up() {
        // Relative *and* pointing at nothing. Only the first refusal is
        // honest about what the caller has to fix.
        assert_eq!(validate(Path::new("no/such/dir/file"), &deny()), Err(Refusal::NotAbsolute));
        assert_eq!(validate(Path::new(""), &deny()), Err(Refusal::NotAbsolute));
    }

    #[test]
    fn a_dot_dot_component_is_refused_in_its_own_words_not_as_protection() {
        // The denylist would call both of these denied, which for the first is
        // simply false. `..` gets its own refusal so the message is true.
        assert_eq!(validate(Path::new("/etc/../etc/hosts"), &deny()), Err(Refusal::DotDot));
        assert_eq!(
            validate(Path::new("/home/user/.config/hatch/../hatch/config.toml"), &deny()),
            Err(Refusal::DotDot)
        );
    }

    #[test]
    fn a_protected_path_is_refused_before_the_filesystem_is_consulted() {
        // Each of these would produce a *different* refusal if the stat ran
        // first — symlink, not-a-regular-file, missing parent — and the
        // difference is exactly the map of the protected set that an agent
        // must not be able to draw without a human ever seeing a prompt.
        let dir = tempfile::tempdir().unwrap();
        let deny = deny_dir(dir.path());

        let real = dir.path().join("real");
        fs::write(&real, "x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();

        assert_eq!(validate(&link, &deny), Err(Refusal::Denied), "a symlink inside it");
        assert_eq!(validate(&sub, &deny), Err(Refusal::Denied), "a directory inside it");
        assert_eq!(validate(&real, &deny), Err(Refusal::Denied), "an ordinary file inside it");
        assert_eq!(
            validate(&dir.path().join("nope/x"), &deny),
            Err(Refusal::Denied),
            "a path inside it whose parent does not exist"
        );
    }

    #[test]
    fn an_unprotected_path_gets_the_refusal_the_filesystem_gives_it() {
        // The mirror of the test above: with the denylist out of the way, each
        // of those shapes reports what it actually is. If this and the
        // previous test ever agree on an answer, the order stopped mattering.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::write(&real, "x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();

        assert_eq!(validate(&link, &deny()), Err(Refusal::Symlink { target: real.clone() }));
        assert_eq!(validate(&sub, &deny()), Err(Refusal::NotARegularFile { what: "a directory" }));
        assert_eq!(validate(&real, &deny()), Ok(()));
        assert_eq!(
            validate(&dir.path().join("nope/x"), &deny()),
            Err(Refusal::MissingParent { parent: dir.path().join("nope") })
        );
    }

    // ---- validate: symlinks ----------------------------------------------

    #[test]
    fn a_symlink_is_judged_by_the_link_and_not_by_what_it_points_at() {
        // The mutation this exists to kill is `metadata` in place of
        // `symlink_metadata`: it would report a perfectly ordinary regular
        // file here and let the write through the link.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::write(&real, "x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert_eq!(validate(&link, &deny()), Err(Refusal::Symlink { target: real }));
    }

    #[test]
    fn a_dangling_symlink_is_refused_rather_than_read_as_a_new_file() {
        // `metadata` fails with NotFound here, which reads as "nothing is
        // there yet" — and the apply would then create whatever the link
        // names, somewhere the user never saw.
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("gone");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&gone, &link).unwrap();

        assert_eq!(validate(&link, &deny()), Err(Refusal::Symlink { target: gone }));
    }

    #[test]
    fn a_symlink_to_a_directory_is_refused_as_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&sub, &link).unwrap();

        assert_eq!(validate(&link, &deny()), Err(Refusal::Symlink { target: sub }));
    }

    #[test]
    fn the_named_target_is_the_links_own_text_relative_or_not() {
        // Reported verbatim rather than resolved. A relative link resolved
        // here would have to be spelled with the `..` this module refuses to
        // interpret elsewhere, and a dangling one has nothing to resolve.
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink("real", &link).unwrap();

        assert_eq!(
            validate(&link, &deny()),
            Err(Refusal::Symlink { target: PathBuf::from("real") })
        );
    }

    // ---- validate: the parent --------------------------------------------

    #[test]
    fn a_missing_parent_names_the_immediate_parent_not_the_highest_missing_one() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("no/such/dir/file");

        assert_eq!(
            validate(&target, &deny()),
            Err(Refusal::MissingParent { parent: dir.path().join("no/such/dir") })
        );
    }

    #[test]
    fn a_parent_that_is_a_file_is_refused_as_not_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, "x").unwrap();

        // The target's own stat fails with ENOTDIR, which `is_absent` reads as
        // "nothing there" — and then the parent, which does exist, has to be
        // the one that says why. Reporting it as missing would send the caller
        // off to create something that is already there under another type.
        assert_eq!(
            validate(&file.join("child"), &deny()),
            Err(Refusal::ParentNotADirectory { parent: file.clone() })
        );
        assert_eq!(
            validate(&file, &deny()),
            Ok(()),
            "the file itself, with a real directory over it, is fine"
        );
    }

    #[test]
    fn a_symlinked_parent_directory_is_followed_and_allowed() {
        // The opposite answer to the target's own component, and deliberately
        // so: writing into a symlinked directory is ordinary.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert_eq!(validate(&link.join("file"), &deny()), Ok(()));
    }

    #[test]
    fn a_symlinked_ancestor_cannot_smuggle_a_protected_target_past_the_lexical_check() {
        // `/tmp/…/link/config.toml` is not lexically inside the protected
        // directory, but it is the same file. The lexical check cannot see
        // that; the resolved one can.
        let protected = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let deny = deny_dir(&fs::canonicalize(protected.path()).unwrap());

        let target = protected.path().join("config.toml");
        fs::write(&target, "token").unwrap();
        let link = elsewhere.path().join("link");
        std::os::unix::fs::symlink(protected.path(), &link).unwrap();

        assert_eq!(validate(&link.join("config.toml"), &deny), Err(Refusal::Denied));
        assert_eq!(
            validate(&link.join("brand-new"), &deny),
            Err(Refusal::Denied),
            "a file that does not exist yet is inside it just the same"
        );
        assert_eq!(
            validate(&elsewhere.path().join("ordinary"), &deny),
            Ok(()),
            "and an unprotected neighbour still validates"
        );
    }

    #[test]
    fn the_resolved_check_judges_the_file_and_not_only_the_directory_it_sits_in() {
        // The protected entry here is a single file rather than a subtree, so
        // a resolved check that stopped at the directory would wave it
        // through. `~/.claude.json` is exactly this shape.
        let protected = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let secret = fs::canonicalize(protected.path()).unwrap().join("secret");
        fs::write(&secret, "x").unwrap();
        let deny = Denylist::new(
            &["/home/user/.config/hatch"],
            Path::new("/home/user"),
            &[secret.to_string_lossy().into_owned()],
        );

        let link = elsewhere.path().join("link");
        std::os::unix::fs::symlink(protected.path(), &link).unwrap();

        assert_eq!(validate(&link.join("secret"), &deny), Err(Refusal::Denied));
        assert_eq!(
            validate(&link.join("ordinary"), &deny),
            Ok(()),
            "its neighbour in the same directory is not protected"
        );
    }

    // ---- validate: the shapes that must not panic ------------------------

    #[test]
    fn a_target_that_cannot_be_examined_is_not_reported_as_absent() {
        // A symlink loop, because it is the one unexaminable path that root
        // cannot walk through either, so this test says the same thing
        // whoever runs it. Treating the error as absence would have hatch
        // announce a create for a path it never managed to look at.
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();
        let target = a.join("f");

        match validate(&target, &deny()) {
            Err(Refusal::Unreadable { path, error }) => {
                assert_eq!(path, target);
                assert!(!error.is_empty(), "the reason has to reach the message");
            }
            other => panic!("expected an unreadable refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_parent_that_stops_being_examinable_is_not_reported_as_missing() {
        // The race arm: between the target's stat and the parent's, the
        // parent became unsearchable. "No such directory" would send the
        // caller off to create a directory that is already there.
        use std::io::{Error, ErrorKind};
        let parent = Path::new("/some/dir");

        assert_eq!(
            parent_refusal(parent, Err(Error::from(ErrorKind::PermissionDenied))),
            Some(Refusal::Unreadable {
                path: parent.to_path_buf(),
                error: Error::from(ErrorKind::PermissionDenied).to_string(),
            })
        );
        assert_eq!(
            parent_refusal(parent, Err(Error::from(ErrorKind::NotFound))),
            Some(Refusal::MissingParent { parent: parent.to_path_buf() })
        );
        assert_eq!(
            parent_refusal(parent, Err(Error::from(ErrorKind::NotADirectory))),
            Some(Refusal::MissingParent { parent: parent.to_path_buf() })
        );
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, "x").unwrap();
        assert_eq!(
            parent_refusal(parent, fs::metadata(dir.path())),
            None,
            "a real directory passes"
        );
        assert_eq!(
            parent_refusal(parent, fs::metadata(&file)),
            Some(Refusal::ParentNotADirectory { parent: parent.to_path_buf() }),
            "and a real file does not"
        );
    }

    #[test]
    fn the_filesystem_root_is_refused_rather_than_planned_for() {
        assert_eq!(
            validate(Path::new("/"), &deny()),
            Err(Refusal::NotARegularFile { what: "a directory" })
        );
    }

    #[test]
    fn a_socket_is_refused_as_not_a_regular_file() {
        // A rename over a socket or a device node succeeds and destroys it,
        // which is not what "replace this file's contents" means.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("s");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

        assert_eq!(
            validate(&sock, &deny()),
            Err(Refusal::NotARegularFile { what: "not a regular file" })
        );
    }

    #[test]
    fn an_ordinary_create_and_an_ordinary_replace_both_validate() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("f");
        fs::write(&existing, "x").unwrap();

        assert_eq!(validate(&existing, &deny()), Ok(()));
        assert_eq!(validate(&dir.path().join("brand-new"), &deny()), Ok(()));
    }

    // ---- the refusal messages --------------------------------------------

    #[test]
    fn each_refusal_names_the_path_its_caller_does_not_already_have() {
        let symlink = Refusal::Symlink { target: PathBuf::from("/elsewhere/real") };
        assert!(symlink.to_string().contains("/elsewhere/real"), "{symlink}");

        let missing = Refusal::MissingParent { parent: PathBuf::from("/no/such/dir") };
        assert!(missing.to_string().contains("/no/such/dir"), "{missing}");

        let not_dir = Refusal::ParentNotADirectory { parent: PathBuf::from("/etc/hosts") };
        assert!(not_dir.to_string().contains("/etc/hosts"), "{not_dir}");

        let unreadable = Refusal::Unreadable {
            path: PathBuf::from("/root/secret"),
            error: "Permission denied (os error 13)".to_string(),
        };
        assert!(unreadable.to_string().contains("/root/secret"), "{unreadable}");
        assert!(unreadable.to_string().contains("Permission denied"), "{unreadable}");
    }

    #[test]
    fn the_protected_refusal_says_nothing_about_what_is_there() {
        // The one message that must not be helpful. It is the same sentence
        // whatever the path is, so two probes cannot be told apart.
        let a = Refusal::Denied.to_string();
        assert_eq!(a, "hatch protects this path and will not write to it");
        assert!(!a.contains("exist"), "{a}");
    }

    #[test]
    fn a_refusal_reads_as_an_error() {
        // It is returned to the agent as the tool error, so it has to be one.
        let e: Box<dyn std::error::Error> = Box::new(Refusal::NotAbsolute);
        assert!(e.to_string().contains("absolute"));
    }

    // ---- plan -------------------------------------------------------------

    #[test]
    fn a_replacement_inherits_mode_owner_and_group() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "old").unwrap();
        set_mode(&f, 0o640);

        let p = plan(&f, b"new", false).unwrap();

        assert_eq!(p.kind, PlanKind::Replace);
        assert_eq!(p.landing_mode, 0o640);
        assert_eq!(p.landing_owner.id, geteuid().as_raw(), "the file is owned by whoever runs the test");
        assert_eq!(p.landing_group.id, fs::metadata(&f).unwrap().gid());
    }

    #[test]
    fn a_replacement_inherits_the_setuid_bits_too() {
        // All twelve bits, not nine. A setuid file that quietly came back
        // without its setuid bit would be broken by an approved edit, and the
        // window states four octal digits so the reader sees which it is.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "old").unwrap();
        set_mode(&f, 0o4755);

        assert_eq!(plan(&f, b"new", false).unwrap().landing_mode, 0o4755);
    }

    #[test]
    fn a_create_lands_at_0644_owned_by_the_running_user() {
        let dir = tempfile::tempdir().unwrap();

        let p = plan(&dir.path().join("brand-new"), b"new", false).unwrap();

        assert_eq!(p.kind, PlanKind::Create);
        assert_eq!(p.landing_mode, 0o644);
        assert_eq!(p.landing_owner.id, geteuid().as_raw());
        assert_eq!(p.landing_group.id, getegid().as_raw());
    }

    #[test]
    fn a_root_create_lands_as_root() {
        let dir = tempfile::tempdir().unwrap();

        let p = plan(&dir.path().join("brand-new"), b"new", true).unwrap();

        assert_eq!(p.landing_owner.id, 0);
        assert_eq!(p.landing_group.id, 0);
    }

    #[test]
    fn a_root_replacement_still_inherits_rather_than_becoming_root() {
        // `root: true` says how the write is performed, not who ends up
        // owning the file. Handing a root write the power to also reassign
        // ownership would make an approved content change quietly a
        // permissions change.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "old").unwrap();
        set_mode(&f, 0o600);

        let p = plan(&f, b"new", true).unwrap();

        assert_eq!(p.landing_mode, 0o600);
        assert_eq!(p.landing_owner.id, geteuid().as_raw());
        assert_eq!(p.landing_group.id, fs::metadata(&f).unwrap().gid());
    }

    #[test]
    fn hash_before_is_absent_exactly_when_the_file_is() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "old").unwrap();

        assert_eq!(plan(&f, b"new", false).unwrap().hash_before.as_deref(), Some(SHA_OLD));
        assert_eq!(plan(&dir.path().join("gone"), b"new", false).unwrap().hash_before, None);
    }

    #[test]
    fn an_empty_file_is_not_the_same_as_no_file() {
        // The reason `hash_before` is an `Option`. If absence were stored as
        // the hash of nothing, these two would be the same value, and Task
        // 13's drift check could not see a file appearing under the target's
        // name between the plan and the apply.
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        fs::write(&empty, b"").unwrap();

        let existing = plan(&empty, b"new", false).unwrap();
        let absent = plan(&dir.path().join("gone"), b"new", false).unwrap();

        assert_eq!(existing.hash_before.as_deref(), Some(SHA_EMPTY));
        assert_eq!(absent.hash_before, None);
        assert_ne!(existing.hash_before, absent.hash_before);
        assert_eq!(existing.kind, PlanKind::Replace);
        assert_eq!(absent.kind, PlanKind::Create);
    }

    #[test]
    fn the_hash_is_of_the_file_on_disk_and_not_of_the_proposed_content() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "old").unwrap();

        let p = plan(&f, b"new", false).unwrap();

        assert_eq!(p.hash_before.as_deref(), Some(SHA_OLD));
        assert_ne!(p.hash_before.as_deref(), Some(SHA_NEW));
    }

    #[test]
    fn a_file_larger_than_one_chunk_is_hashed_to_the_end() {
        // A hash that stopped after the first read would agree with
        // `sha256sum` on every small file and silently miss every change past
        // 64 KB — which is the part of a large file an edit is most likely to
        // be buried in.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("big");
        fs::write(&f, vec![b'a'; 200_000]).unwrap();

        assert_eq!(plan(&f, b"", false).unwrap().hash_before.as_deref(), Some(SHA_200K_A));
    }

    #[test]
    fn the_hash_is_the_same_number_the_diff_panel_shows() {
        // One file, two panels: the metadata hash and the summary hash a
        // binary or oversized side falls back to have to agree, or a reader
        // comparing them learns nothing.
        use crate::render::diff::{Content, render_content};

        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "old").unwrap();

        let planned = plan(&f, b"", false).unwrap().hash_before.unwrap();
        let Content::Summary { sha256, .. } = render_content(b"old", 0) else {
            panic!("a zero cap summarises");
        };

        assert_eq!(planned, SHA_OLD);
        assert_eq!(planned, sha256);
    }

    #[test]
    fn size_delta_is_signed_and_counts_from_what_is_there_now() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "12345").unwrap();

        assert_eq!(plan(&f, b"1234567", false).unwrap().size_delta, 2);
        assert_eq!(plan(&f, b"12", false).unwrap().size_delta, -3);
        assert_eq!(plan(&f, b"54321", false).unwrap().size_delta, 0);
        assert_eq!(plan(&f, b"", false).unwrap().size_delta, -5);
        assert_eq!(
            plan(&dir.path().join("gone"), b"1234567", false).unwrap().size_delta,
            7,
            "a create starts from nothing"
        );
    }

    #[test]
    fn planning_a_target_that_cannot_be_examined_is_an_error_and_not_a_create() {
        // The same symlink loop as the validation test. Reading the failure
        // as absence would produce a confident `Create` plan — 0644, owned by
        // the running user, replacing nothing — for a path nothing ever
        // managed to look at.
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();

        let e = plan(&a.join("f"), b"new", false).unwrap_err().to_string();
        assert!(e.contains("examining"), "{e}");
    }

    #[test]
    fn planning_a_symlink_or_a_directory_is_an_error_and_not_a_plan() {
        // Validation's job, with validation's wording. Reaching it here is a
        // bug in hatch rather than something the agent asked for, so it fails
        // closed rather than describing the link's own inode as if it were
        // the file.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::write(&real, "x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();

        let e = plan(&link, b"new", false).unwrap_err().to_string();
        assert!(e.contains("symbolic link"), "{e}");
        let e = plan(&sub, b"new", false).unwrap_err().to_string();
        assert!(e.contains("a directory"), "{e}");
    }

    // ---- principals -------------------------------------------------------

    #[test]
    fn a_principal_with_no_passwd_entry_still_has_a_usable_name() {
        // A uid that resolves to nothing must not crash the prompt or the
        // `install -o` argument; the number is what everything falls back to.
        let unresolvable = Principal { id: 4_294_967_000, name: None };
        assert_eq!(unresolvable.to_string(), "4294967000");

        let named = Principal { id: 0, name: Some("root".to_string()) };
        assert_eq!(named.to_string(), "root");
    }

    #[test]
    fn a_principal_resolves_a_name_when_the_system_has_one() {
        // Root is the one entry every Unix passwd and group file has.
        assert_eq!(Principal::user(0).name.as_deref(), Some("root"));
        assert_eq!(Principal::user(0).id, 0);
        assert_eq!(Principal::group(0).id, 0);
        assert!(Principal::group(0).name.is_some(), "gid 0 is named on every Unix");
    }

    #[test]
    fn an_unknown_id_resolves_to_no_name_rather_than_failing() {
        let p = Principal::user(4_294_967_000);
        assert_eq!(p.id, 4_294_967_000);
        assert_eq!(p.name, None);
    }

    // ---- helpers ----------------------------------------------------------

    #[test]
    fn hex_is_lowercase_and_two_digits_per_byte() {
        assert_eq!(hex([0x00u8, 0x0f, 0xff, 0xa5]), "000fffa5");
        assert_eq!(hex([] as [u8; 0]), "");
    }

    #[test]
    fn absence_covers_both_ways_the_kernel_says_nothing_is_there() {
        use std::io::{Error, ErrorKind};
        assert!(is_absent(&Error::from(ErrorKind::NotFound)));
        assert!(is_absent(&Error::from(ErrorKind::NotADirectory)));
        assert!(!is_absent(&Error::from(ErrorKind::PermissionDenied)));
        assert!(!is_absent(&Error::from(ErrorKind::Other)));
    }

    // ---- apply: what is re-checked, and what each re-check catches --------

    /// The names in a directory, sorted, for the tests that care that nothing
    /// was left behind.
    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn the_re_check_catches_an_ancestor_that_became_a_symlink_into_protected_space() {
        // The reason `apply` re-runs the whole of `validate` and not only the
        // hash. At plan time `victim/sub` is an ordinary directory and the
        // target does not exist. While the human reads the diff, `sub` becomes
        // a link into the protected directory — and the *hash* still says
        // exactly what it said before, because there is still no file at the
        // resolved path. Only the path check can see this, and without it the
        // approved bytes land inside hatch's own state.
        let victim = tempfile::tempdir().unwrap();
        let protected = tempfile::tempdir().unwrap();
        let deny = deny_dir(&fs::canonicalize(protected.path()).unwrap());

        let sub = victim.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let target = sub.join("file");

        let p = plan(&target, b"payload", false).unwrap();
        assert_eq!(p.kind, PlanKind::Create);
        assert_eq!(validate(&target, &deny), Ok(()), "it was allowed when the plan was made");

        fs::remove_dir(&sub).unwrap();
        std::os::unix::fs::symlink(protected.path(), &sub).unwrap();

        assert_eq!(
            hash_now(&target),
            Ok(None),
            "the hash cannot see it: there is still nothing at the name"
        );
        assert_eq!(
            apply(&target, b"payload", &p, &deny),
            Err(ApplyError::Refused(Refusal::Denied))
        );
        assert_eq!(entries(protected.path()), [] as [String; 0], "and nothing reached it");
    }

    #[test]
    fn the_re_check_catches_a_target_that_became_a_symlink() {
        // The same blindness, one component further down: a dangling link
        // hashes as absence, which is precisely what an approved create
        // expects to find.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("f");
        let p = plan(&target, b"payload", false).unwrap();

        std::os::unix::fs::symlink("nowhere", &target).unwrap();

        assert_eq!(hash_now(&target), Ok(None), "a dangling link reads as nothing there");
        assert_eq!(
            apply(&target, b"payload", &p, &deny()),
            Err(ApplyError::Refused(Refusal::Symlink { target: PathBuf::from("nowhere") }))
        );
        assert!(
            fs::symlink_metadata(&target).unwrap().file_type().is_symlink(),
            "the link is still a link, and nothing was written through it or over it"
        );
    }

    #[test]
    fn a_create_will_not_overwrite_and_a_replacement_will() {
        // The syscall choice, isolated: the drift check has already refused
        // the create whose file appeared while a human was reading, so this is
        // the same refusal for the microseconds afterwards, and it is the
        // kernel's rather than hatch's.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("f");
        fs::write(&target, "theirs").unwrap();

        let mut staged = NamedTempFile::new_in(dir.path()).unwrap();
        staged.as_file_mut().write_all(b"ours").unwrap();
        assert_eq!(land(staged, &target, PlanKind::Create), Err(ApplyError::Collision));
        assert_eq!(fs::read(&target).unwrap(), b"theirs", "a create never destroys");
        assert_eq!(entries(dir.path()), ["f"], "and the temporary file went with the refusal");

        let mut staged = NamedTempFile::new_in(dir.path()).unwrap();
        staged.as_file_mut().write_all(b"ours").unwrap();
        assert_eq!(land(staged, &target, PlanKind::Replace), Ok(()));
        assert_eq!(fs::read(&target).unwrap(), b"ours", "a replacement always does");
        assert_eq!(entries(dir.path()), ["f"]);

        // A rename that fails for any other reason is a failure and says so.
        // Only `EEXIST`, and only under a create, means the thing that was
        // already there was left alone on purpose; reporting anything else as
        // a collision would tell a reader a file exists that does not.
        let gone = dir.path().join("gone").join("f");
        for kind in [PlanKind::Create, PlanKind::Replace] {
            let staged = NamedTempFile::new_in(dir.path()).unwrap();
            match land(staged, &gone, kind) {
                Err(ApplyError::Failed { doing, .. }) => {
                    assert!(doing.contains("renaming"), "{doing}");
                    assert!(doing.contains(&gone.display().to_string()), "{doing}");
                }
                other => panic!("expected a rename failure for {kind:?}, got {other:?}"),
            }
        }
        assert_eq!(entries(dir.path()), ["f"], "and each one took its temporary file with it");
    }

    #[test]
    fn the_approved_mode_lands_including_the_bits_a_umask_would_have_eaten() {
        // Twelve bits from the plan, on the file that lands, whatever the
        // temporary file was created at and whatever the process umask says.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "old").unwrap();
        set_mode(&f, 0o4711);

        let p = plan(&f, b"new", false).unwrap();
        assert_eq!(p.landing_mode, 0o4711);
        apply(&f, b"new", &p, &deny()).unwrap();

        assert_eq!(fs::metadata(&f).unwrap().permissions().mode() & 0o7777, 0o4711);
        assert_eq!(fs::read(&f).unwrap(), b"new");
    }

    #[test]
    fn an_apply_that_would_change_the_files_owner_is_refused() {
        // A rename hands the name to *this process's* file, so a replacement
        // of somebody else's file quietly transfers it. Simulated by a plan
        // that says root, because a test cannot make a file it does not own.
        if geteuid().is_root() {
            eprintln!("skipped: running as root, where the plan and the process agree");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "old").unwrap();
        set_mode(&f, 0o600);
        let mut p = plan(&f, b"new", false).unwrap();
        p.landing_owner = Principal::user(0);

        match apply(&f, b"new", &p, &deny()) {
            Err(ApplyError::NotAsApproved { approved, staged }) => {
                assert!(approved.contains("root"), "{approved}");
                assert_ne!(approved, staged);
                // Both halves describe the same mode, and it is the real one:
                // a reader comparing the two sentences has to be able to see
                // that the owner is the only thing that differs.
                assert!(approved.starts_with("mode 0600, "), "{approved}");
                assert!(staged.starts_with("mode 0600, "), "{staged}");
            }
            other => panic!("expected a refusal to change the owner, got {other:?}"),
        }
        assert_eq!(fs::read(&f).unwrap(), b"old", "and the file was left alone");
        assert_eq!(entries(dir.path()), ["f"]);

        // The group is the same question and is checked against the staged
        // file rather than assumed: a file belonging to a group hatch does not
        // run as would come out belonging to one it does.
        let mut p = plan(&f, b"new", false).unwrap();
        p.landing_group = Principal::group(0);
        match apply(&f, b"new", &p, &deny()) {
            Err(ApplyError::NotAsApproved { approved, staged }) => {
                assert_ne!(approved, staged, "{approved} / {staged}");
            }
            other => panic!("expected a refusal to change the group, got {other:?}"),
        }
        assert_eq!(fs::read(&f).unwrap(), b"old");
    }

    #[test]
    fn a_root_plan_is_refused_here_rather_than_applied_as_the_user() {
        // `root: true` plans belong to the elevated path. Applying one here
        // would create the file owned by whoever runs hatch while the window
        // said root — an approved change quietly becoming a different one.
        if geteuid().is_root() {
            eprintln!("skipped: running as root");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("brand-new");
        let p = plan(&f, b"new", true).unwrap();

        assert!(matches!(
            apply(&f, b"new", &p, &deny()),
            Err(ApplyError::NotAsApproved { .. })
        ));
        assert!(!f.exists(), "and nothing was created");
        assert_eq!(entries(dir.path()), [] as [String; 0]);
    }

    #[test]
    fn a_create_in_a_setgid_directory_is_planned_and_applied_with_that_group() {
        // A setgid directory hands its own group to what is created inside it.
        // The plan has to say so — otherwise the window states a group the
        // file will not have, and the landing check refuses every create in
        // such a directory forever.
        let Some(other) = a_group_we_are_in_but_do_not_run_as() else {
            eprintln!("skipped: the running user is in only one group");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::chown(dir.path(), None, Some(other)).unwrap();
        set_mode(dir.path(), 0o2755);

        let f = dir.path().join("brand-new");
        let p = plan(&f, b"new", false).unwrap();
        assert_eq!(p.landing_group.id, other, "the directory's group, not the process's");
        assert_ne!(p.landing_group.id, getegid().as_raw());

        apply(&f, b"new", &p, &deny()).unwrap();
        assert_eq!(fs::metadata(&f).unwrap().gid(), other);

        // It is the setgid bit that does this and not the directory's group:
        // the same directory without the bit hands new files the effective
        // gid, and a plan that read the directory's group unconditionally
        // would state the wrong one everywhere.
        set_mode(dir.path(), 0o755);
        assert_eq!(
            plan(&dir.path().join("second"), b"new", false).unwrap().landing_group.id,
            getegid().as_raw()
        );

        // And an ordinary directory is still the effective gid.
        let plain = tempfile::tempdir().unwrap();
        assert_eq!(
            plan(&plain.path().join("x"), b"new", false).unwrap().landing_group.id,
            getegid().as_raw()
        );
    }

    /// A gid the running user may create files with but does not run as, or
    /// `None` on a machine where there is no such group.
    fn a_group_we_are_in_but_do_not_run_as() -> Option<u32> {
        let egid = getegid().as_raw();
        nix::unistd::getgroups()
            .ok()?
            .into_iter()
            .map(|g| g.as_raw())
            .find(|&g| g != egid)
    }

    #[test]
    fn a_target_that_cannot_be_read_is_a_failure_and_not_a_disappearance() {
        // Reading the error as absence would report it as a file that had been
        // deleted, which is a different thing to be told and a different thing
        // to do about it.
        if geteuid().is_root() {
            eprintln!("skipped: running as root, where a mode of 0 is no obstacle");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "old").unwrap();
        let p = plan(&f, b"new", false).unwrap();
        set_mode(&f, 0o000);

        match apply(&f, b"new", &p, &deny()) {
            Err(ApplyError::Failed { doing, error, remedy }) => {
                assert!(doing.contains("re-reading"), "{doing}");
                assert!(doing.contains(&f.display().to_string()), "{doing}");
                assert!(error.contains("Permission denied"), "{error}");
                assert!(remedy.is_some(), "permission denied has an answer worth giving");
            }
            other => panic!("expected a read failure, got {other:?}"),
        }
    }

    #[test]
    fn nothing_is_staged_before_both_re_checks_have_passed() {
        // The property behind "no partial file remains": the temporary file is
        // not created until the path and the bytes have both been re-checked,
        // so a refusal has nothing to clean up and cannot fail to.
        //
        // The payload is asserted exactly rather than by shape, because the
        // two hashes are what tell a reader which of the two files is on disk,
        // and a message that has them the wrong way round says the opposite of
        // the truth while still being a `Drift`.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "old").unwrap();
        let p = plan(&f, b"new", false).unwrap();
        fs::write(&f, "new").unwrap();

        assert_eq!(
            apply(&f, b"new", &p, &deny()),
            Err(ApplyError::Drift {
                expected: Some(SHA_OLD.to_string()),
                found: Some(SHA_NEW.to_string()),
            })
        );
        assert_eq!(entries(dir.path()), ["f"]);
    }

    #[test]
    fn the_path_is_re_checked_before_the_bytes_are() {
        // The two re-checks do not commute in what they say. A target that
        // became a directory is a path problem, and the hash has no vocabulary
        // for it: reading a directory fails with EISDIR, which would surface
        // as "re-reading the file failed" — true, unhelpful, and hiding the
        // fact that the name now means something that can never be swapped.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "old").unwrap();
        let p = plan(&f, b"new", false).unwrap();

        fs::remove_file(&f).unwrap();
        fs::create_dir(&f).unwrap();

        assert_eq!(
            apply(&f, b"new", &p, &deny()),
            Err(ApplyError::Refused(Refusal::NotARegularFile { what: "a directory" }))
        );
        assert!(f.is_dir(), "and it is still a directory");
    }

    // ---- apply: the messages ---------------------------------------------

    #[test]
    fn drift_says_which_way_the_file_moved() {
        let appeared =
            ApplyError::Drift { expected: None, found: Some(SHA_NEW.to_string()) }.to_string();
        assert!(appeared.contains("appeared"), "{appeared}");
        assert!(appeared.contains(SHA_NEW), "{appeared}");

        let deleted =
            ApplyError::Drift { expected: Some(SHA_OLD.to_string()), found: None }.to_string();
        assert!(deleted.contains("deleted"), "{deleted}");
        assert!(deleted.contains(SHA_OLD), "{deleted}");

        let changed = ApplyError::Drift {
            expected: Some(SHA_OLD.to_string()),
            found: Some(SHA_NEW.to_string()),
        }
        .to_string();
        assert!(changed.contains("changed"), "{changed}");
        assert!(changed.contains(SHA_OLD) && changed.contains(SHA_NEW), "{changed}");

        // Unreachable while the only constructor is a comparison, and still a
        // true sentence rather than a panic if it ever is reached.
        let neither = ApplyError::Drift { expected: None, found: None }.to_string();
        assert!(neither.contains("changed"), "{neither}");

        for message in [appeared, deleted, changed, neither] {
            assert!(message.contains("nothing was written"), "{message}");
        }
    }

    #[test]
    fn every_apply_error_says_that_nothing_was_written() {
        // The one fact a reader has to be able to take from any of them
        // without reasoning: the file on disk is untouched, so a retry is
        // safe and no half-applied state has to be unpicked.
        let errors = [
            ApplyError::Refused(Refusal::Denied),
            ApplyError::Drift { expected: None, found: Some(SHA_NEW.to_string()) },
            ApplyError::Collision,
            ApplyError::NotAsApproved {
                approved: "mode 0644, owned by root:root".to_string(),
                staged: "mode 0644, owned by user:user".to_string(),
            },
            ApplyError::Failed {
                doing: "creating a temporary file in /etc".to_string(),
                error: "Permission denied (os error 13)".to_string(),
                remedy: None,
            },
        ];
        for e in errors {
            let text = e.to_string();
            assert!(
                text.contains("nothing was written") || text.contains("not touched"),
                "{text}"
            );
        }
    }

    #[test]
    fn a_re_check_refusal_says_it_was_re_checked_and_repeats_the_reason() {
        // The same refusal means something different here: not "this request
        // was never going to work" but "this stopped being true while you were
        // reading".
        let e = ApplyError::Refused(Refusal::Denied).to_string();
        assert!(e.contains("immediately before writing"), "{e}");
        assert!(e.contains(&Refusal::Denied.to_string()), "{e}");
    }

    #[test]
    fn a_failure_carries_the_systems_reason_and_what_to_do_about_it() {
        use std::io::{Error, ErrorKind};

        let denied = Error::from(ErrorKind::PermissionDenied);
        let e = failed("creating a temporary file in /etc".to_string(), &denied);
        let text = e.to_string();
        assert!(text.contains("creating a temporary file in /etc"), "{text}");
        assert!(text.contains("permission denied"), "{text}");
        assert!(text.contains("as a root request"), "the advice is the actionable half: {text}");

        assert!(remedy(ErrorKind::ReadOnlyFilesystem).unwrap().contains("read-only"));
        assert!(remedy(ErrorKind::StorageFull).unwrap().contains("full"));
        assert!(remedy(ErrorKind::QuotaExceeded).unwrap().contains("quota"));
        assert!(remedy(ErrorKind::NotFound).unwrap().contains("was there when"));
        assert!(remedy(ErrorKind::CrossesDevices).unwrap().contains("atomic"));
        assert_eq!(remedy(ErrorKind::Interrupted), None, "no guess where there is no answer");
    }

    #[test]
    fn a_landing_is_four_octal_digits_and_both_principals() {
        // Four digits so a setuid file staying setuid is visible; three would
        // print 0o4644 as 644 and hide the bit that matters.
        assert_eq!(
            landing(0o4644, &Principal { id: 0, name: Some("root".into()) }, &Principal {
                id: 4,
                name: None
            }),
            "mode 4644, owned by root:4"
        );
        assert_eq!(
            landing(0o644, &Principal { id: 0, name: None }, &Principal { id: 0, name: None }),
            "mode 0644, owned by 0:0"
        );
    }

}
