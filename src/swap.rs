//! `swap_file` validation and planning: everything decided before a human is
//! asked anything.
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
//! Applying is Task 13's; nothing here writes.
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
//! `~/.hatch/config.toml`, "no such directory" for `~/.hatch/nope/x` — and
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
//! things — `/tmp/x/config.toml` where `/tmp/x` points at `~/.hatch` is not
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

use std::fmt;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, bail};
use nix::unistd::{Gid, Group, Uid, User, getegid, geteuid};
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
                "hatch protects this path and will not replace it with swap_file",
            ),
            Refusal::Symlink { target } => write!(
                f,
                "the path is a symbolic link to {}: hatch never writes through a symlink; ask \
                 again for the target itself if that is what was meant",
                target.display()
            ),
            Refusal::NotARegularFile { what } => write!(
                f,
                "the path is {what}: swap_file replaces the contents of a regular file"
            ),
            Refusal::MissingParent { parent } => write!(
                f,
                "the directory {} does not exist, and swap_file never creates directories",
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
/// the value usable as `install -o`'s argument in Task 17b: `install` accepts
/// a name or a numeric id in the same position. The residual ambiguity — a
/// system with a *user literally named* `1000` whose uid is not 1000 — is
/// noted and accepted; `install` would resolve the name, which is the same
/// thing every other tool on the system does with that string.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// load-bearing for Task 13. The re-check before applying has to catch
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
            "{} is a symbolic link; swap_file must refuse it in validation rather than plan a \
             write through it",
            path.display()
        ),
        Some(md) if !md.is_file() => bail!(
            "{} is {}; swap_file must refuse it in validation rather than plan a write over it",
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
            hash_before: Some(hash_file(path)?),
            size_delta: delta(content.len(), md.len()),
        }),
        None => {
            let (uid, gid) = if root {
                (0, 0)
            } else {
                // The effective ids, because they are what the kernel will
                // stamp on a file this process creates.
                (geteuid().as_raw(), getegid().as_raw())
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

/// Lowercase hex SHA-256 of the file at `path`, streamed.
///
/// The same form and the same algorithm as
/// [`crate::render::diff::render_content`]'s summary hash, so a user comparing
/// the metadata panel against the diff panel — or against `sha256sum` in a
/// terminal — sees one number and not two.
fn hash_file(path: &Path) -> anyhow::Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK];
    loop {
        let read = file
            .read(&mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
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
        Denylist::new(Path::new("/home/user/.hatch"), &[])
    }

    /// A denylist that protects a real directory, for the cases that do.
    fn deny_dir(dir: &Path) -> Denylist {
        Denylist::new(Path::new("/home/user/.hatch"), &[dir.to_string_lossy().into_owned()])
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
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
            validate(Path::new("/home/user/.hatch/../.hatch/config.toml"), &deny()),
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
            Path::new("/home/user/.hatch"),
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
        assert_eq!(a, "hatch protects this path and will not replace it with swap_file");
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
}
