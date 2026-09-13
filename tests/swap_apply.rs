//! The five behaviours a file write has to get right before a human is asked
//! anything, driven through the public API the daemon will use.
//!
//! Each refusal here happens *before* a prompt exists. Prompting for something
//! that will be refused anyway spends the user's attention — the scarcest
//! resource in this design — and teaches them that refusals are routine, which
//! is the habit that makes the one refusal that matters get clicked through.
//!
//! Everything finer grained — the order the checks run in, the wording, the
//! hash and the ownership arithmetic — is unit-tested next to the code in
//! `src/swap.rs`. This file is the contract.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use hatch::denylist::Denylist;
use hatch::swap::{ApplyError, PlanKind, Refusal, apply, plan, validate};

/// A denylist over a fixed, fictional home directory.
///
/// Fictional on purpose: the protected set is judged lexically and before the
/// filesystem is consulted, so these paths never have to exist, and a test
/// that pointed at the developer's real `~/.config/hatch` would pass or fail
/// depending on whose machine it ran on.
fn deny() -> Denylist {
    Denylist::new(&["/home/user/.config/hatch"], Path::new("/home/user"), &[])
}

#[test]
fn relative_paths_are_refused() {
    assert!(matches!(validate(Path::new("etc/hosts"), &deny()), Err(Refusal::NotAbsolute)));
}

#[test]
fn symlink_targets_are_refused_and_name_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::write(&real, "x").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    match validate(&link, &deny()) {
        Err(Refusal::Symlink { target }) => assert_eq!(target, real),
        other => panic!("expected symlink refusal, got {other:?}"),
    }
}

#[test]
fn missing_parent_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("no/such/dir/file");
    assert!(matches!(validate(&p, &deny()), Err(Refusal::MissingParent { .. })));
}

#[test]
fn denylisted_target_is_refused() {
    assert!(matches!(
        validate(Path::new("/home/user/.config/hatch/config.toml"), &deny()),
        Err(Refusal::Denied)
    ));
}

#[test]
fn plan_reports_create_versus_replace_and_landing_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let existing = dir.path().join("f");
    std::fs::write(&existing, "old").unwrap();
    set_mode(&existing, 0o600);

    let p = plan(&existing, b"new", false).unwrap();
    assert_eq!(p.kind, PlanKind::Replace);
    assert_eq!(p.landing_mode, 0o600, "a replacement inherits the existing mode");

    let p2 = plan(&dir.path().join("brand-new"), b"new", false).unwrap();
    assert_eq!(p2.kind, PlanKind::Create);
    assert_eq!(p2.landing_mode, 0o644);
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

// ---- applying ------------------------------------------------------------
//
// The four behaviours the write itself has to get right. Everything above
// this line happens before a human is asked; everything below it happens
// after one said yes, which is the moment hatch first touches the user's
// filesystem. A defect above misleads. A defect here destroys.

#[test]
fn apply_writes_content_and_preserves_mode() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("f");
    std::fs::write(&f, "old").unwrap();
    set_mode(&f, 0o600);

    let p = plan(&f, b"new", false).unwrap();
    apply(&f, b"new", &p, &deny()).unwrap();

    assert_eq!(std::fs::read(&f).unwrap(), b"new");
    assert_eq!(
        std::fs::metadata(&f).unwrap().permissions().mode() & 0o7777,
        0o600,
        "a replacement lands at the mode the window stated, not at the temporary file's 0600 \
         by accident and not at whatever the umask says"
    );

    // A create is the other half of the same behaviour: nothing there, and
    // afterwards a file at the mode the window stated.
    let new = dir.path().join("brand-new");
    let p = plan(&new, b"fresh", false).unwrap();
    apply(&new, b"fresh", &p, &deny()).unwrap();

    assert_eq!(std::fs::read(&new).unwrap(), b"fresh");
    assert_eq!(std::fs::metadata(&new).unwrap().permissions().mode() & 0o7777, 0o644);
}

#[test]
fn temp_file_is_created_in_the_target_directory() {
    // A temporary file on another filesystem makes `rename()` non-atomic —
    // in fact it makes it fail, which is the only reason the degradation is
    // detectable at all. Two observations, because neither is enough alone.

    // One: where the staging is attempted. A directory that cannot be written
    // into fails at the *first* step when staging happens inside it, and the
    // message names that directory. Staging in the system temporary directory
    // would get as far as the rename and fail with a different sentence.
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("f");
    std::fs::write(&f, "old").unwrap();
    let p = plan(&f, b"new", false).unwrap();
    set_mode(dir.path(), 0o500);
    let e = apply(&f, b"new", &p, &deny()).unwrap_err();
    set_mode(dir.path(), 0o700);

    let msg = e.to_string();
    assert!(msg.contains("temporary file"), "{msg}");
    assert!(
        msg.contains(&dir.path().display().to_string()),
        "the failure has to name the directory staging was attempted in: {msg}"
    );
    assert_eq!(std::fs::read(&f).unwrap(), b"old", "and nothing was written");

    // Two: that a target on a filesystem other than the system temporary
    // directory still applies. `rename(2)` across filesystems fails with
    // EXDEV, so this only passes when the temporary file was a neighbour of
    // the target. /dev/shm is a separate tmpfs from /tmp on any ordinary
    // Linux; where it is not, there is nothing to compare and the check is
    // skipped rather than faked.
    let Some(other_fs) = a_directory_on_another_filesystem() else {
        eprintln!("skipped: no second filesystem to stage across");
        return;
    };
    let f = other_fs.path().join("f");
    std::fs::write(&f, "old").unwrap();
    let p = plan(&f, b"new", false).unwrap();

    apply(&f, b"new", &p, &deny()).unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"new");
}

#[test]
fn drift_is_detected_before_apply() {
    let dir = tempfile::tempdir().unwrap();

    // The file changed under an approved replacement. The human approved a
    // diff against "old"; the bytes on disk are no longer "old", so the diff
    // they read is not the change that would happen.
    let f = dir.path().join("f");
    std::fs::write(&f, "old").unwrap();
    let p = plan(&f, b"new", false).unwrap();
    std::fs::write(&f, "someone else got here first").unwrap();

    assert!(matches!(apply(&f, b"new", &p, &deny()), Err(ApplyError::Drift { .. })));
    assert_eq!(
        std::fs::read(&f).unwrap(),
        b"someone else got here first",
        "the other writer's bytes are still there"
    );

    // The file appeared under an approved create. Drift is not only "the hash
    // differs": absence and presence are the two ends the comparison has to
    // tell apart, or a create silently destroys a file the user never saw.
    let n = dir.path().join("brand-new");
    let p = plan(&n, b"fresh", false).unwrap();
    std::fs::write(&n, "not yours").unwrap();

    assert!(matches!(apply(&n, b"fresh", &p, &deny()), Err(ApplyError::Drift { .. })));
    assert_eq!(std::fs::read(&n).unwrap(), b"not yours");

    // And the file vanished under an approved replacement.
    let g = dir.path().join("g");
    std::fs::write(&g, "old").unwrap();
    let p = plan(&g, b"new", false).unwrap();
    std::fs::remove_file(&g).unwrap();

    assert!(matches!(apply(&g, b"new", &p, &deny()), Err(ApplyError::Drift { .. })));
    assert!(!g.exists(), "and it was not brought back");
}

#[test]
fn no_partial_file_remains_after_a_drift_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("f");
    std::fs::write(&f, "old").unwrap();
    let p = plan(&f, b"new", false).unwrap();
    std::fs::write(&f, "moved on").unwrap();

    assert!(apply(&f, b"new", &p, &deny()).is_err());

    let mut left: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, ["f"], "a refused apply leaves no half-written neighbour behind");
}

/// A directory on a filesystem other than the one temporary files land on, or
/// `None` where the machine has only one.
fn a_directory_on_another_filesystem() -> Option<tempfile::TempDir> {
    use std::os::unix::fs::MetadataExt;
    let here = std::fs::metadata(std::env::temp_dir()).ok()?.dev();
    let there = Path::new("/dev/shm");
    if std::fs::metadata(there).ok()?.dev() == here {
        return None;
    }
    tempfile::TempDir::new_in(there).ok()
}
