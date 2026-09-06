//! The five behaviours `swap_file` has to get right before a human is asked
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
use hatch::swap::{PlanKind, Refusal, plan, validate};

/// A denylist over a fixed, fictional home directory.
///
/// Fictional on purpose: the protected set is judged lexically and before the
/// filesystem is consulted, so these paths never have to exist, and a test
/// that pointed at the developer's real `~/.hatch` would pass or fail
/// depending on whose machine it ran on.
fn deny() -> Denylist {
    Denylist::new(Path::new("/home/user/.hatch"), &[])
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
        validate(Path::new("/home/user/.hatch/config.toml"), &deny()),
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
