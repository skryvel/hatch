//! The files a command names, for the window to offer to show.
//!
//! [`crate::render::command::named_paths`] finds the words whose values
//! hatch can state; this keeps the ones that are regular files where the
//! command will look for them. Like the roster, it touches the filesystem,
//! so the daemon builds it against the request's working directory and
//! environment, and the window is handed the result.
//!
//! The list is what was there when the request was prepared. The window
//! reads a file again when someone asks to see it (see [`crate::peek`]), and
//! the command reads it again when it runs; nothing here holds either of
//! those to what was found.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::render::command::named_paths;

/// The most files one request offers. A command that names more than this
/// is moving files around rather than running one, and the rest are counted
/// rather than listed: see [`Named::more`].
pub const MAX_NAMED_FILES: usize = 12;

/// One file a command names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedFile {
    /// The value as the program receives it: `script.py`, or `/srv/x.py`
    /// for a `"$F"` that holds it. Agent-chosen text, defanged where drawn.
    pub named: String,
    /// Where that is: `named` against the working directory when relative.
    /// What the window reads.
    pub path: PathBuf,
    /// Its size when the request was prepared.
    pub size: u64,
}

/// The files a command names, and whether it names more than were listed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Named {
    pub files: Vec<NamedFile>,
    /// How many more regular files it names past [`MAX_NAMED_FILES`].
    pub more: usize,
}

/// The regular files `command` names, resolved against `cwd`.
///
/// `metadata` follows a link, as the program will, and does not open what it
/// looks at, so a named pipe is answered without anyone writing to it.
pub fn named_files(command: &str, env: &BTreeMap<String, String>, cwd: &Path) -> Named {
    let mut named = Named::default();
    for value in named_paths(command, env) {
        let path = cwd.join(&value);
        let Ok(metadata) = std::fs::metadata(&path) else { continue };
        if !metadata.is_file() {
            continue;
        }
        match named.files.len() < MAX_NAMED_FILES {
            true => named.files.push(NamedFile { named: value, path, size: metadata.len() }),
            false => named.more += 1,
        }
    }
    named
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("script.py"), "print(1)\n").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/inner.py"), "pass\n").unwrap();
        dir
    }

    fn named(command: &str, env: &BTreeMap<String, String>, cwd: &Path) -> Vec<String> {
        named_files(command, env, cwd).files.into_iter().map(|file| file.named).collect()
    }

    #[test]
    fn a_script_handed_to_an_interpreter_is_named() {
        let dir = a_tree();
        let files = named_files("python3 script.py --fast", &BTreeMap::new(), dir.path());
        assert_eq!(
            files.files,
            vec![NamedFile {
                named: "script.py".to_string(),
                path: dir.path().join("script.py"),
                size: 9,
            }]
        );
    }

    #[test]
    fn a_variable_holding_a_full_path_names_the_file_it_holds() {
        let dir = a_tree();
        let full = dir.path().join("script.py").display().to_string();
        let set = format!("F={full}; python3 \"$F\"");
        assert_eq!(named(&set, &BTreeMap::new(), Path::new("/")), vec![full.clone()]);
        let env = BTreeMap::from([("SCRIPT".to_string(), full.clone())]);
        assert_eq!(named("python3 ${SCRIPT}", &env, Path::new("/")), vec![full]);
    }

    #[test]
    fn directories_and_missing_names_are_not_files() {
        let dir = a_tree();
        assert!(named("ls sub nothing.py", &BTreeMap::new(), dir.path()).is_empty());
    }

    #[test]
    fn a_command_naming_many_files_lists_some_and_counts_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let names: Vec<String> = (0..MAX_NAMED_FILES + 3).map(|n| format!("f{n}")).collect();
        for name in &names {
            std::fs::write(dir.path().join(name), "").unwrap();
        }
        let files = named_files(&format!("rm {}", names.join(" ")), &BTreeMap::new(), dir.path());
        assert_eq!(files.files.len(), MAX_NAMED_FILES);
        assert_eq!(files.more, 3);
    }
}
