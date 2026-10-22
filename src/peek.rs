//! Reading a file a command names, so a person can look at it before
//! approving the command.
//!
//! `python script.py` is approved on the strength of a line that says nothing
//! about what `script.py` does. This is the reading half of showing it: what
//! hatch does when the reader asks to see a file. Which words of a command
//! name a file, and how the window shows one, are not decided here.
//!
//! # The name is the agent's
//!
//! Whoever wrote the command chose the path, and can choose one that is not
//! a file at all. So the read refuses everything but a regular file, and the
//! refusal is decided on the open descriptor rather than on the path, which
//! the agent could swap between a check and an open:
//!
//! * **A named pipe would block the open forever** with nobody writing to
//!   it. The open is non-blocking, so it returns at once and is then refused
//!   as what it is. `O_NONBLOCK` means nothing to a regular file's reads.
//! * **A device has no end.** `/dev/zero` and `/dev/urandom` are refused, not
//!   read up to the limit, and a terminal is opened with `O_NOCTTY` so the
//!   open cannot make it this process's controlling terminal.
//! * **A file can be any size.** At most [`LIMIT`] bytes are read, whatever
//!   the file says its size is, and `/proc` files that say they are empty are
//!   read the same way.
//!
//! A symbolic link is followed, because that is what the program the command
//! runs will do with the name. Reading happens with this process's own
//! permissions: a file the person cannot read is unreadable here too.
//!
//! # Every byte drawn as itself
//!
//! Text that is not UTF-8 is not shown at all. Decoding it lossily would
//! draw a replacement character where the file has some other byte, which is
//! a picture of a file that does not exist. A NUL makes a file not text for
//! the same purpose, because a file with one in it is almost never text that
//! someone meant to be read. Characters that draw as nothing are the
//! window's business, as they are for everything else it draws.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;

/// The most of a file that is read: the same quarter of a megabyte as the
/// largest file an agent may write through hatch, `crate::server::MAX_CONTENT_BYTES`.
/// A file longer than that is shown up to it and said to go on.
pub const LIMIT: usize = 256 * 1024;

/// What reading a file gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peek {
    /// The file, as text. `truncated` when it is longer than [`LIMIT`];
    /// `size` is what the file said its size was when it was opened.
    Text { text: String, truncated: bool, size: u64 },
    /// A regular file whose bytes are not text: not UTF-8, or with a NUL in
    /// what was read.
    NotText { size: u64 },
    /// Something that is not a regular file, named the way a person would
    /// name it: "a directory", "a named pipe".
    NotAFile { what: &'static str },
    /// Nothing is there.
    Missing,
    /// It is there and could not be read, with what the system said.
    Unreadable { why: String },
}

/// Read the file at `path`, if it is one.
///
/// Blocking, and bounded by [`LIMIT`] rather than by time: a regular file on
/// a stalled network mount can hold a read up indefinitely, so a window must
/// not call this on the thread that draws it.
pub fn peek(path: &Path) -> Peek {
    let file = match open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Peek::Missing,
        Err(error) => return Peek::Unreadable { why: error.to_string() },
    };
    // The descriptor's own type, not the path's: see the module docs.
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => return Peek::Unreadable { why: error.to_string() },
    };
    if let Some(what) = not_a_file(&metadata) {
        return Peek::NotAFile { what };
    }
    let size = metadata.len();
    let mut bytes = Vec::new();
    // One byte past the limit, which is how a file of exactly `LIMIT` bytes
    // is told from a longer one without trusting `size`.
    if let Err(error) = file.take(LIMIT as u64 + 1).read_to_end(&mut bytes) {
        return Peek::Unreadable { why: error.to_string() };
    }
    let truncated = bytes.len() > LIMIT;
    bytes.truncate(LIMIT);
    match text(bytes, truncated) {
        Some(text) => Peek::Text { text, truncated, size },
        None => Peek::NotText { size },
    }
}

fn open(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY)
        .open(path)
}

fn not_a_file(metadata: &Metadata) -> Option<&'static str> {
    let kind = metadata.file_type();
    if kind.is_file() {
        None
    } else if kind.is_dir() {
        Some("a directory")
    } else if kind.is_fifo() {
        Some("a named pipe")
    } else if kind.is_socket() {
        Some("a socket")
    } else if kind.is_char_device() || kind.is_block_device() {
        Some("a device")
    } else {
        Some("not a regular file")
    }
}

/// The bytes as text, if they are text.
///
/// A file cut at [`LIMIT`] can be cut inside a character. Those few bytes
/// are dropped rather than counted against the file, because they are the
/// cut's doing and not the file's; anywhere else, one byte that is not
/// UTF-8 makes the whole file not text.
fn text(mut bytes: Vec<u8>, truncated: bool) -> Option<String> {
    if bytes.contains(&0) {
        return None;
    }
    if let Err(error) = std::str::from_utf8(&bytes) {
        let cut_inside_a_character = truncated && error.error_len().is_none();
        if !cut_inside_a_character {
            return None;
        }
        bytes.truncate(error.valid_up_to());
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn written(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).expect("written");
        path
    }

    #[test]
    fn a_text_file_is_read_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = written(&dir, "script.py", "print('olá')\n".as_bytes());
        assert_eq!(
            peek(&path),
            Peek::Text { text: "print('olá')\n".to_string(), truncated: false, size: 14 }
        );
    }

    #[test]
    fn a_long_file_is_read_up_to_the_limit_and_said_to_go_on() {
        let dir = tempfile::tempdir().unwrap();
        let exact = written(&dir, "exact", &vec![b'a'; LIMIT]);
        let longer = written(&dir, "longer", &vec![b'a'; LIMIT + 10]);
        assert!(matches!(peek(&exact), Peek::Text { truncated: false, .. }), "{:?}", peek(&exact));
        match peek(&longer) {
            Peek::Text { text, truncated: true, size } => {
                assert_eq!(text.len(), LIMIT);
                assert_eq!(size, LIMIT as u64 + 10);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_character_cut_by_the_limit_is_dropped_and_the_rest_is_still_text() {
        // Three bytes of `€` straddling the limit.
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = vec![b'a'; LIMIT - 1];
        bytes.extend("€€".as_bytes());
        let path = written(&dir, "cut", &bytes);
        match peek(&path) {
            Peek::Text { text, truncated: true, .. } => assert_eq!(text.len(), LIMIT - 1),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bytes_that_are_not_text_are_not_shown() {
        let dir = tempfile::tempdir().unwrap();
        // Not UTF-8 anywhere, including just before the end of a short file,
        // where a cut character would have been forgiven in a long one.
        for (name, bytes) in [
            ("latin1", &b"caf\xe9\n"[..]),
            ("unfinished", &b"ok \xe2\x82"[..]),
            ("nul", &b"ELF\x00\x01"[..]),
        ] {
            let path = written(&dir, name, bytes);
            assert_eq!(peek(&path), Peek::NotText { size: bytes.len() as u64 }, "{name}");
        }
    }

    #[test]
    fn what_is_not_a_regular_file_is_named_and_not_read() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(peek(dir.path()), Peek::NotAFile { what: "a directory" });
        assert_eq!(peek(Path::new("/dev/zero")), Peek::NotAFile { what: "a device" });
        assert_eq!(peek(&dir.path().join("nothing")), Peek::Missing);
    }

    #[test]
    fn a_named_pipe_nobody_writes_to_does_not_hold_the_read_up() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status().expect("mkfifo runs");
        assert!(made.success());
        // On a thread, so a regression fails the test instead of hanging it.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(peek(&fifo)));
        let started = Instant::now();
        let got = rx.recv_timeout(Duration::from_secs(5)).expect("the open blocked on the pipe");
        assert_eq!(got, Peek::NotAFile { what: "a named pipe" });
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_link_is_followed_to_what_the_program_would_read() {
        let dir = tempfile::tempdir().unwrap();
        let target = written(&dir, "real.py", b"pass\n");
        let link = dir.path().join("script.py");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(peek(&link), Peek::Text { ref text, .. } if text == "pass\n"));
    }
}
