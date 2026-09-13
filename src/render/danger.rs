//! Danger marker heuristics.
//!
//! Unwritten, and two things are already waiting for it. Both arrived the same
//! way: a pass established a *fact* about the command and stopped there,
//! because the question of whether that fact should alarm anybody is a
//! different question and belongs in one place rather than in every pass that
//! happens to notice something.
//!
//! [`super::command`] marks a redirection -- the operator and the word it
//! points at -- as *structure*, which is a lexical claim and deliberately not
//! a verdict: `> /dev/null` and `> /etc/passwd` are the same construct and get
//! the same colour. Which of them should alarm a reader is a question about
//! the path, and this is the module that gets to answer it. A redirection
//! whose target is somewhere a write would be hard to take back is the obvious
//! first candidate, and the reason it is not decided in the highlighter is
//! that two passes with an opinion about the same word is how a window comes
//! to shout at `/dev/null`.
//!
//! [`super::roster`] is the second. It says where each name in a command
//! resolves, and whether the file it found or the directory holding it carries
//! a group- or other-write bit. Those are mode bits: a person could check them
//! by hand and get the same answer. What the roster does **not** say is that
//! any particular one of them is alarming -- a binary in a shared build
//! directory that the whole team writes to is the same bit as a binary
//! somebody dropped in `/tmp`, and telling those apart needs a view of the
//! machine that a lookup does not have. This is the module that would take
//! that view. The obvious candidates, in the order they matter: a name that
//! resolves inside a world-writable directory on the command's `PATH`, a name
//! that resolves to nothing at all in a command that is not going to create
//! it, and a `PATH` whose own entries are writable before any name is looked
//! up in them.
//!
//! The same rule holds for both, and it is the whole reason this module is
//! still empty rather than being three heuristics scattered through the
//! renderers: **a verdict is drawn in red, and red is spent once.** A window
//! that marks everything marks nothing.
