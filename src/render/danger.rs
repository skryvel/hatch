//! Danger marker heuristics.
//!
//! Unwritten, and one thing is already waiting for it. [`super::command`]
//! marks a redirection -- the operator and the word it points at -- as
//! *structure*, which is a lexical claim and deliberately not a verdict:
//! `> /dev/null` and `> /etc/passwd` are the same construct and get the same
//! colour. Which of them should alarm a reader is a question about the path,
//! and this is the module that gets to answer it. A redirection whose target
//! is somewhere a write would be hard to take back is the obvious first
//! candidate, and the reason it is not decided in the highlighter is that two
//! passes with an opinion about the same word is how a window comes to shout
//! at `/dev/null`.
