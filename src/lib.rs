//! hatch — supervised host operations for a sandboxed agent.
//!
//! One binary, three runtime modes: `hatch serve` runs the MCP daemon,
//! `hatch prompt` renders a single approval window, and `hatch preview` opens
//! that same window on a built-in sample so a person can look at it and so
//! the README's images can be regenerated. All logic lives here in the
//! library so integration tests can drive the real MCP endpoint against a
//! stubbed prompter; `src/main.rs` is only CLI dispatch.

pub mod audit;
pub mod config;
pub mod denylist;
pub mod exec;
pub mod paths;
pub mod preview;
pub mod prompt_ui;
pub mod prompter;
pub mod protocol;
pub mod queue;
pub mod render;
pub mod server;
pub mod setup;
pub mod swap;
