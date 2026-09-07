//! hatch — supervised host operations for a sandboxed agent.
//!
//! One binary, two runtime modes: `hatch serve` runs the MCP daemon,
//! `hatch prompt` renders a single approval window. All logic lives here in
//! the library so integration tests can drive the real MCP endpoint against a
//! stubbed prompter; `src/main.rs` is only CLI dispatch.

pub mod audit;
pub mod config;
pub mod denylist;
pub mod exec;
pub mod paths;
pub mod prompt_ui;
pub mod prompter;
pub mod protocol;
pub mod queue;
pub mod render;
pub mod server;
pub mod swap;
