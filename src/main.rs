use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "hatch", about = "Supervised host operations for a sandboxed agent")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Run the daemon (MCP server on loopback)
    Serve,
    /// Internal: render one approval window
    Prompt,
    /// Tail the audit log
    Log,
    /// Print the client registration line
    Token,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().mode {
        Mode::Serve => hatch::server::run_serve(),
        Mode::Prompt => hatch::prompt_ui::run_prompt(),
        Mode::Log => hatch::audit::tail(),
        Mode::Token => hatch::config::print_client_line(),
    }
}
