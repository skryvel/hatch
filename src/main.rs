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
    /// Print what is needed to finish an install: `mcp` or `polkit`
    ///
    /// A topic and not a flag, and `hatch setup mcp` rather than
    /// `hatch setup-mcp`, because more than one thing about a new install is
    /// easy to get wrong and they want to live next to each other.
    Setup {
        #[command(subcommand)]
        topic: Option<Topic>,
    },
}

#[derive(Subcommand)]
enum Topic {
    /// Register a running hatch with an MCP client
    Mcp,
    /// The polkit drop-in that keeps root behind two gates
    Polkit,
    /// Anything else.
    ///
    /// Caught here rather than left to clap so that a wrong word is answered
    /// with the list of right ones. Clap's own message for an unrecognised
    /// subcommand names what was not understood and not what would have been.
    #[command(external_subcommand)]
    Other(Vec<String>),
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().mode {
        Mode::Serve => hatch::server::run_serve(),
        Mode::Prompt => hatch::prompt_ui::run_prompt(),
        Mode::Log => hatch::audit::tail(),
        Mode::Token => hatch::config::print_client_line(),
        Mode::Setup { topic } => match topic {
            None => hatch::setup::list(),
            Some(Topic::Mcp) => hatch::setup::mcp(),
            Some(Topic::Polkit) => hatch::setup::polkit(),
            Some(Topic::Other(words)) => hatch::setup::unknown(&words),
        },
    }
}
