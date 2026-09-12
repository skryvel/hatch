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
    /// Open the approval window on a sample, and run nothing
    ///
    /// The window `hatch prompt` draws, on a request built in this process
    /// rather than sent by an agent, so a person can see what their
    /// `font_size`, `theme` and `terminal` settings look like without having
    /// to get an agent to knock. `--shot` photographs the viewport to a PNG
    /// and exits, which is how the README's images are made.
    Preview {
        /// Which sample to draw
        #[arg(value_enum, default_value_t = hatch::preview::Scenario::Command)]
        scenario: hatch::preview::Scenario,
        /// Write the window to this PNG and exit
        #[arg(long, value_name = "PATH")]
        shot: Option<std::path::PathBuf>,
        /// Draw this run in the other palette, leaving the config alone
        #[arg(long, value_enum, value_name = "PALETTE")]
        theme: Option<hatch::prompt_ui::theme::Theme>,
    },
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
        Mode::Preview { scenario, shot, theme } => hatch::preview::run(scenario, shot, theme),
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
