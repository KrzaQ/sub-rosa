mod client;
mod config;
mod mgmt;
mod protocol;
mod server;
mod store;

use anyhow::Result;
use clap::Parser;

/// sub rosa — a secret-brokering agent with a human approval gate on its own tty.
///
/// Run `rosa serve` in a dedicated tmux/screen window; scripts request
/// secrets over a unix socket and you approve them there — a channel the
/// requesting process (human or AI agent) cannot reach.
#[derive(Parser)]
#[command(name = "rosa", version)]
enum Cmd {
    /// Run the agent with its approval TUI (in a dedicated tmux/screen window)
    Serve,
    /// Print a secret's value to stdout (no trailing newline); prefer `exec`
    Get { name: String },
    /// Run a command with the named secrets injected into its environment
    #[command(after_help = "Example: rosa exec DB_URL API_TOKEN -- ./deploy.sh")]
    Exec {
        #[arg(required = true)]
        names: Vec<String>,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// List secret names and policies (never values)
    Ls,
    /// Show agent status
    Status,
    /// Ask a running agent to re-read the store
    Reload,
    /// Add or replace a secret (value typed hidden on this tty)
    Add { name: String },
    /// Remove a secret
    Rm { name: String },
    /// Edit the decrypted store in $EDITOR (plaintext only in tmpfs)
    Edit,
}

fn main() -> Result<()> {
    let cfg = config::Config::load()?;
    match Cmd::parse() {
        Cmd::Serve => server::serve(cfg),
        Cmd::Get { name } => client::get(&name),
        Cmd::Exec { names, cmd } => client::exec(&names, &cmd),
        Cmd::Ls => client::ls(&cfg),
        Cmd::Status => client::status(),
        Cmd::Reload => client::reload(),
        Cmd::Add { name } => mgmt::add(&cfg, &name),
        Cmd::Rm { name } => mgmt::rm(&cfg, &name),
        Cmd::Edit => mgmt::edit(&cfg),
    }
}
