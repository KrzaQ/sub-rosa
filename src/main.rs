mod client;
mod config;
mod mgmt;
mod protocol;
mod server;
mod store;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Clone, Copy, ValueEnum)]
enum PolicyArg {
    /// Release freely while the agent runs
    Auto,
    /// Ask on the agent's tty every time
    Confirm,
}

impl From<PolicyArg> for config::Policy {
    fn from(p: PolicyArg) -> Self {
        match p {
            PolicyArg::Auto => config::Policy::Auto,
            PolicyArg::Confirm => config::Policy::Confirm,
        }
    }
}

/// sub rosa — a secret-brokering agent with a human approval gate on its own tty.
///
/// Run `rosa serve` in a dedicated tmux/screen window; scripts request
/// secrets over a unix socket and you approve them there — a channel the
/// requesting process (human or AI agent) cannot reach.
#[derive(Parser)]
#[command(name = "rosa", version)]
struct Cli {
    /// Path to the gpg-encrypted store, overriding the config's `store` and the default
    /// (~/.config/rosa/secrets.json.gpg). Accepted before or after the subcommand.
    #[arg(long, global = true, value_name = "PATH")]
    store: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create an empty encrypted store
    Init,
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
    /// Print a secret as a JSON HTTP header object, for a Claude Code MCP `headersHelper`
    #[command(after_help = "Example: rosa header API_TOKEN  →  {\"Authorization\":\"Bearer <value>\"}")]
    Header {
        name: String,
        /// Header name
        #[arg(long, default_value = "Authorization")]
        header: String,
        /// Auth scheme put before the value
        #[arg(long, default_value = "Bearer")]
        scheme: String,
        /// Send the bare value, without a scheme
        #[arg(long, conflicts_with = "scheme")]
        raw: bool,
    },
    /// List secret names and policies (never values)
    Ls,
    /// Show agent status
    Status,
    /// Ask a running agent to re-read the store
    Reload,
    /// Print the socket path clients and the agent resolve to
    Sock,
    /// Add or replace a secret (value typed hidden on this tty)
    Add {
        name: String,
        /// Record this policy in config.toml. Omit to leave an existing
        /// secret's policy alone; a running agent applies it after a restart.
        #[arg(long, value_name = "POLICY")]
        policy: Option<PolicyArg>,
    },
    /// Remove a secret
    Rm { name: String },
    /// Edit the decrypted store in $EDITOR (plaintext only in tmpfs)
    Edit,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut cfg = config::Config::load()?;
    if let Some(store) = cli.store {
        cfg.set_store(store);
    }
    match cli.cmd {
        Cmd::Init => mgmt::init(&cfg),
        Cmd::Serve => server::serve(cfg),
        Cmd::Get { name } => client::get(&name),
        Cmd::Exec { names, cmd } => client::exec(&names, &cmd),
        Cmd::Header { name, header, scheme, raw } => {
            client::header(&name, &header, (!raw).then_some(scheme.as_str()))
        }
        Cmd::Ls => client::ls(&cfg),
        Cmd::Status => client::status(),
        Cmd::Reload => client::reload(),
        Cmd::Sock => {
            println!("{}", protocol::sock_path().display());
            Ok(())
        }
        Cmd::Add { name, policy } => mgmt::add(&cfg, &name, policy.map(Into::into)),
        Cmd::Rm { name } => mgmt::rm(&cfg, &name),
        Cmd::Edit => mgmt::edit(&cfg),
    }
}
