use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Wire protocol: one JSON request line from the client, one JSON reply line
/// from the agent. Replies are {"ok":true, ...} or {"ok":false,"error":...}.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Request {
    Get { name: String },
    Ls,
    Status,
    Reload,
}

/// Extra slack the request handler waits beyond the TUI's own deadline, so
/// the TUI (which auto-denies at the deadline) always answers first.
pub const HANDLER_GRACE_SECS: u64 = 5;

/// The socket lives beside the store rather than in $XDG_RUNTIME_DIR: that
/// directory does not exist without a session manager (WSL, containers), and
/// a socket needs no tmpfs. Keep this a pure function of the environment —
/// probing the filesystem would let the agent and a client started later,
/// under different conditions, pick different paths.
pub fn sock_path() -> PathBuf {
    match std::env::var_os("ROSA_SOCK") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => crate::config::config_dir().join("rosa.sock"),
    }
}
