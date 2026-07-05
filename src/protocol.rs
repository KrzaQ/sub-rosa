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

pub fn sock_path() -> PathBuf {
    match std::env::var_os("ROSA_SOCK") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => crate::config::runtime_dir().join("rosa.sock"),
    }
}
