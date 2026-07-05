use std::os::unix::net::UnixStream;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

/// One entry in the requester's process ancestry.
#[derive(Debug, Clone)]
pub struct Proc {
    pub pid: i32,
    pub comm: String,
}

/// Who is on the other end of the socket, per SO_PEERCRED + /proc.
/// Decision context for the human, not authentication — a wrapper can
/// obscure the ultimate consumer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub pid: i32,
    pub uid: u32,
    pub exe: String,
    pub cmdline: String,
    /// Leaf (the caller) first, oldest ancestor last. Stops before pid 1.
    pub ancestry: Vec<Proc>,
}

impl PeerInfo {
    pub fn from_stream(stream: &UnixStream) -> PeerInfo {
        let (pid, uid) = match getsockopt(stream, PeerCredentials) {
            Ok(c) => (c.pid(), c.uid()),
            Err(_) => (0, u32::MAX),
        };
        let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "?".into());
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .trim_end_matches('\0')
                    .replace('\0', " ")
            })
            .unwrap_or_else(|_| "?".into());
        PeerInfo { pid, uid, exe, cmdline, ancestry: ancestry(pid) }
    }

    /// Ancestor comms matching config.flag_ancestors (case-insensitive substring).
    pub fn flagged<'a>(&self, patterns: &'a [String]) -> Vec<&'a str> {
        patterns
            .iter()
            .filter(|pat| self.ancestry.iter().any(|p| comm_matches(&p.comm, pat)))
            .map(String::as_str)
            .collect()
    }
}

pub fn comm_matches(comm: &str, pattern: &str) -> bool {
    comm.to_lowercase().contains(&pattern.to_lowercase())
}

/// comm and ppid from /proc/<pid>/stat. comm may contain spaces and parens,
/// so take everything between the first '(' and the last ')'.
fn read_stat(pid: i32) -> Option<(String, i32)> {
    let data = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let open = data.find('(')?;
    let close = data.rfind(')')?;
    let comm = data.get(open + 1..close)?.to_string();
    let ppid = data.get(close + 1..)?.split_whitespace().nth(1)?.parse().ok()?;
    Some((comm, ppid))
}

fn ancestry(mut pid: i32) -> Vec<Proc> {
    let mut chain = Vec::new();
    for _ in 0..32 {
        let Some((comm, ppid)) = read_stat(pid) else { break };
        chain.push(Proc { pid, comm });
        if ppid <= 1 {
            break;
        }
        pid = ppid;
    }
    chain
}
