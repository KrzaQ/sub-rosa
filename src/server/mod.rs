pub mod peer;
pub mod tui;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use nix::poll::{PollFd, PollFlags, PollTimeout};
use serde_json::{json, Value};

use crate::config::{Config, Policy};
use crate::protocol::{sock_path, Request, HANDLER_GRACE_SECS};
use crate::store::{self, SecretMap};
use peer::PeerInfo;

/// How long an approval grant lasts.
#[derive(Debug, Clone, Copy)]
pub enum GrantUntil {
    At(Instant),
    Session,
}

/// What a grant attaches to. Exe-scoped grants (the requester itself)
/// survive re-runs of the same binary/script; pid-scoped grants (an ancestor
/// picked from the process tree, e.g. one claude session) match any request
/// descending from that live process and die with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantScope {
    Exe(String),
    Pid { pid: i32, comm: String },
}

impl GrantScope {
    pub fn label(&self) -> String {
        match self {
            GrantScope::Exe(path) => std::path::Path::new(path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone()),
            GrantScope::Pid { pid, comm } => format!("{comm}({pid})"),
        }
    }

    fn matches(&self, peer: &PeerInfo) -> bool {
        match self {
            GrantScope::Exe(path) => *path == peer.exe,
            // comm re-checked so a recycled pid doesn't inherit the grant
            GrantScope::Pid { pid, comm } => peer
                .ancestry
                .iter()
                .any(|p| p.pid == *pid && p.comm == *comm),
        }
    }
}

pub struct Grant {
    pub name: String,
    pub scope: GrantScope,
    pub until: GrantUntil,
    /// A pidfd for a `Pid`-scoped grant's ancestor, so `prune_grants` can drop
    /// the grant the moment the process exits (race-free vs. PID reuse). `None`
    /// for `Exe` grants and when `pidfd_open` is unavailable (old kernel) — such
    /// grants fall back to the lazy comm-recheck in `GrantScope::matches`.
    pub watch: Option<OwnedFd>,
}

/// Open a pidfd watching a `Pid`-scoped grant's ancestor process. Returns `None`
/// for `Exe` scopes and if the syscall fails (e.g. pre-5.3 kernel, or the process
/// already exited between selection and here).
pub fn pidfd_for(scope: &GrantScope) -> Option<OwnedFd> {
    let GrantScope::Pid { pid, .. } = scope else {
        return None;
    };
    // SAFETY: pidfd_open has no side effects on our address space; on success it
    // returns a fresh owned fd, which we immediately wrap in OwnedFd. (libc 0.2
    // has no wrapper fn, so go through the raw syscall.)
    let fd = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, *pid, 0) };
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Whether the process behind a pidfd has exited: a pidfd becomes readable
/// (`POLLIN`) exactly when its process dies. Non-blocking (zero timeout).
fn pidfd_dead(fd: &OwnedFd) -> bool {
    let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
    match nix::poll::poll(&mut fds, PollTimeout::ZERO) {
        Ok(n) if n > 0 => fds[0]
            .revents()
            .is_some_and(|r| r.intersects(PollFlags::POLLIN | PollFlags::POLLHUP)),
        _ => false,
    }
}

/// Where an effective policy came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySource {
    Config,
    Override,
}

/// Runtime policy override. TUI-only and ephemeral: never persisted, and
/// deliberately not settable over the socket — anything on the socket is
/// reachable by the processes rosa is guarding.
pub struct PolicyOverride {
    pub policy: Policy,
    pub until: GrantUntil,
}

/// State shared between connection-handler threads and the TUI thread.
pub struct Shared {
    pub store: SecretMap,
    pub grants: Vec<Grant>,
    pub overrides: HashMap<String, PolicyOverride>,
    pub cfg: Config,
    pub started: Instant,
}

impl Shared {
    fn grant_active(&mut self, name: &str, peer: &PeerInfo) -> bool {
        self.prune_grants();
        self.grants
            .iter()
            .any(|g| g.name == name && g.scope.matches(peer))
    }

    pub fn add_grant(&mut self, grant: Grant) {
        self.grants
            .retain(|g| !(g.name == grant.name && g.scope == grant.scope));
        self.grants.push(grant);
    }

    pub fn prune_grants(&mut self) {
        let now = Instant::now();
        self.grants.retain(|g| {
            let expired = matches!(g.until, GrantUntil::At(t) if t <= now);
            let dead = g.watch.as_ref().is_some_and(pidfd_dead);
            !expired && !dead
        });
        self.overrides
            .retain(|_, o| !matches!(o.until, GrantUntil::At(t) if t <= now));
    }

    /// Live override else config. Non-mutating — an expired-but-unpruned
    /// override counts as absent, so this is safe to call while iterating
    /// `store` under the same borrow; removal happens in prune_grants().
    pub fn effective_policy(&self, name: &str) -> (Policy, PolicySource) {
        let now = Instant::now();
        match self.overrides.get(name) {
            Some(o) if !matches!(o.until, GrantUntil::At(t) if t <= now) => {
                (o.policy, PolicySource::Override)
            }
            _ => (self.cfg.policy_for(name), PolicySource::Config),
        }
    }

    /// Returns the number of grants revoked (a confirm lock revokes the
    /// secret's grants — a lock that left live grants active would lie).
    pub fn set_override(&mut self, name: &str, ov: PolicyOverride) -> usize {
        let mut revoked = 0;
        if ov.policy == Policy::Confirm {
            let before = self.grants.len();
            self.grants.retain(|g| g.name != name);
            revoked = before - self.grants.len();
        }
        self.overrides.insert(name.to_string(), ov);
        revoked
    }

    /// Remaining lifetime of a live override, human-formatted.
    pub fn override_expiry(&self, name: &str) -> Option<String> {
        self.overrides.get(name).map(|o| match o.until {
            GrantUntil::Session => "session".to_string(),
            GrantUntil::At(t) => format_remaining(t.saturating_duration_since(Instant::now())),
        })
    }
}

/// The TUI's verdict on a pending request. Any grant is recorded in Shared
/// by the TUI itself before the decision is sent.
#[derive(Debug, Clone, Copy)]
pub enum Decision {
    Allow,
    Deny,
}

/// A confirm-policy request waiting for a human.
pub struct PendingReq {
    pub name: String,
    pub peer: PeerInfo,
    pub received: Instant,
    pub respond: SyncSender<Decision>,
}

/// Messages from handler threads to the TUI thread.
pub enum ServerMsg {
    Request(PendingReq),
    Log { msg: String, deny: bool },
    ReloadReq,
}

pub fn serve(cfg: Config) -> Result<()> {
    let sock = sock_path();
    // A fresh machine may not have the config dir yet.
    if let Some(dir) = sock.parent() {
        crate::config::ensure_private_dir(dir)?;
    }
    if UnixStream::connect(&sock).is_ok() {
        bail!("another agent is already listening on {}", sock.display());
    }
    let _ = std::fs::remove_file(&sock); // stale socket from a dead agent

    // Decrypt before entering the TUI so gpg's pinentry has a sane terminal.
    let store_path = cfg.store_path();
    eprintln!("rosa: decrypting {} …", store_path.display());
    let secrets = store::load(&store_path)?;
    eprintln!("rosa: {} secrets loaded", secrets.len());

    let shared = Arc::new(Mutex::new(Shared {
        store: secrets,
        grants: Vec::new(),
        overrides: HashMap::new(),
        cfg,
        started: Instant::now(),
    }));

    let listener = UnixListener::bind(&sock)
        .with_context(|| format!("binding {}", sock.display()))?;
    // Defense-in-depth; the approval gate is the real control.
    std::fs::set_permissions(&sock, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;

    let (tx, rx): (Sender<ServerMsg>, Receiver<ServerMsg>) = std::sync::mpsc::channel();
    {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || listen(listener, shared, tx));
    }

    let result = tui::run(shared, rx, &sock);
    let _ = std::fs::remove_file(&sock);
    result
}

fn listen(listener: UnixListener, shared: Arc<Mutex<Shared>>, tx: Sender<ServerMsg>) {
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let shared = Arc::clone(&shared);
        let tx = tx.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle(&conn, &shared, &tx) {
                let _ = tx.send(ServerMsg::Log { msg: format!("error: {e}"), deny: true });
            }
        });
    }
}

fn reply(conn: &UnixStream, v: Value) -> Result<()> {
    let mut line = v.to_string();
    line.push('\n');
    (&mut &*conn).write_all(line.as_bytes())?;
    Ok(())
}

fn handle(conn: &UnixStream, shared: &Mutex<Shared>, tx: &Sender<ServerMsg>) -> Result<()> {
    conn.set_read_timeout(Some(Duration::from_secs(30)))?;
    let who = PeerInfo::from_stream(conn);

    let mut line = String::new();
    BufReader::new(conn).read_line(&mut line)?;
    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => return reply(conn, json!({"ok": false, "error": format!("bad request: {e}")})),
    };

    match req {
        Request::Get { name } => handle_get(conn, shared, tx, &name, who),
        Request::Ls => {
            let mut sh = shared.lock().unwrap();
            sh.prune_grants();
            let secrets: Vec<Value> = sh
                .store
                .keys()
                .map(|name| {
                    let (policy, source) = sh.effective_policy(name);
                    let policy = match policy {
                        Policy::Auto => "auto",
                        Policy::Confirm => "confirm",
                    };
                    let (source, expires) = match source {
                        PolicySource::Config => ("config", None),
                        PolicySource::Override => ("override", sh.override_expiry(name)),
                    };
                    let grant = best_grant(&sh, name);
                    json!({
                        "name": name, "policy": policy, "source": source,
                        "expires": expires, "grant": grant,
                    })
                })
                .collect();
            reply(conn, json!({"ok": true, "secrets": secrets}))
        }
        Request::Status => {
            let mut sh = shared.lock().unwrap();
            sh.prune_grants();
            reply(
                conn,
                json!({
                    "ok": true,
                    "secrets": sh.store.len(),
                    "grants": sh.grants.len(),
                    "uptime_secs": sh.started.elapsed().as_secs(),
                }),
            )
        }
        Request::Reload => {
            tx.send(ServerMsg::ReloadReq).ok();
            reply(conn, json!({"ok": true, "note": "reload scheduled"}))
        }
    }
}

/// Longest remaining grant for a secret, human-formatted.
fn best_grant(sh: &Shared, name: &str) -> Option<String> {
    let now = Instant::now();
    let mut best: Option<GrantUntil> = None;
    for g in sh.grants.iter().filter(|g| g.name == name) {
        best = Some(match (best, g.until) {
            (None, g) => g,
            (Some(GrantUntil::Session), _) | (_, GrantUntil::Session) => GrantUntil::Session,
            (Some(GrantUntil::At(a)), GrantUntil::At(b)) => GrantUntil::At(a.max(b)),
        });
    }
    best.map(|g| match g {
        GrantUntil::Session => "session".to_string(),
        GrantUntil::At(t) => format_remaining(t.saturating_duration_since(now)),
    })
}

pub fn format_remaining(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

fn handle_get(
    conn: &UnixStream,
    shared: &Mutex<Shared>,
    tx: &Sender<ServerMsg>,
    name: &str,
    who: PeerInfo,
) -> Result<()> {
    let caller = who
        .ancestry
        .first()
        .map(|p| p.comm.clone())
        .unwrap_or_else(|| "?".into());
    let timeout;
    {
        let mut sh = shared.lock().unwrap();
        timeout = sh.cfg.request_timeout();
        if !sh.store.contains_key(name) {
            drop(sh);
            tx.send(ServerMsg::Log {
                msg: format!("DENY  {name} ← {caller}({}) — unknown secret", who.pid),
                deny: true,
            })
            .ok();
            return reply(conn, json!({"ok": false, "error": format!("unknown secret: {name}")}));
        }
        let released = match sh.effective_policy(name) {
            (Policy::Auto, PolicySource::Override) => Some("auto*"),
            (Policy::Auto, PolicySource::Config) => Some("auto"),
            (Policy::Confirm, _) if sh.grant_active(name, &who) => Some("grant"),
            (Policy::Confirm, _) => None,
        };
        if let Some(why) = released {
            let value = sh.store.get(name).unwrap().to_string();
            drop(sh);
            tx.send(ServerMsg::Log {
                msg: format!("ALLOW {name} ← {caller}({}) [{why}]", who.pid),
                deny: false,
            })
            .ok();
            return reply(conn, json!({"ok": true, "value": value}));
        }
    }

    // Confirm path: park the request with the TUI and wait for the human.
    let (dtx, drx) = std::sync::mpsc::sync_channel::<Decision>(1);
    tx.send(ServerMsg::Request(PendingReq {
        name: name.to_string(),
        peer: who,
        received: Instant::now(),
        respond: dtx,
    }))
    .ok();

    match drx.recv_timeout(timeout + Duration::from_secs(HANDLER_GRACE_SECS)) {
        Ok(Decision::Allow) => {
            let value = shared.lock().unwrap().store.get(name).map(|v| v.to_string());
            match value {
                Some(v) => reply(conn, json!({"ok": true, "value": v})),
                None => reply(conn, json!({"ok": false, "error": "secret vanished on reload"})),
            }
        }
        Ok(Decision::Deny) => reply(conn, json!({"ok": false, "error": "denied by user"})),
        Err(_) => reply(conn, json!({"ok": false, "error": "request timed out unanswered"})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    // A pidfd for a live process must not read as dead; once the process exits
    // it must. This is the liveness signal `prune_grants` relies on to reap
    // pid-scoped grants the moment their process is gone.
    #[test]
    fn pidfd_tracks_process_exit() {
        let mut child = Command::new("sleep").arg("100").spawn().expect("spawn sleep");
        let scope = GrantScope::Pid {
            pid: child.id() as i32,
            comm: "sleep".to_string(),
        };
        let fd = pidfd_for(&scope).expect("pidfd_open on a live child");
        assert!(!pidfd_dead(&fd), "live process must not read as dead");

        child.kill().expect("kill child");
        child.wait().expect("reap child");
        assert!(pidfd_dead(&fd), "exited process must read as dead");
    }

    // Exe-scoped grants have no process to watch.
    #[test]
    fn exe_scope_has_no_pidfd() {
        assert!(pidfd_for(&GrantScope::Exe("/bin/true".into())).is_none());
    }

    // The integration point: a pid-scoped grant whose process has exited is
    // dropped by prune_grants, while an unrelated exe-scoped grant survives.
    #[test]
    fn prune_drops_grant_when_process_dies() {
        let mut child = Command::new("sleep").arg("100").spawn().expect("spawn sleep");
        let pid = child.id() as i32;
        let mut sh = Shared {
            store: SecretMap::new(),
            grants: vec![
                Grant {
                    name: "db".into(),
                    scope: GrantScope::Pid { pid, comm: "sleep".into() },
                    until: GrantUntil::Session,
                    watch: pidfd_for(&GrantScope::Pid { pid, comm: "sleep".into() }),
                },
                Grant {
                    name: "api".into(),
                    scope: GrantScope::Exe("/bin/true".into()),
                    until: GrantUntil::Session,
                    watch: None,
                },
            ],
            overrides: HashMap::new(),
            cfg: Config::default(),
            started: Instant::now(),
        };

        sh.prune_grants();
        assert_eq!(sh.grants.len(), 2, "both grants live while the process runs");

        child.kill().expect("kill child");
        child.wait().expect("reap child");
        sh.prune_grants();
        assert_eq!(sh.grants.len(), 1, "the pid grant is pruned once its process dies");
        assert_eq!(sh.grants[0].name, "api", "the exe grant survives");
    }
}
