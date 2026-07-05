pub mod peer;
pub mod tui;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
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
}

/// State shared between connection-handler threads and the TUI thread.
pub struct Shared {
    pub store: SecretMap,
    pub grants: Vec<Grant>,
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
        self.grants
            .retain(|g| !matches!(g.until, GrantUntil::At(t) if t <= now));
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
                    let policy = match sh.cfg.policy_for(name) {
                        Policy::Auto => "auto",
                        Policy::Confirm => "confirm",
                    };
                    let grant = best_grant(&sh, name);
                    json!({"name": name, "policy": policy, "grant": grant})
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
        let released = match sh.cfg.policy_for(name) {
            Policy::Auto => Some("auto"),
            Policy::Confirm if sh.grant_active(name, &who) => Some("grant"),
            Policy::Confirm => None,
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
