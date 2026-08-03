use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use serde::Deserialize;

/// Per-secret release policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Release without asking while the agent is running.
    Auto,
    /// Ask on the agent's tty every time (unless an approval grant is active).
    Confirm,
}

impl Policy {
    pub fn as_str(self) -> &'static str {
        match self {
            Policy::Auto => "auto",
            Policy::Confirm => "confirm",
        }
    }
}

/// The `[policy]` key holding the fallback for unlisted secrets — and so a name
/// no secret may take. Writing a policy for a secret called `default` would not
/// set that secret's policy; it would change every unlisted secret's.
pub const RESERVED_POLICY_NAME: &str = "default";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Path to the gpg-encrypted JSON store ({"NAME":"value"}).
    store: Option<String>,
    /// Recipient for re-encryption by add/rm/edit. Falls back to
    /// gpg's --default-recipient-self.
    pub gpg_recipient: Option<String>,
    /// Seconds before an unanswered approval request is denied.
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,
    /// Durations offered in the approval menu ("30s", "5m", "1h", ...).
    #[serde(default = "default_durations")]
    pub grant_durations: Vec<String>,
    /// Process names that get a warning banner when found in the
    /// requester's ancestry (e.g. ["claude", "node"]).
    #[serde(default)]
    pub flag_ancestors: Vec<String>,
    /// name -> "auto" | "confirm". The key "default" sets the fallback.
    #[serde(default)]
    policy: HashMap<String, String>,
}

fn default_timeout() -> u64 {
    60
}

fn default_durations() -> Vec<String> {
    ["5m", "15m", "1h"].map(String::from).to_vec()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            store: None,
            gpg_recipient: None,
            request_timeout_secs: default_timeout(),
            grant_durations: default_durations(),
            flag_ancestors: Vec::new(),
            policy: HashMap::new(),
        }
    }
}

impl Config {
    pub fn load() -> Result<Config> {
        let path = config_dir().join("config.toml");
        if !path.exists() {
            return Ok(Config::default());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn store_path(&self) -> PathBuf {
        match &self.store {
            Some(s) => expand_tilde(s),
            None => config_dir().join("secrets.json.gpg"),
        }
    }

    /// Override the store path (from the `--store` flag), winning over both the config's
    /// `store` key and the built-in default. Kept as the same `store` field so `store_path`
    /// stays the one place that resolves it.
    pub fn set_store(&mut self, path: PathBuf) {
        self.store = Some(path.to_string_lossy().into_owned());
    }

    pub fn policy_for(&self, name: &str) -> Policy {
        let raw = self
            .policy
            .get(name)
            .or_else(|| self.policy.get("default"))
            .map(String::as_str)
            .unwrap_or("confirm");
        match raw {
            "auto" => Policy::Auto,
            _ => Policy::Confirm,
        }
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }

    /// The in-memory half of a persisted policy change, so a live agent matches
    /// what `persist_policy` just wrote.
    pub fn set_policy(&mut self, name: &str, policy: Policy) {
        self.policy.insert(name.to_string(), policy.as_str().to_string());
    }
}

pub fn config_dir() -> PathBuf {
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(d) if !d.is_empty() => PathBuf::from(d).join("rosa"),
        _ => home().join(".config/rosa"),
    }
}

/// Create a directory we are about to put secrets (or the socket) in, at
/// `0700`. Only the directories we create get the mode — an existing one is
/// the user's business, and a permissive umask shouldn't decide this for us.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .with_context(|| format!("securing {}", dir.display()))
}

/// Write `name = policy` into config.toml's `[policy]` table, preserving the
/// comments and layout of a hand-maintained file.
///
/// Two processes write this file — the agent's TUI and `rosa add` — so the
/// whole read-modify-write runs under an exclusive lock. The rendered result is
/// parsed back and checked before it replaces the original: a config that no
/// longer loads is a config that no longer gates secret release, so anything
/// unexpected leaves the file untouched and reports instead.
pub fn persist_policy(name: &str, policy: Policy) -> Result<()> {
    persist_policy_at(&config_dir().join("config.toml"), name, policy)
}

fn persist_policy_at(path: &Path, name: &str, policy: Policy) -> Result<()> {
    use nix::fcntl::{Flock, FlockArg};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    ensure!(
        name != RESERVED_POLICY_NAME,
        "`{RESERVED_POLICY_NAME}` is the [policy] fallback key, not a secret name"
    );
    if let Some(dir) = path.parent() {
        ensure_private_dir(dir)?;
    }

    let handle = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let mode = handle.metadata()?.permissions().mode() & 0o777;
    let _lock = Flock::lock(handle, FlockArg::LockExclusive)
        .map_err(|(_, e)| e)
        .with_context(|| format!("locking {}", path.display()))?;

    let mut text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .with_context(|| format!("parsing {}", path.display()))?;

    // A commented-out [policy] is invisible to toml_edit, and appending a second
    // header would be a duplicate-key parse error — so uncomment it by hand.
    if doc.get("policy").is_none() {
        if let Some(uncommented) = uncomment_policy_header(&text) {
            text = uncommented;
            doc = text
                .parse()
                .with_context(|| format!("parsing {}", path.display()))?;
        }
    }

    let table = doc
        .entry("policy")
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()))
        .as_table_mut()
        .with_context(|| {
            format!("[policy] in {} is not a plain table — edit it by hand", path.display())
        })?;
    table[name] = toml_edit::value(policy.as_str());
    let rendered = doc.to_string();

    // Confirm the result before it replaces a working config.
    let parsed: toml::Value = toml::from_str(&rendered)
        .with_context(|| format!("the edit would make {} unparseable", path.display()))?;
    ensure!(
        parsed.get("policy").and_then(|p| p.get(name)).and_then(|v| v.as_str())
            == Some(policy.as_str()),
        "the edit did not take effect in {} — leaving it unchanged",
        path.display()
    );
    toml::from_str::<Config>(&rendered)
        .with_context(|| format!("the edit would make {} invalid — leaving it unchanged", path.display()))?;

    let tmp = path.with_extension("toml.tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(rendered.as_bytes())?;
    f.set_permissions(PermissionsExt::from_mode(mode))?;
    drop(f);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("moving {} into place", tmp.display()))?;
    Ok(())
}

/// Strip the `#` from a commented-out `[policy]` header, leaving everything else
/// (indentation, the rest of the file) byte-identical. `None` when there is none.
fn uncomment_policy_header(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut found = false;
    for line in text.split_inclusive('\n') {
        match line.find('#') {
            Some(hash) if !found && line[hash + 1..].trim() == "[policy]" => {
                found = true;
                out.push_str(&line[..hash]);
                out.push_str(&line[hash + 1..]);
            }
            _ => out.push_str(line),
        }
    }
    found.then_some(out)
}

/// Where `rosa edit` stages the decrypted store for $EDITOR. Wants tmpfs, so
/// it prefers the session runtime dir — but plenty of setups never get one
/// (WSL, sshd without pam_systemd, containers), hence the /tmp fallback.
///
/// Unlike the socket path this probes the filesystem, which is fine: the
/// directory is used once, immediately, by a single process. Nobody has to
/// rendezvous with it.
pub fn edit_staging_dir() -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    let uid = unsafe { nix::libc::getuid() };
    let xdg = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty());
    let run = PathBuf::from(format!("/run/user/{uid}"));

    let dir = match xdg.map(PathBuf::from) {
        Some(d) if d.is_dir() => d,
        _ if run.is_dir() => run,
        _ => {
            let fallback = PathBuf::from(format!("/tmp/rosa-{uid}"));
            if !fallback.exists() {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&fallback)
                    .with_context(|| {
                        format!(
                            "no runtime dir ($XDG_RUNTIME_DIR unset, {} missing) \
                             and cannot create {}",
                            run.display(),
                            fallback.display()
                        )
                    })?;
            }
            fallback
        }
    };

    // /tmp is a shared namespace, so this is load-bearing rather than
    // belt-and-braces: refuse a directory somebody else owns or left open.
    let md = std::fs::symlink_metadata(&dir)
        .with_context(|| format!("stat {}", dir.display()))?;
    ensure!(md.is_dir(), "{} is not a directory", dir.display());
    ensure!(md.uid() == uid, "{} is not owned by us", dir.display());
    ensure!(
        md.mode() & 0o077 == 0,
        "{} is accessible to other users (mode {:03o})",
        dir.display(),
        md.mode() & 0o777
    );

    if !is_memory_backed(&dir) {
        eprintln!(
            "rosa: warning: {} is not tmpfs — the decrypted store will touch disk",
            dir.display()
        );
    }
    Ok(dir)
}

fn is_memory_backed(dir: &Path) -> bool {
    use nix::sys::statfs::{statfs, TMPFS_MAGIC};

    match statfs(dir) {
        Ok(s) => s.filesystem_type() == TMPFS_MAGIC,
        // Can't tell; don't cry wolf.
        Err(_) => true,
    }
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("HOME not set"))
}

fn expand_tilde(s: &str) -> PathBuf {
    match s.strip_prefix("~/") {
        Some(rest) => home().join(rest),
        None => PathBuf::from(s),
    }
}

/// Parse "30s" / "5m" / "2h" / "1d"; a bare number means seconds.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, mult) = match s.as_bytes()[s.len() - 1] {
        b's' => (&s[..s.len() - 1], 1),
        b'm' => (&s[..s.len() - 1], 60),
        b'h' => (&s[..s.len() - 1], 3600),
        b'd' => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    num.parse::<u64>().ok().map(|n| Duration::from_secs(n * mult))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A scratch config path; the dir is left behind on failure so the actual
    /// bytes can be inspected.
    fn scratch(body: &str) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rosa-cfg-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("config.toml");
        if !body.is_empty() {
            std::fs::write(&path, body).expect("write fixture");
        }
        path
    }

    // The everyday shape: [policy] is the last table in the file, so its
    // trailing blank lines are document decor rather than a next header's
    // prefix. The new key must land after the last policy key, and every
    // comment must survive.
    #[test]
    fn appends_after_the_last_key_and_keeps_comments() {
        let path = scratch(
            "# top comment\n\
             request_timeout_secs = 60\n\
             \n\
             [policy]\n\
             # which secrets ask\n\
             default = \"confirm\"\n\
             OMBI_API_KEY = \"auto\"\n\
             \n",
        );
        persist_policy_at(&path, "NPM_TOKEN", Policy::Auto).expect("persist");
        let out = std::fs::read_to_string(&path).unwrap();
        assert!(out.contains("# top comment"), "comments dropped:\n{out}");
        assert!(out.contains("# which secrets ask"), "comments dropped:\n{out}");
        let keys: Vec<&str> = out
            .lines()
            .filter(|l| l.contains(" = "))
            .map(|l| l.trim())
            .collect();
        assert_eq!(
            keys.last().copied(),
            Some("NPM_TOKEN = \"auto\""),
            "new key not after the last policy key:\n{out}"
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    // A commented-out header must be uncommented, never duplicated: two
    // [policy] headers is a TOML parse error, which would leave the file that
    // gates secret release unloadable.
    #[test]
    fn uncomments_a_commented_out_section() {
        let path = scratch("request_timeout_secs = 60\n\n#[policy]\n#NPM_TOKEN = \"auto\"\n");
        persist_policy_at(&path, "GH_TOKEN", Policy::Confirm).expect("persist");
        let out = std::fs::read_to_string(&path).unwrap();
        assert_eq!(out.matches("[policy]").count(), 1, "duplicated header:\n{out}");
        assert!(out.contains("\n[policy]"), "header not uncommented:\n{out}");
        assert!(out.contains("#NPM_TOKEN"), "commented entry disturbed:\n{out}");
        let cfg: Config = toml::from_str(&out).expect("still parses");
        assert_eq!(cfg.policy_for("GH_TOKEN"), Policy::Confirm);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn creates_the_table_and_the_file_when_absent() {
        let path = scratch("request_timeout_secs = 60\n");
        persist_policy_at(&path, "GH_TOKEN", Policy::Auto).expect("persist into table-less file");
        let cfg: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(cfg.policy_for("GH_TOKEN"), Policy::Auto);

        let fresh = scratch("");
        persist_policy_at(&fresh, "GH_TOKEN", Policy::Auto).expect("persist into missing file");
        let md = std::fs::metadata(&fresh).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(md.permissions().mode() & 0o777, 0o600, "new config not private");
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        std::fs::remove_dir_all(fresh.parent().unwrap()).ok();
    }

    #[test]
    fn updates_in_place_without_duplicating() {
        let path = scratch("[policy]\ndefault = \"confirm\"\nGH_TOKEN = \"auto\"\n");
        persist_policy_at(&path, "GH_TOKEN", Policy::Confirm).expect("persist");
        let out = std::fs::read_to_string(&path).unwrap();
        assert_eq!(out.matches("GH_TOKEN").count(), 1, "duplicated key:\n{out}");
        let cfg: Config = toml::from_str(&out).unwrap();
        assert_eq!(cfg.policy_for("GH_TOKEN"), Policy::Confirm);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    // Shapes we cannot edit safely must leave the original untouched rather
    // than write something that no longer loads.
    #[test]
    fn refuses_rather_than_mangling() {
        let inline = "policy = { default = \"confirm\" }\n";
        let path = scratch(inline);
        assert!(persist_policy_at(&path, "GH_TOKEN", Policy::Auto).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), inline, "file was modified");

        let reserved = scratch("[policy]\ndefault = \"confirm\"\n");
        assert!(persist_policy_at(&reserved, RESERVED_POLICY_NAME, Policy::Auto).is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        std::fs::remove_dir_all(reserved.parent().unwrap()).ok();
    }
}
