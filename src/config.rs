use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Per-secret release policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Release without asking while the agent is running.
    Auto,
    /// Ask on the agent's tty every time (unless an approval grant is active).
    Confirm,
}

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
}

pub fn config_dir() -> PathBuf {
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(d) if !d.is_empty() => PathBuf::from(d).join("rosa"),
        _ => home().join(".config/rosa"),
    }
}

pub fn runtime_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => PathBuf::from(format!("/run/user/{}", unsafe { nix::libc::getuid() })),
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
