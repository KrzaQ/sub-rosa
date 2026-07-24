use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, ensure, Context, Result};
use zeroize::Zeroizing;

/// Decrypted secrets held by the agent. BTreeMap for stable ordering.
pub type SecretMap = BTreeMap<String, Zeroizing<String>>;

/// Decrypt the store. gpg-agent handles the pinentry, so this must run on a
/// normal (non-TUI) terminal.
pub fn load(path: &Path) -> Result<SecretMap> {
    let raw = load_raw(path)?;
    Ok(raw.into_iter().map(|(k, v)| (k, Zeroizing::new(v))).collect())
}

/// Decrypt to plain strings — for the management commands that re-encrypt.
pub fn load_raw(path: &Path) -> Result<BTreeMap<String, String>> {
    ensure!(
        path.exists(),
        "store not found: {} — create it with `rosa init` or `rosa add NAME`",
        path.display()
    );
    let out = Command::new("gpg")
        .args(["--quiet", "--decrypt"])
        .arg(path)
        .stderr(Stdio::inherit())
        .output()
        .context("running gpg — is it installed?")?;
    ensure!(out.status.success(), "gpg failed to decrypt {}", path.display());
    serde_json::from_slice(&out.stdout)
        .with_context(|| format!("{} is not a JSON object of NAME:value", path.display()))
}

/// Re-encrypt the store atomically (encrypt to a temp file, then rename).
pub fn save(path: &Path, map: &BTreeMap<String, String>, recipient: Option<&str>) -> Result<()> {
    // The default store now lives under ~/.config/rosa, which a fresh machine may not have yet;
    // gpg's `-o` can't create it, so make the parent first.
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp.gpg");
    let mut cmd = Command::new("gpg");
    cmd.args(["--quiet", "--yes", "--batch", "--encrypt", "-o"]).arg(&tmp);
    match recipient {
        Some(r) => cmd.args(["-r", r]),
        None => cmd.arg("--default-recipient-self"),
    };
    let mut child = cmd
        .stdin(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("running gpg — is it installed?")?;
    let json = serde_json::to_string_pretty(map)?;
    child.stdin.take().unwrap().write_all(json.as_bytes())?;
    if !child.wait()?.success() {
        let _ = std::fs::remove_file(&tmp);
        bail!(
            "gpg failed to encrypt{}",
            if recipient.is_none() {
                " — no default key? set gpg_recipient in the config"
            } else {
                ""
            }
        );
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("moving {} into place", tmp.display()))?;
    Ok(())
}
