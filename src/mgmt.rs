use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;

use anyhow::{bail, ensure, Context, Result};

use crate::config::{edit_staging_dir, Config};
use crate::protocol::Request;
use crate::store;

/// `rosa init` — create an empty encrypted store so `serve` has something
/// to load on a fresh machine.
pub fn init(cfg: &Config) -> Result<()> {
    let path = cfg.store_path();
    ensure!(!path.exists(), "store already exists: {}", path.display());
    store::save(&path, &Default::default(), cfg.gpg_recipient.as_deref())?;
    println!("created empty store: {}", path.display());
    println!("add secrets with `rosa add NAME` (or `rosa edit`), then run `rosa serve`");
    Ok(())
}

/// `rosa add NAME` — value typed (hidden) on this tty, never argv or a pipe.
pub fn add(cfg: &Config, name: &str) -> Result<()> {
    let value = rpassword::prompt_password(format!("value for {name}: "))?;
    let again = rpassword::prompt_password("again: ")?;
    ensure!(value == again, "values do not match");
    ensure!(!value.is_empty(), "empty value");

    let path = cfg.store_path();
    let mut map = if path.exists() {
        store::load_raw(&path)?
    } else {
        Default::default()
    };
    let replaced = map.insert(name.to_string(), value).is_some();
    store::save(&path, &map, cfg.gpg_recipient.as_deref())?;
    println!("{} {name}", if replaced { "replaced" } else { "added" });
    notify_agent();
    Ok(())
}

pub fn rm(cfg: &Config, name: &str) -> Result<()> {
    let path = cfg.store_path();
    let mut map = store::load_raw(&path)?;
    ensure!(map.remove(name).is_some(), "no such secret: {name}");
    store::save(&path, &map, cfg.gpg_recipient.as_deref())?;
    println!("removed {name}");
    notify_agent();
    Ok(())
}

/// `rosa edit` — decrypt into a private tmpfs dir, open $EDITOR, validate,
/// re-encrypt, remove the plaintext.
pub fn edit(cfg: &Config) -> Result<()> {
    let path = cfg.store_path();
    let map = store::load_raw(&path)?;

    let tmp = edit_staging_dir()?.join(format!("rosa-edit-{}.json", std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(serde_json::to_string_pretty(&map)?.as_bytes())?;
    f.write_all(b"\n")?;
    drop(f);

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".into());
    let result = (|| -> Result<()> {
        loop {
            let status = Command::new(&editor).arg(&tmp).status()
                .with_context(|| format!("running {editor}"))?;
            ensure!(status.success(), "{editor} exited with an error");
            match serde_json::from_slice(&std::fs::read(&tmp)?) {
                Ok(new_map) => {
                    store::save(&path, &new_map, cfg.gpg_recipient.as_deref())?;
                    println!("store updated");
                    return Ok(());
                }
                Err(e) => {
                    eprint!("invalid JSON ({e}); re-edit? [Y/n] ");
                    std::io::stderr().flush()?;
                    let mut answer = String::new();
                    std::io::stdin().read_line(&mut answer)?;
                    if answer.trim().eq_ignore_ascii_case("n") {
                        bail!("edit aborted, store unchanged");
                    }
                }
            }
        }
    })();
    let _ = std::fs::remove_file(&tmp);
    result?;
    notify_agent();
    Ok(())
}

/// Best-effort: tell a running agent to re-read the store.
fn notify_agent() {
    match crate::client::call(&Request::Reload) {
        Ok(_) => println!("agent notified (reload)"),
        Err(_) => println!("no running agent to notify — it will pick this up on restart or `rosa reload`"),
    }
}
