use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::config::Config;
use crate::protocol::{sock_path, Request};

pub fn call(req: &Request) -> Result<Value> {
    let path = sock_path();
    let mut stream = UnixStream::connect(&path)
        .with_context(|| format!("agent not running? (no socket at {})", path.display()))?;
    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;

    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply)?;
    if reply.is_empty() {
        bail!("agent closed the connection without replying");
    }
    let v: Value = serde_json::from_str(&reply).context("bad reply from agent")?;
    if !v["ok"].as_bool().unwrap_or(false) {
        bail!("{}", v["error"].as_str().unwrap_or("unknown error"));
    }
    Ok(v)
}

fn fetch(name: &str) -> Result<String> {
    let v = call(&Request::Get { name: name.to_string() })?;
    match v["value"].as_str() {
        Some(s) => Ok(s.to_string()),
        None => bail!("agent reply missing value"),
    }
}

/// `rosa get NAME` — prints the value, no trailing newline. Least private
/// path (the value lands in the calling shell); prefer `exec`.
pub fn get(name: &str) -> Result<()> {
    print!("{}", fetch(name)?);
    std::io::stdout().flush()?;
    Ok(())
}

/// `rosa exec NAME... -- cmd args` — becomes cmd with the secrets in its
/// environment; the values never exist in the invoking shell.
pub fn exec(names: &[String], cmd: &[String]) -> Result<()> {
    let mut env = Vec::new();
    for name in names {
        env.push((name.clone(), fetch(name)?));
    }
    let err = Command::new(&cmd[0]).args(&cmd[1..]).envs(env).exec();
    bail!("exec {}: {}", cmd[0], err);
}

/// `rosa ls` — names and policies from the agent; falls back to decrypting
/// the store directly when no agent is running.
pub fn ls(cfg: &Config) -> Result<()> {
    match call(&Request::Ls) {
        Ok(v) => {
            for s in v["secrets"].as_array().map(Vec::as_slice).unwrap_or_default() {
                let name = s["name"].as_str().unwrap_or("?");
                let policy = s["policy"].as_str().unwrap_or("?");
                match s["grant"].as_str() {
                    Some(g) => println!("{name}\t{policy}\tgranted:{g}"),
                    None => println!("{name}\t{policy}"),
                }
            }
        }
        Err(e) => {
            eprintln!("rosa: {e}; reading the store directly");
            for (name, _) in crate::store::load_raw(&cfg.store_path())? {
                let policy = match cfg.policy_for(&name) {
                    crate::config::Policy::Auto => "auto",
                    crate::config::Policy::Confirm => "confirm",
                };
                println!("{name}\t{policy}");
            }
        }
    }
    Ok(())
}

pub fn status() -> Result<()> {
    let v = call(&Request::Status)?;
    println!(
        "secrets: {}  grants: {}  uptime: {}s",
        v["secrets"], v["grants"], v["uptime_secs"]
    );
    Ok(())
}

pub fn reload() -> Result<()> {
    call(&Request::Reload)?;
    println!("reload requested");
    Ok(())
}
