# sub rosa

*Under the rose* — a secret-brokering agent with a human approval gate on its
own terminal. Built so that scripts (including ones an AI agent runs) can
request credentials without the secrets ever sitting in the ambient
filesystem or shell environment.

Romans hung a rose over the council table: whatever passed beneath it stayed
secret.

## How it works

```
┌ tmux window A (yours) ─────────┐        ┌ tmux window B (agent's) ──────┐
│ $ rosa serve                   │        │ $ rosa exec DB_URL -- ./deploy │
│ ┌ secret request ────────────┐ │  unix  │   (blocks…)                    │
│ │ secret : DB_URL            │◄┼─socket─┤                                │
│ │ ⚠ flagged ancestor: claude │ │        │                                │
│ │┌ grant to ────┐┌ action ──┐│ │        │                                │
│ ││tmux          ││allow once││ │        │                                │
│ ││└ zsh         ││for 5m    ││ │        │                                │
│ ││  └ claude ⚠  ││for 15m   ││ │        │                                │
│ ││    └ deploy  ││session   ││ │        │                                │
│ ││  (requester) ││deny      ││ │        │                                │
│ │└──────────────┘└──────────┘│ │        │                                │
│ └────────────────────────────┘ │        │                                │
└────────────────────────────────┘        └────────────────────────────────┘
```

- Secrets live **gpg-encrypted at rest** (`~/.config/rosa/secrets.json.gpg`
  by default — set `store` in the config or pass `--store` to override — a
  JSON object of `NAME: value`). They are decrypted once, into the agent's
  memory, when `rosa serve` starts.
- Values only leave the agent over a `0600` unix socket at
  `~/.config/rosa/rosa.sock`. No systemd user session required — rosa runs
  the same on a bare WSL or container shell with no `$XDG_RUNTIME_DIR`.
- `confirm`-policy secrets require a decision typed into the **agent's own
  terminal** — a channel the requesting process cannot reach. An AI agent can
  *trigger* a request; it cannot *answer* it.
- The approval dialog identifies the requester via `SO_PEERCRED` and shows
  its full process ancestry (`/proc` ppid chain), with a red banner when a
  configured name like `claude` appears in the chain.
- The approval menu has two columns: **who** gets the grant (a row in the
  process tree) and **for how long** (once / 5m / 15m / 1h / until the agent
  exits). Selecting the *requester* scopes the grant to its exe path, so
  re-runs of the same script keep working; selecting an *ancestor* (say,
  one claude session) scopes it to that live pid — any request descending
  from that process passes, and the grant dies with it. Unanswered requests
  are auto-denied after `request_timeout_secs`.

## Install

```sh
cargo install --path .        # installs the `rosa` binary
mkdir -p ~/.config/rosa && cp config.example.toml ~/.config/rosa/config.toml
rosa init                     # create the empty encrypted store
rosa add MY_TOKEN             # put something in it
```

## Usage

Run the agent in a dedicated tmux/screen window you keep visible:

```sh
rosa serve
```

From anywhere else:

```sh
# preferred: the value only ever exists in the child's environment
rosa exec DB_URL API_TOKEN -- ./deploy.sh

# for cases that genuinely need capture (least private — lands in your shell)
FOO=$(rosa get FOO)

rosa ls          # names + policies + active grants (never values)
rosa status      # secret/grant counts, uptime
rosa reload      # re-read the store without restarting
rosa sock        # print the socket path (for scripts and tooling)

rosa add NAME    # value typed hidden on your tty, then re-encrypted
rosa rm NAME
rosa edit        # decrypt → $EDITOR (plaintext only in tmpfs) → re-encrypt
```

Agent keys: `←/→` switch column, `↑/↓` select, `Enter` apply (`y` = allow
once, `n`/`Esc` = deny); outside a prompt: `r` reload store, `c` clear all
grants, `q` quit.

## Wire protocol

Scripts don't have to shell out to `rosa get` — the socket speaks
newline-delimited JSON, one request per connection:

```
→ {"op":"get","name":"DB_URL"}
← {"ok":true,"value":"postgres://…"}        # or
← {"ok":false,"error":"denied by user"}
```

Other ops: `{"op":"ls"}` → `{"ok":true,"secrets":[{"name":…,"policy":…,
"grant":…}]}`, `{"op":"status"}` → counts and uptime, `{"op":"reload"}`.

- The socket is `$ROSA_SOCK`, defaulting to
  `${XDG_CONFIG_HOME:-$HOME/.config}/rosa/rosa.sock`. `rosa sock` prints the
  resolved path, so tooling can ask instead of re-deriving it.
- A confirm-gated `get` blocks until the human decides — up to
  `request_timeout_secs` (+5s grace). Read without a socket timeout, or
  with a generous one.
- Unknown request fields are ignored, so clients may send extra context;
  any future breaking change will introduce an explicit version field.
- Connecting directly actually improves the approval prompt: `SO_PEERCRED`
  then identifies your script (`python3 ./deploy.py`) as the requester
  rather than the `rosa` client binary.

Drop-in clients live in [examples/](examples/): Python, Ruby, and POSIX
shell (socat + jq).

## Configuration

See [config.example.toml](config.example.toml). Policies are per secret:
`auto` releases freely while the agent runs (for low-stakes tokens);
`confirm` — the default — asks every time unless a grant is active.

`ROSA_SOCK` overrides the socket path (default
`${XDG_CONFIG_HOME:-$HOME/.config}/rosa/rosa.sock`).

## Threat model, honestly

This tool controls **release**, not containment:

- Once a value is released into a child process, anything running as your
  uid can read `/proc/<pid>/environ` or ptrace it. The gate stops
  *unattended* access; it cannot stop you approving a request whose ultimate
  consumer was obscured by a wrapper.
- The ancestry display is decision context, not authentication.
- Prefer scoped, short-lived credentials so a leak has a small blast
  radius. The confirm gate plus a 15-minute token beats the gate alone.
- Rust avoids the worst string-copying sins and the store is held in
  `Zeroizing` buffers, but values pass through JSON parsing and socket
  buffers; memory hygiene is best-effort, not guaranteed (no `mlockall`
  yet).

## Future work

- Auto-relock: drop the decrypted store after N minutes idle, re-prompt the
  gpg passphrase on next use.
- Ancestor-based policy (auto-deny or force-confirm when `claude` is in the
  chain, regardless of per-secret policy).
- `mlockall` + locked memory pages for the store.
