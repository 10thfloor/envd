# envd

[![CI](https://github.com/10thfloor/envd/actions/workflows/ci.yml/badge.svg)](https://github.com/10thfloor/envd/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/10thfloor/envd.svg)](https://pkg.go.dev/github.com/10thfloor/envd)

A daemon that manages **all** of a project's per-environment configuration — and
injects it into your shell automatically as you switch between `dev` / `staging` /
`prod`. Not just secrets: connection strings, API endpoints, feature flags, log
levels, ports — anything your app reads from the environment.

You reference `process.env.DATABASE_URL` (or `LOG_LEVEL`, or `FEATURE_X`) in your
code as normal. Whichever environment is active, `envd` fills it in at process
launch — switch environments and every newly-launched process picks up the new
config. Everything is stored encrypted; secret values are never printed, and
ordinary settings ride the exact same rails.

> **Status: v0.6 — usable, early.** It manages any static configuration — secrets
> and plain settings alike. The full local workflow is implemented and tested:
> per-environment injection, layered environments, reference interpolation, value
> generators, reflog-style history with rollback, a code-aware doctor, zero-step
> onboarding, and an interactive TUI. The provider OAuth machinery is built and
> tested, but no concrete vendor adapters ship yet (each needs its own OAuth app).
> Remote platform sync (Fly/Cloudflare/Encore) is deferred.
>
> The daemon core is pure Go stdlib; only the TUI pulls in third-party libraries
> (Bubble Tea). Everything ships as one binary.

## How it works

- **One daemon, one command.** `envd start` runs a background daemon (unix socket
  at `~/.envd/daemon.sock`). It holds your decrypted vaults in memory and answers
  one query per shell prompt.
- **A direnv-style shell hook** does delivery. When you're in a connected project
  directory, the hook injects that environment's vars at `exec` time. Switch
  environments and every newly-launched process picks up the new values. (Injecting
  env into an *already-running* process is impossible on macOS/Linux — the hook is
  the only no-disk, no-app-change mechanism.)
- **Name-match engine.** The vault stores `{env → {VAR → value}}`. If the active
  environment defines a variable your code reads, you get it. Nothing to wire up.
- **Encrypted vault, safe to commit.** Each project has `./.envd/vault.json`,
  encrypted with AES-256-GCM. The 32-byte key lives in the **macOS Keychain**
  (never committed), or is derived from `ENVD_PASSPHRASE` via PBKDF2 for headless
  use. The encrypted file is the single source of truth and travels with the repo.

## Install

With Go 1.24+:

```sh
go install github.com/10thfloor/envd@latest
```

Or build from source:

```sh
git clone https://github.com/10thfloor/envd
cd envd
go build -o envd .
mv envd /usr/local/bin/   # or anywhere on your PATH
```

> Platform support: developed and tested on **macOS** (the Keychain-backed key
> path). It builds and runs on Linux using the `ENVD_PASSPHRASE` (PBKDF2) key
> path. Windows is untested.

## Quick start

```sh
# 1. Start the daemon (once per machine; backgroundable)
envd start &

# 2. Add the shell hook (once)
echo 'eval "$(envd hook zsh)"' >> ~/.zshrc   # or: envd hook bash
exec zsh

# 3. Register a project (starts with a single `dev` environment)
cd ~/my-app
envd connect            # asks for a name; environments default to just `dev`

# 4. Add more environments whenever you need them
envd env add staging
envd env add prod
envd env ls             # dev, staging, prod  (* marks the active one)

# 5. Give them values (read from stdin — never in your shell history)
cat db-dev-url.txt   | envd set DATABASE_URL --env dev
cat db-stg-url.txt   | envd set DATABASE_URL --env staging

# 6. Switch environments — instantly reflected in new processes
envd use staging        # your prompt shows (envd:staging via $ENVD_ENV)
npm run dev             # sees the staging DATABASE_URL
envd use dev            # back to dev
```

## Commands

| Command | What it does |
|---|---|
| `envd start` | Run the daemon (once per machine). |
| `envd hook <zsh\|bash>` | Print the shell hook to add to your rc file. |
| `envd connect` | Register the current directory as a project (starts with `dev`). |
| `envd connect <provider>` | OAuth-connect a provider adapter and import its values. |
| `envd use <env>` | Set the active environment for this project. |
| `envd env add\|rm\|ls [name]` | Add, remove, or list environments. |
| `envd set <KEY> [--env e]` | Store a value (read from stdin). `--env base` targets the shared layer. |
| `envd unset <KEY> [--env e]` | Delete a value. |
| `envd history [--env e] [--key K] [-n N]` | Show the project's change log (reflog). |
| `envd restore <seq>` | Roll back the change with that history seq. |
| `envd undo` | Roll back the most recent change. |
| `envd diff <envA> <envB>` | Show which keys differ between two environments (values masked). |
| `envd doctor [--env e] [--example]` | Scan code for env-var refs; flag missing/empty/placeholder/unused. `--example` writes `.env.example`. |
| `envd import [file] [--env e]` | Import a `.env` file (default `./.env`) into an environment. |
| `envd adopt` | Register an existing on-disk vault (e.g. a freshly-cloned repo). |
| `envd tui` | Open the interactive vault/environment manager. |
| `envd status` | Show projects, active envs, var counts, and active shell sessions. |

## Layered environments (set once, override rarely)

Every vault has a shared **`base`** layer that all environments inherit. An
environment's effective config is `base` overlaid with its own values (the env
wins). So you set the things that are the same everywhere once:

```sh
echo info                       | envd set LOG_LEVEL --env base   # shared
echo https://api.example.com    | envd set API_BASE  --env base   # shared
echo https://api.prod.example.com | envd set API_BASE --env prod  # override in prod only
```

Now `dev` and `staging` get `API_BASE=https://api.example.com` for free; only
`prod` differs. `envd diff dev prod` shows exactly what's different:

```
app  dev ↔ prod  (values masked)
  only in dev:  DATABASE_URL
  only in prod:  —
  differs:      API_BASE
  identical:    1 key(s)
```

In the TUI, `base` is the first entry in the environments pane; inherited values
are tagged `base` and overrides `ovr`. Editing an inherited value in an env
creates an override; removing it reverts to the base value.

## Interactive TUI

`envd tui` opens a full-screen manager for your vaults (requires the daemon to be
running):

- **Picker** → pick a project. **Browse** → environments on the left, that
  environment's variables in a table on the right.
- Values are **masked by default**; press `r` to reveal (which also *resolves*
  references — see below). Reference-backed values are flagged with `→`.
- Edit in place: `n` new variable, `e` edit value, `d` delete, on the variables
  pane; `a` set-active, `A` add-env, `X` remove-env on the environments pane.
- `tab` switches panes · `p` back to the picker · `q` quits.

Every edit goes through the daemon and is written straight to the encrypted vault.

## References (1Password-style interpolation)

A stored value can be a *reference* that's resolved at inject time, so the real
secret lives elsewhere and is never duplicated:

| Scheme | Resolves to |
|---|---|
| `op://vault/item/field` | A live read from 1Password via the `op` CLI. The secret never enters envd's vault. |
| `envd://<env>/<KEY>` | Another environment's value in the same project (DRY). |

Use either as the whole value, or embed with `${…}`:

```
DATABASE_URL = postgres://app:${op://Private/db/password}@db.internal/app
API_BASE     = envd://shared/API_BASE
```

Resolution is recursive with cycle protection, and **fails closed**: a reference
that can't be resolved (e.g. `op` not signed in) is simply omitted from the
injected environment, and the TUI shows the error when you reveal it.

### Generators (`gen://…`)

A value of `gen://…` is **materialized once, at set time** — the concrete value is
stored, so it's stable forever after (and never re-rolls on read):

```sh
printf gen://random/48   | envd set SESSION_SECRET --env prod   # base64 random
printf gen://uuid        | envd set INSTANCE_ID                  # uuid v4
printf 'redis://${gen://password/16}@cache' | envd set CACHE_URL # embedded
```

Kinds: `random/N` (base64), `hex/N`, `uuid`, `password/N` (alphanumeric).

## History & rollback (`envd history` / `restore` / `undo`)

Every change to a project's vault is recorded in a reflog-like log with the prior
state, so you can always roll back:

```sh
envd history
# [12] 05-25 09:48  set     dev/DATABASE_URL   ••• → ••••••
# [11] 05-25 09:47  unset   dev/OLD_TOKEN      •••
# [10] 05-25 09:40  rmenv   qa                 (3 keys)

envd restore 12     # revert DATABASE_URL to its value before change #12
envd undo           # revert the most recent change
envd restore 10     # bring back the removed `qa` environment, with its contents
```

Values are masked in the log. Restores are themselves recorded, so an `undo` of a
restore puts things back. In the TUI, press `h` to browse history and `enter`/`R`
to restore the selected entry.

## Doctor (`envd doctor`)

Scans your source for env-var references (`process.env.X`, `import.meta.env.X`,
`Deno.env.get(...)`, `Bun.env.X`, `os.Getenv(...)`, `os.environ[...]`) and
reconciles them against an environment's effective config:

```
app/dev — scanned 37 file(s), 12 var(s) referenced
  missing:     STRIPE_KEY
  empty:       SMTP_PASS
  placeholder: API_BASE
  unused:      LEGACY_FLAG
```

- `--env <e>` checks a specific environment (default: active).
- `--example` writes a `.env.example` listing every referenced key (no values).
- In the TUI, press `D` to run it for the current environment.

`node_modules`, `.git`, `dist`, and friends are skipped.

## Onboarding (zero steps)

- **Auto-adopt:** clone a repo that already has `.envd/vault.json`, `cd` into it,
  and (if the decryption key is available) the daemon registers it automatically
  and starts injecting — no `connect` needed. `envd adopt` does it explicitly.
- **Import:** `envd import .env` absorbs an existing dotenv file into an
  environment (`--env base` to put shared keys in the base layer).

## Providers & custom adapters

`envd connect <provider>` runs an OAuth authorization-code flow and pulls a
provider's per-environment values straight into the vault — connect once, never
paste a key. The flow (loopback callback + token exchange) is implemented and
tested; **no concrete vendor adapters ship yet**, because each needs its own
registered OAuth app and client ID.

Adding one is small — implement the `Adapter` interface and register it in `init()`:

```go
type Adapter interface {
    Name() string
    OAuth() OAuthConfig
    ListResources(ctx context.Context, accessToken string) ([]Resource, error)
    FetchSecrets(ctx context.Context, accessToken, resourceID, envName string) (map[string]string, error)
}
```

The generic OAuth runner (`runOAuth`) is provided; an adapter only supplies its
endpoints, client ID, and the resource→secret mapping. New vendors are added
in-source and recompiled — the daemon core stays dependency-free. The same shape
will later grow a `PlatformAdapter` for the deferred deployment-sync side.

## Showing the active environment in your prompt

The hook exports `ENVD_ENV`. Add it to your prompt so the current environment is
unmistakable:

```sh
# zsh
PROMPT='%~ ${ENVD_ENV:+(envd:$ENVD_ENV) }%# '
```

## Security

- All values are encrypted at rest (AES-256-GCM) — secrets are protected and plain
  config rides along the same way — and only ever exist decrypted in the daemon's
  memory and in the target process's environment.
- The vault key is never committed: macOS Keychain by default, or a PBKDF2-derived
  key from `ENVD_PASSPHRASE` (600k iterations) for CI/Linux.
- A wrong key fails closed: GCM authentication rejects it, the project shows as
  `locked`, and the shell hook simply injects nothing (your prompt never breaks).
- The committed `./.envd/vault.json` holds everything (values + provider tokens),
  all encrypted. This is a deliberate tradeoff — anyone with both the repo *and*
  the decryption key has the secrets, so guard Keychain access / the passphrase
  accordingly.

envd is explicit about what it does **not** protect against, too. Read
[`SECURITY.md`](SECURITY.md) before trusting it with real secrets, and report
vulnerabilities privately (not via public issues).

## Design & contributing

See [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture and the decisions
behind it, and [`CONTRIBUTING.md`](CONTRIBUTING.md) to hack on it — the daemon core
is kept dependency-free; the TUI is the only place third-party libraries live.

## License

[MIT](LICENSE) © 2026 Mackenzie Kieran
