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

> **Status: v0.8 — usable, early.** It manages any static configuration — secrets
> and plain settings alike. The full local workflow is implemented and tested:
> per-environment injection, layered environments, reflog-style history with
> rollback, a code-aware doctor, value generators, zero-step onboarding, an
> interactive TUI, a **100+ service catalog** (`envd add stripe`, `neon`, …), and
> **live references into 1Password, Vault, AWS, GCP, Azure, Doppler, Infisical, and
> more** via their CLIs. Remote platform *sync* (pushing to Fly/Cloudflare/Encore)
> is the main deferred piece.
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
envd init               # asks for a name; environments default to just `dev`

# 4. Add more environments whenever you need them
envd env add staging
envd env add prod
envd env ls             # dev, staging, prod  (* marks the active one)

# 5. Give them values — type at a hidden prompt (nothing in shell history),
#    or pipe from a file/command for scripts
envd set DATABASE_URL --env dev          # prompts: value for DATABASE_URL (hidden)
cat db-stg-url.txt | envd set DATABASE_URL --env staging

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
| `envd init` | Register the current directory as a project (starts with `dev`). |
| `envd connect <provider>` | OAuth-connect a provider adapter and import its values. |
| `envd use <env>` | Set the active environment for this project. |
| `envd env add\|rm\|ls [name]` | Add, remove, or list environments. |
| `envd catalog [query]` | List/search known SaaS services and their env vars. |
| `envd add <service> [--env e]` | Scaffold a service's expected keys (e.g. `stripe`, `neon`). |
| `envd set <KEY> [--env e] [--force]` | Store a value — hidden prompt on a terminal, or piped stdin. Prompts before overwriting. `--env base` = shared layer. |
| `envd unset <KEY> [--env e]` | Delete a value. |
| `envd history [--env e] [--key K] [-n N]` | Show the project's change log (reflog). |
| `envd restore <seq>` | Roll back the change with that history seq. |
| `envd undo` | Roll back the most recent change. |
| `envd diff <envA> <envB>` | Show which keys differ between two environments (values masked). |
| `envd doctor [--env e] [--example]` | Scan code for env-var refs; flag missing/empty/placeholder/unused. `--example` writes `.env.example`. |
| `envd import [file] [--env e]` | Import a `.env` file (default `./.env`) into an environment. |
| `envd adopt` | Register an existing on-disk vault (e.g. a freshly-cloned repo). |
| `envd providers` | List supported provider reference schemes and CLI availability. |
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

## Service catalog (`envd add`)

envd ships a catalog of **100+ notable SaaS platforms and frameworks** and the
canonical environment variables each one expects — so you don't have to look them
up. `envd add <service>` scaffolds them into an environment:

```sh
envd add betterauth     # generates BETTER_AUTH_SECRET, defaults BETTER_AUTH_URL
envd add stripe         # creates STRIPE_SECRET_KEY / _PUBLISHABLE_KEY / _WEBHOOK_SECRET
envd add neon supabase  # (run separately) DB connection strings + keys
envd catalog ai         # search: openai, anthropic, huggingface, groq, mistral, …
```

For each variable, `add` either **generates** it (auth secrets), fills a **sensible
default** (callback URLs, regions), or leaves it **blank with a link** to where you
get it (`envd doctor` then flags the blanks). Coverage spans databases (Neon,
Supabase, PlanetScale, Turso, Upstash, Mongo, Firebase, Appwrite, Xata), auth
(Better Auth, Auth.js, Clerk, Auth0, WorkOS, Stytch, Kinde), payments (Stripe,
Paddle, Lemon Squeezy, Polar, Square), email/SMS (Resend, SendGrid, Postmark,
Mailgun, Twilio, …), AI & vector (OpenAI, Anthropic, Hugging Face, Groq, Mistral,
Gemini, Langfuse, Pinecone, Qdrant, …), backends & frameworks (Meteor, Restate,
Convex, Payload, Encore), platforms (Vercel, Cloudflare, Fly, Railway, AWS,
GitHub), observability/analytics (Sentry, PostHog, Datadog, Honeycomb, Segment,
…), CMS (Sanity, Contentful, Storyblok), search, jobs/queues (Temporal, QStash,
Inngest, Trigger.dev), realtime (Liveblocks, Stream, Pusher, Ably), maps (Mapbox,
Google Maps), feature flags, and more. Run `envd catalog` for the full list.

Scaffolded keys compose with references below — `envd add stripe`, then bind
`STRIPE_SECRET_KEY` to `op://…` or `aws-sm://…` instead of pasting it.

## References — pull from any provider

A stored value can be a *reference* that's resolved live at inject time, so the
real value lives in your existing secret manager and is never duplicated. Every
scheme except `envd://` works by shelling out to that vendor's **own CLI**, reusing
the auth you already have — no SDKs, no OAuth apps, no extra dependencies.

| Scheme | Source | Example |
|---|---|---|
| `op://` | 1Password (`op`) | `op://Private/db/password` |
| `vault://` | HashiCorp Vault (`vault`) | `vault://secret/myapp#db_pass` |
| `aws-sm://` | AWS Secrets Manager (`aws`) | `aws-sm://myapp/prod#DB_URL` |
| `aws-ssm://` | AWS SSM Parameter Store (`aws`) | `aws-ssm:///myapp/prod/db_url` |
| `gcp-sm://` | GCP Secret Manager (`gcloud`) | `gcp-sm://my-project/db-url` |
| `azure-kv://` | Azure Key Vault (`az`) | `azure-kv://my-vault/db-url` |
| `doppler://` | Doppler (`doppler`) | `doppler://DATABASE_URL` |
| `infisical://` | Infisical (`infisical`) | `infisical://prod/DATABASE_URL` |
| `pass://` / `gopass://` | password-store / gopass | `pass://db/prod/url` |
| `env://` | The daemon's own environment | `env://HOME_DB_URL` |
| `file://` | A file's contents | `file:///run/secrets/db_url` |
| `cmd://` | Run a command (needs `ENVD_ALLOW_EXEC=1`) | `cmd://my-tool get db-url` |
| `envd://` | Another environment in this project (DRY) | `envd://base/API_BASE` |

Run `envd providers` to see every scheme and whether its CLI is installed. Use a
reference as the whole value, or embed with `${…}`:

```
DATABASE_URL = postgres://app:${op://Private/db/password}@db.internal/app
SENTRY_DSN   = aws-sm://myapp/prod#SENTRY_DSN
API_BASE     = envd://base/API_BASE
```

Resolution is recursive with cycle protection, cached for 60s (so injecting on
every shell prompt doesn't hammer the provider), and **fails closed**: a reference
that can't be resolved (CLI missing, not signed in) is simply omitted from the
injected environment, and the TUI surfaces the error when you reveal it. Literal
URL-ish values like `postgres://…` are left untouched — only known schemes resolve.

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

## Providers — two paths

**1. References (shipping, broad).** The [References](#references--pull-from-any-provider)
table above is the primary integration: a value points at your existing secret
manager, and envd resolves it live via that vendor's CLI. This covers 1Password,
Vault, AWS, GCP, Azure, Doppler, Infisical, pass/gopass, and more today. Adding a
provider is a single entry in `providerList` — no SDK, no OAuth app, no dependency:

```go
{"doppler", "doppler", "Doppler", "doppler://NAME", func(arg string) (string, error) {
    return runCLI("doppler", "secrets", "get", arg, "--plain")
}},
```

**2. OAuth import (machinery, optional).** `envd connect <provider>` runs an OAuth
authorization-code flow and pulls a provider's values *into* the vault in bulk. The
flow (loopback callback + token exchange) is implemented and tested, but no concrete
OAuth adapters ship — each needs its own registered OAuth app and client ID.
Implement the `Adapter` interface (`Name` / `OAuth` / `ListResources` /
`FetchSecrets`) and `registerAdapter` it; the generic `runOAuth` runner does the
rest. The same shape will later grow a `PlatformAdapter` for the deferred
deployment-sync side.

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
- Values are entered via a **hidden prompt** (echo off) or piped stdin — never as a
  command argument, so they don't land in shell history or the process table.
  Overwrites require confirmation (or `--force`), so you can't clobber a value or a
  project's vault by accident.

envd is explicit about what it does **not** protect against, too. Read
[`SECURITY.md`](SECURITY.md) before trusting it with real secrets, and report
vulnerabilities privately (not via public issues).

## Design & contributing

See [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture and the decisions
behind it, and [`CONTRIBUTING.md`](CONTRIBUTING.md) to hack on it — the daemon core
is kept dependency-free; the TUI is the only place third-party libraries live.

## License

[MIT](LICENSE) © 2026 Mackenzie Kieran
