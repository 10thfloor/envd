# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0] — 2026-05-25

### Added
- **`envd assimilate`** — bring an existing project under envd in one step. It:
  - discovers the conventional dotenv files (`.env`, `.env.local`, `.env.<mode>`,
    `.env.<mode>.local`), maps each onto envd's layers using standard dotenv
    precedence (`.env`/`.env.local` → `base`; `.env.<mode>` → that environment;
    `.local` variants override), hoists values shared by every environment into
    `base`, and skips template files (`.env.example`, `.env.vault`, …);
  - **scans the code for referenced env vars** (like `doctor`) and fills any the
    `.env` files didn't cover, using robust heuristics — first your current shell
    environment, then inline code defaults (`process.env.PORT || 3000`,
    `os.getenv("X", "default")`);
  - **warns** about referenced vars whose value it couldn't determine (stored
    blank for you to fill); ignores OS/shell vars like `PATH`/`HOME`;
  - writes everything into the vault, auto-creating the project (with the
    discovered environments) if it isn't registered. Existing values are preserved
    unless `--force`.
- **Drift detection (`envd sync` + TUI).** After assimilating, envd remembers the
  `.env` baseline and detects manual edits you make to those files — keys added,
  removed, or changed — and reconciles the vault on your confirmation. The diff is
  shown explicitly (added/changed/removed, values masked) and never applied without
  an OK, so it's never surprising. `envd sync` reviews + applies from the CLI
  (confirms first, or `--force`); the TUI shows a banner on open and a review
  screen under `S`. A fully-migrated project with no `.env` files is left alone (no
  spurious "remove everything").

### Fixed
- `envd doctor --example` now writes `.env.example` to the **project root** (the
  scanned directory) rather than the current working directory, so running it from
  a subdirectory no longer puts the file somewhere unexpected.

## [0.10.0] — 2026-05-25

### Changed
- **Renamed project registration to `envd init`** (was `envd connect`), so it no
  longer collides with `envd connect <provider>` (OAuth service connect). Bare
  `envd connect` now errors with a pointer to `envd init`.

## [0.9.0] — 2026-05-25

### Added
- **Hidden interactive prompt for `envd set`** — on a terminal it reads the value
  with echo off (nothing in shell history or argv), so you no longer need
  `echo …| envd set`. Piped stdin still works for scripts/CI.
- **Overwrite protection.** `envd set` refuses to overwrite an existing value
  unless you confirm (interactive y/N prompt, or `--force`; non-interactive
  requires `--force`). The TUI prompts on overwrite too. `envd import` skips
  existing keys unless `--force`. `envd connect` no longer silently clobbers a
  directory's existing vault — it asks first.

### Changed
- `set` reading the same value it already holds is a no-op (no prompt).

## [0.8.0] — 2026-05-25

### Added
- **Service catalog** — built-in knowledge of 100+ notable SaaS platforms and
  frameworks (Stripe, Neon, Supabase, Resend, Twilio, Hugging Face, Better Auth,
  Clerk, OpenAI, Anthropic, Vercel, Cloudflare, Sentry, Meteor, Restate, Convex,
  Langfuse, Mapbox, Sanity, Liveblocks, Temporal, …) and the canonical env vars
  each expects, grouped across databases, auth, payments, email/SMS, AI, platforms,
  backends/frameworks, observability, analytics, CMS, search, jobs, realtime, and more.
  - `envd add <service> [--env e]` scaffolds a service's keys into an environment:
    generates secrets (e.g. `BETTER_AUTH_SECRET`), applies sensible defaults (e.g.
    `BETTER_AUTH_URL`), and leaves must-provide secrets blank with a link to where
    to get them. Composes with provider references (fill via `op://`, `aws-sm://`…).
  - `envd catalog [query]` lists/searches the catalog, grouped by category.
- **Provider references for industry-standard config/secret sources.** Any value
  can be a reference resolved live at inject time by shelling out to the vendor's
  own CLI (reusing the auth you already have): `op://` (1Password), `vault://`
  (HashiCorp Vault), `aws-sm://` / `aws-ssm://` (AWS Secrets Manager / SSM),
  `gcp-sm://` (GCP Secret Manager), `azure-kv://` (Azure Key Vault), `doppler://`,
  `infisical://`, `pass://`, `gopass://`, plus `env://`, `file://`, and a gated
  `cmd://` escape hatch. Whole-value or embedded with `${…}`.
  - `envd providers` lists every scheme and whether its CLI is installed.
  - Resolved values are cached for 60s so per-prompt injection stays fast.
  - The daemon augments its `PATH` so provider CLIs are found under launchd.

### Changed
- Reference resolution is now a data-driven registry; adding a provider is one
  entry, no new dependency. `op://` migrated onto it. Literal URL-ish values
  (e.g. `postgres://…`) are correctly left untouched — only known schemes resolve.

## [0.6.0] — 2026-05-25

### Added
- **Reflog-like history**: every mutation (set/unset/import/addenv/rmenv) is
  recorded per project with the prior state.
  - `envd history [--env e] [--key K] [-n N]` shows the change log (values masked).
  - `envd restore <seq>` rolls back a value change, or restores a removed
    environment (with its contents). `envd undo` reverts the most recent change.
  - Restores are themselves recorded, so they're re-undoable.
  - In the TUI, press `h` to browse history and `enter`/`R` to restore.

## [0.5.0] — 2026-05-25

### Added
- `envd env add|rm|ls` — manage environments from the CLI (previously TUI-only).

### Changed
- New projects now start with a single `dev` environment instead of
  `dev,staging,prod`. Add more with `envd env add <name>` (or the TUI `A` key).
  You can still pass a custom comma-separated list at `envd connect` time.

## [0.4.0] — 2026-05-25

### Added
- **Code-aware doctor** (`envd doctor`): scans source for env-var references
  (`process.env`, `import.meta.env`, `Deno.env`, `Bun.env`, `os.Getenv`,
  `os.environ`) and flags missing / empty / placeholder / unused per environment.
  `--example` writes a `.env.example`; TUI `D` key runs it.
- **Zero-step onboarding**: auto-adopt an unregistered vault on `cd`, explicit
  `envd adopt`, and `envd import [file]` to absorb an existing `.env`.
- **Value generators**: `gen://random/N`, `gen://hex/N`, `gen://uuid`,
  `gen://password/N`, materialized once at set time.
- Provider **OAuth machinery** (`runOAuth`) made testable and integration-tested
  against a fake provider; `Adapter` interface ready for concrete vendors.

## [0.3.0] — 2026-05-25

### Added
- **Layered environments**: a shared `base` layer inherited by every environment,
  with per-env overrides. `envd diff <a> <b>` shows what differs. TUI marks
  inherited (`base`) vs overriding (`ovr`) values.

## [0.2.0] — 2026-05-24

### Added
- Interactive **TUI** (`envd tui`) to browse and edit vaults and environments.
- 1Password-style **reference interpolation**: `op://vault/item/field` (via the
  `op` CLI) and `envd://<env>/<KEY>`, whole-value or embedded with `${…}`.

## [0.1.0] — 2026-05-24

### Added
- Initial release: a single-binary daemon with a direnv-style shell hook that
  injects per-environment secrets at process launch. Encrypted-in-repo vault
  (AES-256-GCM), key in the macOS Keychain or via `ENVD_PASSPHRASE` (PBKDF2).
  Commands: `start`, `hook`, `connect`, `use`, `set`, `status`.

[Unreleased]: https://github.com/10thfloor/envd/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/10thfloor/envd/releases/tag/v0.11.0
[0.10.0]: https://github.com/10thfloor/envd/releases/tag/v0.10.0
[0.9.0]: https://github.com/10thfloor/envd/releases/tag/v0.9.0
[0.8.0]: https://github.com/10thfloor/envd/releases/tag/v0.8.0
[0.6.0]: https://github.com/10thfloor/envd/releases/tag/v0.6.0
[0.5.0]: https://github.com/10thfloor/envd/releases/tag/v0.5.0
[0.4.0]: https://github.com/10thfloor/envd/releases/tag/v0.4.0
[0.3.0]: https://github.com/10thfloor/envd/releases/tag/v0.3.0
[0.2.0]: https://github.com/10thfloor/envd/releases/tag/v0.2.0
[0.1.0]: https://github.com/10thfloor/envd/releases/tag/v0.1.0
