# envd — design spec

Date: 2026-05-24 (kept current through v0.9, 2026-05-25)
Status: v0.9 — local workflow complete and tested; a catalog of notable SaaS
services (`envd add`); live references into many providers via their CLIs; hidden
value entry + overwrite protection; remote platform sync deferred.

This document is append-only by version: the sections below the architecture
record what each release added and why. For the current, complete command list
see the [README](../README.md).

## Goal

A daemon, started with a single command, that manages **all** of a project's
per-environment configuration — secrets and ordinary settings alike — and makes
switching between environments (dev / staging / prod) **obvious** and **automatic**.
You reference `process.env.DATABASE_URL` (or `LOG_LEVEL`, a feature flag, a port…)
as normal; whichever environment is active, the daemon fills it in at process
launch. Secret values are additionally protected — encrypted at rest and never
printed — but envd is the single source of truth for configuration of any kind,
not only secrets.

Originally specced as a single, dependency-free file. From v0.2 the TUI relaxed
that (it uses Bubble Tea); the daemon core remains pure Go stdlib and the project
still ships as one binary. Designed to extend to other framework/platform vendors
(Encore, Cloudflare, Fly.io) later.

## Decisions (from brainstorming)

1. **Source of truth:** a single encrypted vault file committed in-repo (`./.envd/vault.json`).
2. **Local delivery:** direnv-style **shell hook** — env is injected at `exec` time when
   you work in a connected project directory. No wrapper command, no plaintext on disk.
   (Injecting env into an already-running process is impossible on macOS/Linux; the shell
   hook is the only no-disk, no-app-change mechanism.)
3. **Daemon model:** always-running, started once (`envd start`). The shell hook talks to it
   over a unix socket. It holds decrypted vaults in memory (unlocked once via Keychain),
   tracks active shell sessions for awareness ("monitor what I'm running"), and answers the
   per-prompt export query.
4. **Engine:** name-match. Vault stores `{env → {VAR → value}}`. If the active env defines a
   var your code references, you get it. Nothing else to wire up.
5. **Providers:** OAuth-based adapters layered on the name-match core. `envd connect neon`
   → OAuth → pick resource → per-env values pulled straight into the vault. You never paste
   a key or read a connection string.
6. **Crypto:** AES-256-GCM. Per-project 32-byte key in the macOS Keychain (never committed).
   Passphrase fallback via PBKDF2 (`ENVD_PASSPHRASE`) for headless/CI/Linux.
7. **Storage model:** the single committed vault holds everything (manifest + per-env values
   + provider tokens), all encrypted. The token-in-git tradeoff was accepted explicitly.

## Out of scope (deferred)

- Remote platform sync (`envd sync prod` → Fly / Cloudflare / Encore secrets) + drift detection.
  The adapter interface is shaped so a `PlatformAdapter` slots in later without rework.

## Architecture (single Go binary)

- `envd start` — runs the daemon (unix socket `~/.envd/daemon.sock`).
- `envd hook <zsh|bash>` — prints the shell hook to add to your rc file.
- `envd connect` — register the current dir as a project (name, environments, key).
- `envd connect <provider>` — OAuth-connect a provider adapter and import its values.
- `envd use <env>` — set the active environment for the current project.
- `envd set <KEY> [--env e]` — store a value (read from stdin so it never hits argv/history).
- `envd status` — projects, active envs, var counts, active shell sessions.

### Data

- `~/.envd/state.json` — non-secret registry: project name, path, id, envs, active env.
- `<project>/.envd/vault.json` — encrypted envelope: `{version, project, key_id, kdf, salt?,
  nonce, ciphertext}`. Plaintext is JSON `{project, environments, base, values, providers,
  history, next_seq}` (later fields added by v0.3+ and omitted/empty in older vaults).
- Keychain item `envd / envd-<id>` — the per-project AES key (when kdf=keychain).

### Daily loop

1. `envd start` (once per machine; backgroundable).
2. `eval "$(envd hook zsh)"` in `~/.zshrc` (once).
3. `cd` into a project → `envd connect` if unrecognized.
4. `envd set` values, or `envd connect <provider>` to import them.
5. `envd use staging` → prompt shows `(envd:staging)`; every newly-launched process
   inherits the staging values. Switch back with `envd use dev`.

## Extensibility

`Adapter` interface: `Name() / OAuth() / ListResources() / FetchSecrets()`. New vendors are
added in-source and recompiled (runtime plugins would require a plugin runtime and pull in
dependencies, against the dependency-free-core goal). The OAuth
code-flow runner is generic stdlib; an adapter only supplies endpoints, client id, and the
resource→secret mapping.

## v0.2 — TUI + reference interpolation (2026-05-25)

Two additions, both on top of the existing daemon protocol.

### Reference interpolation (1Password-style)

- Two schemes, resolved at inject time: `op://vault/item/field` (live read via the `op` CLI;
  the secret never lands in envd's vault) and `envd://<env>/<KEY>` (reuse another env's value).
- Usable as a whole value or embedded via `${…}`. Resolution is recursive with a depth cap
  (8) for cycle protection, and **fails closed** — unresolvable refs are omitted from the
  injected environment.
- Implemented daemon-side in `resolveValue`/`resolveRef`; the export path resolves before
  emitting exports.

### Interactive TUI (`envd tui`)

- Built with Bubble Tea + Lipgloss + Bubbles. This relaxes the original
  "single file, no dependencies" rule for the TUI only — the daemon core stays pure stdlib,
  and the whole thing still ships as one binary (`tui.go` is a separate file).
- Screens: project picker → browse (environments pane + variables table) → input prompt →
  confirm. Values masked by default; `r` reveals and resolves references. Inline set / edit /
  unset of variables and add / remove / set-active of environments.
- New daemon commands added to support it: `projects`, `vars` (with optional `resolve`),
  `unset`, `addenv`, `rmenv`. Mutating commands accept an `Args["project"]` target (path or
  name) so the TUI can act on any project, not just the cwd one.

### Testing

- `tui_test.go` drives the Bubble Tea model as pure functions (navigation, masking, reveal,
  prompt routing) — no terminal needed. Reference resolution and the new daemon commands are
  verified end-to-end against a live daemon.

## v0.3 — layered environments (2026-05-25)

First of a four-feature roadmap to make per-project env management maximally simple/automatic
(remaining: code-aware doctor, zero-step onboarding, provider OAuth + generators).

- **Model:** a single shared `base` layer per vault (`Vault.Base map[string]string`). An
  environment's effective config = `base` overlaid with its own values (env wins). `base` is
  reserved — not selectable as active, can't be added/removed as a normal env.
- **Resolution:** `unlocked.effective(env)` merges base+env; `handleExport` injects the merged,
  reference-resolved set. `envd://base/KEY` references resolve via `readLayer`.
- **Inspection:** `handleVars` returns `Inherited`/`Overrides` flags so the TUI can show
  inherited values (tagged `base`) vs overrides (`ovr`). New `envd diff <a> <b>` reports
  only-in-A / only-in-B / differing keys with values masked.
- **Single-base, not multi-level:** chosen deliberately for simplicity (no precedence rules or
  cycle handling). Backward compatible: old vaults get an empty base on load.

## v0.4 — doctor, onboarding, generators, provider OAuth (2026-05-25)

Completes the four-feature roadmap.

### #2 Code-aware doctor
- `scanEnvRefs` walks the project (skipping `node_modules`/`.git`/build dirs, ≤1 MB text files)
  matching `process.env.X`, `import.meta.env.X`, `Deno.env.get`, `Bun.env.X`, `os.Getenv`,
  `os.environ[...]`. `handleDoctor` reconciles against `effective(env)` → missing / empty /
  placeholder / unused. `envd doctor [--env e] [--example]`; TUI `D` key; `--example` writes
  `.env.example`.

### #3 Zero-step onboarding
- `findVaultRoot` + `adopt` register an existing on-disk vault. `handleExport` auto-adopts when
  `cd`-ing into an unregistered vault dir (if the key is available) — clone → works. Explicit
  `envd adopt`. `envd import [file] --env e` parses dotenv (`Request.KV` bulk) into a layer.

### #4 Generators + provider OAuth
- **Generators:** `materializeGen` expands `gen://random/N|hex/N|uuid|password/N` (whole-value
  or `${…}`) at set time, so the concrete value is persisted and stable. No read-time side
  effects.
- **Provider OAuth:** `runOAuth` refactored into `runOAuthWith(open func(string))` for
  testability; integration-tested against an `httptest` fake provider (authorize → loopback
  callback → token exchange). The `Adapter` interface + `registerAdapter` remain the extension
  point; concrete vendor adapters need the user's own OAuth client credentials, so none ship.

### Testing
- `main_test.go`: generators, OAuth flow (fake provider), dotenv parsing. `tui_test.go`: model.
- Each feature additionally verified end-to-end against a live daemon (doctor flags, auto-adopt
  of a wiped-then-rediscovered vault, import, generator stability across exports).

## v0.5 — custom environments (2026-05-25)

- New projects now start with a single `dev` environment (was `dev,staging,prod`); a custom
  comma-separated list can still be given at `envd connect` time.
- `envd env add|rm|ls` manages environments from the CLI (previously TUI-only), reusing the
  `addenv`/`rmenv` daemon handlers. `base` stays reserved; the last environment can't be removed.

## v0.6 — reflog-style history (2026-05-25)

- **Model:** `Vault.History []HistoryEntry` (capped at 500) plus a monotonic `NextSeq`. Every
  mutation (`set`/`unset`/`import`/`addenv`/`rmenv`) is recorded via `unlocked.record(...)` with
  the prior state — for `set`, the old value and whether it existed; for `rmenv`, a full snapshot
  of the removed environment.
- **Restore:** `handleRestore(seq)` applies the inverse of an entry and records the reversion
  itself, so restores are re-undoable (true reflog behavior): `set` → revert or clear the key;
  `unset` → re-set; `addenv` → remove the env; `rmenv` → recreate the env from its snapshot.
- **Surface:** `envd history [--env e] [--key K] [-n N]` (values masked), `envd restore <seq>`,
  `envd undo` (latest). TUI: `h` opens a history view, `enter`/`R` restores. New daemon commands
  `history` and `restore`.
- Backward compatible: vaults without history start empty and accumulate it going forward.

## v0.7 — provider references (2026-05-25)

Generalizes the `op://` reference into a registry of industry-standard config/secret providers.

- **Mechanism (chosen):** shell out to each vendor's official CLI rather than bundle SDKs or
  build OAuth apps. This reuses the auth the user already has (`aws configure`, `gcloud auth`,
  `doppler login`, `op signin`, …), keeps the daemon dependency-free, and is exactly how the
  original `op://` worked. Each provider is one entry in `providerList` (`scheme`, required
  `bin`, `fn(arg)`); `providerByScheme` indexes them.
- **Schemes:** `op`, `vault`, `aws-sm`, `aws-ssm`, `gcp-sm`, `azure-kv`, `doppler`, `infisical`,
  `pass`, `gopass`, plus dependency-free `env`, `file`, and a gated `cmd` (needs
  `ENVD_ALLOW_EXEC=1` — it runs arbitrary shell, the others run a fixed binary with the ref as
  arguments, so there's no shell-injection surface).
- **Detection:** `schemeOf` + `looksLikeRef` recognize *known* schemes only, so a literal
  `postgres://…` value is injected as-is and never mistaken for a reference.
- **Performance/safety:** `Daemon.refCache` memoizes resolved refs for `refTTL` (60s) so
  per-prompt injection doesn't shell out repeatedly. `ensurePATH` augments the daemon's PATH
  (Homebrew, `/usr/local/bin`, `~/.local/bin`, `~/go/bin`) so CLIs are found under launchd.
- **Surface:** `envd providers` lists schemes and per-CLI availability (checked in the daemon's
  own PATH). The OAuth `Adapter` path is retained for future bulk-import adapters.
- **Tested:** scheme detection, registry dispatch + TTL cache (fake provider), and a real CLI
  shellout via a fake `op` on PATH; plus an end-to-end run resolving `env://`, `file://`, and an
  embedded `${env://…}` through a live daemon.

## v0.8 — service catalog (2026-05-25)

Comprehensive support for notable SaaS platforms and frameworks, framed as data.

- **Mechanism:** a static `catalog []catEntry` mapping each service (name, title,
  category, docs URL, optional note, aliases) to the canonical env vars it expects
  (`catVar{Key, Secret, Default}`). `catByName` indexes names + aliases. 100+ entries
  across databases, auth, payments, email/SMS, AI & vector, backends & frameworks
  (Meteor, Restate, Convex, Payload, Encore), platforms, observability, analytics,
  CMS, search, jobs/queues, realtime, maps, and feature flags. `envd catalog` groups
  by category at display time, so entries can be added in any order.
- **`envd add <service>`** (`handleScaffold`): for each var, generate it when the
  default is a `gen://…` (e.g. `BETTER_AUTH_SECRET`), apply a literal default when
  given (callback URLs, `AWS_REGION`), else create an empty placeholder. Existing
  keys are never overwritten. Every write is recorded in history. Returns a summary
  (generated / defaults / fill-in + where to get them).
- **`envd catalog [query]`** lists/searches the catalog grouped by category
  (client-side; the catalog is baked into the binary).
- **Why a catalog, not per-service APIs:** breadth without dependencies or bespoke
  auth. Knowing the *names* is the high-value, comprehensive part; the *values*
  come from `envd set`, a generator, or a provider reference (v0.7) — which compose
  with scaffolded keys.
- **Tested:** catalog integrity (no dup names, every var keyed, every `gen://`
  default valid) + alias lookup; end-to-end scaffolding of betterauth (generated +
  default), stripe (placeholders), an alias, and a note-only entry against a live
  daemon.

## v0.9 — secure input & overwrite protection (2026-05-25)

- **Hidden input (no echo):** `envd set` reads the value via a no-echo terminal
  prompt (`golang.org/x/term`, already in the dependency graph via Bubble Tea),
  or piped stdin when not a TTY. Removes the need for `echo …| envd set` while
  keeping values out of shell history and argv. Isolated in `term.go` so the
  daemon core stays stdlib-only.
- **Overwrite protection:** `handleSet` returns `NeedConfirm` (without mutating)
  when a value already exists and differs, unless `force` is set. The CLI prompts
  y/N (or errors asking for `--force` when non-interactive); the TUI shows a
  `cOverwrite` confirmation; `handleImport` skips existing keys unless forced. A
  no-op set (same value) never prompts.
- **connect guard:** `envd connect` refuses to silently re-key a directory that
  already has a `.envd/vault.json` (which would abandon its values) — it confirms
  first.
- **Tested:** `handleSet` overwrite/force/no-op logic and `handleImport` skip/force
  via in-memory daemon tests; end-to-end against a live daemon for the
  non-interactive paths and the connect guard.
