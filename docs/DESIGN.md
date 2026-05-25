# envd — design spec

Date: 2026-05-24 (kept current through v0.6, 2026-05-25)
Status: v0.6 — local workflow complete and tested; provider OAuth machinery built
(no vendor adapters ship yet); remote platform sync deferred.

This document is append-only by version: the sections below the architecture
record what each release added and why. For the current, complete command list
see the [README](../README.md).

## Goal

A daemon, started with a single command, that makes switching local development
between environments (dev / staging / prod) **obvious** and **automatic**, so the
developer **never has to handle or even see** the raw secret values. You reference
`process.env.DATABASE_URL` as normal; whichever environment is active, the daemon
fills it in at process launch.

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
