# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/10thfloor/envd/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/10thfloor/envd/releases/tag/v0.6.0
[0.5.0]: https://github.com/10thfloor/envd/releases/tag/v0.5.0
[0.4.0]: https://github.com/10thfloor/envd/releases/tag/v0.4.0
[0.3.0]: https://github.com/10thfloor/envd/releases/tag/v0.3.0
[0.2.0]: https://github.com/10thfloor/envd/releases/tag/v0.2.0
[0.1.0]: https://github.com/10thfloor/envd/releases/tag/v0.1.0
