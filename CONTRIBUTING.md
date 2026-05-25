# Contributing to envd

Thanks for your interest! envd is small on purpose — please keep it that way.

## Build & test

```sh
go build -o envd .     # build the binary
go test ./...          # run tests (no terminal/daemon required)
go vet ./...           # static checks
gofmt -l .             # must print nothing (run `gofmt -w .` to fix)
```

CI runs all four on Linux and macOS for every PR.

## Architecture & guardrails

- **`main.go` is the dependency-free daemon core.** It uses only the Go standard
  library (crypto, sockets, HTTP, PBKDF2). Please keep it that way — no third-party
  imports in the core.
- **`tui.go` is the only place third-party deps live** (Bubble Tea / Lipgloss /
  Bubbles). Everything still ships as a single binary.
- Tests: Bubble Tea models are pure functions — drive them via `Update`/`View`
  (see `tui_test.go`). Daemon/crypto/OAuth logic is unit-tested in `main_test.go`.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design and the decisions behind it.

## Adding a provider adapter

Implement the `Adapter` interface in `main.go` and register it:

```go
type Adapter interface {
    Name() string
    OAuth() OAuthConfig
    ListResources(ctx context.Context, accessToken string) ([]Resource, error)
    FetchSecrets(ctx context.Context, accessToken, resourceID, envName string) (map[string]string, error)
}
```

`registerAdapter(&myAdapter{})` in an `init()`. The generic OAuth code-flow
(`runOAuth`) is already provided — your adapter only supplies endpoints, a client
ID, and the resource→secret mapping.

## Pull requests

- One focused change per PR. Match the surrounding style.
- Add or update tests for behavior changes.
- Keep the core dependency-free; justify any new dependency in the PR description.
- Update `README.md` / `docs/DESIGN.md` and `CHANGELOG.md` when behavior changes.

## Reporting security issues

See [`SECURITY.md`](SECURITY.md) — please disclose privately, not in a public issue.
