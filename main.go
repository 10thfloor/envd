// envd — a daemon that manages all of a project's per-environment configuration
// (secrets and ordinary settings alike) and injects it into your shell
// automatically as you switch between dev/staging/prod. The daemon core is pure
// Go stdlib; the TUI (tui.go) adds Bubble Tea. Everything ships as one binary.
//
// Design: docs/DESIGN.md
//
// Build:  go build -o envd .
// Usage:  envd help
package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	appName = "envd"
	version = "0.11.0"
)

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return h
}
func stateDir() string   { return filepath.Join(homeDir(), ".envd") }
func socketPath() string { return filepath.Join(stateDir(), "daemon.sock") }
func statePath() string  { return filepath.Join(stateDir(), "state.json") }

func vaultDir(root string) string  { return filepath.Join(root, ".envd") }
func vaultPath(root string) string { return filepath.Join(vaultDir(root), "vault.json") }

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

// Project is non-secret registry metadata held in ~/.envd/state.json.
type Project struct {
	Name      string   `json:"name"`
	Path      string   `json:"path"` // absolute project root
	ID        string   `json:"id"`   // keychain key id suffix
	Envs      []string `json:"envs"`
	ActiveEnv string   `json:"active_env"`
}

type State struct {
	Projects []Project `json:"projects"`
}

// Vault is the decrypted, secret payload (one per project, committed encrypted).
type Vault struct {
	Project      string                       `json:"project"`
	Environments []string                     `json:"environments"`
	Base         map[string]string            `json:"base"`      // shared layer, inherited by every env
	Values       map[string]map[string]string `json:"values"`    // env -> KEY -> value (overrides base)
	Providers    map[string]ProviderState     `json:"providers"` // provider name -> token/bindings
	History      []HistoryEntry               `json:"history,omitempty"`
	NextSeq      int                          `json:"next_seq,omitempty"`
	// EnvBaseline is the .env-derived layers as of the last assimilate/sync, used
	// to detect manual edits (added/removed/changed) to the project's .env files.
	EnvBaseline map[string]map[string]string `json:"env_baseline,omitempty"`
}

// HistoryEntry is one recorded mutation (reflog-like). It carries the prior
// state needed to undo it.
type HistoryEntry struct {
	Seq      int               `json:"seq"`
	Time     time.Time         `json:"time"`
	Op       string            `json:"op"` // set | unset | addenv | rmenv
	Env      string            `json:"env"`
	Key      string            `json:"key,omitempty"`
	Old      string            `json:"old,omitempty"`
	New      string            `json:"new,omitempty"`
	HadOld   bool              `json:"had_old,omitempty"`  // key existed before a set
	Snapshot map[string]string `json:"snapshot,omitempty"` // removed env's contents (rmenv)
}

const historyCap = 500

type ProviderState struct {
	Token    json.RawMessage            `json:"token,omitempty"`
	Bindings map[string]ProviderBinding `json:"bindings,omitempty"` // env -> binding
}

type ProviderBinding struct {
	Resource string            `json:"resource"`
	Extra    map[string]string `json:"extra,omitempty"`
}

// vaultFile is the on-disk encrypted envelope.
type vaultFile struct {
	Version int    `json:"version"`
	Project string `json:"project"`
	KeyID   string `json:"key_id"`
	KDF     string `json:"kdf"` // "keychain" | "pbkdf2"
	Salt    string `json:"salt,omitempty"`
	Nonce   string `json:"nonce"`
	Cipher  string `json:"ciphertext"`
}

// ---------------------------------------------------------------------------
// Crypto (AES-256-GCM)
// ---------------------------------------------------------------------------

func newKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		fatal(err)
	}
	return k
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func encrypt(key, plaintext []byte) (nonce, ct []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, nil), nil
}

func decrypt(key, nonce, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

// ---------------------------------------------------------------------------
// Key resolution: macOS Keychain, or PBKDF2 passphrase fallback
// ---------------------------------------------------------------------------

func keychainAvailable() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	_, err := exec.LookPath("security")
	return err == nil
}

func keychainSet(id string, key []byte) error {
	b64 := base64.StdEncoding.EncodeToString(key)
	// Best-effort delete of any prior item, then add/update.
	_ = exec.Command("security", "delete-generic-password", "-a", appName, "-s", id).Run()
	out, err := exec.Command("security", "add-generic-password",
		"-a", appName, "-s", id, "-w", b64, "-U").CombinedOutput()
	if err != nil {
		return fmt.Errorf("keychain set: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func keychainGet(id string) ([]byte, error) {
	out, err := exec.Command("security", "find-generic-password",
		"-a", appName, "-s", id, "-w").Output()
	if err != nil {
		return nil, fmt.Errorf("keychain get %q: %w", id, err)
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
}

func pbkdf2Key(pass string, salt []byte) ([]byte, error) {
	if pass == "" {
		return nil, errors.New("ENVD_PASSPHRASE not set (required for pbkdf2 vaults)")
	}
	return pbkdf2.Key(sha256.New, pass, salt, 600_000, 32)
}

func resolveKey(vf *vaultFile) ([]byte, error) {
	switch vf.KDF {
	case "keychain":
		return keychainGet(vf.KeyID)
	case "pbkdf2":
		salt, err := base64.StdEncoding.DecodeString(vf.Salt)
		if err != nil {
			return nil, err
		}
		return pbkdf2Key(os.Getenv("ENVD_PASSPHRASE"), salt)
	}
	return nil, fmt.Errorf("unknown kdf %q", vf.KDF)
}

// ---------------------------------------------------------------------------
// Vault load/save
// ---------------------------------------------------------------------------

func loadVault(root string) (*Vault, *vaultFile, []byte, error) {
	raw, err := os.ReadFile(vaultPath(root))
	if err != nil {
		return nil, nil, nil, err
	}
	var vf vaultFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		return nil, nil, nil, err
	}
	key, err := resolveKey(&vf)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(vf.Nonce)
	if err != nil {
		return nil, nil, nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(vf.Cipher)
	if err != nil {
		return nil, nil, nil, err
	}
	pt, err := decrypt(key, nonce, ct)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decrypt vault (wrong key?): %w", err)
	}
	var v Vault
	if err := json.Unmarshal(pt, &v); err != nil {
		return nil, nil, nil, err
	}
	if v.Base == nil { // backward-compat: older vaults have no base layer
		v.Base = map[string]string{}
	}
	return &v, &vf, key, nil
}

func saveVault(root string, v *Vault, vf *vaultFile, key []byte) error {
	pt, err := json.Marshal(v)
	if err != nil {
		return err
	}
	nonce, ct, err := encrypt(key, pt)
	if err != nil {
		return err
	}
	vf.Version = 1
	vf.Project = v.Project
	vf.Nonce = base64.StdEncoding.EncodeToString(nonce)
	vf.Cipher = base64.StdEncoding.EncodeToString(ct)
	out, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(vaultDir(root), 0o700); err != nil {
		return err
	}
	return os.WriteFile(vaultPath(root), out, 0o600)
}

// ---------------------------------------------------------------------------
// Daemon protocol
// ---------------------------------------------------------------------------

type Request struct {
	Cmd     string                       `json:"cmd"`
	Cwd     string                       `json:"cwd,omitempty"`
	Applied []string                     `json:"applied,omitempty"`
	Args    map[string]string            `json:"args,omitempty"`
	KV      map[string]string            `json:"kv,omitempty"`     // bulk payload (import)
	Layers  map[string]map[string]string `json:"layers,omitempty"` // env -> KV (assimilate); "base" = shared
}

type Response struct {
	OK          bool              `json:"ok"`
	Error       string            `json:"error,omitempty"`
	Exports     map[string]string `json:"exports,omitempty"`
	Unsets      []string          `json:"unsets,omitempty"`
	Env         string            `json:"env,omitempty"`
	Text        string            `json:"text,omitempty"`
	Projects    []ProjectView     `json:"projects,omitempty"`
	Vars        []VarView         `json:"vars,omitempty"`
	Doctor      *DoctorReport     `json:"doctor,omitempty"`
	History     []HistoryEntry    `json:"history,omitempty"`
	NeedConfirm bool              `json:"need_confirm,omitempty"` // mutation would overwrite; retry with force
	Drift       *DriftReport      `json:"drift,omitempty"`
}

// DriftItem is one manual change to a project's .env files relative to the vault.
type DriftItem struct {
	Env   string `json:"env"`
	Key   string `json:"key"`
	Value string `json:"value,omitempty"` // new value (added/changed); empty for removed
}

// DriftReport describes manual .env edits since the last sync.
type DriftReport struct {
	Added   []DriftItem `json:"added,omitempty"`
	Changed []DriftItem `json:"changed,omitempty"`
	Removed []DriftItem `json:"removed,omitempty"`
}

func (r *DriftReport) empty() bool {
	return r == nil || len(r.Added)+len(r.Changed)+len(r.Removed) == 0
}

func (r *DriftReport) count() int {
	if r == nil {
		return 0
	}
	return len(r.Added) + len(r.Changed) + len(r.Removed)
}

// computeDrift diffs the current .env-derived layers against the baseline.
func computeDrift(baseline, current map[string]map[string]string) *DriftReport {
	r := &DriftReport{}
	envs := map[string]bool{}
	for e := range baseline {
		envs[e] = true
	}
	for e := range current {
		envs[e] = true
	}
	envNames := make([]string, 0, len(envs))
	for e := range envs {
		envNames = append(envNames, e)
	}
	sort.Strings(envNames)
	for _, env := range envNames {
		base, cur := baseline[env], current[env]
		keys := map[string]bool{}
		for k := range base {
			keys[k] = true
		}
		for k := range cur {
			keys[k] = true
		}
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			bv, inBase := base[k]
			cv, inCur := cur[k]
			switch {
			case inCur && !inBase:
				r.Added = append(r.Added, DriftItem{env, k, cv})
			case !inCur && inBase:
				r.Removed = append(r.Removed, DriftItem{env, k, ""})
			case inCur && inBase && bv != cv:
				r.Changed = append(r.Changed, DriftItem{env, k, cv})
			}
		}
	}
	if r.empty() {
		return nil
	}
	return r
}

func totalKeys(layers map[string]map[string]string) int {
	n := 0
	for _, m := range layers {
		n += len(m)
	}
	return n
}

// DoctorReport is the result of scanning project source for env-var references
// and reconciling them against an environment's effective config.
type DoctorReport struct {
	Env          string   `json:"env"`
	FilesScanned int      `json:"files_scanned"`
	Referenced   []string `json:"referenced"`
	Missing      []string `json:"missing"`     // referenced in code, absent from the env
	Empty        []string `json:"empty"`       // present but blank
	Placeholder  []string `json:"placeholder"` // present but looks like a placeholder
	Unused       []string `json:"unused"`      // present but not referenced in code
}

// ProjectView is the structured project summary returned to clients (TUI).
type ProjectView struct {
	Name      string   `json:"name"`
	Path      string   `json:"path"`
	Envs      []string `json:"envs"`
	ActiveEnv string   `json:"active_env"`
	Locked    bool     `json:"locked"`
}

// VarView is one variable as shown in the TUI: the raw stored value plus, on
// request, its resolved form (references expanded).
type VarView struct {
	Key        string `json:"key"`
	Value      string `json:"value"`
	IsRef      bool   `json:"is_ref"`
	Resolved   string `json:"resolved,omitempty"`
	ResolveErr string `json:"resolve_err,omitempty"`
	Inherited  bool   `json:"inherited,omitempty"` // value comes from base, not overridden here
	Overrides  bool   `json:"overrides,omitempty"` // set here AND present in base
}

func arg(req Request, k string) string {
	if req.Args == nil {
		return ""
	}
	return req.Args[k]
}

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

type unlocked struct {
	vault *Vault
	vf    *vaultFile
	key   []byte
}

// readLayer returns the raw value map for env ("base" → the shared layer) and
// whether it exists.
func (u *unlocked) readLayer(env string) (map[string]string, bool) {
	if env == "base" {
		return u.vault.Base, true
	}
	m, ok := u.vault.Values[env]
	return m, ok
}

// layer returns a writable value map for env, creating it if needed.
func (u *unlocked) layer(env string) map[string]string {
	if env == "base" {
		if u.vault.Base == nil {
			u.vault.Base = map[string]string{}
		}
		return u.vault.Base
	}
	if u.vault.Values[env] == nil {
		u.vault.Values[env] = map[string]string{}
	}
	return u.vault.Values[env]
}

// record appends a mutation to the project's reflog, assigning a monotonic Seq
// and capping the log length.
func (u *unlocked) record(e HistoryEntry) {
	u.vault.NextSeq++
	e.Seq = u.vault.NextSeq
	e.Time = time.Now().UTC()
	u.vault.History = append(u.vault.History, e)
	if len(u.vault.History) > historyCap {
		u.vault.History = u.vault.History[len(u.vault.History)-historyCap:]
	}
}

// effective merges the base layer with env's own values (env wins).
func (u *unlocked) effective(env string) map[string]string {
	out := make(map[string]string, len(u.vault.Base)+len(u.vault.Values[env]))
	for k, v := range u.vault.Base {
		out[k] = v
	}
	for k, v := range u.vault.Values[env] {
		out[k] = v
	}
	return out
}

type session struct {
	Project string
	Env     string
	Cwd     string
	Last    time.Time
}

type refCacheEntry struct {
	val string
	exp time.Time
}

type Daemon struct {
	mu       sync.Mutex
	state    *State
	cache    map[string]*unlocked     // by project path
	sessions map[string]session       // by shell id
	refCache map[string]refCacheEntry // resolved provider refs (TTL)
}

const refTTL = 60 * time.Second

// refCacheGet/Set memoize external provider lookups so injection (which runs on
// every shell prompt) doesn't shell out to AWS/Vault/etc. each time. Assumes d.mu.
func (d *Daemon) refCacheGet(ref string) (string, bool) {
	e, ok := d.refCache[ref]
	if !ok || time.Now().After(e.exp) {
		return "", false
	}
	return e.val, true
}

func (d *Daemon) refCacheSet(ref, val string) {
	d.refCache[ref] = refCacheEntry{val: val, exp: time.Now().Add(refTTL)}
}

func loadState() *State {
	raw, err := os.ReadFile(statePath())
	if err != nil {
		return &State{}
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return &State{}
	}
	return &s
}

// saveState assumes d.mu is held.
func (d *Daemon) saveState() {
	out, _ := json.MarshalIndent(d.state, "", "  ")
	_ = os.MkdirAll(stateDir(), 0o700)
	_ = os.WriteFile(statePath(), out, 0o600)
}

// findProject returns the registered project whose path is the longest ancestor
// of cwd. Assumes d.mu is held.
func (d *Daemon) findProject(cwd string) *Project {
	cwd = filepath.Clean(cwd)
	var best *Project
	bestLen := -1
	for i := range d.state.Projects {
		p := &d.state.Projects[i]
		pp := filepath.Clean(p.Path)
		if cwd == pp || strings.HasPrefix(cwd, pp+string(filepath.Separator)) {
			if len(pp) > bestLen {
				best, bestLen = p, len(pp)
			}
		}
	}
	return best
}

// getUnlocked loads+decrypts a project's vault, caching it. Assumes d.mu is held.
func (d *Daemon) getUnlocked(p *Project) (*unlocked, error) {
	if u, ok := d.cache[p.Path]; ok {
		return u, nil
	}
	v, vf, key, err := loadVault(p.Path)
	if err != nil {
		return nil, err
	}
	u := &unlocked{vault: v, vf: vf, key: key}
	d.cache[p.Path] = u
	return u, nil
}

// findVaultRoot walks up from cwd looking for a directory containing
// .envd/vault.json (an unregistered, e.g. freshly-cloned, project).
func findVaultRoot(cwd string) string {
	dir := filepath.Clean(cwd)
	for {
		if _, err := os.Stat(vaultPath(dir)); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// adopt registers an existing on-disk vault into daemon state (zero-step
// onboarding). Requires the decryption key to be available. Assumes d.mu held.
func (d *Daemon) adopt(root string) (string, error) {
	v, vf, key, err := loadVault(root)
	if err != nil {
		return "", err
	}
	active := ""
	if len(v.Environments) > 0 {
		active = v.Environments[0]
	}
	d.removeProjectByPath(root)
	d.state.Projects = append(d.state.Projects, Project{
		Name: v.Project, Path: root, ID: strings.TrimPrefix(vf.KeyID, appName+"-"),
		Envs: v.Environments, ActiveEnv: active,
	})
	d.cache[root] = &unlocked{vault: v, vf: vf, key: key}
	d.saveState()
	return "adopted " + v.Project, nil
}

func (d *Daemon) removeProjectByPath(path string) {
	path = filepath.Clean(path)
	out := d.state.Projects[:0]
	for _, p := range d.state.Projects {
		if filepath.Clean(p.Path) != path {
			out = append(out, p)
		}
	}
	d.state.Projects = out
}

// ---------------------------------------------------------------------------
// Reference interpolation. A value may be a reference resolved at inject time
// (recursively, depth-capped). `envd://<env>/<KEY>` reuses another env's value;
// every other scheme is a provider that shells out to that vendor's official CLI
// (reusing the auth you already have). Usable whole-value or embedded via ${...}.
// ---------------------------------------------------------------------------

var refRe = regexp.MustCompile(`\$\{([^}]+)\}`)

// provider integrates an industry-standard config/secret source via its CLI.
type provider struct {
	scheme  string
	bin     string // required CLI ("" = none / built-in)
	desc    string
	example string
	fn      func(arg string) (string, error) // arg is everything after "scheme://"
}

// providerList is the registry of supported reference schemes. Adding a vendor is
// a single entry here — no SDK, no OAuth app, no new dependency.
var providerList = []provider{
	{"op", "op", "1Password", "op://Private/db/password", func(a string) (string, error) {
		return runCLI("op", "read", "op://"+a)
	}},
	{"vault", "vault", "HashiCorp Vault", "vault://secret/myapp#db_pass", func(a string) (string, error) {
		path, field, ok := strings.Cut(a, "#")
		if !ok || field == "" {
			return "", errors.New("vault ref needs path#field")
		}
		return runCLI("vault", "kv", "get", "-field="+field, path)
	}},
	{"aws-sm", "aws", "AWS Secrets Manager", "aws-sm://myapp/prod#DB_URL", func(a string) (string, error) {
		id, key, hasKey := strings.Cut(a, "#")
		v, err := runCLI("aws", "secretsmanager", "get-secret-value", "--secret-id", id, "--query", "SecretString", "--output", "text")
		if err != nil || !hasKey {
			return v, err
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			return "", fmt.Errorf("secret %q is not JSON: %v", id, err)
		}
		val, ok := m[key]
		if !ok {
			return "", fmt.Errorf("secret %q has no key %q", id, key)
		}
		return fmt.Sprint(val), nil
	}},
	{"aws-ssm", "aws", "AWS SSM Parameter Store", "aws-ssm:///myapp/prod/db_url", func(a string) (string, error) {
		return runCLI("aws", "ssm", "get-parameter", "--name", a, "--with-decryption", "--query", "Parameter.Value", "--output", "text")
	}},
	{"gcp-sm", "gcloud", "GCP Secret Manager", "gcp-sm://my-project/db-url", func(a string) (string, error) {
		proj, sec, ok := strings.Cut(a, "/")
		if ok {
			return runCLI("gcloud", "secrets", "versions", "access", "latest", "--secret="+sec, "--project="+proj)
		}
		return runCLI("gcloud", "secrets", "versions", "access", "latest", "--secret="+a)
	}},
	{"azure-kv", "az", "Azure Key Vault", "azure-kv://my-vault/db-url", func(a string) (string, error) {
		vault, name, ok := strings.Cut(a, "/")
		if !ok {
			return "", errors.New("azure-kv ref needs vault/name")
		}
		return runCLI("az", "keyvault", "secret", "show", "--vault-name", vault, "--name", name, "--query", "value", "-o", "tsv")
	}},
	{"doppler", "doppler", "Doppler", "doppler://DATABASE_URL", func(a string) (string, error) {
		if p := strings.Split(a, "/"); len(p) == 3 {
			return runCLI("doppler", "secrets", "get", p[2], "--plain", "--project", p[0], "--config", p[1])
		}
		return runCLI("doppler", "secrets", "get", a, "--plain")
	}},
	{"infisical", "infisical", "Infisical", "infisical://prod/DATABASE_URL", func(a string) (string, error) {
		env, name, ok := strings.Cut(a, "/")
		if ok {
			return runCLI("infisical", "secrets", "get", name, "--plain", "--env="+env)
		}
		return runCLI("infisical", "secrets", "get", a, "--plain")
	}},
	{"pass", "pass", "pass (password-store)", "pass://db/prod/url", func(a string) (string, error) {
		out, err := runCLI("pass", "show", a)
		if err != nil {
			return "", err
		}
		line, _, _ := strings.Cut(out, "\n")
		return line, nil
	}},
	{"gopass", "gopass", "gopass", "gopass://db/prod/url", func(a string) (string, error) {
		return runCLI("gopass", "show", "-o", a)
	}},
	{"env", "", "Daemon environment var", "env://HOME_DB_URL", func(a string) (string, error) {
		if v, ok := os.LookupEnv(a); ok {
			return v, nil
		}
		return "", fmt.Errorf("$%s not set in the daemon's environment", a)
	}},
	{"file", "", "A file's contents", "file:///run/secrets/db_url", func(a string) (string, error) {
		b, err := os.ReadFile(a)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}},
	{"cmd", "", "Run a command (gated)", "cmd://my-tool get db-url", func(a string) (string, error) {
		if os.Getenv("ENVD_ALLOW_EXEC") == "" {
			return "", errors.New("cmd:// is disabled; set ENVD_ALLOW_EXEC=1 to enable")
		}
		return runCLI("sh", "-c", a)
	}},
}

var providerByScheme = func() map[string]provider {
	m := make(map[string]provider, len(providerList))
	for _, p := range providerList {
		m[p.scheme] = p
	}
	return m
}()

// runCLI runs a provider CLI and returns its trimmed stdout (stderr on error).
func runCLI(bin string, args ...string) (string, error) {
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		msg := err.Error()
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			msg = strings.TrimSpace(string(ee.Stderr))
		}
		return "", fmt.Errorf("%s: %s", bin, msg)
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}

// schemeOf returns the URI scheme of s ("" if it isn't scheme://...).
func schemeOf(s string) string {
	i := strings.Index(s, "://")
	if i <= 0 {
		return ""
	}
	for _, r := range s[:i] {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '+' || r == '.') {
			return ""
		}
	}
	return s[:i]
}

// looksLikeRef reports whether s is a whole-value reference of a KNOWN scheme.
// (A literal like postgres://… is not a known scheme, so it's left untouched.)
func looksLikeRef(s string) bool {
	sc := schemeOf(strings.TrimSpace(s))
	if sc == "envd" {
		return true
	}
	_, ok := providerByScheme[sc]
	return ok
}

// ---------------------------------------------------------------------------
// Service catalog: which env vars each notable SaaS platform / framework expects.
// `envd add <service>` scaffolds these keys (generating secrets, applying
// sensible defaults, leaving must-provide secrets blank with a link). Pure data —
// adding a service is one entry.
// ---------------------------------------------------------------------------

type catVar struct {
	Key     string
	Secret  bool
	Default string // literal default, or gen://… to generate; "" = you must provide it
}

type catEntry struct {
	Name, Title, Cat, URL, Note string
	Aliases                     []string
	Vars                        []catVar
}

var catalog = []catEntry{
	// Databases & data
	{Name: "neon", Title: "Neon", Cat: "Databases", URL: "https://console.neon.tech", Vars: []catVar{{"DATABASE_URL", true, ""}}},
	{Name: "supabase", Title: "Supabase", Cat: "Databases", URL: "https://supabase.com/dashboard/project/_/settings/api", Vars: []catVar{{"SUPABASE_URL", false, ""}, {"SUPABASE_ANON_KEY", false, ""}, {"SUPABASE_SERVICE_ROLE_KEY", true, ""}}},
	{Name: "planetscale", Title: "PlanetScale", Cat: "Databases", URL: "https://app.planetscale.com", Vars: []catVar{{"DATABASE_URL", true, ""}}},
	{Name: "turso", Title: "Turso", Cat: "Databases", URL: "https://turso.tech/app", Vars: []catVar{{"TURSO_DATABASE_URL", false, ""}, {"TURSO_AUTH_TOKEN", true, ""}}},
	{Name: "upstash", Title: "Upstash Redis", Cat: "Databases", URL: "https://console.upstash.com", Aliases: []string{"redis"}, Vars: []catVar{{"UPSTASH_REDIS_REST_URL", false, ""}, {"UPSTASH_REDIS_REST_TOKEN", true, ""}}},
	{Name: "mongodb", Title: "MongoDB Atlas", Cat: "Databases", URL: "https://cloud.mongodb.com", Aliases: []string{"atlas"}, Vars: []catVar{{"MONGODB_URI", true, ""}}},

	// Auth
	{Name: "betterauth", Title: "Better Auth", Cat: "Auth", URL: "https://better-auth.com", Aliases: []string{"better-auth"}, Vars: []catVar{{"BETTER_AUTH_SECRET", true, "gen://random/32"}, {"BETTER_AUTH_URL", false, "http://localhost:3000"}}},
	{Name: "authjs", Title: "Auth.js / NextAuth", Cat: "Auth", URL: "https://authjs.dev", Aliases: []string{"nextauth", "next-auth"}, Vars: []catVar{{"AUTH_SECRET", true, "gen://random/32"}, {"NEXTAUTH_URL", false, "http://localhost:3000"}}},
	{Name: "clerk", Title: "Clerk", Cat: "Auth", URL: "https://dashboard.clerk.com", Vars: []catVar{{"CLERK_SECRET_KEY", true, ""}, {"NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY", false, ""}}},
	{Name: "auth0", Title: "Auth0", Cat: "Auth", URL: "https://manage.auth0.com", Vars: []catVar{{"AUTH0_SECRET", true, "gen://hex/32"}, {"AUTH0_BASE_URL", false, "http://localhost:3000"}, {"AUTH0_ISSUER_BASE_URL", false, ""}, {"AUTH0_CLIENT_ID", false, ""}, {"AUTH0_CLIENT_SECRET", true, ""}}},
	{Name: "workos", Title: "WorkOS", Cat: "Auth", URL: "https://dashboard.workos.com", Vars: []catVar{{"WORKOS_API_KEY", true, ""}, {"WORKOS_CLIENT_ID", false, ""}}},
	{Name: "stytch", Title: "Stytch", Cat: "Auth", URL: "https://stytch.com/dashboard", Vars: []catVar{{"STYTCH_PROJECT_ID", false, ""}, {"STYTCH_SECRET", true, ""}}},
	{Name: "kinde", Title: "Kinde", Cat: "Auth", URL: "https://app.kinde.com", Vars: []catVar{{"KINDE_CLIENT_ID", false, ""}, {"KINDE_CLIENT_SECRET", true, ""}, {"KINDE_ISSUER_URL", false, ""}, {"KINDE_SITE_URL", false, "http://localhost:3000"}}},

	// Payments
	{Name: "stripe", Title: "Stripe", Cat: "Payments", URL: "https://dashboard.stripe.com/apikeys", Vars: []catVar{{"STRIPE_SECRET_KEY", true, ""}, {"STRIPE_PUBLISHABLE_KEY", false, ""}, {"STRIPE_WEBHOOK_SECRET", true, ""}}},
	{Name: "paddle", Title: "Paddle", Cat: "Payments", URL: "https://vendors.paddle.com", Vars: []catVar{{"PADDLE_API_KEY", true, ""}, {"PADDLE_WEBHOOK_SECRET", true, ""}}},
	{Name: "lemonsqueezy", Title: "Lemon Squeezy", Cat: "Payments", URL: "https://app.lemonsqueezy.com/settings/api", Aliases: []string{"lemon"}, Vars: []catVar{{"LEMONSQUEEZY_API_KEY", true, ""}, {"LEMONSQUEEZY_WEBHOOK_SECRET", true, ""}, {"LEMONSQUEEZY_STORE_ID", false, ""}}},

	// Email & SMS
	{Name: "resend", Title: "Resend", Cat: "Email & SMS", URL: "https://resend.com/api-keys", Vars: []catVar{{"RESEND_API_KEY", true, ""}}},
	{Name: "sendgrid", Title: "SendGrid", Cat: "Email & SMS", URL: "https://app.sendgrid.com/settings/api_keys", Vars: []catVar{{"SENDGRID_API_KEY", true, ""}}},
	{Name: "postmark", Title: "Postmark", Cat: "Email & SMS", URL: "https://account.postmarkapp.com", Vars: []catVar{{"POSTMARK_SERVER_TOKEN", true, ""}}},
	{Name: "mailgun", Title: "Mailgun", Cat: "Email & SMS", URL: "https://app.mailgun.com", Vars: []catVar{{"MAILGUN_API_KEY", true, ""}, {"MAILGUN_DOMAIN", false, ""}}},
	{Name: "twilio", Title: "Twilio", Cat: "Email & SMS", URL: "https://console.twilio.com", Vars: []catVar{{"TWILIO_ACCOUNT_SID", false, ""}, {"TWILIO_AUTH_TOKEN", true, ""}, {"TWILIO_PHONE_NUMBER", false, ""}}},
	{Name: "loops", Title: "Loops", Cat: "Email & SMS", URL: "https://app.loops.so", Vars: []catVar{{"LOOPS_API_KEY", true, ""}}},

	// AI / ML
	{Name: "openai", Title: "OpenAI", Cat: "AI", URL: "https://platform.openai.com/api-keys", Vars: []catVar{{"OPENAI_API_KEY", true, ""}}},
	{Name: "anthropic", Title: "Anthropic", Cat: "AI", URL: "https://console.anthropic.com/settings/keys", Aliases: []string{"claude"}, Vars: []catVar{{"ANTHROPIC_API_KEY", true, ""}}},
	{Name: "huggingface", Title: "Hugging Face", Cat: "AI", URL: "https://huggingface.co/settings/tokens", Aliases: []string{"hf"}, Vars: []catVar{{"HF_TOKEN", true, ""}}},
	{Name: "gemini", Title: "Google Generative AI", Cat: "AI", URL: "https://aistudio.google.com/apikey", Aliases: []string{"google-ai"}, Vars: []catVar{{"GEMINI_API_KEY", true, ""}}},
	{Name: "groq", Title: "Groq", Cat: "AI", URL: "https://console.groq.com/keys", Vars: []catVar{{"GROQ_API_KEY", true, ""}}},
	{Name: "mistral", Title: "Mistral", Cat: "AI", URL: "https://console.mistral.ai", Vars: []catVar{{"MISTRAL_API_KEY", true, ""}}},
	{Name: "cohere", Title: "Cohere", Cat: "AI", URL: "https://dashboard.cohere.com/api-keys", Vars: []catVar{{"COHERE_API_KEY", true, ""}}},
	{Name: "replicate", Title: "Replicate", Cat: "AI", URL: "https://replicate.com/account/api-tokens", Vars: []catVar{{"REPLICATE_API_TOKEN", true, ""}}},
	{Name: "openrouter", Title: "OpenRouter", Cat: "AI", URL: "https://openrouter.ai/keys", Vars: []catVar{{"OPENROUTER_API_KEY", true, ""}}},
	{Name: "perplexity", Title: "Perplexity", Cat: "AI", URL: "https://perplexity.ai", Vars: []catVar{{"PERPLEXITY_API_KEY", true, ""}}},
	{Name: "elevenlabs", Title: "ElevenLabs", Cat: "AI", URL: "https://elevenlabs.io/app/settings/api-keys", Vars: []catVar{{"ELEVENLABS_API_KEY", true, ""}}},
	{Name: "xai", Title: "xAI", Cat: "AI", URL: "https://console.x.ai", Aliases: []string{"grok"}, Vars: []catVar{{"XAI_API_KEY", true, ""}}},
	{Name: "deepseek", Title: "DeepSeek", Cat: "AI", URL: "https://platform.deepseek.com", Vars: []catVar{{"DEEPSEEK_API_KEY", true, ""}}},
	{Name: "together", Title: "Together AI", Cat: "AI", URL: "https://api.together.xyz/settings/api-keys", Vars: []catVar{{"TOGETHER_API_KEY", true, ""}}},
	{Name: "fal", Title: "fal", Cat: "AI", URL: "https://fal.ai/dashboard/keys", Vars: []catVar{{"FAL_KEY", true, ""}}},

	// Platforms & infra
	{Name: "vercel", Title: "Vercel", Cat: "Platforms", URL: "https://vercel.com/account/tokens", Vars: []catVar{{"VERCEL_TOKEN", true, ""}, {"VERCEL_ORG_ID", false, ""}, {"VERCEL_PROJECT_ID", false, ""}}},
	{Name: "cloudflare", Title: "Cloudflare", Cat: "Platforms", URL: "https://dash.cloudflare.com/profile/api-tokens", Vars: []catVar{{"CLOUDFLARE_API_TOKEN", true, ""}, {"CLOUDFLARE_ACCOUNT_ID", false, ""}}},
	{Name: "fly", Title: "Fly.io", Cat: "Platforms", URL: "https://fly.io/user/personal_access_tokens", Vars: []catVar{{"FLY_API_TOKEN", true, ""}}},
	{Name: "railway", Title: "Railway", Cat: "Platforms", URL: "https://railway.app/account/tokens", Vars: []catVar{{"RAILWAY_TOKEN", true, ""}}},
	{Name: "aws", Title: "AWS", Cat: "Platforms", URL: "https://console.aws.amazon.com/iam", Vars: []catVar{{"AWS_ACCESS_KEY_ID", false, ""}, {"AWS_SECRET_ACCESS_KEY", true, ""}, {"AWS_REGION", false, "us-east-1"}}},
	{Name: "github", Title: "GitHub (OAuth/API)", Cat: "Platforms", URL: "https://github.com/settings/developers", Vars: []catVar{{"GITHUB_CLIENT_ID", false, ""}, {"GITHUB_CLIENT_SECRET", true, ""}, {"GITHUB_TOKEN", true, ""}}},
	{Name: "google-oauth", Title: "Google OAuth", Cat: "Platforms", URL: "https://console.cloud.google.com/apis/credentials", Vars: []catVar{{"GOOGLE_CLIENT_ID", false, ""}, {"GOOGLE_CLIENT_SECRET", true, ""}}},
	{Name: "encore", Title: "Encore", Cat: "Platforms", URL: "https://encore.dev/docs/primitives/secrets", Note: "Encore manages secrets via `encore secret set` — no standard env vars to scaffold."},

	// Observability & analytics
	{Name: "sentry", Title: "Sentry", Cat: "Observability", URL: "https://sentry.io/settings/account/api/auth-tokens/", Vars: []catVar{{"SENTRY_DSN", false, ""}, {"SENTRY_AUTH_TOKEN", true, ""}}},
	{Name: "posthog", Title: "PostHog", Cat: "Observability", URL: "https://app.posthog.com", Vars: []catVar{{"NEXT_PUBLIC_POSTHOG_KEY", false, ""}, {"NEXT_PUBLIC_POSTHOG_HOST", false, "https://us.i.posthog.com"}}},
	{Name: "datadog", Title: "Datadog", Cat: "Observability", URL: "https://app.datadoghq.com/organization-settings/api-keys", Vars: []catVar{{"DD_API_KEY", true, ""}}},
	{Name: "axiom", Title: "Axiom", Cat: "Observability", URL: "https://app.axiom.co", Vars: []catVar{{"AXIOM_TOKEN", true, ""}, {"AXIOM_ORG_ID", false, ""}}},

	// Storage, search, jobs, realtime
	{Name: "cloudinary", Title: "Cloudinary", Cat: "Storage & media", URL: "https://console.cloudinary.com", Vars: []catVar{{"CLOUDINARY_URL", true, ""}}},
	{Name: "uploadthing", Title: "UploadThing", Cat: "Storage & media", URL: "https://uploadthing.com/dashboard", Vars: []catVar{{"UPLOADTHING_TOKEN", true, ""}}},
	{Name: "algolia", Title: "Algolia", Cat: "Search", URL: "https://dashboard.algolia.com/account/api-keys", Vars: []catVar{{"ALGOLIA_APP_ID", false, ""}, {"ALGOLIA_API_KEY", true, ""}}},
	{Name: "meilisearch", Title: "Meilisearch", Cat: "Search", URL: "https://meilisearch.com", Vars: []catVar{{"MEILI_MASTER_KEY", true, "gen://random/32"}, {"MEILI_HOST", false, "http://localhost:7700"}}},
	{Name: "inngest", Title: "Inngest", Cat: "Jobs & queues", URL: "https://app.inngest.com", Vars: []catVar{{"INNGEST_EVENT_KEY", true, ""}, {"INNGEST_SIGNING_KEY", true, ""}}},
	{Name: "trigger", Title: "Trigger.dev", Cat: "Jobs & queues", URL: "https://cloud.trigger.dev", Vars: []catVar{{"TRIGGER_SECRET_KEY", true, ""}}},
	{Name: "pusher", Title: "Pusher", Cat: "Realtime", URL: "https://dashboard.pusher.com", Vars: []catVar{{"PUSHER_APP_ID", false, ""}, {"PUSHER_KEY", false, ""}, {"PUSHER_SECRET", true, ""}, {"PUSHER_CLUSTER", false, ""}}},
	{Name: "ably", Title: "Ably", Cat: "Realtime", URL: "https://ably.com/accounts", Vars: []catVar{{"ABLY_API_KEY", true, ""}}},
	{Name: "liveblocks", Title: "Liveblocks", Cat: "Realtime", URL: "https://liveblocks.io/dashboard", Vars: []catVar{{"LIVEBLOCKS_SECRET_KEY", true, ""}, {"NEXT_PUBLIC_LIVEBLOCKS_PUBLIC_KEY", false, ""}}},
	{Name: "stream", Title: "Stream", Cat: "Realtime", URL: "https://getstream.io/dashboard", Vars: []catVar{{"STREAM_API_KEY", false, ""}, {"STREAM_API_SECRET", true, ""}}},
	{Name: "knock", Title: "Knock", Cat: "Realtime", URL: "https://dashboard.knock.app", Vars: []catVar{{"KNOCK_API_KEY", true, ""}, {"NEXT_PUBLIC_KNOCK_PUBLIC_API_KEY", false, ""}}},

	// Backends & frameworks
	{Name: "meteor", Title: "Meteor", Cat: "Backends & frameworks", URL: "https://docs.meteor.com/api/meteor.html#environment", Aliases: []string{"galaxy"}, Vars: []catVar{{"MONGO_URL", true, ""}, {"ROOT_URL", false, "http://localhost:3000"}, {"MAIL_URL", true, ""}, {"METEOR_SETTINGS", true, ""}}},
	{Name: "restate", Title: "Restate", Cat: "Backends & frameworks", URL: "https://docs.restate.dev", Vars: []catVar{{"RESTATE_ADMIN_URL", false, "http://localhost:9070"}, {"RESTATE_INGRESS_URL", false, "http://localhost:8080"}, {"RESTATE_API_KEY", true, ""}}},
	{Name: "convex", Title: "Convex", Cat: "Backends & frameworks", URL: "https://dashboard.convex.dev", Vars: []catVar{{"CONVEX_DEPLOYMENT", false, ""}, {"CONVEX_DEPLOY_KEY", true, ""}, {"NEXT_PUBLIC_CONVEX_URL", false, ""}}},
	{Name: "payload", Title: "Payload CMS", Cat: "Backends & frameworks", URL: "https://payloadcms.com", Vars: []catVar{{"PAYLOAD_SECRET", true, "gen://random/32"}, {"DATABASE_URI", true, ""}}},

	// More databases
	{Name: "firebase", Title: "Firebase", Cat: "Databases", URL: "https://console.firebase.google.com", Vars: []catVar{{"FIREBASE_PROJECT_ID", false, ""}, {"NEXT_PUBLIC_FIREBASE_API_KEY", false, ""}, {"FIREBASE_SERVICE_ACCOUNT_KEY", true, ""}}},
	{Name: "appwrite", Title: "Appwrite", Cat: "Databases", URL: "https://cloud.appwrite.io", Vars: []catVar{{"APPWRITE_ENDPOINT", false, "https://cloud.appwrite.io/v1"}, {"APPWRITE_PROJECT_ID", false, ""}, {"APPWRITE_API_KEY", true, ""}}},
	{Name: "xata", Title: "Xata", Cat: "Databases", URL: "https://app.xata.io", Vars: []catVar{{"XATA_API_KEY", true, ""}, {"XATA_BRANCH", false, "main"}}},
	{Name: "redis", Title: "Redis", Cat: "Databases", URL: "https://redis.io", Vars: []catVar{{"REDIS_URL", true, "redis://localhost:6379"}}},

	// More AI / vector
	{Name: "langfuse", Title: "Langfuse", Cat: "AI", URL: "https://cloud.langfuse.com", Vars: []catVar{{"LANGFUSE_PUBLIC_KEY", false, ""}, {"LANGFUSE_SECRET_KEY", true, ""}, {"LANGFUSE_HOST", false, "https://cloud.langfuse.com"}}},
	{Name: "langsmith", Title: "LangSmith", Cat: "AI", URL: "https://smith.langchain.com", Aliases: []string{"langchain"}, Vars: []catVar{{"LANGCHAIN_API_KEY", true, ""}, {"LANGCHAIN_TRACING_V2", false, "true"}, {"LANGCHAIN_ENDPOINT", false, "https://api.smith.langchain.com"}}},
	{Name: "pinecone", Title: "Pinecone", Cat: "AI", URL: "https://app.pinecone.io", Vars: []catVar{{"PINECONE_API_KEY", true, ""}}},
	{Name: "qdrant", Title: "Qdrant", Cat: "AI", URL: "https://cloud.qdrant.io", Vars: []catVar{{"QDRANT_URL", false, ""}, {"QDRANT_API_KEY", true, ""}}},
	{Name: "weaviate", Title: "Weaviate", Cat: "AI", URL: "https://console.weaviate.cloud", Vars: []catVar{{"WEAVIATE_URL", false, ""}, {"WEAVIATE_API_KEY", true, ""}}},
	{Name: "deepgram", Title: "Deepgram", Cat: "AI", URL: "https://console.deepgram.com", Vars: []catVar{{"DEEPGRAM_API_KEY", true, ""}}},
	{Name: "assemblyai", Title: "AssemblyAI", Cat: "AI", URL: "https://www.assemblyai.com/app", Vars: []catVar{{"ASSEMBLYAI_API_KEY", true, ""}}},

	// More payments
	{Name: "polar", Title: "Polar", Cat: "Payments", URL: "https://polar.sh/settings", Vars: []catVar{{"POLAR_ACCESS_TOKEN", true, ""}, {"POLAR_WEBHOOK_SECRET", true, ""}}},
	{Name: "square", Title: "Square", Cat: "Payments", URL: "https://developer.squareup.com/apps", Vars: []catVar{{"SQUARE_ACCESS_TOKEN", true, ""}, {"SQUARE_ENVIRONMENT", false, "sandbox"}}},
	{Name: "razorpay", Title: "Razorpay", Cat: "Payments", URL: "https://dashboard.razorpay.com", Vars: []catVar{{"RAZORPAY_KEY_ID", false, ""}, {"RAZORPAY_KEY_SECRET", true, ""}}},

	// More email / SMS
	{Name: "plunk", Title: "Plunk", Cat: "Email & SMS", URL: "https://app.useplunk.com", Vars: []catVar{{"PLUNK_API_KEY", true, ""}}},
	{Name: "courier", Title: "Courier", Cat: "Email & SMS", URL: "https://app.courier.com", Vars: []catVar{{"COURIER_AUTH_TOKEN", true, ""}}},

	// CMS & content
	{Name: "sanity", Title: "Sanity", Cat: "CMS & content", URL: "https://www.sanity.io/manage", Vars: []catVar{{"SANITY_PROJECT_ID", false, ""}, {"SANITY_DATASET", false, "production"}, {"SANITY_API_TOKEN", true, ""}}},
	{Name: "contentful", Title: "Contentful", Cat: "CMS & content", URL: "https://app.contentful.com", Vars: []catVar{{"CONTENTFUL_SPACE_ID", false, ""}, {"CONTENTFUL_ACCESS_TOKEN", true, ""}}},
	{Name: "storyblok", Title: "Storyblok", Cat: "CMS & content", URL: "https://app.storyblok.com", Vars: []catVar{{"STORYBLOK_TOKEN", true, ""}}},

	// More storage / media
	{Name: "r2", Title: "Cloudflare R2", Cat: "Storage & media", URL: "https://dash.cloudflare.com", Aliases: []string{"cloudflare-r2"}, Vars: []catVar{{"R2_ACCOUNT_ID", false, ""}, {"R2_ACCESS_KEY_ID", false, ""}, {"R2_SECRET_ACCESS_KEY", true, ""}, {"R2_BUCKET", false, ""}}},
	{Name: "mux", Title: "Mux", Cat: "Storage & media", URL: "https://dashboard.mux.com", Vars: []catVar{{"MUX_TOKEN_ID", false, ""}, {"MUX_TOKEN_SECRET", true, ""}}},

	// More observability
	{Name: "honeycomb", Title: "Honeycomb", Cat: "Observability", URL: "https://ui.honeycomb.io", Vars: []catVar{{"HONEYCOMB_API_KEY", true, ""}}},
	{Name: "betterstack", Title: "Better Stack", Cat: "Observability", URL: "https://betterstack.com", Aliases: []string{"logtail"}, Vars: []catVar{{"LOGTAIL_SOURCE_TOKEN", true, ""}}},
	{Name: "newrelic", Title: "New Relic", Cat: "Observability", URL: "https://one.newrelic.com", Vars: []catVar{{"NEW_RELIC_LICENSE_KEY", true, ""}}},
	{Name: "rollbar", Title: "Rollbar", Cat: "Observability", URL: "https://rollbar.com", Vars: []catVar{{"ROLLBAR_ACCESS_TOKEN", true, ""}}},
	{Name: "otel", Title: "OpenTelemetry", Cat: "Observability", URL: "https://opentelemetry.io", Aliases: []string{"opentelemetry"}, Vars: []catVar{{"OTEL_EXPORTER_OTLP_ENDPOINT", false, ""}, {"OTEL_EXPORTER_OTLP_HEADERS", true, ""}}},

	// Analytics
	{Name: "segment", Title: "Segment", Cat: "Analytics", URL: "https://app.segment.com", Vars: []catVar{{"SEGMENT_WRITE_KEY", true, ""}}},
	{Name: "mixpanel", Title: "Mixpanel", Cat: "Analytics", URL: "https://mixpanel.com", Vars: []catVar{{"MIXPANEL_TOKEN", true, ""}}},
	{Name: "amplitude", Title: "Amplitude", Cat: "Analytics", URL: "https://amplitude.com", Vars: []catVar{{"AMPLITUDE_API_KEY", true, ""}}},

	// Feature flags
	{Name: "launchdarkly", Title: "LaunchDarkly", Cat: "Feature flags", URL: "https://app.launchdarkly.com", Vars: []catVar{{"LAUNCHDARKLY_SDK_KEY", true, ""}}},
	{Name: "statsig", Title: "Statsig", Cat: "Feature flags", URL: "https://console.statsig.com", Vars: []catVar{{"STATSIG_SERVER_SECRET_KEY", true, ""}}},

	// More search
	{Name: "typesense", Title: "Typesense", Cat: "Search", URL: "https://cloud.typesense.org", Vars: []catVar{{"TYPESENSE_API_KEY", true, ""}, {"TYPESENSE_HOST", false, ""}}},
	{Name: "elastic", Title: "Elasticsearch", Cat: "Search", URL: "https://cloud.elastic.co", Vars: []catVar{{"ELASTICSEARCH_URL", false, ""}, {"ELASTIC_API_KEY", true, ""}}},

	// More jobs & queues
	{Name: "qstash", Title: "Upstash QStash", Cat: "Jobs & queues", URL: "https://console.upstash.com/qstash", Vars: []catVar{{"QSTASH_TOKEN", true, ""}, {"QSTASH_URL", false, "https://qstash.upstash.io"}}},
	{Name: "temporal", Title: "Temporal", Cat: "Jobs & queues", URL: "https://cloud.temporal.io", Vars: []catVar{{"TEMPORAL_ADDRESS", false, ""}, {"TEMPORAL_NAMESPACE", false, "default"}, {"TEMPORAL_API_KEY", true, ""}}},
	{Name: "svix", Title: "Svix", Cat: "Jobs & queues", URL: "https://dashboard.svix.com", Vars: []catVar{{"SVIX_API_KEY", true, ""}}},

	// Maps
	{Name: "mapbox", Title: "Mapbox", Cat: "Maps", URL: "https://account.mapbox.com/access-tokens", Vars: []catVar{{"MAPBOX_ACCESS_TOKEN", false, ""}}},
	{Name: "googlemaps", Title: "Google Maps", Cat: "Maps", URL: "https://console.cloud.google.com/google/maps-apis", Aliases: []string{"google-maps"}, Vars: []catVar{{"GOOGLE_MAPS_API_KEY", false, ""}}},
}

var catByName = func() map[string]catEntry {
	m := make(map[string]catEntry)
	for _, e := range catalog {
		m[e.Name] = e
		for _, a := range e.Aliases {
			m[a] = e
		}
	}
	return m
}()

func catLookup(s string) (catEntry, bool) {
	e, ok := catByName[strings.ToLower(strings.TrimSpace(s))]
	return e, ok
}

func hasRef(s string) bool { return looksLikeRef(s) || refRe.MatchString(s) }

// resolveValue expands all references in value (env is the environment the value
// belongs to, for relative envd:// lookups). Assumes d.mu is held.
func (d *Daemon) resolveValue(u *unlocked, env, value string, depth int) (string, error) {
	if depth > 8 {
		return "", errors.New("reference depth exceeded (cycle?)")
	}
	var rerr error
	out := refRe.ReplaceAllStringFunc(value, func(m string) string {
		inner := strings.TrimSpace(m[2 : len(m)-1])
		r, err := d.resolveRef(u, env, inner, depth+1)
		if err != nil {
			rerr = err
			return m
		}
		return r
	})
	if rerr != nil {
		return "", rerr
	}
	if looksLikeRef(out) {
		return d.resolveRef(u, env, strings.TrimSpace(out), depth+1)
	}
	return out, nil
}

func (d *Daemon) resolveRef(u *unlocked, env, ref string, depth int) (string, error) {
	// envd:// is internal (recurse into the vault), not a CLI provider.
	if strings.HasPrefix(ref, "envd://") {
		parts := strings.SplitN(strings.TrimPrefix(ref, "envd://"), "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", fmt.Errorf("bad reference %q (want envd://<env>/<KEY>)", ref)
		}
		renv, rkey := parts[0], parts[1]
		m, ok := u.readLayer(renv)
		if !ok {
			return "", fmt.Errorf("%s: unknown env %q", ref, renv)
		}
		v, ok := m[rkey]
		if !ok {
			return "", fmt.Errorf("%s: unknown key %q", ref, rkey)
		}
		return d.resolveValue(u, renv, v, depth+1)
	}

	sc := schemeOf(ref)
	p, ok := providerByScheme[sc]
	if !ok {
		return "", fmt.Errorf("unknown reference scheme in %q", ref)
	}
	if v, ok := d.refCacheGet(ref); ok { // avoid hammering the provider every prompt
		return v, nil
	}
	if p.bin != "" {
		if _, err := exec.LookPath(p.bin); err != nil {
			return "", fmt.Errorf("%s:// needs the %q CLI on PATH", sc, p.bin)
		}
	}
	v, err := p.fn(strings.TrimPrefix(ref, sc+"://"))
	if err != nil {
		return "", err
	}
	d.refCacheSet(ref, v)
	return v, nil
}

// ---------------------------------------------------------------------------
// Value generators: gen://random/N, gen://hex/N, gen://uuid, gen://password/N.
// Materialized once at set-time so the generated value is stable thereafter.
// ---------------------------------------------------------------------------

// materializeGen replaces any gen:// generators in value (whole-value or
// embedded via ${...}) with freshly generated, concrete values.
func materializeGen(value string) (string, error) {
	var rerr error
	out := refRe.ReplaceAllStringFunc(value, func(m string) string {
		inner := strings.TrimSpace(m[2 : len(m)-1])
		if !strings.HasPrefix(inner, "gen://") {
			return m
		}
		v, err := genValue(inner)
		if err != nil {
			rerr = err
			return m
		}
		return v
	})
	if rerr != nil {
		return "", rerr
	}
	if strings.HasPrefix(strings.TrimSpace(out), "gen://") {
		return genValue(strings.TrimSpace(out))
	}
	return out, nil
}

func genValue(spec string) (string, error) {
	parts := strings.SplitN(strings.TrimPrefix(spec, "gen://"), "/", 2)
	n := 0
	if len(parts) == 2 {
		n, _ = strconv.Atoi(parts[1])
	}
	switch parts[0] {
	case "uuid":
		return genUUID(), nil
	case "random":
		if n <= 0 {
			n = 32
		}
		return base64.RawStdEncoding.EncodeToString(randBytes(n)), nil
	case "hex":
		if n <= 0 {
			n = 32
		}
		return hex.EncodeToString(randBytes(n)), nil
	case "password":
		if n <= 0 {
			n = 24
		}
		const al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		rb := randBytes(n)
		out := make([]byte, n)
		for i := range out {
			out[i] = al[int(rb[i])%len(al)]
		}
		return string(out), nil
	}
	return "", fmt.Errorf("unknown generator %q (want random|hex|uuid|password)", spec)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func genUUID() string {
	b := randBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (d *Daemon) handleExport(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	resp := Response{OK: true, Exports: map[string]string{}}
	newSet := map[string]string{}
	p := d.findProject(req.Cwd)
	if p == nil { // auto-adopt a cloned/unregistered vault found at or above cwd
		if root := findVaultRoot(req.Cwd); root != "" {
			if _, err := d.adopt(root); err == nil {
				p = d.findProject(req.Cwd)
			}
		}
	}
	if p != nil {
		if u, err := d.getUnlocked(p); err == nil && u != nil {
			for k, raw := range u.effective(p.ActiveEnv) {
				v, err := d.resolveValue(u, p.ActiveEnv, raw, 0)
				if err != nil {
					continue // fail closed: unresolvable refs are omitted
				}
				newSet[k] = v
			}
			resp.Env = p.ActiveEnv
		}
		if sh := arg(req, "shell"); sh != "" {
			d.sessions[sh] = session{Project: p.Name, Env: p.ActiveEnv, Cwd: req.Cwd, Last: time.Now()}
		}
	}
	resp.Exports = newSet
	for _, k := range req.Applied {
		if _, ok := newSet[k]; !ok {
			resp.Unsets = append(resp.Unsets, k)
		}
	}
	return resp
}

func (d *Daemon) handleUse(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProjectByReq(req)
	if p == nil {
		return Response{Error: "no envd project here (run `envd init`)"}
	}
	env := arg(req, "env")
	found := false
	for _, e := range p.Envs {
		if strings.TrimSpace(e) == env {
			found = true
		}
	}
	if !found {
		return Response{Error: "unknown env " + env + " (have: " + strings.Join(p.Envs, ",") + ")"}
	}
	p.ActiveEnv = env
	d.saveState()
	return Response{OK: true, Env: env, Text: p.Name + ": active env → " + env}
}

func (d *Daemon) handleSet(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProjectByReq(req)
	if p == nil {
		return Response{Error: "no envd project here (run `envd init`)"}
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	env := arg(req, "env")
	if env == "" {
		env = p.ActiveEnv
	}
	if env != "base" {
		if _, ok := u.vault.Values[env]; !ok {
			return Response{Error: "unknown env " + env}
		}
	}
	val, err := materializeGen(arg(req, "value"))
	if err != nil {
		return Response{Error: err.Error()}
	}
	key := arg(req, "key")
	layer := u.layer(env)
	old, had := layer[key]
	if had && old != val && arg(req, "force") != "true" {
		return Response{NeedConfirm: true, Text: fmt.Sprintf("%s is already set in %s/%s", key, p.Name, env)}
	}
	layer[key] = val
	u.record(HistoryEntry{Op: "set", Env: env, Key: key, Old: old, HadOld: had, New: val})
	if err := saveVault(p.Path, u.vault, u.vf, u.key); err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, Text: fmt.Sprintf("set %s for %s/%s", key, p.Name, env)}
}

func (d *Daemon) handleRegister(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.registerLocked(req)
}

// registerLocked is handleRegister's body; assumes d.mu is held so it can be
// reused by other handlers (e.g. assimilate).
func (d *Daemon) registerLocked(req Request) Response {
	name := arg(req, "name")
	path := filepath.Clean(req.Cwd)
	var envs []string
	for _, e := range strings.Split(arg(req, "envs"), ",") {
		if e = strings.TrimSpace(e); e != "" && e != "base" {
			envs = append(envs, e)
		}
	}
	if len(envs) == 0 {
		return Response{Error: "no environments specified"}
	}

	id := newID()
	vf := &vaultFile{Version: 1, Project: name, KeyID: appName + "-" + id, KDF: "keychain"}
	key := newKey()
	if arg(req, "kdf") == "pbkdf2" {
		vf.KDF = "pbkdf2"
		salt := make([]byte, 16)
		_, _ = rand.Read(salt)
		vf.Salt = base64.StdEncoding.EncodeToString(salt)
		k, err := pbkdf2Key(os.Getenv("ENVD_PASSPHRASE"), salt)
		if err != nil {
			return Response{Error: err.Error()}
		}
		key = k
	} else {
		if err := keychainSet(vf.KeyID, key); err != nil {
			return Response{Error: err.Error()}
		}
	}

	v := &Vault{
		Project:      name,
		Environments: envs,
		Base:         map[string]string{},
		Values:       map[string]map[string]string{},
		Providers:    map[string]ProviderState{},
	}
	for _, e := range envs {
		v.Values[e] = map[string]string{}
	}
	if err := saveVault(path, v, vf, key); err != nil {
		return Response{Error: err.Error()}
	}

	d.removeProjectByPath(path)
	d.state.Projects = append(d.state.Projects, Project{
		Name: name, Path: path, ID: id, Envs: envs, ActiveEnv: envs[0],
	})
	d.cache[path] = &unlocked{vault: v, vf: vf, key: key}
	d.saveState()
	return Response{OK: true, Text: fmt.Sprintf("registered %q [%s] active=%s", name, strings.Join(envs, ","), envs[0])}
}

func (d *Daemon) handleSaveProvider(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProject(req.Cwd)
	if p == nil {
		return Response{Error: "no envd project here"}
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	if u.vault.Providers == nil {
		u.vault.Providers = map[string]ProviderState{}
	}
	u.vault.Providers[arg(req, "provider")] = ProviderState{Token: json.RawMessage(arg(req, "token"))}
	if err := saveVault(p.Path, u.vault, u.vf, u.key); err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true}
}

func (d *Daemon) handleStatus() Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "%s daemon — %d project(s)\n", appName, len(d.state.Projects))
	for i := range d.state.Projects {
		p := &d.state.Projects[i]
		note, nVars := "", 0
		if u, err := d.getUnlocked(p); err != nil {
			note = "  [locked: " + err.Error() + "]"
		} else {
			nVars = len(u.vault.Values[p.ActiveEnv])
		}
		fmt.Fprintf(&b, "  • %s  envs=[%s]  active=%s  vars=%d%s\n      %s\n",
			p.Name, strings.Join(p.Envs, ","), p.ActiveEnv, nVars, note, p.Path)
	}
	var shells []string
	for id, s := range d.sessions {
		if time.Since(s.Last) < 2*time.Hour {
			shells = append(shells, fmt.Sprintf("      shell %s → %s/%s  (%s)", id, s.Project, s.Env, s.Cwd))
		}
	}
	if len(shells) > 0 {
		sort.Strings(shells)
		fmt.Fprintf(&b, "  active shells:\n%s\n", strings.Join(shells, "\n"))
	}
	return Response{OK: true, Text: b.String()}
}

// findProjectByReq resolves the target project from Args["project"] (a path or
// name) when set, else falls back to the request cwd. Assumes d.mu is held.
func (d *Daemon) findProjectByReq(req Request) *Project {
	if want := arg(req, "project"); want != "" {
		clean := filepath.Clean(want)
		for i := range d.state.Projects {
			if filepath.Clean(d.state.Projects[i].Path) == clean || d.state.Projects[i].Name == want {
				return &d.state.Projects[i]
			}
		}
		return nil
	}
	return d.findProject(req.Cwd)
}

func (d *Daemon) handleProjects() Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	var pv []ProjectView
	for i := range d.state.Projects {
		p := &d.state.Projects[i]
		_, err := d.getUnlocked(p)
		pv = append(pv, ProjectView{
			Name: p.Name, Path: p.Path, Envs: p.Envs,
			ActiveEnv: p.ActiveEnv, Locked: err != nil,
		})
	}
	return Response{OK: true, Projects: pv}
}

func (d *Daemon) handleVars(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProjectByReq(req)
	if p == nil {
		return Response{Error: "no such project"}
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	env := arg(req, "env")
	if env == "" {
		env = p.ActiveEnv
	}
	if env != "base" {
		if _, ok := u.vault.Values[env]; !ok {
			return Response{Error: "unknown env " + env}
		}
	}
	resolve := arg(req, "resolve") == "true"

	// Effective key set: for a real env, union(base, env) with env overriding;
	// for the base layer itself, just its own keys (nothing to inherit).
	envMap, _ := u.readLayer(env)
	var base map[string]string
	if env != "base" {
		base = u.vault.Base
	}
	keyset := map[string]struct{}{}
	for k := range base {
		keyset[k] = struct{}{}
	}
	for k := range envMap {
		keyset[k] = struct{}{}
	}
	keys := make([]string, 0, len(keyset))
	for k := range keyset {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var vars []VarView
	for _, k := range keys {
		val, inEnv := envMap[k]
		_, inBase := base[k]
		vv := VarView{Key: k}
		if inEnv {
			vv.Value, vv.Overrides = val, inBase
		} else {
			vv.Value, vv.Inherited = base[k], true
		}
		vv.IsRef = hasRef(vv.Value)
		if resolve {
			if r, err := d.resolveValue(u, env, vv.Value, 0); err != nil {
				vv.ResolveErr = err.Error()
			} else {
				vv.Resolved = r
			}
		}
		vars = append(vars, vv)
	}
	return Response{OK: true, Env: env, Vars: vars}
}

func (d *Daemon) handleUnset(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProjectByReq(req)
	if p == nil {
		return Response{Error: "no such project"}
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	env := arg(req, "env")
	if env == "" {
		env = p.ActiveEnv
	}
	m, ok := u.readLayer(env)
	if !ok {
		return Response{Error: "unknown env " + env}
	}
	key := arg(req, "key")
	old, ok := m[key]
	if !ok {
		return Response{Error: "no such key " + key + " in " + env}
	}
	delete(m, key)
	u.record(HistoryEntry{Op: "unset", Env: env, Key: key, Old: old, HadOld: true})
	if err := saveVault(p.Path, u.vault, u.vf, u.key); err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, Text: fmt.Sprintf("unset %s from %s/%s", key, p.Name, env)}
}

func (d *Daemon) handleAddEnv(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProjectByReq(req)
	if p == nil {
		return Response{Error: "no such project"}
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	env := strings.TrimSpace(arg(req, "env"))
	if env == "" {
		return Response{Error: "empty environment name"}
	}
	if env == "base" {
		return Response{Error: "'base' is reserved for the shared layer"}
	}
	if _, ok := u.vault.Values[env]; ok {
		return Response{Error: "environment " + env + " already exists"}
	}
	u.vault.Values[env] = map[string]string{}
	u.vault.Environments = append(u.vault.Environments, env)
	p.Envs = append(p.Envs, env)
	u.record(HistoryEntry{Op: "addenv", Env: env})
	if err := saveVault(p.Path, u.vault, u.vf, u.key); err != nil {
		return Response{Error: err.Error()}
	}
	d.saveState()
	return Response{OK: true, Text: "added environment " + env}
}

func (d *Daemon) handleRmEnv(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProjectByReq(req)
	if p == nil {
		return Response{Error: "no such project"}
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	env := strings.TrimSpace(arg(req, "env"))
	if _, ok := u.vault.Values[env]; !ok {
		return Response{Error: "unknown env " + env}
	}
	if len(p.Envs) <= 1 {
		return Response{Error: "cannot remove the last environment"}
	}
	snap := make(map[string]string, len(u.vault.Values[env]))
	for k, v := range u.vault.Values[env] {
		snap[k] = v
	}
	delete(u.vault.Values, env)
	u.vault.Environments = removeStr(u.vault.Environments, env)
	p.Envs = removeStr(p.Envs, env)
	if p.ActiveEnv == env {
		p.ActiveEnv = p.Envs[0]
	}
	u.record(HistoryEntry{Op: "rmenv", Env: env, Snapshot: snap})
	if err := saveVault(p.Path, u.vault, u.vf, u.key); err != nil {
		return Response{Error: err.Error()}
	}
	d.saveState()
	return Response{OK: true, Text: "removed environment " + env}
}

func removeStr(ss []string, s string) []string {
	out := make([]string, 0, len(ss))
	for _, x := range ss {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

// handleDiff compares two environments' effective config (values masked).
func (d *Daemon) handleDiff(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProjectByReq(req)
	if p == nil {
		return Response{Error: "no such project"}
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	a, b := arg(req, "a"), arg(req, "b")
	for _, e := range []string{a, b} {
		if e != "base" {
			if _, ok := u.vault.Values[e]; !ok {
				return Response{Error: "unknown env " + e}
			}
		}
	}
	ea, eb := u.effective(a), u.effective(b)
	keyset := map[string]struct{}{}
	for k := range ea {
		keyset[k] = struct{}{}
	}
	for k := range eb {
		keyset[k] = struct{}{}
	}
	keys := make([]string, 0, len(keyset))
	for k := range keyset {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var onlyA, onlyB, differ []string
	same := 0
	for _, k := range keys {
		va, okA := ea[k]
		vb, okB := eb[k]
		switch {
		case okA && !okB:
			onlyA = append(onlyA, k)
		case !okA && okB:
			onlyB = append(onlyB, k)
		case va != vb:
			differ = append(differ, k)
		default:
			same++
		}
	}
	join := func(ss []string) string {
		if len(ss) == 0 {
			return "—"
		}
		return strings.Join(ss, ", ")
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s  %s ↔ %s  (values masked)\n", p.Name, a, b)
	fmt.Fprintf(&sb, "  only in %s:  %s\n", a, join(onlyA))
	fmt.Fprintf(&sb, "  only in %s:  %s\n", b, join(onlyB))
	fmt.Fprintf(&sb, "  differs:      %s\n", join(differ))
	fmt.Fprintf(&sb, "  identical:    %d key(s)\n", same)
	return Response{OK: true, Text: sb.String()}
}

// ---------------------------------------------------------------------------
// Code-aware doctor: scan source for env-var references and reconcile.
// ---------------------------------------------------------------------------

var envRefPatterns = []*regexp.Regexp{
	regexp.MustCompile(`process\.env\.([A-Za-z_][A-Za-z0-9_]*)`),
	regexp.MustCompile(`process\.env\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]`),
	regexp.MustCompile(`import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)`),
	regexp.MustCompile(`Deno\.env\.get\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]`),
	regexp.MustCompile(`Bun\.env\.([A-Za-z_][A-Za-z0-9_]*)`),
	regexp.MustCompile(`os\.Getenv\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']`),
	regexp.MustCompile(`os\.environ(?:\.get)?[\[(]\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]`),
}

var scanSkipDirs = map[string]bool{
	"node_modules": true, ".git": true, "dist": true, "build": true, ".next": true,
	".turbo": true, "vendor": true, ".envd": true, "coverage": true, ".cache": true,
	"out": true, "target": true, ".venv": true, "__pycache__": true, ".svelte-kit": true,
}

var scanExts = map[string]bool{
	".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true,
	".go": true, ".py": true, ".rb": true, ".vue": true, ".svelte": true, ".astro": true,
}

var placeholderRe = regexp.MustCompile(`(?i)^(changeme|change[-_ ]?me|todo|tbd|x{3,}|placeholder|your[-_ ]?\w+|<.+>|replace[-_ ]?me|fixme|example)$`)

func looksPlaceholder(v string) bool { return placeholderRe.MatchString(strings.TrimSpace(v)) }

// scanEnvRefs walks root and returns the sorted set of env-var names referenced
// in source files, plus the number of files scanned.
// walkSource calls fn with the contents of each scannable source file under root
// (skipping vendor/build dirs and large/non-source files), returning the count.
func walkSource(root string, fn func(data []byte)) int {
	files := 0
	_ = filepath.WalkDir(root, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if de.IsDir() {
			if scanSkipDirs[de.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !scanExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		if info, err := de.Info(); err != nil || info.Size() > 1<<20 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		files++
		fn(data)
		return nil
	})
	return files
}

func scanEnvRefs(root string) ([]string, int) {
	set := map[string]bool{}
	files := walkSource(root, func(data []byte) {
		for _, re := range envRefPatterns {
			for _, m := range re.FindAllStringSubmatch(string(data), -1) {
				set[m[1]] = true
			}
		}
	})
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, files
}

// envDefaultPatterns capture an inline fallback for a referenced env var, e.g.
// `process.env.PORT || 3000` or `os.getenv("X", "default")`.
var envDefaultPatterns = []*regexp.Regexp{
	regexp.MustCompile(`process\.env\.([A-Za-z_][A-Za-z0-9_]*)\s*(?:\|\||\?\?)\s*['"]([^'"]*)['"]`),
	regexp.MustCompile(`process\.env\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]\s*(?:\|\||\?\?)\s*['"]([^'"]*)['"]`),
	regexp.MustCompile(`process\.env\.([A-Za-z_][A-Za-z0-9_]*)\s*(?:\|\||\?\?)\s*(\d+)`),
	regexp.MustCompile(`os\.getenv\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*,\s*['"]([^'"]*)['"]`),
	regexp.MustCompile(`os\.environ\.get\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*,\s*['"]([^'"]*)['"]`),
}

// discoverDefaults scans source for inline env-var fallbacks → KEY=default value
// (first occurrence wins).
func discoverDefaults(root string) map[string]string {
	out := map[string]string{}
	walkSource(root, func(data []byte) {
		for _, re := range envDefaultPatterns {
			for _, m := range re.FindAllStringSubmatch(string(data), -1) {
				if _, ok := out[m[1]]; !ok {
					out[m[1]] = m[2]
				}
			}
		}
	})
	return out
}

// systemEnvDeny are shell/system vars we never capture from the environment even
// if the code references them.
var systemEnvDeny = map[string]bool{
	"PATH": true, "HOME": true, "SHELL": true, "USER": true, "LOGNAME": true,
	"PWD": true, "OLDPWD": true, "TMPDIR": true, "TERM": true, "LANG": true,
	"SHLVL": true, "_": true,
}

// resolveReferenced fills layers["base"] for code-referenced keys that no .env
// file provided, using (1) the current environment, then (2) an inline code
// default; anything left is stored blank and reported as undetermined.
func resolveReferenced(layers map[string]map[string]string, referenced []string, defaults map[string]string, lookupEnv func(string) (string, bool)) (fromEnv, fromDefault, undetermined []string) {
	if layers["base"] == nil {
		layers["base"] = map[string]string{}
	}
	present := func(k string) bool {
		for _, m := range layers {
			if _, ok := m[k]; ok {
				return true
			}
		}
		return false
	}
	sorted := append([]string(nil), referenced...)
	sort.Strings(sorted)
	for _, k := range sorted {
		if present(k) {
			continue
		}
		if v, ok := lookupEnv(k); ok {
			layers["base"][k] = v
			fromEnv = append(fromEnv, k)
		} else if d, ok := defaults[k]; ok {
			layers["base"][k] = d
			fromDefault = append(fromDefault, k)
		} else {
			layers["base"][k] = "" // referenced but undetermined — track + warn
			undetermined = append(undetermined, k)
		}
	}
	return fromEnv, fromDefault, undetermined
}

func (d *Daemon) handleDoctor(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProjectByReq(req)
	if p == nil {
		return Response{Error: "no such project"}
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	env := arg(req, "env")
	if env == "" {
		env = p.ActiveEnv
	}
	if env != "base" {
		if _, ok := u.vault.Values[env]; !ok {
			return Response{Error: "unknown env " + env}
		}
	}
	referenced, nfiles := scanEnvRefs(p.Path)
	refSet := map[string]bool{}
	for _, k := range referenced {
		refSet[k] = true
	}
	eff := u.effective(env)
	rep := &DoctorReport{Env: env, FilesScanned: nfiles, Referenced: referenced}
	for _, k := range referenced {
		if _, ok := eff[k]; !ok {
			rep.Missing = append(rep.Missing, k)
		}
	}
	keys := make([]string, 0, len(eff))
	for k := range eff {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !refSet[k] {
			rep.Unused = append(rep.Unused, k)
		}
		v := eff[k]
		if hasRef(v) {
			continue // a reference isn't empty/placeholder
		}
		if strings.TrimSpace(v) == "" {
			rep.Empty = append(rep.Empty, k)
		} else if looksPlaceholder(v) {
			rep.Placeholder = append(rep.Placeholder, k)
		}
	}
	text := doctorText(p.Name, rep)
	if arg(req, "example") == "true" {
		var b strings.Builder
		b.WriteString("# Generated by envd — required environment variables (no values).\n")
		for _, k := range referenced {
			b.WriteString(k + "=\n")
		}
		path := filepath.Join(p.Path, ".env.example")
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			return Response{Error: err.Error()}
		}
		text += fmt.Sprintf("\n✓ wrote %s (%d keys)\n", path, len(referenced))
	}
	return Response{OK: true, Doctor: rep, Text: text}
}

func doctorText(project string, r *DoctorReport) string {
	line := func(label string, ss []string) string {
		if len(ss) == 0 {
			return fmt.Sprintf("  %-12s —\n", label)
		}
		return fmt.Sprintf("  %-12s %s\n", label, strings.Join(ss, ", "))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s/%s — scanned %d file(s), %d var(s) referenced\n",
		project, r.Env, r.FilesScanned, len(r.Referenced))
	b.WriteString(line("missing:", r.Missing))
	b.WriteString(line("empty:", r.Empty))
	b.WriteString(line("placeholder:", r.Placeholder))
	b.WriteString(line("unused:", r.Unused))
	if len(r.Missing)+len(r.Empty)+len(r.Placeholder) == 0 {
		b.WriteString("  ✓ every referenced variable is set\n")
	}
	return b.String()
}

func (d *Daemon) handleImport(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProjectByReq(req)
	if p == nil {
		return Response{Error: "no such project"}
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	env := arg(req, "env")
	if env == "" {
		env = p.ActiveEnv
	}
	if env != "base" {
		if _, ok := u.vault.Values[env]; !ok {
			return Response{Error: "unknown env " + env}
		}
	}
	layer := u.layer(env)
	force := arg(req, "force") == "true"
	imported, skipped := 0, 0
	for k, v := range req.KV {
		old, had := layer[k]
		if had && old != v && !force {
			skipped++
			continue
		}
		layer[k] = v
		u.record(HistoryEntry{Op: "set", Env: env, Key: k, Old: old, HadOld: had, New: v})
		imported++
	}
	if err := saveVault(p.Path, u.vault, u.vf, u.key); err != nil {
		return Response{Error: err.Error()}
	}
	text := fmt.Sprintf("imported %d var(s) into %s/%s", imported, p.Name, env)
	if skipped > 0 {
		text += fmt.Sprintf(" (skipped %d existing — pass --force to overwrite)", skipped)
	}
	return Response{OK: true, Text: text}
}

func (d *Daemon) handleAdopt(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	root := findVaultRoot(req.Cwd)
	if root == "" {
		return Response{Error: "no .envd/vault.json found here or above"}
	}
	if p := d.findProject(root); p != nil {
		return Response{OK: true, Text: p.Name + " is already registered"}
	}
	msg, err := d.adopt(root)
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, Text: msg}
}

// handleAssimilate ingests discovered dotenv layers into a project, auto-creating
// it (or adopting an existing vault) if needed. Existing values are preserved
// unless force is set.
func (d *Daemon) handleAssimilate(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	cwd := filepath.Clean(req.Cwd)
	created := false
	p := d.findProject(cwd)
	if p == nil {
		if _, err := os.Stat(vaultPath(cwd)); err == nil { // adopt an existing vault
			if _, err := d.adopt(cwd); err != nil {
				return Response{Error: err.Error()}
			}
		} else { // register a fresh project, with the discovered modes as its envs
			var envs []string
			for e := range req.Layers {
				if e != "base" {
					envs = append(envs, e)
				}
			}
			if len(envs) == 0 {
				envs = []string{"dev"}
			}
			sort.Strings(envs)
			rr := d.registerLocked(Request{Cwd: cwd, Args: map[string]string{
				"name": arg(req, "name"), "envs": strings.Join(envs, ","), "kdf": arg(req, "kdf"),
			}})
			if !rr.OK {
				return rr
			}
			created = true
		}
		p = d.findProject(cwd)
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}

	// ensure every discovered mode env exists
	for env := range req.Layers {
		if env == "base" {
			continue
		}
		if _, ok := u.vault.Values[env]; !ok {
			u.vault.Values[env] = map[string]string{}
			u.vault.Environments = append(u.vault.Environments, env)
			p.Envs = append(p.Envs, env)
		}
	}

	force := arg(req, "force") == "true"
	imported, skipped := 0, 0
	for _, env := range sortedLayerKeys(req.Layers) {
		layer := u.layer(env)
		for k, v := range req.Layers[env] {
			old, had := layer[k]
			if had && old == v {
				continue
			}
			if had && !force {
				skipped++
				continue
			}
			layer[k] = v
			u.record(HistoryEntry{Op: "set", Env: env, Key: k, Old: old, HadOld: had, New: v})
			imported++
		}
	}
	// Record the current .env state as the baseline for future drift detection.
	u.vault.EnvBaseline = discoverEnvFiles(p.Path)
	if err := saveVault(p.Path, u.vault, u.vf, u.key); err != nil {
		return Response{Error: err.Error()}
	}
	d.saveState()

	var b strings.Builder
	verb := "assimilated into existing project"
	if created {
		verb = "created project and assimilated"
	}
	fmt.Fprintf(&b, "%s %q\n", verb, p.Name)
	fmt.Fprintf(&b, "  environments: %s\n", strings.Join(p.Envs, ", "))
	fmt.Fprintf(&b, "  imported %d value(s)", imported)
	if skipped > 0 {
		fmt.Fprintf(&b, "; skipped %d existing (pass --force to overwrite)", skipped)
	}
	b.WriteString("\n")
	return Response{OK: true, Text: b.String()}
}

// driftFor computes the project's .env drift against its baseline. Assumes d.mu
// is held. Returns nil drift when there are no .env files (a fully-migrated
// project shouldn't be nagged to "remove" everything) or when nothing changed.
// Establishes the baseline silently on first encounter.
func (d *Daemon) driftFor(p *Project, u *unlocked) *DriftReport {
	current := discoverEnvFiles(p.Path)
	if totalKeys(current) == 0 {
		return nil
	}
	if u.vault.EnvBaseline == nil {
		u.vault.EnvBaseline = current
		_ = saveVault(p.Path, u.vault, u.vf, u.key)
		return nil
	}
	return computeDrift(u.vault.EnvBaseline, current)
}

func (d *Daemon) handleDrift(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProjectByReq(req)
	if p == nil {
		return Response{Error: "no such project"}
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, Drift: d.driftFor(p, u)}
}

// handleApplyDrift reconciles the vault with the current .env files (apply the
// adds/changes, delete the removals) and advances the baseline.
func (d *Daemon) handleApplyDrift(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProjectByReq(req)
	if p == nil {
		return Response{Error: "no such project"}
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	current := discoverEnvFiles(p.Path)
	drift := computeDrift(u.vault.EnvBaseline, current)
	if drift.empty() {
		return Response{OK: true, Text: "already in sync"}
	}
	ensureEnv := func(env string) {
		if env == "base" {
			return
		}
		if _, ok := u.vault.Values[env]; !ok {
			u.vault.Values[env] = map[string]string{}
			u.vault.Environments = append(u.vault.Environments, env)
			p.Envs = append(p.Envs, env)
		}
	}
	for _, it := range append(append([]DriftItem{}, drift.Added...), drift.Changed...) {
		ensureEnv(it.Env)
		layer := u.layer(it.Env)
		old, had := layer[it.Key]
		layer[it.Key] = it.Value
		u.record(HistoryEntry{Op: "set", Env: it.Env, Key: it.Key, Old: old, HadOld: had, New: it.Value})
	}
	for _, it := range drift.Removed {
		if layer, ok := u.readLayer(it.Env); ok {
			if old, had := layer[it.Key]; had {
				delete(layer, it.Key)
				u.record(HistoryEntry{Op: "unset", Env: it.Env, Key: it.Key, Old: old, HadOld: true})
			}
		}
	}
	u.vault.EnvBaseline = current
	if err := saveVault(p.Path, u.vault, u.vf, u.key); err != nil {
		return Response{Error: err.Error()}
	}
	d.saveState()
	return Response{OK: true, Text: fmt.Sprintf("applied %d .env change(s): +%d ~%d -%d",
		drift.count(), len(drift.Added), len(drift.Changed), len(drift.Removed))}
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (d *Daemon) handleHistory(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProjectByReq(req)
	if p == nil {
		return Response{Error: "no such project"}
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	fEnv, fKey := arg(req, "env"), arg(req, "key")
	limit := 50
	if n, e := strconv.Atoi(arg(req, "n")); e == nil && n > 0 {
		limit = n
	}
	var out []HistoryEntry
	for i := len(u.vault.History) - 1; i >= 0; i-- { // newest first
		e := u.vault.History[i]
		if fEnv != "" && e.Env != fEnv {
			continue
		}
		if fKey != "" && e.Key != fKey {
			continue
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	return Response{OK: true, History: out}
}

// handleRestore applies the inverse of a recorded mutation, recording the
// reversion itself so it's also undoable (reflog-like).
func (d *Daemon) handleRestore(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProjectByReq(req)
	if p == nil {
		return Response{Error: "no such project"}
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	if len(u.vault.History) == 0 {
		return Response{Error: "no history yet"}
	}

	var target HistoryEntry // copy before any record() reallocates the slice
	if s := arg(req, "seq"); s == "" || s == "latest" {
		target = u.vault.History[len(u.vault.History)-1]
	} else {
		seq, err := strconv.Atoi(s)
		if err != nil {
			return Response{Error: "bad seq " + s}
		}
		found := false
		for _, e := range u.vault.History {
			if e.Seq == seq {
				target, found = e, true
				break
			}
		}
		if !found {
			return Response{Error: fmt.Sprintf("no history entry #%s (it may have aged out)", s)}
		}
	}

	structural := false
	var text string
	switch target.Op {
	case "set":
		layer := u.layer(target.Env)
		cur, hadCur := layer[target.Key]
		if target.HadOld {
			layer[target.Key] = target.Old
			u.record(HistoryEntry{Op: "set", Env: target.Env, Key: target.Key, Old: cur, HadOld: hadCur, New: target.Old})
		} else {
			delete(layer, target.Key)
			u.record(HistoryEntry{Op: "unset", Env: target.Env, Key: target.Key, Old: cur, HadOld: hadCur})
		}
		text = fmt.Sprintf("restored %s/%s to its value before #%d", target.Env, target.Key, target.Seq)
	case "unset":
		layer := u.layer(target.Env)
		cur, hadCur := layer[target.Key]
		layer[target.Key] = target.Old
		u.record(HistoryEntry{Op: "set", Env: target.Env, Key: target.Key, Old: cur, HadOld: hadCur, New: target.Old})
		text = fmt.Sprintf("restored %s/%s (undeleted)", target.Env, target.Key)
	case "addenv":
		if _, ok := u.vault.Values[target.Env]; !ok {
			return Response{Error: "env " + target.Env + " no longer exists"}
		}
		if len(p.Envs) <= 1 {
			return Response{Error: "cannot remove the last environment"}
		}
		snap := cloneMap(u.vault.Values[target.Env])
		delete(u.vault.Values, target.Env)
		u.vault.Environments = removeStr(u.vault.Environments, target.Env)
		p.Envs = removeStr(p.Envs, target.Env)
		if p.ActiveEnv == target.Env {
			p.ActiveEnv = p.Envs[0]
		}
		u.record(HistoryEntry{Op: "rmenv", Env: target.Env, Snapshot: snap})
		structural = true
		text = "removed environment " + target.Env + " (undo of add)"
	case "rmenv":
		if _, ok := u.vault.Values[target.Env]; ok {
			return Response{Error: "env " + target.Env + " already exists"}
		}
		u.vault.Values[target.Env] = cloneMap(target.Snapshot)
		u.vault.Environments = append(u.vault.Environments, target.Env)
		p.Envs = append(p.Envs, target.Env)
		u.record(HistoryEntry{Op: "addenv", Env: target.Env})
		structural = true
		text = fmt.Sprintf("restored environment %s (%d keys)", target.Env, len(target.Snapshot))
	default:
		return Response{Error: "cannot restore op " + target.Op}
	}

	if err := saveVault(p.Path, u.vault, u.vf, u.key); err != nil {
		return Response{Error: err.Error()}
	}
	if structural {
		d.saveState()
	}
	return Response{OK: true, Text: text}
}

func (d *Daemon) handleScaffold(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.findProjectByReq(req)
	if p == nil {
		return Response{Error: "no such project"}
	}
	u, err := d.getUnlocked(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	env := arg(req, "env")
	if env == "" {
		env = p.ActiveEnv
	}
	if env != "base" {
		if _, ok := u.vault.Values[env]; !ok {
			return Response{Error: "unknown env " + env}
		}
	}
	e, ok := catLookup(arg(req, "service"))
	if !ok {
		return Response{Error: fmt.Sprintf("unknown service %q (run `envd catalog`)", arg(req, "service"))}
	}

	layer := u.layer(env)
	var generated, defaults, todo, existing []string
	for _, v := range e.Vars {
		if _, ok := layer[v.Key]; ok {
			existing = append(existing, v.Key)
			continue
		}
		switch {
		case strings.HasPrefix(v.Default, "gen://"):
			val, gerr := genValue(v.Default)
			if gerr != nil {
				return Response{Error: gerr.Error()}
			}
			layer[v.Key] = val
			u.record(HistoryEntry{Op: "set", Env: env, Key: v.Key, New: val})
			generated = append(generated, v.Key)
		case v.Default != "":
			layer[v.Key] = v.Default
			u.record(HistoryEntry{Op: "set", Env: env, Key: v.Key, New: v.Default})
			defaults = append(defaults, v.Key)
		default:
			layer[v.Key] = "" // placeholder to fill (doctor flags empties)
			u.record(HistoryEntry{Op: "set", Env: env, Key: v.Key, New: ""})
			todo = append(todo, v.Key)
		}
	}
	if err := saveVault(p.Path, u.vault, u.vf, u.key); err != nil {
		return Response{Error: err.Error()}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s → %s/%s\n", e.Title, p.Name, env)
	if e.Note != "" {
		fmt.Fprintf(&b, "  note:      %s\n", e.Note)
	}
	if len(generated) > 0 {
		fmt.Fprintf(&b, "  generated: %s\n", strings.Join(generated, ", "))
	}
	if len(defaults) > 0 {
		fmt.Fprintf(&b, "  defaults:  %s\n", strings.Join(defaults, ", "))
	}
	if len(todo) > 0 {
		fmt.Fprintf(&b, "  fill in:   %s\n", strings.Join(todo, ", "))
	}
	if len(existing) > 0 {
		fmt.Fprintf(&b, "  unchanged: %s (already set)\n", strings.Join(existing, ", "))
	}
	if e.URL != "" {
		fmt.Fprintf(&b, "  keys at:   %s\n", e.URL)
	}
	if len(todo) > 0 {
		fmt.Fprintf(&b, "  → fill one: cat key.txt | envd set %s --env %s   (or bind a ref, e.g. op://…)\n", todo[0], env)
	}
	return Response{OK: true, Text: b.String()}
}

func (d *Daemon) handleProviders() Response {
	var b strings.Builder
	fmt.Fprintf(&b, "%s reference providers (%d). Use as a value, or embed with ${…}:\n\n", appName, len(providerList))
	fmt.Fprintf(&b, "  %-10s %-24s %-16s %s\n", "SCHEME", "SOURCE", "STATUS", "EXAMPLE")
	for _, p := range providerList {
		status := "ready"
		if p.bin != "" {
			if _, err := exec.LookPath(p.bin); err != nil {
				status = "needs " + p.bin
			}
		}
		fmt.Fprintf(&b, "  %-10s %-24s %-16s %s\n", p.scheme, p.desc, status, p.example)
	}
	fmt.Fprintf(&b, "  %-10s %-24s %-16s %s\n", "envd", "Another env (DRY)", "ready", "envd://base/API_BASE")
	b.WriteString("\nProviders shell out to each vendor's CLI using the auth you already have.\n")
	return Response{OK: true, Text: b.String()}
}

func (d *Daemon) serve(conn net.Conn) {
	defer conn.Close()
	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	var resp Response
	switch req.Cmd {
	case "ping":
		resp = Response{OK: true, Text: appName + " " + version}
	case "export":
		resp = d.handleExport(req)
	case "use":
		resp = d.handleUse(req)
	case "set":
		resp = d.handleSet(req)
	case "unset":
		resp = d.handleUnset(req)
	case "register":
		resp = d.handleRegister(req)
	case "saveprovider":
		resp = d.handleSaveProvider(req)
	case "status":
		resp = d.handleStatus()
	case "projects":
		resp = d.handleProjects()
	case "vars":
		resp = d.handleVars(req)
	case "addenv":
		resp = d.handleAddEnv(req)
	case "rmenv":
		resp = d.handleRmEnv(req)
	case "diff":
		resp = d.handleDiff(req)
	case "doctor":
		resp = d.handleDoctor(req)
	case "import":
		resp = d.handleImport(req)
	case "adopt":
		resp = d.handleAdopt(req)
	case "assimilate":
		resp = d.handleAssimilate(req)
	case "drift":
		resp = d.handleDrift(req)
	case "applydrift":
		resp = d.handleApplyDrift(req)
	case "history":
		resp = d.handleHistory(req)
	case "restore":
		resp = d.handleRestore(req)
	case "providers":
		resp = d.handleProviders()
	case "scaffold":
		resp = d.handleScaffold(req)
	default:
		resp = Response{Error: "unknown cmd " + req.Cmd}
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

// ensurePATH augments the daemon's PATH with common install locations so provider
// CLIs (aws, gcloud, doppler, …) are found even under launchd's minimal PATH.
func ensurePATH() {
	cur := os.Getenv("PATH")
	have := map[string]bool{}
	for _, d := range strings.Split(cur, string(os.PathListSeparator)) {
		have[d] = true
	}
	var add []string
	for _, d := range []string{
		"/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin",
		filepath.Join(homeDir(), ".local", "bin"), filepath.Join(homeDir(), "go", "bin"),
	} {
		if !have[d] {
			add = append(add, d)
		}
	}
	if len(add) > 0 {
		_ = os.Setenv("PATH", strings.Join(add, ":")+":"+cur)
	}
}

func cmdStart() {
	ensurePATH()
	_ = os.MkdirAll(stateDir(), 0o700)
	if _, err := os.Stat(socketPath()); err == nil {
		if c, err := net.Dial("unix", socketPath()); err == nil {
			c.Close()
			fmt.Println(appName + " daemon already running")
			return
		}
		_ = os.Remove(socketPath()) // stale socket
	}
	ln, err := net.Listen("unix", socketPath())
	if err != nil {
		fatal(err)
	}
	_ = os.Chmod(socketPath(), 0o600)

	d := &Daemon{
		state:    loadState(),
		cache:    map[string]*unlocked{},
		sessions: map[string]session{},
		refCache: map[string]refCacheEntry{},
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		_ = os.Remove(socketPath())
		os.Exit(0)
	}()

	fmt.Printf("%s %s — listening on %s (%d project(s))\n", appName, version, socketPath(), len(d.state.Projects))
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go d.serve(conn)
	}
}

// ---------------------------------------------------------------------------
// Client helper
// ---------------------------------------------------------------------------

func daemonCall(req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", socketPath(), 3*time.Second)
	if err != nil {
		return Response{}, fmt.Errorf("daemon not running — run `%s start` (%w)", appName, err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

func mustCall(req Request) Response {
	resp, err := daemonCall(req)
	if err != nil {
		fatal(err)
	}
	if !resp.OK {
		fatalf("%s", resp.Error)
	}
	return resp
}

// ---------------------------------------------------------------------------
// Provider adapters (extension surface) + generic OAuth code flow
// ---------------------------------------------------------------------------

type OAuthConfig struct {
	AuthURL      string
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scopes       []string
}

type Resource struct {
	ID   string
	Name string
}

// Adapter is the extension point for a secret provider. Implement it and call
// registerAdapter in init() to add a vendor (Neon, Upstash, WorkOS, ...).
type Adapter interface {
	Name() string
	OAuth() OAuthConfig
	ListResources(ctx context.Context, accessToken string) ([]Resource, error)
	// FetchSecrets returns VAR->value for a resource bound to envName.
	FetchSecrets(ctx context.Context, accessToken, resourceID, envName string) (map[string]string, error)
}

var adapters = map[string]Adapter{}

func registerAdapter(a Adapter) { adapters[a.Name()] = a }

func adapterNames() []string {
	ns := make([]string, 0, len(adapters))
	for n := range adapters {
		ns = append(ns, n)
	}
	sort.Strings(ns)
	return ns
}

func openBrowser(u string) { _ = exec.Command("open", u).Start() }

// runOAuth performs an authorization-code flow, opening the user's browser.
func runOAuth(ctx context.Context, cfg OAuthConfig) (string, error) {
	return runOAuthWith(ctx, cfg, func(u string) {
		openBrowser(u)
		fmt.Fprintf(os.Stderr, "Opening browser for authorization:\n  %s\n", u)
	})
}

// runOAuthWith runs the code flow against a loopback redirect, calling open with
// the authorization URL (injectable so tests can drive it without a browser).
func runOAuthWith(ctx context.Context, cfg OAuthConfig, open func(string)) (string, error) {
	if cfg.ClientID == "" {
		return "", errors.New("adapter has no OAuth client configured")
	}
	codeCh := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, appName+": authorization received — you can close this tab.")
		codeCh <- r.URL.Query().Get("code")
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer ln.Close()
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	redirect := fmt.Sprintf("http://%s/callback", ln.Addr().String())
	auth, err := url.Parse(cfg.AuthURL)
	if err != nil {
		return "", err
	}
	q := auth.Query()
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", redirect)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(cfg.Scopes, " "))
	auth.RawQuery = q.Encode()
	open(auth.String())

	var code string
	select {
	case code = <-codeCh:
	case <-time.After(2 * time.Minute):
		return "", errors.New("oauth timed out")
	case <-ctx.Done():
		return "", ctx.Err()
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirect)
	form.Set("client_id", cfg.ClientID)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	resp, err := http.PostForm(cfg.TokenURL, form)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(body, &tok)
	if tok.AccessToken == "" {
		return "", fmt.Errorf("token exchange failed: %s", strings.TrimSpace(string(body)))
	}
	return tok.AccessToken, nil
}

// ---------------------------------------------------------------------------
// CLI commands
// ---------------------------------------------------------------------------

func parseFlags(args []string) (positional []string, flags map[string]string) {
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			a = a[2:]
			if eq := strings.IndexByte(a, '='); eq >= 0 {
				flags[a[:eq]] = a[eq+1:]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				flags[a] = args[i+1]
				i++
			} else {
				flags[a] = "true"
			}
		} else {
			positional = append(positional, a)
		}
	}
	return positional, flags
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func prompt(r *bufio.Reader, label, def string) string {
	fmt.Fprintf(os.Stderr, "%s [%s]: ", label, def)
	line, _ := r.ReadString('\n')
	if line = strings.TrimSpace(line); line == "" {
		return def
	}
	return line
}

const zshHook = `_envd_export() {
  eval "$(command envd _export --cwd "$PWD" --applied "${__ENVD_KEYS:-}" --shell $$ 2>/dev/null)"
}
typeset -ag precmd_functions 2>/dev/null
if (( ! ${precmd_functions[(I)_envd_export]} )); then
  precmd_functions+=(_envd_export)
fi
`

const bashHook = `_envd_export() {
  eval "$(command envd _export --cwd "$PWD" --applied "${__ENVD_KEYS:-}" --shell $$ 2>/dev/null)"
}
case "${PROMPT_COMMAND:-}" in
  *_envd_export*) ;;
  *) PROMPT_COMMAND="_envd_export;${PROMPT_COMMAND}" ;;
esac
`

func cmdHook(args []string) {
	pos, _ := parseFlags(args)
	shell := "zsh"
	if len(pos) > 0 {
		shell = pos[0]
	}
	switch shell {
	case "zsh":
		fmt.Print(zshHook)
	case "bash":
		fmt.Print(bashHook)
	default:
		fatalf("unsupported shell %q (use zsh or bash)", shell)
	}
}

// cmdExport is the internal endpoint the shell hook evals each prompt.
func cmdExport(args []string) {
	_, flags := parseFlags(args)
	cwd := flags["cwd"]
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	var applied []string
	if flags["applied"] != "" {
		applied = strings.Fields(flags["applied"])
	}
	resp, err := daemonCall(Request{
		Cmd: "export", Cwd: cwd, Applied: applied,
		Args: map[string]string{"shell": flags["shell"]},
	})
	if err != nil {
		// Daemon down: don't break the prompt. Clear anything we set previously.
		for _, k := range applied {
			fmt.Printf("unset %s\n", k)
		}
		fmt.Println("unset __ENVD_KEYS ENVD_ENV")
		return
	}
	for _, k := range resp.Unsets {
		fmt.Printf("unset %s\n", k)
	}
	keys := make([]string, 0, len(resp.Exports))
	for k := range resp.Exports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("export %s=%s\n", k, shellQuote(resp.Exports[k]))
	}
	if resp.Env != "" {
		fmt.Printf("export __ENVD_KEYS=%s\n", shellQuote(strings.Join(keys, " ")))
		fmt.Printf("export ENVD_ENV=%s\n", shellQuote(resp.Env))
	} else {
		fmt.Println("unset __ENVD_KEYS ENVD_ENV")
	}
}

func cmdConnect(args []string) {
	pos, _ := parseFlags(args)
	if len(pos) == 0 {
		fatalf("usage: envd connect <provider>  —  to register this directory as a project, use `envd init`")
	}
	if _, ok := adapters[pos[0]]; ok {
		cmdConnectProvider(pos[0])
		return
	}
	fatalf("unknown provider %q (registered: %s)", pos[0], strings.Join(adapterNames(), ", "))
}

func cmdConnectProject() {
	cwd, _ := os.Getwd()
	// Re-connecting clobbers an existing vault with a new key, abandoning its
	// values — guard against doing that silently.
	if _, err := os.Stat(vaultPath(cwd)); err == nil {
		if !confirm("this directory already has an envd vault; re-connecting creates a NEW key and abandons its values — continue?") {
			fmt.Fprintln(os.Stderr, "cancelled")
			return
		}
	}
	r := bufio.NewReader(os.Stdin)
	name := prompt(r, "Project name", filepath.Base(cwd))
	envs := prompt(r, "Environments (comma-separated)", "dev")

	kdf := "keychain"
	if os.Getenv("ENVD_PASSPHRASE") != "" {
		kdf = "pbkdf2"
	} else if !keychainAvailable() {
		fatalf("no macOS Keychain available; set ENVD_PASSPHRASE to use the passphrase fallback")
	}

	resp := mustCall(Request{Cmd: "register", Cwd: cwd,
		Args: map[string]string{"name": name, "envs": envs, "kdf": kdf}})
	fmt.Printf("✓ %s\n", resp.Text)
	fmt.Print("\nNext:\n" +
		"  1. Shell hook (once):  add  eval \"$(envd hook zsh)\"  to ~/.zshrc\n" +
		"  2. Set a value:        cat secret.txt | envd set DATABASE_URL\n" +
		"  3. Add an environment: envd env add staging\n")
}

func cmdConnectProvider(name string) {
	a := adapters[name]
	cwd, _ := os.Getwd()
	ctx := context.Background()
	token, err := runOAuth(ctx, a.OAuth())
	if err != nil {
		fatalf("connect %s: %v", name, err)
	}
	resources, err := a.ListResources(ctx, token)
	if err != nil {
		fatal(err)
	}
	if len(resources) == 0 {
		fatalf("%s returned no resources", name)
	}
	res := resources[0]
	vals, err := a.FetchSecrets(ctx, token, res.ID, "")
	if err != nil {
		fatal(err)
	}
	for k, v := range vals {
		mustCall(Request{Cmd: "set", Cwd: cwd, Args: map[string]string{"key": k, "value": v}})
	}
	tokJSON, _ := json.Marshal(map[string]string{"access_token": token})
	mustCall(Request{Cmd: "saveprovider", Cwd: cwd,
		Args: map[string]string{"provider": name, "token": string(tokJSON)}})
	fmt.Printf("✓ connected %s (%s); imported %d value(s)\n", name, res.Name, len(vals))
}

func cmdUse(args []string) {
	pos, _ := parseFlags(args)
	if len(pos) < 1 {
		fatalf("usage: envd use <env>")
	}
	cwd, _ := os.Getwd()
	resp := mustCall(Request{Cmd: "use", Cwd: cwd, Args: map[string]string{"env": pos[0]}})
	fmt.Println(resp.Text)
}

func cmdSet(args []string) {
	pos, flags := parseFlags(args)
	if len(pos) < 1 {
		fatalf("usage: envd set <KEY> [--env ENV] [--force]")
	}
	key := pos[0]
	val := readValue("value for " + key) // hidden prompt on a TTY, else piped stdin
	cwd, _ := os.Getwd()
	a := map[string]string{"env": flags["env"], "key": key, "value": val}
	if flags["force"] != "" || flags["f"] != "" {
		a["force"] = "true"
	}
	resp, err := daemonCall(Request{Cmd: "set", Cwd: cwd, Args: a})
	if err != nil {
		fatal(err)
	}
	if resp.NeedConfirm {
		if !stdinIsTTY() {
			fatalf("%s — pass --force to overwrite", resp.Text)
		}
		if !confirm(resp.Text + " — overwrite?") {
			fmt.Fprintln(os.Stderr, "cancelled")
			return
		}
		a["force"] = "true"
		resp, err = daemonCall(Request{Cmd: "set", Cwd: cwd, Args: a})
		if err != nil {
			fatal(err)
		}
	}
	if !resp.OK {
		fatalf("%s", resp.Error)
	}
	fmt.Printf("✓ %s\n", resp.Text)
}

func cmdUnset(args []string) {
	pos, flags := parseFlags(args)
	if len(pos) < 1 {
		fatalf("usage: envd unset <KEY> [--env ENV]")
	}
	cwd, _ := os.Getwd()
	resp := mustCall(Request{Cmd: "unset", Cwd: cwd,
		Args: map[string]string{"env": flags["env"], "key": pos[0]}})
	fmt.Printf("✓ %s\n", resp.Text)
}

func cmdDiff(args []string) {
	pos, _ := parseFlags(args)
	if len(pos) < 2 {
		fatalf("usage: envd diff <envA> <envB>")
	}
	cwd, _ := os.Getwd()
	resp := mustCall(Request{Cmd: "diff", Cwd: cwd, Args: map[string]string{"a": pos[0], "b": pos[1]}})
	fmt.Print(resp.Text)
}

func cmdDoctor(args []string) {
	_, flags := parseFlags(args)
	cwd, _ := os.Getwd()
	a := map[string]string{"env": flags["env"]}
	if flags["example"] != "" {
		a["example"] = "true" // daemon writes .env.example to the project root
	}
	resp := mustCall(Request{Cmd: "doctor", Cwd: cwd, Args: a})
	fmt.Print(resp.Text)
}

// ---------------------------------------------------------------------------
// Project assimilation: discover conventional dotenv files and map them onto
// envd's base + per-environment layers using the standard dotenv precedence.
//   .env, .env.local            → base (shared; .local overrides)
//   .env.<mode>, .env.<mode>.local → <mode> env (.local overrides)
// Keys common to every mode are hoisted to base; mode keys equal to base drop.
// ---------------------------------------------------------------------------

func normalizeMode(m string) string {
	switch m {
	case "development", "dev":
		return "dev"
	case "production", "prod":
		return "prod"
	case "staging", "stage":
		return "staging"
	case "test", "testing":
		return "test"
	}
	return m
}

// classifyEnvFile maps a filename to (envName, isLocal, ok). envName "base" is the
// shared layer. Template/non-value files (.env.example, .env.vault, …) are skipped.
func classifyEnvFile(name string) (env string, local bool, ok bool) {
	switch name {
	case ".env":
		return "base", false, true
	case ".env.local":
		return "base", true, true
	}
	if !strings.HasPrefix(name, ".env.") {
		return "", false, false
	}
	rest := name[len(".env."):]
	local = strings.HasSuffix(rest, ".local")
	rest = strings.TrimSuffix(rest, ".local")
	switch rest {
	case "", "example", "sample", "template", "dist", "defaults", "schema", "vault", "keys":
		return "", false, false
	}
	return normalizeMode(rest), local, true
}

// discoverEnv reads the dotenv files in dir and returns env -> KV layers (with a
// "base" layer) plus the filenames it used.
func discoverEnv(dir string) (map[string]map[string]string, []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	type ef struct {
		env, path string
		local     bool
	}
	var files []ef
	var used []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		env, local, ok := classifyEnvFile(e.Name())
		if !ok {
			continue
		}
		files = append(files, ef{env: env, path: filepath.Join(dir, e.Name()), local: local})
		used = append(used, e.Name())
	}
	sort.Strings(used)
	layers := map[string]map[string]string{}
	// non-local first, then local overrides
	for _, pass := range []bool{false, true} {
		for _, f := range files {
			if f.local != pass {
				continue
			}
			data, err := os.ReadFile(f.path)
			if err != nil {
				continue
			}
			if layers[f.env] == nil {
				layers[f.env] = map[string]string{}
			}
			for k, v := range parseDotenv(data) {
				layers[f.env][k] = v
			}
		}
	}
	hoistCommon(layers)
	return layers, used
}

// discoverEnvFiles returns just the .env-derived layers for dir (used as the
// drift baseline; daemon-side so it's consistent across checks).
func discoverEnvFiles(dir string) map[string]map[string]string {
	layers, _ := discoverEnv(dir)
	return layers
}

// hoistCommon moves keys shared (same value) by every mode env into base, and
// drops mode keys that merely duplicate a base value.
func hoistCommon(layers map[string]map[string]string) {
	if layers["base"] == nil {
		layers["base"] = map[string]string{}
	}
	base := layers["base"]
	var modes []string
	for e := range layers {
		if e != "base" {
			modes = append(modes, e)
		}
	}
	if len(modes) >= 2 {
		for k, v := range layers[modes[0]] {
			common := true
			for _, m := range modes[1:] {
				if mv, ok := layers[m][k]; !ok || mv != v {
					common = false
					break
				}
			}
			if common {
				if _, inBase := base[k]; !inBase {
					base[k] = v
				}
			}
		}
	}
	for _, m := range modes {
		for k, v := range layers[m] {
			if bv, ok := base[k]; ok && bv == v {
				delete(layers[m], k)
			}
		}
	}
}

func sortedLayerKeys(layers map[string]map[string]string) []string {
	keys := make([]string, 0, len(layers))
	for k := range layers {
		if k != "base" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if _, ok := layers["base"]; ok {
		keys = append([]string{"base"}, keys...) // base first
	}
	return keys
}

// parseDotenv parses a .env file into key/value pairs (supports `export `,
// `#` comments, and single/double-quoted values).
func parseDotenv(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq < 1 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if len(val) >= 2 && (val[0] == '"' && val[len(val)-1] == '"' || val[0] == '\'' && val[len(val)-1] == '\'') {
			val = val[1 : len(val)-1]
		}
		if key != "" {
			out[key] = val
		}
	}
	return out
}

func cmdImport(args []string) {
	pos, flags := parseFlags(args)
	file := ".env"
	if len(pos) > 0 {
		file = pos[0]
	}
	data, err := os.ReadFile(file)
	if err != nil {
		fatal(err)
	}
	kv := parseDotenv(data)
	if len(kv) == 0 {
		fatalf("no variables found in %s", file)
	}
	cwd, _ := os.Getwd()
	a := map[string]string{"env": flags["env"]}
	if flags["force"] != "" || flags["f"] != "" {
		a["force"] = "true"
	}
	resp := mustCall(Request{Cmd: "import", Cwd: cwd, KV: kv, Args: a})
	fmt.Printf("✓ %s\n", resp.Text)
}

func cmdAdopt() {
	cwd, _ := os.Getwd()
	resp := mustCall(Request{Cmd: "adopt", Cwd: cwd})
	fmt.Printf("✓ %s\n", resp.Text)
}

func cmdAssimilate(args []string) {
	_, flags := parseFlags(args)
	cwd, _ := os.Getwd()

	// 1. discover values from conventional dotenv files
	layers, files := discoverEnv(cwd)
	if len(files) > 0 {
		fmt.Fprintf(os.Stderr, "dotenv files: %s\n", strings.Join(files, ", "))
	}

	// 2. scan the code for referenced env vars and fill any the .env files missed,
	//    using the current environment, then inline code defaults.
	referenced, scanned := scanEnvRefs(cwd)
	// Drop shell/OS-provided vars (PATH, HOME, …) — they're not project config and
	// must never be tracked as blank (that would clobber the real value at inject).
	var refs []string
	for _, k := range referenced {
		if !systemEnvDeny[k] {
			refs = append(refs, k)
		}
	}
	defaults := discoverDefaults(cwd)
	lookup := func(k string) (string, bool) {
		v, ok := os.LookupEnv(k)
		if !ok || strings.TrimSpace(v) == "" {
			return "", false
		}
		return v, true
	}
	fromEnv, fromDefault, undetermined := resolveReferenced(layers, refs, defaults, lookup)
	fmt.Fprintf(os.Stderr, "scanned %d source file(s); %d env var(s) referenced in code\n", scanned, len(referenced))

	if len(layers["base"]) == 0 {
		delete(layers, "base")
	}
	if len(layers) == 0 {
		fatalf("nothing to assimilate: no .env files and no env-var references found in %s", cwd)
	}

	kdf := "keychain"
	if os.Getenv("ENVD_PASSPHRASE") != "" {
		kdf = "pbkdf2"
	} else if !keychainAvailable() {
		fatalf("no macOS Keychain available; set ENVD_PASSPHRASE to use the passphrase fallback")
	}
	a := map[string]string{"name": filepath.Base(cwd), "kdf": kdf}
	if flags["force"] != "" || flags["f"] != "" {
		a["force"] = "true"
	}
	resp := mustCall(Request{Cmd: "assimilate", Cwd: cwd, Layers: layers, Args: a})
	fmt.Print(resp.Text)

	if len(fromEnv) > 0 {
		fmt.Printf("  captured from your shell env: %s\n", strings.Join(fromEnv, ", "))
	}
	if len(fromDefault) > 0 {
		fmt.Printf("  captured from code defaults:  %s\n", strings.Join(fromDefault, ", "))
	}
	if len(undetermined) > 0 {
		fmt.Printf("\n⚠ %d referenced var(s) need a value (stored blank): %s\n", len(undetermined), strings.Join(undetermined, ", "))
		fmt.Printf("  set them with `envd set <KEY>` (run `envd doctor` anytime to recheck).\n")
	}
	fmt.Println("\nReview with `envd tui` or `envd diff`. Once envd manages these, you can remove the .env files (the vault is committed; .env stays gitignored).")
}

func pickProjectForCwd(ps []ProjectView, cwd string) *ProjectView {
	cwd = filepath.Clean(cwd)
	var best *ProjectView
	bestLen := -1
	for i := range ps {
		pp := filepath.Clean(ps[i].Path)
		if cwd == pp || strings.HasPrefix(cwd, pp+string(filepath.Separator)) {
			if len(pp) > bestLen {
				best, bestLen = &ps[i], len(pp)
			}
		}
	}
	return best
}

func cmdEnv(args []string) {
	pos, _ := parseFlags(args)
	cwd, _ := os.Getwd()
	sub := ""
	if len(pos) > 0 {
		sub = pos[0]
	}
	switch sub {
	case "add":
		if len(pos) < 2 {
			fatalf("usage: envd env add <name>")
		}
		resp := mustCall(Request{Cmd: "addenv", Cwd: cwd, Args: map[string]string{"env": pos[1]}})
		fmt.Printf("✓ %s\n", resp.Text)
	case "rm", "remove":
		if len(pos) < 2 {
			fatalf("usage: envd env rm <name>")
		}
		resp := mustCall(Request{Cmd: "rmenv", Cwd: cwd, Args: map[string]string{"env": pos[1]}})
		fmt.Printf("✓ %s\n", resp.Text)
	case "ls", "list", "":
		resp := mustCall(Request{Cmd: "projects"})
		p := pickProjectForCwd(resp.Projects, cwd)
		if p == nil {
			fatalf("no envd project here (run `envd init`)")
		}
		for _, e := range p.Envs {
			marker := "  "
			if e == p.ActiveEnv {
				marker = "* "
			}
			fmt.Printf("%s%s\n", marker, e)
		}
	default:
		fatalf("usage: envd env <add|rm|ls> [name]")
	}
}

func maskStr(s string) string {
	if s == "" {
		return "∅"
	}
	n := len([]rune(s))
	if n > 8 {
		n = 8
	}
	if n < 3 {
		n = 3
	}
	return strings.Repeat("•", n)
}

func formatHistEntry(e HistoryEntry) string {
	t := e.Time.Local().Format("01-02 15:04:05")
	loc := e.Env
	if e.Key != "" {
		loc = e.Env + "/" + e.Key
	}
	switch e.Op {
	case "set":
		from := "∅"
		if e.HadOld {
			from = maskStr(e.Old)
		}
		return fmt.Sprintf("[%d] %s  set     %-24s %s → %s", e.Seq, t, loc, from, maskStr(e.New))
	case "unset":
		return fmt.Sprintf("[%d] %s  unset   %-24s %s", e.Seq, t, loc, maskStr(e.Old))
	case "addenv":
		return fmt.Sprintf("[%d] %s  addenv  %s", e.Seq, t, e.Env)
	case "rmenv":
		return fmt.Sprintf("[%d] %s  rmenv   %-24s (%d keys)", e.Seq, t, e.Env, len(e.Snapshot))
	}
	return fmt.Sprintf("[%d] %s  %s  %s", e.Seq, t, e.Op, loc)
}

func cmdHistory(args []string) {
	_, flags := parseFlags(args)
	cwd, _ := os.Getwd()
	resp := mustCall(Request{Cmd: "history", Cwd: cwd,
		Args: map[string]string{"env": flags["env"], "key": flags["key"], "n": flags["n"]}})
	if len(resp.History) == 0 {
		fmt.Println("no history yet")
		return
	}
	for _, e := range resp.History {
		fmt.Println(formatHistEntry(e))
	}
	fmt.Println("\nrestore with: envd restore <seq>   (or `envd undo` for the latest)")
}

func cmdRestore(args []string) {
	pos, _ := parseFlags(args)
	if len(pos) < 1 {
		fatalf("usage: envd restore <seq>   (see `envd history`)")
	}
	cwd, _ := os.Getwd()
	resp := mustCall(Request{Cmd: "restore", Cwd: cwd, Args: map[string]string{"seq": pos[0]}})
	fmt.Printf("✓ %s\n", resp.Text)
}

func cmdUndo() {
	cwd, _ := os.Getwd()
	resp := mustCall(Request{Cmd: "restore", Cwd: cwd, Args: map[string]string{"seq": "latest"}})
	fmt.Printf("✓ %s\n", resp.Text)
}

func cmdAdd(args []string) {
	pos, flags := parseFlags(args)
	if len(pos) < 1 {
		fatalf("usage: envd add <service> [--env e]   (run `envd catalog` to see services)")
	}
	cwd, _ := os.Getwd()
	resp := mustCall(Request{Cmd: "scaffold", Cwd: cwd,
		Args: map[string]string{"service": pos[0], "env": flags["env"]}})
	fmt.Print(resp.Text)
}

func cmdCatalog(args []string) {
	pos, _ := parseFlags(args)
	q := ""
	if len(pos) > 0 {
		q = strings.ToLower(pos[0])
	}
	var order []string
	byCat := map[string][]catEntry{}
	n := 0
	for _, e := range catalog {
		if q != "" {
			hay := strings.ToLower(e.Name + " " + e.Title + " " + e.Cat)
			for _, v := range e.Vars {
				hay += " " + strings.ToLower(v.Key)
			}
			if !strings.Contains(hay, q) {
				continue
			}
		}
		if _, ok := byCat[e.Cat]; !ok {
			order = append(order, e.Cat)
		}
		byCat[e.Cat] = append(byCat[e.Cat], e)
		n++
	}
	for _, c := range order {
		fmt.Printf("\n%s\n", c)
		for _, e := range byCat[c] {
			keys := make([]string, 0, len(e.Vars))
			for _, v := range e.Vars {
				keys = append(keys, v.Key)
			}
			detail := strings.Join(keys, ", ")
			if detail == "" {
				detail = e.Note
			}
			fmt.Printf("  %-14s %s\n", e.Name, detail)
		}
	}
	fmt.Printf("\n%d services. Scaffold one with: envd add <name> [--env e]\n", n)
}

func formatDrift(d *DriftReport) string {
	var b strings.Builder
	b.WriteString("manual .env changes since last sync:\n")
	for _, it := range d.Added {
		fmt.Fprintf(&b, "  + %s/%s = %s   (added)\n", it.Env, it.Key, maskStr(it.Value))
	}
	for _, it := range d.Changed {
		fmt.Fprintf(&b, "  ~ %s/%s = %s   (changed)\n", it.Env, it.Key, maskStr(it.Value))
	}
	for _, it := range d.Removed {
		fmt.Fprintf(&b, "  - %s/%s   (removed)\n", it.Env, it.Key)
	}
	return b.String()
}

func cmdSync(args []string) {
	_, flags := parseFlags(args)
	cwd, _ := os.Getwd()
	resp := mustCall(Request{Cmd: "drift", Cwd: cwd})
	if resp.Drift.empty() {
		fmt.Println("✓ in sync — no manual .env changes detected")
		return
	}
	fmt.Print(formatDrift(resp.Drift))
	if flags["force"] == "" && flags["f"] == "" {
		if !confirm("apply these .env changes to the vault?") {
			fmt.Fprintln(os.Stderr, "cancelled — vault unchanged")
			return
		}
	}
	r := mustCall(Request{Cmd: "applydrift", Cwd: cwd})
	fmt.Printf("✓ %s\n", r.Text)
}

func cmdProviders() {
	resp := mustCall(Request{Cmd: "providers"})
	fmt.Print(resp.Text)
}

func cmdStatus() {
	resp := mustCall(Request{Cmd: "status"})
	fmt.Print(resp.Text)
}

func usage() {
	fmt.Print(`envd ` + version + ` — automatic per-environment configuration (secrets and settings).

Usage:
  envd start                 Run the daemon (once per machine; backgroundable).
  envd hook <zsh|bash>       Print the shell hook to add to your rc file.
  envd init                  Register the current directory as a project.
  envd connect <provider>    OAuth-connect a provider and import its values.
  envd adopt                 Register an existing on-disk vault (cloned repo).
  envd assimilate [--force]  Discover this project's dotenv files (.env, .env.local,
                             .env.<mode>, …), map them to environments, and ingest
                             them into the vault — auto-creating the project.
  envd import [file] [--env e] [--force]
                             Import a .env file (default ./.env). Skips existing keys
                             unless --force.
  envd sync [--force]        Detect manual edits to this project's .env files and
                             reconcile the vault (confirms first, or use the TUI).
  envd use <env>             Set the active environment for this project.
  envd env add <name>        Add a new environment (projects start with just 'dev').
  envd env rm <name>         Remove an environment.
  envd env ls                List this project's environments (* = active).
  envd catalog [query]       List known SaaS services/frameworks and their env vars.
  envd add <service> [--env e]  Scaffold a service's expected keys (e.g. stripe, neon).
  envd set <KEY> [--env e] [--force]
                             Store a value — prompts hidden (no echo) on a terminal,
                             or reads piped stdin. Overwrites prompt unless --force.
  envd unset <KEY> [--env e] Delete a value.
  envd history [--env e] [--key K] [-n N]
                             Show the change log (reflog) for this project.
  envd restore <seq>         Roll back the change with that history seq number.
  envd undo                  Roll back the most recent change.
  envd diff <envA> <envB>    Show which keys differ between two environments.
  envd doctor [--env e] [--example]
                             Scan code for env-var refs; flag missing/empty/placeholder/unused.
                             --example writes a .env.example of all referenced keys.
  envd tui                   Open the interactive vault/environment manager.
  envd status                Show projects, active envs, and active shells.
  envd version               Print version.

  envd providers             List supported config/secret providers (op, vault,
                             aws-sm, gcp-sm, azure-kv, doppler, infisical, …).

References (resolved live at inject time, whole-value or embedded with ${...}):
  op://vault/item/field          1Password           envd://<env>/<KEY>   another env (DRY)
  vault://path#field             HashiCorp Vault     aws-sm://id#key      AWS Secrets Manager
  gcp-sm://project/secret        GCP Secret Manager  doppler://NAME       Doppler
  Run 'envd providers' for the full list.  e.g.  DB=postgres://app:${op://Private/db/pw}@h/db

Generators (materialized once, at set time):
  gen://random/32            Random bytes, base64. Also hex/N, uuid, password/N.
  printf gen://random/48 | envd set SESSION_SECRET --env prod

Daily loop:
  1. envd start &                         # start the daemon
  2. eval "$(envd hook zsh)"  >> ~/.zshrc # one-time
  3. cd my-app && envd init               # register
  4. cat secret.txt | envd set DATABASE_URL --env dev
  5. envd use staging                     # every new process now sees staging

Keys live in the macOS Keychain (or PBKDF2 via ENVD_PASSPHRASE). The encrypted
vault lives at <project>/.envd/vault.json and is safe to commit.
`)
}

func fatal(err error)           { fmt.Fprintln(os.Stderr, appName+": "+err.Error()); os.Exit(1) }
func fatalf(f string, a ...any) { fmt.Fprintf(os.Stderr, appName+": "+f+"\n", a...); os.Exit(1) }

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	rest := os.Args[2:]
	switch os.Args[1] {
	case "start", "daemon":
		cmdStart()
	case "hook":
		cmdHook(rest)
	case "_export":
		cmdExport(rest)
	case "init":
		cmdConnectProject()
	case "connect":
		cmdConnect(rest)
	case "use":
		cmdUse(rest)
	case "env":
		cmdEnv(rest)
	case "set":
		cmdSet(rest)
	case "unset":
		cmdUnset(rest)
	case "history", "log":
		cmdHistory(rest)
	case "restore":
		cmdRestore(rest)
	case "undo":
		cmdUndo()
	case "diff":
		cmdDiff(rest)
	case "doctor":
		cmdDoctor(rest)
	case "import":
		cmdImport(rest)
	case "adopt":
		cmdAdopt()
	case "assimilate", "absorb":
		cmdAssimilate(rest)
	case "sync":
		cmdSync(rest)
	case "tui":
		runTUI()
	case "add":
		cmdAdd(rest)
	case "catalog", "services":
		cmdCatalog(rest)
	case "providers":
		cmdProviders()
	case "status", "ls", "list":
		cmdStatus()
	case "version", "--version", "-v":
		fmt.Println(appName, version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown command %q\n\n", appName, os.Args[1])
		usage()
		os.Exit(1)
	}
}
