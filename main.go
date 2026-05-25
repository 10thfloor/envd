// envd — a single-file, dependency-free daemon that makes switching local
// development between environments (dev/staging/prod) obvious and automatic,
// so you never have to handle or see raw secret values.
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
	version = "0.4.0"
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
}

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
	Cmd     string            `json:"cmd"`
	Cwd     string            `json:"cwd,omitempty"`
	Applied []string          `json:"applied,omitempty"`
	Args    map[string]string `json:"args,omitempty"`
	KV      map[string]string `json:"kv,omitempty"` // bulk payload (import)
}

type Response struct {
	OK       bool              `json:"ok"`
	Error    string            `json:"error,omitempty"`
	Exports  map[string]string `json:"exports,omitempty"`
	Unsets   []string          `json:"unsets,omitempty"`
	Env      string            `json:"env,omitempty"`
	Text     string            `json:"text,omitempty"`
	Projects []ProjectView     `json:"projects,omitempty"`
	Vars     []VarView         `json:"vars,omitempty"`
	Doctor   *DoctorReport     `json:"doctor,omitempty"`
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

type Daemon struct {
	mu       sync.Mutex
	state    *State
	cache    map[string]*unlocked // by project path
	sessions map[string]session   // by shell id
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
// Reference interpolation (1Password-style): op://vault/item/field and
// envd://<env>/<KEY>, usable whole-value or embedded via ${...}. Resolved at
// inject time, recursively, with a depth cap for cycle protection.
// ---------------------------------------------------------------------------

var refRe = regexp.MustCompile(`\$\{([^}]+)\}`)

func looksLikeRef(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "op://") || strings.HasPrefix(s, "envd://")
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
	switch {
	case strings.HasPrefix(ref, "envd://"):
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
	case strings.HasPrefix(ref, "op://"):
		return opRead(ref)
	}
	return "", fmt.Errorf("unknown reference scheme %q", ref)
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

// opRead resolves a 1Password reference via the `op` CLI.
func opRead(ref string) (string, error) {
	if _, err := exec.LookPath("op"); err != nil {
		return "", errors.New("1Password CLI `op` not found on PATH")
	}
	out, err := exec.Command("op", "read", ref).Output()
	if err != nil {
		return "", fmt.Errorf("op read %q failed (signed in?): %v", ref, err)
	}
	return strings.TrimRight(string(out), "\r\n"), nil
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
		return Response{Error: "no envd project here (run `envd connect`)"}
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
		return Response{Error: "no envd project here (run `envd connect`)"}
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
	u.layer(env)[arg(req, "key")] = val
	if err := saveVault(p.Path, u.vault, u.vf, u.key); err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, Text: fmt.Sprintf("set %s for %s/%s", arg(req, "key"), p.Name, env)}
}

func (d *Daemon) handleRegister(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
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
	if _, ok := m[key]; !ok {
		return Response{Error: "no such key " + key + " in " + env}
	}
	delete(m, key)
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
	delete(u.vault.Values, env)
	u.vault.Environments = removeStr(u.vault.Environments, env)
	p.Envs = removeStr(p.Envs, env)
	if p.ActiveEnv == env {
		p.ActiveEnv = p.Envs[0]
	}
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
func scanEnvRefs(root string) ([]string, int) {
	set := map[string]bool{}
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
		for _, re := range envRefPatterns {
			for _, m := range re.FindAllStringSubmatch(string(data), -1) {
				set[m[1]] = true
			}
		}
		return nil
	})
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, files
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
	return Response{OK: true, Doctor: rep, Text: doctorText(p.Name, rep)}
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
	for k, v := range req.KV {
		layer[k] = v
	}
	if err := saveVault(p.Path, u.vault, u.vf, u.key); err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, Text: fmt.Sprintf("imported %d var(s) into %s/%s", len(req.KV), p.Name, env)}
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
	default:
		resp = Response{Error: "unknown cmd " + req.Cmd}
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

func cmdStart() {
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

	d := &Daemon{state: loadState(), cache: map[string]*unlocked{}, sessions: map[string]session{}}

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
	if len(pos) > 0 {
		if _, ok := adapters[pos[0]]; ok {
			cmdConnectProvider(pos[0])
			return
		}
		fatalf("unknown provider %q (registered: %s)", pos[0], strings.Join(adapterNames(), ", "))
	}
	cmdConnectProject()
}

func cmdConnectProject() {
	cwd, _ := os.Getwd()
	r := bufio.NewReader(os.Stdin)
	name := prompt(r, "Project name", filepath.Base(cwd))
	envs := prompt(r, "Environments (comma-separated)", "dev,staging,prod")

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
		"  2. Set a value:        cat secret.txt | envd set DATABASE_URL --env dev\n" +
		"  3. Switch env:         envd use staging\n")
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
		fatalf("usage: envd set <KEY> [--env ENV]   (value read from stdin)")
	}
	fmt.Fprint(os.Stderr, "value (from stdin; pipe to avoid echo): ")
	val, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	val = strings.TrimRight(val, "\r\n")
	cwd, _ := os.Getwd()
	resp := mustCall(Request{Cmd: "set", Cwd: cwd,
		Args: map[string]string{"env": flags["env"], "key": pos[0], "value": val}})
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
	resp := mustCall(Request{Cmd: "doctor", Cwd: cwd, Args: map[string]string{"env": flags["env"]}})
	fmt.Print(resp.Text)
	if flags["example"] != "" && resp.Doctor != nil {
		var b strings.Builder
		b.WriteString("# Generated by envd — required environment variables (no values).\n")
		for _, k := range resp.Doctor.Referenced {
			b.WriteString(k + "=\n")
		}
		path := filepath.Join(cwd, ".env.example")
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("✓ wrote %s (%d keys)\n", path, len(resp.Doctor.Referenced))
	}
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
	resp := mustCall(Request{Cmd: "import", Cwd: cwd, KV: kv, Args: map[string]string{"env": flags["env"]}})
	fmt.Printf("✓ %s\n", resp.Text)
}

func cmdAdopt() {
	cwd, _ := os.Getwd()
	resp := mustCall(Request{Cmd: "adopt", Cwd: cwd})
	fmt.Printf("✓ %s\n", resp.Text)
}

func cmdStatus() {
	resp := mustCall(Request{Cmd: "status"})
	fmt.Print(resp.Text)
}

func usage() {
	fmt.Print(`envd ` + version + ` — never think about per-environment secrets again.

Usage:
  envd start                 Run the daemon (once per machine; backgroundable).
  envd hook <zsh|bash>       Print the shell hook to add to your rc file.
  envd connect               Register the current directory as a project.
  envd connect <provider>    OAuth-connect a provider and import its values.
  envd adopt                 Register an existing on-disk vault (cloned repo).
  envd import [file] [--env e]  Import a .env file (default ./.env) into an environment.
  envd use <env>             Set the active environment for this project.
  envd set <KEY> [--env e]   Store a value (read from stdin). --env base = shared layer.
  envd unset <KEY> [--env e] Delete a value.
  envd diff <envA> <envB>    Show which keys differ between two environments.
  envd doctor [--env e] [--example]
                             Scan code for env-var refs; flag missing/empty/placeholder/unused.
                             --example writes a .env.example of all referenced keys.
  envd tui                   Open the interactive vault/environment manager.
  envd status                Show projects, active envs, and active shells.
  envd version               Print version.

References (resolved at inject time):
  op://vault/item/field      Read live from 1Password (via the op CLI).
  envd://<env>/<KEY>         Reuse another environment's value (DRY).
  Embed either with ${...}:  postgres://app:${op://Private/db/pw}@host/db

Generators (materialized once, at set time):
  gen://random/32            Random bytes, base64. Also hex/N, uuid, password/N.
  printf gen://random/48 | envd set SESSION_SECRET --env prod

Daily loop:
  1. envd start &                         # start the daemon
  2. eval "$(envd hook zsh)"  >> ~/.zshrc # one-time
  3. cd my-app && envd connect            # register
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
	case "connect":
		cmdConnect(rest)
	case "use":
		cmdUse(rest)
	case "set":
		cmdSet(rest)
	case "unset":
		cmdUnset(rest)
	case "diff":
		cmdDiff(rest)
	case "doctor":
		cmdDoctor(rest)
	case "import":
		cmdImport(rest)
	case "adopt":
		cmdAdopt()
	case "tui":
		runTUI()
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
