package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerators(t *testing.T) {
	id, err := materializeGen("gen://uuid")
	if err != nil || len(id) != 36 || strings.Count(id, "-") != 4 {
		t.Fatalf("uuid = %q, err %v", id, err)
	}
	hexv, _ := materializeGen("gen://hex/8")
	if len(hexv) != 16 {
		t.Fatalf("hex/8 should be 16 chars, got %q", hexv)
	}
	pw, _ := materializeGen("gen://password/20")
	if len(pw) != 20 {
		t.Fatalf("password/20 should be 20 chars, got %q", pw)
	}
	emb, _ := materializeGen("pre-${gen://hex/4}-post")
	if !strings.HasPrefix(emb, "pre-") || !strings.HasSuffix(emb, "-post") || len(emb) != len("pre--post")+8 {
		t.Fatalf("embedded gen failed: %q", emb)
	}
	a, _ := materializeGen("gen://random/16")
	b, _ := materializeGen("gen://random/16")
	if a == b || a == "" {
		t.Fatalf("random should differ each call: %q vs %q", a, b)
	}
	if got, _ := materializeGen("plain-literal"); got != "plain-literal" {
		t.Fatalf("non-generator value mutated: %q", got)
	}
	if _, err := materializeGen("gen://bogus"); err == nil {
		t.Fatal("unknown generator should error")
	}
}

// TestOAuthFlow drives the authorization-code flow against a fake provider —
// verifying the loopback redirect, callback capture, and token exchange.
func TestOAuthFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			http.Redirect(w, r, r.URL.Query().Get("redirect_uri")+"?code=testcode", http.StatusFound)
		case "/token":
			if r.FormValue("code") != "testcode" {
				http.Error(w, "bad code", 400)
				return
			}
			w.Write([]byte(`{"access_token":"tok-123"}`))
		}
	}))
	defer srv.Close()

	cfg := OAuthConfig{AuthURL: srv.URL + "/authorize", TokenURL: srv.URL + "/token", ClientID: "cid", Scopes: []string{"read"}}
	tok, err := runOAuthWith(context.Background(), cfg, func(u string) { go http.Get(u) })
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-123" {
		t.Fatalf("token = %q, want tok-123", tok)
	}

	if _, err := runOAuthWith(context.Background(), OAuthConfig{}, func(string) {}); err == nil {
		t.Fatal("missing client id should error")
	}
}

func TestLooksLikeRef(t *testing.T) {
	for _, s := range []string{"op://a/b", "envd://dev/X", "aws-ssm:///p", "vault://x#y", "doppler://NAME"} {
		if !looksLikeRef(s) {
			t.Fatalf("%q should be recognized as a reference", s)
		}
	}
	// literals that merely look URL-ish must NOT be treated as references
	for _, s := range []string{"postgres://u:p@h/db", "redis://h:6379", "https://example.com", "plain-value", ""} {
		if looksLikeRef(s) {
			t.Fatalf("%q should NOT be treated as a reference", s)
		}
	}
}

func TestResolveRefDispatchAndCache(t *testing.T) {
	calls := 0
	providerByScheme["test"] = provider{scheme: "test", fn: func(a string) (string, error) {
		calls++
		return "val:" + a, nil
	}}
	defer delete(providerByScheme, "test")

	d := &Daemon{refCache: map[string]refCacheEntry{}}
	if v, err := d.resolveRef(nil, "", "test://foo", 0); err != nil || v != "val:foo" {
		t.Fatalf("dispatch: got %q, %v", v, err)
	}
	if v, _ := d.resolveRef(nil, "", "test://foo", 0); v != "val:foo" || calls != 1 {
		t.Fatalf("expected cache hit (calls=1), got v=%q calls=%d", v, calls)
	}
	if _, err := d.resolveRef(nil, "", "nope://x", 0); err == nil {
		t.Fatal("unknown scheme should error")
	}
}

// TestProviderShellout verifies a provider resolver actually invokes the vendor
// CLI, using a fake `op` on PATH (no real 1Password needed).
func TestProviderShellout(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "op")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho \"resolved:$2\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	d := &Daemon{refCache: map[string]refCacheEntry{}}
	v, err := d.resolveRef(nil, "", "op://Private/db/pw", 0)
	if err != nil {
		t.Fatal(err)
	}
	if v != "resolved:op://Private/db/pw" {
		t.Fatalf("shellout returned %q", v)
	}
}

func TestCatalog(t *testing.T) {
	if _, ok := catLookup("stripe"); !ok {
		t.Fatal("stripe should be in the catalog")
	}
	if e, ok := catLookup("HF"); !ok || e.Name != "huggingface" {
		t.Fatalf("alias HF should resolve to huggingface, got %q (%v)", e.Name, ok)
	}
	if _, ok := catLookup("definitely-not-a-service"); ok {
		t.Fatal("unknown service should not resolve")
	}
	seen := map[string]bool{}
	for _, e := range catalog {
		if e.Name == "" || e.Title == "" || e.Cat == "" {
			t.Fatalf("incomplete catalog entry: %+v", e)
		}
		if seen[e.Name] {
			t.Fatalf("duplicate service name %q", e.Name)
		}
		seen[e.Name] = true
		for _, v := range e.Vars {
			if v.Key == "" {
				t.Fatalf("%s has an empty var key", e.Name)
			}
			if strings.HasPrefix(v.Default, "gen://") {
				if _, err := genValue(v.Default); err != nil {
					t.Fatalf("%s/%s has an invalid generator %q: %v", e.Name, v.Key, v.Default, err)
				}
			}
		}
		if len(e.Vars) == 0 && e.Note == "" {
			t.Fatalf("%s has neither vars nor a note", e.Name)
		}
	}
}

func newTestDaemon(t *testing.T) (*Daemon, string) {
	t.Helper()
	dir := t.TempDir()
	v := &Vault{
		Project: "p", Environments: []string{"dev"},
		Base:   map[string]string{},
		Values: map[string]map[string]string{"dev": {}},
	}
	return &Daemon{
		state:    &State{Projects: []Project{{Name: "p", Path: dir, Envs: []string{"dev"}, ActiveEnv: "dev"}}},
		cache:    map[string]*unlocked{dir: {vault: v, vf: &vaultFile{Version: 1, KDF: "pbkdf2"}, key: make([]byte, 32)}},
		sessions: map[string]session{},
		refCache: map[string]refCacheEntry{},
	}, dir
}

func TestSetOverwriteGuard(t *testing.T) {
	d, dir := newTestDaemon(t)
	vals := d.cache[dir].vault.Values["dev"]
	set := func(extra map[string]string) Response {
		a := map[string]string{"key": "K", "env": "dev"}
		for k, v := range extra {
			a[k] = v
		}
		return d.handleSet(Request{Cwd: dir, Args: a})
	}

	if r := set(map[string]string{"value": "1"}); !r.OK {
		t.Fatalf("first set should succeed: %+v", r)
	}
	if r := set(map[string]string{"value": "2"}); !r.NeedConfirm || r.OK {
		t.Fatalf("overwrite should require confirmation: %+v", r)
	}
	if vals["K"] != "1" {
		t.Fatalf("value must be unchanged when confirmation needed, got %q", vals["K"])
	}
	if r := set(map[string]string{"value": "1"}); r.NeedConfirm {
		t.Fatal("setting the same value should not need confirmation")
	}
	if r := set(map[string]string{"value": "2", "force": "true"}); !r.OK || vals["K"] != "2" {
		t.Fatalf("force should overwrite: %+v / %q", r, vals["K"])
	}
}

func TestImportSkipsExisting(t *testing.T) {
	d, dir := newTestDaemon(t)
	vals := d.cache[dir].vault.Values["dev"]
	d.handleSet(Request{Cwd: dir, Args: map[string]string{"key": "A", "env": "dev", "value": "1"}})

	r := d.handleImport(Request{Cwd: dir, KV: map[string]string{"A": "x", "B": "y"}, Args: map[string]string{"env": "dev"}})
	if !r.OK {
		t.Fatal(r.Error)
	}
	if vals["A"] != "1" {
		t.Fatalf("existing A should be skipped, got %q", vals["A"])
	}
	if vals["B"] != "y" {
		t.Fatalf("new B should import, got %q", vals["B"])
	}
	d.handleImport(Request{Cwd: dir, KV: map[string]string{"A": "x"}, Args: map[string]string{"env": "dev", "force": "true"}})
	if vals["A"] != "x" {
		t.Fatalf("force should overwrite A, got %q", vals["A"])
	}
}

func TestDoctorExampleWritesToProjectRoot(t *testing.T) {
	d, dir := newTestDaemon(t)
	if err := os.WriteFile(filepath.Join(dir, "app.ts"), []byte("process.env.FOO; process.env.BAR"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := d.handleDoctor(Request{Cwd: dir, Args: map[string]string{"example": "true"}})
	if !r.OK {
		t.Fatalf("doctor failed: %s", r.Error)
	}
	got, err := os.ReadFile(filepath.Join(dir, ".env.example"))
	if err != nil {
		t.Fatalf(".env.example not written to project root: %v", err)
	}
	for _, want := range []string{"BAR=", "FOO="} {
		if !strings.Contains(string(got), want) {
			t.Fatalf(".env.example missing %q; got:\n%s", want, got)
		}
	}
}

func TestClassifyEnvFile(t *testing.T) {
	chk := func(name, env string, local, ok bool) {
		t.Helper()
		e, l, o := classifyEnvFile(name)
		if e != env || l != local || o != ok {
			t.Fatalf("%s → (%q,%v,%v), want (%q,%v,%v)", name, e, l, o, env, local, ok)
		}
	}
	chk(".env", "base", false, true)
	chk(".env.local", "base", true, true)
	chk(".env.production", "prod", false, true)
	chk(".env.production.local", "prod", true, true)
	chk(".env.development", "dev", false, true)
	chk(".env.staging", "staging", false, true)
	chk(".env.test", "test", false, true)
	chk(".env.ci", "ci", false, true)
	chk(".env.example", "", false, false)
	chk(".env.vault", "", false, false)
	chk("config.js", "", false, false)
}

func TestDiscoverEnv(t *testing.T) {
	dir := t.TempDir()
	write := func(n, body string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".env", "SHARED=base\nAPP=common\n")
	write(".env.local", "SHARED=baselocal\n") // .local overrides base
	write(".env.production", "APP=common\nDB=prod\n")
	write(".env.production.local", "DB=prodlocal\n") // .local overrides prod
	write(".env.development", "APP=common\nDB=dev\n")
	write(".env.example", "IGNORED=x\n") // skipped

	layers, used := discoverEnv(dir)
	if layers["base"]["SHARED"] != "baselocal" {
		t.Fatalf("base SHARED = %q (local should win)", layers["base"]["SHARED"])
	}
	if layers["base"]["APP"] != "common" {
		t.Fatalf("base APP = %q", layers["base"]["APP"])
	}
	if _, ok := layers["prod"]["APP"]; ok {
		t.Fatal("APP duplicates base — should be dropped from prod")
	}
	if layers["prod"]["DB"] != "prodlocal" {
		t.Fatalf("prod DB = %q (.local should win)", layers["prod"]["DB"])
	}
	if layers["dev"]["DB"] != "dev" {
		t.Fatalf("dev DB = %q", layers["dev"]["DB"])
	}
	if _, ok := layers["example"]; ok {
		t.Fatal(".env.example must be skipped")
	}
	if len(used) != 5 {
		t.Fatalf("used files = %v", used)
	}
}

func TestDiscoverDefaults(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte(
		`const p = process.env.PORT || 3000;
		 const h = process.env.HOST ?? "localhost";
		 const l = process.env["LOG_LEVEL"] || 'info';`), 0o644)
	os.WriteFile(filepath.Join(dir, "b.py"), []byte(`os.getenv("RETRIES", "3")`), 0o644)
	d := discoverDefaults(dir)
	for k, want := range map[string]string{"PORT": "3000", "HOST": "localhost", "LOG_LEVEL": "info", "RETRIES": "3"} {
		if d[k] != want {
			t.Fatalf("default %s = %q, want %q (all: %v)", k, d[k], want, d)
		}
	}
}

func TestResolveReferenced(t *testing.T) {
	layers := map[string]map[string]string{
		"base": {"A": "1"},
		"prod": {"B": "2"},
	}
	defaults := map[string]string{"D": "dd"}
	env := map[string]string{"C": "from-shell"}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	fromEnv, fromDefault, undet := resolveReferenced(layers, []string{"A", "B", "C", "D", "E"}, defaults, lookup)
	if len(fromEnv) != 1 || fromEnv[0] != "C" || layers["base"]["C"] != "from-shell" {
		t.Fatalf("C should be captured from env: %v / %q", fromEnv, layers["base"]["C"])
	}
	if len(fromDefault) != 1 || fromDefault[0] != "D" || layers["base"]["D"] != "dd" {
		t.Fatalf("D should be captured from defaults: %v / %q", fromDefault, layers["base"]["D"])
	}
	if len(undet) != 1 || undet[0] != "E" {
		t.Fatalf("E should be undetermined: %v", undet)
	}
	if v, ok := layers["base"]["E"]; !ok || v != "" {
		t.Fatal("E should be stored as a blank placeholder")
	}
	if _, ok := layers["base"]["A"]; ok && layers["base"]["A"] != "1" {
		t.Fatal("existing A must not be overwritten")
	}
}

func TestAssimilate(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // sandbox saveState
	d, dir := newTestDaemon(t)
	v := d.cache[dir].vault
	r := d.handleAssimilate(Request{Cwd: dir, Layers: map[string]map[string]string{
		"base": {"SHARED": "x"},
		"prod": {"DB": "p"},
	}})
	if !r.OK {
		t.Fatal(r.Error)
	}
	if v.Base["SHARED"] != "x" {
		t.Fatalf("base SHARED = %q", v.Base["SHARED"])
	}
	if v.Values["prod"]["DB"] != "p" {
		t.Fatalf("prod DB = %q", v.Values["prod"]["DB"])
	}
	found := false
	for _, e := range v.Environments {
		if e == "prod" {
			found = true
		}
	}
	if !found {
		t.Fatalf("prod should be added to environments: %v", v.Environments)
	}
}

func TestComputeDrift(t *testing.T) {
	base := map[string]map[string]string{
		"base": {"SHARED": "1", "GONE": "x"},
		"prod": {"DB": "old"},
	}
	cur := map[string]map[string]string{
		"base": {"SHARED": "1", "NEW": "n"}, // NEW added, GONE removed
		"prod": {"DB": "new"},               // DB changed
	}
	d := computeDrift(base, cur)
	if d == nil {
		t.Fatal("expected drift")
	}
	if len(d.Added) != 1 || d.Added[0].Key != "NEW" || d.Added[0].Value != "n" {
		t.Fatalf("added = %+v", d.Added)
	}
	if len(d.Changed) != 1 || d.Changed[0].Key != "DB" || d.Changed[0].Value != "new" {
		t.Fatalf("changed = %+v", d.Changed)
	}
	if len(d.Removed) != 1 || d.Removed[0].Key != "GONE" {
		t.Fatalf("removed = %+v", d.Removed)
	}
	// identical → nil
	if computeDrift(base, base) != nil {
		t.Fatal("identical layers should report no drift")
	}
}

func TestDriftDetectAndApply(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // sandbox saveState/saveVault baseline writes
	d, dir := newTestDaemon(t)
	write := func(n, body string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// initial .env, assimilate-style baseline
	write(".env", "A=1\nB=2\n")
	d.cache[dir].vault.EnvBaseline = discoverEnvFiles(dir)
	d.cache[dir].vault.Base["A"] = "1"
	d.cache[dir].vault.Base["B"] = "2"

	// user manually edits: A changed, B removed, C added
	write(".env", "A=99\nC=3\n")

	r := d.handleDrift(Request{Cwd: dir})
	if r.Drift.empty() {
		t.Fatal("expected drift after manual edit")
	}
	if r.Drift.count() != 3 {
		t.Fatalf("expected 3 changes (A~ B- C+), got %+v", r.Drift)
	}

	ar := d.handleApplyDrift(Request{Cwd: dir})
	if !ar.OK {
		t.Fatal(ar.Error)
	}
	base := d.cache[dir].vault.Base
	if base["A"] != "99" {
		t.Fatalf("A should be updated to 99, got %q", base["A"])
	}
	if base["C"] != "3" {
		t.Fatalf("C should be added, got %q", base["C"])
	}
	if _, ok := base["B"]; ok {
		t.Fatal("B should be removed from the vault")
	}
	// after apply, no more drift
	if r2 := d.handleDrift(Request{Cwd: dir}); !r2.Drift.empty() {
		t.Fatalf("expected no drift after apply, got %+v", r2.Drift)
	}
}

func TestParseDotenv(t *testing.T) {
	kv := parseDotenv([]byte("A=1\nB=\"two words\"\n# comment\nexport C=3\n\nD=\nbad line\n"))
	want := map[string]string{"A": "1", "B": "two words", "C": "3", "D": ""}
	if len(kv) != len(want) {
		t.Fatalf("parsed %v, want %v", kv, want)
	}
	for k, v := range want {
		if kv[k] != v {
			t.Fatalf("%s = %q, want %q", k, kv[k], v)
		}
	}
}
