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
