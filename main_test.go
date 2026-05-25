package main

import (
	"context"
	"net/http"
	"net/http/httptest"
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
