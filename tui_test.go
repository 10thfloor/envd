package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestTUIModel drives the Bubble Tea model directly (no terminal) to verify
// navigation, masking, reveal, and prompt routing without panicking.
func TestTUIModel(t *testing.T) {
	m := newTUIModel()

	step := func(msg tea.Msg) {
		t.Helper()
		nm, _ := m.Update(msg)
		m = nm.(tuiModel)
	}
	key := func(s string) tea.Msg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

	step(tea.WindowSizeMsg{Width: 100, Height: 30})
	step(projectsMsg{projects: []ProjectView{
		{Name: "app", Path: "/tmp/app", Envs: []string{"dev", "staging"}, ActiveEnv: "dev"},
	}})
	if !strings.Contains(m.View(), "app") {
		t.Fatal("picker should list the project")
	}

	step(tea.KeyMsg{Type: tea.KeyEnter}) // open project
	if m.mode != mBrowse {
		t.Fatalf("expected browse mode, got %v", m.mode)
	}
	if !strings.Contains(m.View(), "base") {
		t.Fatal("env list should include the base layer")
	}
	if m.curEnv() != "dev" {
		t.Fatalf("should open on active env dev, got %q", m.curEnv())
	}

	step(varsMsg{env: "dev", vars: []VarView{
		{Key: "DATABASE_URL", Value: "postgres://secret-value"},
		{Key: "MIRROR", Value: "envd://staging/X", IsRef: true},
	}})
	v := m.View()
	if !strings.Contains(v, "DATABASE_URL") {
		t.Fatal("should show variable key")
	}
	if strings.Contains(v, "secret-value") {
		t.Fatal("value must be masked by default")
	}
	if !strings.Contains(v, "•") {
		t.Fatal("expected masked bullets")
	}

	// reveal (cmd would hit the daemon; we feed the resolved result directly)
	step(key("r"))
	if !m.reveal {
		t.Fatal("r should toggle reveal")
	}
	step(varsMsg{env: "dev", vars: []VarView{
		{Key: "DATABASE_URL", Value: "postgres://secret-value", Resolved: "postgres://secret-value"},
	}})
	if !strings.Contains(m.View(), "secret-value") {
		t.Fatal("revealed value should be visible")
	}

	// focus variables, open a new-var prompt
	step(tea.KeyMsg{Type: tea.KeyTab})
	step(key("n"))
	if m.mode != mPrompt {
		t.Fatal("n should open the input prompt")
	}
	step(tea.KeyMsg{Type: tea.KeyEsc})
	if m.mode != mBrowse {
		t.Fatal("esc should cancel the prompt")
	}

	// back to picker
	step(key("p"))
	if m.mode != mPicker {
		t.Fatal("p should return to the picker")
	}
}

func TestTUIHistory(t *testing.T) {
	m := newTUIModel()
	apply := func(msg tea.Msg) { nm, _ := m.Update(msg); m = nm.(tuiModel) }
	apply(tea.WindowSizeMsg{Width: 100, Height: 30})
	apply(projectsMsg{projects: []ProjectView{
		{Name: "app", Path: "/tmp/app", Envs: []string{"dev"}, ActiveEnv: "dev"},
	}})
	apply(tea.KeyMsg{Type: tea.KeyEnter}) // open project
	apply(historyMsg{entries: []HistoryEntry{
		{Seq: 2, Op: "set", Env: "dev", Key: "FOO", Old: "secret-a", HadOld: true, New: "secret-b"},
		{Seq: 1, Op: "set", Env: "dev", Key: "FOO", New: "secret-a"},
	}})
	if m.mode != mHistory {
		t.Fatal("historyMsg should enter history mode")
	}
	v := m.View()
	if !strings.Contains(v, "FOO") || !strings.Contains(v, "history") {
		t.Fatalf("history view missing expected content:\n%s", v)
	}
	if strings.Contains(v, "secret-a") || strings.Contains(v, "secret-b") {
		t.Fatal("history view must mask values")
	}
	apply(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")}) // move
	apply(tea.KeyMsg{Type: tea.KeyEsc})                       // back
	if m.mode != mBrowse {
		t.Fatal("esc should leave history view")
	}
}

func TestTUIDrift(t *testing.T) {
	m := newTUIModel()
	apply := func(msg tea.Msg) { nm, _ := m.Update(msg); m = nm.(tuiModel) }
	apply(tea.WindowSizeMsg{Width: 100, Height: 30})
	apply(projectsMsg{projects: []ProjectView{
		{Name: "app", Path: "/tmp/app", Envs: []string{"dev"}, ActiveEnv: "dev"},
	}})
	apply(tea.KeyMsg{Type: tea.KeyEnter}) // open
	apply(driftMsg{report: &DriftReport{
		Added:   []DriftItem{{Env: "base", Key: "NEW_KEY", Value: "secret-value"}},
		Removed: []DriftItem{{Env: "base", Key: "OLD_KEY"}},
	}})
	if !strings.Contains(m.View(), "manual .env change") {
		t.Fatalf("expected drift banner in browse view:\n%s", m.View())
	}
	apply(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("S")})
	if m.mode != mDrift {
		t.Fatal("S should open the drift view")
	}
	v := m.View()
	if !strings.Contains(v, "NEW_KEY") || !strings.Contains(v, "OLD_KEY") {
		t.Fatalf("drift view missing items:\n%s", v)
	}
	if strings.Contains(v, "secret-value") {
		t.Fatal("drift view must mask values")
	}
	apply(tea.KeyMsg{Type: tea.KeyEsc})
	if m.mode != mBrowse {
		t.Fatal("esc should dismiss the drift view")
	}
}

func TestMask(t *testing.T) {
	if got := mask(VarView{Value: "abcdefghijklmnop"}, false); strings.ContainsAny(got, "abc") {
		t.Fatalf("masked value leaked content: %q", got)
	}
	if got := mask(VarView{Value: "plain", Resolved: "plain"}, true); got != "plain" {
		t.Fatalf("revealed value = %q, want plain", got)
	}
	if got := mask(VarView{ResolveErr: "boom"}, true); !strings.Contains(got, "boom") {
		t.Fatalf("resolve error should surface, got %q", got)
	}
}
