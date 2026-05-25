package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Bubble Tea TUI for inspecting and editing the vault.
//
//   picker  → choose a project
//   browse  → left: environments, right: variables table
//   prompt  → single-line input (new key / edit value / new env)
//   confirm → y/n for destructive actions
// ---------------------------------------------------------------------------

func runTUI() {
	if _, err := daemonCall(Request{Cmd: "ping"}); err != nil {
		fatal(err)
	}
	if _, err := tea.NewProgram(newTUIModel(), tea.WithAltScreen()).Run(); err != nil {
		fatal(err)
	}
}

type tmode int

const (
	mPicker tmode = iota
	mBrowse
	mPrompt
	mConfirm
	mDoctor
	mHistory
	mDrift
)

type tfocus int

const (
	fEnvs tfocus = iota
	fVars
)

type pkind int

const (
	pNewKey  pkind = iota // entering the name of a new variable
	pNewVal               // entering the value of the new variable in inCtx
	pEditVal              // editing the value of variable inCtx
	pAddEnv               // entering a new environment name
)

type ckind int

const (
	cDelVar ckind = iota
	cDelEnv
	cOverwrite
)

type (
	projectsMsg struct {
		projects []ProjectView
		err      string
	}
	varsMsg struct {
		env  string
		vars []VarView
		err  string
	}
	doctorMsg struct {
		report *DoctorReport
		err    string
	}
	historyMsg struct {
		entries []HistoryEntry
		err     string
	}
	driftMsg struct {
		report *DriftReport
		err    string
	}
)

func runDriftCmd(path string) tea.Cmd {
	return func() tea.Msg {
		r, err := daemonCall(Request{Cmd: "drift", Args: map[string]string{"project": path}})
		if err != nil {
			return driftMsg{err: err.Error()}
		}
		return driftMsg{report: r.Drift}
	}
}

func runHistoryCmd(path string) tea.Cmd {
	return func() tea.Msg {
		r, err := daemonCall(Request{Cmd: "history", Args: map[string]string{"project": path, "n": "200"}})
		if err != nil {
			return historyMsg{err: err.Error()}
		}
		if !r.OK {
			return historyMsg{err: r.Error}
		}
		return historyMsg{entries: r.History}
	}
}

func runDoctorCmd(path, env string) tea.Cmd {
	return func() tea.Msg {
		r, err := daemonCall(Request{Cmd: "doctor", Args: map[string]string{"project": path, "env": env}})
		if err != nil {
			return doctorMsg{err: err.Error()}
		}
		if !r.OK {
			return doctorMsg{err: r.Error}
		}
		return doctorMsg{report: r.Doctor}
	}
}

func loadProjectsCmd() tea.Cmd {
	return func() tea.Msg {
		r, err := daemonCall(Request{Cmd: "projects"})
		if err != nil {
			return projectsMsg{err: err.Error()}
		}
		return projectsMsg{projects: r.Projects}
	}
}

func loadVarsCmd(path, env string, resolve bool) tea.Cmd {
	return func() tea.Msg {
		r, err := daemonCall(Request{Cmd: "vars", Args: map[string]string{
			"project": path, "env": env, "resolve": btoa(resolve),
		}})
		if err != nil {
			return varsMsg{env: env, err: err.Error()}
		}
		if !r.OK {
			return varsMsg{env: env, err: r.Error}
		}
		return varsMsg{env: env, vars: r.Vars}
	}
}

func btoa(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

var (
	stHeader = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("63")).Padding(0, 1)
	stEnvBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	stVarBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 0)
	stActive = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	stCursor = lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Background(lipgloss.Color("57"))
	stDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	stErr    = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	stOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	stWarn   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
)

type tuiModel struct {
	projects []ProjectView
	pIdx     int          // cursor in picker
	proj     *ProjectView // open project (nil in picker)
	envIdx   int          // cursor in env list
	vars     []VarView
	tbl      table.Model

	mode    tmode
	focus   tfocus
	reveal  bool
	in      textinput.Model
	pk      pkind
	ck      ckind
	inCtx   string // key being edited / pending new key
	doc     *DoctorReport
	hist    []HistoryEntry
	histIdx int
	drift   *DriftReport
	// pending set awaiting overwrite confirmation
	pendEnv, pendKey, pendVal string
	status                    string
	w, h                      int
}

// doSet writes a value via the daemon. If it would overwrite an existing value
// and force is false, it stashes the pending set and asks for confirmation —
// editing in the TUI prompts just like the CLI.
func (m *tuiModel) doSet(env, key, val string, force bool) tea.Cmd {
	args := map[string]string{"project": m.proj.Path, "env": env, "key": key, "value": val}
	if force {
		args["force"] = "true"
	}
	r, err := daemonCall(Request{Cmd: "set", Args: args})
	switch {
	case err != nil:
		m.status = stErr.Render("✗ " + err.Error())
		return nil
	case r.NeedConfirm:
		m.pendEnv, m.pendKey, m.pendVal = env, key, val
		m.ck = cOverwrite
		m.mode = mConfirm
		return nil
	case !r.OK:
		m.status = stErr.Render("✗ " + r.Error)
		return nil
	default:
		m.status = stOK.Render("✓ " + r.Text)
		return tea.Batch(m.reloadVars(), loadProjectsCmd())
	}
}

func newTUIModel() tuiModel {
	ti := textinput.New()
	ti.Prompt = "› "
	t := table.New(
		table.WithColumns([]table.Column{{Title: "KEY", Width: 24}, {Title: "VALUE", Width: 40}, {Title: "SRC", Width: 7}}),
		table.WithFocused(true),
	)
	return tuiModel{mode: mPicker, in: ti, tbl: t}
}

func (m tuiModel) Init() tea.Cmd { return loadProjectsCmd() }

// envList is the navigable environment list: the shared base layer first, then
// the project's real environments.
func (m tuiModel) envList() []string {
	if m.proj == nil {
		return nil
	}
	return append([]string{"base"}, m.proj.Envs...)
}

func (m tuiModel) curEnv() string {
	el := m.envList()
	if m.envIdx < 0 || m.envIdx >= len(el) {
		return ""
	}
	return el[m.envIdx]
}

func (m tuiModel) selVar() (VarView, bool) {
	k := m.selKey()
	for _, v := range m.vars {
		if v.Key == k {
			return v, true
		}
	}
	return VarView{}, false
}

func (m tuiModel) selKey() string {
	if r := m.tbl.SelectedRow(); len(r) > 0 {
		return r[0]
	}
	return ""
}

func (m tuiModel) rawValue(key string) string {
	for _, v := range m.vars {
		if v.Key == key {
			return v.Value
		}
	}
	return ""
}

func (m *tuiModel) rebuildRows() {
	rows := make([]table.Row, 0, len(m.vars))
	for _, v := range m.vars {
		flags := ""
		switch {
		case v.Inherited:
			flags = "base"
		case v.Overrides:
			flags = "ovr"
		}
		if v.IsRef {
			if flags != "" {
				flags += " →"
			} else {
				flags = "→"
			}
		}
		rows = append(rows, table.Row{v.Key, mask(v, m.reveal), flags})
	}
	m.tbl.SetRows(rows)
}

func mask(v VarView, reveal bool) string {
	if reveal {
		if v.ResolveErr != "" {
			return "⚠ " + v.ResolveErr
		}
		if v.Resolved != "" {
			return v.Resolved
		}
		return v.Value
	}
	n := len([]rune(v.Value))
	if n > 10 {
		n = 10
	}
	if n < 4 {
		n = 4
	}
	return strings.Repeat("•", n)
}

func (m *tuiModel) open(p *ProjectView) tea.Cmd {
	m.proj = p
	m.mode = mBrowse
	m.focus = fEnvs
	m.envIdx = 0
	for i, e := range m.envList() {
		if e == p.ActiveEnv {
			m.envIdx = i
		}
	}
	return tea.Batch(loadVarsCmd(p.Path, m.curEnv(), m.reveal), runDriftCmd(p.Path))
}

func (m *tuiModel) reloadVars() tea.Cmd {
	return loadVarsCmd(m.proj.Path, m.curEnv(), m.reveal)
}

// call runs a daemon mutation, records a status line, and returns a reload cmd.
func (m *tuiModel) call(req Request, okMsg string) tea.Cmd {
	req.Args["project"] = m.proj.Path
	r, err := daemonCall(req)
	switch {
	case err != nil:
		m.status = stErr.Render("✗ " + err.Error())
	case !r.OK:
		m.status = stErr.Render("✗ " + r.Error)
	default:
		m.status = stOK.Render("✓ " + okMsg)
	}
	return tea.Batch(m.reloadVars(), loadProjectsCmd())
}

func (m *tuiModel) startPrompt(k pkind, label, prefill string) {
	m.mode = mPrompt
	m.pk = k
	m.in.SetValue(prefill)
	m.in.Placeholder = label
	m.in.CursorEnd()
	m.in.Focus()
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		valW := m.w - 22 - 24 - 7 - 8
		if valW < 16 {
			valW = 16
		}
		m.tbl.SetColumns([]table.Column{{Title: "KEY", Width: 24}, {Title: "VALUE", Width: valW}, {Title: "SRC", Width: 7}})
		bodyH := m.h - 6
		if bodyH < 3 {
			bodyH = 3
		}
		m.tbl.SetHeight(bodyH)
		return m, nil

	case projectsMsg:
		if msg.err != "" {
			m.status = stErr.Render("✗ " + msg.err)
			return m, nil
		}
		m.projects = msg.projects
		// keep open project's view in sync
		if m.proj != nil {
			for i := range m.projects {
				if m.projects[i].Path == m.proj.Path {
					m.proj = &m.projects[i]
				}
			}
		}
		return m, nil

	case varsMsg:
		if msg.err != "" {
			m.status = stErr.Render("✗ " + msg.err)
			return m, nil
		}
		m.vars = msg.vars
		m.rebuildRows()
		return m, nil

	case doctorMsg:
		if msg.err != "" {
			m.status = stErr.Render("✗ " + msg.err)
			return m, nil
		}
		m.doc = msg.report
		m.mode = mDoctor
		return m, nil

	case historyMsg:
		if msg.err != "" {
			m.status = stErr.Render("✗ " + msg.err)
			return m, nil
		}
		m.hist = msg.entries
		if m.histIdx >= len(m.hist) {
			m.histIdx = 0
		}
		m.mode = mHistory
		return m, nil

	case driftMsg:
		if msg.err == "" {
			m.drift = msg.report // banner shows in browse; user opens it with S
		}
		return m, nil

	case tea.KeyMsg:
		switch m.mode {
		case mPicker:
			return m.updatePicker(msg)
		case mBrowse:
			return m.updateBrowse(msg)
		case mPrompt:
			return m.updatePrompt(msg)
		case mConfirm:
			return m.updateConfirm(msg)
		case mDoctor:
			m.mode = mBrowse // any key dismisses
			return m, nil
		case mHistory:
			return m.updateHistory(msg)
		case mDrift:
			return m.updateDrift(msg)
		}
	}
	return m, nil
}

func (m tuiModel) updatePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "up", "k":
		if m.pIdx > 0 {
			m.pIdx--
		}
	case "down", "j":
		if m.pIdx < len(m.projects)-1 {
			m.pIdx++
		}
	case "enter":
		if len(m.projects) > 0 {
			cmd := m.open(&m.projects[m.pIdx])
			return m, cmd
		}
	}
	return m, nil
}

func (m tuiModel) updateBrowse(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "p":
		m.proj = nil
		m.mode = mPicker
		return m, loadProjectsCmd()
	case "tab":
		if m.focus == fEnvs {
			m.focus = fVars
		} else {
			m.focus = fEnvs
		}
		return m, nil
	case "r":
		m.reveal = !m.reveal
		return m, m.reloadVars()
	case "D":
		m.status = stDim.Render("scanning code…")
		return m, runDoctorCmd(m.proj.Path, m.curEnv())
	case "h":
		m.histIdx = 0
		return m, runHistoryCmd(m.proj.Path)
	case "S":
		if m.drift.empty() {
			m.status = stDim.Render("no manual .env changes detected")
			return m, nil
		}
		m.mode = mDrift
		return m, nil
	}

	if m.focus == fEnvs {
		switch msg.String() {
		case "up", "k":
			if m.envIdx > 0 {
				m.envIdx--
				return m, m.reloadVars()
			}
		case "down", "j":
			if m.envIdx < len(m.envList())-1 {
				m.envIdx++
				return m, m.reloadVars()
			}
		case "a": // set active
			if m.curEnv() == "base" {
				m.status = stDim.Render("the base layer can't be the active env")
				return m, nil
			}
			return m, m.call(Request{Cmd: "use", Args: map[string]string{"env": m.curEnv()}}, "active env → "+m.curEnv())
		case "A": // add env
			m.startPrompt(pAddEnv, "new environment name", "")
			return m, textinput.Blink
		case "X": // remove env
			if m.curEnv() == "base" {
				m.status = stDim.Render("the base layer can't be removed")
				return m, nil
			}
			m.ck = cDelEnv
			m.mode = mConfirm
			return m, nil
		}
		return m, nil
	}

	// focus == fVars
	switch msg.String() {
	case "n":
		m.startPrompt(pNewKey, "new variable name", "")
		return m, textinput.Blink
	case "e", "enter":
		if k := m.selKey(); k != "" {
			m.inCtx = k
			m.startPrompt(pEditVal, "value for "+k, m.rawValue(k))
			return m, textinput.Blink
		}
	case "d", "x":
		if v, ok := m.selVar(); ok {
			if v.Inherited && m.curEnv() != "base" {
				m.status = stDim.Render("inherited from base — switch to the base layer to remove it")
				return m, nil
			}
			m.ck = cDelVar
			m.mode = mConfirm
		}
		return m, nil
	}
	var cmd tea.Cmd
	m.tbl, cmd = m.tbl.Update(msg)
	return m, cmd
}

func (m tuiModel) updatePrompt(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = mBrowse
		m.in.Blur()
		return m, nil
	case "enter":
		val := strings.TrimSpace(m.in.Value())
		m.mode = mBrowse
		m.in.Blur()
		switch m.pk {
		case pNewKey:
			if val == "" {
				return m, nil
			}
			m.inCtx = val
			m.startPrompt(pNewVal, "value for "+val, "")
			return m, textinput.Blink
		case pNewVal:
			return m, m.doSet(m.curEnv(), m.inCtx, m.in.Value(), false)
		case pEditVal:
			return m, m.doSet(m.curEnv(), m.inCtx, m.in.Value(), false)
		case pAddEnv:
			if val == "" {
				return m, nil
			}
			return m, m.call(Request{Cmd: "addenv", Args: map[string]string{"env": val}}, "added env "+val)
		}
		return m, nil
	}
	var cmd tea.Cmd
	m.in, cmd = m.in.Update(msg)
	return m, cmd
}

func (m tuiModel) updateConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		m.mode = mBrowse
		switch m.ck {
		case cDelVar:
			return m, m.call(Request{Cmd: "unset", Args: map[string]string{"env": m.curEnv(), "key": m.selKey()}}, "deleted "+m.selKey())
		case cDelEnv:
			return m, m.call(Request{Cmd: "rmenv", Args: map[string]string{"env": m.curEnv()}}, "removed env "+m.curEnv())
		case cOverwrite:
			return m, m.doSet(m.pendEnv, m.pendKey, m.pendVal, true)
		}
	default:
		m.mode = mBrowse
		if m.ck == cOverwrite {
			m.status = stDim.Render("cancelled — " + m.pendKey + " unchanged")
		}
	}
	return m, nil
}

func (m tuiModel) updateDrift(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "a", "A", "enter":
		r, err := daemonCall(Request{Cmd: "applydrift", Args: map[string]string{"project": m.proj.Path}})
		if err != nil {
			m.status = stErr.Render("✗ " + err.Error())
		} else if !r.OK {
			m.status = stErr.Render("✗ " + r.Error)
		} else {
			m.status = stOK.Render("✓ " + r.Text)
		}
		m.drift = nil
		m.mode = mBrowse
		return m, tea.Batch(m.reloadVars(), loadProjectsCmd(), runDriftCmd(m.proj.Path))
	default: // esc / any other key dismisses (keeps the banner)
		m.mode = mBrowse
		return m, nil
	}
}

func (m tuiModel) View() string {
	switch m.mode {
	case mPicker:
		return m.viewPicker()
	case mDoctor:
		return m.viewDoctor()
	case mHistory:
		return m.viewHistory()
	case mDrift:
		return m.viewDrift()
	default:
		return m.viewBrowse()
	}
}

func (m tuiModel) viewDrift() string {
	var b strings.Builder
	b.WriteString(stHeader.Render(fmt.Sprintf("manual .env changes · %s", m.proj.Name)) + "\n\n")
	b.WriteString(stDim.Render("Detected by comparing your .env files to the last sync. Applying updates the vault.\n\n"))
	if m.drift.empty() {
		b.WriteString("  (in sync)\n")
	}
	for _, it := range m.drift.Added {
		b.WriteString(stOK.Render(fmt.Sprintf("  + %-22s %s  added\n", it.Env+"/"+it.Key, maskStr(it.Value))))
	}
	for _, it := range m.drift.Changed {
		b.WriteString(stWarn.Render(fmt.Sprintf("  ~ %-22s %s  changed\n", it.Env+"/"+it.Key, maskStr(it.Value))))
	}
	for _, it := range m.drift.Removed {
		b.WriteString(stErr.Render(fmt.Sprintf("  - %-22s     removed\n", it.Env+"/"+it.Key)))
	}
	b.WriteString("\n" + stDim.Render("a/enter apply to vault · esc dismiss (no change)"))
	return b.String()
}

func (m tuiModel) updateHistory(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q", "h":
		m.mode = mBrowse
		return m, nil
	case "up", "k":
		if m.histIdx > 0 {
			m.histIdx--
		}
	case "down", "j":
		if m.histIdx < len(m.hist)-1 {
			m.histIdx++
		}
	case "enter", "R", "r":
		if m.histIdx < len(m.hist) {
			seq := m.hist[m.histIdx].Seq
			r, err := daemonCall(Request{Cmd: "restore", Args: map[string]string{
				"project": m.proj.Path, "seq": strconv.Itoa(seq)}})
			switch {
			case err != nil:
				m.status = stErr.Render("✗ " + err.Error())
			case !r.OK:
				m.status = stErr.Render("✗ " + r.Error)
			default:
				m.status = stOK.Render("✓ " + r.Text)
			}
			return m, tea.Batch(runHistoryCmd(m.proj.Path), m.reloadVars(), loadProjectsCmd())
		}
	}
	return m, nil
}

func (m tuiModel) viewHistory() string {
	var b strings.Builder
	b.WriteString(stHeader.Render(fmt.Sprintf("history · %s  (newest first)", m.proj.Name)) + "\n\n")
	if len(m.hist) == 0 {
		b.WriteString(stDim.Render("  no history yet\n"))
	}
	window := m.h - 7
	if window < 5 {
		window = 5
	}
	start := 0
	if m.histIdx >= window {
		start = m.histIdx - window + 1
	}
	for i := start; i < len(m.hist) && i < start+window; i++ {
		line := formatHistEntry(m.hist[i])
		if i == m.histIdx {
			b.WriteString(stCursor.Render("› "+line) + "\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
	}
	if m.status != "" {
		b.WriteString("\n" + m.status)
	}
	b.WriteString("\n" + stDim.Render("↑/↓ move · enter/R restore · h/esc back"))
	return b.String()
}

func (m tuiModel) viewDoctor() string {
	r := m.doc
	if r == nil {
		return "no report"
	}
	var b strings.Builder
	b.WriteString(stHeader.Render(fmt.Sprintf("doctor · %s/%s", m.proj.Name, r.Env)) + "\n\n")
	fmt.Fprintf(&b, "scanned %d file(s); %d variable(s) referenced in code\n\n", r.FilesScanned, len(r.Referenced))
	row := func(style lipgloss.Style, label string, ss []string) {
		val := "—"
		if len(ss) > 0 {
			val = strings.Join(ss, ", ")
		}
		b.WriteString(style.Render(fmt.Sprintf("  %-12s", label)) + " " + val + "\n")
	}
	row(stErr, "missing", r.Missing)
	row(stWarn, "empty", r.Empty)
	row(stWarn, "placeholder", r.Placeholder)
	row(stDim, "unused", r.Unused)
	if len(r.Missing)+len(r.Empty)+len(r.Placeholder) == 0 {
		b.WriteString("\n" + stOK.Render("  ✓ every referenced variable is set"))
	}
	b.WriteString("\n\n" + stDim.Render("any key to return"))
	return b.String()
}

func (m tuiModel) viewPicker() string {
	var b strings.Builder
	b.WriteString(stHeader.Render("envd — select a project") + "\n\n")
	if len(m.projects) == 0 {
		b.WriteString(stDim.Render("  no projects yet — run `envd connect` in a project directory\n"))
	}
	for i, p := range m.projects {
		line := fmt.Sprintf("  %s  %s", p.Name, stDim.Render("["+strings.Join(p.Envs, ",")+"] · "+p.Path))
		if p.Locked {
			line += stErr.Render("  [locked]")
		}
		if i == m.pIdx {
			line = stCursor.Render("› " + strings.TrimLeft(line, " "))
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("\n" + stDim.Render("↑/↓ move · enter open · q quit"))
	return b.String()
}

func (m tuiModel) viewBrowse() string {
	// header
	hdr := fmt.Sprintf("envd · %s · viewing %s", m.proj.Name, m.curEnv())
	if m.curEnv() == m.proj.ActiveEnv {
		hdr += "  (active)"
	} else {
		hdr += stDim.Render("  active=" + m.proj.ActiveEnv)
	}
	if m.reveal {
		hdr += "  · revealed"
	}
	header := stHeader.Render(hdr)
	if !m.drift.empty() {
		header += "\n" + stWarn.Render(fmt.Sprintf("⚠ %d manual .env change(s) detected — press S to review & sync", m.drift.count()))
	}

	// env list
	var el strings.Builder
	el.WriteString("ENVIRONMENTS\n")
	for i, e := range m.envList() {
		text := "  " + e
		switch {
		case e == "base":
			text = "⊥ base"
		case e == m.proj.ActiveEnv:
			text = "★ " + e
		}
		var rendered string
		switch {
		case i == m.envIdx:
			marker := "› "
			if m.focus != fEnvs {
				marker = "· "
			}
			rendered = stCursor.Render(marker + strings.TrimLeft(text, " "))
		case e == "base":
			rendered = stDim.Render(text)
		case e == m.proj.ActiveEnv:
			rendered = stActive.Render(text)
		default:
			rendered = text
		}
		el.WriteString(rendered + "\n")
	}
	envCol := stEnvBox.Width(18).Height(m.tbl.Height()).Render(el.String())

	// vars table
	tblView := m.tbl.View()
	if len(m.vars) == 0 {
		tblView = m.tbl.View() + "\n" + stDim.Render("  (no variables — press n to add)")
	}
	varCol := stVarBox.Render(tblView)

	body := lipgloss.JoinHorizontal(lipgloss.Top, envCol, varCol)

	// footer
	var footer string
	switch m.mode {
	case mPrompt:
		footer = m.in.View()
	case mConfirm:
		switch m.ck {
		case cOverwrite:
			footer = stWarn.Render(m.pendKey + " is already set — overwrite? (y/n)")
		case cDelEnv:
			footer = stErr.Render("delete environment " + m.curEnv() + "?  (y/n)")
		default:
			footer = stErr.Render("delete " + m.selKey() + "?  (y/n)")
		}
	default:
		var hints string
		if m.focus == fEnvs {
			hints = "tab→vars · ↑/↓ env · a set-active · A add-env · X del-env · r reveal · D doctor · h history · S sync · q quit"
		} else {
			hints = "tab→envs · ↑/↓ row · n new · e edit · d delete · r reveal · D doctor · h history · S sync · q quit"
		}
		footer = m.status
		if footer != "" {
			footer += "\n"
		}
		footer += stDim.Render(hints)
	}

	return lipgloss.JoinVertical(lipgloss.Left, header, body, footer)
}
