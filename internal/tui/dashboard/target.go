package dashboard

import (
	"fmt"
	"path/filepath"
	"strings"

	core "Akemi/internal/core"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

// =============================================================================
// TargetPanel — ① Target Configuration
// =============================================================================

// field indices for target form
const (
	fieldTarget = iota
	fieldAuthURL
	fieldAuthUsername
	fieldAuthPassword
	fieldPorts
	fieldThreads
	fieldProxy
	fieldIntent
	fieldDepth
	fieldTimeout
	fieldCaptureAuth
	fieldStart
	fieldSave
	fieldLoad
	fieldCount
)

var intentOptions = []string{
	"quick_recon",
	"full_surface_map",
	"api_hunter",
	"sqli_hunt",
	"vuln_assessment",
}

// phaseCheckFields maps a display label to the field extractor for phase checkmarks.
var phaseCheckFields = []struct {
	label   string
	present func(ScanProgressMsg) bool
}{
	{"Subdomains", func(m ScanProgressMsg) bool { return m.Subdomains > 0 }},
	{"Ports", func(m ScanProgressMsg) bool { return m.Ports > 0 }},
	{"URLs", func(m ScanProgressMsg) bool { return m.URLs > 0 }},
	{"Endpoints", func(m ScanProgressMsg) bool { return m.Endpoints > 0 }},
	{"Secrets", func(m ScanProgressMsg) bool { return m.Secrets > 0 }},
	{"Params", func(m ScanProgressMsg) bool { return m.Params > 0 }},
	{"JS Files", func(m ScanProgressMsg) bool { return m.JSFiles > 0 }},
}

type targetField struct {
	label       string
	value       string
	placeholder string
	editable    bool
}

type pathPromptMode int

const (
	pathPromptNone pathPromptMode = iota
	pathPromptSave
	pathPromptLoad
)

// TargetPanel manages target configuration.
type TargetPanel struct {
	focused       bool
	width         int
	height        int
	cursor        int // which field is selected
	inputMode     bool
	fields        [fieldCount]targetField
	status        string
	scanning      bool
	recentTargets []string
	recentCursor  int
	viewport      viewport.Model
	pathPrompt    pathPromptMode
	pathInput     string

	// Scan progress visualization
	progressPercent float64
	progressPhase   string
	progressBar     progress.Model
	completedPhases map[string]bool // phase label → done

	// Signal to parent (Dashboard) that a scan was requested.
	// The parent reads and clears this flag.
	ScanRequested        bool
	AuthCaptureRequested bool
	SaveRunRequested     bool
	LoadRunRequested     bool
	PendingConfig        ScanConfig
	PendingRunPath       string
	PendingAuthURL       string
	PendingAuthUsername  string
	PendingAuthPassword  string

	// Duplicate operation confirmation
	ShowDuplicatePrompt bool
	PendingDuplicateMsg OperationDuplicateMsg
}

// NewTargetPanel creates a new target configuration panel.
func NewTargetPanel() *TargetPanel {
	tp := &TargetPanel{
		cursor:    0,
		inputMode: false,
		status:    "Ready — configure target and press [Start]",
		fields: [fieldCount]targetField{
			{label: "Target", value: "", placeholder: "https://example.com or 10.0.0.0/24", editable: true},
			{label: "Login URL", value: "", placeholder: "optional; defaults to Target", editable: true},
			{label: "Auth User", value: "", placeholder: "username or email", editable: true},
			{label: "Auth Pass", value: "", placeholder: "password (not saved)", editable: true},
			{label: "Ports", value: "top-1000", placeholder: "80,443,8080 or top-1000", editable: true},
			{label: "Threads", value: "200", placeholder: "10-500", editable: true},
			{label: "Proxy", value: "", placeholder: "http://127.0.0.1:8080", editable: true},
			{label: "Intent", value: "quick_recon", placeholder: "quick_recon", editable: false},
			{label: "Depth", value: "2", placeholder: "1-7 (7 = unlimited URLs)", editable: true},
			{label: "Timeout", value: "10", placeholder: "seconds", editable: true},
			{label: "[ Capture Auth ]", value: "", placeholder: "", editable: false},
			{label: "[ Start Scan ]", value: "", placeholder: "", editable: false},
			{label: "[ Save Run ]", value: "", placeholder: "", editable: false},
			{label: "[ Load Run ]", value: "", placeholder: "", editable: false},
		},
		recentTargets:   make([]string, 0),
		completedPhases: make(map[string]bool),
		progressBar:     progress.New(progress.WithScaledGradient("#7B2FBE", "#9D4EDD")),
	}
	tp.viewport = viewport.New(40, 10)
	return tp
}

// SetSize updates the panel dimensions.
func (tp *TargetPanel) SetSize(w, h int) {
	tp.width = w
	tp.height = h
}

// Init implements tea.Model.
func (tp *TargetPanel) Init() tea.Cmd {
	return nil
}

// Update handles messages for the target panel.
func (tp *TargetPanel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case ScanStartedMsg:
		tp.scanning = true
		tp.progressPercent = 0
		tp.progressPhase = ""
		tp.completedPhases = make(map[string]bool)
		tp.status = fmt.Sprintf("[%s] Starting...", msg.Intent)
		return tp, nil

	case ScanProgressMsg:
		tp.progressPhase = msg.Phase
		tp.progressPercent = tp.calculateProgress(msg)
		tp.updateCompletedPhases(msg)
		tp.status = fmt.Sprintf("[%s] Running...", msg.Phase)
		return tp, nil

	case ScanDoneMsg:
		tp.scanning = false
		tp.progressPercent = 100
		if msg.Cancelled {
			tp.status = fmt.Sprintf("Stopped - %s", msg.Summary)
			if msg.ArchiveError != "" {
				tp.status = fmt.Sprintf("Stopped - %s (.akemi export failed: %s)", msg.Summary, msg.ArchiveError)
			} else if msg.ArchivePath != "" {
				tp.status = fmt.Sprintf("Stopped - %s (.akemi: %s)", msg.Summary, filepath.Base(msg.ArchivePath))
			}
		} else if msg.Error != nil {
			tp.status = fmt.Sprintf("Error: %s", msg.Error.Error())
		} else {
			tp.status = fmt.Sprintf("Done - %s", msg.Summary)
			if msg.ArchiveError != "" {
				tp.status = fmt.Sprintf("Done - %s (.akemi export failed: %s)", msg.Summary, msg.ArchiveError)
			} else if msg.ArchivePath != "" {
				tp.status = fmt.Sprintf("Done - %s (.akemi: %s)", msg.Summary, filepath.Base(msg.ArchivePath))
			}
			// Add to recent targets
			target := tp.fields[fieldTarget].value
			if target != "" {
				tp.addRecentTarget(target)
			}
		}
		return tp, nil

	case AuthCaptureStartedMsg:
		tp.status = fmt.Sprintf("Capturing auth for %s as %s...", msg.TargetURL, msg.Username)
		return tp, nil

	case AuthCaptureDoneMsg:
		if msg.Error != "" {
			tp.status = fmt.Sprintf("Auth capture failed: %s", msg.Error)
		} else if msg.Session != nil {
			status := "captured"
			if msg.Session.AuthSuccess {
				status = "authenticated"
			}
			tp.status = fmt.Sprintf("DotHound %s: %d cookies; API Hunter will reuse them", status, len(msg.Session.Cookies))
		} else {
			tp.status = "Auth capture completed without a session"
		}
		return tp, nil

	case RunSavedMsg:
		tp.scanning = false
		if msg.Error != "" {
			tp.status = fmt.Sprintf("Save failed: %s", msg.Error)
		} else {
			tp.status = fmt.Sprintf("Saved .akemi: %s", msg.Path)
		}
		return tp, nil

	case RunLoadedMsg:
		tp.scanning = false
		if msg.Error != "" {
			tp.status = fmt.Sprintf("Load failed: %s", msg.Error)
		} else if msg.Summary != "" {
			tp.status = fmt.Sprintf("Loaded .akemi: %s - %s", filepath.Base(msg.Path), msg.Summary)
		} else {
			tp.status = fmt.Sprintf("Loaded .akemi: %s", filepath.Base(msg.Path))
		}
		return tp, nil

	case TargetConfigUpdatedMsg:
		tp.applyToolConfig(msg)
		return tp, nil

	case OperationSkippedMsg:
		tp.ShowDuplicatePrompt = false
		tp.status = fmt.Sprintf("Skipped %s — using existing discoveries", msg.Operations)
		return tp, nil
	}

	if !tp.focused && !tp.inputMode && tp.pathPrompt == pathPromptNone {
		return tp, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if tp.pathPrompt != pathPromptNone {
			return tp.handlePathPrompt(msg)
		}
		if tp.inputMode {
			return tp.handleInput(msg)
		}
		return tp.handleKey(msg)

	case tea.MouseMsg:
		return tp.handleMouse(msg)
	}

	return tp, nil
}

func (tp *TargetPanel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle duplicate operation prompt first
	if tp.ShowDuplicatePrompt {
		switch msg.String() {
		case "y", "Y":
			tp.ShowDuplicatePrompt = false
			tp.status = "Repeating operation..."
			tp.ScanRequested = true
			tp.PendingConfig = tp.PendingDuplicateMsg.PendingConfig
			tp.PendingDuplicateMsg = OperationDuplicateMsg{}
			return tp, nil
		case "n", "N", "esc":
			tp.ShowDuplicatePrompt = false
			tp.status = fmt.Sprintf("Skipped %s — using existing discoveries", tp.PendingDuplicateMsg.Operation)
			tp.PendingDuplicateMsg = OperationDuplicateMsg{}
			return tp, nil
		}
		return tp, nil
	}

	switch msg.String() {
	case "tab":
		// Move focus to next panel (handled by parent)
		return tp, nil

	case "up", "k":
		if tp.cursor > 0 {
			tp.cursor--
		}

	case "down", "j":
		if tp.cursor < fieldCount-1 {
			tp.cursor++
		}

	case "left", "h":
		if tp.cursor == fieldIntent {
			tp.cycleIntent(-1)
		}

	case "right", "l":
		if tp.cursor == fieldIntent {
			tp.cycleIntent(1)
		}

	case "enter":
		if tp.cursor == fieldStart {
			// Signal parent (Dashboard) to start scan via flag
			if tp.fields[fieldTarget].value == "" {
				tp.status = "Error: Target is required"
				return tp, nil
			}
			tp.scanning = true
			tp.progressPercent = 0
			tp.progressPhase = ""
			tp.completedPhases = make(map[string]bool)
			tp.status = "Starting scan..."
			tp.ScanRequested = true
			tp.PendingConfig = tp.buildConfig()
			return tp, nil
		}
		if tp.cursor == fieldCaptureAuth {
			tp.prepareAuthCapture()
			return tp, nil
		}
		if tp.cursor == fieldSave {
			tp.openPathPrompt(pathPromptSave)
			return tp, nil
		}
		if tp.cursor == fieldLoad {
			tp.openPathPrompt(pathPromptLoad)
			return tp, nil
		}
		if tp.cursor == fieldIntent {
			tp.cycleIntent(1)
			return tp, nil
		}
		if tp.fields[tp.cursor].editable {
			tp.inputMode = true
		}

	case "esc":
		tp.inputMode = false
	}

	return tp, nil
}

func (tp *TargetPanel) handlePathPrompt(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		path := strings.TrimSpace(tp.pathInput)
		switch tp.pathPrompt {
		case pathPromptSave:
			tp.SaveRunRequested = true
			tp.PendingRunPath = path
			tp.status = "Saving run..."
			tp.closePathPrompt()
		case pathPromptLoad:
			if path == "" {
				tp.status = "Error: .akemi path is required"
				return tp, nil
			}
			tp.LoadRunRequested = true
			tp.PendingRunPath = path
			tp.status = "Loading run..."
			tp.closePathPrompt()
		}
	case "esc":
		tp.closePathPrompt()
		tp.status = "Ready - configure target and press [Start]"
	case "backspace", "ctrl+h":
		if len(tp.pathInput) > 0 {
			tp.pathInput = tp.pathInput[:len(tp.pathInput)-1]
		}
	default:
		if len(msg.Runes) > 0 {
			tp.pathInput += string(msg.Runes)
		} else if len(msg.String()) == 1 {
			tp.pathInput += msg.String()
		}
	}
	return tp, nil
}

func (tp *TargetPanel) handleInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		tp.inputMode = false
	case "esc":
		tp.inputMode = false
	case "backspace":
		if len(tp.fields[tp.cursor].value) > 0 {
			tp.fields[tp.cursor].value = tp.fields[tp.cursor].value[:len(tp.fields[tp.cursor].value)-1]
		}
	default:
		if len(msg.String()) == 1 {
			tp.fields[tp.cursor].value += msg.String()
		}
	}
	return tp, nil
}

func (tp *TargetPanel) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	switch msg.Action {
	case tea.MouseActionPress:
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			if tp.cursor > 0 {
				tp.cursor--
			}
		case tea.MouseButtonWheelDown:
			if tp.cursor < fieldCount-1 {
				tp.cursor++
			}
		case tea.MouseButtonLeft:
			// Calculate which field was clicked
			y := msg.Y - 3 // offset for border + title
			if y >= 0 && y < fieldCount {
				tp.cursor = y
				if y == fieldStart && tp.fields[fieldTarget].value != "" {
					tp.scanning = true
					tp.progressPercent = 0
					tp.progressPhase = ""
					tp.completedPhases = make(map[string]bool)
					tp.status = "Starting scan..."
					tp.ScanRequested = true
					tp.PendingConfig = tp.buildConfig()
					return tp, nil
				}
				if y == fieldCaptureAuth {
					tp.prepareAuthCapture()
					return tp, nil
				}
				if y == fieldSave {
					tp.openPathPrompt(pathPromptSave)
					return tp, nil
				}
				if y == fieldLoad {
					tp.openPathPrompt(pathPromptLoad)
					return tp, nil
				}
				if y == fieldIntent {
					tp.cycleIntent(1)
					return tp, nil
				}
				if tp.fields[y].editable {
					tp.inputMode = true
				}
			}
		}
	}
	return tp, nil
}

func (tp *TargetPanel) buildConfig() ScanConfig {
	return ScanConfig{
		Target:    tp.fields[fieldTarget].value,
		AuthURL:   tp.authURL(),
		PortRange: tp.fields[fieldPorts].value,
		Threads:   atoi(tp.fields[fieldThreads].value, 200),
		Proxy:     tp.fields[fieldProxy].value,
		Intent:    tp.intent(),
		Depth:     core.NormalizeCrawlDepth(atoi(tp.fields[fieldDepth].value, 2)),
		Timeout:   atoi(tp.fields[fieldTimeout].value, 10),
	}
}

func (tp *TargetPanel) buildArchiveConfig() ScanConfig {
	return ScanConfig{
		Target:    tp.fields[fieldTarget].value,
		AuthURL:   tp.authURL(),
		PortRange: tp.fields[fieldPorts].value,
		Threads:   atoi(tp.fields[fieldThreads].value, 200),
		Proxy:     tp.fields[fieldProxy].value,
		Intent:    tp.rawIntent(),
		Depth:     core.NormalizeCrawlDepth(atoi(tp.fields[fieldDepth].value, 2)),
		Timeout:   atoi(tp.fields[fieldTimeout].value, 10),
	}
}

func (tp *TargetPanel) applyToolConfig(msg TargetConfigUpdatedMsg) {
	cfg := msg.Config
	if cfg.Clear {
		tp.fields[fieldTarget].value = ""
		tp.fields[fieldAuthURL].value = ""
		tp.fields[fieldAuthUsername].value = ""
		tp.fields[fieldAuthPassword].value = ""
		tp.fields[fieldPorts].value = "top-1000"
		tp.fields[fieldThreads].value = "200"
		tp.fields[fieldProxy].value = ""
		tp.fields[fieldIntent].value = "quick_recon"
		tp.fields[fieldDepth].value = "2"
		tp.fields[fieldTimeout].value = "10"
		tp.status = "Cleared from tool"
		return
	}
	if strings.TrimSpace(cfg.Target) != "" {
		tp.fields[fieldTarget].value = cfg.Target
		tp.addRecentTarget(cfg.Target)
	}
	if strings.TrimSpace(cfg.Ports) != "" {
		tp.fields[fieldPorts].value = cfg.Ports
	}
	if cfg.Threads != nil && *cfg.Threads > 0 {
		tp.fields[fieldThreads].value = fmt.Sprintf("%d", *cfg.Threads)
	}
	if strings.TrimSpace(cfg.Proxy) != "" {
		tp.fields[fieldProxy].value = cfg.Proxy
	}
	if strings.TrimSpace(cfg.Intent) != "" {
		tp.fields[fieldIntent].value = cfg.Intent
	}
	if cfg.Depth != nil && *cfg.Depth > 0 {
		tp.fields[fieldDepth].value = fmt.Sprintf("%d", core.NormalizeCrawlDepth(*cfg.Depth))
	}
	if cfg.Timeout != nil && *cfg.Timeout > 0 {
		tp.fields[fieldTimeout].value = fmt.Sprintf("%d", *cfg.Timeout)
	}
	if msg.Phase != "" {
		tp.status = fmt.Sprintf("Updated from tool: %s", msg.Phase)
	} else {
		tp.status = "Updated from tool"
	}
}

func (tp *TargetPanel) prepareAuthCapture() bool {
	targetURL := tp.authURL()
	username := strings.TrimSpace(tp.fields[fieldAuthUsername].value)
	password := tp.fields[fieldAuthPassword].value
	if strings.TrimSpace(targetURL) == "" {
		tp.status = "Error: Target or Login URL is required for auth capture"
		return false
	}
	if username == "" || password == "" {
		tp.status = "Error: Auth User and Auth Pass are required"
		return false
	}
	tp.PendingAuthURL = targetURL
	tp.PendingAuthUsername = username
	tp.PendingAuthPassword = password
	tp.fields[fieldAuthPassword].value = ""
	tp.inputMode = false
	tp.status = "Starting DotHound auth capture..."
	tp.AuthCaptureRequested = true
	return true
}

func (tp *TargetPanel) authURL() string {
	if v := strings.TrimSpace(tp.fields[fieldAuthURL].value); v != "" {
		return v
	}
	return strings.TrimSpace(tp.fields[fieldTarget].value)
}

func (tp *TargetPanel) addRecentTarget(t string) {
	// Deduplicate
	for i, rt := range tp.recentTargets {
		if rt == t {
			tp.recentTargets = append(tp.recentTargets[:i], tp.recentTargets[i+1:]...)
			break
		}
	}
	tp.recentTargets = append([]string{t}, tp.recentTargets...)
	if len(tp.recentTargets) > 10 {
		tp.recentTargets = tp.recentTargets[:10]
	}
}

// =============================================================================
// Progress helpers
// =============================================================================

// calculateProgress computes the overall scan progress (0–100) based on how
// many discovery categories have reported non-zero counts.  Once a category
// becomes non-zero it is never taken away, so progress is monotonic.
func (tp *TargetPanel) calculateProgress(msg ScanProgressMsg) float64 {
	nonZero := 0
	for _, pf := range phaseCheckFields {
		if pf.present(msg) {
			nonZero++
		}
	}
	total := len(phaseCheckFields)
	if total == 0 {
		return tp.progressPercent
	}
	pct := float64(nonZero) / float64(total) * 100
	if pct > tp.progressPercent {
		return pct
	}
	return tp.progressPercent
}

// updateCompletedPhases records which discovery categories have been seen.
func (tp *TargetPanel) updateCompletedPhases(msg ScanProgressMsg) {
	for _, pf := range phaseCheckFields {
		if pf.present(msg) {
			tp.completedPhases[pf.label] = true
		}
	}
}

// renderPhaseCheckmarks returns a single-line string showing which phases are
// done (✓) and which are pending (·), styled with the purple theme.
func (tp *TargetPanel) renderPhaseCheckmarks() string {
	var parts []string
	for _, pf := range phaseCheckFields {
		if tp.completedPhases[pf.label] {
			parts = append(parts, SuccessText.Render("✓")+DimText.Render(pf.label))
		} else {
			parts = append(parts, DimText.Render("·"+pf.label))
		}
	}
	return DimText.Render("Phases: ") + strings.Join(parts, DimText.Render("  "))
}

// View renders the target panel.
func (tp *TargetPanel) View() string {
	var sb strings.Builder

	// Title
	title := PanelTitle
	if tp.focused {
		title = PanelTitleFocused
	}
	sb.WriteString(title.Render("① Target Configuration"))
	sb.WriteString("\n\n")

	// Fields
	for i, field := range tp.fields {
		prefix := "  "
		value := field.value
		displayValue := tp.displayValue(i, value)

		if i == tp.cursor {
			prefix = AccentText.Render("▶ ")
			if tp.inputMode && field.editable {
				displayValue = tp.displayValue(i, field.value) + AccentText.Render("█") // cursor
			}
		}

		if isButtonField(i) {
			// Render as button
			btnStyle := DimText
			if i == tp.cursor {
				btnStyle = HighlightRow
			}
			if tp.scanning && i == fieldStart {
				btnStyle = WarnText
				sb.WriteString(btnStyle.Render(fmt.Sprintf("  ⏳ %s", field.label)))
			} else {
				sb.WriteString(btnStyle.Render(fmt.Sprintf("  %s", field.label)))
			}
			sb.WriteString("\n")
		} else {
			label := DimText.Render(fmt.Sprintf("%-10s", field.label+":"))
			valStr := displayValue
			if i == fieldIntent {
				valStr = tp.renderIntentSelector()
			}
			if value == "" {
				valStr = DimText.Render(field.placeholder)
			}
			sb.WriteString(fmt.Sprintf("%s%s %s\n", prefix, label, valStr))
		}
	}

	sb.WriteString("\n")

	// Scan progress bar (visible only while scanning)
	if tp.scanning {
		sb.WriteString(tp.progressBar.ViewAs(tp.progressPercent / 100.0))
		sb.WriteString("\n")

		// Phase label
		if tp.progressPhase != "" {
			sb.WriteString(AccentText.Render(fmt.Sprintf("  %s", tp.progressPhase)))
			sb.WriteString("\n")
		}

		// Phase checkmarks
		sb.WriteString(tp.renderPhaseCheckmarks())
		sb.WriteString("\n\n")
	}

	if tp.pathPrompt != pathPromptNone {
		sb.WriteString(tp.renderPathPrompt())
		sb.WriteString("\n\n")
	}

	// Recent targets
	if len(tp.recentTargets) > 0 {
		sb.WriteString(DimText.Render("── Recent ──"))
		sb.WriteString("\n")
		for i, rt := range tp.recentTargets {
			if i >= 5 {
				break
			}
			sb.WriteString(DimText.Render(fmt.Sprintf("  %s\n", rt)))
		}
		sb.WriteString("\n")
	}

	// Status
	sb.WriteString(HelpText.Render(tp.status))

	return sb.String()
}

// Focused returns whether this panel has focus.
func (tp *TargetPanel) Focused() bool {
	return tp.focused
}

// Focus sets focus state.
func (tp *TargetPanel) Focus(v bool) {
	tp.focused = v
	if !v {
		tp.inputMode = false
	}
}

func (tp *TargetPanel) PathPromptActive() bool {
	return tp.pathPrompt != pathPromptNone
}

func (tp *TargetPanel) openPathPrompt(mode pathPromptMode) {
	tp.pathPrompt = mode
	tp.pathInput = ""
	tp.inputMode = false
	switch mode {
	case pathPromptSave:
		tp.status = "Enter save path, or leave blank for ~/target.akemi"
	case pathPromptLoad:
		tp.status = "Enter .akemi path to load"
	}
}

func (tp *TargetPanel) closePathPrompt() {
	tp.pathPrompt = pathPromptNone
	tp.pathInput = ""
}

func (tp *TargetPanel) cycleIntent(delta int) {
	idx := intentIndex(tp.fields[fieldIntent].value)
	next := (idx + delta + len(intentOptions)) % len(intentOptions)
	tp.fields[fieldIntent].value = intentOptions[next]
}

func (tp *TargetPanel) intent() string {
	idx := intentIndex(tp.fields[fieldIntent].value)
	tp.fields[fieldIntent].value = intentOptions[idx]
	return tp.fields[fieldIntent].value
}

func (tp *TargetPanel) renderIntentSelector() string {
	current := tp.fields[fieldIntent].value
	if strings.TrimSpace(current) == "" {
		current = tp.intent()
	}
	return HighlightRow.Render(fmt.Sprintf(" %s ", current))
}

func (tp *TargetPanel) renderPathPrompt() string {
	title := "Save Run"
	hint := "Blank = ~/target.akemi"
	if tp.pathPrompt == pathPromptLoad {
		title = "Load Run"
		hint = "Path to .akemi"
	}

	cursor := AccentText.Render("|")
	input := tp.pathInput + cursor
	if tp.pathInput == "" {
		input = DimText.Render(hint) + cursor
	}

	lines := []string{
		HighlightRow.Render(" " + title + " "),
		fmt.Sprintf("  Path: %s", input),
		HelpText.Render("  Enter: confirm  Esc: cancel"),
	}
	return strings.Join(lines, "\n")
}

func (tp *TargetPanel) rawIntent() string {
	current := strings.TrimSpace(tp.fields[fieldIntent].value)
	if current != "" {
		return current
	}
	return tp.intent()
}

func intentIndex(value string) int {
	for i, option := range intentOptions {
		if option == value {
			return i
		}
	}
	return 0
}

func isButtonField(i int) bool {
	return i == fieldCaptureAuth || i == fieldStart || i == fieldSave || i == fieldLoad
}

func (tp *TargetPanel) displayValue(field int, value string) string {
	if field != fieldAuthPassword || value == "" {
		return value
	}
	return strings.Repeat("*", len(value))
}

// =============================================================================
// Helpers
// =============================================================================

func atoi(s string, def int) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	if n <= 0 {
		return def
	}
	return n
}
