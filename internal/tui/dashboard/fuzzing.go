package dashboard

import (
	"fmt"
	"strings"
	"time"

	core "Akemi/internal/core"
	"Akemi/internal/fuzz"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// =============================================================================
// FuzzingPanel — ⚡ Fuzzing Console
// =============================================================================

// field indices for the fuzzing form
const (
	fieldFuzzURL = iota
	fieldFuzzMethod
	fieldFuzzData
	fieldFuzzWordlist
	fieldFuzzConcurrency
	fieldFuzzRepeats
	fieldFuzzStart
	fieldFuzzCount
)

// HTTP methods available in the method selector
var fuzzHTTPMethods = []string{
	"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
}

// FuzzResultMsg carries a batch of fuzzing results to the dashboard.
type FuzzResultMsg struct {
	Results []core.FuzzResult
}

// FuzzProgressMsg carries live progress counters during a fuzzing campaign.
type FuzzProgressMsg struct {
	Total   int
	Success int
	Error   int
}

// FuzzStartedMsg signals that a fuzzing campaign has begun.
type FuzzStartedMsg struct {
	URL    string
	Method string
}

// FuzzDoneMsg signals that a fuzzing campaign has completed.
type FuzzDoneMsg struct {
	Total    int
	Success  int
	Error    int
	ErrorMsg string
}

// FuzzingPanel manages the fuzzing form and result display.
type FuzzingPanel struct {
	focused bool
	width   int
	height  int

	// Form fields (stored as strings for editing)
	fuzzURL         string
	fuzzMethod      string
	fuzzData        string
	fuzzWordlist    string
	fuzzConcurrency string
	fuzzRepeats     string

	// State
	running bool
	results []core.FuzzResult

	resultViewport viewport.Model
	cursor         int // selected form row
	scrollY        int // results scroll offset

	// Stats
	totalRequests int
	successCount  int
	errorCount    int

	status      string
	inputMode   bool
	activeField int // which form field is being edited

	requestPreview string

	// Signal to parent (Dashboard) that fuzzing was requested.
	FuzzStartRequested bool
	PendingFuzzConfig  core.FuzzConfig
}

// NewFuzzingPanel creates a new fuzzing console panel.
func NewFuzzingPanel() *FuzzingPanel {
	fp := &FuzzingPanel{
		cursor:          fieldFuzzURL,
		inputMode:       false,
		status:          "Configure payloads and press [Start Fuzzing]",
		fuzzMethod:      "GET",
		fuzzConcurrency: "20",
		fuzzRepeats:     "1",
		results:         make([]core.FuzzResult, 0),
	}
	fp.resultViewport = viewport.New(40, 15)
	return fp
}

// SetSize updates the panel dimensions.
func (fp *FuzzingPanel) SetSize(w, h int) {
	fp.width = w
	fp.height = h
	fp.resultViewport.Width = w - 6
	if fp.resultViewport.Width < 20 {
		fp.resultViewport.Width = 20
	}
	// Reserve space for title, form, progress, and status
	formRows := 9 // title + 6 fields + button + gap
	progressRows := 0
	if fp.running {
		progressRows = 2
	}
	statusRows := 2
	availableH := h - formRows - progressRows - statusRows
	if availableH < 4 {
		availableH = 4
	}
	fp.resultViewport.Height = availableH
	fp.updateResultViewport()
}

// Init implements tea.Model.
func (fp *FuzzingPanel) Init() tea.Cmd {
	return nil
}

// Update handles messages for the fuzzing panel.
func (fp *FuzzingPanel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case FuzzStartedMsg:
		fp.running = true
		fp.totalRequests = 0
		fp.successCount = 0
		fp.errorCount = 0
		fp.status = fmt.Sprintf("Fuzzing %s %s...", msg.Method, msg.URL)
		return fp, nil

	case FuzzProgressMsg:
		fp.totalRequests = msg.Total
		fp.successCount = msg.Success
		fp.errorCount = msg.Error
		return fp, nil

	case FuzzResultMsg:
		fp.results = append(fp.results, msg.Results...)
		fp.updateResultViewport()
		if !fp.running {
			fp.running = true
		}
		return fp, nil

	case FuzzDoneMsg:
		fp.running = false
		fp.totalRequests = msg.Total
		fp.successCount = msg.Success
		fp.errorCount = msg.Error
		if msg.ErrorMsg != "" {
			fp.status = fmt.Sprintf("Fuzzing error: %s", msg.ErrorMsg)
		} else {
			fp.status = fmt.Sprintf("Done — %d requests, %d success, %d errors", msg.Total, msg.Success, msg.Error)
		}
		fp.updateResultViewport()
		return fp, nil
	}

	if !fp.focused && !fp.inputMode {
		return fp, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		return fp.handleKey(msg)

	case tea.MouseMsg:
		return fp.handleMouse(msg)
	}

	return fp, nil
}

func (fp *FuzzingPanel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Input mode: editing a field value
	if fp.inputMode {
		return fp.handleInput(key)
	}

	switch key {
	case "tab":
		// Next field
		fp.cursor++
		if fp.cursor >= fieldFuzzCount {
			fp.cursor = 0
		}

	case "shift+tab":
		// Previous field
		fp.cursor--
		if fp.cursor < 0 {
			fp.cursor = fieldFuzzCount - 1
		}

	case "up", "k":
		if fp.cursor > 0 {
			fp.cursor--
		}

	case "down", "j":
		if fp.cursor < fieldFuzzCount-1 {
			fp.cursor++
		}

	case "left", "h":
		// Cycle method left
		if fp.cursor == fieldFuzzMethod {
			fp.cycleMethod(-1)
		}

	case "right", "l":
		// Cycle method right
		if fp.cursor == fieldFuzzMethod {
			fp.cycleMethod(1)
		}

	case "enter":
		if fp.cursor == fieldFuzzStart {
			// Start fuzzing
			if fp.fuzzURL == "" {
				fp.status = "Error: URL is required"
				return fp, nil
			}
			if fp.fuzzWordlist == "" {
				fp.status = "Error: Wordlist path is required"
				return fp, nil
			}
			fp.running = true
			fp.results = make([]core.FuzzResult, 0)
			fp.totalRequests = 0
			fp.successCount = 0
			fp.errorCount = 0
			fp.scrollY = 0
			fp.status = "Starting fuzzing..."
			fp.FuzzStartRequested = true
			fp.PendingFuzzConfig = fp.buildConfig()
			fp.updateResultViewport()
			return fp, nil
		}
		// Start editing the field
		fp.inputMode = true
		fp.activeField = fp.cursor

	case "esc":
		fp.inputMode = false

	case "/":
		// Filter results: for now, just reset scroll
		fp.scrollY = 0
		fp.updateResultViewport()

	case "c":
		// Clear results
		fp.results = make([]core.FuzzResult, 0)
		fp.totalRequests = 0
		fp.successCount = 0
		fp.errorCount = 0
		fp.scrollY = 0
		fp.running = false
		fp.status = "Cleared — configure payloads and press [Start Fuzzing]"
		fp.updateResultViewport()
	}

	return fp, nil
}

func (fp *FuzzingPanel) handleInput(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "enter":
		fp.inputMode = false

	case "esc":
		fp.inputMode = false

	case "backspace":
		fp.deleteChar()

	default:
		// Accept printable characters
		if len(key) == 1 && key[0] >= 32 && key[0] < 127 {
			fp.appendChar(key)
		}
	}
	return fp, nil
}

func (fp *FuzzingPanel) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	switch msg.Action {
	case tea.MouseActionPress:
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			if fp.scrollY > 0 {
				fp.scrollY--
				fp.updateResultViewport()
			}
		case tea.MouseButtonWheelDown:
			if fp.scrollY < len(fp.results)-1 {
				fp.scrollY++
				fp.updateResultViewport()
			}
		case tea.MouseButtonLeft:
			// Check if click is on a form row
			y := msg.Y - 3 // offset for border + title
			if y >= 0 && y < fieldFuzzCount {
				fp.cursor = y
				if y == fieldFuzzStart && fp.fuzzURL != "" && fp.fuzzWordlist != "" {
					fp.running = true
					fp.results = make([]core.FuzzResult, 0)
					fp.totalRequests = 0
					fp.successCount = 0
					fp.errorCount = 0
					fp.scrollY = 0
					fp.status = "Starting fuzzing..."
					fp.FuzzStartRequested = true
					fp.PendingFuzzConfig = fp.buildConfig()
					fp.updateResultViewport()
					return fp, nil
				}
				if y == fieldFuzzMethod {
					fp.cycleMethod(1)
					return fp, nil
				}
				fp.inputMode = true
				fp.activeField = y
			}
		}
	}
	return fp, nil
}

func (fp *FuzzingPanel) buildConfig() core.FuzzConfig {
	return core.FuzzConfig{
		URL:         fp.fuzzURL,
		Method:      fp.method(),
		Data:        fp.fuzzData,
		PayloadFile: fp.fuzzWordlist,
		Concurrency: atoi(fp.fuzzConcurrency, 20),
		Repeats:     atoi(fp.fuzzRepeats, 1),
		Timeout:     10,
	}
}

func (fp *FuzzingPanel) method() string {
	if fp.fuzzMethod == "" {
		fp.fuzzMethod = "GET"
	}
	return fp.fuzzMethod
}

func (fp *FuzzingPanel) cycleMethod(delta int) {
	idx := methodIndex(fp.fuzzMethod)
	next := (idx + delta + len(fuzzHTTPMethods)) % len(fuzzHTTPMethods)
	fp.fuzzMethod = fuzzHTTPMethods[next]
}

func methodIndex(value string) int {
	for i, m := range fuzzHTTPMethods {
		if strings.EqualFold(m, value) {
			return i
		}
	}
	return 0
}

func (fp *FuzzingPanel) deleteChar() {
	var ptr *string
	switch fp.activeField {
	case fieldFuzzURL:
		ptr = &fp.fuzzURL
	case fieldFuzzMethod:
		ptr = &fp.fuzzMethod
	case fieldFuzzData:
		ptr = &fp.fuzzData
	case fieldFuzzWordlist:
		ptr = &fp.fuzzWordlist
	case fieldFuzzConcurrency:
		ptr = &fp.fuzzConcurrency
	case fieldFuzzRepeats:
		ptr = &fp.fuzzRepeats
	default:
		return
	}
	if len(*ptr) > 0 {
		*ptr = (*ptr)[:len(*ptr)-1]
	}
}

func (fp *FuzzingPanel) appendChar(ch string) {
	var ptr *string
	switch fp.activeField {
	case fieldFuzzURL:
		ptr = &fp.fuzzURL
	case fieldFuzzMethod:
		ptr = &fp.fuzzMethod
	case fieldFuzzData:
		ptr = &fp.fuzzData
	case fieldFuzzWordlist:
		ptr = &fp.fuzzWordlist
	case fieldFuzzConcurrency:
		ptr = &fp.fuzzConcurrency
	case fieldFuzzRepeats:
		ptr = &fp.fuzzRepeats
	default:
		return
	}
	*ptr += ch
}

// Focused returns whether this panel has focus.
func (fp *FuzzingPanel) Focused() bool {
	return fp.focused
}

// Focus sets focus state.
func (fp *FuzzingPanel) Focus(v bool) {
	fp.focused = v
	if !v {
		fp.inputMode = false
	}
}

// =============================================================================
// View
// =============================================================================

func (fp *FuzzingPanel) View() string {
	var sb strings.Builder

	// Title
	title := PanelTitle
	if fp.focused {
		title = PanelTitleFocused
	}
	sb.WriteString(title.Render("⚡ Fuzzing Console"))
	sb.WriteString("\n\n")

	// Form fields
	sb.WriteString(fp.renderForm())
	sb.WriteString("\n")

	// Progress bar when running
	if fp.running || fp.totalRequests > 0 {
		sb.WriteString(fp.renderProgress())
		sb.WriteString("\n")
	}

	// Results table
	sb.WriteString(fp.renderResults())
	sb.WriteString("\n")

	// Status line
	sb.WriteString(HelpText.Render(fp.status))

	return sb.String()
}

func (fp *FuzzingPanel) renderForm() string {
	var sb strings.Builder

	fields := []struct {
		label       string
		value       string
		placeholder string
		isButton    bool
	}{
		{"URL", fp.fuzzURL, "https://example.com/FUZZ", false},
		{"Method", fp.fuzzMethod, "GET", false},
		{"Data", fp.fuzzData, "q=FUZZ&page=1", false},
		{"Wordlist", fp.fuzzWordlist, "/path/to/wordlist.txt", false},
		{"Concurrency", fp.fuzzConcurrency, "20", false},
		{"Repeats", fp.fuzzRepeats, "1", false},
		{"", "", "", true}, // [Start Fuzzing] button
	}

	for i, f := range fields {
		prefix := "  "
		if i == fp.cursor {
			prefix = AccentText.Render("▶ ")
		}

		if i == fieldFuzzStart {
			// Render as button
			btnStyle := DimText
			if i == fp.cursor {
				btnStyle = HighlightRow
			}
			if fp.running {
				btnStyle = WarnText
				sb.WriteString(btnStyle.Render("  ⏳ [ Start Fuzzing ]"))
			} else {
				sb.WriteString(btnStyle.Render("  [ Start Fuzzing ]"))
			}
			sb.WriteString("\n")
			continue
		}

		label := DimText.Render(fmt.Sprintf("%-13s", f.label+":"))

		valStr := f.value
		if i == fieldFuzzMethod {
			valStr = fp.renderMethodSelector()
		} else if f.value == "" {
			valStr = DimText.Render(f.placeholder)
		}

		// Show cursor in input mode
		if i == fp.cursor && fp.inputMode {
			valStr = f.value + AccentText.Render("█")
		}

		sb.WriteString(fmt.Sprintf("%s%s %s\n", prefix, label, valStr))
	}

	return sb.String()
}

func (fp *FuzzingPanel) renderMethodSelector() string {
	current := fp.method()
	return HighlightRow.Render(fmt.Sprintf(" %s ", current))
}

func (fp *FuzzingPanel) renderProgress() string {
	var sb strings.Builder
	sb.WriteString(DimText.Render(strings.Repeat("─", maxInt(fp.width-4, 20))))
	sb.WriteString("\n")

	progress := fmt.Sprintf("Requests: %d | Success: %d | Error: %d",
		fp.totalRequests, fp.successCount, fp.errorCount)

	style := AccentText
	if fp.running {
		style = WarnText
	}
	sb.WriteString(style.Render(fmt.Sprintf("  %s", progress)))
	sb.WriteString("\n")
	sb.WriteString(DimText.Render(strings.Repeat("─", maxInt(fp.width-4, 20))))

	return sb.String()
}

func (fp *FuzzingPanel) renderResults() string {
	if len(fp.results) == 0 {
		if fp.running {
			return DimText.Render("  Waiting for results...")
		}
		return DimText.Render("  No results yet. Configure and start fuzzing.")
	}

	// Header
	header := DimText.Render(fmt.Sprintf("  %-6s │ %-6s │ %-6s │ %-6s │ %s",
		"Status", "Lines", "Words", "Chars", "Payload"))
	separator := DimText.Render(fmt.Sprintf("  %s┼%s┼%s┼%s┼%s",
		strings.Repeat("─", 6),
		strings.Repeat("─", 7),
		strings.Repeat("─", 7),
		strings.Repeat("─", 6),
		strings.Repeat("─", 20)))

	var sb strings.Builder
	sb.WriteString(header)
	sb.WriteString("\n")
	sb.WriteString(separator)
	sb.WriteString("\n")

	// Render visible portion of results
	start := fp.scrollY
	end := start + fp.resultViewport.Height
	if end > len(fp.results) {
		end = len(fp.results)
	}

	for i := start; i < end; i++ {
		r := fp.results[i]
		rowStyle := fp.statusStyle(r.StatusCode)

		statusStr := fmt.Sprintf("%d", r.StatusCode)
		if r.Error != "" {
			statusStr = "ERR"
			rowStyle = ErrorText
		}

		payload := r.Payload
		if len(payload) > 25 {
			payload = payload[:25] + "..."
		}

		line := fmt.Sprintf("  %-6s │ %-6d │ %-6d │ %-6d │ %s",
			statusStr, r.Lines, r.Words, r.Chars, payload)

		if i == fp.scrollY {
			line = AccentText.Render(">") + rowStyle.Render(line[1:])
		} else {
			line = rowStyle.Render(line)
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	// Scroll indicator
	if len(fp.results) > fp.resultViewport.Height {
		pct := float64(fp.scrollY) / float64(len(fp.results)-fp.resultViewport.Height) * 100
		if pct > 100 {
			pct = 100
		}
		sb.WriteString(DimText.Render(fmt.Sprintf("  ... %d/%d (%.0f%%) ...",
			fp.scrollY+1, len(fp.results), pct)))
	}

	return sb.String()
}

func (fp *FuzzingPanel) statusStyle(code int) lipgloss.Style {
	switch {
	case code >= 200 && code < 300:
		return SuccessText // green
	case code >= 300 && code < 400:
		return lipgloss.NewStyle().Foreground(Blue) // blue — redirects
	case code >= 400 && code < 500:
		return WarnText // yellow/orange — client errors
	case code >= 500:
		return ErrorText // red — server errors
	default:
		return DimText
	}
}

func (fp *FuzzingPanel) updateResultViewport() {
	var sb strings.Builder

	if len(fp.results) == 0 {
		if fp.running {
			sb.WriteString(DimText.Render("  Waiting for results..."))
		} else {
			sb.WriteString(DimText.Render("  No results yet. Configure and start fuzzing."))
		}
		fp.resultViewport.SetContent(sb.String())
		return
	}

	header := fmt.Sprintf("  %-6s │ %-6s │ %-6s │ %-6s │ %s",
		"Status", "Lines", "Words", "Chars", "Payload")
	separator := fmt.Sprintf("  %s┼%s┼%s┼%s┼%s",
		strings.Repeat("─", 6),
		strings.Repeat("─", 7),
		strings.Repeat("─", 7),
		strings.Repeat("─", 6),
		strings.Repeat("─", 20))
	sb.WriteString(header)
	sb.WriteString("\n")
	sb.WriteString(separator)
	sb.WriteString("\n")

	start := fp.scrollY
	end := start + fp.resultViewport.Height
	if end > len(fp.results) {
		end = len(fp.results)
	}

	for i := start; i < end; i++ {
		r := fp.results[i]

		statusStr := fmt.Sprintf("%d", r.StatusCode)
		if r.Error != "" {
			statusStr = "ERR"
		}

		payload := r.Payload
		if len(payload) > 25 {
			payload = payload[:25] + "..."
		}

		line := fmt.Sprintf("  %-6s │ %-6d │ %-6d │ %-6d │ %s",
			statusStr, r.Lines, r.Words, r.Chars, payload)
		if i == fp.scrollY {
			line = AccentText.Render(">") + line[1:]
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	if len(fp.results) > fp.resultViewport.Height {
		pct := float64(fp.scrollY) / float64(len(fp.results)-fp.resultViewport.Height) * 100
		if pct > 100 {
			pct = 100
		}
		sb.WriteString(DimText.Render(fmt.Sprintf("  ... %d/%d (%.0f%%) ...",
			fp.scrollY+1, len(fp.results), pct)))
	}

	fp.resultViewport.SetContent(sb.String())
}

// Summary returns a one-line summary.
func (fp *FuzzingPanel) Summary() string {
	if fp.running {
		return fmt.Sprintf("Fuzzing: %d req, %d ok, %d err", fp.totalRequests, fp.successCount, fp.errorCount)
	}
	if fp.totalRequests > 0 {
		return fmt.Sprintf("Fuzz done: %d req, %d ok, %d err", fp.totalRequests, fp.successCount, fp.errorCount)
	}
	return "Fuzzing idle"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// fuzzRun wraps the legacy fuzzer for the dashboard command loop.
// It is called from Dashboard.runFuzzCmd in a tea.Cmd goroutine.
func fuzzRun(cfg core.FuzzConfig) ([]core.FuzzResult, time.Duration, error) {
	return fuzz.RunFuzzer(cfg)
}
