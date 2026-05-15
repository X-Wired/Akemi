package dashboard

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"Akemi/internal/assistant"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// runIDCounter provides unique IDs for tool runs.
var runIDCounter atomic.Uint64

func nextRunID() string {
	return fmt.Sprintf("run-%d", runIDCounter.Add(1))
}

// =============================================================================
// ToolRunState
// =============================================================================

// ToolRunState captures the lifecycle state of a single tool execution.
type ToolRunState struct {
	ID               string
	ToolName         string
	ServerName       string
	NativeName       string
	ArgumentsSummary string
	Status           string // "requested", "running", "completed", "failed", "denied"
	StartTime        time.Time
	EndTime          time.Time
	ResultText       string
	ResultFindings   []string
	ErrorText        string
	ApprovalRequired bool
}

// DisplayName returns the most specific tool name available.
func (r *ToolRunState) DisplayName() string {
	return firstNonEmptyStr(r.ToolName, r.NativeName, r.ServerName, "tool")
}

// Duration returns the elapsed or total duration.
func (r *ToolRunState) Duration() time.Duration {
	if r.StartTime.IsZero() {
		return 0
	}
	if r.EndTime.IsZero() {
		return time.Since(r.StartTime)
	}
	return r.EndTime.Sub(r.StartTime)
}

// IsTerminal reports whether the run has reached a final state.
func (r *ToolRunState) IsTerminal() bool {
	switch r.Status {
	case "completed", "failed", "denied":
		return true
	default:
		return false
	}
}

// =============================================================================
// ToolExecutionView
// =============================================================================

const maxToolRuns = 10
const maxVisibleRuns = 6

// ToolExecutionView renders a split-pane visualization of running and completed
// tool calls for embedding inside the agent panel.
type ToolExecutionView struct {
	focused        bool
	width          int
	height         int
	activeRuns     []ToolRunState
	selectedRun    int
	detailExpanded bool
	viewport       viewport.Model
}

// NewToolExecutionView creates an initialized ToolExecutionView.
func NewToolExecutionView() *ToolExecutionView {
	vp := viewport.New(40, 10)
	vp.Style = lipgloss.NewStyle().Padding(0, 1)
	return &ToolExecutionView{
		activeRuns:  make([]ToolRunState, 0, maxToolRuns),
		selectedRun: -1,
		viewport:    vp,
	}
}

// AllRuns returns all tool runs (terminal and active).
func (tv *ToolExecutionView) AllRuns() []ToolRunState {
	return tv.activeRuns
}

// ActiveRuns returns the number of active (non-terminal) tool runs.
func (tv *ToolExecutionView) ActiveRuns() int {
	count := 0
	for _, r := range tv.activeRuns {
		if !r.IsTerminal() {
			count++
		}
	}
	return count
}

// Init implements tea.Model.
func (tv *ToolExecutionView) Init() tea.Cmd {
	return nil
}

// SetSize updates the dimensions of the view and its viewport.
func (tv *ToolExecutionView) SetSize(w, h int) {
	tv.width = w
	tv.height = h
	tv.viewport.Width = w - 4
	if tv.viewport.Width < 10 {
		tv.viewport.Width = 10
	}
	// Reserve space for: title(1) + separator(1) + run rows (max 6) +
	// detail separator(1) + detail header(1) + info lines(6) + result header(1) +
	// footer hints(1) + padding(2).
	tv.viewport.Height = h - 1 - 1 - maxVisibleRuns - 1 - 1 - 6 - 1 - 1 - 2
	if tv.viewport.Height < 3 {
		tv.viewport.Height = 3
	}
}

// Focus sets the view as focused.
func (tv *ToolExecutionView) Focus() {
	tv.focused = true
}

// Blur sets the view as unfocused.
func (tv *ToolExecutionView) Blur() {
	tv.focused = false
}

// AddRun adds a new tool run or updates an existing one by ID.
func (tv *ToolExecutionView) AddRun(run ToolRunState) {
	if run.ID == "" {
		run.ID = nextRunID()
	}
	if run.StartTime.IsZero() {
		run.StartTime = time.Now()
	}

	// Update existing run by ID.
	for i := range tv.activeRuns {
		if tv.activeRuns[i].ID == run.ID {
			tv.activeRuns[i] = run
			return
		}
	}

	// Append new run.
	tv.activeRuns = append(tv.activeRuns, run)
	if len(tv.activeRuns) > maxToolRuns {
		tv.activeRuns = tv.activeRuns[len(tv.activeRuns)-maxToolRuns:]
	}
	if tv.selectedRun < 0 {
		tv.selectedRun = len(tv.activeRuns) - 1
	}
}

// findMatchingRun finds the most recent non-terminal run matching the tool
// identity from a ToolRunInfo, or returns -1.
func (tv *ToolExecutionView) findMatchingRun(info *assistant.ToolRunInfo) int {
	if info == nil {
		return -1
	}
	for i := len(tv.activeRuns) - 1; i >= 0; i-- {
		r := tv.activeRuns[i]
		if r.ToolName == info.ToolName &&
			r.ServerName == info.ServerName &&
			r.NativeName == info.NativeName &&
			!r.IsTerminal() {
			return i
		}
	}
	return -1
}

// findOrCreateRun locates a matching non-terminal run or creates a new one.
func (tv *ToolExecutionView) findOrCreateRun(info *assistant.ToolRunInfo) *ToolRunState {
	idx := tv.findMatchingRun(info)
	if idx >= 0 {
		return &tv.activeRuns[idx]
	}
	run := ToolRunState{
		ID:               nextRunID(),
		ToolName:         info.ToolName,
		ServerName:       info.ServerName,
		NativeName:       info.NativeName,
		ArgumentsSummary: info.ArgumentsSummary,
		Status:           info.Status,
		StartTime:        time.Now(),
	}
	tv.AddRun(run)
	// The run was just appended; find it.
	for i := len(tv.activeRuns) - 1; i >= 0; i-- {
		if tv.activeRuns[i].ID == run.ID {
			return &tv.activeRuns[i]
		}
	}
	return &tv.activeRuns[len(tv.activeRuns)-1]
}

// UpdateRun updates the status of an existing run from a ToolRunInfo.
func (tv *ToolExecutionView) UpdateRun(info assistant.ToolRunInfo) {
	idx := tv.findMatchingRun(&info)
	if idx >= 0 {
		tv.activeRuns[idx].Status = info.Status
		tv.activeRuns[idx].ArgumentsSummary = info.ArgumentsSummary
		return
	}
	// Create a new run if none matches.
	run := ToolRunState{
		ID:               nextRunID(),
		ToolName:         info.ToolName,
		ServerName:       info.ServerName,
		NativeName:       info.NativeName,
		ArgumentsSummary: info.ArgumentsSummary,
		Status:           info.Status,
		StartTime:        time.Now(),
	}
	tv.AddRun(run)
}

// CompleteRun marks a matching run as completed with result text and findings.
func (tv *ToolExecutionView) CompleteRun(info assistant.ToolRunInfo, resultText string, findings []string) {
	idx := tv.findMatchingRun(&info)
	if idx >= 0 {
		tv.activeRuns[idx].Status = "completed"
		tv.activeRuns[idx].EndTime = time.Now()
		tv.activeRuns[idx].ResultText = resultText
		tv.activeRuns[idx].ResultFindings = findings
		tv.activeRuns[idx].ErrorText = ""
		return
	}
	// Create a completed run.
	run := ToolRunState{
		ID:               nextRunID(),
		ToolName:         info.ToolName,
		ServerName:       info.ServerName,
		NativeName:       info.NativeName,
		ArgumentsSummary: info.ArgumentsSummary,
		Status:           "completed",
		StartTime:        time.Now(),
		EndTime:          time.Now(),
		ResultText:       resultText,
		ResultFindings:   findings,
	}
	tv.AddRun(run)
}

// FailRun marks a matching run as failed with an error message.
func (tv *ToolExecutionView) FailRun(info assistant.ToolRunInfo, errText string) {
	idx := tv.findMatchingRun(&info)
	if idx >= 0 {
		tv.activeRuns[idx].Status = "failed"
		tv.activeRuns[idx].EndTime = time.Now()
		tv.activeRuns[idx].ErrorText = errText
		return
	}
	run := ToolRunState{
		ID:               nextRunID(),
		ToolName:         info.ToolName,
		ServerName:       info.ServerName,
		NativeName:       info.NativeName,
		ArgumentsSummary: info.ArgumentsSummary,
		Status:           "failed",
		StartTime:        time.Now(),
		EndTime:          time.Now(),
		ErrorText:        errText,
	}
	tv.AddRun(run)
}

// =============================================================================
// Update (tea.Model)
// =============================================================================

// Update handles messages. It returns itself because ToolExecutionView is not
// a standalone tea.Model — it is embedded. The caller forwards messages here.
func (tv *ToolExecutionView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case AIToolRunMsg:
		if msg.ToolRun != nil {
			run := tv.findOrCreateRun(msg.ToolRun)
			run.Status = msg.ToolRun.Status
			run.ArgumentsSummary = msg.ToolRun.ArgumentsSummary
			if msg.ToolRun.Status == "requested" {
				run.ApprovalRequired = true
			}
		}

	case AIToolResultMsg:
		// Complete the most recent non-terminal run.
		for i := len(tv.activeRuns) - 1; i >= 0; i-- {
			if !tv.activeRuns[i].IsTerminal() {
				tv.activeRuns[i].Status = "completed"
				tv.activeRuns[i].EndTime = time.Now()
				tv.activeRuns[i].ResultText = msg.Text
				break
			}
		}

	case AIApprovalRequiredMsg:
		if msg.ToolRun != nil {
			run := tv.findOrCreateRun(msg.ToolRun)
			run.Status = "requested"
			run.ApprovalRequired = true
			run.ArgumentsSummary = msg.ToolRun.ArgumentsSummary
		}
		if msg.Pending != nil {
			// Also create/update from the pending approval's tool-run view.
			tr := msg.Pending.ToolRun("requested")
			if tr != nil {
				run := tv.findOrCreateRun(tr)
				run.ApprovalRequired = true
			}
		}

	case tea.KeyMsg:
		return tv.handleKey(msg)

	case tea.MouseMsg:
		tv.handleMouse(msg)
	}

	return tv, nil
}

func (tv *ToolExecutionView) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if len(tv.activeRuns) == 0 {
		return tv, nil
	}

	switch msg.String() {
	case "up", "k":
		if tv.selectedRun > 0 {
			tv.selectedRun--
		}
	case "down", "j":
		if tv.selectedRun < len(tv.activeRuns)-1 {
			tv.selectedRun++
		}
	case "enter":
		tv.detailExpanded = !tv.detailExpanded
	case "tab":
		// Let parent handle focus change.
		return tv, nil
	}

	// If the detail pane is visible, support scrolling the viewport.
	if tv.detailExpanded && tv.selectedRun >= 0 && tv.selectedRun < len(tv.activeRuns) {
		var cmd tea.Cmd
		tv.viewport, cmd = tv.viewport.Update(msg)
		return tv, cmd
	}

	return tv, nil
}

func (tv *ToolExecutionView) handleMouse(msg tea.MouseMsg) {
	if msg.Action != tea.MouseActionPress {
		return
	}
	if msg.Button != tea.MouseButtonLeft {
		return
	}

	// Calculate which run row was clicked.
	// Layout: title (1) + separator (1) + run rows.
	headerLines := 2
	rowY := msg.Y - headerLines
	// Account for the visible window (last maxVisibleRuns runs).
	visibleStart := 0
	if len(tv.activeRuns) > maxVisibleRuns {
		visibleStart = len(tv.activeRuns) - maxVisibleRuns
	}
	if rowY >= 0 && rowY < maxVisibleRuns {
		idx := visibleStart + rowY
		if idx < len(tv.activeRuns) {
			tv.selectedRun = idx
		}
	}

	// Forward scroll events to viewport when detail is expanded.
	if tv.detailExpanded {
		tv.viewport, _ = tv.viewport.Update(msg)
	}
}

// =============================================================================
// View
// =============================================================================

// View renders the tool execution panel.
func (tv *ToolExecutionView) View() string {
	if tv.width <= 0 {
		tv.width = 40
	}
	if tv.height <= 0 {
		tv.height = 15
	}

	var sb strings.Builder

	// Title.
	titleStyle := PanelTitle
	if tv.focused {
		titleStyle = PanelTitleFocused
	}
	sb.WriteString(titleStyle.Render("🔧 Tool Execution"))
	sb.WriteByte('\n')

	// Separator.
	sep := strings.Repeat("─", tv.width)
	sb.WriteString(DimText.Render(sep))
	sb.WriteByte('\n')

	if len(tv.activeRuns) == 0 {
		sb.WriteString(DimText.Render("  No tool executions yet"))
		sb.WriteByte('\n')
		return sb.String()
	}

	// Render run list (up to maxVisibleRuns).
	visibleStart := 0
	visibleCount := len(tv.activeRuns)
	if visibleCount > maxVisibleRuns {
		visibleStart = visibleCount - maxVisibleRuns
		visibleCount = maxVisibleRuns
	}
	for i := 0; i < visibleCount; i++ {
		idx := visibleStart + i
		selected := idx == tv.selectedRun
		sb.WriteString(tv.renderRunRow(tv.activeRuns[idx], selected))
		sb.WriteByte('\n')
	}

	// Detail pane.
	if tv.detailExpanded && tv.selectedRun >= 0 && tv.selectedRun < len(tv.activeRuns) {
		sb.WriteString(tv.renderDetailPane(tv.activeRuns[tv.selectedRun]))
	}

	return sb.String()
}

// =============================================================================
// Row rendering
// =============================================================================

func (tv *ToolExecutionView) renderRunRow(run ToolRunState, selected bool) string {
	// Status icon.
	icon, iconStyle := statusIcon(run)

	// Tool name.
	name := truncate(run.DisplayName(), 20)

	// Arguments summary (truncated).
	args := truncate(run.ArgumentsSummary, 40)
	if args == "" {
		args = "{}"
	}

	// Duration or status text.
	durText := statusSuffix(run)

	// Build the row.
	iconStr := iconStyle.Render(icon)
	nameStr := AccentText.Render(name)
	argsStr := DimText.Render(args)
	durStr := DimText.Render(durText)

	// Spacing.
	gap := " "

	row := iconStr + gap + nameStr + gap + argsStr + gap + durStr

	// Pad to width.
	row = lipgloss.NewStyle().Width(tv.width).Render(row)

	// Highlight if selected.
	if selected {
		row = HighlightRow.Render(row)
	}

	return row
}

// =============================================================================
// Detail pane rendering
// =============================================================================

func (tv *ToolExecutionView) renderDetailPane(run ToolRunState) string {
	var sb strings.Builder

	// Separator.
	sep := strings.Repeat("─", tv.width)
	sb.WriteString(DimText.Render(sep))
	sb.WriteByte('\n')

	// Header.
	sb.WriteString(AccentText.Render("  📋 Details"))
	sb.WriteByte('\n')

	// Tool identity.
	name := run.DisplayName()
	sb.WriteString(fmt.Sprintf("  Tool:    %s\n", AccentText.Render(name)))
	if run.ServerName != "" {
		sb.WriteString(fmt.Sprintf("  Server:  %s\n", DimText.Render(run.ServerName)))
	}
	if run.NativeName != "" && run.NativeName != run.ToolName {
		sb.WriteString(fmt.Sprintf("  Native:  %s\n", DimText.Render(run.NativeName)))
	}

	// Arguments.
	if run.ArgumentsSummary != "" {
		sb.WriteString(fmt.Sprintf("  Args:    %s\n", DimText.Render(run.ArgumentsSummary)))
	}

	// Status with color.
	_, iconStyle := statusIcon(run)
	statusLabel := run.Status
	if run.ApprovalRequired && run.Status == "requested" {
		statusLabel = "awaiting approval"
	}
	statusText := fmt.Sprintf("  Status:  %s", iconStyle.Render(statusLabel))
	dur := run.Duration()
	if dur > 0 {
		statusText += DimText.Render(fmt.Sprintf("  (%s)", dur.Round(time.Millisecond).String()))
	}
	sb.WriteString(statusText)
	sb.WriteByte('\n')

	// Error.
	if run.ErrorText != "" {
		sb.WriteString(ErrorText.Render(fmt.Sprintf("  Error:   %s", run.ErrorText)))
		sb.WriteByte('\n')
	}

	// Findings.
	if len(run.ResultFindings) > 0 {
		sb.WriteString(AccentText.Render("  Findings:"))
		sb.WriteByte('\n')
		for _, f := range run.ResultFindings {
			sb.WriteString(fmt.Sprintf("    • %s\n", DimText.Render(f)))
		}
	}

	// Result text (scrolled via viewport).
	if run.ResultText != "" {
		sb.WriteString(DimText.Render("  ── Result ──"))
		sb.WriteByte('\n')
		truncated := run.ResultText
		if len(truncated) > 500 {
			truncated = truncated[:500] + "..."
		}
		tv.viewport.SetContent(truncated)
		sb.WriteString(tv.viewport.View())
		sb.WriteByte('\n')
	}

	// Footer hints.
	sb.WriteString(DimText.Render("  Enter: collapse  |  R: re-run"))
	sb.WriteByte('\n')

	return sb.String()
}

// =============================================================================
// Helpers
// =============================================================================

func statusIcon(run ToolRunState) (string, lipgloss.Style) {
	if run.ApprovalRequired && run.Status == "requested" {
		return "⏸", AccentText
	}
	switch run.Status {
	case "running":
		return "⏳", WarnText
	case "completed":
		return "✅", SuccessText
	case "failed":
		return "❌", ErrorText
	case "denied":
		return "🚫", ErrorText
	case "requested":
		return "⏸", AccentText
	default:
		return "•", DimText
	}
}

func statusSuffix(run ToolRunState) string {
	dur := run.Duration()
	switch run.Status {
	case "running":
		if dur > 0 {
			return dur.Round(time.Millisecond).String()
		}
		return "running"
	case "completed":
		if dur > 0 {
			return dur.Round(time.Millisecond).String()
		}
		return "done"
	case "failed":
		return "failed"
	case "denied":
		return "denied"
	case "requested":
		return "awaiting approval"
	default:
		return run.Status
	}
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
