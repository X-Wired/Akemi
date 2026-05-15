package dashboard

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// =============================================================================
// HuntTaskState
// =============================================================================

// HuntTaskState tracks the lifecycle of a single hunt-mode task through
// pending → running → completed/failed/denied.
type HuntTaskState struct {
	Task       AutonomyTask
	Status     string // "pending", "running", "completed", "failed", "denied"
	StartTime  time.Time
	EndTime    time.Time
	ResultText string
	ErrorText  string
	Findings   []string
}

// =============================================================================
// HuntPanel — ⚔️ Hunt Mode
// =============================================================================

// Tab constants
const (
	huntTabPending   = 0
	huntTabRunning   = 1
	huntTabCompleted = 2
	huntTabFailed    = 3
)

// HuntPanel shows a queue of auto-generated tasks the agent wants to execute.
// The operator can see what's pending, running, and completed, and can
// approve or deny tasks with single keystrokes.
type HuntPanel struct {
	focused bool
	width   int
	height  int

	controller *AutonomyController

	pendingTasks   []AutonomyTask  // awaiting approval
	runningTasks   []HuntTaskState // currently executing
	completedTasks []HuntTaskState // done
	failedTasks    []HuntTaskState // failed

	selectedIdx    int
	activeTab      int // 0=Pending, 1=Running, 2=Completed, 3=Failed
	detailExpanded bool
	viewport       viewport.Model
	scrollY        int
	status         string

	// Counters
	totalApproved  int
	totalDenied    int
	totalCompleted int
	totalFindings  int

	// Signals to parent (Dashboard)
	ApproveRequested bool
	DenyRequested    bool
	PendingTask      AutonomyTask

	// Mouse tracking for click-to-select
	lastClickY int
}

// =============================================================================
// Constructor
// =============================================================================

// NewHuntPanel creates a new HuntPanel wired to an AutonomyController.
func NewHuntPanel(controller *AutonomyController) *HuntPanel {
	hp := &HuntPanel{
		controller:     controller,
		pendingTasks:   make([]AutonomyTask, 0),
		runningTasks:   make([]HuntTaskState, 0),
		completedTasks: make([]HuntTaskState, 0),
		failedTasks:    make([]HuntTaskState, 0),
		activeTab:      huntTabPending,
		status:         "Ready — switch to Hunt mode to auto-queue tasks",
	}
	hp.viewport = viewport.New(40, 15)
	return hp
}

// =============================================================================
// Sizing
// =============================================================================

// SetSize updates the panel dimensions and recalculates viewport bounds.
func (hp *HuntPanel) SetSize(w, h int) {
	hp.width = w
	hp.height = h
	hp.viewport.Width = w - 6
	hp.viewport.Height = h - 11
	if hp.viewport.Width < 10 {
		hp.viewport.Width = 10
	}
	if hp.viewport.Height < 3 {
		hp.viewport.Height = 3
	}
	hp.updateViewport()
}

// =============================================================================
// tea.Model Implementation
// =============================================================================

// Init implements tea.Model.
func (hp *HuntPanel) Init() tea.Cmd {
	return nil
}

// Update handles messages and user input.
func (hp *HuntPanel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return hp.handleKey(msg)

	case tea.MouseMsg:
		return hp.handleMouse(msg)

	case DiscoveryItemMsg:
		// Feed discovery to controller; if in Hunt mode, it creates tasks.
		if hp.controller != nil {
			hp.controller.ProcessDiscovery(nil, msg)
			hp.syncPendingFromController()
		}
		hp.updateViewport()
		return hp, nil

	case AutonomyTaskRequestMsg:
		hp.addPendingTask(msg.Task)
		hp.updateViewport()
		return hp, nil

	case AIToolRunMsg:
		hp.onToolRun(msg.ToolRun)
		hp.updateViewport()
		return hp, nil

	case AIToolResultMsg:
		hp.onToolResult(msg.Text)
		hp.updateViewport()
		return hp, nil
	}

	return hp, nil
}

// =============================================================================
// Focus
// =============================================================================

// Focused returns whether the panel currently has focus.
func (hp *HuntPanel) Focused() bool {
	return hp.focused
}

// Focus sets the panel's focus state.
func (hp *HuntPanel) Focus(v bool) {
	hp.focused = v
}

// =============================================================================
// Public API — Task Management
// =============================================================================

// addPendingTask appends an AutonomyTask to the pending queue, deduplicating
// by task ID.
func (hp *HuntPanel) addPendingTask(task AutonomyTask) {
	for _, t := range hp.pendingTasks {
		if t.ID == task.ID {
			return // already queued
		}
	}
	hp.pendingTasks = append(hp.pendingTasks, task)
}

// approveTask approves the pending task at idx and signals the parent.
func (hp *HuntPanel) approveTask(idx int) {
	if idx < 0 || idx >= len(hp.pendingTasks) {
		return
	}
	task := hp.pendingTasks[idx]
	hp.pendingTasks = append(hp.pendingTasks[:idx], hp.pendingTasks[idx+1:]...)
	hp.PendingTask = task
	hp.ApproveRequested = true
	hp.totalApproved++

	// Move to running queue
	state := HuntTaskState{
		Task:      task,
		Status:    "running",
		StartTime: time.Now(),
	}
	hp.runningTasks = append(hp.runningTasks, state)

	if hp.selectedIdx >= len(hp.pendingTasks) && hp.selectedIdx > 0 {
		hp.selectedIdx = len(hp.pendingTasks) - 1
	}
}

// denyTask denies the pending task at idx and removes it.
func (hp *HuntPanel) denyTask(idx int) {
	if idx < 0 || idx >= len(hp.pendingTasks) {
		return
	}
	task := hp.pendingTasks[idx]
	hp.pendingTasks = append(hp.pendingTasks[:idx], hp.pendingTasks[idx+1:]...)
	hp.PendingTask = task
	hp.DenyRequested = true
	hp.totalDenied++

	// Add to completed as denied
	state := HuntTaskState{
		Task:    task,
		Status:  "denied",
		EndTime: time.Now(),
	}
	hp.completedTasks = append(hp.completedTasks, state)

	if hp.selectedIdx >= len(hp.pendingTasks) && hp.selectedIdx > 0 {
		hp.selectedIdx = len(hp.pendingTasks) - 1
	}
}

// approveAllTasks approves every task in the pending queue.
func (hp *HuntPanel) approveAllTasks() {
	for i := len(hp.pendingTasks) - 1; i >= 0; i-- {
		hp.approveTask(i)
	}
}

// denyAllTasks denies every task in the pending queue.
func (hp *HuntPanel) denyAllTasks() {
	for i := len(hp.pendingTasks) - 1; i >= 0; i-- {
		hp.denyTask(i)
	}
}

// reRunFailedTask re-queues a failed task back to pending.
func (hp *HuntPanel) reRunFailedTask(idx int) {
	if idx < 0 || idx >= len(hp.failedTasks) {
		return
	}
	state := hp.failedTasks[idx]
	hp.failedTasks = append(hp.failedTasks[:idx], hp.failedTasks[idx+1:]...)

	// Reset and re-add to pending
	task := state.Task
	task.AutoApproved = true // auto-approve on re-run
	hp.pendingTasks = append(hp.pendingTasks, task)
	hp.status = fmt.Sprintf("Re-queued failed task: %s", task.ToolName)
}

// syncPendingFromController pulls pending tasks from the AutonomyController.
func (hp *HuntPanel) syncPendingFromController() {
	if hp.controller == nil {
		return
	}
	// Process auto-approved tasks — they go straight to running
	autoTasks := hp.controller.AutoApprovedTasks()
	for _, t := range autoTasks {
		state := HuntTaskState{
			Task:      t,
			Status:    "running",
			StartTime: time.Now(),
		}
		hp.runningTasks = append(hp.runningTasks, state)
		hp.totalApproved++
	}
	hp.controller.ClearTasks()

	// Remaining tasks need approval
	needsApproval := hp.controller.PendingApprovalTasks()
	for _, t := range needsApproval {
		hp.addPendingTask(t)
	}
}

// =============================================================================
// Tool Lifecycle Callbacks
// =============================================================================

// onToolRun moves a task from pending→running.
func (hp *HuntPanel) onToolRun(info interface{}) {
	// Try to extract tool name from the run info
	var toolName string
	if tr, ok := info.(*struct {
		ToolName         string
		ServerName       string
		NativeName       string
		ArgumentsSummary string
		Status           string
	}); ok && tr != nil {
		toolName = tr.ToolName
	}

	if toolName == "" {
		return
	}

	// Check waiting tasks
	for i, t := range hp.pendingTasks {
		if t.ToolName == toolName {
			state := HuntTaskState{
				Task:      t,
				Status:    "running",
				StartTime: time.Now(),
			}
			hp.runningTasks = append(hp.runningTasks, state)
			hp.pendingTasks = append(hp.pendingTasks[:i], hp.pendingTasks[i+1:]...)
			hp.totalApproved++
			return
		}
	}
}

// onToolResult moves a task from running→completed or running→failed.
func (hp *HuntPanel) onToolResult(resultText string) {
	if len(hp.runningTasks) == 0 {
		return
	}

	// Assume the oldest running task completed
	state := hp.runningTasks[0]
	hp.runningTasks = hp.runningTasks[1:]

	state.EndTime = time.Now()
	state.ResultText = resultText

	lower := strings.ToLower(resultText)
	if strings.Contains(lower, "error") || strings.Contains(lower, "fail") || strings.Contains(lower, "timeout") {
		state.Status = "failed"
		state.ErrorText = resultText
		hp.failedTasks = append(hp.failedTasks, state)
	} else {
		state.Status = "completed"
		hp.completedTasks = append(hp.completedTasks, state)
		hp.totalCompleted++
	}

	// Extract findings-like data from result
	if strings.Contains(lower, "vulnerab") || strings.Contains(lower, "finding") || strings.Contains(lower, "exposed") {
		hp.totalFindings++
		state.Findings = append(state.Findings, resultText)
	}
}

// =============================================================================
// Status Icons & Badges
// =============================================================================

// taskStatusIcon returns a single-character status icon for a given state.
func (hp *HuntPanel) taskStatusIcon(status string) string {
	switch status {
	case "pending":
		return "⏳"
	case "running":
		return "▶"
	case "completed":
		return "✅"
	case "failed":
		return "❌"
	case "denied":
		return "🚫"
	default:
		return "•"
	}
}

// riskBadge returns a colored risk-level badge string.
func (hp *HuntPanel) riskBadge(level string) string {
	switch strings.ToLower(level) {
	case "intrusive":
		return ErrorText.Render("[intrusive]")
	case "active":
		return WarnText.Render("[active]")
	case "passive":
		return SuccessText.Render("[passive]")
	case "safe":
		return DimText.Render("[safe]")
	default:
		return DimText.Render("[" + level + "]")
	}
}

// toolRiskLevel returns a risk classification for a known tool name.
func toolRiskLevel(toolName string) string {
	switch toolName {
	case "akemi_port_scan", "akemi_probe_vulns", "akemi_fuzz_params",
		"akemi_check_exploitdb", "akemi_brute_force":
		return "intrusive"
	case "akemi_crawl", "akemi_probe_api", "akemi_test_injection",
		"akemi_test_auth_bypass", "akemi_check_default_creds",
		"akemi_validate_secret":
		return "active"
	default:
		return "passive"
	}
}

// =============================================================================
// Key Handling
// =============================================================================

func (hp *HuntPanel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	switch key {
	case "up", "k":
		if hp.selectedIdx > 0 {
			hp.selectedIdx--
		}
		hp.detailExpanded = false
		hp.updateViewport()
		return hp, nil

	case "down", "j":
		maxIdx := hp.currentTabCount() - 1
		if hp.selectedIdx < maxIdx {
			hp.selectedIdx++
		}
		hp.detailExpanded = false
		hp.updateViewport()
		return hp, nil

	case "left", "h":
		if hp.activeTab > 0 {
			hp.activeTab--
			hp.selectedIdx = 0
			hp.detailExpanded = false
			hp.updateViewport()
		}
		return hp, nil

	case "right", "l":
		if hp.activeTab < 3 {
			hp.activeTab++
			hp.selectedIdx = 0
			hp.detailExpanded = false
			hp.updateViewport()
		}
		return hp, nil

	case "enter":
		hp.detailExpanded = !hp.detailExpanded
		hp.updateViewport()
		return hp, nil

	case "a":
		if hp.activeTab == huntTabPending && len(hp.pendingTasks) > 0 {
			hp.approveTask(hp.selectedIdx)
			hp.updateViewport()
		}
		return hp, nil

	case "d":
		if hp.activeTab == huntTabPending && len(hp.pendingTasks) > 0 {
			hp.denyTask(hp.selectedIdx)
			hp.updateViewport()
		}
		return hp, nil

	case "A":
		hp.approveAllTasks()
		hp.updateViewport()
		return hp, nil

	case "D":
		hp.denyAllTasks()
		hp.updateViewport()
		return hp, nil

	case "r":
		if hp.activeTab == huntTabFailed && len(hp.failedTasks) > 0 {
			hp.reRunFailedTask(hp.selectedIdx)
			hp.updateViewport()
		}
		return hp, nil

	case "tab":
		// Pass through to parent — return unchanged so Dashboard can cycle focus.
		return hp, nil
	}

	return hp, nil
}

// =============================================================================
// Mouse Handling
// =============================================================================

func (hp *HuntPanel) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	switch msg.Action {
	case tea.MouseActionPress:
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			hp.scrollUp(3)
			return hp, nil

		case tea.MouseButtonWheelDown:
			hp.scrollDown(3)
			return hp, nil

		case tea.MouseButtonLeft:
			// Click inside content area — select the row under the cursor
			contentY := msg.Y - 4 // offset for header + tabs + divider
			if contentY >= 0 {
				idx := contentY + hp.scrollY
				count := hp.currentTabCount()
				if idx >= 0 && idx < count {
					hp.selectedIdx = idx
					hp.updateViewport()
				}
			}
			hp.lastClickY = msg.Y
			return hp, nil
		}
	}

	return hp, nil
}

// =============================================================================
// Viewport Helpers
// =============================================================================

func (hp *HuntPanel) updateViewport() {
	var sb strings.Builder
	sb.WriteString(hp.renderTaskList())
	hp.viewport.SetContent(sb.String())
	hp.viewport.GotoTop()
}

func (hp *HuntPanel) scrollUp(n int) {
	hp.scrollY -= n
	if hp.scrollY < 0 {
		hp.scrollY = 0
	}
	hp.updateViewport()
}

func (hp *HuntPanel) scrollDown(n int) {
	maxScroll := hp.currentTabCount() - hp.viewport.Height
	if maxScroll < 0 {
		maxScroll = 0
	}
	hp.scrollY += n
	if hp.scrollY > maxScroll {
		hp.scrollY = maxScroll
	}
	hp.updateViewport()
}

func (hp *HuntPanel) currentTabCount() int {
	switch hp.activeTab {
	case huntTabPending:
		return len(hp.pendingTasks)
	case huntTabRunning:
		return len(hp.runningTasks)
	case huntTabCompleted:
		return len(hp.completedTasks)
	case huntTabFailed:
		return len(hp.failedTasks)
	default:
		return 0
	}
}

func (hp *HuntPanel) currentTabTasks() []HuntTaskState {
	switch hp.activeTab {
	case huntTabPending:
		// Convert pending AutonomyTasks to HuntTaskState for rendering
		states := make([]HuntTaskState, len(hp.pendingTasks))
		for i, t := range hp.pendingTasks {
			states[i] = HuntTaskState{
				Task:   t,
				Status: "pending",
			}
		}
		return states
	case huntTabRunning:
		return hp.runningTasks
	case huntTabCompleted:
		return hp.completedTasks
	case huntTabFailed:
		return hp.failedTasks
	default:
		return nil
	}
}

// =============================================================================
// View
// =============================================================================

// View renders the complete HuntPanel UI.
func (hp *HuntPanel) View() string {
	// ── Panel border ──
	borderStyle := PanelStyle
	if hp.focused {
		borderStyle = PanelFocused
	}

	// ── Header ──
	titleStyle := PanelTitle
	if hp.focused {
		titleStyle = PanelTitleFocused
	}
	title := titleStyle.Render("⚔️ Hunt Mode")

	// Stats line
	pendingCount := len(hp.pendingTasks)
	runningCount := len(hp.runningTasks)
	completedCount := len(hp.completedTasks)
	failedCount := len(hp.failedTasks)
	statsLine := DimText.Render(fmt.Sprintf("%d pending · %d running · %d done · %d failed",
		pendingCount, runningCount, completedCount, failedCount))

	// Fill remaining header width
	headerWidth := hp.width - 6
	if headerWidth < 20 {
		headerWidth = 20
	}
	titleAndStats := lipgloss.JoinHorizontal(lipgloss.Left, title, "  "+statsLine)
	titleAndStats = lipgloss.NewStyle().Width(headerWidth).MaxWidth(headerWidth).Render(titleAndStats)

	divider := DimText.Render(strings.Repeat("─", headerWidth))

	// ── Tabs ──
	tabs := hp.renderTabs()
	tabsDivider := DimText.Render(strings.Repeat("─", headerWidth))

	// ── Task list ──
	taskList := hp.renderTaskList()

	// ── Footer ──
	footer := hp.renderFooter()

	// Assemble
	inner := lipgloss.JoinVertical(
		lipgloss.Left,
		titleAndStats,
		divider,
		tabs,
		tabsDivider,
		taskList,
		footer,
	)

	return borderStyle.Width(hp.width).Height(hp.height).Render(inner)
}

// =============================================================================
// Sub-renderers
// =============================================================================

func (hp *HuntPanel) renderTabs() string {
	tabs := []struct {
		label string
		count int
		tab   int
	}{
		{"PENDING", len(hp.pendingTasks), huntTabPending},
		{"RUNNING", len(hp.runningTasks), huntTabRunning},
		{"COMPLETED", len(hp.completedTasks), huntTabCompleted},
		{"FAILED", len(hp.failedTasks), huntTabFailed},
	}

	var parts []string
	for _, t := range tabs {
		label := fmt.Sprintf("[%s %d]", t.label, t.count)
		if hp.activeTab == t.tab {
			switch t.tab {
			case huntTabPending:
				parts = append(parts, WarnText.Bold(true).Render(label))
			case huntTabRunning:
				parts = append(parts, AccentText.Bold(true).Render(label))
			case huntTabCompleted:
				parts = append(parts, SuccessText.Bold(true).Render(label))
			case huntTabFailed:
				parts = append(parts, ErrorText.Bold(true).Render(label))
			}
		} else {
			parts = append(parts, DimText.Render(label))
		}
	}

	return strings.Join(parts, "  ")
}

func (hp *HuntPanel) renderTaskList() string {
	tasks := hp.currentTabTasks()
	if len(tasks) == 0 {
		msg := "  No tasks in this category."
		switch hp.activeTab {
		case huntTabPending:
			msg = "  No pending tasks. Switch to Hunt mode to auto-queue tasks from discoveries."
		case huntTabRunning:
			msg = "  No tasks currently running."
		case huntTabCompleted:
			msg = "  No completed tasks yet."
		case huntTabFailed:
			msg = "  No failed tasks."
		}
		return DimText.Render(msg)
	}

	// Calculate visible slice
	start := hp.scrollY
	end := start + hp.viewport.Height
	if end > len(tasks) {
		end = len(tasks)
	}
	if start >= len(tasks) {
		start = len(tasks) - 1
		if start < 0 {
			start = 0
		}
		end = len(tasks)
	}

	var sb strings.Builder
	for i := start; i < end; i++ {
		state := tasks[i]
		row := hp.renderTaskRow(state, i)
		sb.WriteString(row)
		sb.WriteString("\n")
	}

	return sb.String()
}

func (hp *HuntPanel) renderTaskRow(state HuntTaskState, idx int) string {
	icon := hp.taskStatusIcon(state.Status)
	isSelected := idx == hp.selectedIdx

	// Build the tool + args summary
	toolName := state.Task.ToolName
	if toolName == "" {
		toolName = "unknown"
	}
	argsSummary := ""
	if len(state.Task.Args) > 0 {
		parts := make([]string, 0)
		for k, v := range state.Task.Args {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
		argsSummary = strings.Join(parts, " ")
	}

	// Trigger info
	trigger := state.Task.TriggerFinding
	if trigger == "" {
		trigger = "manual"
	}

	// Auto-approval status
	autoStatus := "Needs approval"
	autoStyle := WarnText
	if state.Task.AutoApproved {
		autoStatus = "Auto-approved"
		autoStyle = SuccessText
	}

	// Risk level
	risk := toolRiskLevel(toolName)
	badge := hp.riskBadge(risk)

	// First line: icon + tool name + args
	line1 := fmt.Sprintf("%s %s %s",
		icon,
		AccentText.Render(toolName),
		DimText.Render(argsSummary),
	)

	// Second line: trigger + auto status + risk
	line2 := fmt.Sprintf("     %s · %s · risk: %s",
		DimText.Render("← "+trigger),
		autoStyle.Render(autoStatus),
		badge,
	)

	// For running tasks, show duration
	if state.Status == "running" && !state.StartTime.IsZero() {
		elapsed := time.Since(state.StartTime).Round(time.Second)
		line2 += DimText.Render(fmt.Sprintf(" · %s elapsed", elapsed))
	}

	// For completed tasks, show result snippet
	if state.Status == "completed" && state.ResultText != "" {
		snippet := state.ResultText
		if len(snippet) > 60 {
			snippet = snippet[:60] + "..."
		}
		line2 += DimText.Render(fmt.Sprintf(" · %s", snippet))
	}

	// For failed tasks, show error snippet
	if state.Status == "failed" && state.ErrorText != "" {
		snippet := state.ErrorText
		if len(snippet) > 60 {
			snippet = snippet[:60] + "..."
		}
		line2 += ErrorText.Render(fmt.Sprintf(" · %s", snippet))
	}

	// Approval hints for pending tasks that need approval
	approvalHint := ""
	if state.Status == "pending" && !state.Task.AutoApproved {
		approvalHint = DimText.Render("    [a]pprove [d]eny")
	}

	// Selection highlight
	row := line1 + "\n" + line2 + approvalHint

	if isSelected && hp.focused {
		prefix := "▶ "
		if state.Status == "pending" && !state.Task.AutoApproved {
			// Keep the full line but highlight
			row = HighlightRow.Render(prefix+line1) + "\n" +
				HighlightRow.Render("     "+strings.TrimPrefix(line2, "     ")+approvalHint)
		} else {
			row = HighlightRow.Render(prefix+strings.TrimPrefix(line1, " ")) + "\n" +
				HighlightRow.Render("     "+strings.TrimPrefix(line2, "     ")+approvalHint)
		}
	}

	// If detail is expanded for this row
	if hp.detailExpanded && isSelected {
		detail := hp.renderDetail(state)
		row += "\n" + detail
	}

	return row
}

func (hp *HuntPanel) renderDetail(state HuntTaskState) string {
	var sb strings.Builder
	divider := DimText.Render("  " + strings.Repeat("·", hp.width-8))

	sb.WriteString(divider)
	sb.WriteString("\n")

	sb.WriteString(DimText.Render(fmt.Sprintf("  ID: %s", state.Task.ID)))
	sb.WriteString("\n")

	if state.Task.TriggerFinding != "" {
		sb.WriteString(DimText.Render(fmt.Sprintf("  Trigger: %s", state.Task.TriggerFinding)))
		sb.WriteString("\n")
	}

	sb.WriteString(DimText.Render(fmt.Sprintf("  Tool: %s", state.Task.ToolName)))
	sb.WriteString("\n")

	if len(state.Task.Args) > 0 {
		for k, v := range state.Task.Args {
			sb.WriteString(DimText.Render(fmt.Sprintf("  Arg %s: %v", k, v)))
			sb.WriteString("\n")
		}
	}

	if !state.StartTime.IsZero() {
		sb.WriteString(DimText.Render(fmt.Sprintf("  Started: %s", state.StartTime.Format("15:04:05"))))
		sb.WriteString("\n")
	}
	if !state.EndTime.IsZero() {
		sb.WriteString(DimText.Render(fmt.Sprintf("  Ended: %s", state.EndTime.Format("15:04:05"))))
		sb.WriteString("\n")
		duration := state.EndTime.Sub(state.StartTime).Round(time.Millisecond)
		sb.WriteString(DimText.Render(fmt.Sprintf("  Duration: %s", duration)))
		sb.WriteString("\n")
	}

	if state.ResultText != "" {
		sb.WriteString(DimText.Render("  Result:"))
		sb.WriteString("\n")
		sb.WriteString(DimText.Render(fmt.Sprintf("    %s", state.ResultText)))
		sb.WriteString("\n")
	}

	if state.ErrorText != "" {
		sb.WriteString(ErrorText.Render("  Error:"))
		sb.WriteString("\n")
		sb.WriteString(ErrorText.Render(fmt.Sprintf("    %s", state.ErrorText)))
		sb.WriteString("\n")
	}

	if len(state.Findings) > 0 {
		sb.WriteString(SuccessText.Render(fmt.Sprintf("  Findings (%d):", len(state.Findings))))
		sb.WriteString("\n")
		for _, f := range state.Findings {
			sb.WriteString(SuccessText.Render(fmt.Sprintf("    • %s", f)))
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func (hp *HuntPanel) renderFooter() string {
	width := hp.width - 6
	if width < 20 {
		width = 20
	}

	divider := DimText.Render(strings.Repeat("─", width))

	// Stats row
	stats := fmt.Sprintf("Stats: %d approved · %d denied · %d findings",
		hp.totalApproved, hp.totalDenied, hp.totalFindings)

	// Key hints
	hints := "[a]pprove [d]eny [A]ll approve [D]eny all"
	if hp.activeTab == huntTabFailed {
		hints = "[r]e-run"
	}

	footerText := lipgloss.JoinHorizontal(
		lipgloss.Left,
		DimText.Render(stats),
		" | ",
		HelpText.Render(hints),
	)

	footerText = lipgloss.NewStyle().Width(width).MaxWidth(width).Render(footerText)

	return divider + "\n" + footerText
}
