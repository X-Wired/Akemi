package dashboard

import (
	"fmt"
	"strings"
	"time"

	"Akemi/internal/agent/events"
	"Akemi/internal/assistant"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const maxLogEntries = 500
const maxChatEntries = 200

type agentPanelMode int

const (
	agentModeActivity agentPanelMode = iota
	agentModeChat
	agentModeHistory
)

type aiSetupStep int

const (
	aiSetupNone aiSetupStep = iota
	aiSetupProvider
	aiSetupAPI
)

// AgentPanel displays live agent activity and AI chat.
type AgentPanel struct {
	focused bool
	width   int
	height  int

	logEntries    []AgentLogEntry
	chatEntries   []AgentChatEntry
	historyItems  []assistant.ConversationSummary
	viewport      viewport.Model
	scrollY       int
	autoScroll    bool
	mode          agentPanelMode
	historyFrom   agentPanelMode
	historyCursor int

	chatInput          string
	chatBusy           bool
	assistantAvailable bool
	toolsSummary       string
	pendingApproval    *AIApprovalRequiredMsg
	setupStep          aiSetupStep
	setupProvider      string
	setupPrompted      bool

	ChatSubmitRequested   bool
	PendingChatInput      string
	ConfigLoadRequested   bool
	SetupRequested        bool
	PendingSetupProvider  string
	PendingSetupAPIKey    string
	ApproveRequested      bool
	DenyRequested         bool
	ClearHistoryRequested bool
	HistoryLoadRequested  bool
	NewChatRequested      bool
	PendingHistoryID      string

	totalTasks     int
	completedTasks int
	findingsCount  int
	criticalCount  int
	agentRunning   bool
	agentStatus    string
}

// NewAgentPanel creates a new agent activity panel.
func NewAgentPanel() *AgentPanel {
	ap := &AgentPanel{
		logEntries:  make([]AgentLogEntry, 0, maxLogEntries),
		chatEntries: make([]AgentChatEntry, 0, maxChatEntries),
		autoScroll:  true,
		agentStatus: "Idle - agent not running",
	}
	ap.viewport = viewport.New(40, 15)
	return ap
}

// SetSize updates dimensions.
func (ap *AgentPanel) SetSize(w, h int) {
	ap.width = w
	ap.height = h
	ap.viewport.Width = w - 6
	ap.viewport.Height = h - 11
	if ap.viewport.Width < 10 {
		ap.viewport.Width = 10
	}
	if ap.viewport.Height < 3 {
		ap.viewport.Height = 3
	}
	ap.updateViewport()
}

// Init implements tea.Model.
func (ap *AgentPanel) Init() tea.Cmd {
	return nil
}

// Update handles messages.
func (ap *AgentPanel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return ap.handleKey(msg)

	case tea.MouseMsg:
		return ap.handleMouse(msg)

	case AgentEventMsg:
		ap.handleAgentEvent(msg.Event)
		ap.updateViewport()
		return ap, nil

	case AIChatStartedMsg:
		ap.chatBusy = true
		ap.updateViewport()
		return ap, nil

	case AISetupStartedMsg:
		ap.chatBusy = true
		ap.updateViewport()
		return ap, nil

	case AIConfigLoadStartedMsg:
		ap.chatBusy = true
		ap.updateViewport()
		return ap, nil

	case AIConfigLoadDoneMsg:
		ap.chatBusy = false
		if strings.TrimSpace(msg.Error) == "" {
			ap.assistantAvailable = true
			ap.toolsSummary = msg.ToolsSummary
			ap.setupStep = aiSetupNone
			ap.setupProvider = ""
			ap.addChat("system", "Connected from akemi.conf.")
			ap.updateViewport()
			return ap, nil
		}
		if msg.NeedsSetup {
			ap.startSetup()
		} else {
			ap.addChat("error", "Could not load LLM config: "+msg.Error)
		}
		ap.updateViewport()
		return ap, nil

	case AISetupDoneMsg:
		ap.chatBusy = false
		if strings.TrimSpace(msg.Error) != "" {
			ap.assistantAvailable = false
			ap.setupStep = aiSetupNone
			ap.setupProvider = ""
			ap.chatInput = ""
			ap.addChat("error", msg.Error)
			ap.addChat("system", "Press F5 or Ctrl+O to configure DeepSeek/OpenAI API settings.")
		} else {
			ap.assistantAvailable = true
			ap.toolsSummary = msg.ToolsSummary
			ap.setupStep = aiSetupNone
			ap.setupProvider = ""
			ap.addChat("system", fmt.Sprintf("Connected to %s.", msg.Provider))
		}
		ap.updateViewport()
		return ap, nil

	case AIChatDoneMsg:
		ap.chatBusy = false
		ap.pendingApproval = nil
		ap.handleToolRun(msg.ToolRun)
		if strings.TrimSpace(msg.ToolResult) != "" {
			ap.addChat("tool", "result: "+msg.ToolResult)
		}
		if strings.TrimSpace(msg.Response) != "" {
			ap.addChat("assistant", msg.Response)
		}
		ap.updateViewport()
		return ap, nil

	case AIChatErrorMsg:
		ap.chatBusy = false
		ap.addChat("error", msg.Error)
		ap.updateViewport()
		return ap, nil

	case AIApprovalRequiredMsg:
		ap.chatBusy = false
		ap.pendingApproval = &msg
		ap.handleToolRun(msg.ToolRun)
		if strings.TrimSpace(msg.ToolResult) != "" {
			ap.addChat("tool", "result: "+msg.ToolResult)
		}
		if strings.TrimSpace(msg.Response) != "" {
			ap.addChat("assistant", msg.Response)
		}
		if msg.Pending != nil {
			ap.addChat("approval", "Approve tool call? "+msg.Pending.Request.Summary())
			ap.handleToolRun(msg.Pending.ToolRun("requested"))
		}
		ap.updateViewport()
		return ap, nil

	case AIToolRunMsg:
		ap.handleToolRun(msg.ToolRun)
		ap.updateViewport()
		return ap, nil

	case AIToolResultMsg:
		if strings.TrimSpace(msg.Text) != "" {
			ap.addChat("tool", msg.Text)
		}
		ap.updateViewport()
		return ap, nil

	case ScanStartedMsg:
		ap.agentRunning = true
		ap.agentStatus = fmt.Sprintf("Agent started - %s on %s", msg.Intent, msg.Target)
		ap.logEntries = make([]AgentLogEntry, 0, maxLogEntries)
		ap.totalTasks = 0
		ap.completedTasks = 0
		ap.findingsCount = 0
		ap.criticalCount = 0
		ap.addLog("plan.started", "agent", msg.Intent)
		ap.updateViewport()
		return ap, nil

	case ScanDoneMsg:
		ap.agentRunning = false
		if msg.Cancelled {
			ap.agentStatus = fmt.Sprintf("Stopped - %s", msg.Summary)
			ap.addLog("plan.cancelled", "agent", msg.Summary)
		} else if msg.Error != nil {
			ap.agentStatus = fmt.Sprintf("Error: %s", msg.Error.Error())
			ap.addLog("plan.failed", "agent", msg.Error.Error())
		} else {
			ap.agentStatus = fmt.Sprintf("Complete - %d findings, %s", len(msg.Findings), msg.Summary)
			ap.addLog("plan.completed", "agent", msg.Summary)
		}
		ap.updateViewport()
		return ap, nil
	}

	return ap, nil
}

func (ap *AgentPanel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if ap.mode == agentModeChat {
		return ap.handleChatKey(msg)
	}
	if ap.mode == agentModeHistory {
		return ap.handleHistoryKey(msg)
	}

	switch msg.String() {
	case "ctrl+p":
		ap.enterChatMode()
	case "ctrl+g":
		ap.enterHistoryMode()
	case "ctrl+n", "ctrl++", "ctrl+=", "ctrl+plus":
		ap.requestNewChat()
	case "up", "k":
		ap.scrollUp(1)
	case "down", "j":
		ap.scrollDown(1)
	case "g":
		ap.scrollTop()
	case "G":
		ap.scrollBottom()
	case "tab":
		return ap, nil
	}
	return ap, nil
}

func (ap *AgentPanel) enterChatMode() {
	ap.mode = agentModeChat
	ap.autoScroll = true
	if !ap.assistantAvailable && ap.setupStep == aiSetupNone && !ap.setupPrompted {
		ap.requestConfigLoad()
	}
	ap.updateViewport()
}

func (ap *AgentPanel) enterActivityMode() {
	ap.mode = agentModeActivity
	ap.autoScroll = true
	ap.updateViewport()
}

func (ap *AgentPanel) enterHistoryMode() {
	if ap.mode != agentModeHistory {
		ap.historyFrom = ap.mode
	}
	ap.mode = agentModeHistory
	if len(ap.historyItems) > 0 && ap.historyCursor == 0 {
		ap.historyCursor = 1
	}
	ap.scrollY = 0
	ap.autoScroll = false
	ap.updateViewport()
}

func (ap *AgentPanel) toggleHistoryMode() {
	if ap.mode == agentModeHistory {
		switch ap.historyFrom {
		case agentModeChat:
			ap.mode = agentModeChat
			ap.autoScroll = true
		default:
			ap.mode = agentModeActivity
			ap.autoScroll = true
		}
		ap.updateViewport()
		return
	}
	ap.enterHistoryMode()
}

func (ap *AgentPanel) scrollUp(lines int) {
	if lines <= 0 {
		return
	}
	ap.scrollY -= lines
	if ap.scrollY < 0 {
		ap.scrollY = 0
	}
	ap.autoScroll = false
	ap.updateViewport()
}

func (ap *AgentPanel) scrollDown(lines int) {
	if lines <= 0 {
		return
	}
	ap.scrollY += lines
	maxScroll := ap.maxScroll()
	if ap.scrollY > maxScroll {
		ap.scrollY = maxScroll
	}
	ap.autoScroll = ap.scrollY >= maxScroll
	ap.updateViewport()
}

func (ap *AgentPanel) scrollTop() {
	ap.scrollY = 0
	ap.autoScroll = false
	ap.updateViewport()
}

func (ap *AgentPanel) scrollBottom() {
	ap.scrollY = ap.maxScroll()
	ap.autoScroll = true
	ap.updateViewport()
}

func (ap *AgentPanel) requestConfigLoad() {
	ap.ConfigLoadRequested = true
	ap.chatBusy = true
	ap.addChat("system", "Checking akemi.conf for LLM settings...")
}

func (ap *AgentPanel) startSetup() {
	ap.setupPrompted = true
	ap.setupStep = aiSetupNone
	ap.setupProvider = ""
	ap.chatInput = ""
	ap.chatBusy = false
	ap.addChat("system", "No usable DeepSeek/OpenAI API key found. Press F5 or Ctrl+O to configure API settings.")
}

func (ap *AgentPanel) handleChatKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if ap.setupStep != aiSetupNone {
		return ap.handleSetupKey(msg)
	}

	switch msg.String() {
	case "ctrl+p":
		ap.enterActivityMode()
	case "ctrl+g":
		ap.enterHistoryMode()
	case "ctrl+n", "ctrl++", "ctrl+=", "ctrl+plus":
		ap.requestNewChat()
	case "ctrl+c", "tab":
		return ap, nil
	case "esc":
		ap.chatInput = ""
	case "y":
		if ap.pendingApproval != nil {
			ap.ApproveRequested = true
		} else if !ap.chatBusy {
			ap.chatInput += "y"
		}
	case "n":
		if ap.pendingApproval != nil {
			ap.DenyRequested = true
		} else if !ap.chatBusy {
			ap.chatInput += "n"
		}
	case "enter":
		text := strings.TrimSpace(ap.chatInput)
		if text == "" || ap.chatBusy || ap.pendingApproval != nil {
			return ap, nil
		}
		ap.chatInput = ""
		if text == "/tools" {
			ap.addChat("system", firstNonEmpty(ap.toolsSummary, "No MCP tools connected."))
			ap.updateViewport()
			return ap, nil
		}
		if text == "/clear" {
			ap.ClearHistoryRequested = true
			ap.chatEntries = nil
			ap.addChat("system", "Chat history cleared.")
			ap.updateViewport()
			return ap, nil
		}
		if !ap.assistantAvailable {
			ap.startSetup()
			ap.updateViewport()
			return ap, nil
		}
		ap.addChat("user", text)
		ap.ChatSubmitRequested = true
		ap.PendingChatInput = text
	case "backspace", "ctrl+h":
		if len(ap.chatInput) > 0 {
			ap.chatInput = ap.chatInput[:len(ap.chatInput)-1]
		}
	case "up":
		ap.scrollUp(1)
	case "down":
		ap.scrollDown(1)
	case "pgup", "ctrl+u":
		ap.scrollUp(max(1, ap.viewport.Height-1))
	case "pgdown", "ctrl+d":
		ap.scrollDown(max(1, ap.viewport.Height-1))
	case "home":
		ap.scrollTop()
	case "end":
		ap.scrollBottom()
	default:
		if len(msg.String()) == 1 && !ap.chatBusy && ap.pendingApproval == nil {
			ap.chatInput += msg.String()
		}
	}
	return ap, nil
}

func (ap *AgentPanel) handleHistoryKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+g", "esc":
		ap.toggleHistoryMode()
	case "ctrl+n", "ctrl++", "ctrl+=", "ctrl+plus":
		ap.requestNewChat()
	case "ctrl+p":
		ap.enterChatMode()
	case "ctrl+a":
		ap.enterActivityMode()
	case "enter":
		ap.requestHistoryLoad()
	case "up", "k":
		ap.moveHistoryCursor(-1)
	case "down", "j":
		ap.moveHistoryCursor(1)
	case "pgup", "ctrl+u":
		ap.moveHistoryCursor(-max(1, ap.viewport.Height-1))
	case "pgdown", "ctrl+d":
		ap.moveHistoryCursor(max(1, ap.viewport.Height-1))
	case "g", "home":
		ap.historyCursor = 0
		ap.scrollTop()
	case "G", "end":
		ap.historyCursor = max(0, ap.historySelectableCount()-1)
		ap.scrollBottom()
	case "tab":
		return ap, nil
	}
	return ap, nil
}

func (ap *AgentPanel) moveHistoryCursor(delta int) {
	count := ap.historySelectableCount()
	if count == 0 {
		return
	}
	ap.historyCursor += delta
	if ap.historyCursor < 0 {
		ap.historyCursor = 0
	}
	if ap.historyCursor >= count {
		ap.historyCursor = count - 1
	}
	ap.ensureHistoryCursorVisible()
	ap.updateViewport()
}

func (ap *AgentPanel) ensureHistoryCursorVisible() {
	headerLines := 2
	cursorLine := headerLines + ap.historyCursor
	if cursorLine < ap.scrollY {
		ap.scrollY = cursorLine
	}
	bottom := ap.scrollY + max(1, ap.viewport.Height) - 1
	if cursorLine > bottom {
		ap.scrollY = cursorLine - max(1, ap.viewport.Height) + 1
	}
	if ap.scrollY < 0 {
		ap.scrollY = 0
	}
}

func (ap *AgentPanel) requestHistoryLoad() {
	if ap.historyCursor == 0 {
		ap.requestNewChat()
		return
	}
	index := ap.historyCursor - 1
	if len(ap.historyItems) == 0 || index < 0 || index >= len(ap.historyItems) {
		return
	}
	id := strings.TrimSpace(ap.historyItems[index].ID)
	if id == "" {
		return
	}
	ap.PendingHistoryID = id
	ap.HistoryLoadRequested = true
}

func (ap *AgentPanel) requestNewChat() {
	ap.PendingHistoryID = ""
	ap.HistoryLoadRequested = false
	ap.NewChatRequested = true
}

func (ap *AgentPanel) handleSetupKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+p":
		ap.enterActivityMode()
	case "ctrl+c", "tab":
		return ap, nil
	case "esc":
		ap.setupStep = aiSetupNone
		ap.setupProvider = ""
		ap.chatInput = ""
		ap.chatBusy = false
		ap.addChat("system", "LLM setup cancelled.")
		ap.updateViewport()
	case "enter":
		value := strings.TrimSpace(ap.chatInput)
		if ap.setupStep == aiSetupProvider {
			provider := normalizeSetupProvider(value)
			if provider == "" {
				ap.addChat("error", "Unsupported vendor. Press F5 or Ctrl+O to configure DeepSeek/OpenAI.")
				ap.chatInput = ""
				ap.updateViewport()
				return ap, nil
			}
			ap.setupProvider = provider
			ap.setupStep = aiSetupAPI
			ap.chatInput = ""
			ap.addChat("system", fmt.Sprintf("Press F5 or Ctrl+O to enter the %s API key.", provider))
			ap.updateViewport()
			return ap, nil
		}
		if ap.setupStep == aiSetupAPI {
			if value == "" {
				ap.addChat("error", "API key is required.")
				ap.updateViewport()
				return ap, nil
			}
			ap.PendingSetupProvider = ap.setupProvider
			ap.PendingSetupAPIKey = value
			ap.SetupRequested = true
			ap.setupStep = aiSetupNone
			ap.setupProvider = ""
			ap.chatInput = ""
			ap.chatBusy = true
			ap.addChat("system", "Connecting to "+ap.PendingSetupProvider+"...")
			ap.updateViewport()
			return ap, nil
		}
	case "backspace", "ctrl+h":
		if len(ap.chatInput) > 0 {
			ap.chatInput = ap.chatInput[:len(ap.chatInput)-1]
			ap.updateViewport()
		}
	default:
		if len(msg.String()) == 1 && !ap.chatBusy {
			ap.chatInput += msg.String()
			ap.updateViewport()
		}
	}
	return ap, nil
}

func normalizeSetupProvider(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "deepseek", "openai":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func (ap *AgentPanel) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	switch msg.Action {
	case tea.MouseActionPress:
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			ap.scrollUp(1)
		case tea.MouseButtonWheelDown:
			ap.scrollDown(1)
		}
	}
	return ap, nil
}

func (ap *AgentPanel) handleAgentEvent(evt events.Event) {
	switch evt.Type {
	case events.EventPlanStarted:
		ap.agentRunning = true
		ap.agentStatus = fmt.Sprintf("Planning: %s", evt.Message)
		ap.addLog("plan.started", "planner", evt.Message)
	case events.EventPlanCompleted:
		ap.agentStatus = fmt.Sprintf("Plan ready - %s", evt.Message)
		ap.addLog("plan.completed", "planner", evt.Message)
	case events.EventPlanFailed:
		ap.agentRunning = false
		ap.agentStatus = fmt.Sprintf("Plan failed: %s", evt.Message)
		ap.addLog("plan.failed", "planner", evt.Message)
	case events.EventTaskStarted:
		ap.totalTasks++
		ap.agentStatus = fmt.Sprintf("Running: %s", evt.ToolName)
		ap.addLog("task.started", evt.ToolName, evt.Message)
	case events.EventTaskProgress:
		ap.addLog("task.progress", evt.ToolName, evt.Message)
	case events.EventTaskCompleted:
		ap.completedTasks++
		findings := eventInt(evt.Data, "findings")
		msg := evt.Message
		if findings > 0 {
			msg = fmt.Sprintf("%s (%d findings)", msg, findings)
		}
		ap.addLog("task.completed", evt.ToolName, msg)
	case events.EventTaskDenied:
		ap.addLog("task.denied", evt.ToolName, evt.Message)
	case events.EventTaskError:
		ap.addLog("task.error", evt.ToolName, evt.Message)
	case events.EventFindingDiscovered:
		ap.findingsCount++
		severity := eventString(evt.Data, "severity")
		if severity == "" {
			severity = "info"
		}
		title := eventString(evt.Data, "title")
		if severity == "critical" || severity == "high" {
			ap.criticalCount++
		}
		ap.addLog("finding.discovered", evt.ToolName, fmt.Sprintf("[%s] %s", severity, title))
	case events.EventSafetyTriggered:
		ap.addLog("safety.triggered", evt.ToolName, evt.Message)
	case events.EventMemoryUpdated:
		ap.addLog("memory.updated", "memory", evt.Message)
	}
}

func (ap *AgentPanel) handleToolRun(info *assistant.ToolRunInfo) {
	if info == nil {
		return
	}
	name := firstNonEmpty(info.ToolName, info.NativeName, "tool")
	args := strings.TrimSpace(info.ArgumentsSummary)
	switch info.Status {
	case "requested":
		ap.addLog("task.progress", name, "approval requested "+args)
	case "running":
		ap.addChat("tool", strings.TrimSpace("running "+name+" "+args))
		ap.addLog("task.started", name, args)
	case "completed":
		ap.addLog("task.completed", name, "completed")
	case "failed":
		ap.addLog("task.error", name, "failed")
	case "denied":
		ap.addChat("tool", strings.TrimSpace("denied "+name+" "+args))
		ap.addLog("task.denied", name, args)
	}
}

func (ap *AgentPanel) addLog(eventType, toolName, message string) {
	ap.logEntries = append(ap.logEntries, AgentLogEntry{
		Time:      time.Now(),
		EventType: eventType,
		ToolName:  toolName,
		Message:   message,
	})
	if len(ap.logEntries) > maxLogEntries {
		ap.logEntries = ap.logEntries[len(ap.logEntries)-maxLogEntries:]
	}
}

func (ap *AgentPanel) addChat(role, message string) {
	ap.chatEntries = append(ap.chatEntries, AgentChatEntry{
		Time:    time.Now(),
		Role:    role,
		Message: message,
	})
	if len(ap.chatEntries) > maxChatEntries {
		ap.chatEntries = ap.chatEntries[len(ap.chatEntries)-maxChatEntries:]
	}
}

func (ap *AgentPanel) updateViewport() {
	var sb strings.Builder
	visibleHeight := ap.viewport.Height
	if visibleHeight <= 0 {
		visibleHeight = 10
	}

	lines := ap.contentLines()
	total := len(lines)
	start := ap.scrollY
	if ap.autoScroll {
		start = max(0, total-visibleHeight)
	}
	maxScroll := max(0, total-visibleHeight)
	if start > maxScroll {
		start = maxScroll
	}
	if start < 0 {
		start = 0
	}
	ap.scrollY = start
	end := start + visibleHeight
	if end > total {
		end = total
	}

	for i := start; i < end; i++ {
		sb.WriteString(lines[i])
		if i < end-1 {
			sb.WriteString("\n")
		}
	}

	ap.viewport.SetContent(sb.String())
}

func (ap *AgentPanel) entryCount() int {
	return len(ap.contentLines())
}

func (ap *AgentPanel) maxScroll() int {
	return max(0, ap.entryCount()-max(1, ap.viewport.Height))
}

func (ap *AgentPanel) contentLines() []string {
	if ap.mode == agentModeHistory {
		return ap.historyLines()
	}
	if ap.mode == agentModeChat {
		if len(ap.chatEntries) == 0 {
			if ap.assistantAvailable {
				return []string{DimText.Render("  Chat ready. Ask about this run, or type /tools.")}
			}
			if ap.chatBusy {
				return []string{DimText.Render("  Checking akemi.conf...")}
			}
			return []string{DimText.Render("  AI offline. Press F5 or Ctrl+O to configure DeepSeek/OpenAI.")}
		}
		lines := make([]string, 0, len(ap.chatEntries)*2)
		for _, entry := range ap.chatEntries {
			lines = append(lines, ap.formatChatEntry(entry)...)
		}
		return lines
	}
	if len(ap.logEntries) == 0 {
		return []string{DimText.Render("  Waiting for agent events...")}
	}
	lines := make([]string, 0, len(ap.logEntries))
	for _, entry := range ap.logEntries {
		lines = append(lines, ap.formatLogEntry(entry))
	}
	return lines
}

func (ap *AgentPanel) historyLines() []string {
	lines := make([]string, 0, len(ap.historyItems)+3)
	lines = append(lines, AccentText.Render("Chat History"))
	lines = append(lines, DimText.Render(fmt.Sprintf("  %d saved conversations", len(ap.historyItems))))
	lines = append(lines, ap.formatNewChatItem())
	if len(ap.historyItems) == 0 {
		lines = append(lines, DimText.Render("  No saved conversations yet."))
		return lines
	}
	for i, item := range ap.historyItems {
		lines = append(lines, ap.formatHistoryItem(i+1, i, item))
	}
	return lines
}

func (ap *AgentPanel) formatNewChatItem() string {
	marker := " "
	markerStyle := DimText
	if ap.historyCursor == 0 {
		marker = ">"
		markerStyle = AccentText
	}
	line := fmt.Sprintf("%s %s",
		markerStyle.Render(marker),
		AccentText.Render("[ New chat ]"),
	)
	if ap.historyCursor == 0 {
		return HighlightRow.Render(line)
	}
	return line
}

func (ap *AgentPanel) formatHistoryItem(cursorIndex, listIndex int, item assistant.ConversationSummary) string {
	marker := " "
	markerStyle := DimText
	if cursorIndex == ap.historyCursor {
		marker = ">"
		markerStyle = AccentText
	}
	updated := item.UpdatedAt.Format("Jan 02 15:04")
	prefixPlain := fmt.Sprintf("%s %02d. ", marker, listIndex+1)
	metaPlain := "  " + updated
	titleWidth := max(8, ap.viewport.Width-len(prefixPlain)-len(metaPlain))
	title := truncateRunes(firstNonEmpty(item.Title, "New chat"), titleWidth)
	line := fmt.Sprintf("%s %s %s %s",
		markerStyle.Render(marker),
		DimText.Render(fmt.Sprintf("%02d.", listIndex+1)),
		title,
		DimText.Render(metaPlain),
	)
	if cursorIndex == ap.historyCursor {
		return HighlightRow.Render(line)
	}
	return line
}

func (ap *AgentPanel) formatLogEntry(entry AgentLogEntry) string {
	timeStr := DimText.Render(entry.Time.Format("15:04:05"))
	eventIcon, eventStyle := ap.eventIcon(entry.EventType)
	toolStr := AccentText.Render(fmt.Sprintf("[%s]", entry.ToolName))
	return fmt.Sprintf("%s %s %s %s", timeStr, eventStyle.Render(eventIcon), toolStr, entry.Message)
}

func (ap *AgentPanel) formatChatEntry(entry AgentChatEntry) []string {
	timePlain := entry.Time.Format("15:04:05")
	role, roleStyle := chatRole(entry.Role)
	prefixPlain := fmt.Sprintf("%s %s ", timePlain, role)
	messageWidth := max(8, ap.viewport.Width-len(prefixPlain))
	parts := wrapText(entry.Message, messageWidth)
	if len(parts) == 0 {
		parts = []string{""}
	}

	timeStr := DimText.Render(timePlain)
	roleStr := roleStyle.Render(role)
	lines := make([]string, 0, len(parts))
	lines = append(lines, fmt.Sprintf("%s %s %s", timeStr, roleStr, parts[0]))
	continuationPrefix := strings.Repeat(" ", len(prefixPlain))
	for _, part := range parts[1:] {
		lines = append(lines, continuationPrefix+part)
	}
	return lines
}

func chatRole(role string) (string, lipgloss.Style) {
	switch role {
	case "user":
		return "you:", AccentText
	case "assistant":
		return "ai:", SuccessText
	case "tool":
		return "tool:", WarnText
	case "approval":
		return "approve:", WarnText
	case "error":
		return "error:", ErrorText
	default:
		return "system:", DimText
	}
}

func (ap *AgentPanel) eventIcon(eventType string) (string, lipgloss.Style) {
	switch eventType {
	case "plan.started":
		return "PLAN", DimText
	case "plan.completed", "task.completed":
		return "OK", SuccessText
	case "plan.failed", "task.error":
		return "ERR", ErrorText
	case "plan.cancelled":
		return "STOP", WarnText
	case "task.started":
		return "RUN", WarnText
	case "task.progress":
		return "...", DimText
	case "task.denied":
		return "DENY", ErrorText
	case "finding.discovered":
		return "FIND", WarnText
	case "safety.triggered":
		return "SAFE", WarnText
	case "memory.updated":
		return "MEM", DimText
	default:
		return "-", DimText
	}
}

// View renders the agent panel.
func (ap *AgentPanel) View() string {
	var sb strings.Builder

	title := PanelTitle
	if ap.focused {
		title = PanelTitleFocused
	}
	panelName := "Agent Activity"
	if ap.mode == agentModeChat {
		panelName = "Agent Chat"
	} else if ap.mode == agentModeHistory {
		panelName = "Chat History"
	}
	sb.WriteString(title.Render(panelName))
	sb.WriteString("\n")

	stats := fmt.Sprintf("Tasks: %d/%d | Findings: %d (crit: %d) | %s",
		ap.completedTasks, ap.totalTasks, ap.findingsCount, ap.criticalCount, ap.agentStatus)
	statsStyle := DimText
	if ap.agentRunning {
		statsStyle = WarnText
	}
	if ap.mode == agentModeChat {
		stats = "AI offline"
		if ap.assistantAvailable {
			stats = "AI ready"
		}
		if ap.setupStep != aiSetupNone {
			stats = "AI setup"
			statsStyle = WarnText
		}
		if ap.chatBusy {
			stats = "AI thinking"
		}
		if ap.pendingApproval != nil {
			stats = "Tool approval pending"
			statsStyle = WarnText
		}
	} else if ap.mode == agentModeHistory {
		stats = fmt.Sprintf("%d saved conversations", len(ap.historyItems))
	}
	maxStats := ap.width - 6
	if len(stats) > maxStats && maxStats > 3 {
		stats = stats[:maxStats-3] + "..."
	}
	sb.WriteString(statsStyle.Render(stats))
	sb.WriteString("\n")
	sb.WriteString(DimText.Render(strings.Repeat("-", max(ap.width-4, 20))))
	sb.WriteString("\n")
	sb.WriteString(ap.viewport.View())
	sb.WriteString("\n")

	if ap.mode == agentModeChat {
		sb.WriteString(ap.renderChatInput())
		sb.WriteString("\n")
	}

	if ap.focused {
		if ap.mode == agentModeChat {
			if ap.setupStep != aiSetupNone {
				sb.WriteString(HelpText.Render("Ctrl+A activity | Ctrl+D discovery | Enter confirm | Esc cancel | Tab next"))
			} else {
				sb.WriteString(HelpText.Render("Ctrl+A activity | Ctrl+D discovery | Ctrl+G history | Ctrl++/Ctrl+N new | Enter send | /tools | Tab next"))
			}
		} else if ap.mode == agentModeHistory {
			sb.WriteString(HelpText.Render("Enter load/new | Ctrl++/Ctrl+N new | Ctrl+G back | Ctrl+P chat | up/down scroll | Tab next"))
		} else {
			sb.WriteString(HelpText.Render("Ctrl+D discovery | Ctrl+P chat | Ctrl+G history | Ctrl++/Ctrl+N new | up/down scroll | Tab next"))
		}
	}

	return sb.String()
}

// Focused returns focus state.
func (ap *AgentPanel) Focused() bool { return ap.focused }

// Focus sets focus state.
func (ap *AgentPanel) Focus(v bool) { ap.focused = v }

// SetAssistantAvailable updates chat readiness and visible tool inventory.
func (ap *AgentPanel) SetAssistantAvailable(available bool, toolsSummary string) {
	ap.assistantAvailable = available
	ap.toolsSummary = toolsSummary
	ap.updateViewport()
}

// SetChatTranscript replaces the visible chat transcript with persisted entries.
func (ap *AgentPanel) SetChatTranscript(entries []assistant.TranscriptEntry) {
	ap.chatEntries = ap.chatEntries[:0]
	for _, entry := range entries {
		if strings.TrimSpace(entry.Message) == "" {
			continue
		}
		t := entry.Time
		if t.IsZero() {
			t = time.Now()
		}
		ap.chatEntries = append(ap.chatEntries, AgentChatEntry{
			Time:    t,
			Role:    entry.Role,
			Message: entry.Message,
		})
	}
	if len(ap.chatEntries) > maxChatEntries {
		ap.chatEntries = ap.chatEntries[len(ap.chatEntries)-maxChatEntries:]
	}
	ap.updateViewport()
}

// SetHistoryEntries replaces the selectable conversation history list.
func (ap *AgentPanel) SetHistoryEntries(entries []assistant.ConversationSummary) {
	ap.historyItems = append(ap.historyItems[:0], entries...)
	if ap.historyCursor >= ap.historySelectableCount() {
		ap.historyCursor = max(0, ap.historySelectableCount()-1)
	}
	if ap.historyCursor < 0 {
		ap.historyCursor = 0
	}
	ap.updateViewport()
}

func (ap *AgentPanel) historySelectableCount() int {
	return len(ap.historyItems) + 1
}

func (ap *AgentPanel) renderChatInput() string {
	if ap.pendingApproval != nil {
		return WarnText.Render("Approve tool call? y = approve, n = deny")
	}
	if ap.setupStep == aiSetupProvider {
		prompt := "vendor> " + ap.chatInput
		if ap.focused {
			prompt += "|"
		}
		return AccentText.Render(prompt)
	}
	if ap.setupStep == aiSetupAPI {
		prompt := "api key> " + strings.Repeat("*", len(ap.chatInput))
		if ap.focused {
			prompt += "|"
		}
		return AccentText.Render(prompt)
	}
	if ap.chatBusy {
		return DimText.Render("AI is thinking...")
	}
	prompt := "> " + ap.chatInput
	if ap.focused {
		prompt += "|"
	}
	return AccentText.Render(prompt)
}

// SubscribeToEvents returns a callback suitable for agent.SubscribeEvents().
func (ap *AgentPanel) SubscribeToEvents() func(events.Event) {
	return func(evt events.Event) {}
}

func eventInt(data map[string]interface{}, key string) int {
	if data == nil {
		return 0
	}
	switch v := data[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	default:
		return 0
	}
}

func eventString(data map[string]interface{}, key string) string {
	if data == nil {
		return ""
	}
	if s, ok := data[key].(string); ok {
		return s
	}
	return ""
}

func wrapText(s string, width int) []string {
	if width < 1 {
		width = 1
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	paragraphs := strings.Split(s, "\n")
	lines := make([]string, 0, len(paragraphs))
	for _, paragraph := range paragraphs {
		if strings.TrimSpace(paragraph) == "" {
			lines = append(lines, "")
			continue
		}
		lines = append(lines, wrapParagraph(paragraph, width)...)
	}
	return lines
}

func wrapParagraph(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	lines := make([]string, 0, len(words))
	line := ""
	for _, word := range words {
		for _, chunk := range splitLongWord(word, width) {
			if line == "" {
				line = chunk
				continue
			}
			if runeLen(line)+1+runeLen(chunk) <= width {
				line += " " + chunk
				continue
			}
			lines = append(lines, line)
			line = chunk
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func splitLongWord(word string, width int) []string {
	runes := []rune(word)
	if width < 1 || len(runes) <= width {
		return []string{word}
	}
	chunks := make([]string, 0, len(runes)/width+1)
	for len(runes) > width {
		chunks = append(chunks, string(runes[:width]))
		runes = runes[width:]
	}
	if len(runes) > 0 {
		chunks = append(chunks, string(runes))
	}
	return chunks
}

func truncateRunes(value string, width int) string {
	if width < 1 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= width {
		return value
	}
	if width <= 3 {
		return string(runes[:width])
	}
	return string(runes[:width-3]) + "..."
}

func runeLen(s string) int {
	return len([]rune(s))
}
