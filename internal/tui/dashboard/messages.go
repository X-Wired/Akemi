package dashboard

import (
	"time"

	"Akemi/internal/agent/events"
	akemiarchive "Akemi/internal/archive"
	"Akemi/internal/assistant"
	core "Akemi/internal/core"
	"Akemi/internal/engagement"
	"Akemi/internal/toolbridge"
)

// =============================================================================
// Scan lifecycle messages
// =============================================================================

// ScanStartedMsg is sent when the user initiates a scan.
type ScanStartedMsg struct {
	Target string
	Intent string
	Config ScanConfig
}

// ScanConfig holds the user's scan configuration.
type ScanConfig struct {
	Target      string
	AuthURL     string
	AuthCookies []string
	PortRange   string
	Threads     int
	Proxy       string
	Intent      string
	Depth       int
	Timeout     int
}

// AuthCaptureStartedMsg is sent when DotHound login capture starts.
type AuthCaptureStartedMsg struct {
	TargetURL string
	Username  string
}

// AuthCaptureDoneMsg reports the result of DotHound login capture.
type AuthCaptureDoneMsg struct {
	Session *engagement.AuthSession
	Error   string
}

// ScanProgressMsg is sent by running scans to update discovery counts.
type ScanProgressMsg struct {
	Subdomains int
	Ports      int
	URLs       int
	Endpoints  int
	Secrets    int
	Params     int
	JSFiles    int
	Findings   int
	Phase      string // current phase name
}

// DiscoveryItemMsg appends one live discovery row to the dashboard.
type DiscoveryItemMsg struct {
	Section string
	Key     string
	Item    string
	Phase   string
}

// TargetConfigUpdatedMsg updates the target panel from an assistant tool.
type TargetConfigUpdatedMsg struct {
	Config toolbridge.TargetConfig
	Phase  string
}

// ScanDoneMsg signals scan completion.
type ScanDoneMsg struct {
	Findings      []core.VulnFinding
	Ports         []core.PortResult
	URLs          []string
	CrawlFindings []core.CrawlFinding
	Subdomains    []string
	APIEndpoints  []core.APIEndpointFinding
	APISpecs      []core.APISpecFinding
	APIParameters []core.APIParameterFinding
	Summary       string
	Archive       *akemiarchive.File
	ArchivePath   string
	ArchiveError  string
	Cancelled     bool
	Error         error
}

// RunSavedMsg reports the result of a manual .akemi save.
type RunSavedMsg struct {
	Path  string
	Error string
}

// RunLoadedMsg reports the result of a manual .akemi load.
type RunLoadedMsg struct {
	Path    string
	Summary string
	Error   string
}

// =============================================================================
// System metrics message
// =============================================================================

// SystemMetricsMsg carries real-time system usage data.
type SystemMetricsMsg struct {
	CPUPercent    float64
	MemPercent    float64
	MemUsed       uint64
	MemTotal      uint64
	NetSentRate   float64 // bytes/sec
	NetRecvRate   float64 // bytes/sec
	DiskPercent   float64
	DiskUsed      uint64
	DiskTotal     uint64
	NumGoroutines int
	Uptime        time.Duration
}

// =============================================================================
// Agent event messages
// =============================================================================

// AgentEventMsg wraps an agent event for the dashboard.
type AgentEventMsg struct {
	Event events.Event
}

// AgentLogEntry is a single line in the agent activity log.
type AgentLogEntry struct {
	Time      time.Time
	EventType string
	ToolName  string
	Message   string
	Severity  string // for findings
}

// AgentChatEntry is one row in the AI chat transcript.
type AgentChatEntry struct {
	Time    time.Time
	Role    string
	Message string
}

// AIChatStartedMsg marks an assistant turn as in flight.
type AIChatStartedMsg struct{}

// AISetupStartedMsg marks first-run assistant setup as in flight.
type AISetupStartedMsg struct{}

// AIConfigLoadStartedMsg marks a config-based assistant load as in flight.
type AIConfigLoadStartedMsg struct{}

// AIConfigLoadDoneMsg reports whether assistant config was found and loaded.
type AIConfigLoadDoneMsg struct {
	Session      *assistant.Session
	ToolsSummary string
	Error        string
	NeedsSetup   bool
}

// AISetupDoneMsg reports the result of first-run assistant setup.
type AISetupDoneMsg struct {
	Provider     string
	Session      *assistant.Session
	ToolsSummary string
	Error        string
}

// APISettings holds DeepSeek/OpenAI settings edited by the F5 modal.
type APISettings struct {
	Provider        string
	Model           string
	BaseURL         string
	APIKey          string
	MaxTokens       int
	Temperature     float64
	ReasoningEffort string
	Thinking        bool
}

// APISettingsLoadStartedMsg marks API settings loading as in flight.
type APISettingsLoadStartedMsg struct{}

// APISettingsLoadDoneMsg carries current API settings into the F5 modal.
type APISettingsLoadDoneMsg struct {
	Settings APISettings
	Error    string
}

// APISettingsTestStartedMsg marks a provider connection test as in flight.
type APISettingsTestStartedMsg struct{}

// APISettingsTestDoneMsg reports provider connection test status.
type APISettingsTestDoneMsg struct {
	Error string
}

// APISettingsApplyStartedMsg marks provider settings application as in flight.
type APISettingsApplyStartedMsg struct{}

// APISettingsApplyDoneMsg reports settings application status and optional new assistant.
type APISettingsApplyDoneMsg struct {
	Provider     string
	Session      *assistant.Session
	ToolsSummary string
	Error        string
}

// AIChatDoneMsg carries an assistant response.
type AIChatDoneMsg struct {
	Response   string
	ToolResult string
	ToolRun    *assistant.ToolRunInfo
}

// AIChatErrorMsg carries assistant failure details.
type AIChatErrorMsg struct {
	Error string
}

// AIApprovalRequiredMsg asks the operator to approve a model-requested tool.
type AIApprovalRequiredMsg struct {
	Pending    *assistant.PendingApproval
	ToolResult string
	ToolRun    *assistant.ToolRunInfo
	Response   string
}

// AIToolResultMsg displays a completed tool call result.
type AIToolResultMsg struct {
	Text string
}

// AIToolRunMsg displays a tool lifecycle update before/while execution happens.
type AIToolRunMsg struct {
	ToolRun *assistant.ToolRunInfo
}

// =============================================================================
// Focus & resize messages
// =============================================================================

// FocusMsg changes the focused panel.
type FocusMsg int

const (
	FocusTarget    FocusMsg = 0
	FocusDiscovery FocusMsg = 1
	FocusSystem    FocusMsg = 2
	FocusAgent     FocusMsg = 3
)

// ResizeMsg adjusts the split ratios.
type ResizeMsg struct {
	SplitH float64 // horizontal split (0.0-1.0)
	SplitV float64 // vertical split (0.0-1.0)
}

// =============================================================================
// Tick messages
// =============================================================================

// SystemTickMsg triggers a system metrics refresh.
type SystemTickMsg struct{}

// AgentTickMsg triggers an agent log refresh.
type AgentTickMsg struct{}

// =============================================================================
// Operation deduplication messages
// =============================================================================

// OperationDuplicateMsg is sent when the user tries to run an operation
// that has already been completed for the target. The dashboard shows a
// confirmation prompt instead of immediately re-running.
type OperationDuplicateMsg struct {
	Target        string
	Operation     string
	CompletedOps  []string
	PendingConfig ScanConfig
}

// OperationSkippedMsg is sent back when the user chooses to skip a repeated
// operation. It carries the operations that were skipped.
type OperationSkippedMsg struct {
	Target     string
	Operations []string
}

// OperationRepeatApprovedMsg is sent when the user confirms they want to
// re-run an operation that was already completed.
type OperationRepeatApprovedMsg struct {
	Target    string
	Operation string
	Config    ScanConfig
}

// SessionStateMsg carries summary info about the current session state
// for display in the target panel.
type SessionStateMsg struct {
	Target       string
	CompletedOps []string
	Summary      string
}
