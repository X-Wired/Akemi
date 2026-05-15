// Package engagement tracks human approval for AI-requested tool execution.
package engagement

import (
	"encoding/json"
	"fmt"
	"time"
)

// ApprovalMode controls how tool execution is authorized.
type ApprovalMode string

const (
	ApprovalAsk   ApprovalMode = "ask"
	ApprovalDeny  ApprovalMode = "deny"
	ApprovalAllow ApprovalMode = "allow"
)

// Request is a pending approval decision for one tool call.
type Request struct {
	ID          string
	ToolName    string
	ServerName  string
	NativeName  string
	Risk        string
	Arguments   string
	RequestedAt time.Time
}

// Summary returns a compact operator-facing description.
func (r Request) Summary() string {
	return fmt.Sprintf("%s.%s risk=%s args=%s", r.ServerName, r.NativeName, r.Risk, compactJSON(r.Arguments))
}

// Manager stores approval policy for the current engagement/session.
type Manager struct {
	mode          ApprovalMode
	sessionGrants map[string]bool
}

// NewManager creates an approval manager. Empty mode defaults to ask.
func NewManager(mode ApprovalMode) *Manager {
	if mode == "" {
		mode = ApprovalAsk
	}
	return &Manager{
		mode:          mode,
		sessionGrants: make(map[string]bool),
	}
}

// Mode returns the current approval mode.
func (m *Manager) Mode() ApprovalMode {
	return m.mode
}

// RequiresApproval reports whether the given tool needs a human decision.
func (m *Manager) RequiresApproval(req Request) bool {
	switch m.mode {
	case ApprovalAllow:
		return false
	case ApprovalDeny:
		return true
	default:
		return !m.sessionGrants[req.ToolName]
	}
}

// GrantForSession lets future calls to a namespaced tool run without prompting.
func (m *Manager) GrantForSession(toolName string) {
	if toolName != "" {
		m.sessionGrants[toolName] = true
	}
}

func compactJSON(value string) string {
	if value == "" {
		return "{}"
	}
	var decoded interface{}
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return value
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return value
	}
	return string(encoded)
}
