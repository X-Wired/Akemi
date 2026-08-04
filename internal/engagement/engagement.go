// Package engagement tracks human approval for AI-requested tool execution.
package engagement

import (
	"encoding/json"
	"fmt"
	"strings"
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
		if m.sessionGrants[req.ToolName] {
			return false
		}
		return isAggressiveOrInvasive(req.ToolName, req.Risk)
	}
}

func isAggressiveOrInvasive(toolName, risk string) bool {
	risk = strings.ToLower(strings.TrimSpace(risk))
	toolName = strings.ToLower(strings.TrimSpace(toolName))

	// Explicit safe/query/read-only tools that never require approval
	switch toolName {
	case "akemi_get_target", "akemi_configure_target", "akemi_configure_defaults",
		"akemi_add_parameters", "akemi_list_parameters", "akemi_clear_context",
		"akemi_list_templates", "akemi_read_report", "akemi_write_report",
		"akemi_get_artifact", "akemi_search_findings", "akemi_get_finding",
		"akemi_run_status", "akemi_cancel_run", "akemi_approve_action",
		"akemi_deny_action", "akemi_summarize_run", "akemi_generate_report",
		"akemi_generate_graph", "akemi_exploit_lookup", "akemi_check_headers",
		"akemi_tech_fingerprint", "akemi_analyze_js", "akemi_discover_api",
		"akemi_subdomain_enum", "akemi_dork":
		return false
	}

	// Check risk classification if provided
	switch risk {
	case "intrusive", "invasive", "active", "high", "destructive", "aggressive":
		return true
	case "safe", "passive", "read_only", "low", "info", "utility", "reporting":
		return false
	}

	// Active scanning/probing/fuzzing tools require approval
	switch toolName {
	case "akemi_probe_vulns", "akemi_auth_capture", "akemi_fuzz", "akemi_full_surface_map",
		"akemi_full_surface_scan", "akemi_port_scan", "akemi_host_discover", "akemi_crawl",
		"akemi_api_hunter", "akemi_scrape_page", "akemi_start_run":
		return true
	}

	return true
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
