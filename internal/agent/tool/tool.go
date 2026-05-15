// Package tool provides agent-specific tool definitions with risk metadata,
// dependency tracking, and safety classification. It wraps the MCP tool layer
// with additional context needed for autonomous agent operation.
package tool

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Category classifies tools for the planner.
type Category string

const (
	CategoryRecon         Category = "reconnaissance"
	CategoryDiscovery     Category = "discovery"
	CategoryVulnerability Category = "vulnerability_validation"
	CategoryExploitation  Category = "exploitation"
	CategoryReporting     Category = "reporting"
	CategoryUtility       Category = "utility"
)

// RiskLevel indicates how dangerous a tool is to run autonomously.
type RiskLevel string

const (
	RiskSafe        RiskLevel = "safe"        // Read-only, no target interaction (e.g., list templates)
	RiskPassive     RiskLevel = "passive"     // Passive recon (DNS, crtsh — no direct target contact)
	RiskActive      RiskLevel = "active"      // Active but non-intrusive (connect scan, crawl)
	RiskIntrusive   RiskLevel = "intrusive"   // Potentially noticeable (vuln probes, fuzzing)
	RiskDestructive RiskLevel = "destructive" // Could cause damage (RCE probes, auth bypass attempts)
)

// ParseRiskLevel converts a user/config string into a known risk level.
func ParseRiskLevel(value string) (RiskLevel, error) {
	switch RiskLevel(strings.ToLower(strings.TrimSpace(value))) {
	case RiskSafe:
		return RiskSafe, nil
	case RiskPassive:
		return RiskPassive, nil
	case RiskActive, "":
		return RiskActive, nil
	case RiskIntrusive:
		return RiskIntrusive, nil
	case RiskDestructive:
		return RiskDestructive, nil
	default:
		return "", fmt.Errorf("unknown risk level %q", value)
	}
}

// RiskOrder returns a comparable ordering for autonomous approval checks.
func RiskOrder(r RiskLevel) int {
	switch r {
	case RiskSafe:
		return 0
	case RiskPassive:
		return 1
	case RiskActive:
		return 2
	case RiskIntrusive:
		return 3
	case RiskDestructive:
		return 4
	default:
		return 2
	}
}

// RiskAllowed reports whether actual is within the approved risk ceiling.
func RiskAllowed(maxApproved, actual RiskLevel) bool {
	return RiskOrder(actual) <= RiskOrder(maxApproved)
}

// AgentTool wraps a callable tool with metadata needed for autonomous planning
// and execution. It extends the MCP tool concept with safety and dependency info.
type AgentTool struct {
	// Identity
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Category    Category `json:"category"`

	// Schema for the LLM / planner
	Description string                 `json:"description"`
	Parameters  map[string]ParamSchema `json:"parameters"`
	Required    []string               `json:"required,omitempty"`

	// Risk metadata
	RiskLevel        RiskLevel `json:"risk_level"`
	IsIdempotent     bool      `json:"is_idempotent"`
	IsDestructive    bool      `json:"is_destructive"`
	RequiresApproval bool      `json:"requires_approval"` // Human-in-the-loop for this tool?

	// Capability contract
	Provides []string `json:"provides"` // Data types this tool produces (e.g., "urls", "ports", "params")
	Requires []string `json:"requires"` // Data types this tool needs as input

	// Execution bounds
	DefaultTimeout time.Duration `json:"default_timeout"`
	MaxRetries     int           `json:"max_retries"`

	// The actual handler
	Handler ToolHandler
}

// ParamSchema describes a single parameter for agent-side validation.
type ParamSchema struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Default     interface{} `json:"default,omitempty"`
	Required    bool        `json:"required,omitempty"`
}

// ToolHandler is the function signature for agent tool execution.
// It receives the context and a map of resolved arguments.
type ToolHandler func(ctx context.Context, args map[string]interface{}) (*ToolResult, error)

// ToolResult is the structured output of a tool execution.
type ToolResult struct {
	ToolName string                 `json:"tool_name"`
	Status   ResultStatus           `json:"status"`
	Summary  string                 `json:"summary"`
	Data     map[string]interface{} `json:"data"`
	Findings []Finding              `json:"findings,omitempty"`
	Metrics  ToolMetrics            `json:"metrics"`
	Error    string                 `json:"error,omitempty"`
}

// ResultStatus indicates tool outcome.
type ResultStatus string

const (
	StatusSuccess ResultStatus = "success"
	StatusPartial ResultStatus = "partial" // Completed but with caveats
	StatusError   ResultStatus = "error"
	StatusDenied  ResultStatus = "denied" // Safety guard blocked execution
	StatusTimeout ResultStatus = "timeout"
)

// Finding is a standardized security discovery across all tools.
type Finding struct {
	ID          string                 `json:"id"`
	ToolName    string                 `json:"tool_name"`
	Type        string                 `json:"type"`     // "open_port", "vulnerability", "secret", "endpoint", etc.
	Severity    string                 `json:"severity"` // critical|high|medium|low|info
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Evidence    string                 `json:"evidence"`
	Target      string                 `json:"target"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ToolMetrics captures execution statistics.
type ToolMetrics struct {
	DurationMs   int64 `json:"duration_ms"`
	RequestsSent int   `json:"requests_sent,omitempty"`
	ItemsFound   int   `json:"items_found"`
	ItemsTested  int   `json:"items_tested,omitempty"`
}

// Registry holds all agent tools and provides lookup by name or capability.
type Registry struct {
	tools     map[string]*AgentTool
	byProvide map[string][]string // capability → tool names
}

// NewRegistry creates an empty tool registry.
func NewRegistry() *Registry {
	return &Registry{
		tools:     make(map[string]*AgentTool),
		byProvide: make(map[string][]string),
	}
}

// Register adds a tool to the registry.
func (r *Registry) Register(t *AgentTool) {
	r.tools[t.Name] = t
	for _, cap := range t.Provides {
		r.byProvide[cap] = append(r.byProvide[cap], t.Name)
	}
}

// Get returns a tool by name.
func (r *Registry) Get(name string) (*AgentTool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// FindByCapability returns tools that provide the given capability.
func (r *Registry) FindByCapability(capability string) []*AgentTool {
	names := r.byProvide[capability]
	tools := make([]*AgentTool, 0, len(names))
	for _, name := range names {
		if t, ok := r.tools[name]; ok {
			tools = append(tools, t)
		}
	}
	return tools
}

// FindByRequired returns tools that require the given capability as input.
func (r *Registry) FindByRequired(capability string) []*AgentTool {
	var tools []*AgentTool
	for _, t := range r.tools {
		for _, req := range t.Requires {
			if req == capability {
				tools = append(tools, t)
			}
		}
	}
	return tools
}

// All returns all registered tools.
func (r *Registry) All() []*AgentTool {
	tools := make([]*AgentTool, 0, len(r.tools))
	for _, t := range r.tools {
		tools = append(tools, t)
	}
	return tools
}

// Count returns the number of registered tools.
func (r *Registry) Count() int {
	return len(r.tools)
}
