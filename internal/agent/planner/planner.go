// Package planner converts high-level security goals into executable task graphs.
// It uses a combination of pre-built plan templates and capability-based decomposition.
package planner

import (
	"fmt"
	"strings"
	"time"

	"Akemi/internal/agent/tool"
)

// DefaultTaskTimeout is used when a tool definition omits an execution bound.
const DefaultTaskTimeout = 60 * time.Second

// Goal describes what the agent should accomplish.
type Goal struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Target      string `json:"target"`
	Intent      string `json:"intent"` // "full_surface_map", "sqli_hunt", "quick_recon", etc.
}

// Plan is a directed acyclic graph (DAG) of tasks to execute.
type Plan struct {
	ID          string        `json:"id"`
	Goal        Goal          `json:"goal"`
	Tasks       []*TaskNode   `json:"tasks"`
	Edges       []*TaskEdge   `json:"edges"`
	Estimated   time.Duration `json:"estimated_duration"`
	RiskSummary string        `json:"risk_summary"`
	CreatedAt   time.Time     `json:"created_at"`
}

// TaskNode represents a single tool invocation within a plan.
type TaskNode struct {
	ID         string                 `json:"id"`
	ToolName   string                 `json:"tool_name"`
	Args       map[string]interface{} `json:"args"`
	Status     TaskStatus             `json:"status"`
	Priority   int                    `json:"priority"` // Lower = higher priority
	RiskLevel  tool.RiskLevel         `json:"risk_level"`
	DependsOn  []string               `json:"depends_on"`
	Timeout    time.Duration          `json:"timeout"`
	MaxRetries int                    `json:"max_retries"`
	Result     *tool.ToolResult       `json:"result,omitempty"`
}

// TaskEdge represents a dependency between two tasks.
type TaskEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	DataFlow string `json:"data_flow"` // What data passes (e.g., "urls", "ports")
}

// TaskStatus tracks where a task is in its lifecycle.
type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"
	TaskReady     TaskStatus = "ready"
	TaskRunning   TaskStatus = "running"
	TaskCompleted TaskStatus = "completed"
	TaskFailed    TaskStatus = "failed"
	TaskDenied    TaskStatus = "denied"
	TaskSkipped   TaskStatus = "skipped" // Dependency failed
)

// PlanTemplate is a pre-built workflow for common security testing goals.
type PlanTemplate struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Intent      string         `json:"intent"`
	Steps       []TemplateStep `json:"steps"`
}

// TemplateStep is a single step in a plan template.
type TemplateStep struct {
	Tool      string                 `json:"tool"`
	Args      map[string]interface{} `json:"args,omitempty"`
	DependsOn int                    `json:"depends_on,omitempty"` // Index of dependency step (-1 = none)
	Priority  int                    `json:"priority"`
}

// Planner converts goals into executable plans.
type Planner struct {
	registry  *tool.Registry
	templates map[string]*PlanTemplate
}

// NewPlanner creates a planner with the given tool registry.
func NewPlanner(registry *tool.Registry) *Planner {
	p := &Planner{
		registry:  registry,
		templates: make(map[string]*PlanTemplate),
	}
	p.registerStandardTemplates()
	return p
}

// Plan creates a task graph from a goal.
func (p *Planner) Plan(goal Goal) (*Plan, error) {
	// Try template-based planning first
	if tmpl, ok := p.templates[goal.Intent]; ok {
		return p.instantiateTemplate(tmpl, goal)
	}

	// Capability-based decomposition
	return p.decomposeByCapabilities(goal)
}

// registerStandardTemplates adds pre-built workflows.
func (p *Planner) registerStandardTemplates() {
	p.templates["full_surface_map"] = &PlanTemplate{
		Name:        "Full Attack Surface Mapping",
		Description: "Complete discovery: subdomains, ports, URLs, params, JS secrets, API endpoints",
		Intent:      "full_surface_map",
		Steps: []TemplateStep{
			{Tool: "akemi_full_surface_map", Priority: 1},
		},
	}

	p.templates["quick_recon"] = &PlanTemplate{
		Name:        "Quick Reconnaissance",
		Description: "Fast triage: port scan top ports, crawl, check headers, fingerprint tech",
		Intent:      "quick_recon",
		Steps: []TemplateStep{
			{Tool: "akemi_port_scan", Priority: 1},
			{Tool: "akemi_crawl", Priority: 2, Args: map[string]interface{}{"depth": 2}},
			{Tool: "akemi_check_headers", Priority: 3},
			{Tool: "akemi_tech_fingerprint", Priority: 3},
		},
	}

	p.templates["sqli_hunt"] = &PlanTemplate{
		Name:        "SQL Injection Hunt",
		Description: "Focused SQLi discovery: crawl, mine params, probe with SQLi templates",
		Intent:      "sqli_hunt",
		Steps: []TemplateStep{
			{Tool: "akemi_crawl", Priority: 1},
			{Tool: "akemi_mine_params", Priority: 2, DependsOn: 0},
			{Tool: "akemi_probe_vulns", Priority: 3, DependsOn: 1,
				Args: map[string]interface{}{"tags": "sqli"}},
		},
	}

	p.templates["vuln_assessment"] = &PlanTemplate{
		Name:        "Vulnerability Assessment",
		Description: "Full vulnerability scan: tech detect, all probe templates, exploit correlation",
		Intent:      "vuln_assessment",
		Steps: []TemplateStep{
			{Tool: "akemi_port_scan", Priority: 1},
			{Tool: "akemi_crawl", Priority: 1},
			{Tool: "akemi_tech_fingerprint", Priority: 2, DependsOn: 0},
			{Tool: "akemi_mine_params", Priority: 2, DependsOn: 1},
			{Tool: "akemi_probe_vulns", Priority: 3, DependsOn: 3},
			{Tool: "akemi_check_headers", Priority: 3},
			{Tool: "akemi_exploit_lookup", Priority: 4, DependsOn: 4},
			{Tool: "akemi_generate_report", Priority: 5, DependsOn: 6},
			{Tool: "akemi_generate_graph", Priority: 5, DependsOn: 6},
		},
	}

	p.templates["api_review"] = &PlanTemplate{
		Name:        "API Security Review",
		Description: "API-focused: discover endpoints, check specs, probe for API vulns",
		Intent:      "api_review",
		Steps: []TemplateStep{
			{Tool: "akemi_discover_api", Priority: 1},
			{Tool: "akemi_crawl", Priority: 1},
			{Tool: "akemi_mine_params", Priority: 2, DependsOn: 1},
			{Tool: "akemi_probe_vulns", Priority: 3, DependsOn: 2,
				Args: map[string]interface{}{"tags": "injection,auth,jwt"}},
			{Tool: "akemi_check_headers", Priority: 3},
		},
	}
}

// instantiateTemplate builds a Plan from a template, filling in the goal's target.
func (p *Planner) instantiateTemplate(tmpl *PlanTemplate, goal Goal) (*Plan, error) {
	plan := &Plan{
		ID:        generateID("plan"),
		Goal:      goal,
		CreatedAt: time.Now(),
	}

	taskByIndex := make(map[int]*TaskNode)

	for i, step := range tmpl.Steps {
		// Validate tool exists
		toolDef, ok := p.registry.Get(step.Tool)
		if !ok {
			return nil, fmt.Errorf("plan template references unknown tool: %s", step.Tool)
		}

		args := make(map[string]interface{})
		for k, v := range step.Args {
			args[k] = v
		}

		// Inject target if not overridden
		if _, hasTarget := args["target"]; !hasTarget {
			if _, hasURL := args["url"]; !hasURL {
				if _, hasDomain := args["domain"]; !hasDomain {
					// Try to figure out the right arg name
					switch step.Tool {
					case "akemi_subdomain_enum":
						args["domain"] = goal.Target
					default:
						args["url"] = goal.Target
					}
				}
			}
		}

		task := taskFromTool(toolDef, args, step.Priority)

		taskByIndex[i] = task
		plan.Tasks = append(plan.Tasks, task)

		// Add dependency edge
		if step.DependsOn >= 0 {
			if dep, ok := taskByIndex[step.DependsOn]; ok {
				task.DependsOn = append(task.DependsOn, dep.ID)
				plan.Edges = append(plan.Edges, &TaskEdge{
					From:     dep.ID,
					To:       task.ID,
					DataFlow: inferDataFlow(dep.ToolName, task.ToolName),
				})
			}
		}
	}

	plan.Estimated = estimateDuration(plan.Tasks)
	plan.RiskSummary = assessPlanRisk(plan.Tasks, p.registry)

	return plan, nil
}

// decomposeByCapabilities builds a plan from scratch based on what tools produce/require.
func (p *Planner) decomposeByCapabilities(goal Goal) (*Plan, error) {
	// Simple capability chain:
	// We look at the goal intent and chain together tools that
	// produce→require the needed data types.

	plan := &Plan{
		ID:        generateID("plan"),
		Goal:      goal,
		CreatedAt: time.Now(),
	}

	intentLower := strings.ToLower(goal.Intent)

	var neededCaps []string
	switch {
	case strings.Contains(intentLower, "sqli") || strings.Contains(intentLower, "injection"):
		neededCaps = []string{"parameters", "vulnerabilities"}
	case strings.Contains(intentLower, "port") || strings.Contains(intentLower, "scan"):
		neededCaps = []string{"open_ports", "services"}
	case strings.Contains(intentLower, "subdomain") || strings.Contains(intentLower, "dns"):
		neededCaps = []string{"subdomains"}
	case strings.Contains(intentLower, "api"):
		neededCaps = []string{"urls", "api_parameters"}
	default:
		neededCaps = []string{"urls", "parameters", "vulnerabilities"}
	}

	// Build a chain: find tools that produce needed capabilities
	var prevTask *TaskNode
	priority := 1

	for _, cap := range neededCaps {
		providers := p.registry.FindByCapability(cap)
		if len(providers) == 0 {
			continue
		}

		// Pick the first provider that doesn't require unavailable data
		t := providers[0]

		args := map[string]interface{}{"url": goal.Target}
		if t.Name == "akemi_subdomain_enum" {
			args = map[string]interface{}{"domain": goal.Target}
		}
		if t.Name == "akemi_port_scan" {
			args = map[string]interface{}{"target": goal.Target}
		}

		task := taskFromTool(t, args, priority)

		if prevTask != nil {
			task.DependsOn = append(task.DependsOn, prevTask.ID)
			plan.Edges = append(plan.Edges, &TaskEdge{
				From:     prevTask.ID,
				To:       task.ID,
				DataFlow: inferDataFlow(prevTask.ToolName, task.ToolName),
			})
		}

		plan.Tasks = append(plan.Tasks, task)
		prevTask = task
		priority++
	}

	plan.Estimated = estimateDuration(plan.Tasks)
	plan.RiskSummary = assessPlanRisk(plan.Tasks, p.registry)

	return plan, nil
}

// =============================================================================
// Helpers
// =============================================================================

func generateID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1000000)
}

func taskFromTool(toolDef *tool.AgentTool, args map[string]interface{}, priority int) *TaskNode {
	timeout := toolDef.DefaultTimeout
	if timeout <= 0 {
		timeout = DefaultTaskTimeout
	}
	maxRetries := toolDef.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}

	return &TaskNode{
		ID:         generateID("task"),
		ToolName:   toolDef.Name,
		Args:       args,
		Status:     TaskPending,
		Priority:   priority,
		RiskLevel:  toolDef.RiskLevel,
		Timeout:    timeout,
		MaxRetries: maxRetries,
	}
}

func inferDataFlow(from, to string) string {
	produces := map[string]string{
		"akemi_port_scan":        "open_ports",
		"akemi_crawl":            "urls",
		"akemi_mine_params":      "parameters",
		"akemi_analyze_js":       "endpoints,secrets",
		"akemi_discover_api":     "api_endpoints",
		"akemi_api_hunter":       "api_endpoints,api_parameters,api_auth_hints",
		"akemi_subdomain_enum":   "subdomains",
		"akemi_tech_fingerprint": "technologies",
		"akemi_probe_vulns":      "vulnerabilities",
	}
	if p, ok := produces[from]; ok {
		return p
	}
	return "data"
}

func estimateDuration(tasks []*TaskNode) time.Duration {
	var total time.Duration
	for _, t := range tasks {
		total += t.Timeout
	}
	return total
}

func assessPlanRisk(tasks []*TaskNode, registry *tool.Registry) string {
	maxRisk := tool.RiskSafe
	for _, t := range tasks {
		if def, ok := registry.Get(t.ToolName); ok {
			if tool.RiskOrder(def.RiskLevel) > tool.RiskOrder(maxRisk) {
				maxRisk = def.RiskLevel
			}
		}
	}
	return string(maxRisk)
}
