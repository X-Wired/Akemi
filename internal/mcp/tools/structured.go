package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"Akemi/internal/mcp"
	mcpstate "Akemi/internal/mcp/state"
)

// CallStructured invokes a tool and returns modern MCP structuredContent.
func (r *ToolRegistry) CallStructured(ctxIface interface{}, name string, args map[string]interface{}) (*mcp.ToolCallResult, error) {
	ctx, _ := ctxIface.(context.Context)
	if ctx == nil {
		ctx = context.Background()
	}
	rt, ok := r.tools[name]
	if !ok {
		return nil, fmt.Errorf("tool not found: %s", name)
	}
	blocks, err := rt.Handler(ctx, args, r.services)
	if err != nil {
		return nil, err
	}
	summary, structured, content := structuredResultFromBlocks(blocks)
	if structured == nil {
		structured = map[string]interface{}{"summary": summary}
	}
	if r.services != nil && r.services.State != nil {
		r.services.State.RecordToolResult(name, summary, structured)
	}
	return &mcp.ToolCallResult{
		Content:           content,
		StructuredContent: structured,
		Meta: map[string]interface{}{
			"akemi/tool": name,
			"akemi/resource_uris": []string{
				"akemi://scan/current/summary",
			},
		},
	}, nil
}

func structuredResultFromBlocks(blocks []mcp.ContentBlock) (string, map[string]interface{}, []mcp.ContentBlock) {
	out := make([]mcp.ContentBlock, 0, len(blocks))
	var fullText []string
	var structured map[string]interface{}
	for _, block := range blocks {
		if block.Type != "" && block.Type != "text" {
			out = append(out, block)
			continue
		}
		text := strings.TrimSpace(block.Text)
		if text == "" {
			continue
		}
		summary := text
		if before, raw, ok := strings.Cut(text, "\n--- RAW JSON ---"); ok {
			summary = strings.TrimSpace(before)
			if parsed := parseStructuredJSON(raw); parsed != nil {
				structured = parsed
			}
		} else if before, raw, ok := strings.Cut(text, "\n\n{"); ok {
			candidate := "{" + raw
			if parsed := parseStructuredJSON(candidate); parsed != nil {
				summary = strings.TrimSpace(before)
				structured = parsed
			}
		}
		if summary != "" {
			out = append(out, mcp.TextContent(summary))
			fullText = append(fullText, summary)
		}
	}
	summary := strings.TrimSpace(strings.Join(fullText, "\n"))
	return summary, structured, out
}

func parseStructuredJSON(raw string) map[string]interface{} {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var decoded interface{}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil
	}
	switch v := decoded.(type) {
	case map[string]interface{}:
		return v
	default:
		return map[string]interface{}{"result": v}
	}
}

func decorateTool(tool *mcp.Tool) {
	if tool == nil {
		return
	}
	tool.Title = toolTitle(tool.Name)
	tool.Risk = toolRisk(tool.Name)
	tool.Category = toolCategory(tool.Name)
	tool.Provides = toolProvides(tool.Name)
	tool.Requires = toolRequires(tool.Name)
	tool.AssistantHidden = assistantHidden(tool.Name)
	tool.OutputSchema = &mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]mcp.Property{
			"summary": {Type: "string", Description: "Concise human-readable result summary"},
		},
	}
	tool.Annotations = &mcp.ToolAnnotations{
		Title:           tool.Title,
		ReadOnlyHint:    boolRef(tool.Risk == "safe" || tool.Risk == "passive"),
		DestructiveHint: boolRef(tool.Risk == "destructive"),
		IdempotentHint:  boolRef(toolRiskIdempotent(tool.Name)),
		OpenWorldHint:   boolRef(tool.Risk != "safe"),
	}
	tool.Meta = map[string]interface{}{
		"akemi/risk":              tool.Risk,
		"akemi/category":          tool.Category,
		"akemi/provides":          tool.Provides,
		"akemi/requires":          tool.Requires,
		"akemi/assistant_visible": !tool.AssistantHidden,
	}
}

func toolTitle(name string) string {
	trimmed := strings.TrimPrefix(name, "akemi_")
	parts := strings.Split(trimmed, "_")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func toolRisk(name string) string {
	switch name {
	case "akemi_configure_target", "akemi_get_target", "akemi_configure_defaults", "akemi_add_parameters", "akemi_list_parameters", "akemi_clear_context", "akemi_list_templates", "akemi_read_report", "akemi_write_report", "akemi_start_run", "akemi_run_status", "akemi_cancel_run", "akemi_get_artifact", "akemi_search_findings", "akemi_get_finding", "akemi_summarize_run":
		return "safe"
	case "akemi_probe_vulns", "akemi_fuzz", "akemi_auth_capture":
		return "intrusive"
	case "akemi_port_scan", "akemi_host_discover", "akemi_crawl", "akemi_scrape_page", "akemi_full_surface_map":
		return "active"
	default:
		return "passive"
	}
}

func toolCategory(name string) string {
	switch name {
	case "akemi_port_scan", "akemi_host_discover", "akemi_subdomain_enum", "akemi_dork":
		return "reconnaissance"
	case "akemi_crawl", "akemi_full_surface_map", "akemi_mine_params", "akemi_analyze_js", "akemi_scrape_page", "akemi_discover_api", "akemi_api_hunter", "akemi_tech_fingerprint":
		return "discovery"
	case "akemi_probe_vulns", "akemi_check_headers", "akemi_auth_capture":
		return "vulnerability_validation"
	case "akemi_generate_report", "akemi_generate_graph", "akemi_read_report", "akemi_write_report":
		return "reporting"
	case "akemi_start_run", "akemi_run_status", "akemi_cancel_run", "akemi_get_artifact", "akemi_search_findings", "akemi_get_finding", "akemi_summarize_run":
		return "utility"
	default:
		return "utility"
	}
}

func toolProvides(name string) []string {
	switch name {
	case "akemi_port_scan":
		return []string{"open_ports", "services", "banners", "technologies"}
	case "akemi_host_discover":
		return []string{"hosts"}
	case "akemi_subdomain_enum":
		return []string{"subdomains"}
	case "akemi_crawl":
		return []string{"urls"}
	case "akemi_full_surface_map":
		return []string{"surface_map", "open_ports", "urls", "parameters", "api_endpoints", "subdomains", "findings", "secrets"}
	case "akemi_mine_params":
		return []string{"parameters"}
	case "akemi_analyze_js":
		return []string{"endpoints", "secrets", "hidden_params"}
	case "akemi_discover_api":
		return []string{"api_endpoints", "api_specs"}
	case "akemi_api_hunter":
		return []string{"api_endpoints", "api_specs", "api_parameters", "api_auth_hints"}
	case "akemi_probe_vulns", "akemi_check_headers":
		return []string{"findings"}
	case "akemi_auth_capture":
		return []string{"auth_session", "session_cookies", "csrf_tokens"}
	case "akemi_generate_report", "akemi_write_report":
		return []string{"report"}
	case "akemi_generate_graph":
		return []string{"graph"}
	default:
		return nil
	}
}

func toolRequires(name string) []string {
	switch name {
	case "akemi_mine_params", "akemi_analyze_js", "akemi_discover_api", "akemi_api_hunter":
		return []string{"urls"}
	case "akemi_probe_vulns":
		return []string{"parameters"}
	case "akemi_exploit_lookup":
		return []string{"technologies", "services"}
	default:
		return nil
	}
}

func assistantHidden(name string) bool {
	switch name {
	case "akemi_exploit_lookup", "akemi_fuzz", "akemi_auth_capture":
		return true
	default:
		return false
	}
}

func toolRiskIdempotent(name string) bool {
	switch name {
	case "akemi_crawl", "akemi_full_surface_map", "akemi_mine_params", "akemi_analyze_js", "akemi_discover_api", "akemi_api_hunter", "akemi_probe_vulns", "akemi_fuzz", "akemi_auth_capture", "akemi_write_report":
		return false
	default:
		return true
	}
}

func boolRef(value bool) *bool {
	return &value
}

// JobManager runs coarse-grained MCP jobs and stores their state.
type JobManager struct {
	state   *mcpstate.Store
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

// NewJobManager creates a job manager.
func NewJobManager(state *mcpstate.Store) *JobManager {
	return &JobManager{state: state, cancels: make(map[string]context.CancelFunc)}
}

// Start launches a supported job.
func (jm *JobManager) Start(svc *Services, kind string, args map[string]interface{}) (mcpstate.JobRecord, error) {
	if jm == nil {
		return mcpstate.JobRecord{}, fmt.Errorf("job manager is not configured")
	}
	if kind == "" {
		kind = "full_surface_map"
	}
	if kind != "full_surface_map" {
		return mcpstate.JobRecord{}, fmt.Errorf("unsupported job kind %q", kind)
	}
	id := fmt.Sprintf("run-%d", time.Now().UnixNano())
	ctx, cancel := context.WithCancel(context.Background())
	job := mcpstate.JobRecord{
		ID:        id,
		Kind:      kind,
		Status:    "running",
		Target:    firstNonBlank(getString(args, "target"), getString(args, "url"), activeTargetBaseURL(context.Background(), svc)),
		StartedAt: time.Now(),
		Progress:  "queued",
	}
	jm.mu.Lock()
	jm.cancels[id] = cancel
	jm.mu.Unlock()
	jm.state.UpsertJob(job)

	go func() {
		blocks, err := handleFullSurfaceMap(ctx, args, svc)
		summary, structured, _ := structuredResultFromBlocks(blocks)
		now := time.Now()
		job.CompletedAt = &now
		job.Summary = summary
		job.Result = structured
		if err != nil {
			job.Status = "failed"
			job.Error = err.Error()
		} else if ctx.Err() != nil {
			job.Status = "cancelled"
			job.Error = ctx.Err().Error()
		} else {
			job.Status = "completed"
			job.Progress = "completed"
			jm.state.RecordToolResult("akemi_full_surface_map", summary, structured)
		}
		jm.state.UpsertJob(job)
		jm.mu.Lock()
		delete(jm.cancels, id)
		jm.mu.Unlock()
	}()

	return job, nil
}

// Cancel cancels a running job.
func (jm *JobManager) Cancel(id string) bool {
	if jm == nil {
		return false
	}
	jm.mu.Lock()
	cancel := jm.cancels[id]
	jm.mu.Unlock()
	if cancel == nil {
		return false
	}
	cancel()
	return true
}
