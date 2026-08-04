package tools

import (
	"context"

	"encoding/json"

	"fmt"

	"strings"

	"sync"

	"time"

	"Akemi/internal/execution"

	"Akemi/internal/mcp"

	"Akemi/internal/results"
	"Akemi/internal/toolmeta"

	mcpstate "Akemi/internal/mcp/state"
)

// CallStructured invokes a tool and returns modern MCP structuredContent.
func (r *ToolRegistry) CallStructured(ctxIface interface{}, name string, args map[string]interface{}) (*mcp.ToolCallResult, error) {
	ctx, _ := ctxIface.(context.Context)
	if ctx == nil {
		ctx = context.Background()
	}
	name = canonicalToolName(name)
	if _, ok := r.tools[name]; !ok {
		return nil, fmt.Errorf("tool not found: %s", name)
	}

	holder := &runIDHolder{}
	ctx = context.WithValue(ctx, runIDKey{}, holder)
	blocks, callErr := r.executeTool(ctx, name, args)
	status := execution.RunCompleted
	if callErr != nil {
		status = structuredStatus(ctx, callErr)
	}
	if len(blocks) == 0 && callErr != nil {
		blocks = []mcp.ContentBlock{mcp.ErrorContent(callErr)}
	}

	summary, structured, content := structuredResultFromBlocks(blocks)
	if structured == nil {
		structured = map[string]interface{}{"summary": summary}
	}
	if summary == "" && callErr != nil {
		summary = callErr.Error()
	}
	redactedValue, notices := results.Redact(structured)
	redacted, ok := redactedValue.(map[string]interface{})
	if !ok {
		redacted = map[string]interface{}{"result": redactedValue}
	}
	envelope := results.New(name, holder.ID, status, summary, redacted)
	envelope.Redactions = notices
	if callErr != nil {
		envelope.Errors = []results.StageError{{Stage: name, Message: redactError(callErr.Error()), Partial: len(content) > 0}}
	}
	content = redactContentBlocks(content)
	structured = results.WithLegacyFields(redacted, envelope)
	if r.services != nil && r.services.State != nil {
		r.services.State.RecordToolResult(name, summary, structured)
	}
	return &mcp.ToolCallResult{
		Content:           content,
		StructuredContent: structured,
		IsError:           callErr != nil,
		Meta: map[string]interface{}{
			"akemi/tool":           name,
			"akemi/schema_version": results.SchemaVersion,
			"akemi/status":         status,
			"akemi/resource_uris": []string{
				"akemi://scan/current/summary",
			},
		},
	}, nil
}

func structuredStatus(ctx context.Context, err error) execution.RunStatus {
	if ctx != nil {
		switch ctx.Err() {
		case context.Canceled:
			return execution.RunCancelled
		case context.DeadlineExceeded:
			return execution.RunTimeout
		}
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "approval") {
		return execution.RunApprovalRequired
	}
	if strings.Contains(message, "outside") || strings.Contains(message, "scope") || strings.Contains(message, "risk") || strings.Contains(message, "denied") {
		return execution.RunDenied
	}
	if err != nil {
		return execution.RunFailed
	}
	return execution.RunCompleted
}

func redactError(message string) string {
	value, _ := results.Redact(message)
	if redacted, ok := value.(string); ok {
		return redacted
	}
	return message
}
func redactContentBlocks(blocks []mcp.ContentBlock) []mcp.ContentBlock {
	out := append([]mcp.ContentBlock(nil), blocks...)
	for i := range out {
		if out[i].Text == "" {
			continue
		}
		value, _ := results.Redact(out[i].Text)
		if text, ok := value.(string); ok {
			out[i].Text = text
		}
	}
	return out
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

func standardOutputSchema() *mcp.ToolInputSchema {
	return &mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]mcp.Property{
			"summary":    {Type: "string", Description: "Concise human-readable result summary"},
			"status":     {Type: "string", Description: "Run lifecycle status"},
			"run_id":     {Type: "string", Description: "Shared execution run identifier"},
			"data":       {Type: "object", Description: "Tool-specific structured data"},
			"findings":   {Type: "array", Items: &mcp.Property{Type: "object"}, Description: "Evidence-backed findings"},
			"errors":     {Type: "array", Items: &mcp.Property{Type: "object"}, Description: "Stage errors and warnings"},
			"metrics":    {Type: "object", Description: "Execution metrics and budget counters"},
			"redactions": {Type: "array", Items: &mcp.Property{Type: "object"}, Description: "Redaction notices"},
			"_akemi":     {Type: "object", Description: "Versioned Akemi result metadata"},
		},
	}
}

func toolReadOnly(name string) bool {
	if descriptor, ok := toolmeta.Lookup(name); ok {
		return descriptor.ReadOnly
	}
	switch name {
	case "akemi_configure_target", "akemi_configure_defaults", "akemi_add_parameters", "akemi_clear_context", "akemi_write_report", "akemi_start_run", "akemi_cancel_run":
		return false
	default:
		return true
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
	tool.OutputSchema = standardOutputSchema()

	tool.Annotations = &mcp.ToolAnnotations{
		Title:           tool.Title,
		ReadOnlyHint:    boolRef(toolReadOnly(tool.Name)),
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
	if descriptor, ok := toolmeta.Lookup(name); ok {
		return string(descriptor.Risk)
	}
	switch name {
	case "akemi_configure_target", "akemi_get_target", "akemi_configure_defaults", "akemi_add_parameters", "akemi_list_parameters", "akemi_clear_context", "akemi_list_templates", "akemi_read_report", "akemi_write_report", "akemi_read_project_findings", "akemi_start_run", "akemi_run_status", "akemi_cancel_run", "akemi_get_artifact", "akemi_search_findings", "akemi_get_finding", "akemi_summarize_run":
		return "safe"
	case "akemi_probe_vulns", "akemi_fuzz", "akemi_auth_capture":
		return "intrusive"
	case "akemi_port_scan", "akemi_host_discover", "akemi_crawl", "akemi_scrape_page", "akemi_full_surface_map", "akemi_full_surface_scan", "akemi_api_hunter":
		return "active"
	default:
		return "passive"
	}
}

func toolCategory(name string) string {
	if descriptor, ok := toolmeta.Lookup(name); ok {
		return string(descriptor.Category)
	}
	switch name {
	case "akemi_port_scan", "akemi_host_discover", "akemi_subdomain_enum", "akemi_dork":
		return "reconnaissance"
	case "akemi_crawl", "akemi_full_surface_map", "akemi_full_surface_scan", "akemi_mine_params", "akemi_analyze_js", "akemi_scrape_page", "akemi_discover_api", "akemi_api_hunter", "akemi_tech_fingerprint":
		return "discovery"
	case "akemi_probe_vulns", "akemi_check_headers", "akemi_auth_capture":
		return "vulnerability_validation"
	case "akemi_generate_report", "akemi_generate_graph", "akemi_read_report", "akemi_write_report", "akemi_read_project_findings":
		return "reporting"
	case "akemi_start_run", "akemi_run_status", "akemi_cancel_run", "akemi_get_artifact", "akemi_search_findings", "akemi_get_finding", "akemi_summarize_run":
		return "utility"
	default:
		return "utility"
	}
}

func toolProvides(name string) []string {
	if descriptor, ok := toolmeta.Lookup(name); ok {
		return append([]string(nil), descriptor.Provides...)
	}
	switch name {
	case "akemi_port_scan":
		return []string{"open_ports", "services", "banners", "technologies"}
	case "akemi_host_discover":
		return []string{"hosts"}
	case "akemi_subdomain_enum":
		return []string{"subdomains"}
	case "akemi_crawl":
		return []string{"urls"}
	case "akemi_full_surface_map", "akemi_full_surface_scan":
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
	if descriptor, ok := toolmeta.Lookup(name); ok {
		return append([]string(nil), descriptor.Requires...)
	}
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
	if descriptor, ok := toolmeta.Lookup(name); ok {
		return !descriptor.AssistantVisible
	}
	switch name {
	case "akemi_exploit_lookup", "akemi_fuzz", "akemi_auth_capture":
		return true
	default:
		return false
	}
}

func toolRiskIdempotent(name string) bool {
	if descriptor, ok := toolmeta.Lookup(name); ok {
		return descriptor.Idempotent
	}
	switch name {
	case "akemi_crawl", "akemi_full_surface_map", "akemi_full_surface_scan", "akemi_mine_params", "akemi_analyze_js", "akemi_discover_api", "akemi_api_hunter", "akemi_probe_vulns", "akemi_fuzz", "akemi_auth_capture", "akemi_write_report":
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
	state     *mcpstate.Store
	execution *execution.Manager
	policy    execution.ExecutionPolicy
	mu        sync.Mutex
	cancels   map[string]context.CancelFunc
}

// NewJobManager creates a job manager.
func NewJobManager(state *mcpstate.Store) *JobManager {
	return &JobManager{state: state, execution: execution.NewManager(100), policy: execution.DefaultPolicy(), cancels: make(map[string]context.CancelFunc)}
}

// Start launches a supported job.
func (jm *JobManager) Start(svc *Services, kind string, args map[string]interface{}) (mcpstate.JobRecord, error) {
	return jm.StartContext(context.Background(), svc, kind, args)
}

func (jm *JobManager) StartContext(parent context.Context, svc *Services, kind string, args map[string]interface{}) (mcpstate.JobRecord, error) {
	if jm == nil {
		return mcpstate.JobRecord{}, fmt.Errorf("job manager is not configured")
	}
	if parent == nil {
		parent = context.Background()
	}
	if kind == "" {
		kind = "full_surface_map"
	}
	kind = canonicalRunKind(kind)
	if kind != "full_surface_map" {
		return mcpstate.JobRecord{}, fmt.Errorf("unsupported job kind %q", kind)
	}
	if svc == nil || svc.Context == nil {
		return mcpstate.JobRecord{}, fmt.Errorf("target context is not configured")
	}
	active, err := svc.Context.GetActiveTarget(parent)
	if err != nil {
		return mcpstate.JobRecord{}, err
	}
	if active == nil {
		return mcpstate.JobRecord{}, fmt.Errorf("target scope is not configured; call akemi_configure_target first")
	}
	target := firstNonBlank(getString(args, "target"), getString(args, "url"), active.BaseURL, active.Domain)
	scope := execution.NormalizeScope(execution.ScopePolicy{}, *active)
	if err := execution.ValidateTarget(scope, target); err != nil {
		return mcpstate.JobRecord{}, err
	}

	id := execution.NewRunID("run")
	runCtx, err := execution.NewRunContext(id, *active, scope, jm.policy)
	if err != nil {
		return mcpstate.JobRecord{}, err
	}
	if _, err := jm.execution.Start(runCtx, "akemi_"+kind); err != nil {
		return mcpstate.JobRecord{}, err
	}

	ctx, cancel := context.WithCancel(execution.WithRunContext(parent, runCtx))
	job := mcpstate.JobRecord{
		ID:        id,
		Kind:      kind,
		Status:    "running",
		Target:    target,
		StartedAt: time.Now(),
		Progress:  "queued",
	}
	jm.mu.Lock()
	jm.cancels[id] = cancel
	jm.mu.Unlock()
	jm.state.UpsertJob(job)

	go func() {
		blocks, runErr := handleFullSurfaceMap(ctx, args, svc)
		summary, structured, _ := structuredResultFromBlocks(blocks)
		now := time.Now()
		job.CompletedAt = &now
		job.Summary = summary
		job.Result = structured
		status := execution.RunCompleted
		if runErr != nil {
			job.Status = "partial"
			job.Error = runErr.Error()
			status = execution.RunPartial
		} else if ctx.Err() != nil {
			job.Status = "cancelled"
			job.Error = ctx.Err().Error()
			status = execution.RunCancelled
		} else {
			job.Status = "completed"
			job.Progress = "completed"
			jm.state.RecordToolResult("akemi_full_surface_map", summary, structured)
		}
		jm.state.UpsertJob(job)
		_ = jm.execution.Finish(id, status, summary, runErr)
		jm.mu.Lock()
		delete(jm.cancels, id)
		jm.mu.Unlock()
	}()

	return job, nil
}
func canonicalRunKind(kind string) string {
	switch strings.TrimSpace(kind) {
	case "full_surface_scan", "akemi_full_surface_scan", "akemi_full_surface_map":
		return "full_surface_map"
	default:
		return kind
	}
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
