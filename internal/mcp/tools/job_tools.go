package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	core "Akemi/internal/core"
	"Akemi/internal/execution"
	"Akemi/internal/mcp"
	mcpstate "Akemi/internal/mcp/state"
)

func handleStartRun(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	_ = ctx
	if svc == nil || svc.Jobs == nil {
		return nil, fmt.Errorf("job manager is not configured")
	}
	job, err := svc.Jobs.StartContext(ctx, svc, getString(args, "kind"), args)
	if err != nil {
		return nil, err
	}
	return jsonContent(fmt.Sprintf("Started %s run %s.", job.Kind, job.ID), job)
}

func handleRunStatus(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	_ = ctx
	runID := getString(args, "run_id")
	if runID == "" {
		return nil, fmt.Errorf("run_id is required")
	}
	job, ok := svc.State.Job(runID)
	if !ok {
		return nil, fmt.Errorf("run not found: %s", runID)
	}
	return jsonContent(fmt.Sprintf("Run %s is %s.", runID, job.Status), job)
}

func handleCancelRun(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	_ = ctx
	runID := getString(args, "run_id")
	if runID == "" {
		return nil, fmt.Errorf("run_id is required")
	}
	cancelled := svc.Jobs.Cancel(runID)
	job, ok := svc.State.Job(runID)
	if ok && cancelled {
		now := time.Now()
		job.Status = "cancelling"
		job.CompletedAt = &now
		job.Error = "cancel requested"
		svc.State.UpsertJob(job)
	}
	return jsonContent(fmt.Sprintf("Cancel requested for %s: %t.", runID, cancelled), map[string]interface{}{
		"run_id":    runID,
		"cancelled": cancelled,
	})
}

func handleApproveAction(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	_ = ctx
	if svc == nil || svc.Execution == nil {
		return nil, fmt.Errorf("approval manager is not configured")
	}
	id := strings.TrimSpace(getString(args, "approval_id"))
	if id == "" {
		return nil, fmt.Errorf("approval_id is required")
	}
	request, ok := svc.Execution.ResolveApproval(id, execution.ApprovalApproved)
	if !ok {
		return nil, fmt.Errorf("approval request not found or already resolved: %s", id)
	}
	return jsonContent(fmt.Sprintf("Approved %s for %s.", request.ID, request.ToolName), request)
}

func handleDenyAction(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	_ = ctx
	if svc == nil || svc.Execution == nil {
		return nil, fmt.Errorf("approval manager is not configured")
	}
	id := strings.TrimSpace(getString(args, "approval_id"))
	if id == "" {
		return nil, fmt.Errorf("approval_id is required")
	}
	request, ok := svc.Execution.ResolveApproval(id, execution.ApprovalDenied)
	if !ok {
		return nil, fmt.Errorf("approval request not found or already resolved: %s", id)
	}
	return jsonContent(fmt.Sprintf("Denied %s for %s.", request.ID, request.ToolName), request)
}
func handleGetArtifact(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	_ = ctx
	artifactID := getString(args, "artifact_id")
	if artifactID == "" {
		return nil, fmt.Errorf("artifact_id is required")
	}
	artifact, ok := svc.State.Artifact(artifactID)
	if !ok {
		return nil, fmt.Errorf("artifact not found: %s", artifactID)
	}
	return jsonContent(fmt.Sprintf("Artifact %s.", artifactID), artifact)
}

func handleSearchFindings(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	_ = ctx
	query := strings.ToLower(strings.TrimSpace(getString(args, "query")))
	severity := strings.ToLower(strings.TrimSpace(getString(args, "severity")))
	findings := collectLatestFindings(svc.State)
	var matches []map[string]interface{}
	for i, finding := range findings {
		if severity != "" && strings.ToLower(stringField(finding, "severity")) != severity {
			continue
		}
		haystack := strings.ToLower(fmt.Sprint(finding))
		if query != "" && !strings.Contains(haystack, query) {
			continue
		}
		item := cloneFinding(finding)
		item["index"] = i
		matches = append(matches, item)
	}
	return jsonContent(fmt.Sprintf("Found %d matching finding(s).", len(matches)), map[string]interface{}{
		"query":    query,
		"severity": severity,
		"findings": matches,
	})
}

func handleGetFinding(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	_ = ctx
	findings := collectLatestFindings(svc.State)
	id := getString(args, "id")
	index := getInt(args, "index", -1)
	if id != "" {
		for i, finding := range findings {
			if stringField(finding, "id") == id {
				item := cloneFinding(finding)
				item["index"] = i
				return jsonContent("Finding "+id+".", item)
			}
		}
		return nil, fmt.Errorf("finding not found: %s", id)
	}
	if index >= 0 && index < len(findings) {
		item := cloneFinding(findings[index])
		item["index"] = index
		return jsonContent(fmt.Sprintf("Finding at index %d.", index), item)
	}
	return nil, fmt.Errorf("id or valid index is required")
}

func handleSummarizeRun(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	_ = ctx
	runID := getString(args, "run_id")
	if runID != "" {
		job, ok := svc.State.Job(runID)
		if !ok {
			return nil, fmt.Errorf("run not found: %s", runID)
		}
		return jsonContent(fmt.Sprintf("Run %s summary: %s.", runID, firstNonBlank(job.Summary, job.Status)), job)
	}
	snapshot := svc.State.Snapshot(context.Background())
	findings := collectLatestFindings(svc.State)
	summary := map[string]interface{}{
		"findings":      len(findings),
		"known_jobs":    len(svc.State.Jobs()),
		"resource_uris": []string{"akemi://scan/current/summary", "akemi://scan/current/vulnerabilities"},
		"runtime_state": snapshot["last_tool"],
	}
	return jsonContent(fmt.Sprintf("Latest Akemi MCP state: %d finding(s), %d job(s).", len(findings), len(svc.State.Jobs())), summary)
}

func collectLatestFindings(store *mcpstate.Store) []map[string]interface{} {
	if store == nil {
		return nil
	}
	var findings []map[string]interface{}
	for _, toolName := range []string{
		"akemi_full_surface_map", "akemi_full_surface_scan", "akemi_quick_recon", "akemi_api_hunter",
		"akemi_probe_vulns", "akemi_check_headers", "akemi_tech_fingerprint", "akemi_crawl",
		"akemi_port_scan", "akemi_mine_params", "akemi_analyze_js", "akemi_discover_api",
	} {
		collectFindings(store.LastStructured(toolName), &findings)
	}
	return findings
}

func collectFindings(value interface{}, out *[]map[string]interface{}) {
	switch v := value.(type) {
	case map[string]interface{}:
		for key, item := range v {
			lower := strings.ToLower(key)
			if lower == "vuln_findings" || lower == "findings" || lower == "vulnerabilities" || lower == "header_findings" {
				appendFindingListAny(item, out)
				continue
			}
			collectFindings(item, out)
		}
	case []interface{}:
		appendFindingList(v, out)
	case []core.VulnFinding:
		appendFindingListAny(v, out)
	case []map[string]interface{}:
		appendFindingListAny(v, out)
	}
}

func appendFindingListAny(item interface{}, out *[]map[string]interface{}) {
	if list, ok := item.([]interface{}); ok {
		appendFindingList(list, out)
	} else if vf, ok := item.([]core.VulnFinding); ok {
		for _, f := range vf {
			*out = append(*out, map[string]interface{}{
				"id":          f.ID,
				"name":        f.Name,
				"severity":    f.Severity,
				"description": f.Description,
				"target":      f.Target,
				"evidence":    f.Evidence,
				"remediation": f.Remediation,
			})
		}
	} else if ms, ok := item.([]map[string]interface{}); ok {
		for _, m := range ms {
			if stringField(m, "severity") != "" || stringField(m, "name") != "" || stringField(m, "title") != "" {
				*out = append(*out, cloneFinding(m))
			}
		}
	}
}

func appendFindingList(list []interface{}, out *[]map[string]interface{}) {
	for _, item := range list {
		if m, ok := item.(map[string]interface{}); ok {
			if stringField(m, "severity") != "" || stringField(m, "name") != "" || stringField(m, "title") != "" {
				*out = append(*out, cloneFinding(m))
			}
		}
	}
}

func cloneFinding(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func stringField(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}
