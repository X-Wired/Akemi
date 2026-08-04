package tools

import (
	"context"
	"fmt"
	"strings"

	agenttool "Akemi/internal/agent/tool"
	"Akemi/internal/engagement"
	"Akemi/internal/execution"
	"Akemi/internal/mcp"
)

type runContextKey struct{}
type runIDKey struct{}
type runIDHolder struct{ ID string }

// RunContextFromContext exposes the shared run metadata to handlers that need
// to attach run IDs or metrics without coupling them to the registry.
func RunContextFromContext(ctx context.Context) (*execution.RunContext, bool) {
	return execution.RunContextFromContext(ctx)
}

func (r *ToolRegistry) executeTool(ctx context.Context, name string, args map[string]interface{}) ([]mcp.ContentBlock, error) {
	rt, ok := r.tools[name]
	if !ok {
		return nil, fmt.Errorf("tool not found: %s", name)
	}
	if err := validateToolArgs(rt.Tool.InputSchema, args); err != nil {
		return nil, err
	}
	if r.services == nil || r.execution == nil || isContextOnlyTool(name) {
		return rt.Handler(ctx, args, r.services)
	}

	active, err := r.services.Context.GetActiveTarget(ctx)
	if err != nil {
		return nil, err
	}
	if active == nil {
		return nil, fmt.Errorf("target scope is not configured; call akemi_configure_target first")
	}

	scope := execution.NormalizeScope(execution.ScopePolicy{}, *active)
	targets := toolTargets(name, args, *active)
	if len(targets) == 0 {
		return nil, fmt.Errorf("target is required for %s", name)
	}
	if err := execution.ValidateTargets(scope, targets); err != nil {
		return nil, err
	}
	runID := execution.NewRunID("run")
	runCtx, err := execution.NewRunContext(runID, *active, scope, r.policy)
	if err != nil {
		return nil, err
	}
	if holder, ok := ctx.Value(runIDKey{}).(*runIDHolder); ok && holder != nil {
		holder.ID = runID
	}

	actual, parseErr := agenttool.ParseRiskLevel(rt.Tool.Risk)
	if parseErr != nil {
		actual = agenttool.RiskActive
	}
	approvalID := strings.TrimSpace(getString(args, "approval_id"))
	riskErr := execution.ValidateRisk(r.policy, actual)
	if riskErr != nil && actual == agenttool.RiskDestructive && approvalID != "" && r.execution.IsApprovalApproved(approvalID, name, targets[0]) {
		approvedPolicy := r.policy
		approvedPolicy.MaxRisk = agenttool.RiskDestructive
		approvedPolicy.AllowDestructive = true
		riskErr = execution.ValidateRisk(approvedPolicy, actual)
	}
	if riskErr != nil {
		if actual == agenttool.RiskDestructive && strings.Contains(strings.ToLower(riskErr.Error()), "destructive") {
			if request, requestErr := r.execution.RequestApproval(runCtx, name, targets[0], args); requestErr == nil {
				return nil, fmt.Errorf("approval required: %s", request.ID)
			}
		}
		return nil, riskErr
	}
	if _, err := r.execution.Start(runCtx, name); err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, r.policy.MaxToolDuration)
	defer cancel()
	callCtx = execution.WithRunContext(callCtx, runCtx)
	blocks, callErr := rt.Handler(callCtx, args, r.services)
	status := execution.RunCompleted
	if callErr != nil {
		switch {
		case callCtx.Err() == context.Canceled:
			status = execution.RunCancelled
		case callCtx.Err() == context.DeadlineExceeded:
			status = execution.RunPartial
		default:
			status = execution.RunFailed
		}
	}
	_ = r.execution.Finish(runID, status, name, callErr)
	return blocks, callErr
}

func toolTargets(name string, args map[string]interface{}, active engagement.TargetProfile) []string {
	var targets []string
	for _, key := range []string{"target", "url", "domain", "host", "cidr", "start_url", "base_url"} {
		if value := strings.TrimSpace(getString(args, key)); value != "" {
			targets = append(targets, value)
		}
	}
	if len(targets) > 0 {
		return targets
	}
	switch {
	case strings.TrimSpace(active.BaseURL) != "":
		return []string{active.BaseURL}
	case strings.TrimSpace(active.Domain) != "":
		return []string{active.Domain}
	case len(active.Hosts) > 0:
		return []string{active.Hosts[0]}
	case len(active.CIDRs) > 0:
		return []string{active.CIDRs[0]}
	default:
		return nil
	}
}

func isContextOnlyTool(name string) bool {
	switch name {
	case "akemi_configure_target", "akemi_get_target", "akemi_configure_defaults", "akemi_add_parameters", "akemi_list_parameters", "akemi_clear_context", "akemi_list_templates", "akemi_read_report", "akemi_write_report", "akemi_read_project_findings", "akemi_get_artifact", "akemi_search_findings", "akemi_get_finding", "akemi_run_status", "akemi_cancel_run", "akemi_approve_action", "akemi_deny_action", "akemi_summarize_run":
		return true
	default:
		return false
	}
}
