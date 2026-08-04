package executor

import (
	"context"
	"fmt"
	"strings"

	"Akemi/internal/agent/planner"
	agenttool "Akemi/internal/agent/tool"
	"Akemi/internal/execution"
)

func validateSharedPolicy(ctx context.Context, task *planner.TaskNode, definition *agenttool.AgentTool) error {
	run, ok := execution.RunContextFromContext(ctx)
	if !ok {
		return nil
	}
	target := taskTarget(task.Args, run)
	if target != "" {
		if err := execution.ValidateTarget(run.Scope, target); err != nil {
			return err
		}
	}
	return execution.ValidateRisk(run.Policy, agenttool.RiskLevel(definition.RiskLevel))
}

func taskTarget(args map[string]interface{}, run *execution.RunContext) string {
	for _, key := range []string{"target", "url", "domain", "host", "cidr", "start_url", "base_url"} {
		if value, ok := args[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	if run == nil {
		return ""
	}
	for _, value := range []string{run.Target.BaseURL, run.Target.Domain} {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	if len(run.Target.Hosts) > 0 {
		return run.Target.Hosts[0]
	}
	if len(run.Target.CIDRs) > 0 {
		return run.Target.CIDRs[0]
	}
	return ""
}

func sharedPolicyError(toolName string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s blocked by shared execution policy: %w", toolName, err)
}
