// Package agent provides the top-level Agent orchestrator that ties together
// the planner, executor, safety layer, memory, and event bus into a cohesive
// autonomous security testing system.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"Akemi/internal/agent/events"
	"Akemi/internal/agent/executor"
	"Akemi/internal/agent/memory"
	"Akemi/internal/agent/planner"
	"Akemi/internal/agent/safety"
	"Akemi/internal/agent/tool"
)

// Agent orchestrates autonomous security testing workflows.
type Agent struct {
	planner  *planner.Planner
	executor *executor.Executor
	safety   *safety.SafetyLayer
	memory   *memory.AgentMemory
	events   *events.Bus
	registry *tool.Registry
	logger   *slog.Logger
}

// Config holds Agent configuration.
type Config struct {
	AllowedDomains []string
	AllowedCIDRs   []string
	BlockedDomains []string
	MaxRPM         int
	MaxConcurrency int
	MaxAutoRisk    tool.RiskLevel
	Logger         *slog.Logger
}

// NewAgent creates a new Agent with the given tool registry.
func NewAgent(registry *tool.Registry, cfg Config) *Agent {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxRPM <= 0 {
		cfg.MaxRPM = 300
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 5
	}
	if cfg.MaxAutoRisk == "" {
		cfg.MaxAutoRisk = tool.RiskActive
	}

	bus := events.NewBus(200)
	safe := safety.NewSafetyLayerWithPolicy(cfg.AllowedDomains, cfg.AllowedCIDRs, cfg.BlockedDomains, cfg.MaxRPM, cfg.MaxAutoRisk)
	mem := memory.NewAgentMemory()

	pl := planner.NewPlanner(registry)
	ex := executor.NewExecutor(registry, safe, bus, cfg.Logger)
	ex.SetConcurrency(cfg.MaxConcurrency)

	return &Agent{
		planner:  pl,
		executor: ex,
		safety:   safe,
		memory:   mem,
		events:   bus,
		registry: registry,
		logger:   cfg.Logger,
	}
}

// Run executes a goal against a target and returns the results.
func (a *Agent) Run(ctx context.Context, goalDesc, target, intent string) (*AgentResult, error) {
	goal := planner.Goal{
		ID:          generateID("goal"),
		Description: goalDesc,
		Target:      target,
		Intent:      intent,
	}

	a.logger.Info("agent starting",
		slog.String("goal_id", goal.ID),
		slog.String("target", target),
		slog.String("intent", intent),
	)

	// Phase 1: Plan
	a.logger.Debug("planning phase")
	plan, err := a.planner.Plan(goal)
	if err != nil {
		return nil, fmt.Errorf("planning failed: %w", err)
	}

	a.logger.Info("plan created",
		slog.String("plan_id", plan.ID),
		slog.Int("tasks", len(plan.Tasks)),
		slog.String("estimated", plan.Estimated.String()),
		slog.String("risk", plan.RiskSummary),
	)

	// Phase 2: Execute
	a.logger.Debug("execution phase")
	execResult, err := a.executor.Execute(ctx, plan)
	if err != nil {
		return nil, fmt.Errorf("execution failed: %w", err)
	}

	// Phase 3: Store in memory
	scanRecord := &memory.ScanRecord{
		SessionID: goal.ID,
		Target:    target,
		StartedAt: execResult.StartedAt,
		EndedAt:   *execResult.CompletedAt,
		Status:    string(execResult.Status),
	}
	for _, f := range execResult.Findings {
		scanRecord.Findings = append(scanRecord.Findings, f)
		a.memory.Working().AddFinding(f)
	}
	a.memory.Episodic().AddScan(scanRecord)

	// Build result
	result := &AgentResult{
		Goal:           goal,
		Plan:           plan,
		Execution:      execResult,
		MemorySnapshot: a.memory.Snapshot(),
	}

	a.logger.Info("agent completed",
		slog.String("status", string(execResult.Status)),
		slog.Int("findings", len(execResult.Findings)),
		slog.String("duration", execResult.CompletedAt.Sub(execResult.StartedAt).String()),
	)

	return result, nil
}

// SubscribeEvents registers a callback for real-time agent events.
func (a *Agent) SubscribeEvents(callback events.Subscriber) {
	a.events.SubscribeAll(callback)
}

// EventHistory returns recent execution events.
func (a *Agent) EventHistory() []events.Event {
	return a.events.History()
}

// Memory returns the agent's memory system.
func (a *Agent) Memory() *memory.AgentMemory {
	return a.memory
}

// Registry returns the tool registry.
func (a *Agent) Registry() *tool.Registry {
	return a.registry
}

// Safety returns the safety layer.
func (a *Agent) Safety() *safety.SafetyLayer {
	return a.safety
}

// =============================================================================
// AgentResult — output of an agent run
// =============================================================================

// AgentResult holds the complete output of an agent execution.
type AgentResult struct {
	Goal           planner.Goal              `json:"goal"`
	Plan           *planner.Plan             `json:"plan"`
	Execution      *executor.ExecutionResult `json:"execution"`
	MemorySnapshot *memory.MemorySnapshot    `json:"memory_snapshot"`
}

// Summary returns a human-readable summary of the agent's work.
func (ar *AgentResult) Summary() string {
	if ar.Execution == nil {
		return "No execution data available."
	}

	s := fmt.Sprintf("Agent Run Summary\n")
	s += fmt.Sprintf("=================\n")
	s += fmt.Sprintf("Goal:    %s\n", ar.Goal.Description)
	s += fmt.Sprintf("Target:  %s\n", ar.Goal.Target)
	s += fmt.Sprintf("Intent:  %s\n", ar.Goal.Intent)
	s += fmt.Sprintf("Status:  %s\n", ar.Execution.Status)
	s += fmt.Sprintf("Tasks:   %d executed\n", len(ar.Execution.Tasks))
	s += fmt.Sprintf("Findings: %d\n", len(ar.Execution.Findings))

	if ar.Execution.CompletedAt != nil {
		s += fmt.Sprintf("Duration: %s\n", ar.Execution.CompletedAt.Sub(ar.Execution.StartedAt))
	}

	if len(ar.Execution.Errors) > 0 {
		s += fmt.Sprintf("\nErrors (%d):\n", len(ar.Execution.Errors))
		for _, e := range ar.Execution.Errors {
			s += fmt.Sprintf("  - [%s] %s: %s\n", e.TaskID, e.ToolName, e.Error)
		}
	}

	return s
}

// FindingsBySeverity groups findings by severity level.
func (ar *AgentResult) FindingsBySeverity() map[string][]*tool.Finding {
	groups := make(map[string][]*tool.Finding)
	for _, f := range ar.Execution.Findings {
		groups[f.Severity] = append(groups[f.Severity], f)
	}
	return groups
}

// CriticalFindings returns only critical and high severity findings.
func (ar *AgentResult) CriticalFindings() []*tool.Finding {
	var findings []*tool.Finding
	for _, f := range ar.Execution.Findings {
		if f.Severity == "critical" || f.Severity == "high" {
			findings = append(findings, f)
		}
	}
	return findings
}

func generateID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1000000)
}
