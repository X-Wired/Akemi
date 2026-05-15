// Package executor runs task graphs produced by the planner.
// It handles topological ordering, parallel execution where dependencies allow,
// data propagation between tasks, and error recovery.
package executor

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"Akemi/internal/agent/events"
	"Akemi/internal/agent/planner"
	"Akemi/internal/agent/safety"
	"Akemi/internal/agent/tool"
)

// Executor runs a Plan by executing its task graph.
type Executor struct {
	registry    *tool.Registry
	safetyLayer *safety.SafetyLayer
	eventBus    *events.Bus
	logger      *slog.Logger
	concurrency int
}

// NewExecutor creates a task graph executor.
func NewExecutor(registry *tool.Registry, safety *safety.SafetyLayer, bus *events.Bus, logger *slog.Logger) *Executor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Executor{
		registry:    registry,
		safetyLayer: safety,
		eventBus:    bus,
		logger:      logger,
		concurrency: 5,
	}
}

// SetConcurrency sets the maximum number of parallel tasks.
func (e *Executor) SetConcurrency(n int) {
	if n > 0 {
		e.concurrency = n
	}
}

// ExecutionResult holds the outcome of running a plan.
type ExecutionResult struct {
	PlanID      string              `json:"plan_id"`
	Status      ExecutionStatus     `json:"status"`
	Tasks       []*planner.TaskNode `json:"tasks"`
	Findings    []*tool.Finding     `json:"findings"`
	StartedAt   time.Time           `json:"started_at"`
	CompletedAt *time.Time          `json:"completed_at,omitempty"`
	Errors      []ExecutionError    `json:"errors,omitempty"`
	Summary     string              `json:"summary"`
}

// ExecutionStatus indicates overall plan outcome.
type ExecutionStatus string

const (
	ExecRunning   ExecutionStatus = "running"
	ExecCompleted ExecutionStatus = "completed"
	ExecFailed    ExecutionStatus = "failed"
	ExecCancelled ExecutionStatus = "cancelled"
)

// ExecutionError records a non-fatal error during execution.
type ExecutionError struct {
	TaskID   string `json:"task_id"`
	ToolName string `json:"tool_name"`
	Error    string `json:"error"`
}

// Execute runs the plan until completion or failure.
func (e *Executor) Execute(ctx context.Context, plan *planner.Plan) (*ExecutionResult, error) {
	result := &ExecutionResult{
		PlanID:    plan.ID,
		Status:    ExecRunning,
		Tasks:     plan.Tasks,
		StartedAt: time.Now(),
	}

	e.eventBus.Publish(events.Event{
		Type:    events.EventPlanStarted,
		PlanID:  plan.ID,
		Message: fmt.Sprintf("Plan started: %s (%d tasks)", plan.Goal.Description, len(plan.Tasks)),
	})

	// Build dependency tracker
	tracker := newTaskTracker(plan.Tasks)
	resultMu := &sync.Mutex{}
	doneCh := make(chan *planner.TaskNode, len(plan.Tasks))

	total := len(plan.Tasks)
	completed := 0
	running := 0
	cancelled := ctx.Err() != nil

	for completed < total {
		if ctx.Err() != nil {
			cancelled = true
		}

		if !cancelled {
			for running < e.concurrency {
				task := tracker.NextReady()
				if task == nil {
					break
				}
				running++
				go func(t *planner.TaskNode) {
					e.executeTask(ctx, t, result, resultMu, tracker)
					doneCh <- t
				}(task)
			}
		}

		if completed >= total {
			break
		}

		if running == 0 {
			completed += tracker.SkipRemaining()
			break
		}

		task := <-doneCh
		running--
		completed += 1 + tracker.MarkDone(task.ID)
	}

	// Determine final status
	now := time.Now()
	result.CompletedAt = &now

	failedCount := 0
	skippedCount := 0
	for _, t := range plan.Tasks {
		if t.Status == planner.TaskFailed || t.Status == planner.TaskDenied {
			failedCount++
		}
		if t.Status == planner.TaskSkipped {
			skippedCount++
		}
	}

	if cancelled {
		result.Status = ExecCancelled
	} else if failedCount > 0 || skippedCount > 0 {
		result.Status = ExecFailed
	} else {
		result.Status = ExecCompleted
	}

	result.Summary = fmt.Sprintf("Executed %d tasks: %d completed, %d failed, %d skipped, %d findings",
		len(plan.Tasks),
		countByStatus(plan.Tasks, planner.TaskCompleted),
		failedCount,
		skippedCount,
		len(result.Findings),
	)

	e.eventBus.Publish(events.Event{
		Type:    events.EventPlanCompleted,
		PlanID:  plan.ID,
		Message: result.Summary,
		Data: map[string]interface{}{
			"status":   string(result.Status),
			"findings": len(result.Findings),
			"duration": now.Sub(result.StartedAt).String(),
		},
	})

	return result, nil
}

func (e *Executor) executeTask(
	ctx context.Context,
	task *planner.TaskNode,
	result *ExecutionResult,
	resultMu *sync.Mutex,
	tracker *taskTracker,
) {
	// Look up tool
	agentTool, ok := e.registry.Get(task.ToolName)
	if !ok {
		task.Status = planner.TaskFailed
		resultMu.Lock()
		result.Errors = append(result.Errors, ExecutionError{
			TaskID: task.ID, ToolName: task.ToolName,
			Error: fmt.Sprintf("unknown tool: %s", task.ToolName),
		})
		resultMu.Unlock()
		return
	}

	// Safety check
	if err := e.safetyLayer.ValidateTask(task.ToolName, task.Args, agentTool.RiskLevel); err != nil {
		task.Status = planner.TaskDenied
		e.eventBus.Publish(events.Event{
			Type: events.EventTaskDenied, PlanID: result.PlanID,
			TaskID: task.ID, ToolName: task.ToolName, Message: err.Error(),
		})
		return
	}

	task.Status = planner.TaskRunning
	e.eventBus.Publish(events.Event{
		Type: events.EventTaskStarted, PlanID: result.PlanID,
		TaskID: task.ID, ToolName: task.ToolName,
	})

	// Execute with retries
	var toolResult *tool.ToolResult
	var lastErr error

	for attempt := 0; attempt <= task.MaxRetries; attempt++ {
		if attempt > 0 {
			e.eventBus.Publish(events.Event{
				Type: events.EventTaskRetrying, PlanID: result.PlanID,
				TaskID: task.ID, ToolName: task.ToolName,
				Data: map[string]interface{}{"attempt": attempt},
			})
			if !sleepWithContext(ctx, time.Duration(attempt)*500*time.Millisecond) {
				lastErr = ctx.Err()
				break
			}
		}

		timeout := task.Timeout
		if timeout <= 0 {
			timeout = planner.DefaultTaskTimeout
		}
		taskCtx, cancel := context.WithTimeout(ctx, timeout)
		toolResult, lastErr = agentTool.Handler(taskCtx, task.Args)
		if taskCtx.Err() == context.DeadlineExceeded && lastErr == nil {
			lastErr = context.DeadlineExceeded
		}
		cancel()

		if lastErr == nil && toolResult == nil {
			lastErr = fmt.Errorf("tool returned nil result")
		}
		if lastErr == nil && toolResult.Status != tool.StatusError {
			break
		}
	}

	// Record result
	task.Result = toolResult

	if lastErr != nil || (toolResult != nil && toolResult.Status == tool.StatusError) {
		task.Status = planner.TaskFailed
		errMsg := "unknown error"
		if lastErr != nil {
			errMsg = lastErr.Error()
		} else if toolResult != nil {
			errMsg = toolResult.Error
		}
		resultMu.Lock()
		result.Errors = append(result.Errors, ExecutionError{
			TaskID: task.ID, ToolName: task.ToolName, Error: errMsg,
		})
		resultMu.Unlock()
		e.eventBus.Publish(events.Event{
			Type: events.EventTaskError, PlanID: result.PlanID,
			TaskID: task.ID, ToolName: task.ToolName, Message: errMsg,
		})
	} else {
		task.Status = planner.TaskCompleted
		e.eventBus.Publish(events.Event{
			Type: events.EventTaskCompleted, PlanID: result.PlanID,
			TaskID: task.ID, ToolName: task.ToolName,
			Data: map[string]interface{}{
				"findings": len(toolResult.Findings),
				"duration": toolResult.Metrics.DurationMs,
			},
		})

		// Collect findings
		if len(toolResult.Findings) > 0 {
			resultMu.Lock()
			for _, f := range toolResult.Findings {
				finding := f // copy
				result.Findings = append(result.Findings, &finding)
				e.eventBus.Publish(events.Event{
					Type: events.EventFindingDiscovered, PlanID: result.PlanID,
					TaskID: task.ID, ToolName: task.ToolName,
					Data: map[string]interface{}{
						"type":     f.Type,
						"severity": f.Severity,
						"title":    f.Title,
					},
				})
			}
			resultMu.Unlock()
		}

		// Propagate data to dependent tasks
		if toolResult.Data != nil {
			e.propagateData(task, toolResult.Data, tracker)
		}
	}
}

func sleepWithContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// propagateData feeds outputs from a completed task into dependent tasks' args.
func (e *Executor) propagateData(task *planner.TaskNode, data map[string]interface{}, tracker *taskTracker) {
	agentTool, _ := e.registry.Get(task.ToolName)
	if agentTool == nil {
		return
	}
	tracker.PropagateData(task.ID, agentTool.Provides, data, e.registry)
}

// =============================================================================
// Task Tracker — manages the DAG state during execution
// =============================================================================

type taskTracker struct {
	ordered []*planner.TaskNode
	tasks   map[string]*planner.TaskNode
	deps    map[string][]string // taskID → list of taskIDs that depend on it
	pending map[string]int      // taskID → count of unfinished dependencies
	queued  map[string]bool
	isDone  map[string]bool
	mu      sync.Mutex
}

func newTaskTracker(tasks []*planner.TaskNode) *taskTracker {
	tt := &taskTracker{
		ordered: tasks,
		tasks:   make(map[string]*planner.TaskNode),
		deps:    make(map[string][]string),
		pending: make(map[string]int),
		queued:  make(map[string]bool),
		isDone:  make(map[string]bool),
	}

	for _, t := range tasks {
		tt.tasks[t.ID] = t
		tt.pending[t.ID] = len(t.DependsOn)
		for _, dep := range t.DependsOn {
			tt.deps[dep] = append(tt.deps[dep], t.ID)
		}
	}

	return tt
}

// NextReady returns the highest-priority task whose dependencies are satisfied.
func (tt *taskTracker) NextReady() *planner.TaskNode {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	var ready []*planner.TaskNode
	for _, task := range tt.ordered {
		if tt.pending[task.ID] == 0 && !tt.isDone[task.ID] && !tt.queued[task.ID] {
			if task.Status == planner.TaskPending || task.Status == planner.TaskReady {
				ready = append(ready, task)
			}
		}
	}
	if len(ready) == 0 {
		return nil
	}

	sort.SliceStable(ready, func(i, j int) bool {
		return ready[i].Priority < ready[j].Priority
	})

	task := ready[0]
	task.Status = planner.TaskReady
	tt.queued[task.ID] = true
	return task
}

// MarkDone marks a task as terminal and returns dependents skipped by failure.
func (tt *taskTracker) MarkDone(taskID string) int {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	if tt.isDone[taskID] {
		return 0
	}

	tt.isDone[taskID] = true
	delete(tt.queued, taskID)

	// Decrement pending counts for tasks that depend on this one
	for _, dependentID := range tt.deps[taskID] {
		if !tt.isDone[dependentID] && tt.pending[dependentID] > 0 {
			tt.pending[dependentID]--
		}
	}

	// If the task failed, mark dependents as skipped
	task := tt.tasks[taskID]
	if task != nil && (task.Status == planner.TaskFailed || task.Status == planner.TaskDenied) {
		return tt.skipDependentsLocked(taskID)
	}
	return 0
}

// SkipRemaining marks any non-terminal tasks skipped and returns how many changed.
func (tt *taskTracker) SkipRemaining() int {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	skipped := 0
	for _, task := range tt.ordered {
		if !tt.isDone[task.ID] {
			task.Status = planner.TaskSkipped
			tt.isDone[task.ID] = true
			delete(tt.queued, task.ID)
			skipped++
		}
	}
	return skipped
}

// PropagateData copies exact capability keys into direct dependent task args.
func (tt *taskTracker) PropagateData(taskID string, provides []string, data map[string]interface{}, registry *tool.Registry) {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	for _, dependentID := range tt.deps[taskID] {
		if tt.isDone[dependentID] || tt.queued[dependentID] {
			continue
		}
		depTask, ok := tt.tasks[dependentID]
		if !ok {
			continue
		}
		depTool, ok := registry.Get(depTask.ToolName)
		if !ok {
			continue
		}
		for _, provided := range provides {
			value, ok := data[provided]
			if !ok || !requiresCapability(depTool, provided) {
				continue
			}
			if depTask.Args == nil {
				depTask.Args = make(map[string]interface{})
			}
			if _, exists := depTask.Args[provided]; !exists {
				depTask.Args[provided] = value
			}
		}
	}
}

func (tt *taskTracker) skipDependentsLocked(taskID string) int {
	skipped := 0
	for _, dependentID := range tt.deps[taskID] {
		if tt.isDone[dependentID] {
			continue
		}
		if depTask, ok := tt.tasks[dependentID]; ok {
			depTask.Status = planner.TaskSkipped
			tt.isDone[dependentID] = true
			delete(tt.queued, dependentID)
			skipped++
			skipped += tt.skipDependentsLocked(dependentID)
		}
	}
	return skipped
}

func requiresCapability(agentTool *tool.AgentTool, capability string) bool {
	for _, required := range agentTool.Requires {
		if required == capability {
			return true
		}
	}
	return false
}

func countByStatus(tasks []*planner.TaskNode, status planner.TaskStatus) int {
	count := 0
	for _, t := range tasks {
		if t.Status == status {
			count++
		}
	}
	return count
}
