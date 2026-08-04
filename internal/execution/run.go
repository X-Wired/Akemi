package execution

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Run is a bounded, observable execution record.
var runSequence atomic.Uint64

// NewRunID returns a process-unique run identifier.
func NewRunID(prefix string) string {
	if strings.TrimSpace(prefix) == "" {
		prefix = "run"
	}
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), runSequence.Add(1))
}

type Run struct {
	Context    *RunContext `json:"context"`
	ToolName   string      `json:"tool_name"`
	Status     RunStatus   `json:"status"`
	Summary    string      `json:"summary,omitempty"`
	Errors     []string    `json:"errors,omitempty"`
	StartedAt  time.Time   `json:"started_at"`
	FinishedAt *time.Time  `json:"finished_at,omitempty"`
	Metrics    Metrics     `json:"metrics"`
}

type Metrics struct {
	RequestsSent int           `json:"requests_sent"`
	ItemsFound   int           `json:"items_found"`
	ItemsTested  int           `json:"items_tested"`
	Duration     time.Duration `json:"duration"`
}

type EventType string

const (
	EventRunStarted       EventType = "run.started"
	EventRunProgress      EventType = "run.progress"
	EventRunCompleted     EventType = "run.completed"
	EventRunError         EventType = "run.error"
	EventApprovalRequired EventType = "approval.required"
)

type Event struct {
	RunID    string                 `json:"run_id"`
	ToolName string                 `json:"tool_name,omitempty"`
	Type     EventType              `json:"type"`
	Phase    string                 `json:"phase,omitempty"`
	Message  string                 `json:"message,omitempty"`
	Status   RunStatus              `json:"status"`
	Progress float64                `json:"progress,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
	At       time.Time              `json:"at"`
}

type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalDenied   ApprovalStatus = "denied"
)

type ApprovalRequest struct {
	ID          string
	RunID       string
	ToolName    string
	Target      string
	Arguments   map[string]interface{}
	Status      ApprovalStatus
	RequestedAt time.Time
	ResolvedAt  *time.Time
}
type subscriber struct {
	ch chan Event
}

// Manager stores active and recent runs in memory. It bounds retention so
// long-lived MCP processes cannot grow without limit.
type Manager struct {
	mu            sync.RWMutex
	maxRuns       int
	runs          map[string]*Run
	order         []string
	subs          map[string]map[*subscriber]struct{}
	approvals     map[string]*ApprovalRequest
	approvalOrder []string
}

func NewManager(maxRuns int) *Manager {
	if maxRuns <= 0 {
		maxRuns = 100
	}
	return &Manager{maxRuns: maxRuns, runs: make(map[string]*Run), subs: make(map[string]map[*subscriber]struct{}), approvals: make(map[string]*ApprovalRequest)}
}

func (m *Manager) RequestApproval(run *RunContext, toolName, target string, args map[string]interface{}) (*ApprovalRequest, error) {
	if m == nil {
		return nil, fmt.Errorf("approval manager is nil")
	}
	request := &ApprovalRequest{
		ID:          executionApprovalID(),
		ToolName:    toolName,
		Target:      target,
		Status:      ApprovalPending,
		RequestedAt: time.Now(),
	}
	if run != nil {
		request.RunID = run.ID
	}
	if args != nil {
		redacted, _ := RedactValue(args)
		if value, ok := redacted.(map[string]interface{}); ok {
			request.Arguments = value
		}
	}
	m.mu.Lock()
	m.approvals[request.ID] = request
	m.mu.Unlock()
	if run != nil {
		m.publish(Event{RunID: run.ID, ToolName: toolName, Type: EventApprovalRequired, Status: RunQueued, Message: request.ID, At: request.RequestedAt, Data: map[string]interface{}{"approval_id": request.ID}})
	}
	return cloneApproval(request), nil
}

func (m *Manager) ResolveApproval(id string, status ApprovalStatus) (*ApprovalRequest, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	request, ok := m.approvals[id]
	if !ok || (status != ApprovalApproved && status != ApprovalDenied) {
		return nil, false
	}
	now := time.Now()
	request.Status = status
	request.ResolvedAt = &now
	return cloneApproval(request), true
}

func (m *Manager) Approval(id string) (*ApprovalRequest, bool) {
	m.mu.RLock()
	request, ok := m.approvals[id]
	m.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return cloneApproval(request), true
}

func (m *Manager) IsApprovalApproved(id, toolName, target string) bool {
	request, ok := m.Approval(id)
	return ok && request.Status == ApprovalApproved && request.ToolName == toolName && request.Target == target
}

func executionApprovalID() string {
	return NewRunID("approval")
}

func cloneApproval(in *ApprovalRequest) *ApprovalRequest {
	if in == nil {
		return nil
	}
	out := *in
	if in.Arguments != nil {
		out.Arguments = make(map[string]interface{}, len(in.Arguments))
		for key, value := range in.Arguments {
			out.Arguments[key] = value
		}
	}
	if in.ResolvedAt != nil {
		resolved := *in.ResolvedAt
		out.ResolvedAt = &resolved
	}
	return &out
}
func (m *Manager) Start(ctx *RunContext, toolName string) (*Run, error) {
	if m == nil {
		return nil, fmt.Errorf("run manager is nil")
	}
	if ctx == nil || strings.TrimSpace(ctx.ID) == "" {
		return nil, fmt.Errorf("run context is required")
	}
	now := time.Now()
	run := &Run{Context: ctx, ToolName: toolName, Status: RunRunning, StartedAt: now}
	m.mu.Lock()
	m.runs[ctx.ID] = run
	m.order = append(m.order, ctx.ID)
	m.evictLocked()
	m.mu.Unlock()
	m.publish(Event{RunID: ctx.ID, ToolName: toolName, Type: EventRunStarted, Status: RunRunning, At: now})
	return cloneRun(run), nil
}

func (m *Manager) Get(id string) (*Run, bool) {
	m.mu.RLock()
	run, ok := m.runs[id]
	m.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return cloneRun(run), true
}

func (m *Manager) Update(id string, update func(*Run)) error {
	m.mu.Lock()
	run, ok := m.runs[id]
	if ok && update != nil {
		update(run)
	}
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("run not found: %s", id)
	}
	return nil
}

func (m *Manager) Finish(id string, status RunStatus, summary string, runErr error) error {
	now := time.Now()
	var event Event
	err := m.Update(id, func(run *Run) {
		run.Status = status
		run.Summary = summary
		run.FinishedAt = &now
		run.Metrics.Duration = now.Sub(run.StartedAt)
		if runErr != nil {
			run.Errors = append(run.Errors, runErr.Error())
		}
		event = Event{RunID: id, ToolName: run.ToolName, Type: EventRunCompleted, Status: status, Message: summary, At: now}
	})
	if err == nil {
		m.publish(event)
	}
	return err
}

func (m *Manager) Progress(id, phase, message string, progress float64, data map[string]interface{}) error {
	run, ok := m.Get(id)
	if !ok {
		return fmt.Errorf("run not found: %s", id)
	}
	m.publish(Event{RunID: id, ToolName: run.ToolName, Type: EventRunProgress, Phase: phase, Message: message, Progress: progress, Status: run.Status, Data: data, At: time.Now()})
	return nil
}

// Subscribe returns a bounded, coalescing-friendly event channel. Slow
// subscribers do not block execution; callers should use the run snapshot to
// recover state if an event is dropped.
func (m *Manager) Subscribe(id string) (<-chan Event, func(), error) {
	if _, ok := m.Get(id); !ok {
		return nil, nil, fmt.Errorf("run not found: %s", id)
	}
	s := &subscriber{ch: make(chan Event, 64)}
	m.mu.Lock()
	if m.subs[id] == nil {
		m.subs[id] = make(map[*subscriber]struct{})
	}
	m.subs[id][s] = struct{}{}
	m.mu.Unlock()
	closeFn := func() {
		m.mu.Lock()
		if set, ok := m.subs[id]; ok {
			if _, exists := set[s]; exists {
				delete(set, s)
				close(s.ch)
			}
		}
		m.mu.Unlock()
	}
	return s.ch, closeFn, nil
}

func (m *Manager) publish(event Event) {
	m.mu.RLock()
	set := m.subs[event.RunID]
	for s := range set {
		select {
		case s.ch <- event:
		default:
		}
	}
	m.mu.RUnlock()
}

func (m *Manager) evictLocked() {
	for len(m.order) > m.maxRuns {
		id := m.order[0]
		m.order = m.order[1:]
		delete(m.runs, id)
		if set, ok := m.subs[id]; ok {
			for s := range set {
				close(s.ch)
			}
			delete(m.subs, id)
		}
	}
}

func cloneRun(in *Run) *Run {
	if in == nil {
		return nil
	}
	out := *in
	out.Errors = append([]string(nil), in.Errors...)
	if in.FinishedAt != nil {
		finished := *in.FinishedAt
		out.FinishedAt = &finished
	}
	return &out
}

// SnapshotIDs returns retained run IDs in start order.
func (m *Manager) SnapshotIDs() []string {
	m.mu.RLock()
	ids := append([]string(nil), m.order...)
	m.mu.RUnlock()
	return ids
}
