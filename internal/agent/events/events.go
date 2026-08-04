// Package events provides a lightweight publish-subscribe event bus
// for real-time observability of agent execution.
package events

import (
	"sync"
	"time"
)

// EventType classifies system events.
type EventType string

const (
	EventPlanStarted       EventType = "plan.started"
	EventPlanCompleted     EventType = "plan.completed"
	EventPlanFailed        EventType = "plan.failed"
	EventTaskStarted       EventType = "task.started"
	EventTaskProgress      EventType = "task.progress"
	EventTaskCompleted     EventType = "task.completed"
	EventTaskRetrying      EventType = "task.retrying"
	EventTaskDenied        EventType = "task.denied"
	EventTaskError         EventType = "task.error"
	EventFindingDiscovered EventType = "finding.discovered"
	EventSafetyTriggered   EventType = "safety.triggered"
	EventMemoryUpdated     EventType = "memory.updated"
)

// Event carries information about something that happened during execution.
type Event struct {
	Type      EventType              `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	PlanID    string                 `json:"plan_id,omitempty"`
	TaskID    string                 `json:"task_id,omitempty"`
	ToolName  string                 `json:"tool_name,omitempty"`
	Message   string                 `json:"message,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// Subscriber receives events.
type Subscriber func(event Event)

// Bus manages event distribution to subscribers.
type Bus struct {
	mu          sync.RWMutex
	subscribers map[EventType][]Subscriber
	allSubs     []Subscriber
	history     []Event
	maxHistory  int
	queue       chan Event
	closeOnce   sync.Once
}

// NewBus creates an event bus with history buffer.
func NewBus(historySize int) *Bus {
	if historySize <= 0 {
		historySize = 100
	}
	b := &Bus{
		subscribers: make(map[EventType][]Subscriber),
		history:     make([]Event, 0, historySize),
		maxHistory:  historySize,
		queue:       make(chan Event, 256),
	}
	go b.dispatch()
	return b
}

func (b *Bus) dispatch() {
	for event := range b.queue {
		b.mu.RLock()
		subs := append([]Subscriber(nil), b.allSubs...)
		if typed, ok := b.subscribers[event.Type]; ok {
			subs = append(subs, typed...)
		}
		b.mu.RUnlock()
		for _, sub := range subs {
			func() {
				defer func() { _ = recover() }()
				sub(event)
			}()
		}
	}
}

// Close stops callback delivery. History remains readable for diagnostics.
func (b *Bus) Close() {
	if b == nil {
		return
	}
	b.closeOnce.Do(func() { close(b.queue) })
}

// Subscribe registers a subscriber for a specific event type.
func (b *Bus) Subscribe(eventType EventType, sub Subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers[eventType] = append(b.subscribers[eventType], sub)
}

// SubscribeAll registers a subscriber for all event types.
func (b *Bus) SubscribeAll(sub Subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.allSubs = append(b.allSubs, sub)
}

// Publish sends an event to all matching subscribers.
func (b *Bus) Publish(event Event) {
	if b == nil {
		return
	}
	event.Timestamp = time.Now()

	b.mu.Lock()
	if len(b.history) >= b.maxHistory {
		b.history = b.history[1:]
	}
	b.history = append(b.history, event)
	b.mu.Unlock()

	select {
	case b.queue <- event:
	default:
		// History is authoritative; slow subscribers can recover from it.
	}
}

// History returns recent events.
func (b *Bus) History() []Event {
	b.mu.RLock()
	defer b.mu.RUnlock()
	hist := make([]Event, len(b.history))
	copy(hist, b.history)
	return hist
}

// HistoryByType returns recent events of a specific type.
func (b *Bus) HistoryByType(eventType EventType) []Event {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var filtered []Event
	for _, e := range b.history {
		if e.Type == eventType {
			filtered = append(filtered, e)
		}
	}
	return filtered
}
