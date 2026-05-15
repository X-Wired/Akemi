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
	allSubs     []Subscriber // Subscribers that receive all events
	history     []Event      // Recent event history for late subscribers
	maxHistory  int
}

// NewBus creates an event bus with history buffer.
func NewBus(historySize int) *Bus {
	if historySize <= 0 {
		historySize = 100
	}
	return &Bus{
		subscribers: make(map[EventType][]Subscriber),
		history:     make([]Event, 0, historySize),
		maxHistory:  historySize,
	}
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
	event.Timestamp = time.Now()

	b.mu.Lock()
	// Store in history
	if len(b.history) >= b.maxHistory {
		b.history = b.history[1:]
	}
	b.history = append(b.history, event)

	// Copy subscriber lists to avoid lock during callback
	subs := make([]Subscriber, 0)
	subs = append(subs, b.allSubs...)
	if typed, ok := b.subscribers[event.Type]; ok {
		subs = append(subs, typed...)
	}
	b.mu.Unlock()

	// Notify outside of lock
	for _, sub := range subs {
		sub(event)
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
