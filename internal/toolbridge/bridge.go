// Package toolbridge carries lightweight tool execution discoveries to UI code.
package toolbridge

import "context"

// Sink receives optional tool events from in-process tool execution.
type Sink interface {
	Emit(ctx context.Context, event Event)
}

// Event is a compact description of useful UI-facing tool output.
type Event struct {
	ToolName    string
	NativeName  string
	Phase       string
	Target      *TargetConfig
	Discoveries []DiscoveryItem
	Error       string
}

// DiscoveryItem maps a tool result into an existing dashboard discovery section.
type DiscoveryItem struct {
	Section string
	Key     string
	Item    string
	Phase   string
}

// TargetConfig contains optional target-panel fields learned from a tool.
type TargetConfig struct {
	Clear   bool
	Target  string
	Ports   string
	Threads *int
	Proxy   string
	Intent  string
	Depth   *int
	Timeout *int
}

// SinkFunc adapts a function into a Sink.
type SinkFunc func(ctx context.Context, event Event)

// Emit implements Sink.
func (f SinkFunc) Emit(ctx context.Context, event Event) {
	if f != nil {
		f(ctx, event)
	}
}
