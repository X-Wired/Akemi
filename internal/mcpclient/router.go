// Package mcpclient adapts MCP tool providers into LLM-callable tools.
package mcpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"Akemi/internal/llm"
	"Akemi/internal/mcp"
	"Akemi/internal/toolbridge"
)

var unsafeToolNameChars = regexp.MustCompile(`[^a-zA-Z0-9_]`)

// Source is a named MCP tool provider.
type Source struct {
	Name     string
	Provider mcp.ToolProvider
}

// Router exposes namespaced MCP tools to an LLM and executes selected calls.
type Router struct {
	sources []Source
	lookup  map[string]ToolRef
}

// ToolRef identifies one MCP tool behind an LLM-safe name.
type ToolRef struct {
	LLMName    string
	ServerName string
	NativeName string
	Risk       string
	Tool       mcp.Tool
}

// ExecutionResult captures an MCP tool result.
type ExecutionResult struct {
	Ref        ToolRef
	Content    []mcp.ContentBlock
	Structured map[string]interface{}
	Text       string
}

type toolEventSinkSetter interface {
	SetEventSink(toolbridge.Sink)
}

// NewRouter creates a tool router from MCP providers.
func NewRouter(sources ...Source) *Router {
	r := &Router{sources: sources, lookup: make(map[string]ToolRef)}
	r.refresh()
	return r
}

// ToolDefinitions returns LLM function schemas for all known tools.
func (r *Router) ToolDefinitions() []llm.ToolDefinition {
	r.refresh()
	defs := make([]llm.ToolDefinition, 0, len(r.lookup))
	for _, ref := range r.lookup {
		defs = append(defs, llm.ToolDefinition{
			Type: "function",
			Function: llm.ToolFunction{
				Name:        ref.LLMName,
				Description: ref.Tool.Description,
				Parameters:  ref.Tool.InputSchema,
			},
			Risk:   ref.Risk,
			Server: ref.ServerName,
			Native: ref.NativeName,
		})
	}
	return defs
}

// ListRefs returns stable refs for display and policy.
func (r *Router) ListRefs() []ToolRef {
	r.refresh()
	refs := make([]ToolRef, 0, len(r.lookup))
	for _, ref := range r.lookup {
		refs = append(refs, ref)
	}
	return refs
}

// Lookup returns a ref by LLM tool name.
func (r *Router) Lookup(llmName string) (ToolRef, bool) {
	r.refresh()
	ref, ok := r.lookup[llmName]
	return ref, ok
}

// SetToolEventSink connects in-process tool providers to a UI/event sink.
func (r *Router) SetToolEventSink(sink toolbridge.Sink) {
	if r == nil {
		return
	}
	for _, source := range r.sources {
		if setter, ok := source.Provider.(toolEventSinkSetter); ok {
			setter.SetEventSink(sink)
		}
	}
}

// Execute calls a namespaced MCP tool with JSON arguments.
func (r *Router) Execute(ctx context.Context, llmName string, arguments string) (*ExecutionResult, error) {
	r.refresh()
	ref, ok := r.lookup[llmName]
	if !ok {
		return nil, fmt.Errorf("unknown tool %q", llmName)
	}
	var args map[string]interface{}
	if strings.TrimSpace(arguments) == "" {
		args = make(map[string]interface{})
	} else if err := json.Unmarshal([]byte(arguments), &args); err != nil {
		return nil, fmt.Errorf("invalid tool arguments: %w", err)
	}

	for _, source := range r.sources {
		if source.Name != ref.ServerName {
			continue
		}
		if structured, ok := source.Provider.(mcp.StructuredToolProvider); ok {
			result, err := structured.CallStructured(ctx, ref.NativeName, args)
			if err != nil {
				return nil, err
			}
			return &ExecutionResult{
				Ref:        ref,
				Content:    result.Content,
				Structured: result.StructuredContent,
				Text:       contentBlocksText(result.Content),
			}, nil
		}
		content, err := source.Provider.Call(ctx, ref.NativeName, args)
		if err != nil {
			return nil, err
		}
		return &ExecutionResult{
			Ref:     ref,
			Content: content,
			Text:    contentBlocksText(content),
		}, nil
	}
	return nil, fmt.Errorf("tool source %q is not available", ref.ServerName)
}

func (r *Router) refresh() {
	lookup := make(map[string]ToolRef)
	for _, source := range r.sources {
		if source.Provider == nil {
			continue
		}
		for _, tool := range source.Provider.List() {
			if tool.AssistantHidden {
				continue
			}
			name := namespacedToolName(source.Name, tool.Name)
			if _, exists := lookup[name]; exists {
				continue
			}
			lookup[name] = ToolRef{
				LLMName:    name,
				ServerName: source.Name,
				NativeName: tool.Name,
				Risk:       toolRisk(tool),
				Tool:       tool,
			}
		}
	}
	r.lookup = lookup
}

func namespacedToolName(server, name string) string {
	server = unsafeToolNameChars.ReplaceAllString(server, "_")
	name = unsafeToolNameChars.ReplaceAllString(name, "_")
	return strings.Trim(server+"__"+name, "_")
}

func contentBlocksText(blocks []mcp.ContentBlock) string {
	var parts []string
	for _, block := range blocks {
		switch block.Type {
		case "text", "":
			if strings.TrimSpace(block.Text) != "" {
				parts = append(parts, block.Text)
			}
		default:
			parts = append(parts, fmt.Sprintf("[%s content]", block.Type))
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func toolRisk(tool mcp.Tool) string {
	if strings.TrimSpace(tool.Risk) != "" {
		return tool.Risk
	}
	if tool.Meta != nil {
		if risk, ok := tool.Meta["akemi/risk"].(string); ok && strings.TrimSpace(risk) != "" {
			return risk
		}
	}
	return "active"
}
