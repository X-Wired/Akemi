// Package llm provides provider-neutral chat and tool-call types for Akemi.
package llm

import (
	"context"

	"Akemi/internal/config"
)

// Client is the minimal interface needed by Akemi's assistant loop.
type Client interface {
	Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error)
	Ping(ctx context.Context) error
}

// ProviderCapabilities describe optional API behavior.
type ProviderCapabilities struct {
	ToolCalls       bool
	Streaming       bool
	ReasoningFields bool
}

// ChatRequest is a provider-neutral chat completion request.
type ChatRequest struct {
	Messages        []Message
	Tools           []ToolDefinition
	MaxTokens       int
	Temperature     float64
	ReasoningEffort string
	Thinking        bool
}

// ChatResponse is a provider-neutral chat completion response.
type ChatResponse struct {
	Message Message
	Raw     []byte
}

// Message is a chat message, including assistant tool calls and tool results.
type Message struct {
	Role             string     `json:"role"`
	Content          string     `json:"content,omitempty"`
	ReasoningContent string     `json:"reasoning_content,omitempty"`
	Name             string     `json:"name,omitempty"`
	ToolCallID       string     `json:"tool_call_id,omitempty"`
	ToolCalls        []ToolCall `json:"tool_calls,omitempty"`
}

// ToolDefinition describes a callable function exposed to the model.
type ToolDefinition struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
	Risk     string       `json:"-"`
	Server   string       `json:"-"`
	Native   string       `json:"-"`
}

// ToolFunction is the OpenAI-compatible function schema.
type ToolFunction struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Parameters  interface{} `json:"parameters,omitempty"`
}

// ToolCall is a model-requested tool invocation.
type ToolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function ToolCallFunction `json:"function"`
}

// ToolCallFunction holds the function name and JSON argument string.
type ToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// NewClient builds the configured provider client.
func NewClient(cfg config.LLMConfig) (Client, ProviderCapabilities, error) {
	provider := cfg.Provider
	if provider == "" {
		provider = "local"
	}
	vendor := cfg.GetActive()
	apiKey := cfg.ActiveAPIKey()

	switch provider {
	case "openai", "local", "deepseek":
		caps := ProviderCapabilities{ToolCalls: true, Streaming: false}
		if provider == "deepseek" {
			caps.ReasoningFields = true
		}
		return NewOpenAICompatibleClient(OpenAICompatibleConfig{
			Provider:        provider,
			APIKey:          apiKey,
			Model:           vendor.Model,
			BaseURL:         vendor.BaseURL,
			OrgID:           vendor.OrgID,
			MaxTokens:       vendor.MaxTokens,
			Temperature:     vendor.Temperature,
			ReasoningEffort: vendor.ReasoningEffort,
			Thinking:        vendor.Thinking,
		}), caps, nil
	case "anthropic", "google":
		return nil, ProviderCapabilities{}, ErrProviderNotImplemented{Provider: provider}
	default:
		return nil, ProviderCapabilities{}, ErrUnknownProvider{Provider: provider}
	}
}
