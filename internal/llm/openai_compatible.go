package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAICompatibleConfig configures OpenAI-compatible chat APIs.
type OpenAICompatibleConfig struct {
	Provider        string
	APIKey          string
	Model           string
	BaseURL         string
	OrgID           string
	MaxTokens       int
	Temperature     float64
	ReasoningEffort string
	Thinking        bool
	HTTPClient      *http.Client
}

// OpenAICompatibleClient calls /chat/completions-compatible providers.
type OpenAICompatibleClient struct {
	cfg    OpenAICompatibleConfig
	client *http.Client
}

const defaultOpenAICompatibleHTTPTimeout = 5 * time.Hour

// NewOpenAICompatibleClient creates a chat client.
func NewOpenAICompatibleClient(cfg OpenAICompatibleConfig) *OpenAICompatibleClient {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:11434/v1"
	}
	if cfg.Model == "" {
		cfg.Model = "llama3.1:8b"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultOpenAICompatibleHTTPTimeout}
	}
	return &OpenAICompatibleClient{cfg: cfg, client: client}
}

// Chat sends a chat completion request.
func (c *OpenAICompatibleClient) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	wireReq := openAIChatRequest{
		Model:       c.cfg.Model,
		Messages:    req.Messages,
		Tools:       req.Tools,
		Stream:      false,
		MaxTokens:   firstPositive(req.MaxTokens, c.cfg.MaxTokens),
		Temperature: firstFloat(req.Temperature, c.cfg.Temperature),
	}
	if wireReq.MaxTokens <= 0 {
		wireReq.MaxTokens = 4096
	}
	if req.ReasoningEffort != "" {
		wireReq.ReasoningEffort = req.ReasoningEffort
	} else if c.cfg.ReasoningEffort != "" {
		wireReq.ReasoningEffort = c.cfg.ReasoningEffort
	}
	if req.Thinking || c.cfg.Thinking {
		wireReq.Thinking = map[string]string{"type": "enabled"}
	}
	if len(wireReq.Tools) == 0 {
		wireReq.Tools = nil
	}

	body, err := json.Marshal(wireReq)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("/chat/completions"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}
	if c.cfg.OrgID != "" {
		httpReq.Header.Set("OpenAI-Organization", c.cfg.OrgID)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("llm chat failed: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var wireResp openAIChatResponse
	if err := json.Unmarshal(respBody, &wireResp); err != nil {
		return nil, err
	}
	if len(wireResp.Choices) == 0 {
		return nil, fmt.Errorf("llm chat failed: no choices returned")
	}

	return &ChatResponse{Message: wireResp.Choices[0].Message, Raw: respBody}, nil
}

// Ping checks that the API responds to a minimal chat request.
func (c *OpenAICompatibleClient) Ping(ctx context.Context) error {
	_, err := c.Chat(ctx, ChatRequest{
		Messages:  []Message{{Role: "user", Content: "ping"}},
		MaxTokens: 8,
	})
	return err
}

func (c *OpenAICompatibleClient) endpoint(path string) string {
	base := strings.TrimRight(c.cfg.BaseURL, "/")
	return base + path
}

type openAIChatRequest struct {
	Model           string            `json:"model"`
	Messages        []Message         `json:"messages"`
	Tools           []ToolDefinition  `json:"tools,omitempty"`
	Stream          bool              `json:"stream"`
	MaxTokens       int               `json:"max_tokens,omitempty"`
	Temperature     float64           `json:"temperature,omitempty"`
	ReasoningEffort string            `json:"reasoning_effort,omitempty"`
	Thinking        map[string]string `json:"thinking,omitempty"`
}

type openAIChatResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func firstFloat(values ...float64) float64 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
