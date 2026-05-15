// Package mcp implements the Model Context Protocol (MCP) server.
// MCP is an open protocol that standardizes how applications provide
// context to LLMs. It uses JSON-RPC 2.0 over stdio or Streamable HTTP.
//
// Spec: https://modelcontextprotocol.io/
package mcp

import "encoding/json"

// =============================================================================
// JSON-RPC 2.0 Base Types
// =============================================================================

// JSONRPCVersion is the JSON-RPC version string.
const JSONRPCVersion = "2.0"

// ProtocolVersion is the MCP version Akemi negotiates with clients.
const ProtocolVersion = "2025-11-25"

// Request represents a JSON-RPC request.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response represents a JSON-RPC success response.
type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result"`
}

// ErrorResponse represents a JSON-RPC error response.
type ErrorResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Error   RPCError    `json:"error"`
}

// RPCError holds JSON-RPC error details.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Notification represents a JSON-RPC notification (no ID).
type Notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	ErrParse          = -32700
	ErrInvalidRequest = -32600
	ErrMethodNotFound = -32601
	ErrInvalidParams  = -32602
	ErrInternal       = -32603
)

// =============================================================================
// MCP Lifecycle Messages
// =============================================================================

// InitializeParams is the params for the "initialize" request.
type InitializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      ClientInfo         `json:"clientInfo"`
}

// ClientCapabilities describes what the client supports.
type ClientCapabilities struct {
	Roots        *RootsCapability       `json:"roots,omitempty"`
	Sampling     *SamplingCapability    `json:"sampling,omitempty"`
	Elicitation  *ElicitationCapability `json:"elicitation,omitempty"`
	Experimental map[string]interface{} `json:"experimental,omitempty"`
}

// ElicitationCapability indicates the client supports user elicitation.
type ElicitationCapability struct {
	Form map[string]interface{} `json:"form,omitempty"`
	URL  map[string]interface{} `json:"url,omitempty"`
}

// RootsCapability indicates the client provides filesystem roots.
type RootsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// SamplingCapability indicates the client supports LLM sampling.
type SamplingCapability struct{}

// ClientInfo identifies the MCP client.
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitializeResult is the response to "initialize".
type InitializeResult struct {
	Meta            map[string]interface{} `json:"_meta,omitempty"`
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    ServerCapabilities     `json:"capabilities"`
	ServerInfo      ServerInfo             `json:"serverInfo"`
	Instructions    string                 `json:"instructions,omitempty"`
}

// ServerCapabilities describes what the server supports.
type ServerCapabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
	Prompts   *PromptsCapability   `json:"prompts,omitempty"`
}

// ToolsCapability indicates tool support.
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapability indicates resource support.
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// PromptsCapability indicates prompt template support.
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ServerInfo identifies the MCP server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// =============================================================================
// MCP Tool Types
// =============================================================================

// ToolsListResult is the response to "tools/list".
type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

// Tool describes a callable tool.
type Tool struct {
	Name         string                 `json:"name"`
	Title        string                 `json:"title,omitempty"`
	Description  string                 `json:"description,omitempty"`
	InputSchema  ToolInputSchema        `json:"inputSchema"`
	Execution    *ToolExecution         `json:"execution,omitempty"`
	OutputSchema *ToolInputSchema       `json:"outputSchema,omitempty"`
	Annotations  *ToolAnnotations       `json:"annotations,omitempty"`
	Meta         map[string]interface{} `json:"_meta,omitempty"`

	// Local metadata used by Akemi's assistant and agent layers.
	Risk            string   `json:"-"`
	Category        string   `json:"-"`
	Provides        []string `json:"-"`
	Requires        []string `json:"-"`
	AssistantHidden bool     `json:"-"`
}

// ToolInputSchema is a JSON Schema for tool parameters.
type ToolInputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties,omitempty"`
	Required   []string            `json:"required,omitempty"`
}

// ToolExecution describes execution behavior for clients that display tools.
type ToolExecution struct {
	Type string `json:"type,omitempty"`
}

// ToolAnnotations are MCP hints for client UIs and tool planners.
type ToolAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

// Property describes a single parameter in a tool's input schema.
type Property struct {
	Type        string              `json:"type"`
	Description string              `json:"description,omitempty"`
	Enum        []string            `json:"enum,omitempty"`
	Default     interface{}         `json:"default,omitempty"`
	Items       *Property           `json:"items,omitempty"`      // For array types
	Properties  map[string]Property `json:"properties,omitempty"` // For object types
}

// ToolCallParams is the params for "tools/call".
type ToolCallParams struct {
	Meta      map[string]interface{} `json:"_meta,omitempty"`
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// ToolCallResult is the response to "tools/call".
type ToolCallResult struct {
	Meta              map[string]interface{} `json:"_meta,omitempty"`
	Content           []ContentBlock         `json:"content"`
	StructuredContent map[string]interface{} `json:"structuredContent,omitempty"`
	IsError           bool                   `json:"isError,omitempty"`
}

// ContentBlock represents a piece of content in a tool result.
type ContentBlock struct {
	Type     string `json:"type"` // "text" | "image" | "resource"
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"` // base64 for images
	MimeType string `json:"mimeType,omitempty"`
}

// =============================================================================
// MCP Resource Types
// =============================================================================

// ResourcesListResult is the response to "resources/list".
type ResourcesListResult struct {
	Resources []Resource `json:"resources"`
}

// Resource describes a readable resource.
type Resource struct {
	URI         string                 `json:"uri"`
	Name        string                 `json:"name"`
	Title       string                 `json:"title,omitempty"`
	Description string                 `json:"description,omitempty"`
	MimeType    string                 `json:"mimeType,omitempty"`
	Meta        map[string]interface{} `json:"_meta,omitempty"`
}

// ResourceReadParams is the params for "resources/read".
type ResourceReadParams struct {
	URI string `json:"uri"`
}

// ResourceReadResult is the response to "resources/read".
type ResourceReadResult struct {
	Contents []ResourceContent `json:"contents"`
}

// ResourceContent holds the actual resource data.
type ResourceContent struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"` // base64
}

// =============================================================================
// MCP Prompt Types
// =============================================================================

// PromptsListResult is the response to "prompts/list".
type PromptsListResult struct {
	Prompts []Prompt `json:"prompts"`
}

// Prompt describes a prompt template.
type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// PromptArgument is a parameter for a prompt template.
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// PromptGetParams is the params for "prompts/get".
type PromptGetParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

// PromptGetResult is the response to "prompts/get".
type PromptGetResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// PromptMessage is a single message in a prompt result.
type PromptMessage struct {
	Role    string       `json:"role"` // "user" | "assistant"
	Content ContentBlock `json:"content"`
}

// =============================================================================
// MCP Notification Types
// =============================================================================

// NotificationMethod names.
const (
	NotifInitialized          = "notifications/initialized"
	NotifProgress             = "notifications/progress"
	NotifToolsListChanged     = "notifications/tools/list_changed"
	NotifResourcesListChanged = "notifications/resources/list_changed"
	NotifResourcesUpdated     = "notifications/resources/updated"
	NotifPromptsListChanged   = "notifications/prompts/list_changed"
)

// ProgressNotificationParams reports progress for a long-running request.
type ProgressNotificationParams struct {
	Meta          map[string]interface{} `json:"_meta,omitempty"`
	ProgressToken interface{}            `json:"progressToken"`
	Progress      float64                `json:"progress"`
	Total         float64                `json:"total,omitempty"`
	Message       string                 `json:"message,omitempty"`
}

// ResourceUpdatedNotificationParams reports that a resource changed.
type ResourceUpdatedNotificationParams struct {
	URI string `json:"uri"`
}

// =============================================================================
// Convenience Constructors
// =============================================================================

// NewSuccessResponse creates a JSON-RPC success response.
func NewSuccessResponse(id interface{}, result interface{}) Response {
	return Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Result:  result,
	}
}

// NewErrorResponse creates a JSON-RPC error response.
func NewErrorResponse(id interface{}, code int, message string, data interface{}) ErrorResponse {
	return ErrorResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

// NewNotification creates a JSON-RPC notification.
func NewNotification(method string, params interface{}) Notification {
	raw, _ := json.Marshal(params)
	return Notification{
		JSONRPC: JSONRPCVersion,
		Method:  method,
		Params:  raw,
	}
}

// TextContent creates a text content block.
func TextContent(text string) ContentBlock {
	return ContentBlock{Type: "text", Text: text}
}

// ErrorContent creates an error content block for tool results.
func ErrorContent(err error) ContentBlock {
	return ContentBlock{Type: "text", Text: "Error: " + err.Error()}
}

// NewProgressNotification creates an MCP progress notification.
func NewProgressNotification(token interface{}, progress, total float64, message string) Notification {
	return NewNotification(NotifProgress, ProgressNotificationParams{
		ProgressToken: token,
		Progress:      progress,
		Total:         total,
		Message:       message,
	})
}

// NewResourceUpdatedNotification creates a resource update notification.
func NewResourceUpdatedNotification(uri string) Notification {
	return NewNotification(NotifResourcesUpdated, ResourceUpdatedNotificationParams{URI: uri})
}

// =============================================================================
// Provider Interfaces (avoids circular imports with tools/resources/prompts)
// =============================================================================

// ToolProvider lists and calls tools.
type ToolProvider interface {
	List() []Tool
	Call(ctx interface{}, name string, args map[string]interface{}) ([]ContentBlock, error)
}

// StructuredToolProvider optionally returns modern MCP structured tool results.
type StructuredToolProvider interface {
	List() []Tool
	Call(ctx interface{}, name string, args map[string]interface{}) ([]ContentBlock, error)
	CallStructured(ctx interface{}, name string, args map[string]interface{}) (*ToolCallResult, error)
}

// ResourceReader lists and reads resources.
type ResourceReader interface {
	List() []Resource
	Read(uri string) ([]ResourceContent, error)
}

// PromptRenderer lists and renders prompts.
type PromptRenderer interface {
	List() []Prompt
	Get(name string, args map[string]string) (*PromptGetResult, error)
}
