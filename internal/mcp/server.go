package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
)

// Server is an MCP-compliant server that exposes Akemi's capabilities
// as tools, resources, and prompts to LLM hosts like Claude Desktop.
type Server struct {
	transport    Transport
	handler      *Handler
	toolProvider ToolProvider
	resources    ResourceReader
	prompts      PromptRenderer
	logger       *slog.Logger
	initialized  bool
}

// ServerConfig configures the MCP server.
type ServerConfig struct {
	Transport Transport
	Logger    *slog.Logger
	Tools     ToolProvider
	Resources ResourceReader
	Prompts   PromptRenderer
}

// NewServer creates an MCP server.
func NewServer(cfg ServerConfig) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Tools == nil {
		cfg.Tools = &noopToolProvider{}
	}
	if cfg.Resources == nil {
		cfg.Resources = &noopResourceReader{}
	}
	if cfg.Prompts == nil {
		cfg.Prompts = &noopPromptRenderer{}
	}

	s := &Server{
		transport:    cfg.Transport,
		logger:       cfg.Logger,
		toolProvider: cfg.Tools,
		resources:    cfg.Resources,
		prompts:      cfg.Prompts,
	}

	s.handler = NewHandler(s)
	return s
}

// Run starts the MCP server. It blocks until the server is closed.
func (s *Server) Run() error {
	if err := s.transport.Start(); err != nil {
		return fmt.Errorf("transport start failed: %w", err)
	}

	s.logger.Info("MCP server running",
		slog.String("name", "Akemi MCP Server"),
		slog.String("version", "2.0.0-dev"),
	)

	for req := range s.transport.Receive() {
		if req == nil {
			continue
		}
		s.handleRequest(req)
	}

	s.logger.Info("MCP server stopped")
	return nil
}

func (s *Server) handleRequest(req *Request) {
	ctx := context.Background()

	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "initialized", NotifInitialized:
		s.initialized = true
		s.logger.Debug("client initialized")
	case "tools/list":
		s.handleToolsList(req)
	case "tools/call":
		s.handleToolsCall(ctx, req)
	case "resources/list":
		s.handleResourcesList(req)
	case "resources/read":
		s.handleResourcesRead(req)
	case "prompts/list":
		s.handlePromptsList(req)
	case "prompts/get":
		s.handlePromptsGet(req)
	case "ping":
		s.handlePing(req)
	default:
		s.logger.Warn("unknown method", slog.String("method", req.Method))
		if req.ID == nil {
			return
		}
		resp := NewErrorResponse(req.ID, ErrMethodNotFound,
			fmt.Sprintf("unknown method: %s", req.Method), nil)
		s.transport.Send(resp)
	}
}

func (s *Server) handleInitialize(req *Request) {
	var params InitializeParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.transport.Send(NewErrorResponse(req.ID, ErrInvalidParams,
			"invalid initialize params", err.Error()))
		return
	}

	s.logger.Info("client initializing",
		slog.String("client_name", params.ClientInfo.Name),
		slog.String("client_version", params.ClientInfo.Version),
		slog.String("protocol_version", params.ProtocolVersion),
	)

	result := InitializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities: ServerCapabilities{
			Tools:     &ToolsCapability{ListChanged: false},
			Resources: &ResourcesCapability{Subscribe: true, ListChanged: false},
			Prompts:   &PromptsCapability{ListChanged: false},
		},
		ServerInfo: ServerInfo{
			Name:    "Akemi",
			Version: "2.0.0-dev",
		},
		Instructions: "Use Akemi tools only for authorized security testing. Long-running tools emit progress and publish structured results through akemi:// resources.",
	}

	s.transport.Send(NewSuccessResponse(req.ID, result))
}

func (s *Server) handlePing(req *Request) {
	s.transport.Send(NewSuccessResponse(req.ID, map[string]string{}))
}

func (s *Server) handleToolsList(req *Request) {
	tools := s.toolProvider.List()
	result := ToolsListResult{Tools: tools}
	s.transport.Send(NewSuccessResponse(req.ID, result))
}

func (s *Server) handleToolsCall(ctx context.Context, req *Request) {
	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.transport.Send(NewErrorResponse(req.ID, ErrInvalidParams,
			"invalid tool call params", err.Error()))
		return
	}

	s.logger.Info("tool call", slog.String("tool", params.Name))

	progressToken := progressToken(params.Meta)
	if progressToken != nil {
		_ = s.transport.Send(NewProgressNotification(progressToken, 0, 1, "starting "+params.Name))
	}

	result, err := s.callTool(ctx, params.Name, params.Arguments)
	if err != nil {
		s.logger.Error("tool call failed",
			slog.String("tool", params.Name),
			slog.String("error", err.Error()),
		)
		if progressToken != nil {
			_ = s.transport.Send(NewProgressNotification(progressToken, 1, 1, "failed "+params.Name))
		}
		s.transport.Send(NewSuccessResponse(req.ID, ToolCallResult{
			Content: []ContentBlock{ErrorContent(err)},
			IsError: true,
		}))
		return
	}

	if progressToken != nil {
		_ = s.transport.Send(NewProgressNotification(progressToken, 1, 1, "completed "+params.Name))
	}
	s.transport.Send(NewSuccessResponse(req.ID, result))
	_ = s.transport.Send(NewResourceUpdatedNotification("akemi://scan/current/summary"))
}

func (s *Server) callTool(ctx context.Context, name string, args map[string]interface{}) (*ToolCallResult, error) {
	if structured, ok := s.toolProvider.(StructuredToolProvider); ok {
		return structured.CallStructured(ctx, name, args)
	}
	content, err := s.toolProvider.Call(ctx, name, args)
	if err != nil {
		return nil, err
	}
	return &ToolCallResult{Content: content}, nil
}

func progressToken(meta map[string]interface{}) interface{} {
	if meta == nil {
		return nil
	}
	if token, ok := meta["progressToken"]; ok {
		return token
	}
	return nil
}

func (s *Server) handleResourcesList(req *Request) {
	resources := s.resources.List()
	result := ResourcesListResult{Resources: resources}
	s.transport.Send(NewSuccessResponse(req.ID, result))
}

func (s *Server) handleResourcesRead(req *Request) {
	var params ResourceReadParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.transport.Send(NewErrorResponse(req.ID, ErrInvalidParams,
			"invalid resource read params", err.Error()))
		return
	}

	contents, err := s.resources.Read(params.URI)
	if err != nil {
		s.transport.Send(NewErrorResponse(req.ID, ErrInvalidParams,
			"resource not found", err.Error()))
		return
	}

	result := ResourceReadResult{Contents: contents}
	s.transport.Send(NewSuccessResponse(req.ID, result))
}

func (s *Server) handlePromptsList(req *Request) {
	prompts := s.prompts.List()
	result := PromptsListResult{Prompts: prompts}
	s.transport.Send(NewSuccessResponse(req.ID, result))
}

func (s *Server) handlePromptsGet(req *Request) {
	var params PromptGetParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.transport.Send(NewErrorResponse(req.ID, ErrInvalidParams,
			"invalid prompt get params", err.Error()))
		return
	}

	result, err := s.prompts.Get(params.Name, params.Arguments)
	if err != nil {
		s.transport.Send(NewErrorResponse(req.ID, ErrInvalidParams,
			"prompt not found", err.Error()))
		return
	}

	s.transport.Send(NewSuccessResponse(req.ID, result))
}

// Handler routes JSON-RPC methods to the appropriate server logic.
type Handler struct {
	server *Server
}

func NewHandler(server *Server) *Handler {
	return &Handler{server: server}
}

// =============================================================================
// No-op providers (fallbacks)
// =============================================================================

type noopToolProvider struct{}

func (n *noopToolProvider) List() []Tool { return nil }
func (n *noopToolProvider) Call(ctx interface{}, name string, args map[string]interface{}) ([]ContentBlock, error) {
	return nil, fmt.Errorf("no tool provider configured")
}

type noopResourceReader struct{}

func (n *noopResourceReader) List() []Resource { return nil }
func (n *noopResourceReader) Read(uri string) ([]ResourceContent, error) {
	return nil, fmt.Errorf("resource not found: %s", uri)
}

type noopPromptRenderer struct{}

func (n *noopPromptRenderer) List() []Prompt { return nil }
func (n *noopPromptRenderer) Get(name string, args map[string]string) (*PromptGetResult, error) {
	return nil, fmt.Errorf("prompt not found: %s", name)
}
