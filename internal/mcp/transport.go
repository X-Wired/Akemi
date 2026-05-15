package mcp

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Transport abstracts the communication channel between MCP client and server.
// Akemi supports stdio and Streamable HTTP. The legacy HTTP+SSE transport is
// intentionally not implemented.
type Transport interface {
	Start() error
	Send(msg interface{}) error
	Receive() <-chan *Request
	Close() error
}

// StdioTransport communicates over stdin/stdout.
type StdioTransport struct {
	reader   *bufio.Scanner
	writer   io.Writer
	incoming chan *Request
	done     chan struct{}
	mu       sync.Mutex
	logger   *slog.Logger
}

// NewStdioTransport creates a stdio transport.
func NewStdioTransport(logger *slog.Logger) *StdioTransport {
	if logger == nil {
		logger = slog.Default()
	}
	return &StdioTransport{
		reader:   bufio.NewScanner(os.Stdin),
		writer:   os.Stdout,
		incoming: make(chan *Request, 64),
		done:     make(chan struct{}),
		logger:   logger,
	}
}

// Start begins reading JSON-RPC messages from stdin.
func (t *StdioTransport) Start() error {
	t.reader.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	go func() {
		defer close(t.incoming)
		for t.reader.Scan() {
			line := t.reader.Text()
			if line == "" {
				continue
			}

			var req Request
			if err := json.Unmarshal([]byte(line), &req); err != nil {
				t.logger.Warn("failed to parse stdin message",
					slog.String("error", err.Error()),
					slog.String("raw", truncateForLog(line, 200)),
				)
				continue
			}
			t.incoming <- &req
		}
		if err := t.reader.Err(); err != nil {
			t.logger.Error("stdin scanner error", slog.String("error", err.Error()))
		}
		close(t.done)
	}()

	return nil
}

// Send writes a JSON-RPC message to stdout.
func (t *StdioTransport) Send(msg interface{}) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}
	_, err = fmt.Fprintf(t.writer, "%s\n", data)
	return err
}

// Receive returns the channel of incoming requests.
func (t *StdioTransport) Receive() <-chan *Request {
	return t.incoming
}

// Close shuts down the transport.
func (t *StdioTransport) Close() error {
	return nil
}

const defaultHTTPMaxBodyBytes int64 = 8 << 20
const defaultHTTPRequestTimeout = 5 * time.Hour

// StreamableHTTPConfig configures the Streamable HTTP transport.
type StreamableHTTPConfig struct {
	Host           string
	Port           int
	Path           string
	APIKey         string
	AllowedOrigins []string
	MaxBodyBytes   int64
	Logger         *slog.Logger
}

// StreamableHTTPTransport communicates over a single MCP HTTP endpoint.
type StreamableHTTPTransport struct {
	host           string
	port           int
	path           string
	apiKey         string
	allowedOrigins map[string]struct{}
	maxBodyBytes   int64
	server         *http.Server
	incoming       chan *Request
	pending        map[string]chan interface{}
	pendingMu      sync.Mutex
	clients        map[chan interface{}]struct{}
	clientsMu      sync.RWMutex
	logger         *slog.Logger
}

// NewStreamableHTTPTransport creates a Streamable HTTP transport.
func NewStreamableHTTPTransport(cfg StreamableHTTPConfig) *StreamableHTTPTransport {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if strings.TrimSpace(cfg.Host) == "" {
		cfg.Host = "127.0.0.1"
	}
	path := strings.TrimSpace(cfg.Path)
	if path == "" {
		path = "/mcp"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultHTTPMaxBodyBytes
	}
	origins := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, origin := range cfg.AllowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			origins[origin] = struct{}{}
		}
	}
	return &StreamableHTTPTransport{
		host:           cfg.Host,
		port:           cfg.Port,
		path:           path,
		apiKey:         strings.TrimSpace(cfg.APIKey),
		allowedOrigins: origins,
		maxBodyBytes:   cfg.MaxBodyBytes,
		incoming:       make(chan *Request, 64),
		pending:        make(map[string]chan interface{}),
		clients:        make(map[chan interface{}]struct{}),
		logger:         logger,
	}
}

// Start begins listening for Streamable HTTP MCP connections.
func (t *StreamableHTTPTransport) Start() error {
	if !isLocalBind(t.host) && t.apiKey == "" {
		return fmt.Errorf("streamable HTTP on non-local host %s requires --api-key", t.host)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(t.path, t.handleMCP)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	t.server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", t.host, t.port),
		Handler: mux,
	}

	t.logger.Info("MCP Streamable HTTP server starting",
		slog.String("host", t.host),
		slog.Int("port", t.port),
		slog.String("path", t.path),
		slog.Bool("auth_enabled", t.apiKey != ""),
	)

	go func() {
		if err := t.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.logger.Error("Streamable HTTP server error", slog.String("error", err.Error()))
		}
	}()

	return nil
}

func (t *StreamableHTTPTransport) handleMCP(w http.ResponseWriter, r *http.Request) {
	if err := t.validateCommon(r); err != nil {
		t.writeHTTPError(w, err.status, err.message)
		return
	}

	switch r.Method {
	case http.MethodPost:
		t.handleMCPPost(w, r)
	case http.MethodGet:
		t.handleMCPGet(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		t.writeHTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (t *StreamableHTTPTransport) handleMCPGet(w http.ResponseWriter, r *http.Request) {
	if !accepts(r.Header.Get("Accept"), "text/event-stream") {
		t.writeHTTPError(w, http.StatusNotAcceptable, "GET requires Accept: text/event-stream")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	ch := make(chan interface{}, 32)
	t.clientsMu.Lock()
	t.clients[ch] = struct{}{}
	t.clientsMu.Unlock()
	defer func() {
		t.clientsMu.Lock()
		delete(t.clients, ch)
		t.clientsMu.Unlock()
	}()

	fmt.Fprintf(w, "id: %d\ndata:\n\n", time.Now().UnixNano())
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(msg)
			fmt.Fprintf(w, "id: %d\nevent: message\ndata: %s\n\n", time.Now().UnixNano(), data)
			flusher.Flush()
		}
	}
}

func (t *StreamableHTTPTransport) handleMCPPost(w http.ResponseWriter, r *http.Request) {
	if !accepts(r.Header.Get("Accept"), "application/json") || !accepts(r.Header.Get("Accept"), "text/event-stream") {
		t.writeHTTPError(w, http.StatusNotAcceptable, "POST requires Accept: application/json, text/event-stream")
		return
	}

	reader := http.MaxBytesReader(w, r.Body, t.maxBodyBytes)
	defer r.Body.Close()

	var req Request
	if err := json.NewDecoder(reader).Decode(&req); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "http: request body too large") {
			status = http.StatusRequestEntityTooLarge
		}
		t.writeHTTPError(w, status, "invalid JSON-RPC request")
		return
	}
	if err := validateRequest(req); err != nil {
		t.writeHTTPError(w, http.StatusBadRequest, err.Error())
		return
	}

	t.logger.Info("MCP HTTP request",
		slog.String("method", req.Method),
		slog.Any("id", req.ID),
		slog.String("remote_addr", r.RemoteAddr),
	)

	if req.ID == nil {
		select {
		case t.incoming <- &req:
			w.WriteHeader(http.StatusAccepted)
		case <-r.Context().Done():
			t.writeHTTPError(w, http.StatusRequestTimeout, "request cancelled")
		}
		return
	}

	key := rpcIDKey(req.ID)
	ch := make(chan interface{}, 1)
	t.pendingMu.Lock()
	t.pending[key] = ch
	t.pendingMu.Unlock()
	defer func() {
		t.pendingMu.Lock()
		delete(t.pending, key)
		t.pendingMu.Unlock()
	}()

	select {
	case t.incoming <- &req:
	case <-r.Context().Done():
		t.writeHTTPError(w, http.StatusRequestTimeout, "request cancelled")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), defaultHTTPRequestTimeout)
	defer cancel()
	select {
	case msg := <-ch:
		data, err := json.Marshal(msg)
		if err != nil {
			t.writeHTTPError(w, http.StatusInternalServerError, "failed to marshal JSON-RPC response")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	case <-ctx.Done():
		t.writeHTTPError(w, http.StatusRequestTimeout, "request timed out")
	}
}

// Send routes responses to their waiting HTTP request and broadcasts
// notifications to any GET SSE listeners.
func (t *StreamableHTTPTransport) Send(msg interface{}) error {
	if id, ok := responseID(msg); ok {
		t.pendingMu.Lock()
		ch := t.pending[rpcIDKey(id)]
		t.pendingMu.Unlock()
		if ch != nil {
			select {
			case ch <- msg:
			default:
			}
		}
		return nil
	}

	t.clientsMu.RLock()
	defer t.clientsMu.RUnlock()
	for ch := range t.clients {
		select {
		case ch <- msg:
		default:
		}
	}
	return nil
}

// Receive returns the channel of incoming requests.
func (t *StreamableHTTPTransport) Receive() <-chan *Request {
	return t.incoming
}

// Close shuts down the HTTP server.
func (t *StreamableHTTPTransport) Close() error {
	if t.server != nil {
		return t.server.Close()
	}
	return nil
}

type httpValidationError struct {
	status  int
	message string
}

func (t *StreamableHTTPTransport) validateCommon(r *http.Request) *httpValidationError {
	if protocol := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version")); protocol != "" && protocol != ProtocolVersion {
		return &httpValidationError{status: http.StatusBadRequest, message: "unsupported MCP protocol version"}
	}
	if err := t.validateAuth(r); err != nil {
		return err
	}
	if err := t.validateOrigin(r); err != nil {
		return err
	}
	return nil
}

func (t *StreamableHTTPTransport) validateAuth(r *http.Request) *httpValidationError {
	if t.apiKey == "" {
		return nil
	}
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return &httpValidationError{status: http.StatusUnauthorized, message: "missing bearer token"}
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if subtle.ConstantTimeCompare([]byte(token), []byte(t.apiKey)) != 1 {
		return &httpValidationError{status: http.StatusUnauthorized, message: "invalid bearer token"}
	}
	return nil
}

func (t *StreamableHTTPTransport) validateOrigin(r *http.Request) *httpValidationError {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return nil
	}
	if _, ok := t.allowedOrigins["*"]; ok {
		return nil
	}
	if _, ok := t.allowedOrigins[origin]; ok {
		return nil
	}
	if len(t.allowedOrigins) == 0 && isLocalOrigin(origin) {
		return nil
	}
	return &httpValidationError{status: http.StatusForbidden, message: "origin is not allowed"}
}

func (t *StreamableHTTPTransport) writeHTTPError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(NewErrorResponse(nil, ErrInvalidRequest, message, nil))
}

func validateRequest(req Request) error {
	if req.JSONRPC != JSONRPCVersion {
		return fmt.Errorf("jsonrpc must be %s", JSONRPCVersion)
	}
	if strings.TrimSpace(req.Method) == "" {
		return fmt.Errorf("method is required")
	}
	return nil
}

func accepts(header, value string) bool {
	if strings.TrimSpace(header) == "" {
		return true
	}
	for _, part := range strings.Split(header, ",") {
		media := strings.TrimSpace(strings.Split(part, ";")[0])
		if media == value || media == "*/*" {
			return true
		}
	}
	return false
}

func responseID(msg interface{}) (interface{}, bool) {
	switch v := msg.(type) {
	case Response:
		return v.ID, v.ID != nil
	case *Response:
		if v == nil {
			return nil, false
		}
		return v.ID, v.ID != nil
	case ErrorResponse:
		return v.ID, v.ID != nil
	case *ErrorResponse:
		if v == nil {
			return nil, false
		}
		return v.ID, v.ID != nil
	default:
		return nil, false
	}
}

func rpcIDKey(id interface{}) string {
	data, err := json.Marshal(id)
	if err != nil {
		return fmt.Sprint(id)
	}
	return string(data)
}

func isLocalBind(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isLocalOrigin(origin string) bool {
	parts := strings.SplitN(strings.TrimSpace(origin), "://", 2)
	if len(parts) != 2 {
		return false
	}
	host := parts[1]
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return isLocalBind(host)
}

func truncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
