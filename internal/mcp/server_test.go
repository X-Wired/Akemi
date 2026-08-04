package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

type testTransport struct {
	incoming chan *Request
	sent     []interface{}
}

func (t *testTransport) Start() error                   { return nil }
func (t *testTransport) Receive() <-chan *Request       { return t.incoming }
func (t *testTransport) Close() error                   { return nil }
func (t *testTransport) Send(message interface{}) error { t.sent = append(t.sent, message); return nil }

type contextToolProvider struct {
	ctx context.Context
}

func (p *contextToolProvider) List() []Tool {
	return []Tool{{Name: "test_tool", InputSchema: ToolInputSchema{Type: "object"}}}
}
func (p *contextToolProvider) Call(ctx interface{}, name string, args map[string]interface{}) ([]ContentBlock, error) {
	p.ctx, _ = ctx.(context.Context)
	return []ContentBlock{TextContent("ok")}, nil
}

func TestServerRejectsCallsBeforeInitialize(t *testing.T) {
	transport := &testTransport{incoming: make(chan *Request)}
	server := NewServer(ServerConfig{Transport: transport, Logger: slog.Default()})
	server.handleRequest(&Request{JSONRPC: JSONRPCVersion, ID: "1", Method: "tools/list"})
	if len(transport.sent) != 1 {
		t.Fatalf("expected one lifecycle error, got %d", len(transport.sent))
	}
	if _, ok := transport.sent[0].(ErrorResponse); !ok {
		t.Fatalf("expected JSON-RPC error, got %#v", transport.sent[0])
	}
}

func TestServerPassesRequestContextToToolsAfterInitialize(t *testing.T) {
	transport := &testTransport{incoming: make(chan *Request)}
	provider := &contextToolProvider{}
	server := NewServer(ServerConfig{Transport: transport, Tools: provider, Logger: slog.Default()})
	params, _ := json.Marshal(InitializeParams{ProtocolVersion: ProtocolVersion, ClientInfo: ClientInfo{Name: "test", Version: "1"}})
	server.handleRequest(&Request{JSONRPC: JSONRPCVersion, ID: "1", Method: "initialize", Params: params})
	server.handleRequest(&Request{JSONRPC: JSONRPCVersion, Method: NotifInitialized})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server.handleRequest(&Request{JSONRPC: JSONRPCVersion, ID: "2", Method: "tools/call", Context: ctx, Params: mustJSON(ToolCallParams{Name: "test_tool"})})
	if provider.ctx != ctx {
		t.Fatal("tool did not receive the request context")
	}
}

func mustJSON(value interface{}) json.RawMessage {
	data, _ := json.Marshal(value)
	return data
}
