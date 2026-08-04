package execution

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"Akemi/internal/engagement"
)

func TestWrapHTTPClientCapsBodyAndCountsRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer server.Close()

	policy := DefaultPolicy()
	policy.MaxResponseBytes = 4
	policy.MaxRequests = 1
	run, err := NewRunContext("run-http", engagement.TargetProfile{Domain: "127.0.0.1"}, ScopePolicy{ExactHosts: []string{"127.0.0.1"}}, policy)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRunContext(context.Background(), run)
	client := WrapHTTPClient(ctx, &http.Client{})
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "0123" {
		t.Fatalf("body was not capped: %q", body)
	}
	if got := run.limiter.budget.Used(); got != 1 {
		t.Fatalf("expected one request, got %d", got)
	}
}

func TestWrapHTTPClientPropagatesCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer server.Close()

	policy := DefaultPolicy()
	run, err := NewRunContext("run-cancel", engagement.TargetProfile{Domain: "127.0.0.1"}, ScopePolicy{ExactHosts: []string{"127.0.0.1"}}, policy)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(WithRunContext(context.Background(), run))
	client := WrapHTTPClient(ctx, &http.Client{})
	cancel()
	_, err = client.Get(server.URL)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "canceled") {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
