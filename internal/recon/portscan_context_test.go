package recon

import (
	"context"
	"errors"
	"testing"
)

func TestPortScannerRunContextStopsBeforeDialing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	scanner := &PortScanner{
		Host:    "127.0.0.1",
		Ports:   []int{1, 2, 3},
		Threads: 2,
	}
	_, err := scanner.runGoNative(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestExtractHostWithPort(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"127.0.0.1:8643", "127.0.0.1"},
		{"http://127.0.0.1:8643", "127.0.0.1"},
		{"https://example.com:8443/api", "example.com"},
		{"127.0.0.1", "127.0.0.1"},
		{"example.com", "example.com"},
	}

	for _, tt := range tests {
		got := extractHost(tt.input)
		if got != tt.expected {
			t.Errorf("extractHost(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}
