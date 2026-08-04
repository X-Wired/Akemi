package core

import (
	"testing"
)

func TestCleanInput(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"\x00https://127.0.0.1:8643", "https://127.0.0.1:8643"},
		{"  \x00http://example.com \t", "http://example.com"},
		{"127.0.0.1:8080\x00", "127.0.0.1:8080"},
	}

	for _, tt := range tests {
		got := CleanInput(tt.input)
		if got != tt.expected {
			t.Errorf("CleanInput(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestEnsureProtocol(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"\x00https://127.0.0.1:8643", "https://127.0.0.1:8643"},
		{"https://127.0.0.1:8643", "https://127.0.0.1:8643"},
		{"http://127.0.0.1:8643", "http://127.0.0.1:8643"},
		{"127.0.0.1:8643", "http://127.0.0.1:8643"},
		{"10.0.0.0/24", "10.0.0.0/24"},
	}

	for _, tt := range tests {
		got := EnsureProtocol(tt.input)
		if got != tt.expected {
			t.Errorf("EnsureProtocol(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}
