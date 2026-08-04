package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeLLMProviderGemini(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"google", "google"},
		{"gemini", "google"},
		{"Gemini", "google"},
		{"deepseek", "deepseek"},
		{"openai", "openai"},
		{"anthropic", "anthropic"},
		{"local", "local"},
		{"invalid", ""},
	}

	for _, tt := range tests {
		got := NormalizeLLMProvider(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeLLMProvider(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestGeminiDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.LLM.Google.Model != "gemini-3.6-flash" {
		t.Errorf("Default Google model = %q; want gemini-3.6-flash", cfg.LLM.Google.Model)
	}
	if cfg.LLM.Google.BaseURL != "https://generativelanguage.googleapis.com/v1beta/openai" {
		t.Errorf("Default Google BaseURL = %q; want OpenAI-compatible URL", cfg.LLM.Google.BaseURL)
	}
}

func TestEnsureWorkemiConfigFileCreatesWorkemiOnFirstOpen(t *testing.T) {
	workDir := t.TempDir()
	workemiDir := filepath.Join(workDir, "workemi")
	t.Setenv("AKEMI_WORKEMI_DIR", workemiDir)

	configPath, cfg, unconfigured, err := EnsureWorkemiConfigFile()
	if err != nil {
		t.Fatalf("EnsureWorkemiConfigFile() error = %v", err)
	}
	if !unconfigured || cfg == nil || cfg.General.Configured != 0 {
		t.Fatalf("first open = path %q, cfg %#v, unconfigured %v", configPath, cfg, unconfigured)
	}
	if _, err := os.Stat(workemiDir); err != nil {
		t.Fatalf("workemi directory was not created: %v", err)
	}
	if want := filepath.Join(workemiDir, "akemi.conf"); configPath != want {
		t.Fatalf("config path = %q, want %q", configPath, want)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read first-open config: %v", err)
	}
	if !strings.Contains(string(data), "configured = 0") {
		t.Fatalf("first-open config does not set configured = 0: %s", data)
	}
}

func TestWorkemiDirectoryDefaultsToAkemiDirectory(t *testing.T) {
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	workDir := t.TempDir()
	if err := os.Chdir(workDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldDir) })
	t.Setenv("AKEMI_WORKEMI_DIR", "")

	if got, want := WorkemiDirectory(), filepath.Join(workDir, "workemi"); got != want {
		t.Fatalf("WorkemiDirectory() = %q, want %q", got, want)
	}
}

func TestWorkemiDirectoryUsesAkemiRootFromBinWindows(t *testing.T) {
	root := findAkemiRoot(".")
	if root == "" {
		t.Skip("Akemi application root is not available")
	}
	binWindows := filepath.Join(root, "bin", "windows")
	if _, err := os.Stat(binWindows); err != nil {
		t.Skip("bin/windows is not available")
	}
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(binWindows); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldDir) })
	t.Setenv("AKEMI_WORKEMI_DIR", "")

	if got, want := WorkemiDirectory(), filepath.Join(root, "workemi"); got != want {
		t.Fatalf("WorkemiDirectory() from bin/windows = %q, want %q", got, want)
	}
}
