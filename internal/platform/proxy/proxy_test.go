package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseProxyURL(t *testing.T) {
	t.Parallel()

	valid := []string{
		"http://127.0.0.1:8080",
		"https://proxy.example:8443",
		"socks5://127.0.0.1:9050",
		"socks5h://127.0.0.1:9050",
	}
	for _, raw := range valid {
		if _, err := parseProxyURL(raw); err != nil {
			t.Fatalf("expected valid proxy URL %q, got error: %v", raw, err)
		}
	}

	if _, err := parseProxyURL("ftp://proxy.example:21"); err == nil {
		t.Fatal("expected unsupported proxy scheme to fail")
	}
}

func TestNormalizeProxyConfigEntry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want string
	}{
		{raw: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080"},
		{raw: "127.0.0.1:8080", want: "http://127.0.0.1:8080"},
		{raw: "proxy.example:8080:user:pass", want: "http://user:pass@proxy.example:8080"},
	}

	for _, tt := range tests {
		got, err := normalizeProxyConfigEntry(tt.raw)
		if err != nil {
			t.Fatalf("normalizeProxyConfigEntry(%q): %v", tt.raw, err)
		}
		if got != tt.want {
			t.Fatalf("normalizeProxyConfigEntry(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestShouldBypassProxy(t *testing.T) {
	t.Setenv("AKEMI_PROXY", "")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("AKEMI_NO_PROXY", "example.com,.internal.local")
	t.Cleanup(func() {
		_ = ConfigureProxy("", "")
	})

	if err := ConfigureProxy("http://127.0.0.1:8080", ""); err != nil {
		t.Fatalf("configure proxy: %v", err)
	}

	tests := []struct {
		host string
		want bool
	}{
		{host: "localhost:8080", want: true},
		{host: "127.0.0.1:8080", want: true},
		{host: "api.example.com:443", want: true},
		{host: "svc.internal.local:8443", want: true},
		{host: "remote.target.tld:443", want: false},
	}

	for _, tt := range tests {
		if got := ShouldBypassProxy(tt.host); got != tt.want {
			t.Fatalf("ShouldBypassProxy(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestActiveProxyURLPrefersOverride(t *testing.T) {
	t.Setenv("AKEMI_PROXY", "http://env-proxy:8080")
	t.Cleanup(func() {
		_ = ConfigureProxy("", "")
		DisableProxy()
	})

	if err := ConfigureProxy("socks5://127.0.0.1:9050", ""); err != nil {
		t.Fatalf("configure proxy: %v", err)
	}

	if got := ActiveProxyURL(); got != "socks5://127.0.0.1:9050" {
		t.Fatalf("ActiveProxyURL() = %q, want override", got)
	}

	_ = ConfigureProxy("", "")
	if got := ActiveProxyURL(); got != "http://env-proxy:8080" {
		t.Fatalf("ActiveProxyURL() = %q, want env proxy", got)
	}
}

func TestActiveProxyURLFallsBackToConfigFile(t *testing.T) {
	t.Setenv("AKEMI_PROXY", "")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	if err := ConfigureProxy("", ""); err != nil {
		t.Fatalf("reset proxy config: %v", err)
	}
	defer func() {
		_ = ConfigureProxy("", "")
	}()

	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	configPath := filepath.Join(configDir, "proxy.txt")
	if err := os.WriteFile(configPath, []byte("# comment\nproxy-one.example:8080:user:pass\nsocks5://proxy-two.example:1080\n"), 0o644); err != nil {
		t.Fatalf("write proxy file: %v", err)
	}

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldWD)
	}()

	if got := ActiveProxyURL(); got != "http://user:pass@proxy-one.example:8080" {
		t.Fatalf("ActiveProxyURL() = %q, want first file proxy", got)
	}
	chain := ActiveProxyChain()
	if len(chain) != 2 {
		t.Fatalf("ActiveProxyChain() length = %d, want 2", len(chain))
	}
	if chain[1] != "socks5://proxy-two.example:1080" {
		t.Fatalf("ActiveProxyChain()[1] = %q", chain[1])
	}
	if got := ActiveProxyDisplay(); got != "http://user:pass@proxy-one.example:8080 -> socks5://proxy-two.example:1080" {
		t.Fatalf("ActiveProxyDisplay() = %q", got)
	}
	if got := ActiveProxySource(); got != "file:"+configPath {
		t.Fatalf("ActiveProxySource() = %q", got)
	}
}

func TestFirstNonEmptyEnv(t *testing.T) {
	t.Setenv("AKEMI_PROXY", "")
	t.Setenv("HTTP_PROXY", "http://proxy-one:8080")
	t.Setenv("HTTPS_PROXY", "http://proxy-two:8080")

	got := firstNonEmptyEnv("AKEMI_PROXY", "HTTP_PROXY", "HTTPS_PROXY")
	if got != "http://proxy-one:8080" {
		t.Fatalf("firstNonEmptyEnv returned %q", got)
	}

	_ = os.Unsetenv("HTTP_PROXY")
	_ = os.Unsetenv("HTTPS_PROXY")
}
