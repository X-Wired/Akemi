// Package config provides a unified configuration system for Akemi.
// Configuration is loaded from (in order of increasing priority):
//  1. Default values
//  2. TOML config file (./akemi.conf, ~/.akemi/config.toml)
//  3. Environment variables (AKEMI_* prefix)
//  4. CLI flags (highest priority)
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// AkemiConfig is the root configuration.
type AkemiConfig struct {
	General   GeneralConfig   `toml:"general"`
	Proxy     ProxyConfig     `toml:"proxy"`
	Scanner   ScannerConfig   `toml:"scanner"`
	Discovery DiscoveryConfig `toml:"discovery"`
	Vuln      VulnConfig      `toml:"vuln"`
	Fuzzing   FuzzingConfig   `toml:"fuzzing"`
	Reporting ReportingConfig `toml:"reporting"`
	Database  DatabaseConfig  `toml:"database"`
	MCPServer MCPServerConfig `toml:"mcp_server"`
	MCPClient MCPClientConfig `toml:"mcp_client"`
	LLM       LLMConfig       `toml:"llm"`
	Agent     AgentConfig     `toml:"agent"`
	Safety    SafetyConfig    `toml:"safety"`
	Plugins   PluginsConfig   `toml:"plugins"`
	Advanced  AdvancedConfig  `toml:"advanced"`
}

// ── General ──────────────────────────────────────────────────────

type GeneralConfig struct {
	LogLevel  string `toml:"log_level"`
	Quiet     bool   `toml:"quiet"`
	Timeout   int    `toml:"timeout"`
	OutputDir string `toml:"output_dir"`
}

// ── Proxy ────────────────────────────────────────────────────────

type ProxyConfig struct {
	URL     string `toml:"url"`
	NoProxy string `toml:"no_proxy"`
}

// ── Scanner ──────────────────────────────────────────────────────

type ScannerConfig struct {
	DefaultPorts   string  `toml:"default_ports"`
	DefaultThreads int     `toml:"default_threads"`
	DefaultTimeout int     `toml:"default_timeout"`
	DefaultRate    float64 `toml:"default_rate"`
	SynScan        bool    `toml:"syn_scan"`
	Randomize      bool    `toml:"randomize"`
	Retries        int     `toml:"retries"`
	ProbeDir       string  `toml:"probe_dir"`
}

// ── Discovery ────────────────────────────────────────────────────

type DiscoveryConfig struct {
	CrawlDepth  int  `toml:"crawl_depth"`
	MineJS      bool `toml:"mine_js"`
	MineForms   bool `toml:"mine_forms"`
	MineJSON    bool `toml:"mine_json"`
	MinePath    bool `toml:"mine_path"`
	ActiveBrute bool `toml:"active_brute"`
}

// ── Vuln ─────────────────────────────────────────────────────────

type VulnConfig struct {
	Threads     int    `toml:"threads"`
	Timeout     int    `toml:"timeout"`
	TemplateDir string `toml:"template_dir"`
	DefaultTags string `toml:"default_tags"`
}

// ── Fuzzing ─────────────────────────────────────────────────────

type FuzzingConfig struct {
	DefaultConcurrency int    `toml:"default_concurrency"`
	DefaultTimeout     int    `toml:"default_timeout"`
	DefaultPayloadFile string `toml:"default_payload_file"`
}

// ── Reporting ───────────────────────────────────────────────────

type ReportingConfig struct {
	OutputDir    string `toml:"output_dir"`
	GenerateHTML bool   `toml:"generate_html"`
	GenerateJSON bool   `toml:"generate_json"`
}

// ── Database ────────────────────────────────────────────────────

type DatabaseConfig struct {
	Driver string `toml:"driver"`
	DSN    string `toml:"dsn"`
}

// ── MCP Server ──────────────────────────────────────────────────

type MCPServerConfig struct {
	Enabled        bool     `toml:"enabled"`
	Transport      string   `toml:"transport"`
	Host           string   `toml:"host"`
	Port           int      `toml:"port"`
	Path           string   `toml:"path"`
	APIKey         string   `toml:"api_key"`
	AllowedOrigins []string `toml:"allowed_origins"`
}

// MCPClientConfig controls MCP servers available to the LLM assistant.
type MCPClientConfig struct {
	Enabled        bool                    `toml:"enabled"`
	ApprovalPolicy string                  `toml:"approval_policy"`
	Servers        []MCPClientServerConfig `toml:"servers"`
}

// MCPClientServerConfig describes one MCP tool source.
type MCPClientServerConfig struct {
	Name      string   `toml:"name"`
	Transport string   `toml:"transport"`
	Enabled   bool     `toml:"enabled"`
	Command   string   `toml:"command,omitempty"`
	Args      []string `toml:"args,omitempty"`
	URL       string   `toml:"url,omitempty"`
	APIKey    string   `toml:"api_key,omitempty"`
}

// ═════════════════════════════════════════════════════════════════
// LLM VENDOR CONFIGURATION
// ═════════════════════════════════════════════════════════════════

// LLMConfig selects and configures LLM providers for agent planning.
type LLMConfig struct {
	Provider         string          `toml:"provider"`
	FallbackProvider string          `toml:"fallback_provider"`
	Anthropic        LLMVendorConfig `toml:"anthropic"`
	OpenAI           LLMVendorConfig `toml:"openai"`
	DeepSeek         LLMVendorConfig `toml:"deepseek"`
	Google           LLMVendorConfig `toml:"google"`
	Local            LLMVendorConfig `toml:"local"`
}

// LLMVendorConfig holds connection details for a single LLM provider.
type LLMVendorConfig struct {
	APIKey          string  `toml:"api_key"`
	Model           string  `toml:"model"`
	BaseURL         string  `toml:"base_url"`
	MaxTokens       int     `toml:"max_tokens"`
	Temperature     float64 `toml:"temperature"`
	MaxRPM          int     `toml:"max_rpm"`
	OrgID           string  `toml:"org_id,omitempty"` // OpenAI-specific
	ReasoningEffort string  `toml:"reasoning_effort,omitempty"`
	Thinking        bool    `toml:"thinking,omitempty"`
}

// LLMProviderSettings captures provider settings persisted by the API settings modal.
type LLMProviderSettings struct {
	Provider        string
	APIKey          string
	Model           string
	BaseURL         string
	MaxTokens       int
	Temperature     float64
	ReasoningEffort string
	Thinking        bool
}

// GetActive returns the vendor config for the currently selected provider.
func (c *LLMConfig) GetActive() *LLMVendorConfig {
	if vendor := c.GetProvider(c.Provider); vendor != nil {
		return vendor
	}
	return &c.Local
}

// GetProvider returns the vendor config for a named provider.
func (c *LLMConfig) GetProvider(provider string) *LLMVendorConfig {
	switch NormalizeLLMProvider(provider) {
	case "anthropic":
		return &c.Anthropic
	case "openai":
		return &c.OpenAI
	case "deepseek":
		return &c.DeepSeek
	case "google":
		return &c.Google
	case "local":
		return &c.Local
	default:
		return nil
	}
}

// IsConfigured checks if at least one vendor has an API key.
func (c *LLMConfig) IsConfigured() bool {
	return c.APIKeyForProvider("anthropic") != "" ||
		c.APIKeyForProvider("openai") != "" ||
		c.APIKeyForProvider("deepseek") != "" ||
		c.APIKeyForProvider("google") != "" ||
		c.APIKeyForProvider("local") != "" ||
		c.Local.BaseURL != "" // Local doesn't always need a key
}

// ── Agent ───────────────────────────────────────────────────────

type AgentConfig struct {
	MaxConcurrentTasks  int    `toml:"max_concurrent_tasks"`
	MaxDuration         string `toml:"max_duration"`
	RequireConfirmation bool   `toml:"require_confirmation"`
	DefaultRiskLevel    string `toml:"default_risk_level"`
	UseLLMPlanning      bool   `toml:"use_llm_planning"`
	MaxRetries          int    `toml:"max_retries"`
	RetryDelay          int    `toml:"retry_delay"`
}

// ── Safety ──────────────────────────────────────────────────────

type SafetyConfig struct {
	AllowedDomains         []string `toml:"allowed_domains"`
	AllowedCIDRs           []string `toml:"allowed_cidrs"`
	BlockedDomains         []string `toml:"blocked_domains"`
	MaxRequestsPerMin      int      `toml:"max_requests_per_min"`
	MaxConcurrentPerTarget int      `toml:"max_concurrent_per_target"`
	RequestDelayMs         int      `toml:"request_delay_ms"`
}

// ── Plugins ─────────────────────────────────────────────────────

type PluginsConfig struct {
	CustomProbesDir string `toml:"custom_probes_dir"`
	ExploitDBPath   string `toml:"exploitdb_path"`
	WordlistDir     string `toml:"wordlist_dir"`
	EnableDotHound  bool   `toml:"enable_dothound"`
}

// ── Advanced ────────────────────────────────────────────────────

type AdvancedConfig struct {
	MaxBodyCapture  int    `toml:"max_body_capture"`
	UserAgent       string `toml:"user_agent"`
	FollowRedirects bool   `toml:"follow_redirects"`
	MaxRedirects    int    `toml:"max_redirects"`
	TLSVerify       bool   `toml:"tls_verify"`
	HTTP2           bool   `toml:"http2"`
}

// =============================================================================
// Defaults
// =============================================================================

func DefaultConfig() *AkemiConfig {
	return &AkemiConfig{
		General: GeneralConfig{
			LogLevel:  "info",
			Quiet:     false,
			Timeout:   10,
			OutputDir: "./results",
		},
		Proxy: ProxyConfig{
			NoProxy: "localhost,127.0.0.1,.local",
		},
		Scanner: ScannerConfig{
			DefaultPorts:   "top-1000",
			DefaultThreads: 200,
			DefaultTimeout: 3,
			Randomize:      true,
			Retries:        1,
			ProbeDir:       "./probes",
		},
		Discovery: DiscoveryConfig{
			CrawlDepth: 3,
			MineJS:     true,
			MineForms:  true,
			MineJSON:   true,
			MinePath:   true,
		},
		Vuln: VulnConfig{
			Threads:     5,
			Timeout:     10,
			TemplateDir: "./probes",
		},
		Fuzzing: FuzzingConfig{
			DefaultConcurrency: 10,
			DefaultTimeout:     10,
			DefaultPayloadFile: "payloads.txt",
		},
		Reporting: ReportingConfig{
			OutputDir:    "./results",
			GenerateHTML: true,
		},
		Database: DatabaseConfig{
			Driver: "sqlite",
			DSN:    "akemi.db",
		},
		MCPServer: MCPServerConfig{
			Transport: "stdio",
			Host:      "127.0.0.1",
			Port:      9090,
			Path:      "/mcp",
		},
		MCPClient: MCPClientConfig{
			Enabled:        true,
			ApprovalPolicy: "ask",
			Servers: []MCPClientServerConfig{
				{Name: "akemi", Transport: "inprocess", Enabled: true},
			},
		},
		LLM: LLMConfig{
			Provider: "local",
			Anthropic: LLMVendorConfig{
				Model:       "claude-3-5-sonnet-20241022",
				BaseURL:     "https://api.anthropic.com",
				MaxTokens:   4096,
				Temperature: 0.3,
				MaxRPM:      50,
			},
			OpenAI: LLMVendorConfig{
				Model:       "gpt-4o-mini",
				BaseURL:     "https://api.openai.com/v1",
				MaxTokens:   4096,
				Temperature: 0.3,
				MaxRPM:      60,
			},
			DeepSeek: LLMVendorConfig{
				Model:           "deepseek-v4-pro",
				BaseURL:         "https://api.deepseek.com",
				MaxTokens:       4096,
				Temperature:     0.3,
				MaxRPM:          60,
				ReasoningEffort: "high",
			},
			Google: LLMVendorConfig{
				Model:       "gemini-2.0-flash-exp",
				BaseURL:     "https://generativelanguage.googleapis.com/v1beta",
				MaxTokens:   4096,
				Temperature: 0.3,
				MaxRPM:      30,
			},
			Local: LLMVendorConfig{
				Model:       "llama3.1:8b",
				BaseURL:     "http://localhost:11434/v1",
				MaxTokens:   4096,
				Temperature: 0.3,
				MaxRPM:      100,
			},
		},
		Agent: AgentConfig{
			MaxConcurrentTasks:  5,
			MaxDuration:         "30m",
			RequireConfirmation: true,
			DefaultRiskLevel:    "active",
			UseLLMPlanning:      true,
			MaxRetries:          2,
			RetryDelay:          2,
		},
		Safety: SafetyConfig{
			BlockedDomains:         []string{"*.gov", "*.mil"},
			MaxRequestsPerMin:      300,
			MaxConcurrentPerTarget: 50,
			RequestDelayMs:         100,
		},
		Plugins: PluginsConfig{
			CustomProbesDir: "./probes/custom",
			WordlistDir:     "./wordlists",
			EnableDotHound:  true,
		},
		Advanced: AdvancedConfig{
			MaxBodyCapture:  1048576,
			UserAgent:       "Akemi/2.0.0 (Security Assessment Framework)",
			FollowRedirects: true,
			MaxRedirects:    10,
			TLSVerify:       true,
		},
	}
}

// FindConfigFile searches for a config file in standard locations.
func FindConfigFile() string {
	candidates := []string{
		"akemi.conf",
		".akemi.toml",
		"akemi.toml",
	}
	if wd, err := os.Getwd(); err == nil {
		for _, name := range []string{"akemi.conf", ".akemi.toml", "akemi.toml"} {
			candidates = append(candidates, ancestorConfigCandidates(wd, name)...)
		}
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		for _, name := range []string{"akemi.conf", ".akemi.toml", "akemi.toml"} {
			candidates = append(candidates, ancestorConfigCandidates(exeDir, name)...)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".akemi", "config.toml"),
			filepath.Join(home, ".akemi.conf"),
		)
	}
	candidates = append(candidates, "/etc/akemi/akemi.conf")
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func ancestorConfigCandidates(start, name string) []string {
	start = filepath.Clean(start)
	var out []string
	for {
		out = append(out, filepath.Join(start, name))
		parent := filepath.Dir(start)
		if parent == start {
			break
		}
		start = parent
	}
	return out
}

// Load reads Akemi configuration from defaults, a TOML file, and environment.
func Load(path string) (*AkemiConfig, error) {
	cfg := DefaultConfig()
	if strings.TrimSpace(path) == "" {
		path = FindConfigFile()
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("load config %s: %w", path, err)
		}
		content := string(data)
		repaired := repairLLMTOMLTables(content)
		if repaired != content {
			if err := os.WriteFile(path, []byte(repaired), 0600); err != nil {
				return nil, fmt.Errorf("repair config %s: %w", path, err)
			}
			_ = os.Chmod(path, 0600)
		}
		if _, err := toml.Decode(repaired, cfg); err != nil {
			return nil, fmt.Errorf("load config %s: %w", path, err)
		}
	}
	cfg.ApplyEnv()
	cfg.LLM.Provider = strings.ToLower(strings.TrimSpace(cfg.LLM.Provider))
	cfg.LLM.FallbackProvider = strings.ToLower(strings.TrimSpace(cfg.LLM.FallbackProvider))
	cfg.MCPServer.Transport = strings.ToLower(strings.TrimSpace(cfg.MCPServer.Transport))
	return cfg, cfg.Validate()
}

// ApplyEnv overlays AKEMI_* environment variables onto the config.
func (c *AkemiConfig) ApplyEnv() {
	if v := os.Getenv("AKEMI_LLM_PROVIDER"); v != "" {
		c.LLM.Provider = v
	}
	if v := os.Getenv("AKEMI_LLM_FALLBACK_PROVIDER"); v != "" {
		c.LLM.FallbackProvider = v
	}
	applyVendorEnv(&c.LLM.Anthropic, "AKEMI_LLM_ANTHROPIC")
	applyVendorEnv(&c.LLM.OpenAI, "AKEMI_LLM_OPENAI")
	applyVendorEnv(&c.LLM.DeepSeek, "AKEMI_LLM_DEEPSEEK")
	applyVendorEnv(&c.LLM.Google, "AKEMI_LLM_GOOGLE")
	applyVendorEnv(&c.LLM.Local, "AKEMI_LLM_LOCAL")
	if v := os.Getenv("AKEMI_AGENT_DEFAULT_RISK_LEVEL"); v != "" {
		c.Agent.DefaultRiskLevel = v
	}
	if v := os.Getenv("AKEMI_AGENT_USE_LLM_PLANNING"); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			c.Agent.UseLLMPlanning = parsed
		}
	}
	if v := os.Getenv("AKEMI_MCP_SERVER_API_KEY"); v != "" {
		c.MCPServer.APIKey = v
	}
	if v := os.Getenv("AKEMI_MCP_SERVER_TRANSPORT"); v != "" {
		c.MCPServer.Transport = v
	}
	if v := os.Getenv("AKEMI_MCP_SERVER_HOST"); v != "" {
		c.MCPServer.Host = v
	}
	if v := os.Getenv("AKEMI_MCP_SERVER_PORT"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			c.MCPServer.Port = parsed
		}
	}
	if v := os.Getenv("AKEMI_MCP_SERVER_ALLOWED_ORIGINS"); v != "" {
		c.MCPServer.AllowedOrigins = splitEnvList(v)
	}
	if v := os.Getenv("AKEMI_MCP_SERVER_PATH"); v != "" {
		c.MCPServer.Path = v
	}
	if v := os.Getenv("AKEMI_SAFETY_ALLOWED_DOMAINS"); v != "" {
		c.Safety.AllowedDomains = splitEnvList(v)
	}
	if v := os.Getenv("AKEMI_SAFETY_ALLOWED_CIDRS"); v != "" {
		c.Safety.AllowedCIDRs = splitEnvList(v)
	}
}

func applyVendorEnv(vendor *LLMVendorConfig, prefix string) {
	if v := firstEnv(prefix+"_KEY", prefix+"_API_KEY"); v != "" {
		vendor.APIKey = v
	}
	if v := os.Getenv(prefix + "_MODEL"); v != "" {
		vendor.Model = v
	}
	if v := os.Getenv(prefix + "_BASE_URL"); v != "" {
		vendor.BaseURL = v
	}
	if v := os.Getenv(prefix + "_ORG_ID"); v != "" {
		vendor.OrgID = v
	}
	if v := os.Getenv(prefix + "_MAX_TOKENS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			vendor.MaxTokens = parsed
		}
	}
	if v := os.Getenv(prefix + "_TEMPERATURE"); v != "" {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil {
			vendor.Temperature = parsed
		}
	}
	if v := os.Getenv(prefix + "_REASONING_EFFORT"); v != "" {
		vendor.ReasoningEffort = v
	}
	if v := os.Getenv(prefix + "_THINKING"); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			vendor.Thinking = parsed
		}
	}
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return ""
}

// NormalizeLLMProvider returns the canonical provider name when supported.
func NormalizeLLMProvider(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case "anthropic", "openai", "deepseek", "google", "local":
		return provider
	default:
		return ""
	}
}

func splitEnvList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// Validate checks the configuration for inconsistencies.
func (c *AkemiConfig) Validate() error {
	var errs []string

	if c.Scanner.DefaultThreads < 1 || c.Scanner.DefaultThreads > 10000 {
		errs = append(errs, "scanner.default_threads must be 1-10000")
	}
	if c.Scanner.DefaultTimeout < 1 {
		errs = append(errs, "scanner.default_timeout must be >= 1")
	}
	if c.MCPServer.Enabled && c.MCPServer.Transport == "http" && c.MCPServer.Port < 1 {
		errs = append(errs, "mcp_server.port required for HTTP transport")
	}
	if c.MCPServer.Transport != "" {
		validTransport := map[string]bool{"stdio": true, "http": true}
		if !validTransport[c.MCPServer.Transport] {
			errs = append(errs, "mcp_server.transport must be: stdio or http")
		}
	}
	if c.MCPServer.Transport == "http" && c.MCPServer.Path != "" && !strings.HasPrefix(c.MCPServer.Path, "/") {
		errs = append(errs, "mcp_server.path must start with /")
	}
	if c.MCPClient.ApprovalPolicy != "" {
		validApproval := map[string]bool{"ask": true, "allow": true, "deny": true}
		if !validApproval[c.MCPClient.ApprovalPolicy] {
			errs = append(errs, "mcp_client.approval_policy must be: ask, allow, or deny")
		}
	}
	if c.Agent.UseLLMPlanning && !c.LLM.IsConfigured() {
		errs = append(errs, "agent.use_llm_planning=true but no LLM API keys configured")
	}
	if c.LLM.Provider != "" {
		if NormalizeLLMProvider(c.LLM.Provider) == "" {
			errs = append(errs, "llm.provider must be: anthropic, openai, deepseek, google, or local")
		}
	}
	if c.LLM.FallbackProvider != "" {
		if NormalizeLLMProvider(c.LLM.FallbackProvider) == "" {
			errs = append(errs, "llm.fallback_provider must be: anthropic, openai, deepseek, google, or local")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("configuration errors:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// ResolveProbeDir resolves the probe template directory path.
func (c *AkemiConfig) ResolveProbeDir() string {
	dir := c.Scanner.ProbeDir
	if c.Vuln.TemplateDir != "" && c.Vuln.TemplateDir != "./probes" {
		dir = c.Vuln.TemplateDir
	}
	if filepath.IsAbs(dir) {
		return dir
	}
	if wd, err := os.Getwd(); err == nil {
		resolved := filepath.Join(wd, dir)
		if info, err := os.Stat(resolved); err == nil && info.IsDir() {
			return resolved
		}
	}
	return dir
}

// ActiveAPIKey returns the API key for the selected LLM provider.
// It checks environment variables first, then the config file.
func (c *LLMConfig) ActiveAPIKey() string {
	return c.APIKeyForProvider(c.Provider)
}

// APIKeyForProvider returns a provider key, checking environment first.
func (c *LLMConfig) APIKeyForProvider(provider string) string {
	provider = NormalizeLLMProvider(provider)
	if provider == "" {
		return ""
	}
	envMap := map[string]string{
		"anthropic": "AKEMI_LLM_ANTHROPIC_KEY",
		"openai":    "AKEMI_LLM_OPENAI_KEY",
		"deepseek":  "AKEMI_LLM_DEEPSEEK_KEY",
		"google":    "AKEMI_LLM_GOOGLE_KEY",
		"local":     "AKEMI_LLM_LOCAL_KEY",
	}
	if envKey, ok := envMap[provider]; ok {
		if val := os.Getenv(envKey); val != "" {
			return val
		}
	}
	vendor := c.GetProvider(provider)
	if vendor == nil {
		return ""
	}
	return vendor.APIKey
}

// FirstProviderWithAPIKey returns the first provider with a configured key.
func (c *LLMConfig) FirstProviderWithAPIKey(preferred ...string) string {
	seen := make(map[string]struct{})
	check := func(provider string) string {
		provider = NormalizeLLMProvider(provider)
		if provider == "" {
			return ""
		}
		if _, ok := seen[provider]; ok {
			return ""
		}
		seen[provider] = struct{}{}
		if strings.TrimSpace(c.APIKeyForProvider(provider)) != "" {
			return provider
		}
		return ""
	}
	for _, provider := range preferred {
		if found := check(provider); found != "" {
			return found
		}
	}
	for _, provider := range []string{c.Provider, c.FallbackProvider, "deepseek", "openai", "anthropic", "google", "local"} {
		if found := check(provider); found != "" {
			return found
		}
	}
	return ""
}

// ParseDuration parses the agent max_duration string.
func (a *AgentConfig) ParseDuration() time.Duration {
	d, err := time.ParseDuration(a.MaxDuration)
	if err != nil {
		return 30 * time.Minute
	}
	return d
}

// UpdateLLMAPIKey persists the active LLM provider and API key in akemi.conf.
func UpdateLLMAPIKey(path, provider, apiKey string) (string, error) {
	originalProvider := provider
	provider = NormalizeLLMProvider(provider)
	if provider == "" {
		return "", fmt.Errorf("unsupported llm provider %q", originalProvider)
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return "", fmt.Errorf("llm api key is required")
	}
	if strings.TrimSpace(path) == "" {
		path = FindConfigFile()
		if path == "" {
			path = "akemi.conf"
		}
	}

	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("read config %s: %w", path, err)
	}
	content := string(data)
	content = repairLLMTOMLTables(content)
	content = upsertTOMLValue(content, "llm", "provider", strconv.Quote(provider))
	content = upsertTOMLValue(content, "llm."+provider, "api_key", strconv.Quote(apiKey))

	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return "", fmt.Errorf("create config directory %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("write config %s: %w", path, err)
	}
	_ = os.Chmod(path, 0600)
	return path, nil
}

// UpdateLLMProviderSettings persists LLM provider settings.
func UpdateLLMProviderSettings(path string, settings LLMProviderSettings) (string, error) {
	provider := NormalizeLLMProvider(settings.Provider)
	if provider == "" {
		return "", fmt.Errorf("unsupported llm provider %q", settings.Provider)
	}
	if strings.TrimSpace(path) == "" {
		path = FindConfigFile()
		if path == "" {
			path = "akemi.conf"
		}
	}

	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("read config %s: %w", path, err)
	}
	content := string(data)
	content = repairLLMTOMLTables(content)
	content = upsertTOMLValue(content, "llm", "provider", strconv.Quote(provider))

	section := "llm." + provider
	content = upsertTOMLValue(content, section, "api_key", strconv.Quote(strings.TrimSpace(settings.APIKey)))
	if strings.TrimSpace(settings.Model) != "" {
		content = upsertTOMLValue(content, section, "model", strconv.Quote(strings.TrimSpace(settings.Model)))
	}
	if strings.TrimSpace(settings.BaseURL) != "" {
		content = upsertTOMLValue(content, section, "base_url", strconv.Quote(strings.TrimSpace(settings.BaseURL)))
	}
	if settings.MaxTokens > 0 {
		content = upsertTOMLValue(content, section, "max_tokens", strconv.Itoa(settings.MaxTokens))
	}
	if settings.Temperature >= 0 {
		content = upsertTOMLValue(content, section, "temperature", strconv.FormatFloat(settings.Temperature, 'f', -1, 64))
	}
	if strings.TrimSpace(settings.ReasoningEffort) != "" {
		content = upsertTOMLValue(content, section, "reasoning_effort", strconv.Quote(strings.TrimSpace(settings.ReasoningEffort)))
	}
	content = upsertTOMLValue(content, section, "thinking", strconv.FormatBool(settings.Thinking))

	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return "", fmt.Errorf("create config directory %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("write config %s: %w", path, err)
	}
	_ = os.Chmod(path, 0600)
	return path, nil
}

func upsertTOMLValue(content, section, key, quotedValue string) string {
	newline := "\n"
	if strings.Contains(content, "\r\n") {
		newline = "\r\n"
	}
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	lines := strings.Split(normalized, "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}

	start, end := findTOMLSection(lines, section)
	keyLine := key + " = " + quotedValue
	if start == -1 {
		insert := len(lines)
		if !strings.Contains(section, ".") {
			for i, line := range lines {
				name, _, ok := tomlTableName(line)
				if ok && strings.HasPrefix(name, section+".") {
					insert = i
					break
				}
			}
		}
		if insert < len(lines) {
			block := []string{"[" + section + "]", keyLine, ""}
			lines = append(lines[:insert], append(block, lines[insert:]...)...)
			return strings.Join(lines, newline)
		}
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, "["+section+"]", keyLine)
		return strings.Join(lines, newline) + newline
	}

	var updated []string
	updated = append(updated, lines[:start+1]...)
	replaced := false
	for i := start + 1; i < end; i++ {
		if isTOMLKeyLine(lines[i], key) {
			if !replaced {
				indent := lines[i][:len(lines[i])-len(strings.TrimLeft(lines[i], " \t"))]
				updated = append(updated, indent+keyLine)
				replaced = true
			}
			continue
		}
		updated = append(updated, lines[i])
	}
	if replaced {
		updated = append(updated, lines[end:]...)
		return strings.Join(updated, newline)
	}

	lines = append(lines[:end], append([]string{keyLine}, lines[end:]...)...)
	return strings.Join(lines, newline)
}

func coalesceTOMLTable(content, section string) string {
	newline := "\n"
	if strings.Contains(content, "\r\n") {
		newline = "\r\n"
	}
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	lines := strings.Split(normalized, "\n")
	if len(lines) == 1 && lines[0] == "" {
		return content
	}

	var tableBody []string
	var kept []string
	found := false
	for i := 0; i < len(lines); {
		name, isArray, ok := tomlTableName(lines[i])
		if ok && !isArray && name == section {
			found = true
			i++
			for i < len(lines) {
				if _, _, nextOK := tomlTableName(lines[i]); nextOK {
					break
				}
				tableBody = append(tableBody, lines[i])
				i++
			}
			continue
		}
		kept = append(kept, lines[i])
		i++
	}
	if !found {
		return content
	}
	tableBody = dedupeTOMLKeyLines(tableBody)

	insert := len(kept)
	if !strings.Contains(section, ".") {
		for i, line := range kept {
			name, _, ok := tomlTableName(line)
			if ok && strings.HasPrefix(name, section+".") {
				insert = i
				break
			}
		}
	}
	block := append([]string{"[" + section + "]"}, tableBody...)
	if len(block) == 1 || strings.TrimSpace(block[len(block)-1]) != "" {
		block = append(block, "")
	}
	kept = append(kept[:insert], append(block, kept[insert:]...)...)
	return strings.Join(kept, newline)
}

func repairLLMTOMLTables(content string) string {
	content = sanitizeTOMLAPIKeyLines(content)
	content = coalesceTOMLTable(content, "llm")
	for _, provider := range []string{"anthropic", "openai", "deepseek", "google", "local"} {
		content = coalesceTOMLTable(content, "llm."+provider)
	}
	return content
}

func sanitizeTOMLAPIKeyLines(content string) string {
	newline := "\n"
	if strings.Contains(content, "\r\n") {
		newline = "\r\n"
	}
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	lines := strings.Split(normalized, "\n")
	for i, line := range lines {
		key, ok := tomlKeyName(line)
		if !ok || key != "api_key" {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		rhs := strings.TrimSpace(line[idx+1:])
		if !strings.HasPrefix(rhs, "\"") {
			continue
		}
		end := strings.LastIndex(rhs[1:], "\"")
		if end < 0 {
			continue
		}
		value := rhs[1 : end+1]
		cleaned := strings.ReplaceAll(value, `\x00`, "")
		cleaned = strings.ReplaceAll(cleaned, "\x00", "")
		if cleaned == value {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		lines[i] = indent + "api_key = " + strconv.Quote(cleaned)
	}
	return strings.Join(lines, newline)
}

func dedupeTOMLKeyLines(lines []string) []string {
	last := make(map[string]int)
	for i, line := range lines {
		if key, ok := tomlKeyName(line); ok {
			last[key] = i
		}
	}
	if len(last) == 0 {
		return lines
	}
	out := make([]string, 0, len(lines))
	for i, line := range lines {
		if key, ok := tomlKeyName(line); ok && last[key] != i {
			continue
		}
		out = append(out, line)
	}
	return out
}

func tomlKeyName(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	trimmed = strings.TrimPrefix(trimmed, "\ufeff")
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", false
	}
	idx := strings.Index(trimmed, "=")
	if idx < 0 {
		return "", false
	}
	key := strings.TrimSpace(trimmed[:idx])
	if key == "" || strings.HasPrefix(key, "[") {
		return "", false
	}
	return key, true
}

func findTOMLSection(lines []string, section string) (int, int) {
	start := -1
	for i, line := range lines {
		name, _, ok := tomlTableName(line)
		if !ok {
			continue
		}
		if start != -1 {
			return start, i
		}
		if name == section {
			start = i
		}
	}
	if start == -1 {
		return -1, -1
	}
	return start, len(lines)
}

func tomlTableName(line string) (string, bool, bool) {
	trimmed := strings.TrimSpace(line)
	trimmed = strings.TrimPrefix(trimmed, "\ufeff")
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", false, false
	}
	if idx := strings.Index(trimmed, "#"); idx >= 0 {
		trimmed = strings.TrimSpace(trimmed[:idx])
	}
	if strings.HasPrefix(trimmed, "[[") {
		end := strings.Index(trimmed, "]]")
		if end < 0 {
			return "", false, false
		}
		return strings.TrimSpace(trimmed[2:end]), true, true
	}
	if strings.HasPrefix(trimmed, "[") {
		end := strings.Index(trimmed, "]")
		if end < 0 {
			return "", false, false
		}
		return strings.TrimSpace(trimmed[1:end]), false, true
	}
	return "", false, false
}

func isTOMLKeyLine(line, key string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	idx := strings.Index(trimmed, "=")
	if idx < 0 {
		return false
	}
	return strings.TrimSpace(trimmed[:idx]) == key
}

// ParseScope returns structured domain and CIDR lists from safety config.
func (s *SafetyConfig) ParseScope() (domains, cidrs []string) {
	domains = append([]string{}, s.AllowedDomains...)
	cidrs = append([]string{}, s.AllowedCIDRs...)
	return
}
