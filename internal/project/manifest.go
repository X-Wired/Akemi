package project

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// SchemaVersion is the current akemi.project.toml schema version.
const SchemaVersion = 1

// ProjectManifest is the on-disk representation of akemi.project.toml.
// It serves as the golden source of truth for the project's identity,
// scope, and directory layout.
type ProjectManifest struct {
	SchemaVersion int            `toml:"schema_version"`
	Name          string         `toml:"name"`
	Description   string         `toml:"description"`
	CreatedAt     time.Time      `toml:"created_at"`
	UpdatedAt     time.Time      `toml:"updated_at"`
	Targets       []string       `toml:"targets"`
	Scope         ScopeConfig    `toml:"scope"`
	Paths         ManifestPaths  `toml:"paths"`
	Config        *ProjectConfig `toml:"config,omitempty"`
}

// ManifestPaths allows the operator to customize the project's directory
// layout. All paths are relative to the project root. Empty values fall
// back to the defaults defined in paths.go.
type ManifestPaths struct {
	Archives    string `toml:"archives"`
	Reports     string `toml:"reports"`
	Graphs      string `toml:"graphs"`
	Logs        string `toml:"logs"`
	Wordlists   string `toml:"wordlists"`
	Probes      string `toml:"probes"`
	Screenshots string `toml:"screenshots"`
	DotHound    string `toml:"dothound"`
	State       string `toml:"state"`
}

// ScopeConfig defines the engagement boundaries for a project. These
// constraints are enforced by the agent safety system and serve as
// documentation for the human operator.
type ScopeConfig struct {
	AllowedDomains []string `toml:"allowed_domains"`
	AllowedCIDRs   []string `toml:"allowed_cidrs"`
	BlockedDomains []string `toml:"blocked_domains"`
	Notes          string   `toml:"notes"`
}

// ProjectConfig holds optional per-project configuration overrides. These
// are merged into the global AkemiConfig at runtime, with project values
// taking precedence over defaults but not over environment variables or CLI flags.
type ProjectConfig struct {
	Scanner   *ProjectScannerConfig   `toml:"scanner,omitempty"`
	Discovery *ProjectDiscoveryConfig `toml:"discovery,omitempty"`
	Vuln      *ProjectVulnConfig      `toml:"vuln,omitempty"`
	Fuzzing   *ProjectFuzzingConfig   `toml:"fuzzing,omitempty"`
}

// ProjectScannerConfig holds project-level scanner defaults.
type ProjectScannerConfig struct {
	DefaultPorts   string  `toml:"default_ports"`
	DefaultThreads int     `toml:"default_threads"`
	DefaultTimeout int     `toml:"default_timeout"`
	DefaultRate    float64 `toml:"default_rate"`
	SynScan        *bool   `toml:"syn_scan,omitempty"`
	Randomize      *bool   `toml:"randomize,omitempty"`
	Retries        int     `toml:"retries"`
}

// ProjectDiscoveryConfig holds project-level discovery defaults.
type ProjectDiscoveryConfig struct {
	CrawlDepth  int   `toml:"crawl_depth"`
	MineJS      *bool `toml:"mine_js,omitempty"`
	MineForms   *bool `toml:"mine_forms,omitempty"`
	MineJSON    *bool `toml:"mine_json,omitempty"`
	MinePath    *bool `toml:"mine_path,omitempty"`
	ActiveBrute *bool `toml:"active_brute,omitempty"`
}

// ProjectVulnConfig holds project-level vulnerability probe defaults.
type ProjectVulnConfig struct {
	Threads     int    `toml:"threads"`
	Timeout     int    `toml:"timeout"`
	DefaultTags string `toml:"default_tags"`
}

// ProjectFuzzingConfig holds project-level fuzzing defaults.
type ProjectFuzzingConfig struct {
	DefaultConcurrency int    `toml:"default_concurrency"`
	DefaultTimeout     int    `toml:"default_timeout"`
	DefaultPayloadFile string `toml:"default_payload_file"`
}

// NewManifest creates a ProjectManifest with sensible defaults and the
// current timestamp. The returned manifest is ready to be written to disk.
func NewManifest(name string) *ProjectManifest {
	now := time.Now().UTC()
	return &ProjectManifest{
		SchemaVersion: SchemaVersion,
		Name:          sanitizeName(name),
		Description:   "",
		CreatedAt:     now,
		UpdatedAt:     now,
		Targets:       []string{},
		Scope: ScopeConfig{
			AllowedDomains: []string{},
			AllowedCIDRs:   []string{},
			BlockedDomains: []string{},
		},
		Paths: ManifestPaths{}, // all empty = use defaults
	}
}

// LoadManifest reads and validates an akemi.project.toml file.
func LoadManifest(path string) (*ProjectManifest, error) {
	if path == "" {
		return nil, fmt.Errorf("manifest path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m ProjectManifest
	if err := toml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("validate manifest: %w", err)
	}
	m.normalize()
	return &m, nil
}

// WriteManifest serializes the manifest to the given path with private
// permissions (may contain scope information that is sensitive).
func WriteManifest(path string, m *ProjectManifest) error {
	if m == nil {
		return fmt.Errorf("manifest is nil")
	}
	m.normalize()
	if err := m.Validate(); err != nil {
		return err
	}
	dir := strings.TrimSuffix(path, "/akemi.project.toml")
	if dir != path && dir != "" {
		if err := os.MkdirAll(dir, DefaultDirPermissions); err != nil {
			return fmt.Errorf("create manifest directory: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, DefaultFilePermissions)
	if err != nil {
		return fmt.Errorf("open manifest for writing: %w", err)
	}
	defer f.Close()
	if err := toml.NewEncoder(f).Encode(m); err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	return nil
}

// Validate checks that required fields are present and schema version is
// compatible.
func (m *ProjectManifest) Validate() error {
	if m == nil {
		return fmt.Errorf("manifest is nil")
	}
	if m.SchemaVersion <= 0 || m.SchemaVersion > SchemaVersion {
		return fmt.Errorf("unsupported schema version %d (expected %d)", m.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("project name is required")
	}
	return nil
}

// normalize fills in defaults and sanitizes fields.
func (m *ProjectManifest) normalize() {
	if m == nil {
		return
	}
	if m.SchemaVersion == 0 {
		m.SchemaVersion = SchemaVersion
	}
	m.Name = sanitizeName(m.Name)
	m.Description = strings.TrimSpace(m.Description)
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now().UTC()
	}
	if m.UpdatedAt.IsZero() || m.UpdatedAt.Before(m.CreatedAt) {
		m.UpdatedAt = time.Now().UTC()
	}
	// Normalize targets
	m.Targets = cleanStringList(m.Targets)
	m.Scope.AllowedDomains = cleanStringList(m.Scope.AllowedDomains)
	m.Scope.AllowedCIDRs = cleanStringList(m.Scope.AllowedCIDRs)
	m.Scope.BlockedDomains = cleanStringList(m.Scope.BlockedDomains)
	m.Scope.Notes = strings.TrimSpace(m.Scope.Notes)
	// Trim path overrides
	m.Paths.Archives = strings.TrimSpace(m.Paths.Archives)
	m.Paths.Reports = strings.TrimSpace(m.Paths.Reports)
	m.Paths.Graphs = strings.TrimSpace(m.Paths.Graphs)
	m.Paths.Logs = strings.TrimSpace(m.Paths.Logs)
	m.Paths.Wordlists = strings.TrimSpace(m.Paths.Wordlists)
	m.Paths.Probes = strings.TrimSpace(m.Paths.Probes)
	m.Paths.Screenshots = strings.TrimSpace(m.Paths.Screenshots)
	m.Paths.DotHound = strings.TrimSpace(m.Paths.DotHound)
	m.Paths.State = strings.TrimSpace(m.Paths.State)
}

// Touch sets UpdatedAt to now so the registry knows the project is active.
func (m *ProjectManifest) Touch() {
	if m == nil {
		return
	}
	m.UpdatedAt = time.Now().UTC()
}

// Summary returns a single-line description suitable for the recent-projects list.
func (m *ProjectManifest) Summary() string {
	if m == nil {
		return ""
	}
	targets := strings.Join(m.Targets, ", ")
	if targets == "" {
		targets = "(no targets defined)"
	}
	return fmt.Sprintf("%s — %s", m.Name, targets)
}

// AddTarget appends a target if it is not already present.
func (m *ProjectManifest) AddTarget(target string) {
	target = strings.TrimSpace(target)
	if target == "" {
		return
	}
	for _, existing := range m.Targets {
		if strings.EqualFold(existing, target) {
			return
		}
	}
	m.Targets = append(m.Targets, target)
	m.Touch()
}

func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "untitled-engagement"
	}
	// Replace characters that are annoying in paths.
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '_' || r == '-':
			b.WriteRune('-')
		default:
			// Skip characters that are problematic in paths.
		}
	}
	result := strings.Trim(b.String(), "-._")
	if result == "" {
		return "untitled-engagement"
	}
	return result
}

func cleanStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		lower := strings.ToLower(v)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		out = append(out, v)
	}
	return out
}
