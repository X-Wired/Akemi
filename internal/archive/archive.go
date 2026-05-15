// Package archive reads and writes versioned .akemi scan archives.
package archive

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	core "Akemi/internal/core"
	"Akemi/internal/engagement"
)

const (
	Magic           = "akemi.archive"
	SchemaVersion   = 1
	MaxArchiveBytes = 100 << 20
)

// ScanConfig captures the operator-facing scan configuration.
type ScanConfig struct {
	Target    string `json:"target"`
	AuthURL   string `json:"auth_url,omitempty"`
	PortRange string `json:"port_range,omitempty"`
	Threads   int    `json:"threads,omitempty"`
	Proxy     string `json:"proxy,omitempty"`
	Intent    string `json:"intent,omitempty"`
	Depth     int    `json:"depth,omitempty"`
	Timeout   int    `json:"timeout,omitempty"`
}

// DiscoveryItem stores the exact live dashboard row that was captured.
type DiscoveryItem struct {
	Key   string `json:"key,omitempty"`
	Item  string `json:"item"`
	Phase string `json:"phase,omitempty"`
}

// DiscoverySection groups captured dashboard items by category.
type DiscoverySection struct {
	Name  string          `json:"name"`
	Count int             `json:"count"`
	Items []DiscoveryItem `json:"items,omitempty"`
}

// JSAnalysisCapture keeps JavaScript findings tied to the page that produced them.
type JSAnalysisCapture struct {
	PageURL string                `json:"page_url"`
	Result  core.JSAnalysisResult `json:"result"`
}

// Results carries the structured scan data Akemi knows how to reason about.
type Results struct {
	Ports         []core.PortResult           `json:"ports,omitempty"`
	URLs          []string                    `json:"urls,omitempty"`
	CrawlFindings []core.CrawlFinding         `json:"crawl_findings,omitempty"`
	Subdomains    []string                    `json:"subdomains,omitempty"`
	Params        map[string]core.ParamDetail `json:"params,omitempty"`
	JSAnalysis    []JSAnalysisCapture         `json:"js_analysis,omitempty"`
	APIEndpoints  []core.APIEndpointFinding   `json:"api_endpoints,omitempty"`
	APISpecs      []core.APISpecFinding       `json:"api_specs,omitempty"`
	APIParameters []core.APIParameterFinding  `json:"api_parameters,omitempty"`
	Secrets       []core.SecretFinding        `json:"secrets,omitempty"`
	Findings      []core.VulnFinding          `json:"findings,omitempty"`
}

// File is the top-level .akemi archive contract.
type File struct {
	Magic             string                        `json:"magic"`
	SchemaVersion     int                           `json:"schema_version"`
	ExportedAt        time.Time                     `json:"exported_at"`
	Source            string                        `json:"source"`
	Config            ScanConfig                    `json:"config"`
	Summary           string                        `json:"summary,omitempty"`
	Counts            map[string]int                `json:"counts,omitempty"`
	Results           Results                       `json:"results"`
	DiscoverySections []DiscoverySection            `json:"discovery_sections,omitempty"`
	MCPContext        *engagement.EngagementContext `json:"mcp_context,omitempty"`
}

// New builds a normalized archive from scan output.
func New(config ScanConfig, summary string, results Results, sections []DiscoverySection) *File {
	f := &File{
		Magic:             Magic,
		SchemaVersion:     SchemaVersion,
		ExportedAt:        time.Now().UTC(),
		Source:            "akemi",
		Config:            config,
		Summary:           summary,
		Results:           results,
		DiscoverySections: sections,
	}
	f.Normalize()
	return f
}

// Normalize fills default metadata and recomputes counts.
func (f *File) Normalize() {
	if f.Magic == "" {
		f.Magic = Magic
	}
	if f.SchemaVersion == 0 {
		f.SchemaVersion = SchemaVersion
	}
	if f.ExportedAt.IsZero() {
		f.ExportedAt = time.Now().UTC()
	}
	if f.Source == "" {
		f.Source = "akemi"
	}
	for i := range f.DiscoverySections {
		f.DiscoverySections[i].Count = len(f.DiscoverySections[i].Items)
	}
	f.Counts = f.computeCounts()
}

// Validate checks the archive envelope without executing or trusting its data.
func (f *File) Validate() error {
	if f.Magic != Magic {
		return fmt.Errorf("not an Akemi archive")
	}
	if f.SchemaVersion <= 0 || f.SchemaVersion > SchemaVersion {
		return fmt.Errorf("unsupported .akemi schema version %d", f.SchemaVersion)
	}
	return nil
}

// WriteFile writes a .akemi archive with private permissions because scan data
// may include secrets, endpoints, and authenticated targets.
func WriteFile(path string, f *File) error {
	if f == nil {
		return fmt.Errorf("nil archive")
	}
	f.Normalize()
	if err := f.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("archive path is required")
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create archive directory: %w", err)
		}
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal archive: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write archive: %w", err)
	}
	return nil
}

// ReadFile reads and validates a .akemi archive. The size limit keeps imports
// bounded before JSON decoding.
func ReadFile(path string) (*File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat archive: %w", err)
	}
	if stat.Size() > MaxArchiveBytes {
		return nil, fmt.Errorf("archive is too large: %d bytes", stat.Size())
	}

	var f File
	dec := json.NewDecoder(io.LimitReader(file, MaxArchiveBytes+1))
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decode archive: %w", err)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	f.Normalize()
	return &f, nil
}

// DefaultFilename creates a stable, readable .akemi filename for a target.
func DefaultFilename(target string, t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	target = sanitizeFilename(target)
	if target == "" {
		target = "scan"
	}
	return fmt.Sprintf("akemi-%s-%s.akemi", target, t.UTC().Format("20060102-150405"))
}

// DefaultRunFilename creates the non-timestamped filename used for manual saves.
func DefaultRunFilename(target string) string {
	target = sanitizeFilename(target)
	if target == "" {
		target = "akemi-run"
	}
	return target + ".akemi"
}

func (f *File) computeCounts() map[string]int {
	counts := map[string]int{
		"ports":          len(f.Results.Ports),
		"urls":           len(f.Results.URLs),
		"crawl_findings": len(f.Results.CrawlFindings),
		"subdomains":     len(f.Results.Subdomains),
		"params":         len(f.Results.Params),
		"js_analysis":    len(f.Results.JSAnalysis),
		"api_endpoints":  len(f.Results.APIEndpoints),
		"api_specs":      len(f.Results.APISpecs),
		"api_parameters": len(f.Results.APIParameters),
		"secrets":        len(f.Results.Secrets),
		"findings":       len(f.Results.Findings),
	}
	for _, section := range f.DiscoverySections {
		key := strings.ToLower(strings.ReplaceAll(section.Name, " ", "_"))
		counts[key] = section.Count
	}
	return counts
}

func sanitizeFilename(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-._")
}
