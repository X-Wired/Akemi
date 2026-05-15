// Package core defines the foundational interfaces, types, and contracts
// that all Akemi service modules implement. This enables loose coupling
// between the CLI, MCP server, agent system, and the underlying engines.
package core

import (
	"context"
	"net/http"
	"time"
)

// =============================================================================
// Scanner — Port scanning and host discovery
// =============================================================================

// Scanner provides high-performance network port scanning.
// Implementations may use the Rust Akemi-Spear engine or a Go fallback.
type Scanner interface {
	// Scan performs a port scan against the given target.
	Scan(ctx context.Context, req ScanRequest) (*ScanResult, error)

	// DiscoverHosts performs host discovery on a CIDR range.
	DiscoverHosts(ctx context.Context, req HostDiscoveryRequest) (*HostDiscoveryResult, error)
}

// ScanRequest describes a port scan job.
type ScanRequest struct {
	Host           string  `json:"host"`
	Ports          []int   `json:"ports"`
	Threads        int     `json:"threads"`
	TimeoutMs      int     `json:"timeout_ms"`
	Rate           float64 `json:"rate"`
	Retries        int     `json:"retries"`
	Randomize      bool    `json:"randomize"`
	SynMode        bool    `json:"syn_mode"`
	BannerGrab     bool    `json:"banner_grab"`
	ProbeDir       string  `json:"probe_dir,omitempty"`
	ResumeFile     string  `json:"resume_file,omitempty"`
	Verbose        bool    `json:"verbose"`
	SuppressOutput bool    `json:"-"` // silences scanner stdout when running under TUI
}

// ScanResult holds the result of a port scan.
type ScanResult struct {
	Hostname     string       `json:"hostname"`
	IPs          []string     `json:"ips"`
	OpenPorts    []PortResult `json:"open_ports"`
	ScanTimeMs   int64        `json:"scan_time_ms"`
	TotalScanned int          `json:"total_scanned"`
	ScanMode     string       `json:"scan_mode"`
	OSHint       string       `json:"os_hint,omitempty"`
	TTL          int          `json:"ttl,omitempty"`
}

// PortResult describes a single open port.
type PortResult struct {
	Port       int      `json:"port"`
	State      string   `json:"state"`
	Banner     string   `json:"banner,omitempty"`
	Technology []string `json:"technology,omitempty"`
	// TechMatches preserves structured fingerprint evidence from Akemi-Spear.
	TechMatches []TechMatch `json:"tech_matches,omitempty"`
	Service     string      `json:"service,omitempty"`
	Version     string      `json:"version,omitempty"`
	TLS         bool        `json:"tls"`
	TLSCN       string      `json:"tls_cn,omitempty"`
}

// TechMatch is a normalized technology fingerprint with confidence and evidence.
type TechMatch struct {
	Name       string  `json:"name"`
	Category   string  `json:"category"`
	Confidence float32 `json:"confidence"`
	Version    string  `json:"version,omitempty"`
	Evidence   string  `json:"evidence,omitempty"`
	Source     string  `json:"source,omitempty"`
}

// HostDiscoveryRequest describes a host discovery sweep.
type HostDiscoveryRequest struct {
	CIDR      string  `json:"cidr"`
	Threads   int     `json:"threads"`
	TimeoutMs int     `json:"timeout_ms"`
	Rate      float64 `json:"rate"`
	Verbose   bool    `json:"verbose"`
}

// HostDiscoveryResult holds the result of host discovery.
type HostDiscoveryResult struct {
	TotalHosts int         `json:"total_hosts"`
	AliveHosts []AliveHost `json:"alive_hosts"`
	ScanTimeMs int64       `json:"scan_time_ms"`
}

// AliveHost represents a responsive host.
type AliveHost struct {
	IP        string  `json:"ip"`
	Alive     bool    `json:"alive"`
	LatencyMs float64 `json:"latency_ms"`
	RDNS      string  `json:"rdns,omitempty"`
	Method    string  `json:"method"`
}

// =============================================================================
// Discoverer — Web surface discovery (crawl, params, JS, API)
// =============================================================================

// Discoverer performs web attack surface discovery.
type Discoverer interface {
	// Crawl discovers URLs by crawling from a start URL.
	Crawl(ctx context.Context, startURL string, maxDepth int) ([]CrawlFinding, error)

	// MineParams discovers HTTP parameters from URLs, forms, JS, and JSON.
	MineParams(ctx context.Context, targetURL string, cfg MiningConfig) (*ParamDiscoveryResult, error)

	// AnalyzeJS fetches and analyzes JavaScript files for endpoints and secrets.
	AnalyzeJS(ctx context.Context, pageURL string) (*JSAnalysisResult, error)

	// ScrapePage scrapes a page for structured data and keywords.
	ScrapePage(ctx context.Context, pageURL string, keywords []string) (*ScrapeResult, error)

	// DiscoverAPISurface discovers API endpoints and specs on a target.
	DiscoverAPISurface(ctx context.Context, startURL string, discoveredURLs []string) (*APISurfaceResult, error)

	// HuntAPISurface performs richer API discovery with optional safe-active probing.
	HuntAPISurface(ctx context.Context, req APIHuntRequest) (*APIHuntResult, error)
}

// CrawlFinding represents a discovered URL from crawling.
type CrawlFinding struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Depth      int    `json:"depth"`
	SourceURL  string `json:"source_url"`
	Title      string `json:"title,omitempty"`
}

// MiningConfig configures parameter mining behavior.
type MiningConfig struct {
	Depth        int      `json:"depth"`
	Threads      int      `json:"threads"`
	Timeout      int      `json:"timeout"`
	MineJS       bool     `json:"mine_js"`
	MineForms    bool     `json:"mine_forms"`
	MineJSON     bool     `json:"mine_json"`
	MinePath     bool     `json:"mine_path"`
	ActiveBrute  bool     `json:"active_brute"`
	Keywords     []string `json:"keywords,omitempty"`
	MineKeywords bool     `json:"mine_keywords"`
}

// ParamDiscoveryResult holds the result of parameter mining.
type ParamDiscoveryResult struct {
	Params     map[string]ParamDetail `json:"params"`
	TotalCount int                    `json:"total_count"`
}

// ParamDetail describes a discovered parameter.
type ParamDetail struct {
	Name     string   `json:"name"`
	Sources  []string `json:"sources"`
	Examples []string `json:"examples,omitempty"`
}

// JSAnalysisResult holds JavaScript analysis findings.
type JSAnalysisResult struct {
	ScriptURLs   []string        `json:"script_urls"`
	Endpoints    []string        `json:"endpoints"`
	Secrets      []SecretFinding `json:"secrets"`
	HiddenParams []string        `json:"hidden_params"`
}

// SecretFinding represents a discovered secret.
type SecretFinding struct {
	Category   string `json:"category"`
	Value      string `json:"value"`
	SourceURL  string `json:"source_url"`
	SourceKind string `json:"source_kind"`
	Evidence   string `json:"evidence,omitempty"`
}

// ScrapeResult holds page scraping output.
type ScrapeResult struct {
	Title          string              `json:"title"`
	Description    string              `json:"description"`
	MetaTags       map[string]string   `json:"meta_tags"`
	Links          []string            `json:"links"`
	Forms          []FormInfo          `json:"forms"`
	Comments       []string            `json:"comments"`
	KeywordMatches map[string][]string `json:"keyword_matches"`
}

// FormInfo describes an HTML form.
type FormInfo struct {
	Action string       `json:"action"`
	Method string       `json:"method"`
	Inputs []InputField `json:"inputs"`
}

// InputField describes a form input.
type InputField struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Value      string `json:"value"`
	Vulnerable bool   `json:"vulnerable"`
}

// APISurfaceResult holds API discovery output.
type APISurfaceResult struct {
	APIEndpoints []APIEndpointFinding `json:"api_endpoints"`
	APISpecs     []APISpecFinding     `json:"api_specs"`
}

// APIHuntRequest configures first-class API surface hunting.
type APIHuntRequest struct {
	StartURL       string   `json:"start_url"`
	DiscoveredURLs []string `json:"discovered_urls,omitempty"`
	Mode           string   `json:"mode,omitempty"` // passive or safe-active
	Wordlist       []string `json:"wordlist,omitempty"`
	WordlistFile   string   `json:"wordlist_file,omitempty"`
	AuthCookies    []string `json:"auth_cookies,omitempty"`
	MaxCandidates  int      `json:"max_candidates,omitempty"`
	Threads        int      `json:"threads,omitempty"`
	Timeout        int      `json:"timeout,omitempty"`
}

// APIHuntResult aggregates API Hunter findings.
type APIHuntResult struct {
	StartURL      string                `json:"start_url"`
	Mode          string                `json:"mode"`
	APIEndpoints  []APIEndpointFinding  `json:"api_endpoints"`
	APISpecs      []APISpecFinding      `json:"api_specs"`
	Parameters    []APIParameterFinding `json:"parameters,omitempty"`
	Counts        map[string]int        `json:"counts,omitempty"`
	StageErrors   []string              `json:"stage_errors,omitempty"`
	SourceSummary map[string]int        `json:"source_summary,omitempty"`
}

// APIEndpointFinding represents a discovered API endpoint.
type APIEndpointFinding struct {
	URL          string         `json:"url"`
	Path         string         `json:"path"`
	Method       string         `json:"method"`
	APIType      string         `json:"api_type"`
	Version      string         `json:"version,omitempty"`
	StatusCode   int            `json:"status_code,omitempty"`
	Status       string         `json:"status,omitempty"`
	ContentType  string         `json:"content_type,omitempty"`
	AuthRequired bool           `json:"auth_required,omitempty"`
	Confidence   float64        `json:"confidence,omitempty"`
	SourceURLs   []string       `json:"source_urls,omitempty"`
	SourceKinds  []string       `json:"source_kinds,omitempty"`
	Evidence     []string       `json:"evidence,omitempty"`
	Parameters   []APIParameter `json:"parameters,omitempty"`
}

// APISpecFinding represents a discovered API specification.
type APISpecFinding struct {
	URL                     string   `json:"url"`
	APIType                 string   `json:"api_type"`
	Format                  string   `json:"format"`
	Title                   string   `json:"title"`
	Version                 string   `json:"version,omitempty"`
	StatusCode              int      `json:"status_code,omitempty"`
	Status                  string   `json:"status,omitempty"`
	ContentType             string   `json:"content_type,omitempty"`
	SourceURLs              []string `json:"source_urls,omitempty"`
	Evidence                []string `json:"evidence,omitempty"`
	EndpointCount           int      `json:"endpoint_count,omitempty"`
	DiscoveredEndpointCount int      `json:"discovered_endpoint_count,omitempty"`
	CoveragePercent         float64  `json:"coverage_percent,omitempty"`
}

// APIParameter describes a parameter associated with an API endpoint.
type APIParameter struct {
	Name     string   `json:"name"`
	In       string   `json:"in,omitempty"`
	Required bool     `json:"required,omitempty"`
	Type     string   `json:"type,omitempty"`
	Sources  []string `json:"sources,omitempty"`
}

// APIParameterFinding tracks a parameter across API endpoints.
type APIParameterFinding struct {
	Name      string   `json:"name"`
	In        string   `json:"in,omitempty"`
	Type      string   `json:"type,omitempty"`
	Required  bool     `json:"required,omitempty"`
	Endpoints []string `json:"endpoints,omitempty"`
	Sources   []string `json:"sources,omitempty"`
}

// =============================================================================
// Prober — Vulnerability validation
// =============================================================================

// Prober validates vulnerabilities using YAML templates.
type Prober interface {
	// ListTemplates returns all loaded probe templates.
	ListTemplates() []ProbeTemplate

	// FilterTemplates returns templates matching the given criteria.
	FilterTemplates(tags []string, ids []string) []ProbeTemplate

	// Probe executes vulnerability probes against a target.
	Probe(ctx context.Context, targetURL string, cfg ProbeConfig) ([]VulnFinding, error)
}

// ProbeTemplate represents a YAML vulnerability probe.
type ProbeTemplate struct {
	ID        string           `json:"id" yaml:"id"`
	Disabled  bool             `json:"disabled,omitempty" yaml:"disabled,omitempty"`
	Info      TemplateInfo     `json:"info" yaml:"info"`
	Protocol  string           `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Ports     []string         `json:"ports,omitempty" yaml:"ports,omitempty"`
	Inject    string           `json:"inject" yaml:"inject"`
	Detection string           `json:"detection" yaml:"detection"`
	Payloads  []string         `json:"payloads,omitempty" yaml:"payloads,omitempty"`
	Matchers  TemplateMatchers `json:"matchers,omitempty" yaml:"matchers,omitempty"`
}

// TemplateInfo holds probe metadata.
type TemplateInfo struct {
	Name        string   `json:"name" yaml:"name"`
	Severity    string   `json:"severity" yaml:"severity"`
	Description string   `json:"description" yaml:"description"`
	Tags        []string `json:"tags" yaml:"tags"`
	Author      string   `json:"author" yaml:"author"`
}

// TemplateMatchers defines detection criteria.
type TemplateMatchers struct {
	BodyPatterns   []string          `json:"body_patterns,omitempty" yaml:"body_patterns,omitempty"`
	BannerPatterns []string          `json:"banner_patterns,omitempty" yaml:"banner_patterns,omitempty"`
	StatusCodes    []int             `json:"status_codes,omitempty" yaml:"status_codes,omitempty"`
	Headers        map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
}

// ProbeConfig configures vulnerability probing.
type ProbeConfig struct {
	Threads      int      `json:"threads"`
	Timeout      int      `json:"timeout"`
	UseTemplates bool     `json:"use_templates"`
	TemplateDir  string   `json:"template_dir,omitempty"`
	TemplateTags []string `json:"template_tags,omitempty"`
	TemplateIDs  []string `json:"template_ids,omitempty"`
}

// VulnFinding represents a discovered vulnerability.
type VulnFinding struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Target      string `json:"target"`
	Evidence    string `json:"evidence,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// =============================================================================
// SubEnumerator — Subdomain enumeration
// =============================================================================

// SubEnumerator discovers subdomains for a domain.
type SubEnumerator interface {
	// Enumerate discovers subdomains using passive and active methods.
	Enumerate(ctx context.Context, domain string, cfg SubdomainConfig) ([]SubdomainResult, error)
}

// SubdomainConfig configures subdomain enumeration.
type SubdomainConfig struct {
	WordlistFile string `json:"wordlist_file,omitempty"`
	Threads      int    `json:"threads"`
	Timeout      int    `json:"timeout"`
	UseCrtSh     bool   `json:"use_crtsh"`
	CheckAlive   bool   `json:"check_alive"`
	Permutate    bool   `json:"permutate"`
}

// SubdomainResult represents a discovered subdomain.
type SubdomainResult struct {
	Name       string   `json:"name"`
	Source     string   `json:"source"`
	IPs        []string `json:"ips,omitempty"`
	IsAlive    bool     `json:"is_alive"`
	StatusCode int      `json:"status_code,omitempty"`
}

// =============================================================================
// Reporter — Report and graph generation
// =============================================================================

// Reporter generates scan reports and visualizations.
type Reporter interface {
	// GenerateReport produces an HTML and/or JSON report from scan data.
	GenerateReport(ctx context.Context, data *ReportData) (*Report, error)

	// GenerateGraph produces a relational graph from scan data.
	GenerateGraph(ctx context.Context, data *ReportData) (*GraphData, error)
}

// ReportData aggregates all scan findings for reporting.
type ReportData struct {
	Target        string                `json:"target"`
	StartTime     time.Time             `json:"start_time"`
	EndTime       time.Time             `json:"end_time"`
	PortScan      *ScanResult           `json:"port_scan,omitempty"`
	CrawlFindings []CrawlFinding        `json:"crawl_findings,omitempty"`
	Params        *ParamDiscoveryResult `json:"params,omitempty"`
	JSAnalysis    *JSAnalysisResult     `json:"js_analysis,omitempty"`
	APIEndpoints  []APIEndpointFinding  `json:"api_endpoints,omitempty"`
	APISpecs      []APISpecFinding      `json:"api_specs,omitempty"`
	APIParameters []APIParameterFinding `json:"api_parameters,omitempty"`
	Subdomains    []SubdomainResult     `json:"subdomains,omitempty"`
	VulnFindings  []VulnFinding         `json:"vuln_findings,omitempty"`
	Secrets       []SecretFinding       `json:"secrets,omitempty"`
	FuzzResults   []FuzzResult          `json:"fuzz_results,omitempty"`
}

// Report holds generated report output.
type Report struct {
	HTMLPath string        `json:"html_path,omitempty"`
	JSONPath string        `json:"json_path,omitempty"`
	Summary  ReportSummary `json:"summary"`
}

// ReportSummary provides a high-level overview.
type ReportSummary struct {
	Target          string `json:"target"`
	Duration        string `json:"duration"`
	TotalURLs       int    `json:"total_urls"`
	TotalParams     int    `json:"total_params"`
	TotalSubdomains int    `json:"total_subdomains"`
	TotalVulns      int    `json:"total_vulns"`
	HighSeverity    int    `json:"high_severity"`
	MediumSeverity  int    `json:"medium_severity"`
	LowSeverity     int    `json:"low_severity"`
	TotalSecrets    int    `json:"total_secrets"`
}

// GraphData holds graph nodes and edges.
type GraphData struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// GraphNode represents a node in the attack surface graph.
type GraphNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Type  string `json:"type"`
}

// GraphEdge connects two graph nodes.
type GraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label"`
}

// =============================================================================
// Fuzzer — Web fuzzing
// =============================================================================

// Fuzzer performs web fuzzing with wordlists.
type Fuzzer interface {
	// Fuzz runs a fuzzing campaign.
	Fuzz(ctx context.Context, cfg FuzzConfig) ([]FuzzResult, error)
}

// FuzzConfig configures a fuzzing run.
type FuzzConfig struct {
	URL         string `json:"url"`
	Method      string `json:"method"`
	Data        string `json:"data"`
	PayloadFile string `json:"payload_file"`
	OutputFile  string `json:"output_file"`
	Repeats     int    `json:"repeats"`
	Timeout     int    `json:"timeout"`
	Concurrency int    `json:"concurrency"`
}

// FuzzResult holds a single fuzzing result.
type FuzzResult struct {
	ID         int    `json:"id"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Lines      int    `json:"lines"`
	Words      int    `json:"words"`
	Chars      int    `json:"chars"`
	Payload    string `json:"payload"`
	Error      string `json:"error,omitempty"`
}

// =============================================================================
// ExploitLookup — ExploitDB correlation
// =============================================================================

// ExploitLookup correlates services with known exploits.
type ExploitLookup interface {
	// SearchByBanner finds exploits matching a service banner.
	SearchByBanner(ctx context.Context, banner string, port int, maxResults int) ([]ExploitMatch, error)

	// SearchByTechnology finds exploits for specific technologies.
	SearchByTechnology(ctx context.Context, technologies []string, maxResults int) ([]ExploitMatch, error)
}

// ExploitMatch represents a matched exploit entry.
type ExploitMatch struct {
	ID          int    `json:"id"`
	Description string `json:"description"`
	Date        string `json:"date"`
	Author      string `json:"author"`
	Platform    string `json:"platform"`
	Type        string `json:"type"`
	Port        int    `json:"port,omitempty"`
	EDBURL      string `json:"edb_url"`
}

// =============================================================================
// HTTPClientFactory — Creates configured HTTP clients
// =============================================================================

// HTTPClientFactory creates HTTP clients with proxy and auth settings.
type HTTPClientFactory interface {
	// Create returns an HTTP client configured with the current settings.
	Create(timeoutSeconds int) *http.Client

	// CreateWithCookies returns a client that sends the given cookies.
	CreateWithCookies(timeoutSeconds int, cookies []string) *http.Client
}
