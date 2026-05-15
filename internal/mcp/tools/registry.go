package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	core "Akemi/internal/core"
	"Akemi/internal/dothound"
	"Akemi/internal/engagement"
	"Akemi/internal/mcp"
	mcpstate "Akemi/internal/mcp/state"
	recon "Akemi/internal/recon"
	"Akemi/internal/toolbridge"
)

// ToolFunc is the function signature for a tool handler.
type ToolFunc func(ctx context.Context, args map[string]interface{}, services *Services) ([]mcp.ContentBlock, error)

// RegisteredTool pairs MCP metadata with a handler function.
type RegisteredTool struct {
	Tool    mcp.Tool
	Handler ToolFunc
}

// Services holds the Phase 1 service interfaces needed by tools.
type Services struct {
	Scanner       core.Scanner
	Discoverer    core.Discoverer
	Prober        core.Prober
	SubEnumerator core.SubEnumerator
	Reporter      core.Reporter
	Context       engagement.ContextStore
	ReportDir     string
	Logger        *slog.Logger
	EventSink     toolbridge.Sink
	State         *mcpstate.Store
	Jobs          *JobManager
}

// ToolRegistry manages all registered MCP tools.
type ToolRegistry struct {
	tools    map[string]*RegisteredTool
	services *Services
}

// ToolRegistryConfig holds the dependencies needed to create a ToolRegistry.
type ToolRegistryConfig struct {
	Scanner       core.Scanner
	Discoverer    core.Discoverer
	Prober        core.Prober
	SubEnumerator core.SubEnumerator
	Reporter      core.Reporter
	Context       engagement.ContextStore
	ReportDir     string
	Logger        *slog.Logger
	EventSink     toolbridge.Sink
	State         *mcpstate.Store
	Jobs          *JobManager
}

// NewToolRegistry creates a registry with all standard Akemi tools.
func NewToolRegistry(cfg ToolRegistryConfig) *ToolRegistry {
	svc := &Services{
		Scanner:       cfg.Scanner,
		Discoverer:    cfg.Discoverer,
		Prober:        cfg.Prober,
		SubEnumerator: cfg.SubEnumerator,
		Reporter:      cfg.Reporter,
		Context:       cfg.Context,
		ReportDir:     cfg.ReportDir,
		Logger:        cfg.Logger,
		EventSink:     cfg.EventSink,
		State:         cfg.State,
		Jobs:          cfg.Jobs,
	}
	if svc.Context == nil {
		svc.Context = engagement.NewMemoryContextStore()
	}
	if svc.State == nil {
		svc.State = mcpstate.NewStore(svc.Context)
	} else {
		svc.State.SetContextStore(svc.Context)
	}
	if svc.Jobs == nil {
		svc.Jobs = NewJobManager(svc.State)
	}
	if svc.ReportDir == "" {
		svc.ReportDir = "."
	}

	reg := &ToolRegistry{
		tools:    make(map[string]*RegisteredTool),
		services: svc,
	}

	reg.registerAll()
	return reg
}

// SetEventSink attaches an optional UI bridge for in-process tool execution.
func (r *ToolRegistry) SetEventSink(sink toolbridge.Sink) {
	if r == nil || r.services == nil {
		return
	}
	r.services.EventSink = sink
}

// List returns all registered tools as MCP Tool descriptors.
func (r *ToolRegistry) List() []mcp.Tool {
	tools := make([]mcp.Tool, 0, len(r.tools))
	for _, rt := range r.tools {
		tools = append(tools, rt.Tool)
	}
	return tools
}

// Call invokes a tool by name. The ctxIface must be a context.Context;
// we use interface{} to match mcp.ToolProvider without circular imports.
func (r *ToolRegistry) Call(ctxIface interface{}, name string, args map[string]interface{}) ([]mcp.ContentBlock, error) {
	ctx, _ := ctxIface.(context.Context)
	if ctx == nil {
		ctx = context.Background()
	}
	name = canonicalToolName(name)
	rt, ok := r.tools[name]
	if !ok {
		return nil, fmt.Errorf("tool not found: %s", name)
	}

	if r.services.Logger != nil {
		r.services.Logger.Info("executing tool",
			slog.String("tool", name),
		)
	}

	return rt.Handler(ctx, args, r.services)
}

func canonicalToolName(name string) string {
	switch strings.TrimSpace(name) {
	case "akemi_full_surface_scan", "full_surface_scan", "full_surface_map":
		return "akemi_full_surface_map"
	default:
		return name
	}
}

// registerAll adds every standard Akemi tool to the registry.
func (r *ToolRegistry) registerAll() {
	r.registerContextTools()

	// ── Reconnaissance ─────────────────────────────────────
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_port_scan",
			Description: "High-speed TCP port scanning with service fingerprinting. Performs connect or SYN scan, banner grabbing, technology identification, and OS detection via TTL analysis. Returns open ports with service details.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":    {Type: "string", Description: "Target IP, hostname, or CIDR range (e.g., 192.168.1.0/24)"},
					"ports":     {Type: "string", Description: "Ports to scan: comma-separated list or ranges (e.g., '22,80,443,8000-8080')", Default: "top-1000"},
					"threads":   {Type: "integer", Description: "Concurrent scan threads", Default: float64(200)},
					"syn_mode":  {Type: "boolean", Description: "Use SYN stealth scan (requires root/admin privileges)", Default: false},
					"rate":      {Type: "number", Description: "Rate limit in connections/second (0 = unlimited)", Default: float64(0)},
					"timeout":   {Type: "integer", Description: "Timeout per port in seconds", Default: float64(3)},
					"randomize": {Type: "boolean", Description: "Randomize port scan order for IDS evasion", Default: true},
				},
			},
		},
		Handler: handlePortScan,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_host_discover",
			Description: "Discover live hosts in a CIDR range. Uses ICMP and TCP-ping methods to identify responsive IPs with latency measurements. Useful for mapping an internal network before deeper scanning.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"cidr":    {Type: "string", Description: "CIDR range to scan (e.g., 192.168.1.0/24, 10.0.0.0/16)"},
					"threads": {Type: "integer", Description: "Concurrent threads", Default: float64(100)},
					"timeout": {Type: "integer", Description: "Timeout per host in seconds", Default: float64(2)},
				},
				Required: []string{"cidr"},
			},
		},
		Handler: handleHostDiscover,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_subdomain_enum",
			Description: "Enumerate subdomains using certificate transparency logs (crt.sh), wordlist brute-force, and permutation generation. Optionally probes discovered subdomains for live HTTP/HTTPS services.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"domain":   {Type: "string", Description: "Target domain (e.g., example.com)"},
					"wordlist": {Type: "string", Description: "Path to wordlist file for brute-force (optional)"},
					"threads":  {Type: "integer", Description: "Concurrent threads", Default: float64(20)},
					"crtsh":    {Type: "boolean", Description: "Query crt.sh certificate transparency logs", Default: true},
					"alive":    {Type: "boolean", Description: "Probe subdomains for live HTTP services", Default: true},
					"permute":  {Type: "boolean", Description: "Generate permutations from discovered subdomains", Default: false},
				},
				Required: []string{"domain"},
			},
		},
		Handler: handleSubdomainEnum,
	})

	// ── Discovery ─────────────────────────────────────────
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_crawl",
			Description: "Crawl a website using Akemi's managed crawler. Depth is 1-7; depths 1-6 cap URLs at depth*1000, while depth 7 removes the URL cap.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"url":   {Type: "string", Description: "Starting URL for the crawl"},
					"depth": {Type: "integer", Description: "Managed crawl depth 1-7. 1=1000 URLs, 2=2000 URLs, ... 6=6000 URLs, 7=unlimited URL budget.", Default: float64(3)},
				},
			},
		},
		Handler: handleCrawl,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_full_surface_map",
			Description: "Run Akemi's dedicated full_surface_map workflow using the same live service sequence as the target configuration dashboard: managed crawl, port scan, header/tech probes, parameter mining, JavaScript analysis, API discovery, and subdomain enumeration.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":     {Type: "string", Description: "Target URL, hostname, or IP. Defaults to the configured active target."},
					"domain":     {Type: "string", Description: "Domain to use for subdomain enumeration. Defaults to the target hostname."},
					"port_range": {Type: "string", Description: "Dashboard port range, e.g. top-1000 or 80,443,8080", Default: "top-1000"},
					"threads":    {Type: "integer", Description: "Concurrent scan/probe threads", Default: float64(200)},
					"timeout":    {Type: "integer", Description: "Network timeout in seconds", Default: float64(10)},
					"depth":      {Type: "integer", Description: "Managed crawl depth 1-7. 1=1000 URLs, 2=2000 URLs, ... 6=6000 URLs, 7=unlimited URL budget.", Default: float64(2)},
					"rate":       {Type: "number", Description: "Port scan rate limit in connections/second (0 = unlimited)", Default: float64(0)},
					"syn_mode":   {Type: "boolean", Description: "Use SYN scan mode for the port scan", Default: false},
					"randomize":  {Type: "boolean", Description: "Randomize port scan order", Default: true},
				},
			},
		},
		Handler: handleFullSurfaceMap,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_full_surface_scan",
			Description: "Alias for akemi_full_surface_map. Runs the full_surface_scan/full_surface_map workflow and streams port, crawl, parameter, JavaScript, API, subdomain, finding, and secret discoveries.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":     {Type: "string", Description: "Target URL, hostname, or IP. Defaults to the configured active target."},
					"domain":     {Type: "string", Description: "Domain to use for subdomain enumeration. Defaults to the target hostname."},
					"port_range": {Type: "string", Description: "Dashboard port range, e.g. top-1000 or 80,443,8080", Default: "top-1000"},
					"threads":    {Type: "integer", Description: "Concurrent scan/probe threads", Default: float64(200)},
					"timeout":    {Type: "integer", Description: "Network timeout in seconds", Default: float64(10)},
					"depth":      {Type: "integer", Description: "Managed crawl depth 1-7. 1=1000 URLs, 2=2000 URLs, ... 6=6000 URLs, 7=unlimited URL budget.", Default: float64(2)},
					"rate":       {Type: "number", Description: "Port scan rate limit in connections/second (0 = unlimited)", Default: float64(0)},
					"syn_mode":   {Type: "boolean", Description: "Use SYN scan mode for the port scan", Default: false},
					"randomize":  {Type: "boolean", Description: "Randomize port scan order", Default: true},
				},
			},
		},
		Handler: handleFullSurfaceMap,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_mine_params",
			Description: "Mine HTTP parameters from URLs, HTML forms, JSON responses, JavaScript files, and path segments. Discovers query parameters, form inputs, JSON keys, and REST path parameters.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"url":          {Type: "string", Description: "Target URL to mine parameters from"},
					"mine_js":      {Type: "boolean", Description: "Mine JavaScript files for parameters", Default: true},
					"mine_forms":   {Type: "boolean", Description: "Mine HTML forms for input names", Default: true},
					"mine_json":    {Type: "boolean", Description: "Mine JSON responses for keys", Default: true},
					"mine_path":    {Type: "boolean", Description: "Detect path parameters", Default: true},
					"active_brute": {Type: "boolean", Description: "Active parameter brute-force (Arjun-style)", Default: false},
				},
			},
		},
		Handler: handleMineParams,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_analyze_js",
			Description: "Fetch and analyze JavaScript files from a page. Extracts API endpoints, secrets (API keys, tokens, passwords), internal paths, and framework-specific patterns. Critical for finding hidden attack surface.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"url": {Type: "string", Description: "Page URL to analyze (JS files will be discovered and fetched automatically)"},
				},
				Required: []string{"url"},
			},
		},
		Handler: handleAnalyzeJS,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_scrape_page",
			Description: "Scrape a specific page for structured data: title, meta tags, forms with input fields, all links, HTML comments, and keyword matches. Useful for detailed analysis of a single endpoint.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"url": {Type: "string", Description: "Page URL to scrape"},
					"keywords": {Type: "array", Description: "Keywords to search for in page content",
						Items: &mcp.Property{Type: "string"}},
				},
				Required: []string{"url"},
			},
		},
		Handler: handleScrapePage,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_discover_api",
			Description: "Discover API endpoints and specifications. Detects REST endpoints, OpenAPI/Swagger specs, GraphQL introspection endpoints, and versioned API routes from crawled URLs.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"url": {Type: "string", Description: "Starting URL for API discovery"},
					"discovered_urls": {Type: "array", Description: "Optional: list of previously discovered URLs to analyze",
						Items: &mcp.Property{Type: "string"}},
				},
				Required: []string{"url"},
			},
		},
		Handler: handleDiscoverAPI,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_api_hunter",
			Description: "Run API Hunter: combines crawl/JS/config/spec discovery with optional safe-active GET/HEAD/OPTIONS probing, endpoint confidence, auth-required hints, parameters, and spec coverage.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"url":            {Type: "string", Description: "Starting URL for API Hunter"},
					"mode":           {Type: "string", Description: "API Hunter mode", Default: "safe-active", Enum: []string{"passive", "safe-active"}},
					"max_candidates": {Type: "integer", Description: "Maximum candidates to safely probe", Default: float64(250)},
					"wordlist":       {Type: "string", Description: "Optional path to an API wordlist file"},
					"cookies":        {Type: "string", Description: "Optional semicolon-separated cookies for authenticated API discovery"},
					"discovered_urls": {Type: "array", Description: "Optional: previously discovered URLs",
						Items: &mcp.Property{Type: "string"}},
				},
				Required: []string{"url"},
			},
		},
		Handler: handleAPIHunter,
	})

	// ── Vulnerability Validation ─────────────────────────
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_list_templates",
			Description: "List all available YAML vulnerability probe templates. Returns template IDs, names, severities, tags, and descriptions. Use this to understand what vulnerability classes can be tested before running probes.",
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]mcp.Property{},
			},
		},
		Handler: handleListTemplates,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_probe_vulns",
			Description: "Execute YAML-based vulnerability probes against a target. Tests for SQL injection, XSS, LFI/RFI, command injection, SSRF, deserialization, and more. ACTIVE probing — only use on authorized targets.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"url":      {Type: "string", Description: "Target URL with parameters to test (e.g., https://target.com/page?id=1)"},
					"tags":     {Type: "string", Description: "Comma-separated tags to filter templates (e.g., 'sqli,xss,lfi,high'). Leave empty for all."},
					"template": {Type: "string", Description: "Run a specific template by ID (e.g., 'log4shell', 'sqli-error')"},
					"threads":  {Type: "integer", Description: "Concurrent probe threads", Default: float64(5)},
					"timeout":  {Type: "integer", Description: "Timeout per probe in seconds", Default: float64(10)},
				},
			},
		},
		Handler: handleProbeVulns,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_check_headers",
			Description: "Audit HTTP security headers and cookie security. Checks for missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and proper cookie flags (HttpOnly, Secure, SameSite). Also detects CORS misconfigurations.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"url": {Type: "string", Description: "Target URL to check headers on"},
				},
			},
		},
		Handler: handleCheckHeaders,
	})

	// ── Exploitation & Correlation ───────────────────────
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_exploit_lookup",
			Description: "Query the ExploitDB dataset for known exploits matching identified services, versions, banners, and technologies. Returns ranked exploit matches with EDB-IDs, descriptions, and links.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"banner": {Type: "string", Description: "Service banner to search for (e.g., 'Apache/2.4.41')"},
					"technologies": {Type: "array", Description: "Technology names to search for (e.g., ['nginx', 'php'])",
						Items: &mcp.Property{Type: "string"}},
					"port":        {Type: "integer", Description: "Port number for targeted search"},
					"max_results": {Type: "integer", Description: "Maximum results to return", Default: float64(10)},
				},
			},
		},
		Handler: handleExploitLookup,
	})

	// ── Fuzzing ──────────────────────────────────────────
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_fuzz",
			Description: "Fuzz URL paths, query parameters, or POST data with a wordlist. Uses the FUZZ placeholder for injection points. Returns responses with status codes, line/word/char counts for anomaly detection.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"url":         {Type: "string", Description: "Target URL with FUZZ placeholder (e.g., https://target.com/FUZZ)"},
					"method":      {Type: "string", Description: "HTTP method", Default: "GET", Enum: []string{"GET", "POST", "PUT", "DELETE", "PATCH"}},
					"data":        {Type: "string", Description: "POST body data with FUZZ placeholder"},
					"wordlist":    {Type: "string", Description: "Path to wordlist file (required)"},
					"concurrency": {Type: "integer", Description: "Concurrent workers", Default: float64(10)},
					"repeats":     {Type: "integer", Description: "Requests per payload", Default: float64(1)},
				},
				Required: []string{"url", "wordlist"},
			},
		},
		Handler: handleFuzz,
	})

	// ── OSINT ────────────────────────────────────────────
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_dork",
			Description: "Execute search engine dork queries to discover vulnerable endpoints, exposed documents, and indexed sensitive content. Uses DuckDuckGo or Google as the backend.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"query":       {Type: "string", Description: "Dork query (e.g., 'site:target.com ext:php inurl:id=')"},
					"engine":      {Type: "string", Description: "Search engine to use", Default: "duckduckgo", Enum: []string{"duckduckgo", "google"}},
					"max_results": {Type: "integer", Description: "Maximum results to return", Default: float64(20)},
				},
				Required: []string{"query"},
			},
		},
		Handler: handleDork,
	})

	// ── Reporting ────────────────────────────────────────
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_generate_report",
			Description: "Generate a comprehensive HTML or JSON report from scan findings. Includes executive summary, findings by severity, service details, and remediation guidance.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target":     {Type: "string", Description: "Target name/identifier for the report"},
					"format":     {Type: "string", Description: "Report format", Default: "html", Enum: []string{"html", "json", "both"}},
					"output_dir": {Type: "string", Description: "Output directory", Default: "."},
				},
				Required: []string{"target"},
			},
		},
		Handler: handleGenerateReport,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_generate_graph",
			Description: "Generate an interactive attack surface graph visualization. Shows targets, endpoints, parameters, vulnerabilities, and their relationships as an explorable node-edge diagram.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target": {Type: "string", Description: "Target identifier for the graph"},
					"format": {Type: "string", Description: "Output format", Default: "html", Enum: []string{"html", "json", "dot"}},
				},
				Required: []string{"target"},
			},
		},
		Handler: handleGenerateGraph,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_read_report",
			Description: "Read a report artifact from the configured Akemi report directory. Paths are relative to the report directory and limited to report file extensions.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"path":      {Type: "string", Description: "Relative report path, e.g. report.md or findings/report.html"},
					"max_bytes": {Type: "integer", Description: "Maximum bytes to read", Default: float64(5242880)},
				},
				Required: []string{"path"},
			},
		},
		Handler: handleReadReport,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_write_report",
			Description: "Write a report artifact under the configured Akemi report directory. Paths are relative to the report directory and limited to report file extensions.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"path":      {Type: "string", Description: "Relative report path, e.g. report.md or findings/report.html"},
					"content":   {Type: "string", Description: "Report file content"},
					"overwrite": {Type: "boolean", Description: "Overwrite an existing report file", Default: true},
				},
				Required: []string{"path", "content"},
			},
		},
		Handler: handleWriteReport,
	})

	// ── Technology Fingerprinting ────────────────────────
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_tech_fingerprint",
			Description: "Identify the technology stack of a target: web server, frameworks, JavaScript libraries, CDN, and version detection from response headers, cookies, HTML patterns, and file fingerprints.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"url": {Type: "string", Description: "Target URL to fingerprint"},
				},
			},
		},
		Handler: handleTechFingerprint,
	})

	// ── Auth & Session ───────────────────────────────────
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_auth_capture",
			Description: "Capture a login workflow using headless HTTPS MITM proxy (DotHound). Records all HTTP exchanges during authentication, extracts session cookies and CSRF tokens for subsequent authenticated scanning.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"url":      {Type: "string", Description: "Login page URL"},
					"username": {Type: "string", Description: "Login username"},
					"password": {Type: "string", Description: "Login password"},
				},
				Required: []string{"url", "username", "password"},
			},
		},
		Handler: handleAuthCapture,
	})

	// Job and detail tools.
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_start_run",
			Description: "Start a long-running Akemi job. Currently supports kind=full_surface_map or full_surface_scan and returns a run ID for status, cancellation, and artifact retrieval.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"kind":       {Type: "string", Description: "Job kind", Default: "full_surface_map", Enum: []string{"full_surface_map", "full_surface_scan"}},
					"target":     {Type: "string", Description: "Target URL, hostname, or IP"},
					"domain":     {Type: "string", Description: "Domain for subdomain enumeration"},
					"port_range": {Type: "string", Description: "Port range", Default: "top-1000"},
					"depth":      {Type: "integer", Description: "Managed crawl depth", Default: float64(2)},
					"threads":    {Type: "integer", Description: "Concurrent scan/probe threads", Default: float64(200)},
					"timeout":    {Type: "integer", Description: "Network timeout seconds", Default: float64(10)},
				},
			},
		},
		Handler: handleStartRun,
	})
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_run_status",
			Description: "Read the status of an Akemi long-running job.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"run_id": {Type: "string", Description: "Run ID returned by akemi_start_run"},
				},
				Required: []string{"run_id"},
			},
		},
		Handler: handleRunStatus,
	})
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_cancel_run",
			Description: "Cancel a running Akemi job.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"run_id": {Type: "string", Description: "Run ID returned by akemi_start_run"},
				},
				Required: []string{"run_id"},
			},
		},
		Handler: handleCancelRun,
	})
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_get_artifact",
			Description: "Read a stored Akemi job artifact by artifact ID.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"artifact_id": {Type: "string", Description: "Artifact ID"},
				},
				Required: []string{"artifact_id"},
			},
		},
		Handler: handleGetArtifact,
	})
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_search_findings",
			Description: "Search the latest structured findings and surface-map data.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"query":    {Type: "string", Description: "Text to search in finding names, descriptions, evidence, and targets"},
					"severity": {Type: "string", Description: "Optional severity filter"},
				},
			},
		},
		Handler: handleSearchFindings,
	})
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_get_finding",
			Description: "Read one finding from the latest structured result by index or ID.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"id":    {Type: "string", Description: "Finding ID"},
					"index": {Type: "integer", Description: "Finding index from akemi_search_findings"},
				},
			},
		},
		Handler: handleGetFinding,
	})
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_summarize_run",
			Description: "Summarize the latest run or a specific run ID from stored MCP state.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"run_id": {Type: "string", Description: "Optional run ID"},
				},
			},
		},
		Handler: handleSummarizeRun,
	})
}

func (r *ToolRegistry) register(rt RegisteredTool) {
	decorateTool(&rt.Tool)
	r.tools[rt.Tool.Name] = &rt
}

// =============================================================================
// Tool Handler Implementations
// =============================================================================

func handlePortScan(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	target := getString(args, "target")
	if target == "" {
		target = activeTargetForPortScan(ctx, svc)
	}
	if target == "" {
		return nil, fmt.Errorf("target is required; call akemi_configure_target or pass target")
	}
	def := defaults(ctx, svc)
	portsStr := getString(args, "ports")
	if portsStr == "" {
		portsStr = def.Ports
	}
	if portsStr == "" {
		portsStr = "top-1000"
	}

	ports := recon.ParsePortsList([]string{portsStr})
	threadDefault := 200
	if def.Threads > 0 {
		threadDefault = def.Threads
	}
	timeoutDefault := 3
	if def.Timeout > 0 {
		timeoutDefault = def.Timeout
	}

	req := core.ScanRequest{
		Host:       target,
		Ports:      ports,
		Threads:    getInt(args, "threads", threadDefault),
		TimeoutMs:  getInt(args, "timeout", timeoutDefault) * 1000,
		Rate:       getFloat64(args, "rate", 0),
		SynMode:    getBool(args, "syn_mode"),
		Randomize:  getBoolDefault(args, "randomize", true),
		BannerGrab: true,
	}
	emitTargetConfig(ctx, svc, "akemi_port_scan", "Port scan", toolbridge.TargetConfig{
		Target:  target,
		Ports:   portsStr,
		Threads: intPtr(req.Threads),
		Timeout: intPtr(req.TimeoutMs / 1000),
	})

	result, err := svc.Scanner.Scan(ctx, req)
	if err != nil {
		return nil, err
	}
	emitDiscoveryItems(ctx, svc, "akemi_port_scan", "Port scan", portDiscoveryItems(result.OpenPorts)...)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Port Scan Results for %s:\n", result.Hostname))
	sb.WriteString(fmt.Sprintf("Mode: %s | Scanned: %d | Open: %d | Duration: %.1fs\n\n",
		result.ScanMode, result.TotalScanned, len(result.OpenPorts),
		float64(result.ScanTimeMs)/1000.0))

	for _, p := range result.OpenPorts {
		tech := ""
		if len(p.Technology) > 0 {
			tech = fmt.Sprintf(" [%s]", strings.Join(p.Technology, ", "))
		}
		banner := ""
		if p.Banner != "" {
			banner = fmt.Sprintf(" — %s", truncate(p.Banner, 100))
		}
		sb.WriteString(fmt.Sprintf("  Port %-5d %s%s%s\n", p.Port, p.State, tech, banner))
	}

	// Also produce structured JSON
	jsonData, _ := json.MarshalIndent(result, "", "  ")
	sb.WriteString("\n\n--- RAW JSON ---\n")
	sb.WriteString(string(jsonData))

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleHostDiscover(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	cidr := getString(args, "cidr")
	req := core.HostDiscoveryRequest{
		CIDR:      cidr,
		Threads:   getInt(args, "threads", 100),
		TimeoutMs: getInt(args, "timeout", 2) * 1000,
	}
	emitTargetConfig(ctx, svc, "akemi_host_discover", "Host discovery", toolbridge.TargetConfig{
		Target:  cidr,
		Threads: intPtr(req.Threads),
		Timeout: intPtr(req.TimeoutMs / 1000),
	})

	result, err := svc.Scanner.DiscoverHosts(ctx, req)
	if err != nil {
		return nil, err
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Host Discovery Results for %s:\n", cidr))
	sb.WriteString(fmt.Sprintf("Total alive hosts: %d\n\n", result.TotalHosts))
	for _, h := range result.AliveHosts {
		rdns := ""
		if h.RDNS != "" {
			rdns = fmt.Sprintf(" (%s)", h.RDNS)
		}
		sb.WriteString(fmt.Sprintf("  [+] %s%s — %.1fms via %s\n", h.IP, rdns, h.LatencyMs, h.Method))
	}

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleSubdomainEnum(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	domain := getString(args, "domain")
	cfg := core.SubdomainConfig{
		WordlistFile: getString(args, "wordlist"),
		Threads:      getInt(args, "threads", 20),
		Timeout:      10,
		UseCrtSh:     getBool(args, "crtsh"),
		CheckAlive:   getBool(args, "alive"),
		Permutate:    getBool(args, "permute"),
	}
	emitTargetConfig(ctx, svc, "akemi_subdomain_enum", "Subdomain enumeration", toolbridge.TargetConfig{
		Target:  domain,
		Threads: intPtr(cfg.Threads),
		Timeout: intPtr(cfg.Timeout),
	})

	results, err := svc.SubEnumerator.Enumerate(ctx, domain, cfg)
	if err != nil {
		return nil, err
	}
	emitDiscoveryItems(ctx, svc, "akemi_subdomain_enum", "Subdomain enumeration", subdomainDiscoveryItems(results)...)

	var sb strings.Builder
	alive := 0
	for _, r := range results {
		if r.IsAlive {
			alive++
		}
	}
	sb.WriteString(fmt.Sprintf("Subdomain Enumeration for %s: %d found (%d alive)\n\n", domain, len(results), alive))
	for _, r := range results {
		marker := "[*]"
		if r.IsAlive {
			marker = "[+]"
		}
		ipStr := ""
		if len(r.IPs) > 0 {
			ipStr = fmt.Sprintf(" → %v", r.IPs)
		}
		sb.WriteString(fmt.Sprintf("  %s %s (%s)%s\n", marker, r.Name, r.Source, ipStr))
	}

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleCrawl(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	url := getString(args, "url")
	if url == "" {
		url = activeTargetBaseURL(ctx, svc)
	}
	if url == "" {
		return nil, fmt.Errorf("url is required; call akemi_configure_target with base_url or pass url")
	}
	def := defaults(ctx, svc)
	depthDefault := 3
	if def.Depth > 0 {
		depthDefault = def.Depth
	}
	depth := core.NormalizeCrawlDepth(getInt(args, "depth", depthDefault))
	emitTargetConfig(ctx, svc, "akemi_crawl", "Crawling", toolbridge.TargetConfig{
		Target: url,
		Depth:  intPtr(depth),
	})

	var findings []core.CrawlFinding
	var err error
	if live, ok := svc.Discoverer.(liveCrawlDiscoverer); ok {
		findings, err = live.CrawlWithCallback(ctx, url, depth, func(f core.CrawlFinding) {
			emitDiscoveryItems(ctx, svc, "akemi_crawl", "Crawling", crawlDiscoveryItem(f))
		})
	} else {
		findings, err = svc.Discoverer.Crawl(ctx, url, depth)
	}
	if err != nil {
		return nil, err
	}
	if _, ok := svc.Discoverer.(liveCrawlDiscoverer); !ok {
		emitDiscoveryItems(ctx, svc, "akemi_crawl", "Crawling", crawlDiscoveryItems(findings)...)
	}

	var sb strings.Builder
	limit := core.CrawlURLLimitForDepth(depth)
	limitText := "unlimited"
	if limit > 0 {
		limitText = fmt.Sprintf("%d", limit)
	}
	sb.WriteString(fmt.Sprintf("Crawl Results for %s (depth %d, URL limit %s): %d URLs found\n\n", url, depth, limitText, len(findings)))
	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("  [%d] %s\n", f.StatusCode, f.URL))
	}
	sb.WriteString(fmt.Sprintf("\nSummary: %d URLs discovered.", len(findings)))

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleMineParams(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	url := getString(args, "url")
	if url == "" {
		url = activeTargetBaseURL(ctx, svc)
	}
	if url == "" {
		return nil, fmt.Errorf("url is required; call akemi_configure_target with base_url or pass url")
	}
	def := defaults(ctx, svc)
	cfg := core.MiningConfig{
		Depth:       def.Depth,
		Threads:     def.Threads,
		Timeout:     def.Timeout,
		MineJS:      getBoolDefault(args, "mine_js", defaultBool(def.MineJS, true)),
		MineForms:   getBoolDefault(args, "mine_forms", defaultBool(def.MineForms, true)),
		MineJSON:    getBoolDefault(args, "mine_json", defaultBool(def.MineJSON, true)),
		MinePath:    getBoolDefault(args, "mine_path", defaultBool(def.MinePath, true)),
		ActiveBrute: getBoolDefault(args, "active_brute", defaultBool(def.ActiveBrute, false)),
	}
	emitTargetConfig(ctx, svc, "akemi_mine_params", "Parameter mining", toolbridge.TargetConfig{
		Target:  url,
		Threads: intPtr(cfg.Threads),
		Depth:   intPtr(cfg.Depth),
		Timeout: intPtr(cfg.Timeout),
	})

	result, err := svc.Discoverer.MineParams(ctx, url, cfg)
	if err != nil {
		return nil, err
	}
	emitDiscoveryItems(ctx, svc, "akemi_mine_params", "Parameter mining", paramDiscoveryItems(result.Params)...)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Parameter Mining Results for %s: %d parameters discovered\n\n", url, result.TotalCount))
	for name, detail := range result.Params {
		sources := strings.Join(detail.Sources, ", ")
		examples := ""
		if len(detail.Examples) > 0 {
			examples = fmt.Sprintf(" (e.g., %s)", strings.Join(detail.Examples, ", "))
		}
		sb.WriteString(fmt.Sprintf("  %s [%s]%s\n", name, sources, examples))
	}

	storeDiscoveredParams(ctx, svc, url, result)

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleAnalyzeJS(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	url := getString(args, "url")
	emitTargetConfig(ctx, svc, "akemi_analyze_js", "JavaScript analysis", toolbridge.TargetConfig{Target: url})

	result, err := svc.Discoverer.AnalyzeJS(ctx, url)
	if err != nil {
		return nil, err
	}
	emitDiscoveryItems(ctx, svc, "akemi_analyze_js", "JavaScript analysis", jsDiscoveryItems(result)...)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("JavaScript Analysis for %s:\n", url))
	sb.WriteString(fmt.Sprintf("  Scripts: %d | Endpoints: %d | Secrets: %d | Hidden Params: %d\n\n",
		len(result.ScriptURLs), len(result.Endpoints), len(result.Secrets), len(result.HiddenParams)))

	if len(result.Endpoints) > 0 {
		sb.WriteString("Discovered Endpoints:\n")
		for _, ep := range result.Endpoints {
			sb.WriteString(fmt.Sprintf("  - %s\n", ep))
		}
		sb.WriteString("\n")
	}

	if len(result.Secrets) > 0 {
		sb.WriteString("⚠️  POTENTIAL SECRETS FOUND:\n")
		for _, s := range result.Secrets {
			sb.WriteString(fmt.Sprintf("  [%s] %s (source: %s)\n", s.Category, maskSecret(s.Value), s.SourceURL))
		}
	}

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleScrapePage(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	url := getString(args, "url")
	emitTargetConfig(ctx, svc, "akemi_scrape_page", "Page scrape", toolbridge.TargetConfig{Target: url})
	var keywords []string
	if kw, ok := args["keywords"].([]interface{}); ok {
		for _, k := range kw {
			if s, ok := k.(string); ok {
				keywords = append(keywords, s)
			}
		}
	}

	result, err := svc.Discoverer.ScrapePage(ctx, url, keywords)
	if err != nil {
		return nil, err
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Page Scrape: %s\n", url))
	sb.WriteString(fmt.Sprintf("Title: %s\n", result.Title))
	sb.WriteString(fmt.Sprintf("Description: %s\n", result.Description))
	sb.WriteString(fmt.Sprintf("Links: %d | Forms: %d | Comments: %d\n\n", len(result.Links), len(result.Forms), len(result.Comments)))

	if len(result.Forms) > 0 {
		sb.WriteString("Forms:\n")
		for i, f := range result.Forms {
			sb.WriteString(fmt.Sprintf("  Form %d: %s %s\n", i+1, f.Method, f.Action))
			for _, inp := range f.Inputs {
				marker := ""
				if inp.Vulnerable {
					marker = " ⚠️"
				}
				sb.WriteString(fmt.Sprintf("    - %s (%s)%s\n", inp.Name, inp.Type, marker))
			}
		}
	}

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleDiscoverAPI(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	url := getString(args, "url")
	emitTargetConfig(ctx, svc, "akemi_discover_api", "API discovery", toolbridge.TargetConfig{Target: url})
	var discoveredURLs []string
	if du, ok := args["discovered_urls"].([]interface{}); ok {
		for _, u := range du {
			if s, ok := u.(string); ok {
				discoveredURLs = append(discoveredURLs, s)
			}
		}
	}

	result, err := svc.Discoverer.DiscoverAPISurface(ctx, url, discoveredURLs)
	if err != nil {
		return nil, err
	}
	emitDiscoveryItems(ctx, svc, "akemi_discover_api", "API discovery", apiDiscoveryItems(result)...)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("API Discovery for %s:\n", url))
	sb.WriteString(fmt.Sprintf("Endpoints: %d | API Specs: %d\n\n", len(result.APIEndpoints), len(result.APISpecs)))

	if len(result.APIEndpoints) > 0 {
		sb.WriteString("API Endpoints:\n")
		for _, ep := range result.APIEndpoints {
			sb.WriteString(fmt.Sprintf("  [%s] %s %s (%s)\n", ep.Method, ep.Path, ep.APIType, ep.Version))
		}
		sb.WriteString("\n")
	}

	if len(result.APISpecs) > 0 {
		sb.WriteString("API Specifications:\n")
		for _, sp := range result.APISpecs {
			sb.WriteString(fmt.Sprintf("  %s — %s (%s, %d endpoints)\n", sp.Title, sp.URL, sp.Format, sp.EndpointCount))
		}
	}

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleAPIHunter(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	url := getString(args, "url")
	if url == "" {
		url = activeTargetBaseURL(ctx, svc)
	}
	if url == "" {
		return nil, fmt.Errorf("url is required; call akemi_configure_target with base_url or pass url")
	}
	mode := getString(args, "mode")
	if mode == "" {
		mode = "safe-active"
	}
	emitTargetConfig(ctx, svc, "akemi_api_hunter", "API Hunter", toolbridge.TargetConfig{Target: url, Intent: "api_hunter"})

	discoveredURLs := stringSliceArg(args["discovered_urls"])
	authCookies := splitCookieHeaderValue(getString(args, "cookies"))
	authCookieSource := "argument"
	if len(authCookies) == 0 {
		authCookies = activeAuthCookies(ctx, svc, url)
		authCookieSource = activeAuthCookieSource(ctx, svc, url)
	}
	result, err := svc.Discoverer.HuntAPISurface(ctx, core.APIHuntRequest{
		StartURL:       url,
		DiscoveredURLs: discoveredURLs,
		Mode:           mode,
		WordlistFile:   getString(args, "wordlist"),
		AuthCookies:    authCookies,
		MaxCandidates:  getInt(args, "max_candidates", 250),
		Timeout:        firstPositive(defaults(ctx, svc).Timeout, 10),
		Threads:        firstPositive(defaults(ctx, svc).Threads, 10),
	})
	if err != nil {
		return nil, err
	}
	discoveryItems := apiDiscoveryItems(&core.APISurfaceResult{
		APIEndpoints: result.APIEndpoints,
		APISpecs:     result.APISpecs,
	})
	discoveryItems = append(discoveryItems, apiParameterDiscoveryItems(result.Parameters)...)
	emitDiscoveryItems(ctx, svc, "akemi_api_hunter", "API Hunter", discoveryItems...)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("API Hunter for %s (%s):\n", url, result.Mode))
	if len(authCookies) > 0 {
		sb.WriteString(fmt.Sprintf("Authenticated context: %d cookie(s) loaded from %s.\n", len(authCookies), authCookieSource))
	}
	sb.WriteString(fmt.Sprintf("Endpoints: %d | Specs: %d | Parameters: %d | Stage Errors: %d\n\n",
		len(result.APIEndpoints), len(result.APISpecs), len(result.Parameters), len(result.StageErrors)))

	if len(result.APIEndpoints) > 0 {
		sb.WriteString("API Endpoints:\n")
		for _, ep := range result.APIEndpoints {
			method := firstNonBlank(ep.Method, "ANY")
			status := firstNonBlank(ep.Status, fmt.Sprintf("%d", ep.StatusCode))
			auth := ""
			if ep.AuthRequired {
				auth = " auth-required"
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s %s (%s, confidence %.2f%s)\n", method, ep.Path, ep.APIType, status, ep.Confidence, auth))
		}
		sb.WriteString("\n")
	}
	if len(result.APISpecs) > 0 {
		sb.WriteString("API Specifications:\n")
		for _, sp := range result.APISpecs {
			sb.WriteString(fmt.Sprintf("  %s — %s (%s, %d endpoints, spec-coverage %.0f%%)\n",
				firstNonBlank(sp.Title, sp.APIType), sp.URL, sp.Format, sp.EndpointCount, sp.CoveragePercent))
		}
	}
	if len(result.StageErrors) > 0 {
		sb.WriteString("\nStage Errors:\n")
		for _, stageErr := range result.StageErrors {
			sb.WriteString(fmt.Sprintf("  - %s\n", stageErr))
		}
	}
	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleListTemplates(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	templates := svc.Prober.ListTemplates()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Available Probe Templates: %d\n\n", len(templates)))
	sb.WriteString(fmt.Sprintf("%-4s %-8s %-35s %s\n", "", "Severity", "ID", "Tags"))
	sb.WriteString(fmt.Sprintf("%-4s %-8s %-35s %s\n", "----", "--------", "---", "----"))

	for _, t := range templates {
		if t.Disabled {
			continue
		}
		tags := strings.Join(t.Info.Tags, ", ")
		sb.WriteString(fmt.Sprintf("%-4s %-8s %-35s %s\n", "", t.Info.Severity, t.ID, tags))
	}

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleProbeVulns(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	url := getString(args, "url")
	if url == "" {
		url = activeTargetBaseURL(ctx, svc)
	}
	if url == "" {
		return nil, fmt.Errorf("url is required; call akemi_configure_target with base_url or pass url")
	}
	def := defaults(ctx, svc)
	tagsStr := getString(args, "tags")
	templateID := getString(args, "template")
	if tagsStr == "" && len(def.VulnTags) > 0 {
		tagsStr = strings.Join(def.VulnTags, ",")
	}
	if templateID == "" {
		templateID = def.TemplateID
	}

	var tags []string
	var ids []string
	if tagsStr != "" {
		tags = strings.Split(tagsStr, ",")
	}
	if templateID != "" {
		ids = []string{templateID}
	}

	cfg := core.ProbeConfig{
		Threads:      getInt(args, "threads", firstPositive(def.Threads, 5)),
		Timeout:      getInt(args, "timeout", firstPositive(def.Timeout, 10)),
		UseTemplates: true,
		TemplateTags: tags,
		TemplateIDs:  ids,
	}
	emitTargetConfig(ctx, svc, "akemi_probe_vulns", "Vulnerability probing", toolbridge.TargetConfig{
		Target:  url,
		Threads: intPtr(cfg.Threads),
		Timeout: intPtr(cfg.Timeout),
	})

	findings, err := svc.Prober.Probe(ctx, url, cfg)
	if err != nil {
		return nil, err
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Vulnerability Probe Results for %s: %d findings\n\n", url, len(findings)))

	if len(findings) == 0 {
		sb.WriteString("No vulnerabilities detected.")
		return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
	}

	groups := map[string][]core.VulnFinding{}
	for _, f := range findings {
		groups[f.Severity] = append(groups[f.Severity], f)
	}

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if group, ok := groups[sev]; ok {
			sb.WriteString(fmt.Sprintf("[%s] %d finding(s):\n", strings.ToUpper(sev), len(group)))
			for _, f := range group {
				sb.WriteString(fmt.Sprintf("  - %s: %s\n", f.Name, f.Description))
				if f.Evidence != "" {
					sb.WriteString(fmt.Sprintf("    Evidence: %s\n", truncate(f.Evidence, 120)))
				}
			}
			sb.WriteString("\n")
		}
	}

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleCheckHeaders(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	url := getString(args, "url")
	if url == "" {
		url = activeTargetBaseURL(ctx, svc)
	}
	if url == "" {
		return nil, fmt.Errorf("url is required; call akemi_configure_target with base_url or pass url")
	}
	def := defaults(ctx, svc)
	// Use probe with security-header templates
	cfg := core.ProbeConfig{
		Threads:      1,
		Timeout:      firstPositive(def.Timeout, 10),
		UseTemplates: true,
		TemplateTags: []string{"headers", "misconfig"},
	}
	emitTargetConfig(ctx, svc, "akemi_check_headers", "Header audit", toolbridge.TargetConfig{
		Target:  url,
		Threads: intPtr(cfg.Threads),
		Timeout: intPtr(cfg.Timeout),
	})

	findings, err := svc.Prober.Probe(ctx, url, cfg)
	if err != nil {
		return nil, err
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Security Header Audit for %s: %d issues\n\n", url, len(findings)))
	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("  [%s] %s\n", f.Severity, f.Description))
	}

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleExploitLookup(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	// This requires the ExploitDB to be loaded, which is done via the exploit package directly
	// For MCP, we provide a simplified interface
	var sb strings.Builder
	sb.WriteString("ExploitDB Lookup:\n")
	sb.WriteString("Note: ExploitDB CSV must be loaded via the CLI with --exploitdb flag.\n")
	sb.WriteString("In server mode, use akemi serve --exploitdb /path/to/files_exploits.csv\n\n")

	banner := getString(args, "banner")
	port := getInt(args, "port", 0)

	if banner != "" {
		sb.WriteString(fmt.Sprintf("Searching for exploits matching banner: %s (port %d)\n", banner, port))
		// In a full implementation, this would call the ExploitLookup service
		sb.WriteString("(ExploitDB search requires CSV database to be loaded)\n")
	}

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleFuzz(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	url := getString(args, "url")
	wordlist := getString(args, "wordlist")

	// We call the legacy fuzz.RunFuzzer directly as core.Fuzzer isn't wired yet
	// In a full implementation, this would go through the Fuzzer interface
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Fuzzing %s with wordlist %s\n", url, wordlist))
	sb.WriteString("Note: Full fuzzing integration available in Phase 5.\n")
	sb.WriteString("Use CLI mode 'akemi fuzz' for interactive fuzzing.\n")

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleDork(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	query := getString(args, "query")
	engine := getString(args, "engine")
	if engine == "" {
		engine = "duckduckgo"
	}
	maxResults := getInt(args, "max_results", 20)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Dorking with %s: '%s' (max %d results)\n", engine, query, maxResults))

	// The dork functionality is in recon.PerformDork
	cfg := recon.DorkConfig{
		Query:      query,
		Engine:     engine,
		MaxResults: maxResults,
	}
	results, err := recon.PerformDork(cfg)
	if err != nil {
		return nil, err
	}

	sb.WriteString(fmt.Sprintf("\nFound %d results:\n", len(results)))
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("  - %s\n", r))
	}

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleGenerateReport(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	target := getString(args, "target")
	emitTargetConfig(ctx, svc, "akemi_generate_report", "Report generation", toolbridge.TargetConfig{Target: target})

	data := &core.ReportData{
		Target:    target,
		StartTime: time.Now().Add(-5 * time.Minute),
		EndTime:   time.Now(),
	}

	report, err := svc.Reporter.GenerateReport(ctx, data)
	if err != nil {
		return nil, err
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Report generated for %s:\n", target))
	sb.WriteString(fmt.Sprintf("  HTML: %s\n", report.HTMLPath))
	sb.WriteString(fmt.Sprintf("  JSON: %s\n", report.JSONPath))

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleGenerateGraph(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	target := getString(args, "target")
	emitTargetConfig(ctx, svc, "akemi_generate_graph", "Graph generation", toolbridge.TargetConfig{Target: target})

	data := &core.ReportData{
		Target:    target,
		StartTime: time.Now().Add(-5 * time.Minute),
		EndTime:   time.Now(),
	}

	graph, err := svc.Reporter.GenerateGraph(ctx, data)
	if err != nil {
		return nil, err
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Graph generated for %s:\n", target))
	sb.WriteString(fmt.Sprintf("  Nodes: %d | Edges: %d\n", len(graph.Nodes), len(graph.Edges)))

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleTechFingerprint(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	url := getString(args, "url")
	if url == "" {
		url = activeTargetBaseURL(ctx, svc)
	}
	if url == "" {
		return nil, fmt.Errorf("url is required; call akemi_configure_target with base_url or pass url")
	}
	def := defaults(ctx, svc)
	// Use vulnerability probe with network/tech-detect templates
	cfg := core.ProbeConfig{
		Threads:      1,
		Timeout:      firstPositive(def.Timeout, 10),
		UseTemplates: true,
		TemplateTags: []string{"tech", "detect"},
	}
	emitTargetConfig(ctx, svc, "akemi_tech_fingerprint", "Technology fingerprinting", toolbridge.TargetConfig{
		Target:  url,
		Threads: intPtr(cfg.Threads),
		Timeout: intPtr(cfg.Timeout),
	})

	findings, err := svc.Prober.Probe(ctx, url, cfg)
	if err != nil {
		return nil, err
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Technology Fingerprint for %s:\n\n", url))
	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("  %s\n", f.Description))
	}
	if len(findings) == 0 {
		sb.WriteString("  No specific technologies identified. Try crawling first.\n")
	}

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func handleAuthCapture(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	targetURL := getString(args, "url")
	username := getString(args, "username")
	password := getString(args, "password")
	if targetURL == "" {
		targetURL = activeTargetBaseURL(ctx, svc)
	}
	if targetURL == "" {
		return nil, fmt.Errorf("url is required; call akemi_configure_target with base_url or pass url")
	}
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("username and password are required")
	}

	emitTargetConfig(ctx, svc, "akemi_auth_capture", "DotHound auth capture", toolbridge.TargetConfig{Target: targetURL})

	session, err := dothound.CaptureLoginWithOptions(targetURL, username, password, dothound.StdinOptions{
		IncludeSecrets:      false,
		MaxBodyCaptureBytes: 64 * 1024,
	})
	if err != nil {
		return nil, err
	}

	targetID := ""
	if svc != nil && svc.Context != nil {
		target, _ := svc.Context.GetActiveTarget(ctx)
		if target == nil || strings.TrimSpace(target.ID) == "" {
			_ = svc.Context.SetTarget(ctx, engagement.TargetProfile{
				Name:    targetURL,
				BaseURL: normalizeURLArg(targetURL),
			})
			target, _ = svc.Context.GetActiveTarget(ctx)
		}
		if target != nil && targetMatchesURL(target, targetURL) {
			targetID = target.ID
		}
	}
	authSession := engagementAuthSessionFromDotHound(session, targetID)
	if svc != nil && svc.Context != nil {
		if err := svc.Context.SetAuthSession(ctx, authSession); err != nil {
			return nil, err
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Auth Capture for %s:\n", targetURL))
	sb.WriteString(fmt.Sprintf("  Username: %s\n", username))
	if authSession.AuthSuccess {
		sb.WriteString("  Status: authenticated\n")
	} else {
		sb.WriteString("  Status: captured, but login success was not confirmed\n")
	}
	sb.WriteString(fmt.Sprintf("  Session cookies: %d captured and loaded for API Hunter\n", len(authSession.Cookies)))
	sb.WriteString(fmt.Sprintf("  CSRF tokens: %d\n", len(authSession.CSRFTokens)))
	if authSession.WorkflowPath != "" {
		sb.WriteString(fmt.Sprintf("  Workflow JSON: %s\n", authSession.WorkflowPath))
	}
	if authSession.HTMLReportPath != "" {
		sb.WriteString(fmt.Sprintf("  Workflow HTML: %s\n", authSession.HTMLReportPath))
	}

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

// =============================================================================
// Argument Helpers
// =============================================================================

func getString(args map[string]interface{}, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func stringSliceArg(value interface{}) []string {
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{strings.TrimSpace(v)}
	default:
		return nil
	}
}

func splitCookieHeaderValue(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ";")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func activeAuthCookies(ctx context.Context, svc *Services, targetURL string) []string {
	if svc != nil && svc.Context != nil {
		session, err := svc.Context.GetAuthSession(ctx)
		if err == nil && session != nil && len(session.Cookies) > 0 && authSessionMatchesTarget(ctx, svc, session, targetURL) {
			return append([]string(nil), session.Cookies...)
		}
	}
	return nil
}

func activeAuthCookieSource(ctx context.Context, svc *Services, targetURL string) string {
	if svc != nil && svc.Context != nil {
		session, err := svc.Context.GetAuthSession(ctx)
		if err == nil && session != nil && len(session.Cookies) > 0 && authSessionMatchesTarget(ctx, svc, session, targetURL) {
			if strings.TrimSpace(session.Source) != "" {
				return session.Source
			}
			return "MCP auth session"
		}
	}
	return "none"
}

func authSessionMatchesTarget(ctx context.Context, svc *Services, session *engagement.AuthSession, targetURL string) bool {
	if session == nil {
		return false
	}
	if svc != nil && svc.Context != nil {
		target, err := svc.Context.GetActiveTarget(ctx)
		if err == nil && target != nil && strings.TrimSpace(target.ID) != "" && strings.TrimSpace(session.TargetID) != "" {
			if target.ID == session.TargetID {
				return true
			}
		}
	}
	sessionHost := hostForCookieTarget(session.TargetURL)
	targetHost := hostForCookieTarget(targetURL)
	return sessionHost != "" && targetHost != "" && sessionHost == targetHost
}

func targetMatchesURL(target *engagement.TargetProfile, targetURL string) bool {
	if target == nil {
		return false
	}
	targetHost := hostForCookieTarget(targetURL)
	if targetHost == "" {
		return false
	}
	if hostForCookieTarget(target.BaseURL) == targetHost {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(target.Domain), targetHost) {
		return true
	}
	for _, host := range target.Hosts {
		if strings.EqualFold(strings.TrimSpace(host), targetHost) {
			return true
		}
	}
	return false
}

func hostForCookieTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = core.EnsureProtocol(raw)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

func engagementAuthSessionFromDotHound(session *dothound.AuthSession, targetID string) engagement.AuthSession {
	if session == nil {
		return engagement.AuthSession{TargetID: targetID, Source: "dothound", CapturedAt: time.Now()}
	}
	return engagement.AuthSession{
		TargetID:       targetID,
		TargetURL:      session.TargetURL,
		Source:         "dothound",
		AuthSuccess:    session.AuthSuccess,
		Cookies:        append([]string(nil), session.Cookies...),
		CSRFTokens:     append([]string(nil), session.CSRFTokens...),
		RedirectChain:  append([]string(nil), session.RedirectChain...),
		CapturedAt:     session.CapturedAt,
		WorkflowPath:   session.WorkflowPath,
		HTMLReportPath: session.HTMLReportPath,
	}
}

func getInt(args map[string]interface{}, key string, defaultVal int) int {
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return defaultVal
}

func getFloat64(args map[string]interface{}, key string, defaultVal float64) float64 {
	if v, ok := args[key]; ok {
		if n, ok := v.(float64); ok {
			return n
		}
	}
	return defaultVal
}

func getBool(args map[string]interface{}, key string) bool {
	if v, ok := args[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "..." + s[len(s)-4:]
}
