package core

import (
	"net/http"
	"strings"
	"sync"

	proxy "Akemi/internal/platform/proxy"
)

// ====================================================
// Fuzzer Types — canonical definitions in interfaces.go
// FuzzConfig and FuzzResult are defined in interfaces.go
// ====================================================

type FuzzRequest struct {
	URL         string `json:"url"`
	Method      string `json:"method"`
	Data        string `json:"data"`
	PayloadFile string `json:"payload_file"`
	OutputFile  string `json:"output_file"`
	Repeats     int    `json:"repeats"`
	Timeout     int    `json:"timeout"`
	Concurrency int    `json:"concurrency"`
}

// ====================================================
// Discovery Types
// ====================================================

type DiscoveryRequest struct {
	URL   string `json:"url"`
	Depth int    `json:"depth"`
}

const (
	MinCrawlDepth       = 1
	MaxCrawlDepth       = 7
	UnlimitedCrawlDepth = 7
)

// NormalizeCrawlDepth clamps operator and tool crawl depth to Akemi's managed
// range. Depth 7 intentionally means unlimited URL budget.
func NormalizeCrawlDepth(depth int) int {
	if depth < MinCrawlDepth {
		return MinCrawlDepth
	}
	if depth > MaxCrawlDepth {
		return MaxCrawlDepth
	}
	return depth
}

// CrawlURLLimitForDepth maps managed crawl depth to a URL budget. A return
// value of 0 means unlimited.
func CrawlURLLimitForDepth(depth int) int {
	depth = NormalizeCrawlDepth(depth)
	if depth >= UnlimitedCrawlDepth {
		return 0
	}
	return depth * 1000
}

type ParamsRequest struct {
	URL          string   `json:"url"`
	Depth        int      `json:"depth"`
	MineJS       bool     `json:"mine_js"`
	MineForms    bool     `json:"mine_forms"`
	MineJSON     bool     `json:"mine_json"`
	MinePath     bool     `json:"mine_path"`
	ActiveBrute  bool     `json:"active_brute"`
	Keywords     []string `json:"keywords"`
	MineKeywords bool     `json:"mine_keywords"`
}

type DorkRequest struct {
	Query      string `json:"query"`
	Engine     string `json:"engine"`
	MaxResults int    `json:"max_results"`
}

type JSRequest struct {
	URL string `json:"url"`
}

// ====================================================
// Vuln Probe Types
// ====================================================

type ProbeRequest struct {
	URL          string   `json:"url"`
	Threads      int      `json:"threads"`
	Timeout      int      `json:"timeout"`
	UseOOB       bool     `json:"use_oob"`
	UseTemplates bool     `json:"use_templates"`
	TemplateDir  string   `json:"template_dir,omitempty"`
	TemplateTags []string `json:"template_tags,omitempty"`
	TemplateIDs  []string `json:"template_ids,omitempty"`
}

type SubdomainRequest struct {
	Domain       string `json:"domain"`
	WordlistFile string `json:"wordlist_file"`
	Threads      int    `json:"threads"`
	Timeout      int    `json:"timeout"`
	UseCrtSh     bool   `json:"use_crtsh"`
	CheckAlive   bool   `json:"check_alive"`
	Permutate    bool   `json:"permutate"`
}

type OOBStartRequest struct {
	Host     string `json:"host"`
	HTTPPort int    `json:"http_port"`
	DNSPort  int    `json:"dns_port"`
}

type PortScanRequest struct {
	Targets   string  `json:"targets"`
	Ports     string  `json:"ports"`
	Rate      float64 `json:"rate"`
	Syn       bool    `json:"syn"`
	Retries   int     `json:"retries"`
	Randomize bool    `json:"randomize"`
	Timeout   int     `json:"timeout"`
	Threads   int     `json:"threads"`
	ProbeDir  string  `json:"probe_dir,omitempty"`
}

// FullScanRequest is used by the API for comprehensive scans
type FullScanRequest struct {
	URL        string `json:"url"`
	Crawl      bool   `json:"crawl"`
	CrawlDepth int    `json:"crawl_depth"`
	Scrape     bool   `json:"scrape"`
	Params     bool   `json:"params"`
	JS         bool   `json:"js"`
	VulnCheck  bool   `json:"vuln_check"`
}

// EnsureProtocol is a shared helper
func EnsureProtocol(url string) string {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return "http://" + url
	}
	return url
}

// Contains checks if a string slice contains a string
func Contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// Default session cookies injected into every HTTP client created via
// CreateHTTPClient when SetDefaultCookies has been called.
var (
	defaultCookies   []string
	defaultCookiesMu sync.RWMutex
)

// SetDefaultCookies stores session cookies that will be automatically
// injected into every HTTP client created via CreateHTTPClient.
// Pass nil to clear.
func SetDefaultCookies(cookies []string) {
	defaultCookiesMu.Lock()
	defer defaultCookiesMu.Unlock()
	if cookies == nil {
		defaultCookies = nil
		return
	}
	defaultCookies = make([]string, len(cookies))
	copy(defaultCookies, cookies)
}

// ClearDefaultCookies removes any injected session cookies.
func ClearDefaultCookies() {
	SetDefaultCookies(nil)
}

// GetDefaultCookies returns the currently stored default cookies (may be nil).
func GetDefaultCookies() []string {
	defaultCookiesMu.RLock()
	defer defaultCookiesMu.RUnlock()
	if defaultCookies == nil {
		return nil
	}
	out := make([]string, len(defaultCookies))
	copy(out, defaultCookies)
	return out
}

// CreateHTTPClient is a shared helper. If default session cookies have been
// set via SetDefaultCookies, they are automatically injected into every request.
func CreateHTTPClient(timeout int) *http.Client {
	defaultCookiesMu.RLock()
	cookies := defaultCookies
	defaultCookiesMu.RUnlock()

	return CreateHTTPClientWithCookies(timeout, cookies)
}

// CreateHTTPClientWithCookies creates a client that injects the provided raw
// Set-Cookie/Cookie values without mutating the process-wide default cookies.
func CreateHTTPClientWithCookies(timeout int, cookies []string) *http.Client {
	if len(cookies) == 0 {
		return proxy.CreateHTTPClientWithOptions(timeout, proxy.HTTPClientOptions{})
	}

	cookieHeader := joinCookies(cookies)
	return proxy.CreateHTTPClientWithOptions(timeout, proxy.HTTPClientOptions{
		DefaultHeaders: map[string]string{
			"Cookie": cookieHeader,
		},
	})
}

// joinCookies formats raw Set-Cookie strings as a single Cookie header value.
func joinCookies(cookies []string) string {
	var parts []string
	for _, c := range cookies {
		if idx := strings.Index(c, ";"); idx >= 0 {
			parts = append(parts, strings.TrimSpace(c[:idx]))
		} else {
			parts = append(parts, strings.TrimSpace(c))
		}
	}
	return strings.Join(parts, "; ")
}
