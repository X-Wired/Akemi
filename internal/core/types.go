package core

import (
	"net/http"
	"strings"

	proxy "Akemi/internal/platform/proxy"
)

// ====================================================
// Fuzzer Types
// ====================================================

type FuzzConfig struct {
	URL         string
	Method      string
	Data        string
	PayloadFile string
	OutputFile  string
	Repeats     int
	Timeout     int
	Concurrency int
}

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

// ====================================================
// Discovery Types
// ====================================================

type DiscoveryRequest struct {
	URL   string `json:"url"`
	Depth int    `json:"depth"`
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

// CreateHTTPClient is a shared helper
func CreateHTTPClient(timeout int) *http.Client {
	return proxy.CreateHTTPClientWithOptions(timeout, proxy.HTTPClientOptions{})
}
