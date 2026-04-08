package recon

import (
	core "Akemi/internal/core"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// =============================================================
// ── ORIGINAL DATA STRUCTURES (unchanged) ─────────────────────
// =============================================================

// ScrapeResult holds details from a scraped page.
type ScrapeResult struct {
	Title            string
	Description      string
	MetaTags         map[string]string
	Links            []string
	Forms            []FormInfo
	Comments         []string
	VulnerableParams map[string][]string // Query parameters flagged as suspicious.
	KeywordMatches   map[string][]string // keyword -> list of matching lines/contexts
}

// FormInfo holds details about an HTML form.
type FormInfo struct {
	Action string
	Method string
	Inputs []InputField
}

// InputField holds details about an HTML form input.
type InputField struct {
	Name       string
	Type       string
	Value      string
	Vulnerable bool // Marked true if a potential vulnerability is detected.
}

// ParamDetail holds aggregated parameter values along with their source URLs.
// Kept for backward compatibility — main.go --params flag still uses this.
type ParamDetail struct {
	Values  []string
	Sources []string
}

// =============================================================
// ── ENHANCED PARAM MINING DATA STRUCTURES ────────────────────
// =============================================================

// ParamSource describes where a parameter was found.
type ParamSource string

const (
	SourceURLQuery    ParamSource = "url_query"
	SourceJSFile      ParamSource = "js_file"
	SourceFormInput   ParamSource = "form_input"
	SourceJSONBody    ParamSource = "json_response"
	SourcePathParam   ParamSource = "path_param"
	SourceActiveBrute ParamSource = "active_brute"
)

// ParamType is an inferred data type based on observed values.
type ParamType string

const (
	TypeString  ParamType = "string"
	TypeInt     ParamType = "int"
	TypeBool    ParamType = "bool"
	TypeUUID    ParamType = "uuid"
	TypeJWT     ParamType = "jwt"
	TypeEmail   ParamType = "email"
	TypeUnknown ParamType = "unknown"
)

// RichParamDetail extends ParamDetail with source type tracking and type inference.
type RichParamDetail struct {
	Values       []string
	Sources      []string      // URLs where this param was observed
	SourceTypes  []ParamSource // How it was found (deduped)
	InferredType ParamType     // Best guess at value type
	Suspicious   bool          // Matches the suspicious regex
}

// CrawlFinding preserves the URL and HTTP response status observed during crawling.
type CrawlFinding struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Status     string `json:"status"`
}

// MiningConfig holds all options for the enhanced param miner.
type MiningConfig struct {
	Depth             int
	Threads           int
	Timeout           int
	SuspiciousPattern *regexp.Regexp
	MineJS            bool     // Extract params from JS files and inline scripts
	MineForms         bool     // Extract input names from HTML forms
	MineJSONResponses bool     // Recursively extract keys from JSON API responses
	MinePathParams    bool     // Detect /:id, /{param} path segments
	ActiveBrute       bool     // Arjun-style: probe wordlist params and diff responses
	ActiveWordlist    []string // Wordlist for active brute (uses built-in if nil)
	ActiveChunkSize   int      // How many params to test per request (default 15)
	Keywords          []string // Keywords to search for in content
	MineKeywords      bool     // Enable keyword discovery
}

// DiscoveryResult aggregates all findings from a discovery run.
type DiscoveryResult struct {
	Params          map[string]RichParamDetail
	KeywordMatches  map[string][]string
	CrawlDetails    []CrawlFinding
	SecretFindings  []SecretFinding
	ConfigResources []string
	APIEndpoints    []APIEndpointFinding
	APISpecs        []APISpecFinding
}

// DorkConfig holds parameters for search engine dorking.
type DorkConfig struct {
	Query      string
	Engine     string // "google", "duckduckgo", "bing"
	MaxResults int
	Timeout    int
}

// DorkResult holds URLs found via dorking.
type DorkResult struct {
	URLs []string
}

// ActiveBruteConfig holds per-request options for active param brute-force.
type ActiveBruteConfig struct {
	BaseURL   string
	Threads   int
	Timeout   int
	ChunkSize int
	Wordlist  []string
}

// =============================================================
// ── ORIGINAL HELPER FUNCTIONS (unchanged) ────────────────────
// =============================================================

// getAttrs extracts attributes from an HTML node into a map with lowercase keys.
func getAttrs(n *html.Node) map[string]string {
	attrs := make(map[string]string)
	for _, a := range n.Attr {
		attrs[strings.ToLower(a.Key)] = a.Val
	}
	return attrs
}

// ExtractLinks parses the HTML document from body and returns all links (absolute URLs) found in <a> tags.
func ExtractLinks(pageURL string, body io.Reader) ([]string, error) {
	var links []string
	doc, err := html.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("error parsing HTML: %w", err)
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			attrs := getAttrs(n)
			if href, ok := attrs["href"]; ok {
				link := strings.TrimSpace(href)
				if link != "" {
					if parsedLink, err := url.Parse(link); err == nil {
						if base, err := url.Parse(pageURL); err == nil {
							fullURL := base.ResolveReference(parsedLink)
							links = append(links, fullURL.String())
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return links, nil
}

// Crawl recursively visits URLs (within the same host) up to maxDepth using controlled concurrency.
func Crawl(startURL string, maxDepth int) ([]string, error) {
	details, err := CrawlDetailed(startURL, maxDepth)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(details))
	for _, item := range details {
		result = append(result, item.URL)
	}
	return result, nil
}

// CrawlDetailed recursively visits URLs and preserves the response status for reports and terminal output.
func CrawlDetailed(startURL string, maxDepth int) ([]CrawlFinding, error) {
	client := core.CreateHTTPClient(10)
	return crawlDetailedWithClient(startURL, maxDepth, client)
}

func crawlDetailedWithClient(startURL string, maxDepth int, client *http.Client) ([]CrawlFinding, error) {
	startURL = core.EnsureProtocol(startURL)
	discovered := make(map[string]bool)
	details := make(map[string]CrawlFinding)
	var mu sync.Mutex
	var wg sync.WaitGroup

	maxConcurrent := 10
	semaphore := make(chan struct{}, maxConcurrent)
	baseURL, err := url.Parse(startURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing startURL %s: %w", startURL, err)
	}

	recordStatus := func(u string, statusCode int, status string) {
		mu.Lock()
		details[u] = CrawlFinding{
			URL:        u,
			StatusCode: statusCode,
			Status:     normalizeHTTPStatus(statusCode, status),
		}
		mu.Unlock()
	}

	var crawlFunc func(string, int)
	crawlFunc = func(u string, depth int) {
		defer wg.Done()
		if depth > maxDepth {
			return
		}
		mu.Lock()
		if discovered[u] {
			mu.Unlock()
			return
		}
		discovered[u] = true
		if _, ok := details[u]; !ok {
			details[u] = CrawlFinding{URL: u, StatusCode: 0, Status: "PENDING"}
		}
		mu.Unlock()

		semaphore <- struct{}{}
		defer func() { <-semaphore }()

		// Simple rate limiting.
		time.Sleep(500 * time.Millisecond)

		resp, err := client.Get(u)
		if err != nil {
			log.Printf("Error fetching URL %s: %v", u, err)
			recordStatus(u, 0, "ERROR")
			return
		}
		defer resp.Body.Close()
		recordStatus(u, resp.StatusCode, resp.Status)

		if resp.StatusCode != http.StatusOK {
			log.Printf("HTTP error for %s: %s", u, resp.Status)
			return
		}

		links, err := ExtractLinks(u, resp.Body)
		if err != nil {
			log.Printf("Error extracting links from %s: %v", u, err)
			return
		}

		for _, link := range links {
			if linkURL, err := url.Parse(link); err == nil {
				// Only follow links within the same host.
				if linkURL.Host == baseURL.Host {
					mu.Lock()
					if !discovered[link] {
						wg.Add(1)
						go crawlFunc(link, depth+1)
					}
					mu.Unlock()
				}
			}
		}
	}

	for _, seed := range collectSeedURLs(startURL, client) {
		wg.Add(1)
		go crawlFunc(seed, 0)
	}
	wg.Wait()

	result := make([]CrawlFinding, 0, len(discovered))
	for u := range discovered {
		if detail, ok := details[u]; ok {
			result = append(result, detail)
			continue
		}
		result = append(result, CrawlFinding{URL: u, StatusCode: 0, Status: "UNKNOWN"})
	}
	sort.Slice(result, func(i, j int) bool {
		return crawlFindingLess(result[i], result[j])
	})
	return result, nil
}

// ScrapePage retrieves a page, parses the HTML, extracts its data, and detects potential vulnerabilities.
func ScrapePage(pageURL string, keywords []string) (*ScrapeResult, error) {
	pageURL = core.EnsureProtocol(pageURL)
	client := core.CreateHTTPClient(10)
	resp, err := client.Get(pageURL)
	if err != nil {
		return nil, fmt.Errorf("error fetching page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status not OK for %s: %s", pageURL, resp.Status)
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error parsing HTML: %w", err)
	}

	result := &ScrapeResult{
		MetaTags:         make(map[string]string),
		VulnerableParams: make(map[string][]string),
		KeywordMatches:   make(map[string][]string),
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)
	if len(keywords) > 0 {
		result.KeywordMatches = ScanForKeywords(bodyStr, keywords)
	}

	// Use a fixed regex for detecting suspicious parameters.
	suspiciousRegex := regexp.MustCompile(`(?i)(id|page|user|token|key|pass|debug|cmd|exec)`)
	if parsedURL, err := url.Parse(pageURL); err == nil {
		q := parsedURL.Query()
		for key, values := range q {
			if suspiciousRegex.MatchString(key) {
				result.VulnerableParams[key] = values
			}
		}
	}

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		switch n.Type {
		case html.ElementNode:
			switch n.Data {
			case "title":
				if n.FirstChild != nil {
					result.Title = n.FirstChild.Data
				}
			case "meta":
				attrs := getAttrs(n)
				if name, ok := attrs["name"]; ok {
					result.MetaTags[name] = attrs["content"]
					if strings.ToLower(name) == "description" && result.Description == "" {
						result.Description = attrs["content"]
					}
				}
			case "a":
				attrs := getAttrs(n)
				if href, ok := attrs["href"]; ok {
					trimmed := strings.TrimSpace(href)
					if trimmed != "" {
						result.Links = append(result.Links, trimmed)
					}
				}
			case "form":
				attrs := getAttrs(n)
				form := FormInfo{
					Action: attrs["action"],
					Method: attrs["method"],
				}
				var processInputs func(*html.Node)
				processInputs = func(node *html.Node) {
					if node.Type == html.ElementNode && node.Data == "input" {
						inputAttrs := getAttrs(node)
						input := InputField{
							Name:  inputAttrs["name"],
							Type:  inputAttrs["type"],
							Value: inputAttrs["value"],
						}
						if strings.ToLower(input.Type) == "file" ||
							strings.ToLower(input.Type) == "password" ||
							suspiciousRegex.MatchString(input.Name) {
							input.Vulnerable = true
						}
						form.Inputs = append(form.Inputs, input)
					}
					for c := node.FirstChild; c != nil; c = c.NextSibling {
						processInputs(c)
					}
				}
				processInputs(n)
				result.Forms = append(result.Forms, form)
			}
		case html.CommentNode:
			result.Comments = append(result.Comments, n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(doc)
	return result, nil
}

// contains checks if a slice contains a given string.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// =============================================================
// ── ORIGINAL DiscoverParams (kept as backward-compat wrapper) ─
// =============================================================
// main.go calls this with --params flag. It now delegates to
// EnhancedDiscoverParams and converts RichParamDetail → ParamDetail
// so nothing in main.go needs to change.

func DiscoverParams(rawURL string, depth int, suspiciousPattern *regexp.Regexp) (map[string]ParamDetail, error) {
	cfg := MiningConfig{
		Depth:             depth,
		Threads:           10,
		Timeout:           10,
		SuspiciousPattern: suspiciousPattern,
		MineJS:            true,
		MineForms:         true,
		MineJSONResponses: true,
		MinePathParams:    true,
		ActiveBrute:       false, // Off by default in legacy mode
	}

	rich, err := EnhancedDiscoverParams(rawURL, cfg)
	if err != nil {
		return nil, err
	}

	// Convert RichParamDetail → ParamDetail for backward compatibility
	result := make(map[string]ParamDetail)
	for k, v := range rich.Params {
		result[k] = ParamDetail{
			Values:  v.Values,
			Sources: v.Sources,
		}
	}
	return result, nil
}

// =============================================================
// ── JAVASCRIPT PARAM EXTRACTION ──────────────────────────────
// =============================================================

// JS patterns that reveal parameter names in various coding styles.
var jsParamPatterns = []*regexp.Regexp{
	// ?param= and &param= in strings
	regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})=`),
	// { params: { key: val } } — axios/jQuery style
	regexp.MustCompile(`params\s*:\s*\{([^}]{1,300})\}`),
	// data: { key: val } — form post / ajax
	regexp.MustCompile(`data\s*:\s*\{([^}]{1,300})\}`),
	// URLSearchParams({ key: val })
	regexp.MustCompile(`URLSearchParams\s*\(\s*\{([^}]{1,300})\}`),
	// .append('key', val)
	regexp.MustCompile(`\.append\s*\(\s*['"]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})['"]\s*,`),
	// .set('key', val)
	regexp.MustCompile(`\.set\s*\(\s*['"]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})['"]\s*,`),
	// getParameter('key') / getParam('key') / .get('key')
	regexp.MustCompile(`(?:getParam(?:eter)?|\.get)\s*\(\s*['"]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})['"]\s*\)`),
	// Template literals: `${paramName}`
	regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]{1,40})\}`),
	// name: 'param' inside object definitions
	regexp.MustCompile(`name\s*:\s*['"]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})['"]`),
	// action/href/url: '/endpoint?param='
	regexp.MustCompile(`(?:action|href|src|url)\s*[=:]\s*['"][^'"]*[?&]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})=`),
}

// objectKeyRegex extracts keys from JS object literals like { key: val, key2: val2 }.
var objectKeyRegex = regexp.MustCompile(`['"]?([a-zA-Z_][a-zA-Z0-9_\-]{1,40})['"]?\s*:`)

// jsKeywords is the set of JS tokens that should never be treated as param names.
var jsKeywords = map[string]bool{
	"function": true, "return": true, "var": true, "let": true, "const": true,
	"if": true, "else": true, "for": true, "while": true, "class": true,
	"this": true, "true": true, "false": true, "null": true, "undefined": true,
	"new": true, "delete": true, "typeof": true, "import": true, "export": true,
	"default": true, "async": true, "await": true, "try": true, "catch": true,
	"switch": true, "case": true, "break": true, "continue": true, "throw": true,
	"type": true, "interface": true, "extends": true, "implements": true,
	"then": true, "error": true, "resolve": true, "reject": true,
	"response": true, "request": true, "result": true, "data": true, "options": true,
	"config": true, "event": true, "target": true, "value": true, "index": true,
	"length": true, "push": true, "pop": true, "map": true, "filter": true,
	"forEach": true, "reduce": true, "split": true, "join": true, "trim": true,
}

// extractParamsFromJS runs all patterns against raw JS content and returns unique param names.
func extractParamsFromJS(content string, sourceURL string) map[string]RichParamDetail {
	found := make(map[string]RichParamDetail)
	seen := make(map[string]bool)

	addParam := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] || len(name) > 50 || jsKeywords[name] {
			return
		}
		seen[name] = true
		found[name] = RichParamDetail{
			Sources:      []string{sourceURL},
			SourceTypes:  []ParamSource{SourceJSFile},
			InferredType: TypeUnknown,
		}
	}

	// Pattern 0: direct ?param= and &param= in strings
	for _, match := range jsParamPatterns[0].FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			addParam(match[1])
		}
	}

	// Patterns 1–2: extract object keys from { params: {...} } and { data: {...} }
	for _, objPattern := range jsParamPatterns[1:3] {
		for _, match := range objPattern.FindAllStringSubmatch(content, -1) {
			if len(match) > 1 {
				for _, keyMatch := range objectKeyRegex.FindAllStringSubmatch(match[1], -1) {
					if len(keyMatch) > 1 {
						addParam(keyMatch[1])
					}
				}
			}
		}
	}

	// Patterns 3–9: single-capture patterns
	for _, p := range jsParamPatterns[3:] {
		for _, match := range p.FindAllStringSubmatch(content, -1) {
			if len(match) > 1 {
				addParam(match[1])
			}
		}
	}

	return found
}

// mineJSFilesFromPage fetches the page, finds all <script src="">, fetches each JS file,
// and also scans inline <script> blocks. Returns all discovered param names.
func mineJSFilesFromPage(pageURL string, client *http.Client) map[string]RichParamDetail {
	result := make(map[string]RichParamDetail)

	resp, err := client.Get(pageURL)
	if err != nil {
		log.Printf("[ParamMiner] Error fetching page for JS mining %s: %v", pageURL, err)
		return result
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return result
	}
	bodyStr := string(bodyBytes)

	// Scan inline <script> blocks
	inlineScriptRegex := regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`)
	for _, match := range inlineScriptRegex.FindAllStringSubmatch(bodyStr, -1) {
		if len(match) > 1 {
			for k, v := range extractParamsFromJS(match[1], pageURL+"#inline") {
				mergeRichParam(result, k, v)
			}
		}
	}

	// Parse HTML for external <script src=""> tags
	doc, err := html.Parse(strings.NewReader(bodyStr))
	if err != nil {
		return result
	}

	base, _ := url.Parse(pageURL)
	var scriptURLs []string

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			attrs := getAttrs(n)
			if src, ok := attrs["src"]; ok && strings.TrimSpace(src) != "" {
				if parsed, err := url.Parse(strings.TrimSpace(src)); err == nil {
					scriptURLs = append(scriptURLs, base.ResolveReference(parsed).String())
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	// Fetch and analyze each external JS file concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 5)

	for _, jsURL := range scriptURLs {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			jsResp, err := client.Get(u)
			if err != nil {
				return
			}
			defer jsResp.Body.Close()

			jsBytes, err := io.ReadAll(jsResp.Body)
			if err != nil {
				return
			}

			params := extractParamsFromJS(string(jsBytes), u)

			mu.Lock()
			for k, v := range params {
				mergeRichParam(result, k, v)
			}
			mu.Unlock()
		}(jsURL)
	}

	wg.Wait()
	return result
}

// =============================================================
// ── FORM INPUT EXTRACTION ────────────────────────────────────
// =============================================================

// mineFormInputs parses HTML and extracts all input/textarea/select name attributes.
func mineFormInputs(pageURL string, body string) map[string]RichParamDetail {
	result := make(map[string]RichParamDetail)

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return result
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input", "textarea", "select", "button":
				attrs := getAttrs(n)
				name, ok := attrs["name"]
				if !ok || strings.TrimSpace(name) == "" {
					break
				}
				inputType := attrs["type"]
				// Skip non-data inputs
				if inputType == "submit" || inputType == "reset" ||
					inputType == "button" || inputType == "image" {
					break
				}
				detail := RichParamDetail{
					Sources:      []string{pageURL},
					SourceTypes:  []ParamSource{SourceFormInput},
					InferredType: inferTypeFromInput(inputType, attrs["value"]),
				}
				if attrs["value"] != "" {
					detail.Values = []string{attrs["value"]}
				}
				mergeRichParam(result, name, detail)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return result
}

// =============================================================
// ── JSON RESPONSE KEY EXTRACTION ─────────────────────────────
// =============================================================

// mineJSONResponse recursively extracts all keys from a JSON response body.
func mineJSONResponse(sourceURL string, body []byte) map[string]RichParamDetail {
	result := make(map[string]RichParamDetail)

	var parsed interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return result
	}

	var extractKeys func(v interface{}, depth int)
	extractKeys = func(v interface{}, depth int) {
		if depth > 8 {
			return
		}
		switch obj := v.(type) {
		case map[string]interface{}:
			for key, val := range obj {
				if strings.TrimSpace(key) == "" || len(key) > 60 {
					continue
				}
				detail := RichParamDetail{
					Sources:      []string{sourceURL},
					SourceTypes:  []ParamSource{SourceJSONBody},
					InferredType: inferTypeFromJSONValue(val),
				}
				if strVal, ok := val.(string); ok && strVal != "" {
					detail.Values = []string{strVal}
				}
				mergeRichParam(result, key, detail)
				extractKeys(val, depth+1)
			}
		case []interface{}:
			for _, item := range obj {
				extractKeys(item, depth+1)
			}
		}
	}
	extractKeys(parsed, 0)
	return result
}

// =============================================================
// ── PATH PARAMETER DETECTION ─────────────────────────────────
// =============================================================

// pathParamRegex matches explicit path param patterns: /:id, /{param}, /[param]
var pathParamRegex = regexp.MustCompile(`/[:{[]([a-zA-Z_][a-zA-Z0-9_\-]{0,40})[}\]:]?(?:/|$)`)

// numericSegmentRegex matches URL paths with numeric segments: /users/42
var numericSegmentRegex = regexp.MustCompile(`/([a-zA-Z_][a-zA-Z0-9_\-]{1,30})/(\d+)(?:/([a-zA-Z_][a-zA-Z0-9_\-]{0,30}))?`)

// minePathParams scans a list of crawled URLs for path parameter patterns.
func minePathParams(urls []string) map[string]RichParamDetail {
	result := make(map[string]RichParamDetail)

	for _, rawURL := range urls {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		path := parsed.Path

		// Pattern 1: explicit /:param or /{param} markers
		for _, match := range pathParamRegex.FindAllStringSubmatch(path, -1) {
			if len(match) > 1 {
				detail := RichParamDetail{
					Sources:      []string{rawURL},
					SourceTypes:  []ParamSource{SourcePathParam},
					InferredType: TypeUnknown,
				}
				mergeRichParam(result, match[1], detail)
			}
		}

		// Pattern 2: infer param name from position — /resource/{number}
		// e.g. /users/42 → param name "user_id"
		for _, match := range numericSegmentRegex.FindAllStringSubmatch(path, -1) {
			if len(match) > 2 {
				paramName := strings.TrimRight(match[1], "s") + "_id" // users → user_id
				detail := RichParamDetail{
					Sources:      []string{rawURL},
					SourceTypes:  []ParamSource{SourcePathParam},
					Values:       []string{match[2]},
					InferredType: TypeInt,
				}
				mergeRichParam(result, paramName, detail)
			}
		}
	}

	return result
}

// =============================================================
// ── ACTIVE PARAMETER BRUTE-FORCE (Arjun-style) ───────────────
// =============================================================

// builtinParamWordlist is the default wordlist used when no file is provided.
var builtinParamWordlist = []string{
	// Auth / session
	"token", "access_token", "refresh_token", "api_key", "apikey", "key", "secret",
	"auth", "authorization", "session", "session_id", "sid", "csrf", "csrf_token",
	"jwt", "bearer", "oauth_token",
	// Identity
	"id", "user_id", "uid", "username", "user", "email", "account", "account_id",
	"profile_id", "member_id", "client_id", "customer_id",
	// Navigation
	"page", "page_size", "limit", "offset", "per_page", "count", "size", "cursor",
	"next", "prev", "after", "before", "from", "to", "start", "end",
	// Content
	"q", "query", "search", "filter", "sort", "order", "orderby", "order_by",
	"category", "tag", "type", "status", "state", "format", "lang", "locale",
	// Actions
	"action", "cmd", "command", "exec", "run", "op", "operation", "method",
	"callback", "redirect", "url", "return", "return_url", "next_url",
	// Debug / internal
	"debug", "test", "dev", "admin", "internal", "verbose", "trace",
	// Identifiers
	"ref", "reference", "source", "src", "dest", "destination", "target",
	"name", "title", "slug", "path", "file", "filename", "dir", "folder",
	// Version / config
	"version", "v", "api_version", "include", "exclude", "fields", "expand",
	"embed", "with", "populate",
	// Numbers
	"amount", "price", "quantity", "total", "score", "rank", "weight",
	// Date / time
	"date", "time", "timestamp", "created_at", "updated_at", "expires",
	"start_date", "end_date",
}

// activeProbeParams sends requests with chunked param sets and detects which
// params cause a behavioral difference in the response (status, size, or canary reflection).
func activeProbeParams(cfg ActiveBruteConfig) (map[string]RichParamDetail, error) {
	result := make(map[string]RichParamDetail)

	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = 15
	}
	if cfg.Threads == 0 {
		cfg.Threads = 5
	}
	wordlist := cfg.Wordlist
	if len(wordlist) == 0 {
		wordlist = builtinParamWordlist
	}

	client := core.CreateHTTPClient(cfg.Timeout)

	// Step 1: establish a baseline response with no extra params
	baseResp, err := client.Get(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("error fetching baseline: %w", err)
	}
	baseBody, _ := io.ReadAll(baseResp.Body)
	baseResp.Body.Close()
	baseSize := len(baseBody)
	baseStatus := baseResp.StatusCode

	fmt.Printf("[ActiveBrute] Baseline: HTTP %d, %d bytes\n", baseStatus, baseSize)
	fmt.Printf("[ActiveBrute] Testing %d params in chunks of %d\n", len(wordlist), cfg.ChunkSize)

	// Step 2: chunk the wordlist and probe each chunk concurrently
	chunks := chunkSlice(wordlist, cfg.ChunkSize)

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)

	for _, chunk := range chunks {
		wg.Add(1)
		go func(params []string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Build URL with all params in this chunk set to a unique canary value
			testURL, _ := url.Parse(cfg.BaseURL)
			q := testURL.Query()
			const canary = "alemi1337"
			for _, p := range params {
				q.Set(p, canary)
			}
			testURL.RawQuery = q.Encode()

			resp, err := client.Get(testURL.String())
			if err != nil {
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			// If the chunk triggered a diff, drill down to isolate each param
			if isDifferentResponse(baseStatus, baseSize, string(baseBody), resp.StatusCode, len(body), string(body)) {
				for _, param := range params {
					singleURL, _ := url.Parse(cfg.BaseURL)
					sq := singleURL.Query()
					sq.Set(param, canary)
					singleURL.RawQuery = sq.Encode()

					sResp, err := client.Get(singleURL.String())
					if err != nil {
						continue
					}
					sBody, _ := io.ReadAll(sResp.Body)
					sResp.Body.Close()

					if isDifferentResponse(baseStatus, baseSize, string(baseBody), sResp.StatusCode, len(sBody), string(sBody)) {
						detail := RichParamDetail{
							Sources:      []string{cfg.BaseURL},
							SourceTypes:  []ParamSource{SourceActiveBrute},
							InferredType: TypeUnknown,
						}
						mu.Lock()
						mergeRichParam(result, param, detail)
						mu.Unlock()
						fmt.Printf("[ActiveBrute] *** Found param: %s (HTTP %d, %d bytes)\n",
							param, sResp.StatusCode, len(sBody))
					}
				}
			}
		}(chunk)
	}

	wg.Wait()
	return result, nil
}

// isDifferentResponse returns true if the response is meaningfully different from baseline.
func isDifferentResponse(baseStatus, baseSize int, baseBody string, newStatus, newSize int, newBody string) bool {
	if newStatus != baseStatus {
		return true
	}
	if baseSize > 0 {
		diff := newSize - baseSize
		if diff < 0 {
			diff = -diff
		}
		if float64(diff)/float64(baseSize) > 0.05 {
			return true
		}
	}
	if strings.Contains(newBody, "alemi1337") {
		return true
	}
	return false
}

// =============================================================
// ── MAIN ENTRY POINT: EnhancedDiscoverParams ─────────────────
// =============================================================

// EnhancedDiscoverParams is the upgraded replacement for DiscoverParams.
// It combines URL query mining, JS extraction (external files + inline blocks),
// form input mining, JSON response key extraction, path param detection,
// and optional active brute-force into a single concurrent pass.
func EnhancedDiscoverParams(rawURL string, cfg MiningConfig) (*DiscoveryResult, error) {
	rawURL = core.EnsureProtocol(rawURL)

	if cfg.Threads == 0 {
		cfg.Threads = 10
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10
	}
	if cfg.SuspiciousPattern == nil {
		cfg.SuspiciousPattern = regexp.MustCompile(
			`(?i)(id|page|user|token|key|pass|debug|cmd|exec|file|path|url|redirect|search|query|action)`,
		)
	}

	aggregated := make(map[string]RichParamDetail)
	keywordAggregated := make(map[string][]string)
	var secretFindings []SecretFinding
	var configResources []string
	var apiEndpoints []APIEndpointFinding
	var apiSpecs []APISpecFinding

	fmt.Printf("\n[ParamMiner] Starting enhanced param discovery on %s\n", rawURL)
	fmt.Printf("%s\n", strings.Repeat("-", 55))

	// ── Step 1: Crawl ──────────────────────────────────────────
	fmt.Println("[ParamMiner] Crawling site...")
	crawlDetails, err := CrawlDetailed(rawURL, cfg.Depth)
	if err != nil {
		return nil, fmt.Errorf("crawl error: %w", err)
	}
	discoveredURLs := make([]string, 0, len(crawlDetails))
	for _, detail := range crawlDetails {
		discoveredURLs = append(discoveredURLs, detail.URL)
	}
	fmt.Printf("[ParamMiner] Crawled %d URLs\n", len(discoveredURLs))
	if summary := summarizeCrawlStatuses(crawlDetails); summary != "" {
		fmt.Printf("[ParamMiner] Response codes: %s\n", summary)
	}

	// ── Step 2: Path Parameter Detection ──────────────────────
	if cfg.MinePathParams {
		fmt.Println("[ParamMiner] Mining path parameters...")
		pathParams := minePathParams(discoveredURLs)
		for k, v := range pathParams {
			mergeRichParam(aggregated, k, v)
		}
		fmt.Printf("[ParamMiner] Path params found: %d\n", len(pathParams))
	}

	// ── Steps 3–6: Per-URL concurrent mining ──────────────────
	ctxTimeout := time.Duration(cfg.Timeout*len(discoveredURLs)+30) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	client := core.CreateHTTPClient(cfg.Timeout)
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Threads)
	var mu sync.Mutex

	for _, u := range discoveredURLs {
		wg.Add(1)
		go func(pageURL string) {
			defer wg.Done()
			pageURL = core.EnsureProtocol(pageURL)
			sem <- struct{}{}
			defer func() { <-sem }()

			req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AlemiScanner/2.0)")

			resp, err := client.Do(req)
			if err != nil {
				log.Printf("[ParamMiner] Error fetching %s: %v", pageURL, err)
				return
			}
			defer resp.Body.Close()

			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}
			bodyStr := string(bodyBytes)
			contentType := resp.Header.Get("Content-Type")

			local := make(map[string]RichParamDetail)
			var localSecrets []SecretFinding
			var localConfigs []string
			var localAPIs []APIEndpointFinding
			var localSpecs []APISpecFinding

			// ── Step 0: Keyword Scanning ──────────────────────
			if cfg.MineKeywords && len(cfg.Keywords) > 0 {
				matches := ScanForKeywords(bodyStr, cfg.Keywords)
				mu.Lock()
				for k, v := range matches {
					keywordAggregated[k] = append(keywordAggregated[k], v...)
				}
				mu.Unlock()
			}

			// ── Step 3: URL Query Params ───────────────────────
			if parsedURL, err := url.Parse(pageURL); err == nil {
				for key, values := range parsedURL.Query() {
					detail := RichParamDetail{
						Values:       values,
						Sources:      []string{pageURL},
						SourceTypes:  []ParamSource{SourceURLQuery},
						InferredType: inferTypeFromValues(values),
						Suspicious:   cfg.SuspiciousPattern.MatchString(key),
					}
					mergeRichParam(local, key, detail)
				}
			}

			// ── Step 4: Form Input Names ───────────────────────
			if cfg.MineForms && strings.Contains(contentType, "text/html") {
				for k, v := range mineFormInputs(pageURL, bodyStr) {
					mergeRichParam(local, k, v)
				}
			}

			// ── Step 5: JSON Response Key Extraction ───────────
			if cfg.MineJSONResponses && strings.Contains(contentType, "application/json") {
				for k, v := range mineJSONResponse(pageURL, bodyBytes) {
					mergeRichParam(local, k, v)
				}
				localSecrets = append(localSecrets, detectSecretFindings(bodyStr, pageURL, "json_response")...)
			}

			// ── Step 6: JS File Mining ─────────────────────────
			if cfg.MineJS && strings.Contains(contentType, "text/html") {
				analysis := analyzeHTMLClientSurface(pageURL, bodyStr, client)
				for k, v := range analysis.ParamDetails {
					mergeRichParam(local, k, v)
				}
				localSecrets = append(localSecrets, analysis.SecretFindings...)
				localConfigs = append(localConfigs, analysis.ConfigResources...)
				localAPIs = append(localAPIs, analysis.APIEndpoints...)
				localSpecs = append(localSpecs, analysis.APISpecs...)
			}

			mu.Lock()
			for k, v := range local {
				mergeRichParam(aggregated, k, v)
			}
			for _, finding := range localSecrets {
				if !hasSecretFinding(secretFindings, finding) {
					secretFindings = append(secretFindings, finding)
				}
			}
			configResources = mergeStringListUnique(configResources, localConfigs)
			apiEndpoints = mergeAPIEndpointList(apiEndpoints, localAPIs)
			apiSpecs = mergeAPISpecList(apiSpecs, localSpecs)
			mu.Unlock()

		}(u)
	}

	wg.Wait()

	endpointsFromDiscovery, specsFromDiscovery, err := DiscoverAPISurface(rawURL, discoveredURLs, configResources, client)
	if err == nil {
		apiEndpoints = mergeAPIEndpointList(apiEndpoints, endpointsFromDiscovery)
		apiSpecs = mergeAPISpecList(apiSpecs, specsFromDiscovery)
	}

	// ── Step 7: Active Brute-Force ─────────────────────────────
	if cfg.ActiveBrute {
		fmt.Println("\n[ParamMiner] Starting active param brute-force...")
		bruteCfg := ActiveBruteConfig{
			BaseURL:   rawURL,
			Threads:   cfg.Threads,
			Timeout:   cfg.Timeout,
			ChunkSize: cfg.ActiveChunkSize,
			Wordlist:  cfg.ActiveWordlist,
		}
		bruteParams, err := activeProbeParams(bruteCfg)
		if err != nil {
			log.Printf("[ParamMiner] Active brute error: %v", err)
		} else {
			for k, v := range bruteParams {
				mergeRichParam(aggregated, k, v)
			}
		}
	}

	// Final pass: mark suspicious params
	for k, v := range aggregated {
		if cfg.SuspiciousPattern.MatchString(k) {
			v.Suspicious = true
			aggregated[k] = v
		}
	}

	fmt.Printf("\n[ParamMiner] Total unique params discovered: %d\n", len(aggregated))
	return &DiscoveryResult{
		Params:          aggregated,
		KeywordMatches:  keywordAggregated,
		CrawlDetails:    crawlDetails,
		SecretFindings:  secretFindings,
		ConfigResources: configResources,
		APIEndpoints:    apiEndpoints,
		APISpecs:        apiSpecs,
	}, nil
}

// =============================================================
// ── OUTPUT / REPORTING ───────────────────────────────────────
// =============================================================

// PrintParamMiningResult prints a rich, categorized report of all discovered params.
func PrintParamMiningResult(params map[string]RichParamDetail) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("  PARAM MINING RESULTS — %d unique parameters\n", len(params))
	fmt.Printf("%s\n", strings.Repeat("=", 60))

	bySource := map[ParamSource][]string{}
	for name, detail := range params {
		for _, st := range detail.SourceTypes {
			bySource[st] = append(bySource[st], name)
		}
	}

	sourceOrder := []ParamSource{
		SourceURLQuery, SourceFormInput, SourceJSFile,
		SourceJSONBody, SourcePathParam, SourceActiveBrute,
	}
	sourceLabels := map[ParamSource]string{
		SourceURLQuery:    "URL Query Params",
		SourceFormInput:   "Form Inputs",
		SourceJSFile:      "JavaScript Files",
		SourceJSONBody:    "JSON API Responses",
		SourcePathParam:   "Path Parameters",
		SourceActiveBrute: "Active Brute-Force",
	}

	for _, src := range sourceOrder {
		names, ok := bySource[src]
		if !ok || len(names) == 0 {
			continue
		}
		fmt.Printf("\n[%s] (%d found)\n", sourceLabels[src], len(names))
		for _, name := range names {
			detail := params[name]
			suspFlag := ""
			if detail.Suspicious {
				suspFlag = " *** SUSPICIOUS"
			}
			valStr := ""
			if len(detail.Values) > 0 {
				vals := detail.Values
				if len(vals) > 3 {
					vals = vals[:3]
				}
				valStr = fmt.Sprintf(" [ex: %s]", strings.Join(vals, ", "))
			}
			sourceTypeStr := strings.Join(paramSourceStrings(detail.SourceTypes), ", ")
			fmt.Printf("  %-35s type:%-8s via:%s%s%s\n",
				name, string(detail.InferredType), sourceTypeStr, valStr, suspFlag)
			if len(detail.Sources) > 0 {
				fmt.Printf("      from: %s\n", strings.Join(detail.Sources, ", "))
			}
		}
	}

	fmt.Printf("\n%s\n", strings.Repeat("-", 60))
	fmt.Println("  HIGH-INTEREST PARAMS (suspicious pattern match):")
	count := 0
	for name, detail := range params {
		if detail.Suspicious {
			count++
			fmt.Printf("  *** %-30s  type: %-8s  via: %s\n",
				name, string(detail.InferredType), strings.Join(paramSourceStrings(detail.SourceTypes), ", "))
			if len(detail.Sources) > 0 {
				fmt.Printf("      from: %s\n", strings.Join(detail.Sources, ", "))
			}
		}
	}
	if count == 0 {
		fmt.Println("  None flagged.")
	}
}

// =============================================================
// ── TYPE INFERENCE ───────────────────────────────────────────
// =============================================================

var (
	uuidRegex  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	intRegex   = regexp.MustCompile(`^\d+$`)
	emailRegex = regexp.MustCompile(`^[^@]+@[^@]+\.[^@]+$`)
	jwtRegex   = regexp.MustCompile(`^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$`)
)

func inferTypeFromValues(values []string) ParamType {
	if len(values) == 0 {
		return TypeUnknown
	}
	return inferTypeFromString(values[0])
}

func inferTypeFromString(s string) ParamType {
	s = strings.TrimSpace(s)
	if s == "" {
		return TypeUnknown
	}
	if uuidRegex.MatchString(s) {
		return TypeUUID
	}
	if jwtRegex.MatchString(s) && len(s) > 50 {
		return TypeJWT
	}
	if emailRegex.MatchString(s) {
		return TypeEmail
	}
	if intRegex.MatchString(s) {
		return TypeInt
	}
	if s == "true" || s == "false" || s == "1" || s == "0" {
		return TypeBool
	}
	return TypeString
}

func inferTypeFromJSONValue(v interface{}) ParamType {
	switch val := v.(type) {
	case float64:
		return TypeInt
	case bool:
		return TypeBool
	case string:
		return inferTypeFromString(val)
	}
	return TypeUnknown
}

func inferTypeFromInput(inputType, value string) ParamType {
	switch strings.ToLower(inputType) {
	case "number", "range":
		return TypeInt
	case "checkbox", "radio":
		return TypeBool
	case "email":
		return TypeEmail
	case "hidden":
		return inferTypeFromString(value)
	}
	return inferTypeFromString(value)
}

func paramSourceStrings(sourceTypes []ParamSource) []string {
	if len(sourceTypes) == 0 {
		return nil
	}
	result := make([]string, 0, len(sourceTypes))
	for _, item := range sourceTypes {
		result = append(result, string(item))
	}
	return result
}

func summarizeCrawlStatuses(details []CrawlFinding) string {
	if len(details) == 0 {
		return ""
	}
	counts := make(map[int]int)
	var codes []int
	for _, detail := range details {
		counts[detail.StatusCode]++
	}
	for code := range counts {
		codes = append(codes, code)
	}
	sort.Slice(codes, func(i, j int) bool {
		left := CrawlFinding{StatusCode: codes[i]}
		right := CrawlFinding{StatusCode: codes[j]}
		if crawlFindingPriority(left) != crawlFindingPriority(right) {
			return crawlFindingPriority(left) < crawlFindingPriority(right)
		}
		return normalizedStatusCode(left.StatusCode) < normalizedStatusCode(right.StatusCode)
	})
	parts := make([]string, 0, len(codes))
	for _, code := range codes {
		label := "ERR"
		if code > 0 {
			label = fmt.Sprintf("%d", code)
		}
		parts = append(parts, fmt.Sprintf("%s=%d", label, counts[code]))
	}
	return strings.Join(parts, ", ")
}

func normalizeHTTPStatus(statusCode int, status string) string {
	status = strings.TrimSpace(status)
	if statusCode == 0 {
		if status == "" {
			return "ERROR"
		}
		return status
	}
	expectedPrefix := fmt.Sprintf("%d", statusCode)
	if status == "" || !strings.HasPrefix(status, expectedPrefix) {
		if text := http.StatusText(statusCode); text != "" {
			return fmt.Sprintf("%d %s", statusCode, text)
		}
		return expectedPrefix
	}
	return status
}

func crawlFindingLess(left CrawlFinding, right CrawlFinding) bool {
	leftPriority := crawlFindingPriority(left)
	rightPriority := crawlFindingPriority(right)
	if leftPriority != rightPriority {
		return leftPriority < rightPriority
	}
	leftCode := normalizedStatusCode(left.StatusCode)
	rightCode := normalizedStatusCode(right.StatusCode)
	if leftCode != rightCode {
		return leftCode < rightCode
	}
	return left.URL < right.URL
}

func crawlFindingPriority(finding CrawlFinding) int {
	switch {
	case finding.StatusCode >= 200 && finding.StatusCode < 300:
		return 0
	case finding.StatusCode == http.StatusNotFound:
		return 2
	default:
		return 1
	}
}

func normalizedStatusCode(statusCode int) int {
	if statusCode == 0 {
		return 999
	}
	return statusCode
}

// =============================================================
// ── MERGE & UTILITY HELPERS ──────────────────────────────────
// =============================================================

// mergeRichParam merges a new RichParamDetail into an existing map entry,
// deduplicating values, sources, and source types.
func mergeRichParam(dst map[string]RichParamDetail, key string, incoming RichParamDetail) {
	existing, ok := dst[key]
	if !ok {
		dst[key] = incoming
		return
	}
	for _, v := range incoming.Values {
		if !contains(existing.Values, v) {
			existing.Values = append(existing.Values, v)
		}
	}
	for _, s := range incoming.Sources {
		if !contains(existing.Sources, s) {
			existing.Sources = append(existing.Sources, s)
		}
	}
	for _, st := range incoming.SourceTypes {
		found := false
		for _, est := range existing.SourceTypes {
			if est == st {
				found = true
				break
			}
		}
		if !found {
			existing.SourceTypes = append(existing.SourceTypes, st)
		}
	}
	if existing.InferredType == TypeUnknown && incoming.InferredType != TypeUnknown {
		existing.InferredType = incoming.InferredType
	}
	if incoming.Suspicious {
		existing.Suspicious = true
	}
	dst[key] = existing
}

// chunkSlice splits a string slice into chunks of the given size.
func chunkSlice(slice []string, size int) [][]string {
	var chunks [][]string
	for i := 0; i < len(slice); i += size {
		end := i + size
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}
	return chunks
}

// =============================================================
// ── GOOGLE DORKING & SEARCH ENGINE SCRAPING ──────────────────
// =============================================================

// PerformDork executes a search query on the specified engine and returns discovered URLs.
func PerformDork(cfg DorkConfig) ([]string, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 15
	}
	if cfg.MaxResults == 0 {
		cfg.MaxResults = 30
	}

	switch strings.ToLower(cfg.Engine) {
	case "duckduckgo", "ddg", "":
		return scrapeDuckDuckGo(cfg)
	case "google":
		return scrapeGoogle(cfg)
	default:
		return nil, fmt.Errorf("unsupported search engine: %s", cfg.Engine)
	}
}

var randomUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
}

func getRandomUA() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return randomUserAgents[r.Intn(len(randomUserAgents))]
}

func scrapeDuckDuckGo(cfg DorkConfig) ([]string, error) {
	searchURL := fmt.Sprintf("https://html.duckduckgo.com/html/?q=%s", url.QueryEscape(cfg.Query))
	client := core.CreateHTTPClient(cfg.Timeout)

	req, _ := http.NewRequest("GET", searchURL, nil)
	req.Header.Set("User-Agent", getRandomUA())
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DuckDuckGo returned %s", resp.Status)
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, err
	}

	var urls []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			attrs := getAttrs(n)
			if class, ok := attrs["class"]; ok && (strings.Contains(class, "result__url") || strings.Contains(class, "result__a") || strings.Contains(class, "result__snippet")) {
				if href, ok := attrs["href"]; ok {
					decodedURL := href
					if strings.Contains(href, "uddg=") {
						u, _ := url.Parse(href)
						decodedURL = u.Query().Get("uddg")
					}
					if decodedURL != "" && !strings.Contains(decodedURL, "duckduckgo.com") {
						urls = append(urls, decodedURL)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	// Deduplicate
	unique := make(map[string]bool)
	var final []string
	for _, u := range urls {
		if !unique[u] && strings.HasPrefix(u, "http") {
			unique[u] = true
			final = append(final, u)
		}
	}

	if len(final) > cfg.MaxResults {
		final = final[:cfg.MaxResults]
	}
	return final, nil
}

func scrapeGoogle(cfg DorkConfig) ([]string, error) {
	searchURL := fmt.Sprintf("https://www.google.com/search?q=%s&num=%d", url.QueryEscape(cfg.Query), cfg.MaxResults)
	client := core.CreateHTTPClient(cfg.Timeout)

	req, _ := http.NewRequest("GET", searchURL, nil)
	req.Header.Set("User-Agent", getRandomUA())
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == 429 {
			return nil, fmt.Errorf("Google rate-limited us (429)")
		}
		return nil, fmt.Errorf("Google returned %s", resp.Status)
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, err
	}

	var urls []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			attrs := getAttrs(n)
			if href, ok := attrs["href"]; ok {
				if strings.HasPrefix(href, "/url?q=") {
					u, _ := url.Parse(href)
					rawURL := u.Query().Get("q")
					if rawURL != "" && !strings.Contains(rawURL, "google.com") {
						urls = append(urls, rawURL)
					}
				} else if strings.HasPrefix(href, "http") && !strings.Contains(href, "google.com") && !strings.Contains(href, "schema.org") && !strings.Contains(href, "support.google.com") {
					urls = append(urls, href)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	unique := make(map[string]bool)
	var final []string
	for _, u := range urls {
		if !unique[u] {
			unique[u] = true
			final = append(final, u)
		}
	}

	if len(final) > cfg.MaxResults {
		final = final[:cfg.MaxResults]
	}
	return final, nil
}

// =============================================================
// ── KEYWORD DISCOVERY ────────────────────────────────────────
// =============================================================

// ScanForKeywords searches for a list of keywords in a text block.
// Returns a map of keyword -> matching contexts (lines).
func ScanForKeywords(content string, keywords []string) map[string][]string {
	results := make(map[string][]string)
	if len(keywords) == 0 {
		return results
	}

	lines := strings.Split(content, "\n")
	for _, kw := range keywords {
		kwLower := strings.ToLower(kw)
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), kwLower) {
				results[kw] = append(results[kw], strings.TrimSpace(line))
			}
		}
	}

	for kw, matches := range results {
		if len(matches) > 10 {
			results[kw] = matches[:10]
		}
	}

	return results
}
