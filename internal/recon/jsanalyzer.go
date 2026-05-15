package recon

import (
	core "Akemi/internal/core"
	"bufio"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// JSAnalysisResult holds everything extracted from JS files found on a page.
type JSAnalysisResult struct {
	ScriptURLs      []string             // All <script src=""> URLs found
	Endpoints       []string             // API/path endpoints found inside JS
	Secrets         map[string][]string  // Categorized potential secrets (keys, tokens, etc.)
	HiddenParams    []string             // Query param names found inside JS
	SecretFindings  []SecretFinding      // Context-rich secret findings
	ConfigResources []string             // Config-like resources discovered from HTML/JS
	APIEndpoints    []APIEndpointFinding `json:"api_endpoints,omitempty"`
	APISpecs        []APISpecFinding     `json:"api_specs,omitempty"`
}

// Regex patterns for JS analysis
var (
	// Matches path-like strings: /api/v1/users, /admin/login, etc.
	endpointRegex = regexp.MustCompile(`["'/]((?:/[a-zA-Z0-9_\-\.]+){2,})["'?]`)

	// Matches common secret patterns
	secretPatterns = map[string]*regexp.Regexp{
		"API Key":       regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*["']([A-Za-z0-9\-_]{16,})["']`),
		"Bearer Token":  regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9\-_\.]{20,})`),
		"AWS Key":       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"Private Key":   regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`),
		"Password":      regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["']([^"']{4,})["']`),
		"Secret":        regexp.MustCompile(`(?i)(secret[_-]?key|client[_-]?secret)\s*[:=]\s*["']([A-Za-z0-9\-_]{8,})["']`),
		"Firebase URL":  regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`),
		"Google OAuth":  regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
		"Authorization": regexp.MustCompile(`(?i)authorization\s*[:=]\s*["']?(?:bearer\s+)?[A-Za-z0-9\-_\.=]{12,}["']?`),
		"JWT":           regexp.MustCompile(`eyJ[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+`),
	}

	// Matches param names used in JS: fetch('/api?param=', axios.get('...?key='))
	hiddenParamRegex = regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_\-]{1,30})=`)
)

// extractScriptURLs parses HTML and returns all external script src URLs (absolute).
func extractScriptURLs(pageURL string, body io.Reader) ([]string, error) {
	var scripts []string
	doc, err := html.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("error parsing HTML: %w", err)
	}

	base, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing base URL: %w", err)
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			attrs := getAttrs(n)
			if src, ok := attrs["src"]; ok && strings.TrimSpace(src) != "" {
				parsed, err := url.Parse(strings.TrimSpace(src))
				if err == nil {
					scripts = append(scripts, base.ResolveReference(parsed).String())
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return scripts, nil
}

// analyzeJSContent runs all regex patterns against raw JS content.
func analyzeJSContent(content string) (endpoints []string, secrets map[string][]string, params []string) {
	secrets = make(map[string][]string)
	seen := make(map[string]bool)

	// Extract endpoints
	for _, match := range endpointRegex.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 && !seen["ep:"+match[1]] {
			seen["ep:"+match[1]] = true
			endpoints = append(endpoints, match[1])
		}
	}

	// Extract secrets by category
	for category, pattern := range secretPatterns {
		for _, match := range pattern.FindAllString(content, -1) {
			secrets[category] = append(secrets[category], match)
		}
	}

	// Extract hidden params
	for _, match := range hiddenParamRegex.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 && !seen["param:"+match[1]] {
			seen["param:"+match[1]] = true
			params = append(params, match[1])
		}
	}

	return endpoints, secrets, params
}

// AnalyzeJS is the main entry point: fetches the target page, finds all script
// URLs, fetches and analyzes each one concurrently, and returns aggregated results.
func AnalyzeJS(pageURL string) (*JSAnalysisResult, error) {
	pageURL = core.EnsureProtocol(pageURL)
	client := core.CreateHTTPClient(10)

	resp, err := client.Get(pageURL)
	if err != nil {
		return nil, fmt.Errorf("error fetching page: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading page body: %w", err)
	}

	analysis := analyzeHTMLClientSurface(pageURL, string(bodyBytes), client)
	result := &JSAnalysisResult{
		ScriptURLs:      analysis.ScriptURLs,
		Endpoints:       analysis.Endpoints,
		Secrets:         analysis.LegacySecrets,
		HiddenParams:    analysis.HiddenParams,
		SecretFindings:  analysis.SecretFindings,
		ConfigResources: analysis.ConfigResources,
		APIEndpoints:    analysis.APIEndpoints,
		APISpecs:        analysis.APISpecs,
	}

	return result, nil
}

// PrintJSAnalysisResult prints the analysis in a clean, readable format.
func PrintJSAnalysisResult(result *JSAnalysisResult) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 50))
	fmt.Println("  JS ANALYSIS RESULTS")
	fmt.Printf("%s\n", strings.Repeat("=", 50))

	fmt.Printf("\n[+] Script files found (%d):\n", len(result.ScriptURLs))
	for _, u := range result.ScriptURLs {
		fmt.Printf("    %s\n", u)
	}

	if len(result.ConfigResources) > 0 {
		fmt.Printf("\n[+] Config resources (%d):\n", len(result.ConfigResources))
		for _, u := range result.ConfigResources {
			fmt.Printf("    %s\n", u)
		}
	}

	fmt.Printf("\n[+] Endpoints discovered (%d):\n", len(result.Endpoints))
	for _, e := range result.Endpoints {
		fmt.Printf("    %s\n", e)
	}

	if len(result.APIEndpoints) > 0 {
		fmt.Printf("\n[+] API surface (%d endpoint(s)):\n", len(result.APIEndpoints))
		for _, endpoint := range result.APIEndpoints {
			method := endpoint.Method
			if method == "" {
				method = "ANY"
			}
			status := endpoint.Status
			if status == "" {
				status = "UNKNOWN"
			}
			fmt.Printf("    [%s] [%s] %s (%s)\n", endpoint.APIType, status, endpoint.URL, method)
		}
	}

	if len(result.APISpecs) > 0 {
		fmt.Printf("\n[+] API specs (%d):\n", len(result.APISpecs))
		for _, spec := range result.APISpecs {
			status := spec.Status
			if status == "" {
				status = "UNKNOWN"
			}
			fmt.Printf("    [%s] [%s] %s (%s)\n", spec.APIType, status, spec.URL, spec.Format)
		}
	}

	fmt.Printf("\n[+] Hidden parameters found (%d):\n", len(result.HiddenParams))
	for _, p := range result.HiddenParams {
		fmt.Printf("    ?%s=\n", p)
	}

	fmt.Printf("\n[!] Potential secrets detected:\n")
	if len(result.SecretFindings) == 0 && len(result.Secrets) == 0 {
		fmt.Println("    None found.")
	}
	if len(result.SecretFindings) > 0 {
		for _, finding := range result.SecretFindings {
			value := finding.Value
			if len(value) > 80 {
				value = value[:80] + "..."
			}
			fmt.Printf("    [%s] %s (%s)\n", finding.Category, value, finding.SourceURL)
		}
	} else {
		for category, matches := range result.Secrets {
			fmt.Printf("    [%s] (%d match(es))\n", category, len(matches))
			for _, m := range matches {
				if len(m) > 80 {
					m = m[:80] + "..."
				}
				fmt.Printf("      -> %s\n", m)
			}
		}
	}

	// Summary scanner for quick triage
	fmt.Printf("\n%s\n", strings.Repeat("-", 50))
	totalSecrets := len(result.SecretFindings)
	if totalSecrets == 0 {
		for _, v := range result.Secrets {
			totalSecrets += len(v)
		}
	}
	fmt.Printf("Summary: %d scripts | %d endpoints | %d params | %d secret(s)\n",
		len(result.ScriptURLs), len(result.Endpoints), len(result.HiddenParams), totalSecrets)

	// Warn loudly if high-value secrets found
	for _, critical := range []string{"AWS Key", "Private Key"} {
		if hits, ok := result.Secrets[critical]; ok && len(hits) > 0 {
			scanner := bufio.NewScanner(strings.NewReader(""))
			_ = scanner
			fmt.Printf("\n  *** CRITICAL: %s detected! Verify immediately. ***\n", critical)
			continue
		}
		for _, finding := range result.SecretFindings {
			if finding.Category == critical {
				scanner := bufio.NewScanner(strings.NewReader(""))
				_ = scanner
				fmt.Printf("\n  *** CRITICAL: %s detected! Verify immediately. ***\n", critical)
				break
			}
		}
	}
}
