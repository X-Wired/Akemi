package recon

import (
	core "Akemi/internal/core"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"
	"gopkg.in/yaml.v3"
)

// SecretFinding preserves secret exposure context for reporting and APIs.
type SecretFinding struct {
	Category   string   `json:"category"`
	Value      string   `json:"value"`
	SourceURL  string   `json:"source_url"`
	SourceKind string   `json:"source_kind"`
	Evidence   []string `json:"evidence,omitempty"`
}

// APIEndpointFinding captures passive API surface discovery details.
type APIEndpointFinding struct {
	URL          string         `json:"url"`
	Path         string         `json:"path,omitempty"`
	Method       string         `json:"method,omitempty"`
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

// APISpecFinding tracks discovered API specs and their metadata.
type APISpecFinding struct {
	URL                     string   `json:"url"`
	APIType                 string   `json:"api_type"`
	Format                  string   `json:"format,omitempty"`
	Title                   string   `json:"title,omitempty"`
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

// APIHuntRequest configures Akemi's richer API Hunter workflow.
type APIHuntRequest struct {
	StartURL       string
	DiscoveredURLs []string
	Mode           string
	Wordlist       []string
	WordlistFile   string
	AuthCookies    []string
	MaxCandidates  int
	Threads        int
	Timeout        int
}

// APIHuntResult aggregates API Hunter output.
type APIHuntResult struct {
	StartURL      string
	Mode          string
	APIEndpoints  []APIEndpointFinding
	APISpecs      []APISpecFinding
	Parameters    []APIParameterFinding
	Counts        map[string]int
	StageErrors   []string
	SourceSummary map[string]int
}

// APIParameter describes a parameter tied to an API endpoint.
type APIParameter struct {
	Name     string   `json:"name"`
	In       string   `json:"in,omitempty"`
	Required bool     `json:"required,omitempty"`
	Type     string   `json:"type,omitempty"`
	Sources  []string `json:"sources,omitempty"`
}

// APIParameterFinding aggregates API parameters across endpoints.
type APIParameterFinding struct {
	Name      string   `json:"name"`
	In        string   `json:"in,omitempty"`
	Type      string   `json:"type,omitempty"`
	Required  bool     `json:"required,omitempty"`
	Endpoints []string `json:"endpoints,omitempty"`
	Sources   []string `json:"sources,omitempty"`
}

type clientSurfaceAnalysis struct {
	ScriptURLs      []string
	ConfigResources []string
	Endpoints       []string
	HiddenParams    []string
	LegacySecrets   map[string][]string
	SecretFindings  []SecretFinding
	APIEndpoints    []APIEndpointFinding
	APISpecs        []APISpecFinding
	ParamDetails    map[string]RichParamDetail
	KeywordMatches  map[string][]string
}

type sitemapURLSet struct {
	URLs []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
}

type sitemapIndex struct {
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

type openAPISpecDoc struct {
	OpenAPI string `json:"openapi" yaml:"openapi"`
	Swagger string `json:"swagger" yaml:"swagger"`
	Info    struct {
		Title   string `json:"title" yaml:"title"`
		Version string `json:"version" yaml:"version"`
	} `json:"info" yaml:"info"`
	Paths map[string]map[string]openAPIOperation `json:"paths" yaml:"paths"`
}

type openAPIOperation struct {
	Parameters  []openAPIParameter `json:"parameters" yaml:"parameters"`
	RequestBody struct {
		Content map[string]struct {
			Schema map[string]interface{} `json:"schema" yaml:"schema"`
		} `json:"content" yaml:"content"`
	} `json:"requestBody" yaml:"requestBody"`
}

type openAPIParameter struct {
	Name     string                 `json:"name" yaml:"name"`
	In       string                 `json:"in" yaml:"in"`
	Required bool                   `json:"required" yaml:"required"`
	Schema   map[string]interface{} `json:"schema" yaml:"schema"`
}

var (
	configResourcePattern  = regexp.MustCompile(`(?i)["']([^"'?#\s]*(?:config|settings|env|runtime|manifest|app-config|site-config)[^"'?#\s]*(?:\.json|\.js|/manifest\.json|/manifest)?)["']`)
	graphQLPathPattern     = regexp.MustCompile(`(?i)(/[\w./-]*graphql(?:/[\w./-]+)?)`)
	apiURLWithQueryPattern = regexp.MustCompile(`(?i)["']((?:/(?:api|rest|services?|graphql)[^"'\s?#]+(?:/[^"'\s?#]+)*)\?[^"'\s]+)["']`)
	restVersionedPattern   = regexp.MustCompile(`(?i)(/(?:api/)?v[0-9]+(?:/[a-zA-Z0-9_.{}\-/]+)+)`)
	restPrefixedPattern    = regexp.MustCompile(`(?i)(/(?:api|rest|services?)(?:/[a-zA-Z0-9_.{}\-/]+)+)`)
	openAPISpecPattern     = regexp.MustCompile(`(?i)(/\.well-known/openapi\.json|/openapi\.(?:json|yaml)|/swagger\.(?:json|yaml)|/v[23]/api-docs)`)
	versionSegmentPattern  = regexp.MustCompile(`(?i)/(v[0-9]+)(?:/|$)`)
)

var knownSpecPaths = []string{
	"/.well-known/openapi.json",
	"/openapi.json",
	"/openapi.yaml",
	"/swagger.json",
	"/swagger.yaml",
	"/v2/api-docs",
	"/v3/api-docs",
}

var openAPIHTTPMethods = map[string]struct{}{
	http.MethodGet:     {},
	http.MethodPost:    {},
	http.MethodPut:     {},
	http.MethodDelete:  {},
	http.MethodPatch:   {},
	http.MethodHead:    {},
	http.MethodOptions: {},
	http.MethodTrace:   {},
}

var graphQLMarkers = []string{
	"__schema",
	"query",
	"mutation",
	"subscription",
	"graphiql",
	"apollo",
	"relay",
}

func collectSeedURLs(startURL string, client *http.Client) []string {
	return collectSeedURLsWithContext(context.Background(), startURL, client)
}

func collectSeedURLsWithContext(ctx context.Context, startURL string, client *http.Client) []string {
	if ctx == nil {
		ctx = context.Background()
	}
	startURL = core.EnsureProtocol(startURL)
	base, err := url.Parse(startURL)
	if err != nil {
		return []string{startURL}
	}

	results := make(map[string]struct{})
	addURL := func(candidate string) {
		if normalized, ok := resolveSameHostURL(base, candidate); ok {
			results[normalized] = struct{}{}
		}
	}

	addURL(startURL)

	robotsURL := base.ResolveReference(&url.URL{Path: "/robots.txt"}).String()
	var sitemapQueue []string

	if resp, err := clientGetWithContext(ctx, client, robotsURL); err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			disallowed, sitemaps := parseRobotsTxt(base, string(body))
			for _, item := range disallowed {
				addURL(item)
			}
			sitemapQueue = append(sitemapQueue, sitemaps...)
		}
	}

	sitemapQueue = append(sitemapQueue,
		base.ResolveReference(&url.URL{Path: "/sitemap.xml"}).String(),
		base.ResolveReference(&url.URL{Path: "/sitemap_index.xml"}).String(),
	)

	visited := make(map[string]struct{})
	for len(sitemapQueue) > 0 {
		if ctx.Err() != nil {
			break
		}
		current := sitemapQueue[0]
		sitemapQueue = sitemapQueue[1:]

		normalized, ok := resolveSameHostURL(base, current)
		if !ok {
			continue
		}
		if _, seen := visited[normalized]; seen {
			continue
		}
		visited[normalized] = struct{}{}

		resp, err := clientGetWithContext(ctx, client, normalized)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}

		urls, nested := parseSitemap(body)
		for _, item := range urls {
			addURL(item)
		}
		for _, item := range nested {
			if nestedURL, ok := resolveSameHostURL(base, item); ok {
				sitemapQueue = append(sitemapQueue, nestedURL)
			}
		}
	}

	final := make([]string, 0, len(results))
	for item := range results {
		final = append(final, item)
	}
	sort.Strings(final)
	return final
}

func clientGetWithContext(ctx context.Context, client *http.Client, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func parseRobotsTxt(base *url.URL, body string) ([]string, []string) {
	var disallowed []string
	var sitemaps []string

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}

		switch key {
		case "disallow":
			if value == "/" || value == "*" {
				continue
			}
			if resolved, ok := resolveSameHostURL(base, value); ok {
				disallowed = append(disallowed, resolved)
			}
		case "sitemap":
			if resolved, ok := resolveSameHostURL(base, value); ok {
				sitemaps = append(sitemaps, resolved)
			}
		}
	}

	return uniqueStrings(disallowed), uniqueStrings(sitemaps)
}

func parseSitemap(body []byte) ([]string, []string) {
	var urlSet sitemapURLSet
	if err := xml.Unmarshal(body, &urlSet); err == nil && len(urlSet.URLs) > 0 {
		urls := make([]string, 0, len(urlSet.URLs))
		for _, item := range urlSet.URLs {
			if strings.TrimSpace(item.Loc) != "" {
				urls = append(urls, strings.TrimSpace(item.Loc))
			}
		}
		return uniqueStrings(urls), nil
	}

	var index sitemapIndex
	if err := xml.Unmarshal(body, &index); err == nil && len(index.Sitemaps) > 0 {
		nested := make([]string, 0, len(index.Sitemaps))
		for _, item := range index.Sitemaps {
			if strings.TrimSpace(item.Loc) != "" {
				nested = append(nested, strings.TrimSpace(item.Loc))
			}
		}
		return nil, uniqueStrings(nested)
	}

	return nil, nil
}

func DiscoverAPISurface(startURL string, discoveredURLs []string, configResources []string, client *http.Client) ([]APIEndpointFinding, []APISpecFinding, error) {
	startURL = core.EnsureProtocol(startURL)
	if client == nil {
		client = core.CreateHTTPClient(10)
	}

	base, err := url.Parse(startURL)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing base URL: %w", err)
	}

	endpointMap := make(map[string]APIEndpointFinding)
	specMap := make(map[string]APISpecFinding)

	for _, item := range discoveredURLs {
		if finding, ok := classifyAPIEndpoint(item, base, item, "discovered_url"); ok {
			endpointMap[apiEndpointKey(finding)] = mergeAPIEndpointFindings(endpointMap[apiEndpointKey(finding)], finding)
		}
	}
	for _, item := range configResources {
		if finding, ok := classifyAPIEndpoint(item, base, item, "config_resource"); ok {
			endpointMap[apiEndpointKey(finding)] = mergeAPIEndpointFindings(endpointMap[apiEndpointKey(finding)], finding)
		}
	}

	specCandidates := make(map[string]struct{})
	for _, raw := range knownSpecPaths {
		if candidate, ok := resolveSameHostURL(base, raw); ok {
			specCandidates[candidate] = struct{}{}
		}
	}
	for _, source := range append(append([]string{}, discoveredURLs...), configResources...) {
		if looksLikeOpenAPISpecURL(source) {
			if candidate, ok := resolveSameHostURL(base, source); ok {
				specCandidates[candidate] = struct{}{}
			}
		}
	}

	for candidate := range specCandidates {
		spec, endpoints, err := fetchOpenAPISpec(candidate, base, client)
		if err != nil {
			continue
		}
		specMap[candidate] = mergeAPISpecFindings(specMap[candidate], spec)
		for _, endpoint := range endpoints {
			endpointMap[apiEndpointKey(endpoint)] = mergeAPIEndpointFindings(endpointMap[apiEndpointKey(endpoint)], endpoint)
		}
	}

	endpoints := make([]APIEndpointFinding, 0, len(endpointMap))
	for _, item := range endpointMap {
		item.SourceURLs = uniqueStrings(item.SourceURLs)
		item.Evidence = uniqueStrings(item.Evidence)
		endpoints = append(endpoints, item)
	}
	endpoints = enrichAPIEndpointStatuses(endpoints, client)
	sortAPIEndpointFindings(endpoints)

	specs := make([]APISpecFinding, 0, len(specMap))
	for _, item := range specMap {
		item.SourceURLs = uniqueStrings(item.SourceURLs)
		item.Evidence = uniqueStrings(item.Evidence)
		specs = append(specs, item)
	}
	sortAPISpecFindings(specs)

	return endpoints, specs, nil
}

// HuntAPISurface runs the first-class API Hunter workflow. It keeps the
// existing passive API discovery as the seed, then optionally adds safe-active
// endpoint probing and wordlist candidates without sending mutation requests.
func HuntAPISurface(req APIHuntRequest, client *http.Client) (*APIHuntResult, error) {
	req = normalizeAPIHuntRequest(req)
	if client == nil {
		client = core.CreateHTTPClientWithCookies(req.Timeout, req.AuthCookies)
	}

	base, err := url.Parse(req.StartURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing base URL: %w", err)
	}

	result := &APIHuntResult{
		StartURL:      req.StartURL,
		Mode:          req.Mode,
		SourceSummary: map[string]int{},
	}

	discoveredURLs := uniqueStrings(append([]string{req.StartURL}, req.DiscoveredURLs...))
	if len(req.DiscoveredURLs) == 0 {
		discoveredURLs = uniqueStrings(append(discoveredURLs, collectSeedURLs(req.StartURL, client)...))
	}

	var configResources []string
	if resp, err := client.Get(req.StartURL); err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html") || len(body) > 0 {
			analysis := analyzeHTMLClientSurface(req.StartURL, string(body), client)
			discoveredURLs = uniqueStrings(append(discoveredURLs, analysis.Endpoints...))
			configResources = uniqueStrings(append(configResources, analysis.ConfigResources...))
			result.APIEndpoints = mergeAPIEndpointList(result.APIEndpoints, analysis.APIEndpoints)
			result.APISpecs = mergeAPISpecList(result.APISpecs, analysis.APISpecs)
		}
	} else {
		result.StageErrors = append(result.StageErrors, "fetch_start_url: "+err.Error())
	}

	passiveEndpoints, passiveSpecs, err := DiscoverAPISurface(req.StartURL, discoveredURLs, configResources, client)
	if err != nil {
		result.StageErrors = append(result.StageErrors, "passive_discovery: "+err.Error())
	} else {
		result.APIEndpoints = mergeAPIEndpointList(result.APIEndpoints, passiveEndpoints)
		result.APISpecs = mergeAPISpecList(result.APISpecs, passiveSpecs)
	}

	for _, candidate := range apiWordlistCandidates(base, req.Wordlist) {
		if len(result.APIEndpoints) >= req.MaxCandidates {
			break
		}
		if finding, ok := classifyAPIEndpoint(candidate, base, req.StartURL, "api_hunter_wordlist"); ok {
			result.APIEndpoints = mergeAPIEndpointList(result.APIEndpoints, []APIEndpointFinding{finding})
		}
	}

	if req.Mode == "safe-active" {
		result.APIEndpoints = probeAPIEndpointsSafe(result.APIEndpoints, client, req.MaxCandidates)
	}

	result.APIEndpoints = finalizeAPIEndpointList(result.APIEndpoints)
	result.Parameters = aggregateAPIParameters(result.APIEndpoints)
	result.APISpecs = finalizeAPISpecCoverage(result.APISpecs, result.APIEndpoints)
	result.SourceSummary = summarizeAPISources(result.APIEndpoints, result.APISpecs)
	result.Counts = map[string]int{
		"api_endpoints": len(result.APIEndpoints),
		"api_specs":     len(result.APISpecs),
		"parameters":    len(result.Parameters),
		"stage_errors":  len(result.StageErrors),
	}
	return result, nil
}

func analyzeHTMLClientSurface(pageURL string, body string, client *http.Client) *clientSurfaceAnalysis {
	result := newClientSurfaceAnalysis()
	result.ConfigResources = append(result.ConfigResources, extractConfigResourcesFromHTML(pageURL, body)...)

	for _, finding := range detectSecretFindings(body, pageURL, "html") {
		addSecretFinding(result, finding)
	}
	for _, endpoint := range extractAPIEndpointsFromContent(body, pageURL, pageURL, "html") {
		addAPIEndpointFinding(result, endpoint)
	}

	inlineScriptRegex := regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`)
	for _, match := range inlineScriptRegex.FindAllStringSubmatch(body, -1) {
		if len(match) < 2 || strings.TrimSpace(match[1]) == "" {
			continue
		}
		mergeClientSurface(result, analyzeJSLikeContent(match[1], pageURL+"#inline", "inline_js", pageURL))
	}

	scriptURLs, err := extractScriptURLs(pageURL, strings.NewReader(body))
	if err == nil {
		result.ScriptURLs = append(result.ScriptURLs, scriptURLs...)
	}

	for _, scriptURL := range uniqueStrings(scriptURLs) {
		resp, err := client.Get(scriptURL)
		if err != nil {
			continue
		}
		content, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		mergeClientSurface(result, analyzeJSLikeContent(string(content), scriptURL, "external_js", pageURL))
	}

	for _, resourceURL := range uniqueStrings(result.ConfigResources) {
		resp, err := client.Get(resourceURL)
		if err != nil {
			continue
		}
		content, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}

		sourceKind := "config_js"
		if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "json") ||
			strings.HasSuffix(strings.ToLower(resourceURL), ".json") {
			sourceKind = "config_json"
		}
		mergeClientSurface(result, analyzeJSLikeContent(string(content), resourceURL, sourceKind, pageURL))
	}

	apiSeeds := append([]string{pageURL}, result.ConfigResources...)
	for _, finding := range result.APIEndpoints {
		apiSeeds = append(apiSeeds, finding.URL)
	}
	endpoints, specs, err := DiscoverAPISurface(pageURL, uniqueStrings(apiSeeds), uniqueStrings(result.ConfigResources), client)
	if err == nil {
		for _, endpoint := range endpoints {
			addAPIEndpointFinding(result, endpoint)
		}
		for _, spec := range specs {
			addAPISpecFinding(result, spec)
		}
	}

	result.APIEndpoints = enrichAPIEndpointStatuses(result.APIEndpoints, client)
	finalizeClientSurfaceAnalysis(result)
	return result
}

func analyzeJSLikeContent(content string, sourceURL string, sourceKind string, resolutionBase string) *clientSurfaceAnalysis {
	result := newClientSurfaceAnalysis()

	endpoints, legacySecrets, params := analyzeJSContent(content)
	for _, endpoint := range endpoints {
		result.Endpoints = append(result.Endpoints, endpoint)
	}
	for category, matches := range legacySecrets {
		for _, match := range matches {
			addLegacySecret(result, category, match)
		}
	}
	for _, param := range params {
		if !contains(result.HiddenParams, param) {
			result.HiddenParams = append(result.HiddenParams, param)
		}
		mergeRichParam(result.ParamDetails, param, RichParamDetail{
			Sources:      []string{sourceURL},
			SourceTypes:  []ParamSource{SourceJSFile},
			InferredType: TypeUnknown,
		})
	}

	for _, finding := range detectSecretFindings(content, sourceURL, sourceKind) {
		addSecretFinding(result, finding)
	}

	result.ConfigResources = append(result.ConfigResources, extractConfigResourcesFromContent(sourceURL, resolutionBase, content)...)

	for _, endpoint := range extractAPIEndpointsFromContent(content, sourceURL, resolutionBase, sourceKind) {
		addAPIEndpointFinding(result, endpoint)
	}

	finalizeClientSurfaceAnalysis(result)
	return result
}

func detectSecretFindings(content string, sourceURL string, sourceKind string) []SecretFinding {
	var findings []SecretFinding
	seen := make(map[string]struct{})

	for category, pattern := range secretPatterns {
		for _, match := range pattern.FindAllString(content, -1) {
			key := strings.ToLower(category) + "|" + match + "|" + sourceURL + "|" + sourceKind
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, SecretFinding{
				Category:   category,
				Value:      match,
				SourceURL:  sourceURL,
				SourceKind: sourceKind,
				Evidence: []string{
					"pattern:" + category,
				},
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].SourceURL == findings[j].SourceURL {
			if findings[i].Category == findings[j].Category {
				return findings[i].Value < findings[j].Value
			}
			return findings[i].Category < findings[j].Category
		}
		return findings[i].SourceURL < findings[j].SourceURL
	})

	return findings
}

func extractConfigResourcesFromHTML(pageURL string, body string) []string {
	base, err := url.Parse(core.EnsureProtocol(pageURL))
	if err != nil {
		return nil
	}

	results := make(map[string]struct{})
	addCandidate := func(candidate string) {
		if normalized, ok := resolveSameHostURL(base, candidate); ok {
			results[normalized] = struct{}{}
		}
	}

	doc, err := html.Parse(strings.NewReader(body))
	if err == nil {
		var walk func(*html.Node)
		walk = func(n *html.Node) {
			if n.Type == html.ElementNode {
				attrs := getAttrs(n)
				switch n.Data {
				case "script":
					if src := strings.TrimSpace(attrs["src"]); src != "" && looksLikeConfigResource(src) {
						addCandidate(src)
					}
				case "link":
					if rel := strings.ToLower(strings.TrimSpace(attrs["rel"])); rel == "manifest" {
						if href := strings.TrimSpace(attrs["href"]); href != "" {
							addCandidate(href)
						}
					} else if href := strings.TrimSpace(attrs["href"]); href != "" && looksLikeConfigResource(href) {
						addCandidate(href)
					}
				case "a":
					if href := strings.TrimSpace(attrs["href"]); href != "" && looksLikeConfigResource(href) {
						addCandidate(href)
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
		walk(doc)
	}

	for _, match := range configResourcePattern.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 {
			addCandidate(match[1])
		}
	}

	return mapKeys(results)
}

func extractConfigResourcesFromContent(sourceURL string, resolutionBase string, content string) []string {
	base, err := url.Parse(core.EnsureProtocol(resolutionBase))
	if err != nil {
		base, err = url.Parse(core.EnsureProtocol(sourceURL))
		if err != nil {
			return nil
		}
	}

	results := make(map[string]struct{})
	for _, match := range configResourcePattern.FindAllStringSubmatch(content, -1) {
		if len(match) < 2 {
			continue
		}
		if normalized, ok := resolveSameHostURL(base, match[1]); ok {
			results[normalized] = struct{}{}
		}
	}
	return mapKeys(results)
}

func extractAPIEndpointsFromContent(content string, sourceURL string, resolutionBase string, sourceKind string) []APIEndpointFinding {
	base, err := url.Parse(core.EnsureProtocol(resolutionBase))
	if err != nil {
		base, err = url.Parse(core.EnsureProtocol(sourceURL))
		if err != nil {
			return nil
		}
	}

	seen := make(map[string]APIEndpointFinding)
	addCandidate := func(candidate string, evidence string) {
		if finding, ok := classifyAPIEndpoint(candidate, base, sourceURL, evidence); ok {
			seen[apiEndpointKey(finding)] = mergeAPIEndpointFindings(seen[apiEndpointKey(finding)], finding)
		}
	}

	for _, item := range endpointRegex.FindAllStringSubmatch(content, -1) {
		if len(item) > 1 {
			addCandidate(item[1], sourceKind)
		}
	}
	for _, item := range apiURLWithQueryPattern.FindAllStringSubmatch(content, -1) {
		if len(item) > 1 {
			addCandidate(item[1], sourceKind)
		}
	}
	for _, item := range graphQLPathPattern.FindAllStringSubmatch(content, -1) {
		if len(item) > 1 {
			addCandidate(item[1], sourceKind)
		}
	}
	for _, item := range restVersionedPattern.FindAllStringSubmatch(content, -1) {
		if len(item) > 1 {
			addCandidate(item[1], sourceKind)
		}
	}
	for _, item := range restPrefixedPattern.FindAllStringSubmatch(content, -1) {
		if len(item) > 1 {
			addCandidate(item[1], sourceKind)
		}
	}

	endpoints := make([]APIEndpointFinding, 0, len(seen))
	for _, item := range seen {
		endpoints = append(endpoints, item)
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].URL == endpoints[j].URL {
			return endpoints[i].Method < endpoints[j].Method
		}
		return endpoints[i].URL < endpoints[j].URL
	})
	return endpoints
}

func fetchOpenAPISpec(specURL string, base *url.URL, client *http.Client) (APISpecFinding, []APIEndpointFinding, error) {
	resp, err := client.Get(specURL)
	if err != nil {
		return APISpecFinding{}, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return APISpecFinding{}, nil, fmt.Errorf("unexpected status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return APISpecFinding{}, nil, err
	}

	var doc openAPISpecDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		if yerr := yaml.Unmarshal(body, &doc); yerr != nil {
			return APISpecFinding{}, nil, yerr
		}
	}
	if doc.OpenAPI == "" && doc.Swagger == "" {
		return APISpecFinding{}, nil, fmt.Errorf("not an OpenAPI/Swagger document")
	}
	if len(doc.Paths) == 0 {
		return APISpecFinding{}, nil, fmt.Errorf("spec has no paths")
	}

	format := "json"
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "yaml") ||
		strings.HasSuffix(strings.ToLower(specURL), ".yaml") {
		format = "yaml"
	}

	spec := APISpecFinding{
		URL:         specURL,
		APIType:     "openapi",
		Format:      format,
		Title:       doc.Info.Title,
		Version:     doc.Info.Version,
		StatusCode:  resp.StatusCode,
		Status:      normalizeAPIHTTPStatus(resp.StatusCode, resp.Status),
		ContentType: resp.Header.Get("Content-Type"),
		SourceURLs:  []string{specURL},
		Evidence:    []string{"openapi_spec"},
	}

	var endpoints []APIEndpointFinding
	for rawPath, methods := range doc.Paths {
		for method, operation := range methods {
			method = strings.ToUpper(strings.TrimSpace(method))
			if _, ok := openAPIHTTPMethods[method]; !ok {
				continue
			}
			fullURL := buildSpecEndpointURL(base, rawPath)
			params := openAPIParameters(operation.Parameters, specURL)
			params = append(params, pathParameters(rawPath, specURL)...)
			endpoints = append(endpoints, APIEndpointFinding{
				URL:         fullURL,
				Path:        rawPath,
				Method:      method,
				APIType:     "openapi",
				Version:     extractVersion(rawPath),
				Confidence:  0.98,
				SourceURLs:  []string{specURL},
				SourceKinds: []string{"openapi_spec"},
				Evidence:    []string{"openapi_spec"},
				Parameters:  params,
			})
			spec.EndpointCount++
		}
	}

	return spec, endpoints, nil
}

func buildSpecEndpointURL(base *url.URL, rawPath string) string {
	if parsed, err := url.Parse(rawPath); err == nil && parsed.IsAbs() {
		return parsed.String()
	}
	clean := rawPath
	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}
	return base.ResolveReference(&url.URL{Path: clean}).String()
}

func classifyAPIEndpoint(candidate string, base *url.URL, sourceURL string, evidence string) (APIEndpointFinding, bool) {
	resolved, ok := resolveSameHostURL(base, candidate)
	if !ok {
		return APIEndpointFinding{}, false
	}
	if looksLikeOpenAPISpecURL(resolved) {
		return APIEndpointFinding{}, false
	}

	parsed, err := url.Parse(resolved)
	if err != nil {
		return APIEndpointFinding{}, false
	}
	apiType := ""
	switch {
	case strings.Contains(strings.ToLower(parsed.Path), "graphql"):
		apiType = "graphql"
	case restVersionedPattern.MatchString(parsed.Path), restPrefixedPattern.MatchString(parsed.Path):
		apiType = "rest"
	default:
		return APIEndpointFinding{}, false
	}

	return APIEndpointFinding{
		URL:         resolved,
		Path:        parsed.Path,
		Method:      "",
		APIType:     apiType,
		Version:     extractVersion(parsed.Path),
		Confidence:  confidenceForAPIEvidence(apiType, evidence),
		SourceURLs:  []string{sourceURL},
		SourceKinds: []string{evidence},
		Evidence:    []string{evidence},
		Parameters:  endpointParameters(resolved, parsed.Path, sourceURL),
	}, true
}

func looksLikeConfigResource(candidate string) bool {
	lowered := strings.ToLower(candidate)
	if strings.HasPrefix(lowered, "javascript:") || strings.HasPrefix(lowered, "data:") {
		return false
	}
	for _, keyword := range []string{"config", "settings", "env", "runtime", "manifest", "app-config", "site-config"} {
		if strings.Contains(lowered, keyword) {
			return true
		}
	}
	return false
}

func looksLikeOpenAPISpecURL(candidate string) bool {
	return openAPISpecPattern.MatchString(strings.ToLower(candidate))
}

func resolveSameHostURL(base *url.URL, candidate string) (string, bool) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", false
	}
	if strings.HasPrefix(candidate, "#") {
		return "", false
	}

	parsed, err := url.Parse(candidate)
	if err != nil {
		return "", false
	}
	resolved := base.ResolveReference(parsed)
	if resolved.Hostname() == "" || !strings.EqualFold(resolved.Hostname(), base.Hostname()) {
		return "", false
	}

	resolved.Fragment = ""
	resolved.Host = strings.ToLower(resolved.Host)
	if resolved.Path == "" {
		resolved.Path = "/"
	}

	return resolved.String(), true
}

func extractVersion(rawPath string) string {
	match := versionSegmentPattern.FindStringSubmatch(rawPath)
	if len(match) > 1 {
		return strings.ToLower(match[1])
	}
	return ""
}

func newClientSurfaceAnalysis() *clientSurfaceAnalysis {
	return &clientSurfaceAnalysis{
		LegacySecrets:  make(map[string][]string),
		ParamDetails:   make(map[string]RichParamDetail),
		KeywordMatches: make(map[string][]string),
	}
}

func finalizeClientSurfaceAnalysis(result *clientSurfaceAnalysis) {
	result.ScriptURLs = uniqueStrings(result.ScriptURLs)
	result.ConfigResources = uniqueStrings(result.ConfigResources)
	result.Endpoints = uniqueStrings(result.Endpoints)
	result.HiddenParams = uniqueStrings(result.HiddenParams)
	for category, matches := range result.LegacySecrets {
		result.LegacySecrets[category] = uniqueStrings(matches)
	}
	sort.Slice(result.SecretFindings, func(i, j int) bool {
		if result.SecretFindings[i].SourceURL == result.SecretFindings[j].SourceURL {
			if result.SecretFindings[i].Category == result.SecretFindings[j].Category {
				return result.SecretFindings[i].Value < result.SecretFindings[j].Value
			}
			return result.SecretFindings[i].Category < result.SecretFindings[j].Category
		}
		return result.SecretFindings[i].SourceURL < result.SecretFindings[j].SourceURL
	})
	sortAPIEndpointFindings(result.APIEndpoints)
	sortAPISpecFindings(result.APISpecs)
}

func mergeClientSurface(dst *clientSurfaceAnalysis, src *clientSurfaceAnalysis) {
	if src == nil {
		return
	}
	dst.ScriptURLs = append(dst.ScriptURLs, src.ScriptURLs...)
	dst.ConfigResources = append(dst.ConfigResources, src.ConfigResources...)
	dst.Endpoints = append(dst.Endpoints, src.Endpoints...)
	dst.HiddenParams = append(dst.HiddenParams, src.HiddenParams...)
	for category, matches := range src.LegacySecrets {
		for _, match := range matches {
			addLegacySecret(dst, category, match)
		}
	}
	for _, finding := range src.SecretFindings {
		addSecretFinding(dst, finding)
	}
	for _, endpoint := range src.APIEndpoints {
		addAPIEndpointFinding(dst, endpoint)
	}
	for _, spec := range src.APISpecs {
		addAPISpecFinding(dst, spec)
	}
	for name, detail := range src.ParamDetails {
		mergeRichParam(dst.ParamDetails, name, detail)
	}
	finalizeClientSurfaceAnalysis(dst)
}

func addLegacySecret(dst *clientSurfaceAnalysis, category string, value string) {
	if dst.LegacySecrets == nil {
		dst.LegacySecrets = make(map[string][]string)
	}
	if !contains(dst.LegacySecrets[category], value) {
		dst.LegacySecrets[category] = append(dst.LegacySecrets[category], value)
	}
}

func addSecretFinding(dst *clientSurfaceAnalysis, finding SecretFinding) {
	key := secretFindingKey(finding)
	for i, existing := range dst.SecretFindings {
		if secretFindingKey(existing) == key {
			dst.SecretFindings[i].Evidence = uniqueStrings(append(dst.SecretFindings[i].Evidence, finding.Evidence...))
			return
		}
	}
	dst.SecretFindings = append(dst.SecretFindings, finding)
	addLegacySecret(dst, finding.Category, finding.Value)
}

func addAPIEndpointFinding(dst *clientSurfaceAnalysis, finding APIEndpointFinding) {
	key := apiEndpointKey(finding)
	for i, existing := range dst.APIEndpoints {
		if apiEndpointKey(existing) == key {
			dst.APIEndpoints[i] = mergeAPIEndpointFindings(existing, finding)
			return
		}
	}
	dst.APIEndpoints = append(dst.APIEndpoints, finding)
	if finding.URL != "" && !contains(dst.Endpoints, finding.URL) {
		dst.Endpoints = append(dst.Endpoints, finding.URL)
	}
}

func addAPISpecFinding(dst *clientSurfaceAnalysis, finding APISpecFinding) {
	for i, existing := range dst.APISpecs {
		if existing.URL == finding.URL {
			dst.APISpecs[i] = mergeAPISpecFindings(existing, finding)
			return
		}
	}
	dst.APISpecs = append(dst.APISpecs, finding)
}

func mergeAPIEndpointFindings(existing APIEndpointFinding, incoming APIEndpointFinding) APIEndpointFinding {
	if existing.URL == "" {
		incoming.SourceURLs = uniqueStrings(incoming.SourceURLs)
		incoming.Evidence = uniqueStrings(incoming.Evidence)
		incoming.SourceKinds = uniqueStrings(incoming.SourceKinds)
		incoming.Parameters = mergeAPIParameters(nil, incoming.Parameters)
		return incoming
	}
	existing.SourceURLs = uniqueStrings(append(existing.SourceURLs, incoming.SourceURLs...))
	existing.Evidence = uniqueStrings(append(existing.Evidence, incoming.Evidence...))
	if existing.Path == "" {
		existing.Path = incoming.Path
	}
	if existing.Method == "" {
		existing.Method = incoming.Method
	}
	if existing.Version == "" {
		existing.Version = incoming.Version
	}
	if existing.APIType == "" {
		existing.APIType = incoming.APIType
	}
	if existing.StatusCode == 0 && incoming.StatusCode != 0 {
		existing.StatusCode = incoming.StatusCode
	}
	if existing.Status == "" && incoming.Status != "" {
		existing.Status = incoming.Status
	}
	if existing.ContentType == "" {
		existing.ContentType = incoming.ContentType
	}
	existing.AuthRequired = existing.AuthRequired || incoming.AuthRequired
	if incoming.Confidence > existing.Confidence {
		existing.Confidence = incoming.Confidence
	}
	existing.SourceKinds = uniqueStrings(append(existing.SourceKinds, incoming.SourceKinds...))
	existing.Parameters = mergeAPIParameters(existing.Parameters, incoming.Parameters)
	return existing
}

func mergeAPISpecFindings(existing APISpecFinding, incoming APISpecFinding) APISpecFinding {
	if existing.URL == "" {
		incoming.SourceURLs = uniqueStrings(incoming.SourceURLs)
		incoming.Evidence = uniqueStrings(incoming.Evidence)
		return incoming
	}
	existing.SourceURLs = uniqueStrings(append(existing.SourceURLs, incoming.SourceURLs...))
	existing.Evidence = uniqueStrings(append(existing.Evidence, incoming.Evidence...))
	if existing.Format == "" {
		existing.Format = incoming.Format
	}
	if existing.Title == "" {
		existing.Title = incoming.Title
	}
	if existing.Version == "" {
		existing.Version = incoming.Version
	}
	if existing.StatusCode == 0 && incoming.StatusCode != 0 {
		existing.StatusCode = incoming.StatusCode
	}
	if existing.Status == "" && incoming.Status != "" {
		existing.Status = incoming.Status
	}
	if existing.ContentType == "" {
		existing.ContentType = incoming.ContentType
	}
	if incoming.EndpointCount > existing.EndpointCount {
		existing.EndpointCount = incoming.EndpointCount
	}
	if incoming.DiscoveredEndpointCount > existing.DiscoveredEndpointCount {
		existing.DiscoveredEndpointCount = incoming.DiscoveredEndpointCount
	}
	if incoming.CoveragePercent > existing.CoveragePercent {
		existing.CoveragePercent = incoming.CoveragePercent
	}
	return existing
}

func apiEndpointKey(finding APIEndpointFinding) string {
	return strings.ToLower(finding.APIType) + "|" + strings.ToUpper(finding.Method) + "|" + strings.ToLower(finding.URL)
}

func secretFindingKey(finding SecretFinding) string {
	return strings.ToLower(finding.Category) + "|" + finding.Value + "|" + finding.SourceURL + "|" + finding.SourceKind
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, item := range values {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func mapKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func mergeStringListUnique(existing []string, incoming []string) []string {
	return uniqueStrings(append(existing, incoming...))
}

func hasSecretFinding(existing []SecretFinding, incoming SecretFinding) bool {
	for _, item := range existing {
		if secretFindingKey(item) == secretFindingKey(incoming) {
			return true
		}
	}
	return false
}

func mergeAPIEndpointList(existing []APIEndpointFinding, incoming []APIEndpointFinding) []APIEndpointFinding {
	merged := make(map[string]APIEndpointFinding, len(existing)+len(incoming))
	for _, item := range existing {
		merged[apiEndpointKey(item)] = mergeAPIEndpointFindings(merged[apiEndpointKey(item)], item)
	}
	for _, item := range incoming {
		merged[apiEndpointKey(item)] = mergeAPIEndpointFindings(merged[apiEndpointKey(item)], item)
	}

	result := make([]APIEndpointFinding, 0, len(merged))
	for _, item := range merged {
		item.SourceURLs = uniqueStrings(item.SourceURLs)
		item.Evidence = uniqueStrings(item.Evidence)
		result = append(result, item)
	}
	sortAPIEndpointFindings(result)
	return result
}

func mergeAPISpecList(existing []APISpecFinding, incoming []APISpecFinding) []APISpecFinding {
	merged := make(map[string]APISpecFinding, len(existing)+len(incoming))
	for _, item := range existing {
		merged[item.URL] = mergeAPISpecFindings(merged[item.URL], item)
	}
	for _, item := range incoming {
		merged[item.URL] = mergeAPISpecFindings(merged[item.URL], item)
	}

	result := make([]APISpecFinding, 0, len(merged))
	for _, item := range merged {
		item.SourceURLs = uniqueStrings(item.SourceURLs)
		item.Evidence = uniqueStrings(item.Evidence)
		result = append(result, item)
	}
	sortAPISpecFindings(result)
	return result
}

func enrichAPIEndpointStatuses(endpoints []APIEndpointFinding, client *http.Client) []APIEndpointFinding {
	if len(endpoints) == 0 || client == nil {
		return endpoints
	}
	type statusResult struct {
		code         int
		status       string
		contentType  string
		authRequired bool
	}
	cache := make(map[string]statusResult, len(endpoints))
	for i := range endpoints {
		if endpoints[i].URL == "" {
			continue
		}
		if cached, ok := cache[endpoints[i].URL]; ok {
			if endpoints[i].StatusCode == 0 && cached.code != 0 {
				endpoints[i].StatusCode = cached.code
			}
			if endpoints[i].Status == "" && cached.status != "" {
				endpoints[i].Status = cached.status
			}
			if endpoints[i].ContentType == "" {
				endpoints[i].ContentType = cached.contentType
			}
			endpoints[i].AuthRequired = endpoints[i].AuthRequired || cached.authRequired
			continue
		}
		req, err := http.NewRequest(http.MethodGet, endpoints[i].URL, nil)
		if err != nil {
			cache[endpoints[i].URL] = statusResult{}
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			cache[endpoints[i].URL] = statusResult{}
			continue
		}
		_ = resp.Body.Close()
		cached := statusResult{
			code:         resp.StatusCode,
			status:       normalizeAPIHTTPStatus(resp.StatusCode, resp.Status),
			contentType:  resp.Header.Get("Content-Type"),
			authRequired: responseLooksAuthRequired(resp),
		}
		cache[endpoints[i].URL] = cached
		if endpoints[i].StatusCode == 0 {
			endpoints[i].StatusCode = cached.code
		}
		if endpoints[i].Status == "" {
			endpoints[i].Status = cached.status
		}
		if endpoints[i].ContentType == "" {
			endpoints[i].ContentType = cached.contentType
		}
		endpoints[i].AuthRequired = endpoints[i].AuthRequired || cached.authRequired
		if endpoints[i].Confidence == 0 {
			endpoints[i].Confidence = confidenceForAPIStatus(endpoints[i].APIType, resp.StatusCode)
		}
	}
	return endpoints
}

func normalizeAPIHTTPStatus(statusCode int, status string) string {
	status = strings.TrimSpace(status)
	if statusCode == 0 {
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

func sortAPIEndpointFindings(findings []APIEndpointFinding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].URL == findings[j].URL {
			if findings[i].Method == findings[j].Method {
				return findings[i].APIType < findings[j].APIType
			}
			return findings[i].Method < findings[j].Method
		}
		return findings[i].URL < findings[j].URL
	})
}

func sortAPISpecFindings(findings []APISpecFinding) {
	sort.Slice(findings, func(i, j int) bool { return findings[i].URL < findings[j].URL })
}

func normalizeAPIHuntRequest(req APIHuntRequest) APIHuntRequest {
	req.StartURL = core.EnsureProtocol(strings.TrimSpace(req.StartURL))
	req.Mode = strings.ToLower(strings.TrimSpace(req.Mode))
	if req.Mode == "" {
		req.Mode = "safe-active"
	}
	if req.Mode != "passive" && req.Mode != "safe-active" {
		req.Mode = "safe-active"
	}
	if req.Timeout <= 0 {
		req.Timeout = 10
	}
	if req.Threads <= 0 {
		req.Threads = 10
	}
	if req.MaxCandidates <= 0 {
		req.MaxCandidates = 250
	}
	if req.WordlistFile != "" {
		if data, err := os.ReadFile(req.WordlistFile); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					req.Wordlist = append(req.Wordlist, line)
				}
			}
		}
	}
	if len(req.Wordlist) == 0 {
		req.Wordlist = defaultAPIHunterWordlist()
	}
	return req
}

func defaultAPIHunterWordlist() []string {
	return []string{
		"/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/services",
		"/graphql", "/graphiql", "/playground", "/openapi.json", "/swagger.json",
		"/swagger.yaml", "/api-docs", "/v2/api-docs", "/v3/api-docs",
		"/swagger-ui", "/swagger-ui/index.html", "/redoc", "/docs",
		"/actuator", "/actuator/health", "/health", "/metrics",
	}
}

func apiWordlistCandidates(base *url.URL, wordlist []string) []string {
	results := make(map[string]struct{})
	for _, item := range wordlist {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !strings.HasPrefix(item, "/") {
			item = "/" + item
		}
		if resolved, ok := resolveSameHostURL(base, item); ok {
			results[resolved] = struct{}{}
		}
	}
	return mapKeys(results)
}

func probeAPIEndpointsSafe(endpoints []APIEndpointFinding, client *http.Client, maxCandidates int) []APIEndpointFinding {
	if client == nil || len(endpoints) == 0 {
		return endpoints
	}
	if maxCandidates <= 0 || maxCandidates > len(endpoints) {
		maxCandidates = len(endpoints)
	}
	for i := 0; i < maxCandidates; i++ {
		endpoint := &endpoints[i]
		if endpoint.URL == "" {
			continue
		}
		for _, method := range []string{http.MethodHead, http.MethodOptions, http.MethodGet} {
			req, err := http.NewRequest(method, endpoint.URL, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			_ = resp.Body.Close()
			if endpoint.StatusCode == 0 || method == http.MethodGet {
				endpoint.StatusCode = resp.StatusCode
				endpoint.Status = normalizeAPIHTTPStatus(resp.StatusCode, resp.Status)
				endpoint.ContentType = firstNonEmpty(endpoint.ContentType, resp.Header.Get("Content-Type"))
				endpoint.AuthRequired = endpoint.AuthRequired || responseLooksAuthRequired(resp)
				endpoint.Evidence = uniqueStrings(append(endpoint.Evidence, "safe_probe:"+method))
				endpoint.SourceKinds = uniqueStrings(append(endpoint.SourceKinds, "safe_probe"))
				if endpoint.Confidence == 0 || endpoint.Confidence < confidenceForAPIStatus(endpoint.APIType, resp.StatusCode) {
					endpoint.Confidence = confidenceForAPIStatus(endpoint.APIType, resp.StatusCode)
				}
			}
			if method == http.MethodOptions {
				if allow := resp.Header.Get("Allow"); allow != "" && endpoint.Method == "" {
					endpoint.Evidence = uniqueStrings(append(endpoint.Evidence, "allow:"+allow))
				}
			}
			if resp.StatusCode != http.StatusMethodNotAllowed {
				if endpoint.Method == "" && method == http.MethodGet {
					endpoint.Method = http.MethodGet
				}
				break
			}
		}
	}
	return endpoints
}

func responseLooksAuthRequired(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return true
	}
	return strings.TrimSpace(resp.Header.Get("WWW-Authenticate")) != ""
}

func finalizeAPIEndpointList(endpoints []APIEndpointFinding) []APIEndpointFinding {
	for i := range endpoints {
		if endpoints[i].Confidence == 0 {
			endpoints[i].Confidence = confidenceForAPIStatus(endpoints[i].APIType, endpoints[i].StatusCode)
		}
		endpoints[i].SourceURLs = uniqueStrings(endpoints[i].SourceURLs)
		endpoints[i].SourceKinds = uniqueStrings(endpoints[i].SourceKinds)
		endpoints[i].Evidence = uniqueStrings(endpoints[i].Evidence)
		endpoints[i].Parameters = mergeAPIParameters(nil, endpoints[i].Parameters)
	}
	sortAPIEndpointFindings(endpoints)
	return endpoints
}

func finalizeAPISpecCoverage(specs []APISpecFinding, endpoints []APIEndpointFinding) []APISpecFinding {
	for i := range specs {
		count := 0
		for _, endpoint := range endpoints {
			for _, source := range endpoint.SourceURLs {
				if source == specs[i].URL {
					count++
					break
				}
			}
		}
		specs[i].DiscoveredEndpointCount = count
		if specs[i].EndpointCount > 0 {
			specs[i].CoveragePercent = float64(count) / float64(specs[i].EndpointCount) * 100
			if specs[i].CoveragePercent > 100 {
				specs[i].CoveragePercent = 100
			}
		}
		specs[i].SourceURLs = uniqueStrings(specs[i].SourceURLs)
		specs[i].Evidence = uniqueStrings(specs[i].Evidence)
	}
	sortAPISpecFindings(specs)
	return specs
}

func summarizeAPISources(endpoints []APIEndpointFinding, specs []APISpecFinding) map[string]int {
	summary := map[string]int{}
	for _, endpoint := range endpoints {
		for _, source := range endpoint.SourceKinds {
			summary[source]++
		}
	}
	for _, spec := range specs {
		for _, evidence := range spec.Evidence {
			summary[evidence]++
		}
	}
	return summary
}

func aggregateAPIParameters(endpoints []APIEndpointFinding) []APIParameterFinding {
	merged := map[string]APIParameterFinding{}
	for _, endpoint := range endpoints {
		for _, param := range endpoint.Parameters {
			name := strings.TrimSpace(param.Name)
			if name == "" {
				continue
			}
			key := strings.ToLower(param.In) + "|" + strings.ToLower(name)
			existing := merged[key]
			if existing.Name == "" {
				existing.Name = name
				existing.In = param.In
				existing.Type = param.Type
				existing.Required = param.Required
			}
			if param.Required {
				existing.Required = true
			}
			if existing.Type == "" {
				existing.Type = param.Type
			}
			existing.Endpoints = uniqueStrings(append(existing.Endpoints, endpoint.URL))
			existing.Sources = uniqueStrings(append(existing.Sources, param.Sources...))
			merged[key] = existing
		}
	}
	out := make([]APIParameterFinding, 0, len(merged))
	for _, item := range merged {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].In == out[j].In {
			return out[i].Name < out[j].Name
		}
		return out[i].In < out[j].In
	})
	return out
}

func endpointParameters(rawURL string, rawPath string, source string) []APIParameter {
	var params []APIParameter
	if parsed, err := url.Parse(rawURL); err == nil {
		for name := range parsed.Query() {
			params = append(params, APIParameter{Name: name, In: "query", Sources: []string{source}})
		}
	}
	params = append(params, pathParameters(rawPath, source)...)
	return mergeAPIParameters(nil, params)
}

func pathParameters(rawPath string, source string) []APIParameter {
	var params []APIParameter
	for _, segment := range strings.Split(rawPath, "/") {
		segment = strings.TrimSpace(segment)
		switch {
		case strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}"):
			name := strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}")
			params = append(params, APIParameter{Name: name, In: "path", Required: true, Sources: []string{source}})
		case strings.HasPrefix(segment, ":") && len(segment) > 1:
			params = append(params, APIParameter{Name: strings.TrimPrefix(segment, ":"), In: "path", Required: true, Sources: []string{source}})
		}
	}
	return params
}

func openAPIParameters(params []openAPIParameter, source string) []APIParameter {
	out := make([]APIParameter, 0, len(params))
	for _, param := range params {
		if strings.TrimSpace(param.Name) == "" {
			continue
		}
		out = append(out, APIParameter{
			Name:     param.Name,
			In:       param.In,
			Required: param.Required,
			Type:     schemaType(param.Schema),
			Sources:  []string{source},
		})
	}
	return out
}

func schemaType(schema map[string]interface{}) string {
	if len(schema) == 0 {
		return ""
	}
	if t, ok := schema["type"].(string); ok {
		return t
	}
	return ""
}

func mergeAPIParameters(existing []APIParameter, incoming []APIParameter) []APIParameter {
	merged := make(map[string]APIParameter, len(existing)+len(incoming))
	for _, param := range append(existing, incoming...) {
		name := strings.TrimSpace(param.Name)
		if name == "" {
			continue
		}
		key := strings.ToLower(param.In) + "|" + strings.ToLower(name)
		current := merged[key]
		if current.Name == "" {
			current = param
		} else {
			current.Required = current.Required || param.Required
			if current.Type == "" {
				current.Type = param.Type
			}
			current.Sources = uniqueStrings(append(current.Sources, param.Sources...))
		}
		merged[key] = current
	}
	out := make([]APIParameter, 0, len(merged))
	for _, param := range merged {
		param.Sources = uniqueStrings(param.Sources)
		out = append(out, param)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].In == out[j].In {
			return out[i].Name < out[j].Name
		}
		return out[i].In < out[j].In
	})
	return out
}

func confidenceForAPIEvidence(apiType string, evidence string) float64 {
	switch evidence {
	case "openapi_spec":
		return 0.98
	case "api_hunter_wordlist":
		return 0.45
	case "html", "inline_js", "external_js", "config_js", "config_json":
		return 0.78
	case "discovered_url", "config_resource":
		return 0.68
	default:
		if apiType == "graphql" {
			return 0.72
		}
		return 0.60
	}
}

func confidenceForAPIStatus(apiType string, statusCode int) float64 {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return 0.88
	case statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden:
		return 0.82
	case statusCode == http.StatusBadRequest && apiType == "graphql":
		return 0.86
	case statusCode >= 300 && statusCode < 500:
		return 0.65
	case statusCode >= 500:
		return 0.55
	default:
		return 0.50
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func maskSecretValue(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}

func classifyConfigKind(resourceURL string, contentType string) string {
	loweredURL := strings.ToLower(resourceURL)
	loweredType := strings.ToLower(contentType)
	switch {
	case strings.Contains(loweredType, "json"), strings.HasSuffix(loweredURL, ".json"), path.Base(loweredURL) == "manifest":
		return "config_json"
	default:
		return "config_js"
	}
}
