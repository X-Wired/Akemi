package vuln

import (
	core "Akemi/internal/core"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// =============================================================
// ── YAML TEMPLATE DATA STRUCTURES ───────────────────────────
// =============================================================

// ProbeTemplate represents a parsed YAML probe definition.
type ProbeTemplate struct {
	ID           string        `yaml:"id"`
	Disabled     bool          `yaml:"disabled,omitempty"`
	Info         TemplateInfo  `yaml:"info"`
	Protocol     string        `yaml:"protocol,omitempty"`     // http | tcp
	Ports        []string      `yaml:"ports,omitempty"`        // e.g. ["80", "443", "1-1024"]
	ProbeString  string        `yaml:"probe_string,omitempty"` // payload to elicit response on tcp
	Inject       string        `yaml:"inject"`                 // query_params | body | headers | path | cookie
	Detection    string        `yaml:"detection"`              // pattern | time | status_diff | oob | header_check | banner
	HeaderNames  []string      `yaml:"header_names,omitempty"`
	Payloads     []string      `yaml:"payloads,omitempty"`
	Matchers     Matchers      `yaml:"matchers"`
	TimePayloads *TimePayloads `yaml:"time_payloads,omitempty"`
	OOBPayloads  []string      `yaml:"oob_payloads,omitempty"`
}

// TemplateInfo holds metadata about a probe template.
type TemplateInfo struct {
	Name        string   `yaml:"name"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
	Author      string   `yaml:"author"`
}

// Matchers defines how to confirm a vulnerability.
type Matchers struct {
	BodyPatterns   []string          `yaml:"body_patterns,omitempty"`
	BannerPatterns []string          `yaml:"banner_patterns,omitempty"`
	StatusCodes    []int             `yaml:"status_codes,omitempty"`
	Headers        map[string]string `yaml:"headers,omitempty"` // header_name -> expected_substring
	CookieFlags    []string          `yaml:"cookie_flags,omitempty"`
}

// TimePayloads holds time-based detection settings.
type TimePayloads struct {
	DelaySeconds float64  `yaml:"delay_seconds"`
	Payloads     []string `yaml:"payloads"`
}

// =============================================================
// ── TEMPLATE LOADING ────────────────────────────────────────
// =============================================================

// LoadTemplates reads all .yml/.yaml files from a directory (recursively) and returns parsed templates.
func LoadTemplates(dir string) ([]ProbeTemplate, error) {
	var templates []ProbeTemplate
	dir = core.ResolveProbeTemplateDir(dir)

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible paths
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".yml") && !strings.HasSuffix(d.Name(), ".yaml") {
			return nil
		}

		tmpl, err := loadSingleTemplate(path)
		if err != nil {
			log.Printf("[TemplateEngine] Warning: skipping %s — %v", path, err)
			return nil
		}
		if tmpl.Disabled {
			return nil
		}
		templates = append(templates, *tmpl)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error walking probe directory %s: %w", dir, err)
	}

	return templates, nil
}

// loadSingleTemplate parses a single YAML template file.
func loadSingleTemplate(path string) (*ProbeTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	var tmpl ProbeTemplate
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("error parsing YAML: %w", err)
	}

	if tmpl.ID == "" {
		return nil, fmt.Errorf("template missing required 'id' field")
	}
	if tmpl.Info.Name == "" {
		return nil, fmt.Errorf("template %s missing required 'info.name' field", tmpl.ID)
	}

	// Default values
	if tmpl.Protocol == "" {
		tmpl.Protocol = "http"
	}
	if tmpl.Inject == "" && tmpl.Protocol == "http" {
		tmpl.Inject = "query_params"
	}
	if tmpl.Detection == "" && tmpl.Protocol == "http" {
		tmpl.Detection = "pattern"
	}
	if tmpl.Detection == "" && tmpl.Protocol == "tcp" {
		tmpl.Detection = "banner"
	}
	if tmpl.Info.Severity == "" {
		tmpl.Info.Severity = "medium"
	}

	return &tmpl, nil
}

// FilterTemplates returns only templates matching the given tags or IDs.
// If tags is empty & ids is empty, returns all templates.
func FilterTemplates(templates []ProbeTemplate, tags []string, ids []string) []ProbeTemplate {
	if len(tags) == 0 && len(ids) == 0 {
		return templates
	}

	var filtered []ProbeTemplate
	for _, tmpl := range templates {
		// Check ID match
		for _, id := range ids {
			if strings.EqualFold(tmpl.ID, id) {
				filtered = append(filtered, tmpl)
				goto next
			}
		}
		// Check tag match
		for _, tag := range tags {
			for _, tmplTag := range tmpl.Info.Tags {
				if strings.EqualFold(tag, tmplTag) {
					filtered = append(filtered, tmpl)
					goto next
				}
			}
			// Also match severity as a tag
			if strings.EqualFold(tag, tmpl.Info.Severity) {
				filtered = append(filtered, tmpl)
				goto next
			}
		}
	next:
	}
	return filtered
}

// ListTemplates prints a formatted list of all available templates.
func ListTemplates(templates []ProbeTemplate) {
	fmt.Printf("\n%-25s %-40s %-8s %s\n", "ID", "NAME", "SEVERITY", "TAGS")
	fmt.Println(strings.Repeat("-", 100))
	for _, t := range templates {
		fmt.Printf("%-25s %-40s %-8s %s\n",
			t.ID,
			t.Info.Name,
			strings.ToUpper(t.Info.Severity),
			strings.Join(t.Info.Tags, ", "),
		)
	}
	fmt.Printf("\nTotal: %d templates\n", len(templates))
}

// =============================================================
// ── TEMPLATE EXECUTION ──────────────────────────────────────
// =============================================================

// ExecuteAllTemplates runs all loaded templates against a URL, probing each
// query parameter. Returns aggregated findings.
// If targetCtx is non-nil (from prior fingerprinting), it is used to display
// context info; template prioritization will consume it in Phase 2.
func ExecuteAllTemplates(
	templates []ProbeTemplate,
	rawURL string,
	candidateParams []string,
	cfg ProbeConfig,
	targetCtx *core.TargetContext,
) ([]VulnFinding, error) {

	rawURL = core.EnsureProtocol(rawURL)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing URL: %w", err)
	}

	queryParams := parsed.Query()
	paramNames := mergeParamNames(queryParams, candidateParams)
	baseURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, parsed.Path)
	client := core.CreateHTTPClient(cfg.Timeout)

	// ── Adaptive prioritization ───────────────────────────
	if cfg.Prioritize && targetCtx != nil && len(templates) > 1 {
		templates = PrioritizeTemplates(templates, targetCtx, paramNames, !cfg.Quiet)
	}

	var findings []VulnFinding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Threads)

	totalProbes := len(templates)
	if len(paramNames) > 0 {
		totalProbes *= len(paramNames)
	}
	if !cfg.Quiet {
		fmt.Printf("\n[*] Running %d template(s) against %s\n", len(templates), baseURL)
		if targetCtx != nil {
			parts := make([]string, 0, 3)
			if targetCtx.Framework != "" {
				parts = append(parts, targetCtx.Framework)
			}
			if targetCtx.Language != "" && targetCtx.Language != targetCtx.Framework {
				parts = append(parts, targetCtx.Language)
			}
			if targetCtx.WAF != "" {
				parts = append(parts, targetCtx.WAF)
			}
			if len(parts) > 0 {
				fmt.Printf("[*] Detected: %s\n", strings.Join(parts, " / "))
			}
		}
		if len(paramNames) > 0 {
			fmt.Printf("[*] Testing %d parameter(s) × %d template(s) = %d probe(s)\n",
				len(paramNames), len(templates), totalProbes)
		}
		fmt.Printf("%s\n", strings.Repeat("-", 55))
	}

	for _, tmpl := range templates {
		tmpl := tmpl // capture

		switch tmpl.Inject {
		case "query_params":
			// Test each query parameter with this template
			if len(paramNames) == 0 && cfg.Quiet {
				continue
			}
			if len(paramNames) == 0 {
				fmt.Printf("[!] Template %s requires query_params but URL has none — skipping\n", tmpl.ID)
				continue
			}
			for _, param := range paramNames {
				wg.Add(1)
				go func(p string, t ProbeTemplate) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					results := executeTemplateOnParam(client, t, baseURL, p, queryParams, cfg)
					if len(results) > 0 {
						mu.Lock()
						findings = append(findings, results...)
						mu.Unlock()
						if !cfg.Quiet {
							for _, f := range results {
								printFinding(f)
							}
						}
					}
				}(param, tmpl)
			}

		case "headers":
			// Test by injecting payloads into request headers
			wg.Add(1)
			go func(t ProbeTemplate) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				results := executeTemplateOnHeaders(client, t, rawURL, cfg)
				if len(results) > 0 {
					mu.Lock()
					findings = append(findings, results...)
					mu.Unlock()
					if !cfg.Quiet {
						for _, f := range results {
							printFinding(f)
						}
					}
				}
			}(tmpl)

		case "body":
			// Test by sending payloads in POST body
			wg.Add(1)
			go func(t ProbeTemplate) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				results := executeTemplateOnBody(client, t, rawURL, cfg)
				if len(results) > 0 {
					mu.Lock()
					findings = append(findings, results...)
					mu.Unlock()
					if !cfg.Quiet {
						for _, f := range results {
							printFinding(f)
						}
					}
				}
			}(tmpl)

		case "none":
			// Passive checks (e.g. security headers) — no injection
			wg.Add(1)
			go func(t ProbeTemplate) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				results := executePassiveCheck(client, t, rawURL, cfg)
				if len(results) > 0 {
					mu.Lock()
					findings = append(findings, results...)
					mu.Unlock()
					if !cfg.Quiet {
						for _, f := range results {
							printFinding(f)
						}
					}
				}
			}(tmpl)

		default:
			// Default to query_params behavior
			if len(paramNames) == 0 {
				continue
			}
			for _, param := range paramNames {
				wg.Add(1)
				go func(p string, t ProbeTemplate) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					results := executeTemplateOnParam(client, t, baseURL, p, queryParams, cfg)
					if len(results) > 0 {
						mu.Lock()
						findings = append(findings, results...)
						mu.Unlock()
						if !cfg.Quiet {
							for _, f := range results {
								printFinding(f)
							}
						}
					}
				}(param, tmpl)
			}
		}
	}

	wg.Wait()
	return findings, nil
}

// =============================================================
// ── PER-INJECTION-POINT EXECUTORS ───────────────────────────
// =============================================================

func buildQueryURL(baseURL string, params url.Values) string {
	if encoded := params.Encode(); encoded != "" {
		return baseURL + "?" + encoded
	}
	return baseURL
}

func effectiveHeaderNames(tmpl ProbeTemplate) []string {
	if len(tmpl.HeaderNames) == 0 {
		return []string{"Host"}
	}
	return tmpl.HeaderNames
}

func evaluatePatternDetection(
	candidate *TimedResponse,
	baseline *TimedResponse,
	bodyPatterns []*regexp.Regexp,
) string {
	if candidate == nil {
		return ""
	}

	baselineBody := ""
	if baseline != nil {
		baselineBody = baseline.BodyStr
	}

	newMatches := newPatternMatches(candidate.BodyStr, baselineBody, bodyPatterns)
	if len(newMatches) == 0 {
		return ""
	}

	return fmt.Sprintf("New body pattern matched after mutation: %s", newMatches[0])
}

func evaluateStatusDiffDetection(
	candidate *TimedResponse,
	baseline *TimedResponse,
	matchers Matchers,
	bodyPatterns []*regexp.Regexp,
) string {
	if candidate == nil || candidate.Response == nil {
		return ""
	}

	if len(matchers.StatusCodes) > 0 {
		statusMatched := false
		for _, code := range matchers.StatusCodes {
			if candidate.Response.StatusCode == code {
				statusMatched = true
				break
			}
		}
		if !statusMatched {
			return ""
		}
	}

	signals := []string{fmt.Sprintf("status=%d", candidate.Response.StatusCode)}

	matchedHeaders := matchingExpectedHeaders(candidate.Response, matchers.Headers)
	if len(matchers.Headers) > 0 {
		if len(matchedHeaders) == 0 {
			return ""
		}
		signals = append(signals, matchedHeaders...)
	}

	baselineBody := ""
	if baseline != nil {
		baselineBody = baseline.BodyStr
	}
	newMatches := newPatternMatches(candidate.BodyStr, baselineBody, bodyPatterns)
	if len(newMatches) > 0 {
		signals = append(signals, "body="+newMatches[0])
	}

	hasNewSignal := responseMeaningfullyDiffers(baseline, candidate)
	if baseline != nil {
		hasNewSignal = hasNewSignal || expectedHeadersIntroduceNewSignal(baseline.Response, candidate.Response, matchers.Headers)
	} else if len(matchers.Headers) > 0 {
		hasNewSignal = true
	}
	hasNewSignal = hasNewSignal || len(newMatches) > 0

	if !hasNewSignal {
		return ""
	}

	return fmt.Sprintf("Baseline diverged after mutation: %s", strings.Join(signals, "; "))
}

func evaluateHeaderCheckDetection(
	candidate *TimedResponse,
	baseline *TimedResponse,
	expected map[string]string,
) string {
	if candidate == nil || candidate.Response == nil || len(expected) == 0 {
		return ""
	}

	matchedHeaders := matchingExpectedHeaders(candidate.Response, expected)
	if len(matchedHeaders) == 0 {
		return ""
	}

	if baseline != nil && !expectedHeadersIntroduceNewSignal(baseline.Response, candidate.Response, expected) {
		return ""
	}

	return fmt.Sprintf("Headers matched after mutation: %s", strings.Join(matchedHeaders, ", "))
}

func minimumAddedDelay(delay time.Duration) time.Duration {
	required := time.Duration(float64(delay) * 0.70)
	if required < 1500*time.Millisecond {
		required = 1500 * time.Millisecond
	}
	if required > delay {
		required = delay
	}
	return required
}

func newTemplateFinding(
	tmpl ProbeTemplate,
	targetURL string,
	param string,
	payload string,
	evidence string,
	method string,
	headerName string,
	contentType string,
	requiresOOB bool,
) VulnFinding {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		if tmpl.Inject == "body" {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
	}

	requestCtx := buildRequestContext(targetURL, method, tmpl.Inject, param, headerName, contentType, payload)

	return VulnFinding{
		Type:        VulnType(tmpl.Info.Name),
		URL:         targetURL,
		Param:       param,
		Payload:     payload,
		Evidence:    evidence,
		Severity:    strings.ToUpper(tmpl.Info.Severity),
		Inject:      tmpl.Inject,
		Method:      method,
		HeaderName:  headerName,
		ContentType: contentType,
		TemplateID:  tmpl.ID,
		RequiresOOB: requiresOOB,
		Tags:        append([]string{}, tmpl.Info.Tags...),
		Detection:   tmpl.Detection,
		Request:     requestCtx,
		Hints:       inferExploitHints(tmpl, requiresOOB),
	}
}

func buildRequestContext(
	targetURL string,
	method string,
	inject string,
	param string,
	headerName string,
	contentType string,
	payload string,
) RequestContext {
	ctx := RequestContext{
		ReplayURL:   targetURL,
		Method:      method,
		Inject:      inject,
		ContentType: contentType,
		TargetParam: param,
		HeaderName:  headerName,
	}

	if parsed, err := url.Parse(targetURL); err == nil {
		ctx.BaseURL = fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, parsed.Path)
	}

	switch inject {
	case "headers":
		if headerName != "" {
			ctx.Headers = map[string]string{headerName: payload}
		}
	case "body":
		ctx.Body = payload
	case "cookie":
		ctx.CookieName = param
	case "path":
		ctx.PathHint = param
	}

	return ctx
}

func inferExploitHints(tmpl ProbeTemplate, requiresOOB bool) ExploitHints {
	hints := ExploitHints{
		Tech:       detectTemplateTech(tmpl.Info.Tags),
		Frameworks: detectTemplateFrameworks(tmpl.Info.Tags, tmpl.Info.Name),
		Stack:      append([]string{}, tmpl.Info.Tags...),
	}

	switch {
	case requiresOOB:
		hints.Exploitability = "oob-only"
	case templateSuggestsManualFollowup(tmpl):
		hints.Exploitability = "manual-followup"
	case templateIsRCECapable(tmpl):
		hints.Exploitability = "rce-capable"
	default:
		hints.Exploitability = "verified"
	}

	if strings.EqualFold(tmpl.ID, "spring4shell") {
		hints.Notes = append(hints.Notes, "template indicates file-write style RCE flow")
	}
	if strings.Contains(strings.ToLower(tmpl.Info.Name), "log4shell") {
		hints.Notes = append(hints.Notes, "jndi callback expected before follow-up exploitation")
	}

	return hints
}

func detectTemplateTech(tags []string) string {
	for _, tag := range tags {
		switch strings.ToLower(strings.TrimSpace(tag)) {
		case "php", "java", "dotnet", "python", "nodejs", "ruby", "yaml":
			return strings.ToLower(strings.TrimSpace(tag))
		}
	}
	return ""
}

func detectTemplateFrameworks(tags []string, name string) []string {
	frameworks := []string{}
	seen := map[string]bool{}
	appendFramework := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[strings.ToLower(value)] {
			return
		}
		seen[strings.ToLower(value)] = true
		frameworks = append(frameworks, value)
	}

	for _, tag := range tags {
		switch strings.ToLower(strings.TrimSpace(tag)) {
		case "spring":
			appendFramework("Spring")
		case "spel":
			appendFramework("SpEL")
		case "ognl":
			appendFramework("OGNL")
		case "log4j":
			appendFramework("Log4j")
		case "pickle":
			appendFramework("Pickle")
		}
	}

	if strings.Contains(strings.ToLower(name), "log4shell") {
		appendFramework("Log4j")
	}

	return frameworks
}

func templateSuggestsManualFollowup(tmpl ProbeTemplate) bool {
	id := strings.ToLower(strings.TrimSpace(tmpl.ID))
	switch id {
	case "ssrf", "rfi", "log4shell", "spring4shell":
		return true
	}
	return false
}

func templateIsRCECapable(tmpl ProbeTemplate) bool {
	for _, tag := range tmpl.Info.Tags {
		switch strings.ToLower(strings.TrimSpace(tag)) {
		case "rce", "cmdi", "ssti", "deserialization", "gadget", "jndi":
			return true
		}
	}
	return false
}

// executeTemplateOnParam runs a single template against a query parameter.
func executeTemplateOnParam(
	client *http.Client,
	tmpl ProbeTemplate,
	baseURL string,
	param string,
	otherParams url.Values,
	cfg ProbeConfig,
) []VulnFinding {
	var findings []VulnFinding

	// Compile body patterns once
	bodyPatterns := compilePatterns(tmpl.Matchers.BodyPatterns)
	baselineURL := buildQueryURL(baseURL, otherParams)
	baselineResp, _ := timedGET(client, baselineURL)

	// ── Standard payloads ────────────────────────────────
	for _, rawPayload := range tmpl.Payloads {
		payload := replaceTemplateVars(rawPayload, baseURL)

		params := cloneValues(otherParams)
		params.Set(param, payload)
		testURL := buildQueryURL(baseURL, params)

		tresp, err := timedGET(client, testURL)
		if err != nil {
			continue
		}

		var evidence string
		switch tmpl.Detection {
		case "", "pattern":
			evidence = evaluatePatternDetection(tresp, baselineResp, bodyPatterns)
		case "status_diff":
			evidence = evaluateStatusDiffDetection(tresp, baselineResp, tmpl.Matchers, bodyPatterns)
		case "header_check":
			evidence = evaluateHeaderCheckDetection(tresp, baselineResp, tmpl.Matchers.Headers)
		}

		if evidence != "" {
			findings = append(findings, newTemplateFinding(
				tmpl,
				testURL,
				param,
				payload,
				evidence,
				http.MethodGet,
				"",
				"",
				false,
			))
			return findings
		}

	}

	// ── Time-based payloads ──────────────────────────────
	if tmpl.TimePayloads != nil {
		delay := time.Duration(tmpl.TimePayloads.DelaySeconds * float64(time.Second))
		baselineMedian, err := measureMedianDuration(2, func() (*TimedResponse, error) {
			return timedGET(client, baselineURL)
		})
		if err == nil {
			requiredIncrease := minimumAddedDelay(delay)

			for _, rawPayload := range tmpl.TimePayloads.Payloads {
				payload := replaceTemplateVars(rawPayload, baseURL)

				params := cloneValues(otherParams)
				params.Set(param, payload)
				testURL := buildQueryURL(baseURL, params)

				testMedian, err := measureMedianDuration(2, func() (*TimedResponse, error) {
					return timedGET(client, testURL)
				})
				if err != nil {
					continue
				}

				if testMedian >= baselineMedian+requiredIncrease {
					findings = append(findings, newTemplateFinding(
						tmpl,
						testURL,
						param,
						payload,
						fmt.Sprintf("Median response delay %.2fs over baseline %.2fs (required increase %.2fs)", testMedian.Seconds(), baselineMedian.Seconds(), requiredIncrease.Seconds()),
						http.MethodGet,
						"",
						"",
						false,
					))
					return findings
				}
			}
		}
	}

	// ── OOB-specific payloads ───────────────────────────
	return findings
}

// executeTemplateOnHeaders injects payloads into HTTP headers (e.g. Host header injection).
func executeTemplateOnHeaders(
	client *http.Client,
	tmpl ProbeTemplate,
	targetURL string,
	cfg ProbeConfig,
) []VulnFinding {
	var findings []VulnFinding
	bodyPatterns := compilePatterns(tmpl.Matchers.BodyPatterns)
	baselineResp, _ := timedGET(client, targetURL)
	headerNames := effectiveHeaderNames(tmpl)

	for _, headerName := range headerNames {
		for _, rawPayload := range tmpl.Payloads {
			payload := replaceTemplateVars(rawPayload, targetURL)
			headers := map[string]string{
				headerName: payload,
			}

			tresp, err := sendRequestWithHeaders(client, targetURL, headers)
			if err != nil {
				continue
			}

			var evidence string
			switch tmpl.Detection {
			case "", "pattern":
				evidence = evaluatePatternDetection(tresp, baselineResp, bodyPatterns)
			case "status_diff":
				evidence = evaluateStatusDiffDetection(tresp, baselineResp, tmpl.Matchers, bodyPatterns)
			case "header_check":
				evidence = evaluateHeaderCheckDetection(tresp, baselineResp, tmpl.Matchers.Headers)
			}

			if evidence == "" {
				continue
			}

			findings = append(findings, newTemplateFinding(
				tmpl,
				targetURL,
				fmt.Sprintf("%s header", headerName),
				payload,
				evidence,
				http.MethodGet,
				headerName,
				"",
				false,
			))
			return findings
		}
	}

	return findings
}

// executeTemplateOnBody sends payloads as POST body (e.g. XXE).
func executeTemplateOnBody(
	client *http.Client,
	tmpl ProbeTemplate,
	targetURL string,
	cfg ProbeConfig,
) []VulnFinding {
	var findings []VulnFinding
	bodyPatterns := compilePatterns(tmpl.Matchers.BodyPatterns)

	// Determine content type from tags
	contentType := "application/x-www-form-urlencoded"
	for _, tag := range tmpl.Info.Tags {
		if tag == "xml" || tag == "xxe" {
			contentType = "application/xml"
			break
		}
		if tag == "json" {
			contentType = "application/json"
			break
		}
	}

	baselineResp, _ := sendPOSTWithBody(client, targetURL, contentType, "")

	for _, rawPayload := range tmpl.Payloads {
		payload := replaceTemplateVars(rawPayload, targetURL)

		tresp, err := sendPOSTWithBody(client, targetURL, contentType, payload)
		if err != nil {
			continue
		}

		var evidence string
		switch tmpl.Detection {
		case "", "pattern":
			evidence = evaluatePatternDetection(tresp, baselineResp, bodyPatterns)
		case "status_diff":
			evidence = evaluateStatusDiffDetection(tresp, baselineResp, tmpl.Matchers, bodyPatterns)
		case "header_check":
			evidence = evaluateHeaderCheckDetection(tresp, baselineResp, tmpl.Matchers.Headers)
		}

		if evidence != "" {
			findings = append(findings, newTemplateFinding(
				tmpl,
				targetURL,
				"POST body",
				truncatePayload(payload, 120),
				evidence,
				http.MethodPost,
				"",
				contentType,
				false,
			))
			return findings
		}

	}

	return findings
}

// executePassiveCheck performs passive analysis without injection (e.g. security headers).
func executePassiveCheck(
	client *http.Client,
	tmpl ProbeTemplate,
	targetURL string,
	cfg ProbeConfig,
) []VulnFinding {
	var findings []VulnFinding

	tresp, err := timedGET(client, targetURL)
	if err != nil {
		return findings
	}

	if tmpl.Detection == "cookie_flags" {
		cookies := tresp.Response.Header.Values("Set-Cookie")
		for _, rawCookie := range cookies {
			cookieName := strings.TrimSpace(strings.SplitN(rawCookie, "=", 2)[0])
			cookieNameLower := strings.ToLower(cookieName)
			if cookieName == "" {
				continue
			}
			if !strings.Contains(cookieNameLower, "session") &&
				!strings.Contains(cookieNameLower, "sess") &&
				!strings.Contains(cookieNameLower, "sid") &&
				!strings.Contains(cookieNameLower, "auth") &&
				!strings.Contains(cookieNameLower, "token") &&
				!strings.Contains(cookieNameLower, "jwt") &&
				!strings.Contains(cookieNameLower, "remember") {
				continue
			}

			rawCookieLower := strings.ToLower(rawCookie)
			var missingFlags []string
			for _, flag := range tmpl.Matchers.CookieFlags {
				switch strings.ToLower(flag) {
				case "secure":
					if !strings.Contains(rawCookieLower, "; secure") {
						missingFlags = append(missingFlags, "Secure")
					}
				case "httponly":
					if !strings.Contains(rawCookieLower, "; httponly") {
						missingFlags = append(missingFlags, "HttpOnly")
					}
				case "samesite":
					if !strings.Contains(rawCookieLower, "; samesite=") {
						missingFlags = append(missingFlags, "SameSite")
					}
				}
			}

			if len(missingFlags) == 0 {
				continue
			}

			findings = append(findings, newTemplateFinding(
				tmpl,
				targetURL,
				"response cookie",
				cookieName,
				fmt.Sprintf("Cookie %s missing flags: %s", cookieName, strings.Join(missingFlags, ", ")),
				http.MethodGet,
				"",
				"",
				false,
			))
		}
		return findings
	}

	// For "none" injection + header_check detection:
	// Headers map means "these headers should be PRESENT" — finding means they're MISSING
	if tmpl.Detection == "header_check" {
		parsedTarget, _ := url.Parse(targetURL)
		for hName, hExpected := range tmpl.Matchers.Headers {
			if strings.EqualFold(hName, "Strict-Transport-Security") && (parsedTarget == nil || !strings.EqualFold(parsedTarget.Scheme, "https")) {
				continue
			}

			if hExpected == "MISSING" {
				if headerMissing(tresp.Response, hName) {
					if strings.EqualFold(hName, "X-Frame-Options") && headerContains(tresp.Response, "Content-Security-Policy", "frame-ancestors") {
						continue
					}
					findings = append(findings, newTemplateFinding(
						tmpl,
						targetURL,
						"response header",
						"N/A (passive check)",
						fmt.Sprintf("Security header missing: %s", hName),
						http.MethodGet,
						"",
						"",
						false,
					))
				}
			} else if !headerContains(tresp.Response, hName, hExpected) {
				findings = append(findings, newTemplateFinding(
					tmpl,
					targetURL,
					"response header",
					"N/A (passive check)",
					fmt.Sprintf("Header %s does not contain expected '%s'", hName, hExpected),
					http.MethodGet,
					"",
					"",
					false,
				))
			}
		}
	}

	// Body pattern check on passive response
	if tmpl.Detection == "pattern" || tmpl.Detection == "" {
		bodyPatterns := compilePatterns(tmpl.Matchers.BodyPatterns)
		if matched := containsAnyPattern(tresp.BodyStr, bodyPatterns); matched != "" {
			findings = append(findings, newTemplateFinding(
				tmpl,
				targetURL,
				"response body",
				"N/A (passive check)",
				fmt.Sprintf("Body pattern matched: %s", matched),
				http.MethodGet,
				"",
				"",
				false,
			))
		}
	}

	return findings
}

// ── Helpers ──────────────────────────────────────────────────

// truncatePayload shortens long payloads for display.
func truncatePayload(payload string, maxLen int) string {
	// Remove newlines for display
	payload = strings.ReplaceAll(payload, "\n", "\\n")
	if len(payload) > maxLen {
		return payload[:maxLen] + "..."
	}
	return payload
}

// hasOOBVars checks if a payload string contains OOB template variables.
func hasOOBVars(payload string) bool {
	return strings.Contains(payload, "{{OOB_URL}}") || strings.Contains(payload, "{{OOB_DOMAIN}}")
}

// normalizeSeverity returns uppercase severity (HIGH, MEDIUM, LOW).
func normalizeSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "HIGH", "CRITICAL":
		return "HIGH"
	case "MEDIUM", "MED":
		return "MEDIUM"
	case "LOW", "INFO":
		return "LOW"
	default:
		return "MEDIUM"
	}
}

// Compile-time check that we use regexp import (compiler would flag otherwise).
var _ = regexp.Compile
