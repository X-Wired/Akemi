package vuln

import (
	core "Akemi/internal/core"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSendRequestWithHeadersSupportsHostOverride(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Host))
	}))
	defer srv.Close()

	resp, err := sendRequestWithHeaders(srv.Client(), srv.URL, map[string]string{
		"Host": "evil.example",
	})
	if err != nil {
		t.Fatalf("sendRequestWithHeaders: %v", err)
	}
	if !strings.Contains(resp.BodyStr, "evil.example") {
		t.Fatalf("expected overridden host in response body, got %q", resp.BodyStr)
	}
}

func TestExecuteTemplateOnHeadersUsesConfiguredHeaderName(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tmpl := ProbeTemplate{
		ID:          "cors-test",
		Inject:      "headers",
		Detection:   "header_check",
		HeaderNames: []string{"Origin"},
		Payloads:    []string{"https://evil.com"},
		Matchers: Matchers{
			Headers: map[string]string{
				"Access-Control-Allow-Origin": "evil.com",
			},
		},
		Info: TemplateInfo{
			Name:     "CORS Misconfiguration",
			Severity: "low",
		},
	}

	findings := executeTemplateOnHeaders(srv.Client(), tmpl, srv.URL, ProbeConfig{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Param != "Origin header" {
		t.Fatalf("expected Origin header finding, got %q", findings[0].Param)
	}
}

func TestExecuteTemplateOnParamStatusDiffRequiresBaselineChange(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("same body"))
	}))
	defer srv.Close()

	tmpl := ProbeTemplate{
		ID:        "status-diff-test",
		Inject:    "query_params",
		Detection: "status_diff",
		Payloads:  []string{"2"},
		Matchers: Matchers{
			StatusCodes: []int{200},
		},
		Info: TemplateInfo{
			Name:     "Insecure Direct Object Reference",
			Severity: "high",
		},
	}

	findings := executeTemplateOnParam(
		srv.Client(),
		tmpl,
		srv.URL,
		"id",
		url.Values{"id": []string{"1"}},
		ProbeConfig{},
	)
	if len(findings) != 0 {
		t.Fatalf("expected no findings without baseline change, got %d", len(findings))
	}
}

func TestExecuteTemplateOnParamStatusDiffFindsNewSensitiveSignal(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") == "2" {
			_, _ = w.Write([]byte(`{"email":"admin@example.com"}`))
			return
		}
		_, _ = w.Write([]byte(`{"message":"denied"}`))
	}))
	defer srv.Close()

	tmpl := ProbeTemplate{
		ID:        "idor-test",
		Inject:    "query_params",
		Detection: "status_diff",
		Payloads:  []string{"2"},
		Matchers: Matchers{
			StatusCodes:  []int{200},
			BodyPatterns: []string{`(?i)email`},
		},
		Info: TemplateInfo{
			Name:     "Insecure Direct Object Reference",
			Severity: "high",
		},
	}

	findings := executeTemplateOnParam(
		srv.Client(),
		tmpl,
		srv.URL,
		"id",
		url.Values{"id": []string{"1"}},
		ProbeConfig{},
	)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "body=") {
		t.Fatalf("expected body evidence in finding, got %q", findings[0].Evidence)
	}
}

func TestExecuteTemplateOnParamHeaderCheckDoesNotFallbackToBodyPattern(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("evil.com"))
	}))
	defer srv.Close()

	tmpl := ProbeTemplate{
		ID:        "open-redirect-test",
		Inject:    "query_params",
		Detection: "header_check",
		Payloads:  []string{"https://evil.com"},
		Matchers: Matchers{
			Headers: map[string]string{
				"Location": "evil.com",
			},
			BodyPatterns: []string{`(?i)evil\.com`},
		},
		Info: TemplateInfo{
			Name:     "Open Redirect",
			Severity: "medium",
		},
	}

	findings := executeTemplateOnParam(
		srv.Client(),
		tmpl,
		srv.URL,
		"next",
		url.Values{"next": []string{"/home"}},
		ProbeConfig{},
	)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when only body pattern matches, got %d", len(findings))
	}
}

func TestExecutePassiveCheckCookieFlagsIgnoresMissingCookiesAndFlagsRiskyOnes(t *testing.T) {
	t.Parallel()

	noCookieSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer noCookieSrv.Close()

	tmpl := ProbeTemplate{
		ID:        "cookie-security",
		Inject:    "none",
		Detection: "cookie_flags",
		Matchers: Matchers{
			CookieFlags: []string{"Secure", "HttpOnly", "SameSite"},
		},
		Info: TemplateInfo{
			Name:     "Insecure Cookie Configuration",
			Severity: "low",
		},
	}

	if findings := executePassiveCheck(noCookieSrv.Client(), tmpl, noCookieSrv.URL, ProbeConfig{}); len(findings) != 0 {
		t.Fatalf("expected no findings when no cookies are set, got %d", len(findings))
	}

	sessionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "sessionid=abc123; Path=/")
		_, _ = w.Write([]byte("ok"))
	}))
	defer sessionSrv.Close()

	findings := executePassiveCheck(sessionSrv.Client(), tmpl, sessionSrv.URL, ProbeConfig{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for insecure session cookie, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "Secure") || !strings.Contains(findings[0].Evidence, "HttpOnly") || !strings.Contains(findings[0].Evidence, "SameSite") {
		t.Fatalf("unexpected cookie evidence: %q", findings[0].Evidence)
	}
}

func TestExecutePassiveCheckSkipsClickjackingWhenFrameAncestorsExists(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tmpl := ProbeTemplate{
		ID:        "clickjacking",
		Inject:    "none",
		Detection: "header_check",
		Matchers: Matchers{
			Headers: map[string]string{
				"X-Frame-Options": "MISSING",
			},
		},
		Info: TemplateInfo{
			Name:     "Clickjacking Protection Missing",
			Severity: "low",
		},
	}

	findings := executePassiveCheck(srv.Client(), tmpl, srv.URL, ProbeConfig{})
	if len(findings) != 0 {
		t.Fatalf("expected CSP frame-ancestors to suppress clickjacking finding, got %d", len(findings))
	}
}

func TestProbeParamsWithCandidatesFindsCandidateParamWithoutOriginalQuery(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("hck") == "sentinel" {
			_, _ = w.Write([]byte("found sentinel"))
			return
		}
		_, _ = w.Write([]byte("baseline"))
	}))
	defer srv.Close()

	templateDir := t.TempDir()
	templatePath := filepath.Join(templateDir, "candidate.yaml")
	templateBody := strings.Join([]string{
		"id: candidate-param-test",
		"info:",
		"  name: Candidate Param Test",
		"  severity: medium",
		"inject: query_params",
		"detection: pattern",
		"payloads:",
		"  - sentinel",
		"matchers:",
		"  body_patterns:",
		"    - sentinel",
	}, "\n")
	if err := os.WriteFile(templatePath, []byte(templateBody), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	findings, err := ProbeParamsWithCandidates(srv.URL, []string{"hck"}, ProbeConfig{
		UseTemplates: true,
		TemplateDir:  templateDir,
		Threads:      2,
		Timeout:      5,
	})
	if err != nil {
		t.Fatalf("ProbeParamsWithCandidates: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Param != "hck" {
		t.Fatalf("expected hck param, got %q", findings[0].Param)
	}
}

func TestProbeParamsWithCandidatesMergesOriginalAndCandidateParamsWithoutDuplicates(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") == "sentinel" || r.URL.Query().Get("hck") == "sentinel" {
			_, _ = w.Write([]byte("sentinel"))
			return
		}
		_, _ = w.Write([]byte("baseline"))
	}))
	defer srv.Close()

	templateDir := t.TempDir()
	templatePath := filepath.Join(templateDir, "merge.yaml")
	templateBody := strings.Join([]string{
		"id: merge-param-test",
		"info:",
		"  name: Merge Param Test",
		"  severity: medium",
		"inject: query_params",
		"detection: pattern",
		"payloads:",
		"  - sentinel",
		"matchers:",
		"  body_patterns:",
		"    - sentinel",
	}, "\n")
	if err := os.WriteFile(templatePath, []byte(templateBody), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	findings, err := ProbeParamsWithCandidates(srv.URL+"?id=1", []string{"hck", "id"}, ProbeConfig{
		UseTemplates: true,
		TemplateDir:  templateDir,
		Threads:      2,
		Timeout:      5,
	})
	if err != nil {
		t.Fatalf("ProbeParamsWithCandidates: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for id and hck, got %d", len(findings))
	}

	params := map[string]int{}
	for _, finding := range findings {
		params[finding.Param]++
	}
	if params["id"] != 1 || params["hck"] != 1 {
		t.Fatalf("expected exactly one finding per param, got %#v", params)
	}
}

func TestLoadTemplatesFindsRepoProbesFromNestedWorkingDirectory(t *testing.T) {
	rootDir := t.TempDir()
	probesDir := filepath.Join(rootDir, "probes", "client-side")
	panelDir := filepath.Join(rootDir, "akemi_panel")
	if err := os.MkdirAll(probesDir, 0o755); err != nil {
		t.Fatalf("mkdir probes: %v", err)
	}
	if err := os.MkdirAll(panelDir, 0o755); err != nil {
		t.Fatalf("mkdir panel: %v", err)
	}

	templatePath := filepath.Join(probesDir, "xss-reflected.yml")
	templateBody := strings.Join([]string{
		"id: cwd-probe-test",
		"info:",
		"  name: CWD Probe Test",
		"  severity: medium",
		"inject: query_params",
		"detection: pattern",
		"payloads:",
		"  - sentinel",
		"matchers:",
		"  body_patterns:",
		"    - sentinel",
	}, "\n")
	if err := os.WriteFile(templatePath, []byte(templateBody), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() {
		_ = os.Chdir(originalWD)
	}()
	if err := os.Chdir(panelDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	templates, err := LoadTemplates("./probes")
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	if len(templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(templates))
	}
	if templates[0].ID != "cwd-probe-test" {
		t.Fatalf("unexpected template id: %q", templates[0].ID)
	}
}

// =============================================================
// ── Fingerprinting Tests ─────────────────────────────────────
// =============================================================

func TestFingerprintTargetDetectsSpringBoot(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "JSESSIONID=ABC123; Path=/")
		w.Header().Set("X-Application-Context", "application:8080")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>Whitelabel Error Page</body></html>`))
	}))
	defer srv.Close()

	ctx, err := FingerprintTarget(srv.URL, nil, srv.Client())
	if err != nil {
		t.Fatalf("FingerprintTarget: %v", err)
	}

	if ctx.Framework != "Spring Boot" {
		t.Fatalf("expected Spring Boot, got %q", ctx.Framework)
	}
	if ctx.Language != "java" {
		t.Fatalf("expected java, got %q", ctx.Language)
	}
}

func TestFingerprintTargetDetectsCloudflare(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("cf-ray", "abc123")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx, err := FingerprintTarget(srv.URL, nil, srv.Client())
	if err != nil {
		t.Fatalf("FingerprintTarget: %v", err)
	}

	if ctx.WAF != "Cloudflare" {
		t.Fatalf("expected Cloudflare WAF, got %q", ctx.WAF)
	}
	if ctx.WAFConfidence <= 0 {
		t.Fatalf("expected WAF confidence > 0, got %f", ctx.WAFConfidence)
	}
}

func TestFingerprintTargetClassifiesParameters(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx, err := FingerprintTarget(srv.URL+"?id=123&q=test&redirect=https://evil.com&token=abc", nil, srv.Client())
	if err != nil {
		t.Fatalf("FingerprintTarget: %v", err)
	}

	if ctx.ParameterProfile == nil {
		t.Fatal("expected parameter profile to be non-nil")
	}

	categories := map[string]string{}
	for _, p := range ctx.ParameterProfile.Parameters {
		categories[p.Name] = p.Category
	}

	if categories["id"] != "numeric_id" {
		t.Fatalf("expected id to be numeric_id, got %q", categories["id"])
	}
	if categories["q"] != "search_query" {
		t.Fatalf("expected q to be search_query, got %q", categories["q"])
	}
	if categories["redirect"] != "redirect_url" {
		t.Fatalf("expected redirect to be redirect_url, got %q", categories["redirect"])
	}
	if categories["token"] != "token_hash" {
		t.Fatalf("expected token to be token_hash, got %q", categories["token"])
	}
}

func TestFingerprintTargetDetectsDjango(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "csrftoken=XYZ789; Path=/")
		w.Header().Set("Set-Cookie", "sessionid=DEF456; Path=/; HttpOnly")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><meta name="generator" content="Django 4.2"></html>`))
	}))
	defer srv.Close()

	ctx, err := FingerprintTarget(srv.URL, nil, srv.Client())
	if err != nil {
		t.Fatalf("FingerprintTarget: %v", err)
	}

	if ctx.Framework != "Django" {
		t.Fatalf("expected Django, got %q", ctx.Framework)
	}
	if ctx.Language != "python" {
		t.Fatalf("expected python, got %q", ctx.Language)
	}
	if len(ctx.SessionCookies) == 0 {
		t.Fatal("expected session cookies to be detected")
	}
}

func TestFingerprintTargetDetectsAPIExposure(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// GraphQL-like introspection response
		_, _ = w.Write([]byte(`{"data": {"__schema": {"types": []}}}`))
	}))
	defer srv.Close()

	ctx, err := FingerprintTarget(srv.URL+"/graphql", nil, srv.Client())
	if err != nil {
		t.Fatalf("FingerprintTarget: %v", err)
	}

	if ctx.APIExposure != "graphql" {
		t.Fatalf("expected graphql API exposure, got %q", ctx.APIExposure)
	}
}

func TestFingerprintTargetRespectsCandidateParams(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx, err := FingerprintTarget(srv.URL, []string{"file", "callback_url"}, srv.Client())
	if err != nil {
		t.Fatalf("FingerprintTarget: %v", err)
	}

	if ctx.ParameterProfile == nil {
		t.Fatal("expected parameter profile")
	}

	categories := map[string]string{}
	for _, p := range ctx.ParameterProfile.Parameters {
		categories[p.Name] = p.Category
	}

	if categories["file"] != "file_path" {
		t.Fatalf("expected file to be file_path, got %q", categories["file"])
	}
	if categories["callback_url"] != "callback" {
		t.Fatalf("expected callback_url to be callback, got %q", categories["callback_url"])
	}
}

// =============================================================
// ── Prioritization Tests ─────────────────────────────────────
// =============================================================

func makeBasicTemplate(id, name, severity string, tags []string) ProbeTemplate {
	return ProbeTemplate{
		ID:       id,
		Disabled: false,
		Info: TemplateInfo{
			Name:     name,
			Severity: severity,
			Tags:     tags,
		},
		Inject:    "query_params",
		Detection: "pattern",
		Payloads:  []string{"test"},
		Matchers: Matchers{
			BodyPatterns: []string{"test"},
		},
	}
}

func TestPrioritizeTemplatesNilContextReturnsOriginal(t *testing.T) {
	t.Parallel()

	tmpls := []ProbeTemplate{
		makeBasicTemplate("a", "A", "high", []string{"php"}),
		makeBasicTemplate("b", "B", "low", []string{"java"}),
	}

	result := PrioritizeTemplates(tmpls, nil, nil, false)

	if len(result) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(result))
	}
	if result[0].ID != "a" || result[1].ID != "b" {
		t.Fatal("expected original order preserved with nil context")
	}
}

func TestPrioritizeTemplatesSingleElementNoop(t *testing.T) {
	t.Parallel()

	tmpls := []ProbeTemplate{
		makeBasicTemplate("only", "Only", "high", []string{"php"}),
	}

	ctx := &core.TargetContext{Language: "php", Framework: "Laravel"}
	result := PrioritizeTemplates(tmpls, ctx, []string{"id"}, false)

	if len(result) != 1 {
		t.Fatalf("expected 1 template, got %d", len(result))
	}
}

func TestPrioritizeTemplatesTechStackBoostsJavaOnSpringTarget(t *testing.T) {
	t.Parallel()

	// Java deserialization should be boosted against a Spring Boot target
	javaTmpl := makeBasicTemplate("java-deser", "Java Deserialization", "high",
		[]string{"java", "deserialization", "gadget"})
	phpTmpl := makeBasicTemplate("php-sqli", "PHP SQLi", "critical",
		[]string{"php", "sqli", "injection"})

	tmpls := []ProbeTemplate{phpTmpl, javaTmpl}

	ctx := &core.TargetContext{
		Framework: "Spring Boot",
		Language:  "java",
	}

	result := PrioritizeTemplates(tmpls, ctx, nil, false)

	if len(result) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(result))
	}

	// Java deserialization should be ranked higher than PHP SQLi on a Java target
	if result[0].ID != "java-deser" {
		t.Fatalf("expected java-deser first on Java target, got %q", result[0].ID)
	}
}

func TestPrioritizeTemplatesCVEBoostsLog4ShellOnJavaTarget(t *testing.T) {
	t.Parallel()

	log4jTmpl := makeBasicTemplate("log4shell", "Log4Shell", "critical",
		[]string{"cve", "log4j", "jndi", "rce", "java"})
	genericTmpl := makeBasicTemplate("sqli-error", "SQLi Error", "high",
		[]string{"sqli", "injection", "database"})

	tmpls := []ProbeTemplate{genericTmpl, log4jTmpl}

	// Target: Spring Boot (Java) — Log4Shell should get CVE bonus
	ctx := &core.TargetContext{
		Framework: "Spring Boot",
		Language:  "java",
		TechStack: []string{"Spring Boot", "java", "Log4j"},
	}

	result := PrioritizeTemplates(tmpls, ctx, nil, false)

	if len(result) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(result))
	}

	// Log4Shell should be ranked higher due to CVE+tech bonus
	if result[0].ID != "log4shell" {
		t.Fatalf("expected log4shell first on Log4j target, got %q", result[0].ID)
	}
}

func TestPrioritizeTemplatesParamMatchBoostsSSRFOnRedirectParam(t *testing.T) {
	t.Parallel()

	ssrfTmpl := makeBasicTemplate("ssrf", "SSRF", "high",
		[]string{"ssrf", "injection", "cloud"})
	xssTmpl := makeBasicTemplate("xss-reflected", "XSS", "medium",
		[]string{"xss", "injection", "client-side"})

	tmpls := []ProbeTemplate{xssTmpl, ssrfTmpl}

	ctx := &core.TargetContext{
		ParameterProfile: &core.ParameterProfile{
			Parameters: []core.ParameterClass{
				{Name: "redirect", Category: "redirect_url", PriorityTags: []string{"ssrf", "open_redirect", "lfi"}},
			},
		},
	}

	result := PrioritizeTemplates(tmpls, ctx, []string{"redirect"}, false)

	if len(result) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(result))
	}

	// SSRF should be ranked higher because the redirect param's priority tags include "ssrf"
	if result[0].ID != "ssrf" {
		t.Fatalf("expected ssrf first on redirect param, got %q", result[0].ID)
	}
}

func TestPrioritizeTemplatesWAFPenaltyDeprioritizesSQLiOnCloudflare(t *testing.T) {
	t.Parallel()

	sqliTmpl := makeBasicTemplate("sqli-error", "SQLi", "high",
		[]string{"sqli", "injection", "database"})
	cmdiTmpl := makeBasicTemplate("cmdi-blind", "CMD Injection", "high",
		[]string{"cmdi", "rce", "injection"})

	tmpls := []ProbeTemplate{sqliTmpl, cmdiTmpl}

	ctx := &core.TargetContext{
		WAF:           "Cloudflare",
		WAFConfidence: 0.95,
	}

	result := PrioritizeTemplates(tmpls, ctx, nil, false)

	if len(result) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(result))
	}

	// SQLi gets a 0.40 penalty on Cloudflare; CMDi only 0.50
	// Both are "high" severity and no tech match, but CMDi should be higher
	if result[0].ID != "cmdi-blind" {
		t.Fatalf("expected cmdi-blind first (sqli penalized on Cloudflare), got %q", result[0].ID)
	}
}

func TestPrioritizeTemplatesCriticalOverHighSeverity(t *testing.T) {
	t.Parallel()

	criticalTmpl := makeBasicTemplate("critical-cve", "Critical CVE", "critical", []string{"cve"})
	highTmpl := makeBasicTemplate("high-thing", "High Thing", "high", []string{})
	mediumTmpl := makeBasicTemplate("medium-thing", "Medium Thing", "medium", []string{})
	lowTmpl := makeBasicTemplate("low-thing", "Low Thing", "low", []string{})

	tmpls := []ProbeTemplate{lowTmpl, mediumTmpl, highTmpl, criticalTmpl}

	result := PrioritizeTemplates(tmpls, &core.TargetContext{URL: "http://test.com"}, nil, false)

	if len(result) != 4 {
		t.Fatalf("expected 4 templates, got %d", len(result))
	}

	// Critical should be first, low should be last
	if result[0].ID != "critical-cve" {
		t.Fatalf("expected critical-cve first, got %q", result[0].ID)
	}
	if result[3].ID != "low-thing" {
		t.Fatalf("expected low-thing last, got %q", result[3].ID)
	}
}

func TestPrioritizeTemplatesStableSortPreservesOrderOnTie(t *testing.T) {
	t.Parallel()

	// Templates with identical scoring should preserve their relative order
	tmplA := makeBasicTemplate("a-first", "A", "high", []string{})
	tmplB := makeBasicTemplate("b-second", "B", "high", []string{})

	tmpls := []ProbeTemplate{tmplA, tmplB}

	result := PrioritizeTemplates(tmpls, &core.TargetContext{URL: "http://test.com"}, nil, false)

	if len(result) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(result))
	}

	// On tie, stable sort should preserve a-then-b
	if result[0].ID != "a-first" || result[1].ID != "b-second" {
		t.Fatalf("expected stable sort [a-first, b-second], got [%s, %s]", result[0].ID, result[1].ID)
	}
}

func TestScoreSeverity(t *testing.T) {
	t.Parallel()

	if scoreSeverity("critical") <= scoreSeverity("high") {
		t.Fatal("expected critical > high")
	}
	if scoreSeverity("high") <= scoreSeverity("medium") {
		t.Fatal("expected high > medium")
	}
	if scoreSeverity("medium") <= scoreSeverity("low") {
		t.Fatal("expected medium > low")
	}
	if scoreSeverity("low") <= 0 {
		t.Fatal("expected low > 0")
	}
}

func TestScoreTechMatchPHPOnDjangoTarget(t *testing.T) {
	t.Parallel()

	tmpl := makeBasicTemplate("x", "X", "high", []string{"php", "sqli"})
	ctx := &core.TargetContext{Framework: "Django", Language: "python"}

	s := scoreTechMatch(tmpl, ctx)
	if s > 0 {
		t.Fatalf("expected 0 tech match for PHP template on Django, got %f", s)
	}
}

func TestScoreTechMatchJavaOnSpringTarget(t *testing.T) {
	t.Parallel()

	tmpl := makeBasicTemplate("x", "X", "high", []string{"java", "deserialization"})
	ctx := &core.TargetContext{Framework: "Spring Boot", Language: "java"}

	s := scoreTechMatch(tmpl, ctx)
	if s <= 0 {
		t.Fatalf("expected positive tech match for Java template on Spring, got %f", s)
	}
}
