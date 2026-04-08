package vuln

import (
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
