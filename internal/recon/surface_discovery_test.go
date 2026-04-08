package recon

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func newTestClient(responses map[string]testHTTPResponse) *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			key := req.URL.String()
			resp, ok := responses[key]
			if !ok {
				resp = testHTTPResponse{statusCode: http.StatusNotFound, body: "not found"}
			}
			if resp.statusCode == 0 {
				resp.statusCode = http.StatusOK
			}
			headers := make(http.Header)
			if resp.contentType != "" {
				headers.Set("Content-Type", resp.contentType)
			}
			return &http.Response{
				StatusCode: resp.statusCode,
				Status:     http.StatusText(resp.statusCode),
				Header:     headers,
				Body:       io.NopCloser(strings.NewReader(resp.body)),
				Request:    req,
			}, nil
		}),
	}
}

type testHTTPResponse struct {
	statusCode  int
	contentType string
	body        string
}

func TestCollectSeedURLsIncludesRobotsAndSitemaps(t *testing.T) {
	client := newTestClient(map[string]testHTTPResponse{
		"https://example.com/robots.txt": {
			body: "User-agent: *\nDisallow: /admin\nSitemap: https://example.com/sitemap.xml\n",
		},
		"https://example.com/sitemap.xml": {
			contentType: "application/xml",
			body:        `<sitemapindex><sitemap><loc>https://example.com/nested.xml</loc></sitemap></sitemapindex>`,
		},
		"https://example.com/nested.xml": {
			contentType: "application/xml",
			body: `<urlset>
				<url><loc>https://example.com/api/v1/users</loc></url>
				<url><loc>https://offsite.example.net/ignore</loc></url>
			</urlset>`,
		},
	})

	seeds := collectSeedURLs("https://example.com", client)

	for _, expected := range []string{
		"https://example.com/",
		"https://example.com/admin",
		"https://example.com/api/v1/users",
	} {
		if !contains(seeds, expected) {
			t.Fatalf("expected seed URL %q in %v", expected, seeds)
		}
	}
	if contains(seeds, "https://offsite.example.net/ignore") {
		t.Fatalf("unexpected offsite URL in seeds: %v", seeds)
	}
}

func TestDiscoverAPISurfaceParsesSpecsAndClassifiesPassiveEndpoints(t *testing.T) {
	client := newTestClient(map[string]testHTTPResponse{
		"https://example.com/graphql": {
			statusCode: http.StatusBadRequest,
			body:       `{"error":"query required"}`,
		},
		"https://example.com/api/v1/users": {
			statusCode: http.StatusOK,
			body:       `[]`,
		},
		"https://example.com/api/v2/orders": {
			statusCode: http.StatusInternalServerError,
			body:       `{"error":"boom"}`,
		},
		"https://example.com/openapi.yaml": {
			contentType: "application/yaml",
			body: `openapi: 3.0.0
info:
  title: Example API
  version: 2026.04
paths:
  /api/v2/orders:
    get:
      description: list orders
`,
		},
	})

	endpoints, specs, err := DiscoverAPISurface(
		"https://example.com",
		[]string{
			"https://example.com/graphql",
			"https://example.com/api/v1/users",
			"https://example.com/openapi.yaml",
		},
		nil,
		client,
	)
	if err != nil {
		t.Fatalf("DiscoverAPISurface returned error: %v", err)
	}

	if !hasEndpoint(endpoints, "https://example.com/graphql", "graphql", "") {
		t.Fatalf("expected graphql endpoint in %v", endpoints)
	}
	if !hasEndpoint(endpoints, "https://example.com/api/v1/users", "rest", "") {
		t.Fatalf("expected rest endpoint in %v", endpoints)
	}
	if !hasEndpoint(endpoints, "https://example.com/api/v2/orders", "openapi", "GET") {
		t.Fatalf("expected openapi endpoint from spec in %v", endpoints)
	}
	if !hasEndpointStatus(endpoints, "https://example.com/graphql", http.StatusBadRequest) {
		t.Fatalf("expected graphql status in %v", endpoints)
	}
	if !hasEndpointStatus(endpoints, "https://example.com/api/v1/users", http.StatusOK) {
		t.Fatalf("expected rest status in %v", endpoints)
	}
	if !hasEndpointStatus(endpoints, "https://example.com/api/v2/orders", http.StatusInternalServerError) {
		t.Fatalf("expected openapi endpoint status in %v", endpoints)
	}
	if len(specs) != 1 || specs[0].URL != "https://example.com/openapi.yaml" {
		t.Fatalf("expected openapi spec, got %#v", specs)
	}
	if specs[0].StatusCode != http.StatusOK {
		t.Fatalf("expected openapi spec status 200, got %#v", specs)
	}
}

func TestCrawlDetailedPreservesHTTPStatuses(t *testing.T) {
	client := newTestClient(map[string]testHTTPResponse{
		"https://example.com/": {
			contentType: "text/html",
			body:        `<html><body><a href="/ok">ok</a><a href="/missing">missing</a></body></html>`,
		},
		"https://example.com/ok": {
			contentType: "text/html",
			body:        `<html><body>ok</body></html>`,
		},
		"https://example.com/missing": {
			statusCode:  http.StatusNotFound,
			contentType: "text/html",
			body:        `missing`,
		},
		"https://example.com/robots.txt": {
			statusCode: http.StatusNotFound,
			body:       `not found`,
		},
		"https://example.com/sitemap.xml": {
			statusCode: http.StatusNotFound,
			body:       `not found`,
		},
		"https://example.com/sitemap_index.xml": {
			statusCode: http.StatusNotFound,
			body:       `not found`,
		},
	})

	findings, err := crawlDetailedWithClient("https://example.com", 1, client)
	if err != nil {
		t.Fatalf("crawlDetailedWithClient returned error: %v", err)
	}

	if !hasCrawlFinding(findings, "https://example.com/", http.StatusOK) {
		t.Fatalf("expected 200 for root in %#v", findings)
	}
	if !hasCrawlFinding(findings, "https://example.com/ok", http.StatusOK) {
		t.Fatalf("expected 200 for /ok in %#v", findings)
	}
	if !hasCrawlFinding(findings, "https://example.com/missing", http.StatusNotFound) {
		t.Fatalf("expected 404 for /missing in %#v", findings)
	}
	if len(findings) == 0 || findings[len(findings)-1].StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 findings to be ordered last, got %#v", findings)
	}
}

func TestAnalyzeHTMLClientSurfaceFindsSecretsConfigAndAPISurface(t *testing.T) {
	client := newTestClient(map[string]testHTTPResponse{
		"https://example.com/assets/app.js": {
			contentType: "application/javascript",
			body: `const api_key = "ABCDEFGHIJKLMNOPQRST";
const users = "/api/v1/users";
const cfg = "/config.js";
`,
		},
		"https://example.com/config.js": {
			contentType: "application/javascript",
			body: `window.runtime = {
  client_secret: "supersecretABCDEFGH",
  auth: "Authorization: Bearer token.token.token"
};`,
		},
		"https://example.com/manifest.json": {
			contentType: "application/json",
			body:        `{"name":"Akemi"}`,
		},
		"https://example.com/openapi.json": {
			contentType: "application/json",
			body: `{
  "openapi": "3.0.0",
  "info": {"title": "Spec API", "version": "2.6.7"},
  "paths": {
    "/api/v2/orders": {
      "post": {}
    }
  }
}`,
		},
		"https://example.com/graphql": {
			statusCode: http.StatusBadRequest,
			body:       `{"error":"query required"}`,
		},
		"https://example.com/api/v1/users": {
			statusCode: http.StatusOK,
			body:       `[]`,
		},
		"https://example.com/api/v2/orders": {
			statusCode: http.StatusInternalServerError,
			body:       `{"error":"boom"}`,
		},
	})

	html := `<html>
<head>
  <link rel="manifest" href="/manifest.json">
  <script src="/assets/app.js"></script>
  <script>
    fetch("/graphql");
    const runtimeConfig = "/config.js";
  </script>
</head>
<body></body>
</html>`

	analysis := analyzeHTMLClientSurface("https://example.com/", html, client)

	for _, resource := range []string{
		"https://example.com/config.js",
		"https://example.com/manifest.json",
	} {
		if !contains(analysis.ConfigResources, resource) {
			t.Fatalf("expected config resource %q in %v", resource, analysis.ConfigResources)
		}
	}
	if !hasSecretCategory(analysis.SecretFindings, "API Key") {
		t.Fatalf("expected API Key finding in %#v", analysis.SecretFindings)
	}
	if !hasSecretCategory(analysis.SecretFindings, "Secret") {
		t.Fatalf("expected Secret finding in %#v", analysis.SecretFindings)
	}
	if !hasEndpoint(analysis.APIEndpoints, "https://example.com/graphql", "graphql", "") {
		t.Fatalf("expected graphql endpoint in %#v", analysis.APIEndpoints)
	}
	if !hasEndpoint(analysis.APIEndpoints, "https://example.com/api/v1/users", "rest", "") {
		t.Fatalf("expected rest endpoint in %#v", analysis.APIEndpoints)
	}
	if !hasEndpoint(analysis.APIEndpoints, "https://example.com/api/v2/orders", "openapi", "POST") {
		t.Fatalf("expected openapi endpoint in %#v", analysis.APIEndpoints)
	}
	if !hasEndpointStatus(analysis.APIEndpoints, "https://example.com/graphql", http.StatusBadRequest) {
		t.Fatalf("expected graphql status in %#v", analysis.APIEndpoints)
	}
	if !hasEndpointStatus(analysis.APIEndpoints, "https://example.com/api/v1/users", http.StatusOK) {
		t.Fatalf("expected rest status in %#v", analysis.APIEndpoints)
	}
	if !hasEndpointStatus(analysis.APIEndpoints, "https://example.com/api/v2/orders", http.StatusInternalServerError) {
		t.Fatalf("expected openapi endpoint status in %#v", analysis.APIEndpoints)
	}
	if len(analysis.APISpecs) != 1 || analysis.APISpecs[0].URL != "https://example.com/openapi.json" {
		t.Fatalf("expected openapi spec discovery, got %#v", analysis.APISpecs)
	}
	if analysis.APISpecs[0].StatusCode != http.StatusOK {
		t.Fatalf("expected openapi spec status 200, got %#v", analysis.APISpecs)
	}
	if len(analysis.LegacySecrets) == 0 {
		t.Fatalf("expected legacy secrets map to remain populated")
	}
}

func hasEndpoint(endpoints []APIEndpointFinding, url string, apiType string, method string) bool {
	for _, endpoint := range endpoints {
		if endpoint.URL == url && endpoint.APIType == apiType && endpoint.Method == method {
			return true
		}
	}
	return false
}

func hasEndpointStatus(endpoints []APIEndpointFinding, url string, statusCode int) bool {
	for _, endpoint := range endpoints {
		if endpoint.URL == url && endpoint.StatusCode == statusCode {
			return true
		}
	}
	return false
}

func hasSecretCategory(findings []SecretFinding, category string) bool {
	for _, finding := range findings {
		if finding.Category == category {
			return true
		}
	}
	return false
}

func hasCrawlFinding(findings []CrawlFinding, url string, statusCode int) bool {
	for _, finding := range findings {
		if finding.URL == url && finding.StatusCode == statusCode {
			return true
		}
	}
	return false
}
