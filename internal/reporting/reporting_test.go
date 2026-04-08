package reporting

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildGraphMasksSecretsAndIncludesAPISurfaceNodes(t *testing.T) {
	secretValue := "supersecretABCDEFGH1234"
	report := &ScanReport{
		Target:          "https://example.com",
		CrawlDetails:    []CrawlFinding{{URL: "https://example.com/", StatusCode: 200, Status: "200 OK"}},
		ConfigResources: []string{"https://example.com/config.js"},
		SecretFindings: []SecretFinding{
			{
				Category:   "Secret",
				Value:      secretValue,
				SourceURL:  "https://example.com/config.js",
				SourceKind: "config_js",
			},
		},
		APIEndpoints: []APIEndpointFinding{
			{
				URL:        "https://example.com/api/v1/users",
				APIType:    "rest",
				Version:    "v1",
				StatusCode: 200,
				Status:     "200 OK",
			},
		},
		APISpecs: []APISpecFinding{
			{
				URL:        "https://example.com/openapi.json",
				APIType:    "openapi",
				Format:     "json",
				StatusCode: 200,
				Status:     "200 OK",
			},
		},
	}

	graph := BuildGraph(report)

	var hasConfigNode, hasEndpointNode, hasSpecNode bool
	for _, node := range graph.Nodes {
		switch node.Type {
		case "config_resource":
			hasConfigNode = true
		case "api_endpoint":
			hasEndpointNode = true
			if node.Meta["status_code"] != "200" {
				t.Fatalf("expected api endpoint status in graph meta: %#v", node)
			}
		case "api_spec":
			hasSpecNode = true
			if node.Meta["status_code"] != "200" {
				t.Fatalf("expected api spec status in graph meta: %#v", node)
			}
		}

		if strings.Contains(node.Label, secretValue) {
			t.Fatalf("graph leaked full secret in label: %#v", node)
		}
		for key, value := range node.Meta {
			if strings.Contains(key, secretValue) || strings.Contains(value, secretValue) {
				t.Fatalf("graph leaked full secret in meta: %#v", node)
			}
		}
	}

	if !hasConfigNode || !hasEndpointNode || !hasSpecNode {
		t.Fatalf("expected config/api nodes, got %#v", graph.Nodes)
	}
}

func TestWriteHTMLIncludesFullSecretAndAPISurface(t *testing.T) {
	secretValue := "supersecretABCDEFGH1234"
	report := &ScanReport{
		Target: "https://example.com",
		CrawlDetails: []CrawlFinding{
			{URL: "https://example.com/missing", StatusCode: 404, Status: "404 Not Found"},
			{URL: "https://example.com/", StatusCode: 200, Status: "200 OK"},
		},
		ParamMining:     map[string]RichParamDetail{"id": {InferredType: "int", SourceTypes: []ParamSource{"url_query"}, Sources: []string{"https://example.com/?id=1"}, Values: []string{"1"}}},
		ConfigResources: []string{"https://example.com/config.js"},
		SecretFindings: []SecretFinding{
			{
				Category:   "Secret",
				Value:      secretValue,
				SourceURL:  "https://example.com/config.js",
				SourceKind: "config_js",
			},
		},
		APIEndpoints: []APIEndpointFinding{
			{
				URL:        "https://example.com/graphql",
				APIType:    "graphql",
				Method:     "POST",
				StatusCode: 400,
				Status:     "400 Bad Request",
				Evidence:   []string{"inline_js"},
			},
		},
		APISpecs: []APISpecFinding{
			{
				URL:           "https://example.com/openapi.json",
				APIType:       "openapi",
				Format:        "json",
				Title:         "Spec API",
				Version:       "2.6.7",
				StatusCode:    200,
				Status:        "200 OK",
				EndpointCount: 1,
			},
		},
	}

	graph := BuildGraph(report)
	var buf bytes.Buffer
	if err := report.WriteHTML(&buf, graph); err != nil {
		t.Fatalf("WriteHTML returned error: %v", err)
	}

	html := buf.String()
	for _, expected := range []string{
		secretValue,
		"API Surface",
		"https://example.com/openapi.json",
		"https://example.com/graphql",
		"200 OK",
		"400 Bad Request",
		"404 Not Found",
		"https://example.com/?id=1",
	} {
		if !strings.Contains(html, expected) {
			t.Fatalf("expected HTML report to contain %q", expected)
		}
	}
	if strings.Index(html, "https://example.com/") > strings.Index(html, "https://example.com/missing") {
		t.Fatalf("expected 200 crawl rows to appear before 404 crawl rows in HTML: %s", html)
	}
}
