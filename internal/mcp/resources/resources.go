package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	core "Akemi/internal/core"
	"Akemi/internal/engagement"
	"Akemi/internal/mcp"
	mcpstate "Akemi/internal/mcp/state"
)

// Config wires MCP resources to live Akemi state.
type Config struct {
	Context engagement.ContextStore
	Prober  core.Prober
	State   *mcpstate.Store
}

// ResourceProvider manages MCP resources: read-only data that gives LLMs
// current scan, template, and engagement context.
type ResourceProvider struct {
	resources map[string]mcp.Resource
	context   engagement.ContextStore
	prober    core.Prober
	state     *mcpstate.Store
}

// NewResourceProvider creates a resource provider with standard resources.
func NewResourceProvider(cfgs ...Config) *ResourceProvider {
	var cfg Config
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}
	if cfg.State == nil {
		cfg.State = mcpstate.NewStore(cfg.Context)
	}
	rp := &ResourceProvider{
		resources: make(map[string]mcp.Resource),
		context:   cfg.Context,
		prober:    cfg.Prober,
		state:     cfg.State,
	}
	rp.registerAll()
	return rp
}

// List returns all available resources.
func (rp *ResourceProvider) List() []mcp.Resource {
	resources := make([]mcp.Resource, 0, len(rp.resources))
	for _, r := range rp.resources {
		resources = append(resources, r)
	}
	return resources
}

// Read returns the content of a resource by URI.
func (rp *ResourceProvider) Read(uri string) ([]mcp.ResourceContent, error) {
	resource, ok := rp.resources[uri]
	if !ok {
		return nil, fmt.Errorf("resource not found: %s", uri)
	}
	value, mimeType, err := rp.valueForURI(uri)
	if err != nil {
		return nil, err
	}
	if mimeType == "" {
		mimeType = resource.MimeType
	}
	text := ""
	if strings.HasPrefix(mimeType, "application/json") {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return nil, err
		}
		text = string(data)
	} else if s, ok := value.(string); ok {
		text = s
	} else {
		text = fmt.Sprint(value)
	}
	return []mcp.ResourceContent{{
		URI:      resource.URI,
		MimeType: mimeType,
		Text:     text,
	}}, nil
}

func (rp *ResourceProvider) valueForURI(uri string) (interface{}, string, error) {
	ctx := context.Background()
	switch uri {
	case "akemi://templates/list":
		if rp.prober == nil {
			return []core.ProbeTemplate{}, "application/json", nil
		}
		return rp.prober.ListTemplates(), "application/json", nil
	case "akemi://config":
		value := map[string]interface{}{}
		if rp.context != nil {
			if snapshot, err := rp.context.Snapshot(ctx); err == nil {
				value["engagement"] = snapshot
			}
		}
		if rp.state != nil {
			value["runtime"] = rp.state.Snapshot(ctx)
		}
		return value, "application/json", nil
	case "akemi://scan/current/summary":
		return rp.scanSummary(), "application/json", nil
	case "akemi://scan/current/open_ports":
		return rp.pathFromLatest("port_scan", "open_ports"), "application/json", nil
	case "akemi://scan/current/vulnerabilities":
		return firstNonNil(rp.pathFromLatest("vuln_findings"), rp.pathFromLatest("findings"), []interface{}{}), "application/json", nil
	case "akemi://scan/current/discovered_urls":
		return firstNonNil(rp.pathFromLatest("crawl_findings"), rp.pathFromLatest("urls"), []interface{}{}), "application/json", nil
	case "akemi://scan/current/secrets":
		return redactSecrets(firstNonNil(rp.pathFromLatest("secrets"), []interface{}{})), "application/json", nil
	case "akemi://scan/current/api_endpoints":
		return firstNonNil(rp.pathFromLatest("api_endpoints"), []interface{}{}), "application/json", nil
	case "akemi://scan/current/subdomains":
		return firstNonNil(rp.pathFromLatest("subdomains"), []interface{}{}), "application/json", nil
	case "akemi://help/usage":
		return usageGuide(), "text/markdown", nil
	default:
		return nil, "", fmt.Errorf("resource not found: %s", uri)
	}
}

func (rp *ResourceProvider) scanSummary() map[string]interface{} {
	out := map[string]interface{}{
		"resources": []string{
			"akemi://scan/current/open_ports",
			"akemi://scan/current/vulnerabilities",
			"akemi://scan/current/discovered_urls",
			"akemi://scan/current/secrets",
			"akemi://scan/current/api_endpoints",
			"akemi://scan/current/subdomains",
		},
	}
	if rp.state == nil {
		return out
	}
	snapshot := rp.state.Snapshot(context.Background())
	out["last_tool"] = snapshot["last_tool"]
	out["jobs"] = snapshot["jobs"]
	if structured := rp.latestStructured(); structured != nil {
		if counts, ok := structured["counts"]; ok {
			out["counts"] = counts
		}
	}
	return out
}

func (rp *ResourceProvider) latestStructured() map[string]interface{} {
	if rp.state == nil {
		return nil
	}
	for _, toolName := range []string{"akemi_full_surface_map", "akemi_port_scan", "akemi_probe_vulns", "akemi_crawl"} {
		if structured := rp.state.LastStructured(toolName); structured != nil {
			return structured
		}
	}
	return nil
}

func (rp *ResourceProvider) pathFromLatest(path ...string) interface{} {
	value := interface{}(rp.latestStructured())
	for _, segment := range path {
		m, ok := value.(map[string]interface{})
		if !ok {
			return nil
		}
		value = m[segment]
	}
	return value
}

func firstNonNil(values ...interface{}) interface{} {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func redactSecrets(value interface{}) interface{} {
	switch v := value.(type) {
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, item := range v {
			out[i] = redactSecrets(item)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, item := range v {
			if strings.EqualFold(key, "value") || strings.EqualFold(key, "evidence") {
				out[key] = mask(fmt.Sprint(item))
				continue
			}
			out[key] = redactSecrets(item)
		}
		return out
	default:
		return value
	}
}

func mask(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return "<redacted>"
	}
	return value[:4] + "..." + value[len(value)-4:]
}

func usageGuide() string {
	return `# Akemi MCP Usage

Configure the active target first with akemi_configure_target, then run discovery or validation tools that match the authorized scope.

Use akemi_start_run for long-running full surface mapping and akemi_run_status to poll progress. Read akemi://scan/current/summary and related resources for structured results instead of asking for large raw tool output.

Only test targets you are authorized to assess.`
}

func (rp *ResourceProvider) registerAll() {
	resources := []mcp.Resource{
		{URI: "akemi://templates/list", Name: "Probe Templates", Title: "Probe Templates", Description: "All available YAML vulnerability probe templates with IDs, severities, tags, and descriptions", MimeType: "application/json"},
		{URI: "akemi://config", Name: "Current Configuration", Title: "Current Configuration", Description: "The current Akemi engagement context and runtime MCP state", MimeType: "application/json"},
		{URI: "akemi://scan/current/summary", Name: "Current Scan Summary", Title: "Current Scan Summary", Description: "Summary of the most recent or ongoing scan", MimeType: "application/json"},
		{URI: "akemi://scan/current/open_ports", Name: "Open Ports", Title: "Open Ports", Description: "Open ports discovered in the current scan", MimeType: "application/json"},
		{URI: "akemi://scan/current/vulnerabilities", Name: "Vulnerability Findings", Title: "Vulnerability Findings", Description: "Vulnerability findings from the current scan", MimeType: "application/json"},
		{URI: "akemi://scan/current/discovered_urls", Name: "Discovered URLs", Title: "Discovered URLs", Description: "URLs discovered by crawling", MimeType: "application/json"},
		{URI: "akemi://scan/current/secrets", Name: "Discovered Secrets", Title: "Discovered Secrets", Description: "Secrets found in JavaScript files and configuration resources with values redacted", MimeType: "application/json"},
		{URI: "akemi://scan/current/api_endpoints", Name: "API Endpoints", Title: "API Endpoints", Description: "Discovered API endpoints", MimeType: "application/json"},
		{URI: "akemi://scan/current/subdomains", Name: "Discovered Subdomains", Title: "Discovered Subdomains", Description: "Enumerated subdomains", MimeType: "application/json"},
		{URI: "akemi://help/usage", Name: "Usage Guide", Title: "Usage Guide", Description: "How to use Akemi MCP tools and resources", MimeType: "text/markdown"},
	}
	for _, r := range resources {
		rp.resources[r.URI] = r
	}
}
