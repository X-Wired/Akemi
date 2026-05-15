package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	core "Akemi/internal/core"
	"Akemi/internal/engagement"
	"Akemi/internal/mcp"
	"Akemi/internal/toolbridge"
)

func (r *ToolRegistry) registerContextTools() {
	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_configure_target",
			Description: "Configure the active Akemi MCP target context. Later tools can omit target/url and will use this profile.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"id":       {Type: "string", Description: "Stable target identifier. If omitted, Akemi derives one."},
					"name":     {Type: "string", Description: "Human-readable target name"},
					"base_url": {Type: "string", Description: "Primary web URL, e.g. https://example.com"},
					"domain":   {Type: "string", Description: "Primary DNS domain, e.g. example.com"},
					"hosts":    {Type: "array", Description: "Hostnames or IPs in scope", Items: &mcp.Property{Type: "string"}},
					"cidrs":    {Type: "array", Description: "CIDR ranges in scope", Items: &mcp.Property{Type: "string"}},
					"notes":    {Type: "string", Description: "Operator notes for this target"},
				},
			},
		},
		Handler: handleConfigureTarget,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_get_target",
			Description: "Read the current Akemi MCP target context, configured defaults, and parameter count.",
			InputSchema: mcp.ToolInputSchema{Type: "object", Properties: map[string]mcp.Property{}},
		},
		Handler: handleGetTarget,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_configure_defaults",
			Description: "Configure default scan/crawl/probe/parameter-mining options used when MCP tool arguments are omitted.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"ports":        {Type: "string", Description: "Default port list or range, e.g. top-1000 or 80,443,8000-8080"},
					"threads":      {Type: "integer", Description: "Default thread/concurrency count"},
					"timeout":      {Type: "integer", Description: "Default timeout in seconds"},
					"depth":        {Type: "integer", Description: "Default managed crawl depth 1-7. 1=1000 URLs, 2=2000 URLs, ... 6=6000 URLs, 7=unlimited URL budget."},
					"vuln_tags":    {Type: "array", Description: "Default vulnerability template tags", Items: &mcp.Property{Type: "string"}},
					"template_id":  {Type: "string", Description: "Default vulnerability template ID"},
					"mine_js":      {Type: "boolean", Description: "Default parameter mining: JavaScript"},
					"mine_forms":   {Type: "boolean", Description: "Default parameter mining: HTML forms"},
					"mine_json":    {Type: "boolean", Description: "Default parameter mining: JSON keys"},
					"mine_path":    {Type: "boolean", Description: "Default parameter mining: REST path segments"},
					"active_brute": {Type: "boolean", Description: "Default parameter mining: active brute force"},
				},
			},
		},
		Handler: handleConfigureDefaults,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_add_parameters",
			Description: "Add one or more manually known parameters to the active target parameter catalog.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target_id":    {Type: "string", Description: "Target ID. Defaults to active target."},
					"parameters":   {Type: "array", Description: "Parameter objects with name, endpoint, method, location, sample_value, and source", Items: &mcp.Property{Type: "object"}},
					"name":         {Type: "string", Description: "Single parameter name"},
					"endpoint":     {Type: "string", Description: "Endpoint where the parameter appears"},
					"method":       {Type: "string", Description: "HTTP method", Default: "GET"},
					"location":     {Type: "string", Description: "Parameter location", Enum: []string{"query", "body", "path", "header", "cookie", "form", "json"}},
					"sample_value": {Type: "string", Description: "Example value"},
					"source":       {Type: "string", Description: "Source or operator note"},
				},
			},
		},
		Handler: handleAddParameters,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_list_parameters",
			Description: "List configured and discovered parameters for the active target.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"target_id": {Type: "string", Description: "Target ID. Defaults to active target."},
				},
			},
		},
		Handler: handleListParameters,
	})

	r.register(RegisteredTool{
		Tool: mcp.Tool{
			Name:        "akemi_clear_context",
			Description: "Clear the active Akemi MCP target context, defaults, and parameter catalog.",
			InputSchema: mcp.ToolInputSchema{Type: "object", Properties: map[string]mcp.Property{}},
		},
		Handler: handleClearContext,
	})
}

func handleConfigureTarget(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	target := engagement.TargetProfile{
		ID:      getString(args, "id"),
		Name:    getString(args, "name"),
		BaseURL: normalizeURLArg(getString(args, "base_url")),
		Domain:  getString(args, "domain"),
		Hosts:   getStringSlice(args, "hosts"),
		CIDRs:   getStringSlice(args, "cidrs"),
		Notes:   getString(args, "notes"),
	}
	if target.BaseURL == "" && target.Domain == "" && len(target.Hosts) == 0 && len(target.CIDRs) == 0 {
		return nil, fmt.Errorf("configure target requires base_url, domain, hosts, or cidrs")
	}
	if err := svc.Context.SetTarget(ctx, target); err != nil {
		return nil, err
	}
	snapshot, _ := svc.Context.Snapshot(ctx)
	emitTargetConfig(ctx, svc, "akemi_configure_target", "Target configured", toolbridge.TargetConfig{
		Target: displayTarget(target),
	})
	return jsonContent("Configured active target.", snapshot)
}

func handleGetTarget(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	_ = args
	snapshot, err := svc.Context.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	return jsonContent("Current Akemi MCP context.", snapshot)
}

func handleConfigureDefaults(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	defaults, err := svc.Context.GetDefaults(ctx)
	if err != nil {
		return nil, err
	}
	if hasArg(args, "ports") {
		defaults.Ports = getString(args, "ports")
	}
	if hasArg(args, "threads") {
		defaults.Threads = getInt(args, "threads", defaults.Threads)
	}
	if hasArg(args, "timeout") {
		defaults.Timeout = getInt(args, "timeout", defaults.Timeout)
	}
	if hasArg(args, "depth") {
		defaults.Depth = core.NormalizeCrawlDepth(getInt(args, "depth", defaults.Depth))
	}
	if hasArg(args, "vuln_tags") {
		defaults.VulnTags = getStringSlice(args, "vuln_tags")
	}
	if hasArg(args, "template_id") {
		defaults.TemplateID = getString(args, "template_id")
	}
	if hasArg(args, "mine_js") {
		defaults.MineJS = boolPtr(getBool(args, "mine_js"))
	}
	if hasArg(args, "mine_forms") {
		defaults.MineForms = boolPtr(getBool(args, "mine_forms"))
	}
	if hasArg(args, "mine_json") {
		defaults.MineJSON = boolPtr(getBool(args, "mine_json"))
	}
	if hasArg(args, "mine_path") {
		defaults.MinePath = boolPtr(getBool(args, "mine_path"))
	}
	if hasArg(args, "active_brute") {
		defaults.ActiveBrute = boolPtr(getBool(args, "active_brute"))
	}
	if err := svc.Context.SetDefaults(ctx, defaults); err != nil {
		return nil, err
	}
	emitTargetConfig(ctx, svc, "akemi_configure_defaults", "Defaults configured", toolbridge.TargetConfig{
		Ports:   defaults.Ports,
		Threads: intPtr(defaults.Threads),
		Depth:   intPtr(defaults.Depth),
		Timeout: intPtr(defaults.Timeout),
	})
	return jsonContent("Configured MCP tool defaults.", defaults)
}

func displayTarget(target engagement.TargetProfile) string {
	switch {
	case strings.TrimSpace(target.BaseURL) != "":
		return target.BaseURL
	case strings.TrimSpace(target.Domain) != "":
		return target.Domain
	case len(target.Hosts) > 0 && strings.TrimSpace(target.Hosts[0]) != "":
		return target.Hosts[0]
	case len(target.CIDRs) > 0 && strings.TrimSpace(target.CIDRs[0]) != "":
		return target.CIDRs[0]
	case strings.TrimSpace(target.Name) != "":
		return target.Name
	default:
		return target.ID
	}
}

func handleAddParameters(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	targetID, err := resolveTargetID(ctx, svc, getString(args, "target_id"))
	if err != nil {
		return nil, err
	}

	params := parseParameterRecords(args)
	if len(params) == 0 {
		return nil, fmt.Errorf("add parameters requires at least one parameter name")
	}
	if err := svc.Context.AddParameters(ctx, targetID, params); err != nil {
		return nil, err
	}
	all, _ := svc.Context.ListParameters(ctx, targetID)
	return jsonContent(fmt.Sprintf("Added %d parameter(s). Target now has %d parameter record(s).", len(params), len(all)), all)
}

func handleListParameters(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	targetID, err := resolveTargetID(ctx, svc, getString(args, "target_id"))
	if err != nil {
		return nil, err
	}
	params, err := svc.Context.ListParameters(ctx, targetID)
	if err != nil {
		return nil, err
	}
	return jsonContent(fmt.Sprintf("Parameter catalog for %s: %d record(s).", targetID, len(params)), params)
}

func handleClearContext(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	_ = args
	if err := svc.Context.Clear(ctx); err != nil {
		return nil, err
	}
	emitTargetConfig(ctx, svc, "akemi_clear_context", "Context cleared", toolbridge.TargetConfig{Clear: true})
	return []mcp.ContentBlock{mcp.TextContent("Akemi MCP context cleared.")}, nil
}

func parseParameterRecords(args map[string]interface{}) []engagement.ParameterRecord {
	var params []engagement.ParameterRecord
	if raw, ok := args["parameters"].([]interface{}); ok {
		for _, item := range raw {
			if m, ok := item.(map[string]interface{}); ok {
				params = append(params, engagement.ParameterRecord{
					TargetID:    getString(m, "target_id"),
					Endpoint:    getString(m, "endpoint"),
					Method:      getString(m, "method"),
					Name:        getString(m, "name"),
					Location:    getString(m, "location"),
					SampleValue: getString(m, "sample_value"),
					Source:      getString(m, "source"),
				})
			}
		}
	}
	if name := getString(args, "name"); name != "" {
		params = append(params, engagement.ParameterRecord{
			Endpoint:    getString(args, "endpoint"),
			Method:      getString(args, "method"),
			Name:        name,
			Location:    getString(args, "location"),
			SampleValue: getString(args, "sample_value"),
			Source:      getString(args, "source"),
		})
	}
	return params
}

func resolveTargetID(ctx context.Context, svc *Services, targetID string) (string, error) {
	targetID = strings.TrimSpace(targetID)
	if targetID != "" {
		return targetID, nil
	}
	target, err := svc.Context.GetActiveTarget(ctx)
	if err != nil {
		return "", err
	}
	if target == nil || strings.TrimSpace(target.ID) == "" {
		return "", fmt.Errorf("no active target configured; call akemi_configure_target or pass target_id")
	}
	return target.ID, nil
}

func activeTargetForPortScan(ctx context.Context, svc *Services) string {
	target, err := svc.Context.GetActiveTarget(ctx)
	if err != nil || target == nil {
		return ""
	}
	if len(target.Hosts) > 0 {
		return target.Hosts[0]
	}
	if target.Domain != "" {
		return target.Domain
	}
	if len(target.CIDRs) > 0 {
		return target.CIDRs[0]
	}
	if target.BaseURL != "" {
		if parsed, err := url.Parse(target.BaseURL); err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
	}
	return ""
}

func activeTargetBaseURL(ctx context.Context, svc *Services) string {
	target, err := svc.Context.GetActiveTarget(ctx)
	if err != nil || target == nil {
		return ""
	}
	if target.BaseURL != "" {
		return target.BaseURL
	}
	if target.Domain != "" {
		return core.EnsureProtocol(target.Domain)
	}
	if len(target.Hosts) > 0 {
		return core.EnsureProtocol(target.Hosts[0])
	}
	return ""
}

func defaults(ctx context.Context, svc *Services) engagement.ScanDefaults {
	if svc == nil || svc.Context == nil {
		return engagement.ScanDefaults{}
	}
	d, err := svc.Context.GetDefaults(ctx)
	if err != nil {
		return engagement.ScanDefaults{}
	}
	return d
}

func jsonContent(summary string, value interface{}) ([]mcp.ContentBlock, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return []mcp.ContentBlock{mcp.TextContent(summary + "\n\n" + string(data))}, nil
}

func normalizeURLArg(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return core.EnsureProtocol(value)
}

func hasArg(args map[string]interface{}, key string) bool {
	if args == nil {
		return false
	}
	_, ok := args[key]
	return ok
}

func getBoolDefault(args map[string]interface{}, key string, defaultVal bool) bool {
	if !hasArg(args, key) {
		return defaultVal
	}
	return getBool(args, key)
}

func defaultBool(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func getStringSlice(args map[string]interface{}, key string) []string {
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil
	}
	var values []string
	switch v := raw.(type) {
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				values = append(values, strings.TrimSpace(s))
			}
		}
	case []string:
		for _, item := range v {
			if strings.TrimSpace(item) != "" {
				values = append(values, strings.TrimSpace(item))
			}
		}
	case string:
		for _, item := range strings.Split(v, ",") {
			if strings.TrimSpace(item) != "" {
				values = append(values, strings.TrimSpace(item))
			}
		}
	}
	return values
}

func boolPtr(value bool) *bool {
	return &value
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func storeDiscoveredParams(ctx context.Context, svc *Services, endpoint string, result *core.ParamDiscoveryResult) {
	if svc == nil || svc.Context == nil || result == nil || len(result.Params) == 0 {
		return
	}
	target, err := svc.Context.GetActiveTarget(ctx)
	if err != nil || target == nil || strings.TrimSpace(target.ID) == "" {
		return
	}
	records := make([]engagement.ParameterRecord, 0, len(result.Params))
	for name, detail := range result.Params {
		if strings.TrimSpace(name) == "" {
			continue
		}
		records = append(records, engagement.ParameterRecord{
			TargetID: target.ID,
			Endpoint: endpoint,
			Method:   "GET",
			Name:     name,
			Location: "unknown",
			Source:   "akemi_mine_params:" + strings.Join(detail.Sources, ","),
		})
	}
	_ = svc.Context.AddParameters(ctx, target.ID, records)
}
