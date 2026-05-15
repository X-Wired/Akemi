package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	core "Akemi/internal/core"
	"Akemi/internal/mcp"
	"Akemi/internal/surface"
	"Akemi/internal/toolbridge"
)

func handleFullSurfaceMap(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	target := getString(args, "target")
	if target == "" {
		target = getString(args, "url")
	}
	if target == "" {
		target = activeTargetBaseURL(ctx, svc)
	}
	if target == "" {
		target = activeTargetForPortScan(ctx, svc)
	}
	if target == "" {
		return nil, fmt.Errorf("target is required; call akemi_configure_target or pass target")
	}

	def := defaults(ctx, svc)
	portRange := firstNonBlank(getString(args, "port_range"), getString(args, "ports"), def.Ports, "top-1000")
	depthDefault := 2
	if def.Depth > 0 {
		depthDefault = def.Depth
	}
	cfg := surface.FullSurfaceConfig{
		Target:    target,
		Domain:    getString(args, "domain"),
		PortRange: portRange,
		Threads:   getInt(args, "threads", firstPositive(def.Threads, 200)),
		Timeout:   getInt(args, "timeout", firstPositive(def.Timeout, 10)),
		Depth:     getInt(args, "depth", depthDefault),
		Rate:      getFloat64(args, "rate", 0),
		SynMode:   getBool(args, "syn_mode"),
		Randomize: getBoolDefault(args, "randomize", true),
	}

	emitTargetConfig(ctx, svc, "akemi_full_surface_map", "Full surface map", toolbridge.TargetConfig{
		Target:  target,
		Ports:   portRange,
		Intent:  "full_surface_map",
		Threads: intPtr(cfg.Threads),
		Depth:   intPtr(cfg.Depth),
		Timeout: intPtr(cfg.Timeout),
	})

	result, err := surface.RunFullSurfaceMap(ctx, surface.Services{
		Scanner:       svc.Scanner,
		Discoverer:    svc.Discoverer,
		Prober:        svc.Prober,
		SubEnumerator: svc.SubEnumerator,
	}, cfg, surface.Callbacks{
		Port: func(port core.PortResult) {
			emitDiscoveryItems(ctx, svc, "akemi_full_surface_map", "Port scanning", portDiscoveryItems([]core.PortResult{port})...)
		},
		CrawlFinding: func(finding core.CrawlFinding) {
			emitDiscoveryItems(ctx, svc, "akemi_full_surface_map", "Crawling", crawlDiscoveryItem(finding))
		},
		Finding: func(finding core.VulnFinding) {
			emitDiscoveryItems(ctx, svc, "akemi_full_surface_map", "Checking headers and tech", vulnDiscoveryItem(finding))
		},
		Param: func(name string, detail core.ParamDetail) {
			emitDiscoveryItems(ctx, svc, "akemi_full_surface_map", "Mining parameters", paramDiscoveryItems(map[string]core.ParamDetail{name: detail})...)
		},
		JSAnalysis: func(pageURL string, jsResult *core.JSAnalysisResult) {
			_ = pageURL
			emitDiscoveryItems(ctx, svc, "akemi_full_surface_map", "Analyzing JavaScript", jsDiscoveryItems(jsResult)...)
		},
		APIResult: func(apiResult *core.APISurfaceResult) {
			emitDiscoveryItems(ctx, svc, "akemi_full_surface_map", "Discovering API surface", apiDiscoveryItems(apiResult)...)
		},
		Subdomain: func(subdomain core.SubdomainResult) {
			emitDiscoveryItems(ctx, svc, "akemi_full_surface_map", "Enumerating subdomains", subdomainDiscoveryItems([]core.SubdomainResult{subdomain})...)
		},
	})
	if err != nil {
		return nil, err
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	counts := result.Counts
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Full Surface Map Results for %s:\n", target))
	sb.WriteString(fmt.Sprintf("  Ports: %d\n", counts["ports"]))
	sb.WriteString(fmt.Sprintf("  URLs: %d\n", counts["urls"]))
	sb.WriteString(fmt.Sprintf("  Params: %d\n", counts["params"]))
	sb.WriteString(fmt.Sprintf("  JS analyses: %d\n", counts["js_analysis"]))
	sb.WriteString(fmt.Sprintf("  API endpoints: %d | API specs: %d\n", counts["api_endpoints"], counts["api_specs"]))
	sb.WriteString(fmt.Sprintf("  Subdomains: %d\n", counts["subdomains"]))
	sb.WriteString(fmt.Sprintf("  Findings: %d | Secrets: %d\n", counts["vuln_findings"], counts["secrets"]))
	if len(result.Errors) > 0 {
		sb.WriteString(fmt.Sprintf("  Stage errors: %d\n", len(result.Errors)))
		for _, stageErr := range result.Errors {
			sb.WriteString(fmt.Sprintf("    - %s: %s\n", stageErr.Stage, stageErr.Error))
		}
	}
	sb.WriteString("\n--- RAW JSON ---\n")
	sb.Write(data)

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func vulnDiscoveryItem(f core.VulnFinding) toolbridge.DiscoveryItem {
	key := strings.Join([]string{f.ID, f.Name, f.Target, f.Evidence}, "|")
	item := strings.TrimSpace(f.Name)
	if item == "" {
		item = strings.TrimSpace(f.Description)
	}
	if item == "" {
		item = "finding"
	}
	if f.Severity != "" {
		item = fmt.Sprintf("[%s] %s", f.Severity, item)
	}
	if f.Target != "" {
		item = fmt.Sprintf("%s (%s)", item, f.Target)
	}
	return toolbridge.DiscoveryItem{Section: "Findings", Key: key, Item: item}
}
