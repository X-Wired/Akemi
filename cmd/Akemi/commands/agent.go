package commands

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"Akemi/internal/agent"
	"Akemi/internal/agent/events"
	"Akemi/internal/agent/safety"
	"Akemi/internal/agent/tool"
	core "Akemi/internal/core"
	"Akemi/internal/reportfiles"
	"Akemi/internal/surface"

	"github.com/spf13/cobra"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run Akemi as an autonomous security testing agent",
		Long: `Execute autonomous security testing workflows powered by the agent system.

The agent takes a high-level goal and target, plans a task graph using the
tool registry, executes tasks in dependency order with parallel execution,
and reports findings in real-time.

Available intents:
  full_surface_map    Complete attack surface discovery
  full_surface_scan   Alias for full_surface_map
  quick_recon         Fast initial triage
  sqli_hunt           Focused SQL injection discovery
  vuln_assessment     Full vulnerability scan with exploit correlation
  api_review          API-focused security assessment

Examples:
  akemi agent --target https://example.com --intent quick_recon
  akemi agent --target example.com --intent full_surface_map
  akemi agent --target https://target.com/page?id=1 --intent sqli_hunt
  akemi agent --target https://api.target.com --intent api_review`,
		RunE: runAgent,
	}

	cmd.Flags().StringP("target", "t", "", "Target URL, domain, or IP (required)")
	cmd.Flags().String("intent", "quick_recon", "Agent intent: quick_recon, full_surface_map/full_surface_scan, sqli_hunt, vuln_assessment, api_review")
	cmd.Flags().String("description", "", "Custom description of the goal (optional)")
	cmd.Flags().Int("concurrency", 5, "Maximum parallel tasks")
	cmd.Flags().Int("max-rpm", 300, "Maximum requests per minute per target")
	cmd.Flags().String("approve-risk", "active", "Maximum autonomous risk: safe, passive, active, intrusive, destructive")
	cmd.Flags().StringSlice("allow-domain", nil, "Allowed domains (can specify multiple)")
	cmd.Flags().StringSlice("allow-cidr", nil, "Allowed CIDR ranges")
	cmd.Flags().StringSlice("block-domain", nil, "Blocked domains")
	cmd.Flags().String("probe-dir", "./probes", "Directory containing YAML probe templates")

	return cmd
}

func runAgent(cmd *cobra.Command, args []string) error {
	target, _ := cmd.Flags().GetString("target")
	if target == "" {
		return fmt.Errorf("--target is required")
	}

	intent, _ := cmd.Flags().GetString("intent")
	description, _ := cmd.Flags().GetString("description")
	concurrency, _ := cmd.Flags().GetInt("concurrency")
	maxRPM, _ := cmd.Flags().GetInt("max-rpm")
	approveRisk, _ := cmd.Flags().GetString("approve-risk")
	allowDomains, _ := cmd.Flags().GetStringSlice("allow-domain")
	allowCIDRs, _ := cmd.Flags().GetStringSlice("allow-cidr")
	blockDomains, _ := cmd.Flags().GetStringSlice("block-domain")
	probeDir, _ := cmd.Flags().GetString("probe-dir")
	maxAutoRisk, err := tool.ParseRiskLevel(approveRisk)
	if err != nil {
		return err
	}
	if len(allowDomains) == 0 && len(allowCIDRs) == 0 {
		allowDomains, allowCIDRs = deriveAgentScope(target)
	}

	if description == "" {
		description = fmt.Sprintf("Run %s against %s", intent, target)
	}

	// Setup logger
	logLevel := slog.LevelInfo
	if rootVerbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Initialize services and build tool registry
	svc := initServices(logger, rootOutputDir)
	if probeDir != "" {
		svc.Vuln.LoadTemplates(probeDir)
	}

	reg := buildAgentToolRegistry(svc, logger)

	// Create agent
	ag := agent.NewAgent(reg, agent.Config{
		AllowedDomains: allowDomains,
		AllowedCIDRs:   allowCIDRs,
		BlockedDomains: blockDomains,
		MaxRPM:         maxRPM,
		MaxConcurrency: concurrency,
		MaxAutoRisk:    maxAutoRisk,
		Logger:         logger,
	})

	// Subscribe to real-time events
	ag.SubscribeEvents(func(evt events.Event) {
		switch evt.Type {
		case events.EventPlanStarted:
			fmt.Printf("\n📋 %s\n", evt.Message)
		case events.EventPlanCompleted:
			fmt.Printf("\n✅ Plan completed: %s\n", evt.Message)
			if data, ok := evt.Data["duration"]; ok {
				fmt.Printf("   Duration: %s\n", data)
			}
		case events.EventTaskStarted:
			fmt.Printf("  ⏳ [%s] Starting...\n", evt.ToolName)
		case events.EventTaskCompleted:
			findings := eventDataInt(evt.Data, "findings")
			fmt.Printf("  ✅ [%s] Completed — %d findings\n", evt.ToolName, findings)
		case events.EventTaskDenied:
			fmt.Printf("  🛑 [%s] DENIED: %s\n", evt.ToolName, evt.Message)
		case events.EventTaskError:
			fmt.Printf("  ❌ [%s] ERROR: %s\n", evt.ToolName, evt.Message)
		case events.EventFindingDiscovered:
			sev := eventDataString(evt.Data, "severity")
			title := eventDataString(evt.Data, "title")
			fmt.Printf("    🔍 [%s] %s\n", sev, title)
		}
	})

	// Handle Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[!] Cancelling agent...")
		cancel()
	}()

	// Run agent
	startTime := time.Now()
	fmt.Printf("\n🤖 Akemi Agent v2.0.0-dev\n")
	fmt.Printf("   Target: %s\n", target)
	fmt.Printf("   Intent: %s\n", intent)
	fmt.Printf("   Risk:   <= %s\n", maxAutoRisk)
	fmt.Printf("   Tools:  %d available\n", reg.Count())
	if len(allowDomains) > 0 {
		fmt.Printf("   Scope:  %v\n", allowDomains)
	}
	if len(allowCIDRs) > 0 {
		fmt.Printf("   CIDRs:  %v\n", allowCIDRs)
	}
	fmt.Println()

	result, err := ag.Run(ctx, description, target, intent)
	if err != nil {
		return fmt.Errorf("agent execution failed: %w", err)
	}

	// Print final report
	fmt.Println()
	fmt.Println(result.Summary())

	// Print critical findings
	critical := result.CriticalFindings()
	if len(critical) > 0 {
		fmt.Printf("\n⚠️  CRITICAL/HIGH FINDINGS (%d):\n", len(critical))
		for _, f := range critical {
			fmt.Printf("  [%s] %s — %s\n", f.Severity, f.Title, f.Target)
			if f.Evidence != "" {
				fmt.Printf("    Evidence: %s\n", truncate(f.Evidence, 120))
			}
		}
	}

	fmt.Printf("\n⏱️  Total agent time: %s\n", time.Since(startTime))

	return nil
}

func deriveAgentScope(target string) ([]string, []string) {
	normalized := safety.NormalizeTargetHost(target)
	if normalized == "" {
		return nil, nil
	}
	if _, _, err := net.ParseCIDR(normalized); err == nil {
		return nil, []string{normalized}
	}
	if ip := net.ParseIP(normalized); ip != nil {
		if ip.To4() != nil {
			return nil, []string{ip.String() + "/32"}
		}
		return nil, []string{ip.String() + "/128"}
	}
	return []string{normalized}, nil
}

func eventDataInt(data map[string]interface{}, key string) int {
	if data == nil {
		return 0
	}
	switch v := data[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case int32:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	default:
		return 0
	}
}

func eventDataString(data map[string]interface{}, key string) string {
	if data == nil {
		return ""
	}
	if s, ok := data[key].(string); ok {
		return s
	}
	return ""
}

// buildAgentToolRegistry creates an agent tool registry from Phase 1 services.
func buildAgentToolRegistry(svc *Services, logger *slog.Logger) *tool.Registry {
	reg := tool.NewRegistry()
	const agentToolTimeout = 5 * time.Hour

	// Port scanning
	reg.Register(&tool.AgentTool{
		Name: "akemi_port_scan", DisplayName: "Port Scanner", Category: tool.CategoryRecon,
		Description: "High-speed TCP port scanning with service fingerprinting and banner grabbing.",
		RiskLevel:   tool.RiskActive, IsIdempotent: true,
		Provides:       []string{"open_ports", "services", "banners", "technologies"},
		Requires:       []string{},
		DefaultTimeout: agentToolTimeout, MaxRetries: 1,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_port_scan", args)
		},
	})

	// Crawl
	reg.Register(&tool.AgentTool{
		Name: "akemi_crawl", DisplayName: "Web Crawler", Category: tool.CategoryDiscovery,
		Description: "Crawl a website through Akemi's managed crawler. Depth 1-6 caps URLs at depth*1000; depth 7 removes the URL cap.",
		RiskLevel:   tool.RiskActive, IsIdempotent: false,
		Provides:       []string{"urls", "discovered_urls"},
		Requires:       []string{},
		DefaultTimeout: agentToolTimeout, MaxRetries: 0,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_crawl", args)
		},
	})

	// Full surface map
	reg.Register(&tool.AgentTool{
		Name: "akemi_full_surface_map", DisplayName: "Full Surface Map", Category: tool.CategoryDiscovery,
		Description: "Run the dedicated full_surface_map workflow used by the target configuration dashboard.",
		RiskLevel:   tool.RiskActive, IsIdempotent: false,
		Provides:       []string{"surface_map", "open_ports", "urls", "parameters", "api_endpoints", "subdomains", "findings", "secrets"},
		Requires:       []string{},
		DefaultTimeout: agentToolTimeout, MaxRetries: 0,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_full_surface_map", args)
		},
	})

	// Parameter mining
	reg.Register(&tool.AgentTool{
		Name: "akemi_mine_params", DisplayName: "Parameter Miner", Category: tool.CategoryDiscovery,
		Description: "Mine HTTP parameters from URLs, forms, JS, and JSON.",
		RiskLevel:   tool.RiskPassive, IsIdempotent: false,
		Provides:       []string{"parameters", "form_inputs"},
		Requires:       []string{"urls"},
		DefaultTimeout: agentToolTimeout, MaxRetries: 0,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_mine_params", args)
		},
	})

	// JS analysis
	reg.Register(&tool.AgentTool{
		Name: "akemi_analyze_js", DisplayName: "JS Analyzer", Category: tool.CategoryDiscovery,
		Description: "Analyze JavaScript for endpoints and secrets.",
		RiskLevel:   tool.RiskPassive, IsIdempotent: false,
		Provides:       []string{"endpoints", "secrets", "hidden_params"},
		Requires:       []string{"urls"},
		DefaultTimeout: agentToolTimeout, MaxRetries: 0,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_analyze_js", args)
		},
	})

	// API discovery
	reg.Register(&tool.AgentTool{
		Name: "akemi_discover_api", DisplayName: "API Discovery", Category: tool.CategoryDiscovery,
		Description: "Discover API endpoints and specifications.",
		RiskLevel:   tool.RiskPassive, IsIdempotent: false,
		Provides:       []string{"api_endpoints", "api_specs"},
		Requires:       []string{"urls"},
		DefaultTimeout: agentToolTimeout, MaxRetries: 0,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_discover_api", args)
		},
	})

	reg.Register(&tool.AgentTool{
		Name: "akemi_api_hunter", DisplayName: "API Hunter", Category: tool.CategoryDiscovery,
		Description: "First-class API hunting with JS/config/spec discovery, safe-active probing, auth hints, parameters, and confidence scoring.",
		RiskLevel:   tool.RiskActive, IsIdempotent: false,
		Provides:       []string{"api_endpoints", "api_specs", "api_parameters", "api_auth_hints"},
		Requires:       []string{"urls"},
		DefaultTimeout: agentToolTimeout, MaxRetries: 0,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_api_hunter", args)
		},
	})

	// Subdomain enumeration
	reg.Register(&tool.AgentTool{
		Name: "akemi_subdomain_enum", DisplayName: "Subdomain Enumerator", Category: tool.CategoryRecon,
		Description: "Enumerate subdomains via crt.sh and wordlist.",
		RiskLevel:   tool.RiskPassive, IsIdempotent: true,
		Provides:       []string{"subdomains", "dns_records"},
		Requires:       []string{},
		DefaultTimeout: agentToolTimeout, MaxRetries: 1,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_subdomain_enum", args)
		},
	})

	// Vulnerability probing
	reg.Register(&tool.AgentTool{
		Name: "akemi_probe_vulns", DisplayName: "Vulnerability Prober", Category: tool.CategoryVulnerability,
		Description: "Execute YAML-based vulnerability probes. ACTIVE — requires confirmation.",
		RiskLevel:   tool.RiskIntrusive, IsIdempotent: false, RequiresApproval: true,
		Provides:       []string{"vulnerabilities", "findings"},
		Requires:       []string{"parameters"},
		DefaultTimeout: agentToolTimeout, MaxRetries: 0,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_probe_vulns", args)
		},
	})

	// Security headers
	reg.Register(&tool.AgentTool{
		Name: "akemi_check_headers", DisplayName: "Header Auditor", Category: tool.CategoryVulnerability,
		Description: "Audit HTTP security headers and cookie flags.",
		RiskLevel:   tool.RiskPassive, IsIdempotent: true,
		Provides:       []string{"header_findings", "cookie_issues"},
		Requires:       []string{},
		DefaultTimeout: agentToolTimeout, MaxRetries: 0,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_check_headers", args)
		},
	})

	// Tech fingerprint
	reg.Register(&tool.AgentTool{
		Name: "akemi_tech_fingerprint", DisplayName: "Tech Fingerprinter", Category: tool.CategoryDiscovery,
		Description: "Identify technology stack from headers and responses.",
		RiskLevel:   tool.RiskPassive, IsIdempotent: true,
		Provides:       []string{"technologies", "framework_hints"},
		Requires:       []string{},
		DefaultTimeout: agentToolTimeout, MaxRetries: 0,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_tech_fingerprint", args)
		},
	})

	// Exploit lookup
	reg.Register(&tool.AgentTool{
		Name: "akemi_exploit_lookup", DisplayName: "ExploitDB Lookup", Category: tool.CategoryExploitation,
		Description: "Query ExploitDB for matching known exploits.",
		RiskLevel:   tool.RiskSafe, IsIdempotent: true,
		Provides:       []string{"exploit_matches"},
		Requires:       []string{"technologies", "services"},
		DefaultTimeout: agentToolTimeout, MaxRetries: 0,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_exploit_lookup", args)
		},
	})

	// Report generation
	reg.Register(&tool.AgentTool{
		Name: "akemi_generate_report", DisplayName: "Report Generator", Category: tool.CategoryReporting,
		Description: "Generate HTML/JSON reports from findings.",
		RiskLevel:   tool.RiskSafe, IsIdempotent: true,
		Provides:       []string{"report"},
		Requires:       []string{},
		DefaultTimeout: agentToolTimeout, MaxRetries: 0,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_generate_report", args)
		},
	})

	reg.Register(&tool.AgentTool{
		Name: "akemi_read_report", DisplayName: "Report Reader", Category: tool.CategoryReporting,
		Description: "Read a report artifact from Akemi's configured report directory.",
		RiskLevel:   tool.RiskSafe, IsIdempotent: true,
		Provides:       []string{"report_content"},
		Requires:       []string{"report"},
		DefaultTimeout: agentToolTimeout, MaxRetries: 0,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_read_report", args)
		},
	})

	reg.Register(&tool.AgentTool{
		Name: "akemi_write_report", DisplayName: "Report Writer", Category: tool.CategoryReporting,
		Description: "Write a report artifact under Akemi's configured report directory.",
		RiskLevel:   tool.RiskSafe, IsIdempotent: false,
		Provides:       []string{"report"},
		Requires:       []string{},
		DefaultTimeout: agentToolTimeout, MaxRetries: 0,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_write_report", args)
		},
	})

	// Graph generation
	reg.Register(&tool.AgentTool{
		Name: "akemi_generate_graph", DisplayName: "Graph Generator", Category: tool.CategoryReporting,
		Description: "Generate attack surface graph visualizations.",
		RiskLevel:   tool.RiskSafe, IsIdempotent: true,
		Provides:       []string{"graph"},
		Requires:       []string{},
		DefaultTimeout: agentToolTimeout, MaxRetries: 0,
		Handler: func(ctx context.Context, args map[string]interface{}) (*tool.ToolResult, error) {
			return executeTool(ctx, svc, "akemi_generate_graph", args)
		},
	})

	return reg
}

// executeTool routes agent tool calls to the Phase 1 service layer.
func executeTool(ctx context.Context, svc *Services, toolName string, args map[string]interface{}) (*tool.ToolResult, error) {
	start := time.Now()
	result := &tool.ToolResult{
		ToolName: toolName,
		Status:   tool.StatusSuccess,
		Data:     make(map[string]interface{}),
	}

	var err error

	switch toolName {
	case "akemi_port_scan":
		target := getFirstString(args, "target", "host", "url", "domain")
		portsStr := getStr(args, "ports")
		var ports []int
		if portsStr != "" {
			// Parse ports - simplified
			ports = []int{80, 443, 8080, 8443} // Default top ports
		} else {
			ports = []int{80, 443, 8080, 8443}
		}
		scanResult, scanErr := svc.Scanner.Scan(ctx, buildScanRequest(target, ports, args))
		err = scanErr
		if scanResult != nil {
			result.Data["open_ports"] = scanResult.OpenPorts
			result.Data["services"] = extractServices(scanResult)
			result.Summary = fmt.Sprintf("Scan complete: %d open ports on %s", len(scanResult.OpenPorts), target)
			result.Metrics.ItemsFound = len(scanResult.OpenPorts)
		}

	case "akemi_crawl":
		url := getURLInput(args)
		depth := core.NormalizeCrawlDepth(getInt(args, "depth", 3))
		findings, crawlErr := svc.Discovery.Crawl(ctx, url, depth)
		err = crawlErr
		if findings != nil {
			urls := make([]string, len(findings))
			for i, f := range findings {
				urls[i] = f.URL
			}
			result.Data["urls"] = urls
			result.Data["discovered_urls"] = findings
			limit := core.CrawlURLLimitForDepth(depth)
			limitText := "unlimited"
			if limit > 0 {
				limitText = fmt.Sprintf("%d", limit)
			}
			result.Data["crawl_depth"] = depth
			result.Data["url_limit"] = limit
			result.Summary = fmt.Sprintf("Crawl complete: %d URLs discovered (depth %d, URL limit %s)", len(findings), depth, limitText)
			result.Metrics.ItemsFound = len(findings)
		}

	case "akemi_full_surface_map":
		target := getURLInput(args)
		portRange := getFirstString(args, "port_range", "ports")
		if portRange == "" {
			portRange = "top-1000"
		}
		mapResult, mapErr := surface.RunFullSurfaceMap(ctx, surface.Services{
			Scanner:       svc.Scanner,
			Discoverer:    svc.Discovery,
			Prober:        svc.Vuln,
			SubEnumerator: svc.Subdomain,
		}, surface.FullSurfaceConfig{
			Target:    target,
			Domain:    getStr(args, "domain"),
			PortRange: portRange,
			Threads:   getInt(args, "threads", 200),
			Timeout:   getInt(args, "timeout", 10),
			Depth:     getInt(args, "depth", 2),
			Rate:      0,
			Randomize: true,
		}, surface.Callbacks{})
		err = mapErr
		if mapResult != nil {
			result.Data["surface_map"] = mapResult
			if mapResult.PortScan != nil {
				result.Data["open_ports"] = mapResult.PortScan.OpenPorts
			}
			result.Data["discovered_urls"] = mapResult.CrawlFindings
			result.Data["parameters"] = mapResult.Params
			result.Data["api_endpoints"] = mapResult.APIEndpoints
			result.Data["api_specs"] = mapResult.APISpecs
			result.Data["subdomains"] = mapResult.Subdomains
			result.Data["findings"] = mapResult.VulnFindings
			result.Data["secrets"] = mapResult.Secrets
			result.Data["counts"] = mapResult.Counts
			if len(mapResult.Errors) > 0 {
				result.Status = tool.StatusPartial
				result.Data["stage_errors"] = mapResult.Errors
			}
			result.Summary = fmt.Sprintf(
				"Full surface map: %d ports, %d URLs, %d params, %d API endpoints, %d subdomains, %d findings, %d secrets",
				mapResult.Counts["ports"],
				mapResult.Counts["urls"],
				mapResult.Counts["params"],
				mapResult.Counts["api_endpoints"],
				mapResult.Counts["subdomains"],
				mapResult.Counts["vuln_findings"],
				mapResult.Counts["secrets"],
			)
			result.Metrics.ItemsFound = mapResult.Counts["ports"] +
				mapResult.Counts["urls"] +
				mapResult.Counts["params"] +
				mapResult.Counts["api_endpoints"] +
				mapResult.Counts["subdomains"] +
				mapResult.Counts["vuln_findings"] +
				mapResult.Counts["secrets"]
		}

	case "akemi_mine_params":
		url := getURLInput(args)
		cfg := buildMiningConfig(args)
		params, mineErr := svc.Discovery.MineParams(ctx, url, cfg)
		err = mineErr
		if params != nil {
			result.Data["parameters"] = params
			result.Summary = fmt.Sprintf("Parameter mining complete: %d parameters found", params.TotalCount)
			result.Metrics.ItemsFound = params.TotalCount
		}

	case "akemi_analyze_js":
		url := getURLInput(args)
		jsResult, jsErr := svc.Discovery.AnalyzeJS(ctx, url)
		err = jsErr
		if jsResult != nil {
			result.Data["endpoints"] = jsResult.Endpoints
			result.Data["secrets"] = jsResult.Secrets
			result.Summary = fmt.Sprintf("JS analysis: %d endpoints, %d secrets", len(jsResult.Endpoints), len(jsResult.Secrets))
			result.Metrics.ItemsFound = len(jsResult.Endpoints) + len(jsResult.Secrets)
		}

	case "akemi_discover_api":
		url := getURLInput(args)
		apiResult, apiErr := svc.Discovery.DiscoverAPISurface(ctx, url, nil)
		err = apiErr
		if apiResult != nil {
			result.Data["api_endpoints"] = apiResult.APIEndpoints
			result.Data["api_specs"] = apiResult.APISpecs
			result.Summary = fmt.Sprintf("API discovery: %d endpoints, %d specs", len(apiResult.APIEndpoints), len(apiResult.APISpecs))
			result.Metrics.ItemsFound = len(apiResult.APIEndpoints) + len(apiResult.APISpecs)
		}

	case "akemi_api_hunter":
		url := getURLInput(args)
		huntResult, huntErr := svc.Discovery.HuntAPISurface(ctx, core.APIHuntRequest{
			StartURL:      url,
			Mode:          firstNonBlank(getStr(args, "mode"), "safe-active"),
			WordlistFile:  getStr(args, "wordlist"),
			AuthCookies:   splitCookieHeader(getStr(args, "cookies")),
			MaxCandidates: getInt(args, "max_candidates", 250),
			Threads:       getInt(args, "threads", 10),
			Timeout:       getInt(args, "timeout", 10),
		})
		err = huntErr
		if huntResult != nil {
			result.Data["api_hunter"] = huntResult
			result.Data["api_endpoints"] = huntResult.APIEndpoints
			result.Data["api_specs"] = huntResult.APISpecs
			result.Data["api_parameters"] = huntResult.Parameters
			result.Data["api_source_summary"] = huntResult.SourceSummary
			result.Summary = fmt.Sprintf("API Hunter: %d endpoints, %d specs, %d parameters",
				len(huntResult.APIEndpoints), len(huntResult.APISpecs), len(huntResult.Parameters))
			result.Metrics.ItemsFound = len(huntResult.APIEndpoints) + len(huntResult.APISpecs) + len(huntResult.Parameters)
		}

	case "akemi_subdomain_enum":
		domain := getStr(args, "domain")
		subCfg := buildSubdomainConfig(args)
		subs, subErr := svc.Subdomain.Enumerate(ctx, domain, subCfg)
		err = subErr
		if subs != nil {
			result.Data["subdomains"] = subs
			result.Summary = fmt.Sprintf("Subdomain enumeration: %d found", len(subs))
			result.Metrics.ItemsFound = len(subs)
		}

	case "akemi_probe_vulns":
		url := getURLInput(args)
		probeCfg := buildProbeConfig(args)
		findings, probeErr := svc.Vuln.Probe(ctx, url, probeCfg)
		err = probeErr
		if findings != nil {
			result.Data["vulnerabilities"] = findings
			result.Data["findings"] = findings
			result.Summary = fmt.Sprintf("Vulnerability probe: %d findings", len(findings))
			result.Metrics.ItemsFound = len(findings)
			// Convert to agent findings
			for _, f := range findings {
				result.Findings = append(result.Findings, tool.Finding{
					ID:          f.ID,
					ToolName:    toolName,
					Type:        "vulnerability",
					Severity:    f.Severity,
					Title:       f.Name,
					Description: f.Description,
					Evidence:    f.Evidence,
					Target:      f.Target,
					Timestamp:   time.Now(),
				})
			}
		}

	case "akemi_check_headers":
		url := getStr(args, "url")
		hdrCfg := buildProbeConfig(args)
		hdrCfg.TemplateTags = []string{"headers", "misconfig"}
		findings, hdrErr := svc.Vuln.Probe(ctx, url, hdrCfg)
		err = hdrErr
		if findings != nil {
			result.Data["header_findings"] = findings
			result.Summary = fmt.Sprintf("Header audit: %d issues found", len(findings))
			result.Metrics.ItemsFound = len(findings)
		}

	case "akemi_tech_fingerprint":
		url := getStr(args, "url")
		techCfg := buildProbeConfig(args)
		techCfg.TemplateTags = []string{"tech", "detect"}
		findings, techErr := svc.Vuln.Probe(ctx, url, techCfg)
		err = techErr
		if findings != nil {
			result.Data["technologies"] = findings
			result.Summary = fmt.Sprintf("Tech fingerprint: %d technologies identified", len(findings))
			result.Metrics.ItemsFound = len(findings)
		}

	case "akemi_exploit_lookup", "akemi_generate_report", "akemi_generate_graph":
		result.Status = tool.StatusPartial
		result.Summary = fmt.Sprintf("%s: available via full MCP server mode", toolName)

	case "akemi_read_report":
		path := getStr(args, "path")
		maxBytes := int64(getInt(args, "max_bytes", int(reportfiles.MaxReportBytes)))
		resolved, data, readErr := reportfiles.Read(rootOutputDir, path, maxBytes)
		err = readErr
		if readErr == nil {
			result.Data["path"] = resolved
			result.Data["content"] = string(data)
			result.Summary = fmt.Sprintf("Report read: %s (%d bytes)", resolved, len(data))
			result.Metrics.ItemsFound = 1
		}

	case "akemi_write_report":
		path := getStr(args, "path")
		content := getStr(args, "content")
		overwrite := true
		if v, ok := args["overwrite"].(bool); ok {
			overwrite = v
		}
		resolved, bytesWritten, writeErr := reportfiles.Write(rootOutputDir, path, content, overwrite)
		err = writeErr
		if writeErr == nil {
			result.Data["path"] = resolved
			result.Data["bytes"] = bytesWritten
			result.Summary = fmt.Sprintf("Report written: %s (%d bytes)", resolved, bytesWritten)
			result.Metrics.ItemsFound = 1
		}

	default:
		return nil, fmt.Errorf("unknown agent tool: %s", toolName)
	}

	if err != nil {
		result.Status = tool.StatusError
		result.Error = err.Error()
	}

	result.Metrics.DurationMs = time.Since(start).Milliseconds()
	return result, nil
}

// =============================================================================
// Helper functions for argument extraction and config building
// =============================================================================

func getStr(args map[string]interface{}, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func getFirstString(args map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if s := getStringValue(args[key]); s != "" {
			return s
		}
	}
	return ""
}

func getURLInput(args map[string]interface{}) string {
	return getFirstString(args, "urls", "url", "target", "host", "domain")
}

func getStringValue(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case []string:
		if len(v) > 0 {
			return v[0]
		}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func getInt(args map[string]interface{}, key string, def int) int {
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return def
}

func buildScanRequest(target string, ports []int, args map[string]interface{}) core.ScanRequest {
	return core.ScanRequest{
		Host:       target,
		Ports:      ports,
		Threads:    200,
		TimeoutMs:  3000,
		BannerGrab: true,
	}
}

func buildMiningConfig(args map[string]interface{}) core.MiningConfig {
	return core.MiningConfig{
		MineJS:    true,
		MineForms: true,
		MineJSON:  true,
		MinePath:  true,
	}
}

func buildSubdomainConfig(args map[string]interface{}) core.SubdomainConfig {
	return core.SubdomainConfig{
		Threads:    20,
		Timeout:    10,
		UseCrtSh:   true,
		CheckAlive: true,
	}
}

func buildProbeConfig(args map[string]interface{}) core.ProbeConfig {
	tags := getStr(args, "tags")
	var tagList []string
	if tags != "" {
		tagList = splitComma(tags)
	}
	return core.ProbeConfig{
		Threads:      5,
		Timeout:      10,
		UseTemplates: true,
		TemplateTags: tagList,
	}
}

func extractServices(result *core.ScanResult) []string {
	var services []string
	for _, p := range result.OpenPorts {
		for _, tech := range p.Technology {
			services = append(services, tech)
		}
	}
	return services
}
