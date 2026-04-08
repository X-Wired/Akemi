package main

import (
	akemi "Akemi/internal/app"
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

func main() {
	startTime := time.Now()


	// ── Original CLI flags ────────────────────────────
	urlPtr := flag.String("u", "", "Target URL")
	methodPtr := flag.String("m", "GET", "HTTP Request Type (GET|POST|PUT|DELETE|PATCH)")
	dataPtr := flag.String("d", "", "POST/PUT/PATCH data")
	payloadFilePtr := flag.String("w", "payloads.txt", "Wordlist/Payload data file (formerly -p)")
	outputFilePtr := flag.String("o", "fuzz_results.txt", "Fuzz output")
	repeats := flag.Int("r", 1, "Request number per payload")
	timeout := flag.Int("t", 10, "Timeout (seconds)")
	concurrency := flag.Int("c", 10, "Concurrency (threads)")
	crawlFlag := flag.Bool("crawl", false, "Crawl the site and list discovered URLs")
	paramsFlag := flag.Bool("params", false, "Enhanced param mining (JS + forms + JSON + path + URL)")
	scrapeFlag := flag.Bool("scrape", false, "Scrape page title, meta, forms, links and comments")
	depth := flag.Int("depth", 2, "Crawl depth")
	proxyPtr := flag.String("proxy", "", "Route outbound HTTP/TCP traffic through a proxy (http://, https://, socks5://, socks5h://)")
	noProxyPtr := flag.String("no-proxy", "", "Comma-separated hosts or domains to bypass the proxy")
	quietFlag := flag.Bool("quiet", false, "Suppress ASCII art and decorative headers")
	flag.BoolVar(quietFlag, "q", false, "Shorthand for --quiet")

	helpPtr := flag.Bool("h", false, "Show help")

	// ── New module flags ──────────────────────────────

	// JS Analyzer
	jsFlag := flag.Bool("js", false, "Analyze JS files for endpoints, params and secrets")


	// Vuln Check
	probeFlag := flag.Bool("vuln-check", false, "Run active vuln probes (uses YAML templates by default)")
	probeThreads := flag.Int("vuln-check-threads", 5, "Threads for vuln probing")
	probeDir := flag.String("vuln-check-dir", "./probes", "Directory containing YAML probe templates")
	probeTags := flag.String("vuln-check-tags", "", "Comma-separated tags to filter templates (e.g. sqli,high)")
	probeID := flag.String("vuln-check-id", "", "Run a specific probe template by ID")
	probeList := flag.Bool("vuln-check-list", false, "List all available probe templates and exit")
	probeLegacy := flag.Bool("vuln-check-legacy", false, "Use legacy hardcoded probes instead of YAML templates")

	// Subdomain Enumeration
	subFlag := flag.Bool("sub", false, "Enumerate subdomains")
	subWordlist := flag.String("sub-w", "", "Wordlist file for subdomain bruteforce")
	subThreads := flag.Int("sub-threads", 20, "Threads for subdomain enumeration")
	subCrtSh := flag.Bool("sub-crtsh", true, "Query crt.sh certificate transparency logs")
	subAlive := flag.Bool("sub-alive", true, "Probe discovered subdomains for live HTTP")
	subPermute := flag.Bool("sub-permute", false, "Generate subdomain permutations from found names")

	// Enhanced param mining options (used with --params)
	paramJS := flag.Bool("params-js", true, "Mine JS files during param discovery")
	paramForms := flag.Bool("params-forms", true, "Mine form inputs during param discovery")
	paramJSON := flag.Bool("params-json", true, "Mine JSON response keys during param discovery")
	paramPath := flag.Bool("params-path", true, "Detect path parameters during param discovery")
	paramBrute := flag.Bool("params-brute", false, "Active param brute-force (Arjun-style)")

	// Report generation
	reportFlag := flag.Bool("report", false, "Generate scan report after execution")
	reportJSON := flag.Bool("report-json", false, "Export report as JSON")
	reportHTML := flag.Bool("report-html", false, "Export report as HTML (default if --report)")
	reportDir := flag.String("report-dir", ".", "Output directory for reports")

	// Port Scanning
	portScanFlag := flag.Bool("port-scan", false, "Run template-based port scan")
	portScanPorts := flag.String("p", akemi.Top1000Ports, "Comma-separated ports or ranges for port scan")
	portScanRate := flag.Float64("rate", 0, "Port scan rate limit (connections/sec, 0=unlimited)")
	portScanSyn := flag.Bool("syn", false, "Use SYN scan mode (requires admin/root + Npcap on Windows)")
	portScanRetries := flag.Int("retries", 1, "Retry count for timed-out ports")
	portScanRandomize := flag.Bool("randomize", true, "Randomize port scan order (IDS evasion)")
	portScanResume := flag.String("resume", "", "Path to scan state file for resume")
	portScanTargets := flag.String("targets", "", "File containing list of targets (IPs or domains) for port scan")
	portScanThreads := flag.Int("scanthreads", 200, "Concurrent threads for port scanning (default 200)")
	portScanVerbose := flag.Bool("v", false, "Verbose scanner output (show progress, headers)")
	portScanNoPort := flag.Bool("np", false, "Host discovery only (CIDR sweep/IP), no port scanning")



	// Graph generation
	graphFlag := flag.Bool("graph", false, "Generate relational scan graph")
	graphJSON := flag.Bool("graph-json", false, "Export graph as JSON")
	graphDOT := flag.Bool("graph-dot", false, "Export graph as DOT (Graphviz)")
	graphHTML := flag.Bool("graph-html", false, "Export graph as interactive HTML (default if --graph)")
	graphOut := flag.String("graph-out", "", "Custom output path for graph file")

	// Dorking & Keywords
	dorkPtr := flag.String("dork", "", "Execute Google/DuckDuckGo dorking query to find targets")
	dorkFilePtr := flag.String("dork-file", "", "File containing dork templates (use TARGET as placeholder)")
	flag.StringVar(dorkFilePtr, "D", "", "Shorthand for --dork-file")
	enginePtr := flag.String("engine", "duckduckgo", "Search engine to use (google|duckduckgo)")
	keywordsPtr := flag.String("keywords", "", "Comma-separated list of keywords to hunt for in discovered pages")

	scrapingFlag := flag.Bool("scraping", false, "Alias for dorking/search mode")

	// ExploitDB Integration
	exploitDBPath := flag.String("exploitdb", "", "Path to ExploitDB files_exploits.csv")
	exploitLookup := flag.Bool("exploit-lookup", false, "Correlate port scan results with ExploitDB")
	exploitLookupMax := flag.Int("exploit-lookup-max", 10, "Max exploits per service in lookup")


	flag.Parse()

	if !*quietFlag {
		akemi.PrintASCIIArtNeon()
	}

	if err := akemi.ConfigureProxy(*proxyPtr, *noProxyPtr); err != nil {
		if !handleBrokenProxy(err) {
			return
		}
	}
	if err := akemi.ValidateActiveProxy(); err != nil {
		if !handleBrokenProxy(err) {
			return
		}
	}
	if err := akemi.CheckActiveProxyConnectivity(8); err != nil {
		if !handleBrokenProxy(err) {
			return
		}
	}
	if akemi.ProxyEnabled() {
		fmt.Printf("[proxy] Outbound traffic routed via %s\n", akemi.ActiveProxyDisplay())
		if source := akemi.ActiveProxySource(); source != "" {
			fmt.Printf("[proxy] Source: %s\n", source)
		}
		if bypass := akemi.ActiveNoProxy(); bypass != "" {
			fmt.Printf("[proxy] Bypass list: %s\n", bypass)
		}
	}

	// ── Probe list mode ───────────────────
	if *probeList {
		templates, err := akemi.LoadTemplates(*probeDir)
		if err != nil {
			fmt.Printf("Error loading templates: %v\n", err)
			return
		}
		akemi.ListTemplates(templates)
		return
	}

	// ── CLI mode ──────────────────────────────────────

	if *helpPtr {
		ShowHelp()
		return
	}

	if *urlPtr == "" && *portScanTargets == "" && *dorkPtr == "" && *dorkFilePtr == "" && !*scrapingFlag {
		fmt.Println("Missing parameter -u (or --targets for port scan or --dork/--dork-file for search mode)")
		return
	}


	// ── Dorking Logic ─────────────────────────────────
	var finalDorks []string
	if *dorkPtr != "" {
		finalDorks = append(finalDorks, *dorkPtr)
	}
	if *dorkFilePtr != "" {
		content, err := os.ReadFile(*dorkFilePtr)
		if err != nil {
			fmt.Printf("[!] Error reading dork file: %v\n", err)
		} else {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				processed := strings.ReplaceAll(line, "TARGET", *urlPtr)
				finalDorks = append(finalDorks, processed)
			}
		}
	}

	if len(finalDorks) > 0 {
		var allDiscoveredURLs []string
		seenURLs := make(map[string]bool)

		for i, dork := range finalDorks {
			if i > 0 {
				r := rand.New(rand.NewSource(time.Now().UnixNano()))
				delay := time.Duration(r.Intn(4)+2) * time.Second // 2 to 5 seconds
				fmt.Printf("[*] Sleeping for %v before next dork query...\n", delay)
				time.Sleep(delay)
			}
			fmt.Printf("[*] Performing dork: %s [%s]\n", dork, *enginePtr)
			dorkCfg := akemi.DorkConfig{
				Query:      dork,
				Engine:     *enginePtr,
				MaxResults: 20,
			}
			urls, err := akemi.PerformDork(dorkCfg)
			if err != nil {
				fmt.Printf("[!] Dork error for '%s': %v\n", dork, err)
				continue
			}
			for _, u := range urls {
				if !seenURLs[u] {
					seenURLs[u] = true
					allDiscoveredURLs = append(allDiscoveredURLs, u)
				}
			}
		}

		if len(allDiscoveredURLs) > 0 {
			fmt.Printf("[+] Found %d unique potential targets via dorking\n", len(allDiscoveredURLs))
			for _, u := range allDiscoveredURLs {
				fmt.Printf("    -> %s\n", u)
			}
			if *urlPtr == "" {
				*urlPtr = allDiscoveredURLs[0]
				fmt.Printf("[*] Using %s as primary target for subsequent modules\n", *urlPtr)
			}
		}
	}

	explicitFuzzing := strings.Contains(*urlPtr, "FUZZ") ||
		strings.Contains(*dataPtr, "FUZZ") ||
		*payloadFilePtr != "payloads.txt"
	if len(finalDorks) > 0 && !explicitFuzzing && !*crawlFlag && !*paramsFlag &&
		!*scrapeFlag && !*jsFlag && !*subFlag && !*probeFlag && !*portScanFlag {
		fmt.Printf("\nTotal execution time: %s\n", time.Since(startTime))
		return
	}

	// Parsing keywords
	var keywords []string
	if *keywordsPtr != "" {
		keywords = strings.Split(*keywordsPtr, ",")
		for i := range keywords {
			keywords[i] = strings.TrimSpace(keywords[i])
		}
	}

	discoveryMode := *crawlFlag || *paramsFlag || *scrapeFlag || *jsFlag || *subFlag

	var report *akemi.ScanReport
	wantReport := *reportFlag || *reportJSON || *reportHTML
	wantGraph := *graphFlag || *graphJSON || *graphDOT || *graphHTML
	if wantReport || wantGraph {
		report = akemi.NewScanReport(*urlPtr)
	}

	// ── Port Scanning ─────────────────────────────────
	if *portScanFlag || *portScanNoPort {
		var psTargets []string
		if *portScanTargets != "" {
			file, err := os.Open(*portScanTargets)
			if err == nil {
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					t := strings.TrimSpace(scanner.Text())
					if t != "" && !strings.HasPrefix(t, "#") {
						psTargets = append(psTargets, t)
					}
				}
				file.Close()
			} else {
				fmt.Printf("Error reading targets file: %v\n", err)
			}
		} else if *urlPtr != "" {
			targetHost := *urlPtr
			_, _, errCIDR := net.ParseCIDR(targetHost)
			if errCIDR != nil {
				if parsed, err := url.Parse(akemi.EnsureProtocol(targetHost)); err == nil {
					targetHost = parsed.Hostname()
				}
			}
			psTargets = append(psTargets, targetHost)
		}

		if len(psTargets) == 0 {
			fmt.Println("No targets provided for port scan (use -u or --targets)")
		} else {
			ports := akemi.ParsePortsList(strings.Split(*portScanPorts, ","))
			for _, targetHost := range psTargets {
				scanner := &akemi.PortScanner{
					Host:      targetHost,
					Threads:   *portScanThreads,
					TimeoutS:  *timeout,
					Ports:     ports,
					ProbeDir:  *probeDir,
					Rate:      *portScanRate,
					SynMode:   *portScanSyn,
					Retries:   *portScanRetries,
					Randomize: *portScanRandomize,
					Resume:    *portScanResume,
					Verbose:   *portScanVerbose,
					NoPorts:   *portScanNoPort,
				}
				summary, err := scanner.Run()
				if err != nil {
					fmt.Printf("Error running port scan for %s: %v\n", targetHost, err)
				} else if report != nil {
					if report.PortScanData == nil {
						report.PortScanData = summary
					} else {
						report.PortScanData.Results = append(report.PortScanData.Results, summary.Results...)
						for _, ip := range summary.IPs {
							if !akemi.Contains(report.PortScanData.IPs, ip) {
								report.PortScanData.IPs = append(report.PortScanData.IPs, ip)
							}
						}
					}
				}
			}
		}

		// ── ExploitDB Correlation ──────────────────────
		if *exploitLookup && *exploitDBPath != "" && report != nil && report.PortScanData != nil {
			fmt.Println("\n[*] Correlating port scan with ExploitDB...")
			edb, err := akemi.LoadExploitDB(*exploitDBPath)
			if err != nil {
				fmt.Printf("[!] ExploitDB error: %v\n", edb)
			} else {
				matches := akemi.MatchExploitsToScan(edb, report.PortScanData, *exploitLookupMax)
				akemi.PrintExploitMatches(matches)
				for _, m := range matches {
					report.ExploitMatches = append(report.ExploitMatches, m.Matches...)
				}
			}
		}
	}

	if discoveryMode {
		if *crawlFlag {
			fmt.Println("[*] Ejecutando Crawl...")
			crawlDetails, err := akemi.CrawlDetailed(*urlPtr, *depth)
			if err != nil {
				fmt.Printf("Error en Crawl: %v\n", err)
			} else {
				urls := make([]string, 0, len(crawlDetails))
				fmt.Printf("[+] URLs descubiertas (%d):\n", len(crawlDetails))
				for _, finding := range crawlDetails {
					urls = append(urls, finding.URL)
					fmt.Printf("  [%s] %s\n", finding.Status, finding.URL)
				}
				if report != nil {
					report.CrawlResults = urls
					report.CrawlDetails = crawlDetails
					if apiEndpoints, apiSpecs, err := akemi.DiscoverAPISurface(*urlPtr, urls, nil, akemi.CreateHTTPClient(*timeout)); err == nil {
						report.APIEndpoints = mergeAPIEndpointFindings(report.APIEndpoints, apiEndpoints)
						report.APISpecs = mergeAPISpecFindings(report.APISpecs, apiSpecs)
					}
				}
			}
		}

		if *paramsFlag {
			fmt.Println("\n[*] Ejecutando Enhanced Param Mining...")
			cfg := akemi.MiningConfig{
				Depth:   *depth,
				Threads: 10,
				Timeout: *timeout,
				SuspiciousPattern: regexp.MustCompile(
					`(?i)(id|page|user|token|key|pass|debug|cmd|exec|file|path|url|redirect|search|query|action)`,
				),
				MineJS:            *paramJS,
				MineForms:         *paramForms,
				MineJSONResponses: *paramJSON,
				MinePathParams:    *paramPath,
				ActiveBrute:       *paramBrute,
				Keywords:          keywords,
				MineKeywords:      len(keywords) > 0,
			}
			params, err := akemi.EnhancedDiscoverParams(*urlPtr, cfg)
			if err != nil {
				fmt.Printf("Error en param mining: %v\n", err)
			} else {
				akemi.PrintParamMiningResult(params.Params)
				if report != nil {
					applyDiscoveryResult(report, params)
				}
			}
		}

		if *scrapeFlag {
			fmt.Println("\n[*] Ejecutando ScrapePage...")
			result, err := akemi.ScrapePage(*urlPtr, keywords)
			if err != nil {
				fmt.Printf("Error en ScrapePage: %v\n", err)
			} else {
				if report != nil {
					report.ScrapeData = result
				}
			}
		}

		if *jsFlag {
			fmt.Println("\n[*] Ejecutando JS Analyzer...")
			jsResult, err := akemi.AnalyzeJS(*urlPtr)
			if err != nil {
				fmt.Printf("Error en JS analysis: %v\n", err)
			} else {
				akemi.PrintJSAnalysisResult(jsResult)
				if report != nil {
					applyJSAnalysisResult(report, jsResult)
				}
			}
		}

		if *subFlag {
			targetDomain := *urlPtr
			if parsed, err := url.Parse(akemi.EnsureProtocol(targetDomain)); err == nil {
				targetDomain = parsed.Hostname()
			}
			cfg := akemi.SubdomainConfig{
				Threads:      *subThreads,
				Timeout:      *timeout,
				WordlistFile: *subWordlist,
				CheckAlive:   *subAlive,
				UseCrtSh:     *subCrtSh,
				Permutate:    *subPermute,
			}
			results, err := akemi.EnumerateSubdomains(targetDomain, cfg)
			if err != nil {
				fmt.Printf("Error en subdomain enumeration: %v\n", err)
			} else {
				akemi.PrintSubdomainSummary(results)
				if report != nil {
					report.Subdomains = results
				}
			}
		}

		if *probeFlag {
			fmt.Println("\n[*] Ejecutando Vuln Probe...")
			probeCfg := akemi.ProbeConfig{
				Timeout:      *timeout,
				Threads:      *probeThreads,
				UseTemplates: !*probeLegacy,
				TemplateDir:  *probeDir,
			}
			if *probeTags != "" {
				probeCfg.TemplateTags = strings.Split(*probeTags, ",")
			}
			if *probeID != "" {
				probeCfg.TemplateIDs = []string{*probeID}
			}
			findings, err := akemi.ProbeParams(*urlPtr, probeCfg)
			if err != nil {
				fmt.Printf("Error en vuln probe: %v\n", err)
			} else {
				akemi.PrintVulnSummary(findings)
				if report != nil {
					report.VulnFindings = findings
				}

			}
		}


		if report != nil {
			report.Finalize()
			generateReportOutputs(report, *reportFlag, *reportJSON, *reportHTML, *reportDir)
			generateGraphOutputs(report, *graphFlag, *graphJSON, *graphDOT, *graphHTML, *graphOut, *reportDir)
		}

		fmt.Printf("\nTotal execution time: %s\n", time.Since(startTime))
		return
	}

	if *probeFlag {
		fmt.Println("\n[*] Ejecutando Vuln Probe...")
		probeCfg := akemi.ProbeConfig{
			Timeout:      *timeout,
			Threads:      *probeThreads,
			UseTemplates: !*probeLegacy,
			TemplateDir:  *probeDir,
		}
		if *probeTags != "" {
			probeCfg.TemplateTags = strings.Split(*probeTags, ",")
		}
		if *probeID != "" {
			probeCfg.TemplateIDs = []string{*probeID}
		}
		findings, err := akemi.ProbeParams(*urlPtr, probeCfg)
		if err != nil {
			fmt.Printf("Error en vuln probe: %v\n", err)
		} else {
			akemi.PrintVulnSummary(findings)

		}
		fmt.Printf("\nTotal execution time: %s\n", time.Since(startTime))
		return
	}


	// ── Fuzzer mode ───────────────────────────────────────
	if (*portScanFlag || *portScanNoPort) && !discoveryMode && *payloadFilePtr == "payloads.txt" {
		if _, err := os.Stat("payloads.txt"); os.IsNotExist(err) {
			if report != nil {
				report.Finalize()
				generateReportOutputs(report, *reportFlag, *reportJSON, *reportHTML, *reportDir)
			}
			return
		}
	}

	cfg := akemi.FuzzConfig{
		URL:         *urlPtr,
		Method:      *methodPtr,
		Data:        *dataPtr,
		PayloadFile: *payloadFilePtr,
		OutputFile:  *outputFilePtr,
		Repeats:     *repeats,
		Timeout:     *timeout,
		Concurrency: *concurrency,
	}

	results, fElapsed, err := akemi.RunFuzzer(cfg)
	if err != nil {
		fmt.Printf("Fuzzer error: %v\n", err)
		return
	}

	if report != nil {
		report.FuzzResults = results
		report.Finalize()
		generateReportOutputs(report, *reportFlag, *reportJSON, *reportHTML, *reportDir)
		generateGraphOutputs(report, *graphFlag, *graphJSON, *graphDOT, *graphHTML, *graphOut, *reportDir)
	}

	fmt.Printf("\nFuzzer time:           %s\n", fElapsed)
	fmt.Printf("Total execution time:  %s\n", time.Since(startTime))
}

func generateReportOutputs(report *akemi.ScanReport, doReport, doJSON, doHTML bool, dir string) {
	if !doReport && !doJSON && !doHTML {
		return
	}
	if doReport && !doJSON && !doHTML {
		doHTML = true
	}
	if doJSON {
		path := filepath.Join(dir, "akemi_report.json")
		report.SaveJSON(path)
	}
	if doHTML {
		graph := akemi.BuildGraph(report)
		path := filepath.Join(dir, "akemi_report.html")
		report.SaveHTML(path, graph)
	}
}

func generateGraphOutputs(report *akemi.ScanReport, doGraph, doJSON, doDOT, doHTML bool, customOut, dir string) {
	if !doGraph && !doJSON && !doDOT && !doHTML {
		return
	}
	graph := akemi.BuildGraph(report)
	if doGraph && !doJSON && !doDOT && !doHTML {
		doHTML = true
	}
	if doJSON {
		path := customOut
		if path == "" {
			path = filepath.Join(dir, "akemi_graph.json")
		}
		graph.SaveGraphJSON(path)
	}
	if doDOT {
		path := customOut
		if path == "" {
			path = filepath.Join(dir, "akemi_graph.dot")
		}
		graph.SaveGraphDOT(path)
	}
	if doHTML {
		path := customOut
		if path == "" {
			path = filepath.Join(dir, "akemi_graph.html")
		}
		graph.SaveGraphHTML(path)
	}
}

func ShowHelp() {
	fmt.Println("Usage: Akemi [options]")
	fmt.Println("\nCore Options:")
	fmt.Println("  -u <url>              Target URL")
	fmt.Println("  -server               Run in HTTP server mode")
	fmt.Println("  -addr <addr>          Server address (default :8080)")
	fmt.Println("  Proxy file            config/proxy.txt (auto-loaded, one proxy per line)")
	fmt.Println("\nModule Options:")
	fmt.Println("  -crawl                Enable web crawler")
	fmt.Println("  -params               Enable parameter discovery")
	fmt.Println("  -vuln-check           Enable active vulnerability probing")
	fmt.Println("  -sub                  Enable subdomain enumeration")
	fmt.Println("  -port-scan            Enable template-based port scanning")
	fmt.Println("\nReporting Options:")
	fmt.Println("  -report               Generate HTML report")
	fmt.Println("  -graph                Generate interaction graph")
	fmt.Println("\nUse -h for full list of flags.")
}

func handleBrokenProxy(err error) bool {
	fmt.Printf("[proxy] %v\n", err)
	if !proxyPromptSupported() {
		fmt.Println("[proxy] Cannot prompt in non-interactive mode. Aborting startup.")
		return false
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("[proxy] The configured proxy is not working. Continue without proxy? [y/N]: ")
	answer, readErr := reader.ReadString('\n')
	if readErr != nil {
		fmt.Printf("[proxy] Failed to read confirmation: %v\n", readErr)
		return false
	}

	answer = strings.ToLower(strings.TrimSpace(answer))
	switch answer {
	case "y", "yes", "s", "si", "sí":
		akemi.DisableProxy()
		fmt.Println("[proxy] Continuing without proxy.")
		return true
	default:
		fmt.Println("[proxy] Startup cancelled.")
		return false
	}
}

func proxyPromptSupported() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func applyDiscoveryResult(report *akemi.ScanReport, result *akemi.DiscoveryResult) {
	if report == nil || result == nil {
		return
	}
	report.ParamMining = result.Params
	report.KeywordMatches = result.KeywordMatches
	report.CrawlDetails = mergeCrawlFindings(report.CrawlDetails, result.CrawlDetails)
	if len(report.CrawlResults) == 0 && len(report.CrawlDetails) > 0 {
		report.CrawlResults = crawlFindingURLs(report.CrawlDetails)
	}
	report.ConfigResources = mergeStrings(report.ConfigResources, result.ConfigResources)
	report.SecretFindings = mergeSecretFindings(report.SecretFindings, result.SecretFindings)
	report.APIEndpoints = mergeAPIEndpointFindings(report.APIEndpoints, result.APIEndpoints)
	report.APISpecs = mergeAPISpecFindings(report.APISpecs, result.APISpecs)
}

func applyJSAnalysisResult(report *akemi.ScanReport, result *akemi.JSAnalysisResult) {
	if report == nil || result == nil {
		return
	}
	report.JSAnalysis = result
	report.ConfigResources = mergeStrings(report.ConfigResources, result.ConfigResources)
	report.SecretFindings = mergeSecretFindings(report.SecretFindings, result.SecretFindings)
	report.APIEndpoints = mergeAPIEndpointFindings(report.APIEndpoints, result.APIEndpoints)
	report.APISpecs = mergeAPISpecFindings(report.APISpecs, result.APISpecs)
}

func crawlFindingURLs(findings []akemi.CrawlFinding) []string {
	urls := make([]string, 0, len(findings))
	for _, finding := range findings {
		urls = append(urls, finding.URL)
	}
	return urls
}

func mergeCrawlFindings(existing []akemi.CrawlFinding, incoming []akemi.CrawlFinding) []akemi.CrawlFinding {
	seen := make(map[string]akemi.CrawlFinding, len(existing)+len(incoming))
	order := make([]string, 0, len(existing)+len(incoming))
	for _, finding := range append(existing, incoming...) {
		key := finding.URL
		if current, ok := seen[key]; ok {
			if current.StatusCode == 0 && finding.StatusCode != 0 {
				current.StatusCode = finding.StatusCode
			}
			if current.Status == "" || current.Status == "PENDING" || current.Status == "UNKNOWN" {
				current.Status = finding.Status
			}
			seen[key] = current
			continue
		}
		seen[key] = finding
		order = append(order, key)
	}
	merged := make([]akemi.CrawlFinding, 0, len(order))
	for _, key := range order {
		merged = append(merged, seen[key])
	}
	sort.Slice(merged, func(i, j int) bool {
		return crawlFindingLess(merged[i], merged[j])
	})
	return merged
}

func mergeStrings(existing []string, incoming []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	merged := make([]string, 0, len(existing)+len(incoming))
	for _, value := range append(existing, incoming...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		merged = append(merged, value)
	}
	return merged
}

func mergeSecretFindings(existing []akemi.SecretFinding, incoming []akemi.SecretFinding) []akemi.SecretFinding {
	seen := make(map[string]akemi.SecretFinding, len(existing)+len(incoming))
	order := make([]string, 0, len(existing)+len(incoming))
	for _, finding := range append(existing, incoming...) {
		key := finding.Category + "|" + finding.Value + "|" + finding.SourceURL + "|" + finding.SourceKind
		if current, ok := seen[key]; ok {
			current.Evidence = mergeStrings(current.Evidence, finding.Evidence)
			seen[key] = current
			continue
		}
		finding.Evidence = mergeStrings(nil, finding.Evidence)
		seen[key] = finding
		order = append(order, key)
	}
	merged := make([]akemi.SecretFinding, 0, len(order))
	for _, key := range order {
		merged = append(merged, seen[key])
	}
	return merged
}

func mergeAPIEndpointFindings(existing []akemi.APIEndpointFinding, incoming []akemi.APIEndpointFinding) []akemi.APIEndpointFinding {
	seen := make(map[string]akemi.APIEndpointFinding, len(existing)+len(incoming))
	order := make([]string, 0, len(existing)+len(incoming))
	for _, endpoint := range append(existing, incoming...) {
		key := endpoint.APIType + "|" + endpoint.Method + "|" + endpoint.URL
		if current, ok := seen[key]; ok {
			current.SourceURLs = mergeStrings(current.SourceURLs, endpoint.SourceURLs)
			current.Evidence = mergeStrings(current.Evidence, endpoint.Evidence)
			if current.Path == "" {
				current.Path = endpoint.Path
			}
			if current.Version == "" {
				current.Version = endpoint.Version
			}
			if current.StatusCode == 0 && endpoint.StatusCode != 0 {
				current.StatusCode = endpoint.StatusCode
			}
			if current.Status == "" && endpoint.Status != "" {
				current.Status = endpoint.Status
			}
			seen[key] = current
			continue
		}
		endpoint.SourceURLs = mergeStrings(nil, endpoint.SourceURLs)
		endpoint.Evidence = mergeStrings(nil, endpoint.Evidence)
		seen[key] = endpoint
		order = append(order, key)
	}
	merged := make([]akemi.APIEndpointFinding, 0, len(order))
	for _, key := range order {
		merged = append(merged, seen[key])
	}
	return merged
}

func mergeAPISpecFindings(existing []akemi.APISpecFinding, incoming []akemi.APISpecFinding) []akemi.APISpecFinding {
	seen := make(map[string]akemi.APISpecFinding, len(existing)+len(incoming))
	order := make([]string, 0, len(existing)+len(incoming))
	for _, spec := range append(existing, incoming...) {
		key := spec.URL
		if current, ok := seen[key]; ok {
			current.SourceURLs = mergeStrings(current.SourceURLs, spec.SourceURLs)
			current.Evidence = mergeStrings(current.Evidence, spec.Evidence)
			if current.APIType == "" {
				current.APIType = spec.APIType
			}
			if current.Format == "" {
				current.Format = spec.Format
			}
			if current.Title == "" {
				current.Title = spec.Title
			}
			if current.Version == "" {
				current.Version = spec.Version
			}
			if current.StatusCode == 0 && spec.StatusCode != 0 {
				current.StatusCode = spec.StatusCode
			}
			if current.Status == "" && spec.Status != "" {
				current.Status = spec.Status
			}
			if spec.EndpointCount > current.EndpointCount {
				current.EndpointCount = spec.EndpointCount
			}
			seen[key] = current
			continue
		}
		spec.SourceURLs = mergeStrings(nil, spec.SourceURLs)
		spec.Evidence = mergeStrings(nil, spec.Evidence)
		seen[key] = spec
		order = append(order, key)
	}
	merged := make([]akemi.APISpecFinding, 0, len(order))
	for _, key := range order {
		merged = append(merged, seen[key])
	}
	return merged
}

func crawlFindingLess(left akemi.CrawlFinding, right akemi.CrawlFinding) bool {
	leftPriority := crawlFindingPriority(left.StatusCode)
	rightPriority := crawlFindingPriority(right.StatusCode)
	if leftPriority != rightPriority {
		return leftPriority < rightPriority
	}
	leftCode := normalizedStatusCode(left.StatusCode)
	rightCode := normalizedStatusCode(right.StatusCode)
	if leftCode != rightCode {
		return leftCode < rightCode
	}
	return left.URL < right.URL
}

func crawlFindingPriority(statusCode int) int {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return 0
	case statusCode == 404:
		return 2
	default:
		return 1
	}
}

func normalizedStatusCode(statusCode int) int {
	if statusCode == 0 {
		return 999
	}
	return statusCode
}
