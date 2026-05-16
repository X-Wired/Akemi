// Package commands implements the Akemi CLI using Cobra.
// All original flags are preserved on the root command for backward compatibility.
// New structured subcommands (scan, discover, probe, etc.) are also provided.
package commands

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	akemiarchive "Akemi/internal/archive"
	ui "Akemi/internal/cli/ui"
	core "Akemi/internal/core"
	"Akemi/internal/engagement"
	"Akemi/internal/service"
	"Akemi/internal/tui/dashboard"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

// Services holds all initialized service instances.
type Services struct {
	Scanner    *service.ScannerService
	Discovery  *service.DiscoveryService
	Vuln       *service.VulnService
	Subdomain  *service.SubdomainService
	Reporting  *service.ReportingService
	MCPContext engagement.ContextStore
}

var (
	// Global services (lazily initialized)
	svc *Services

	// Root flags (shared across all commands)
	rootQuiet       bool
	rootVerbose     bool
	rootProxy       string
	rootNoProxy     string
	rootTimeout     int
	rootOutputDir   string
	rootAkemiImport string
)

// RootCmd is the base Akemi command. When run without subcommands,
// it provides the original monolithic behavior.
var RootCmd = &cobra.Command{
	Use:   "akemi",
	Short: "Akemi — Surface Map Attack Framework",
	Long: `Akemi is a modular, high-performance attack surface mapping and
vulnerability validation framework. It bridges the gap between massive
reconnaissance and actionable exploitation.

Run 'akemi [command] --help' for details on each subcommand.`,
	Version: "2.0.0-dev",
	RunE:    runRoot,
}

// SetVersion allows the build system to inject the real version.
func SetVersion(v string) {
	RootCmd.Version = v
}

// Execute runs the root command.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Global flags
	RootCmd.PersistentFlags().BoolVarP(&rootQuiet, "quiet", "q", false, "Suppress ASCII art and decorative headers")
	RootCmd.PersistentFlags().BoolVarP(&rootVerbose, "verbose", "v", false, "Verbose output")
	RootCmd.PersistentFlags().StringVar(&rootProxy, "proxy", "", "Route outbound traffic through proxy (http://, https://, socks5://)")
	RootCmd.PersistentFlags().StringVar(&rootNoProxy, "no-proxy", "", "Comma-separated hosts or domains to bypass the proxy")
	RootCmd.PersistentFlags().IntVarP(&rootTimeout, "timeout", "t", 10, "Network timeout in seconds")
	RootCmd.PersistentFlags().StringVar(&rootOutputDir, "output-dir", ".", "Output directory for reports and results")
	RootCmd.PersistentFlags().StringVar(&rootAkemiImport, "import-akemi", "", "Load a .akemi archive into the interactive dashboard")

	// Legacy flags on root command for backward compatibility
	RootCmd.Flags().StringP("url", "u", "", "Target URL")
	RootCmd.Flags().StringP("method", "m", "GET", "HTTP method")
	RootCmd.Flags().StringP("data", "d", "", "POST/PUT/PATCH data")
	RootCmd.Flags().StringP("wordlist", "w", "payloads.txt", "Wordlist file")
	RootCmd.Flags().StringP("output", "o", "fuzz_results.txt", "Fuzz output file")
	RootCmd.Flags().IntP("repeats", "r", 1, "Requests per payload")
	RootCmd.Flags().IntP("concurrency", "c", 10, "Concurrency/threads")
	RootCmd.Flags().Bool("crawl", false, "Crawl the site")
	RootCmd.Flags().Bool("params", false, "Enhanced parameter mining")
	RootCmd.Flags().Bool("scrape", false, "Scrape page content")
	RootCmd.Flags().Int("depth", 2, "Managed crawl depth 1-7. 1=1000 URLs, 2=2000 URLs, ... 6=6000 URLs, 7=unlimited URL budget")
	RootCmd.Flags().Bool("js", false, "Analyze JavaScript files")
	RootCmd.Flags().Bool("vuln-check", false, "Run vulnerability probes")
	RootCmd.Flags().Int("vuln-check-threads", 5, "Threads for vuln probing")
	RootCmd.Flags().String("vuln-check-dir", "./probes", "Probe template directory")
	RootCmd.Flags().String("vuln-check-tags", "", "Filter templates by tags")
	RootCmd.Flags().String("vuln-check-id", "", "Specific probe template ID")
	RootCmd.Flags().Bool("vuln-check-list", false, "List available templates")
	RootCmd.Flags().Bool("vuln-check-legacy", false, "Use legacy hardcoded probes")
	RootCmd.Flags().Bool("sub", false, "Enumerate subdomains")
	RootCmd.Flags().String("sub-w", "", "Subdomain wordlist")
	RootCmd.Flags().Int("sub-threads", 20, "Subdomain threads")
	RootCmd.Flags().Bool("sub-crtsh", true, "Query crt.sh")
	RootCmd.Flags().Bool("sub-alive", true, "Check subdomains alive")
	RootCmd.Flags().Bool("sub-permute", false, "Generate permutations")
	RootCmd.Flags().Bool("report", false, "Generate report")
	RootCmd.Flags().Bool("report-json", false, "Export JSON report")
	RootCmd.Flags().Bool("report-html", false, "Export HTML report")
	RootCmd.Flags().String("report-dir", ".", "Report output directory")
	RootCmd.Flags().String("port-scan-ports", "p", "top-1000")
	RootCmd.Flags().Float64("rate", 0, "Scan rate limit")
	RootCmd.Flags().Bool("syn", false, "SYN scan mode")
	RootCmd.Flags().Int("retries", 1, "Port scan retries")
	RootCmd.Flags().Bool("randomize", true, "Randomize port order")
	RootCmd.Flags().String("targets", "", "Targets file")
	RootCmd.Flags().Int("scanthreads", 200, "Scan threads")
	RootCmd.Flags().Bool("np", false, "Host discovery only")
	RootCmd.Flags().Bool("graph", false, "Generate graph")
	RootCmd.Flags().Bool("graph-json", false, "Export graph as JSON")
	RootCmd.Flags().Bool("graph-dot", false, "Export graph as DOT")
	RootCmd.Flags().Bool("graph-html", false, "Export graph as HTML")
	RootCmd.Flags().String("graph-out", "", "Graph output path")

	// Register subcommands
	RootCmd.AddCommand(newScanCmd())
	RootCmd.AddCommand(newDiscoverCmd())
	RootCmd.AddCommand(newProbeCmd())
	RootCmd.AddCommand(newFuzzCmd())
	RootCmd.AddCommand(newSubdomainCmd())
	RootCmd.AddCommand(newReportCmd())
	RootCmd.AddCommand(newGraphCmd())
	RootCmd.AddCommand(newServeCmd())
	RootCmd.AddCommand(newAgentCmd())
	RootCmd.AddCommand(newInteractiveCmd())
	RootCmd.AddCommand(newArchiveCmd())
}

// getServices lazily initializes and returns the service container.
func getServices() *Services {
	if svc == nil {
		logger := core.Logger()
		if rootVerbose {
			handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
			logger = slog.New(handler)
			core.SetLogger(logger)
		}

		vulnSvc, _ := service.NewVulnService(logger, "./probes")

		svc = &Services{
			Scanner:    service.NewScannerService(logger),
			Discovery:  service.NewDiscoveryService(logger),
			Vuln:       vulnSvc,
			Subdomain:  service.NewSubdomainService(logger),
			Reporting:  service.NewReportingService(logger, rootOutputDir),
			MCPContext: engagement.NewMemoryContextStore(),
		}
	}
	return svc
}

// =============================================================================
// runRoot — parallelized + pipeline-optimized execution
// =============================================================================
//
// Phase 1.1: independent operations run concurrently via errgroup.
// Phase 2.2: --crawl + --params use the streaming CrawlAndMine pipeline
//            (single crawl, live param mining on discovered URLs).

// runResult bundles all the results produced by a concurrent scan phase.
type runResult struct {
	subResults   []core.SubdomainResult
	subErr       error
	crawlResults []core.CrawlFinding
	crawlErr     error
	jsResult     *core.JSAnalysisResult
	jsErr        error
	paramsResult *core.ParamDiscoveryResult
	paramsErr    error
	vulnResults  []core.VulnFinding
	vulnErr      error
}

// runRoot provides the original monolithic behavior when no subcommand is given.
func runRoot(cmd *cobra.Command, args []string) error {
	// Print banner unless quiet
	if !rootQuiet {
		ui.PrintASCIIArtNeon()
	}

	ctx := context.Background()
	traceID := core.NewTraceID()
	ctx = core.WithTraceID(ctx, traceID)

	urlFlag, _ := cmd.Flags().GetString("url")
	if urlFlag == "" && !hasAnyActiveFlag(cmd) {
		// No URL and no specific action — launch the interactive dashboard
		if !rootQuiet {
			ui.PrintASCIIArtNeon()
		}
		prevLogger := core.Logger()
		core.SetLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
		defer core.SetLogger(prevLogger)

		initialArchive, err := loadAkemiArchive(rootAkemiImport)
		if err != nil {
			return err
		}
		s := getServices()
		dashSvc := dashboard.ConvertServices(s.Scanner, s.Discovery, s.Vuln, s.Subdomain, s.Reporting)
		dashSvc.ArchiveDir = rootOutputDir
		dashSvc.InitialArchive = initialArchive
		dashSvc.MCPContext = s.MCPContext
		dashSvc.AssistantLoad = buildDashboardAssistantLoad(s, core.Logger())
		dashSvc.AssistantSetup = buildDashboardAssistantSetup(s, core.Logger())
		dashSvc.APISettingsLoad = buildDashboardAPISettingsLoad()
		dashSvc.APISettingsTest = buildDashboardAPISettingsTest()
		dashSvc.APISettingsApply = buildDashboardAPISettingsApply(s, core.Logger())
		if assistantSession, err := buildAssistantSession(s, core.Logger()); err == nil {
			dashSvc.Assistant = assistantSession
		}
		return dashboard.RunDashboard(dashSvc)
	}

	s := getServices()
	startTime := time.Now()
	logger := core.Logger()

	logger.Info("akemi scan starting",
		slog.String("trace_id", traceID),
		slog.String("url", urlFlag),
	)

	subFlag, _ := cmd.Flags().GetBool("sub")
	crawlFlag, _ := cmd.Flags().GetBool("crawl")
	jsFlag, _ := cmd.Flags().GetBool("js")
	paramsFlag, _ := cmd.Flags().GetBool("params")
	vulnFlag, _ := cmd.Flags().GetBool("vuln-check")
	vulnListOnly, _ := cmd.Flags().GetBool("vuln-check-list")

	// Template listing is instant — handle synchronously.
	if vulnFlag && vulnListOnly {
		templates := s.Vuln.ListTemplates()
		for _, t := range templates {
			fmt.Printf("  [%s] %s (%s)\n", t.Info.Severity, t.Info.Name, t.ID)
		}
		return nil
	}

	// Single-operation shortcut: no goroutine overhead.
	activeCount := countBools(subFlag, crawlFlag, jsFlag, paramsFlag, vulnFlag)
	if activeCount <= 1 {
		return runRootSequential(cmd, ctx, s, logger, urlFlag, startTime)
	}

	// ── Concurrent execution ──────────────────────────────────────────
	var (
		result  runResult
		printMu sync.Mutex
	)

	g, gctx := errgroup.WithContext(ctx)

	// 🔍 Subdomain enumeration
	if subFlag {
		g.Go(func() error {
			domain := urlFlag
			subCfg := core.SubdomainConfig{
				WordlistFile: flagString(cmd, "sub-w"),
				Threads:      flagInt(cmd, "sub-threads"),
				Timeout:      rootTimeout,
				UseCrtSh:     flagBool(cmd, "sub-crtsh"),
				CheckAlive:   flagBool(cmd, "sub-alive"),
				Permutate:    flagBool(cmd, "sub-permute"),
			}
			results, err := s.Subdomain.Enumerate(gctx, domain, subCfg)
			result.subResults = results
			result.subErr = err
			if err != nil {
				logger.Error("subdomain enumeration failed", slog.String("error", err.Error()))
			} else {
				printMu.Lock()
				for _, r := range results {
					if r.IsAlive {
						fmt.Printf("  [+]=%s (%s)\n", r.Name, r.Source)
					} else {
						fmt.Printf("  [*] %s (%s)\n", r.Name, r.Source)
					}
				}
				printMu.Unlock()
			}
			return nil
		})
	}

	// 🌐 Crawl + 🔎 Params — streaming pipeline when both active
	if crawlFlag && paramsFlag {
		g.Go(func() error {
			depth, _ := cmd.Flags().GetInt("depth")
			miningCfg := core.MiningConfig{
				MineJS:    true,
				MineForms: true,
				MineJSON:  true,
				MinePath:  true,
			}
			findings, paramsResult, err := s.Discovery.CrawlAndMine(gctx, urlFlag, depth, miningCfg)
			result.crawlResults = findings
			result.crawlErr = err
			result.paramsResult = paramsResult
			if err != nil {
				logger.Error("crawl-and-mine pipeline failed", slog.String("error", err.Error()))
			} else {
				printMu.Lock()
				for _, f := range findings {
					fmt.Printf("  [%d] %s\n", f.StatusCode, f.URL)
				}
				if paramsResult != nil {
					fmt.Printf("\n[*] Discovered %d parameters (streaming pipeline)\n", paramsResult.TotalCount)
				}
				printMu.Unlock()
			}
			return nil
		})
	} else {
		// 🌐 Crawl (standalone)
		if crawlFlag {
			g.Go(func() error {
				depth, _ := cmd.Flags().GetInt("depth")
				depth = core.NormalizeCrawlDepth(depth)
				findings, err := s.Discovery.Crawl(gctx, urlFlag, depth)
				result.crawlResults = findings
				result.crawlErr = err
				if err != nil {
					logger.Error("crawl failed", slog.String("error", err.Error()))
				} else {
					printMu.Lock()
					for _, f := range findings {
						fmt.Printf("  [%d] %s\n", f.StatusCode, f.URL)
					}
					printMu.Unlock()
				}
				return nil
			})
		}

		// 🔎 Parameter mining (standalone)
		if paramsFlag {
			g.Go(func() error {
				cfg := core.MiningConfig{
					MineJS:    true,
					MineForms: true,
					MineJSON:  true,
					MinePath:  true,
				}
				paramsResult, err := s.Discovery.MineParams(gctx, urlFlag, cfg)
				result.paramsResult = paramsResult
				result.paramsErr = err
				if err != nil {
					logger.Error("param mining failed", slog.String("error", err.Error()))
				} else {
					printMu.Lock()
					fmt.Printf("\n[*] Discovered %d parameters\n", paramsResult.TotalCount)
					printMu.Unlock()
				}
				return nil
			})
		}
	}

	// 📜 JavaScript analysis
	if jsFlag {
		g.Go(func() error {
			jsResult, err := s.Discovery.AnalyzeJS(gctx, urlFlag)
			result.jsResult = jsResult
			result.jsErr = err
			if err != nil {
				logger.Error("JS analysis failed", slog.String("error", err.Error()))
			} else {
				printMu.Lock()
				fmt.Printf("\n[*] JS Analysis: %d scripts, %d endpoints, %d secrets\n",
					len(jsResult.ScriptURLs), len(jsResult.Endpoints), len(jsResult.Secrets))
				printMu.Unlock()
			}
			return nil
		})
	}

	// 💥 Vulnerability probes
	if vulnFlag {
		g.Go(func() error {
			cfg := core.ProbeConfig{
				Threads:      flagInt(cmd, "vuln-check-threads"),
				Timeout:      rootTimeout,
				UseTemplates: !flagBool(cmd, "vuln-check-legacy"),
				TemplateDir:  flagString(cmd, "vuln-check-dir"),
			}
			findings, err := s.Vuln.Probe(gctx, urlFlag, cfg)
			result.vulnResults = findings
			result.vulnErr = err
			if err != nil {
				logger.Error("vuln probe failed", slog.String("error", err.Error()))
			} else {
				printMu.Lock()
				for _, f := range findings {
					fmt.Printf("  [%s] %s — %s\n", f.Severity, f.Name, f.Target)
				}
				printMu.Unlock()
			}
			return nil
		})
	}

	// Wait for all parallel operations to complete.
	_ = g.Wait()

	elapsed := time.Since(startTime)
	logger.Info("akemi scan completed",
		slog.String("trace_id", traceID),
		slog.Duration("elapsed", elapsed),
	)

	return nil
}

// runRootSequential executes a single operation without goroutine overhead.
// Called when only one flag is active, or zero (edge-case).
func runRootSequential(cmd *cobra.Command, ctx context.Context, s *Services, logger *slog.Logger, urlFlag string, startTime time.Time) error {
	subFlag, _ := cmd.Flags().GetBool("sub")
	crawlFlag, _ := cmd.Flags().GetBool("crawl")
	jsFlag, _ := cmd.Flags().GetBool("js")
	paramsFlag, _ := cmd.Flags().GetBool("params")
	vulnFlag, _ := cmd.Flags().GetBool("vuln-check")

	// 🔍 Subdomain enumeration
	if subFlag {
		domain := urlFlag
		subCfg := core.SubdomainConfig{
			WordlistFile: flagString(cmd, "sub-w"),
			Threads:      flagInt(cmd, "sub-threads"),
			Timeout:      rootTimeout,
			UseCrtSh:     flagBool(cmd, "sub-crtsh"),
			CheckAlive:   flagBool(cmd, "sub-alive"),
			Permutate:    flagBool(cmd, "sub-permute"),
		}
		results, err := s.Subdomain.Enumerate(ctx, domain, subCfg)
		if err != nil {
			logger.Error("subdomain enumeration failed", slog.String("error", err.Error()))
		} else {
			for _, r := range results {
				if r.IsAlive {
					fmt.Printf("  [+]=%s (%s)\n", r.Name, r.Source)
				} else {
					fmt.Printf("  [*] %s (%s)\n", r.Name, r.Source)
				}
			}
		}
	}

	// 🌐 Crawl + 🔎 Params — streaming pipeline when both active (sequential path)
	if crawlFlag && paramsFlag {
		depth, _ := cmd.Flags().GetInt("depth")
		miningCfg := core.MiningConfig{
			MineJS:    true,
			MineForms: true,
			MineJSON:  true,
			MinePath:  true,
		}
		findings, paramsResult, err := s.Discovery.CrawlAndMine(ctx, urlFlag, depth, miningCfg)
		if err != nil {
			logger.Error("crawl-and-mine pipeline failed", slog.String("error", err.Error()))
		} else {
			for _, f := range findings {
				fmt.Printf("  [%d] %s\n", f.StatusCode, f.URL)
			}
			if paramsResult != nil {
				fmt.Printf("\n[*] Discovered %d parameters (streaming pipeline)\n", paramsResult.TotalCount)
			}
		}
	} else {
		// 🌐 Crawl (standalone)
		if crawlFlag {
			depth, _ := cmd.Flags().GetInt("depth")
			depth = core.NormalizeCrawlDepth(depth)
			findings, err := s.Discovery.Crawl(ctx, urlFlag, depth)
			if err != nil {
				logger.Error("crawl failed", slog.String("error", err.Error()))
			} else {
				for _, f := range findings {
					fmt.Printf("  [%d] %s\n", f.StatusCode, f.URL)
				}
			}
		}

		// 🔎 Parameter mining (standalone)
		if paramsFlag {
			cfg := core.MiningConfig{
				MineJS:    true,
				MineForms: true,
				MineJSON:  true,
				MinePath:  true,
			}
			result, err := s.Discovery.MineParams(ctx, urlFlag, cfg)
			if err != nil {
				logger.Error("param mining failed", slog.String("error", err.Error()))
			} else {
				fmt.Printf("\n[*] Discovered %d parameters\n", result.TotalCount)
			}
		}
	}

	// 📜 JavaScript analysis
	if jsFlag {
		result, err := s.Discovery.AnalyzeJS(ctx, urlFlag)
		if err != nil {
			logger.Error("JS analysis failed", slog.String("error", err.Error()))
		} else {
			fmt.Printf("\n[*] JS Analysis: %d scripts, %d endpoints, %d secrets\n",
				len(result.ScriptURLs), len(result.Endpoints), len(result.Secrets))
		}
	}

	// 💥 Vulnerability probes
	if vulnFlag {
		cfg := core.ProbeConfig{
			Threads:      flagInt(cmd, "vuln-check-threads"),
			Timeout:      rootTimeout,
			UseTemplates: !flagBool(cmd, "vuln-check-legacy"),
			TemplateDir:  flagString(cmd, "vuln-check-dir"),
		}
		findings, err := s.Vuln.Probe(ctx, urlFlag, cfg)
		if err != nil {
			logger.Error("vuln probe failed", slog.String("error", err.Error()))
		} else {
			for _, f := range findings {
				fmt.Printf("  [%s] %s — %s\n", f.Severity, f.Name, f.Target)
			}
		}
	}

	elapsed := time.Since(startTime)
	logger.Info("akemi scan completed",
		slog.String("trace_id", core.TraceIDFromContext(ctx)),
		slog.Duration("elapsed", elapsed),
	)

	return nil
}

// countBools returns how many of the provided bools are true.
func countBools(vals ...bool) int {
	n := 0
	for _, v := range vals {
		if v {
			n++
		}
	}
	return n
}

// =============================================================================
// Helper functions for flag extraction
// =============================================================================

func flagString(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

func flagInt(cmd *cobra.Command, name string) int {
	v, _ := cmd.Flags().GetInt(name)
	return v
}

func flagBool(cmd *cobra.Command, name string) bool {
	v, _ := cmd.Flags().GetBool(name)
	return v
}

func hasAnyActiveFlag(cmd *cobra.Command) bool {
	activeFlags := []string{
		"crawl", "params", "js", "scrape", "vuln-check",
		"sub", "graph", "report", "port-scan",
	}
	for _, name := range activeFlags {
		if flagBool(cmd, name) {
			return true
		}
	}
	return false
}

// initServices initializes services with the given logger and output directory.
func initServices(logger *slog.Logger, outputDir string) *Services {
	vulnSvc, _ := service.NewVulnService(logger, "./probes")
	return &Services{
		Scanner:    service.NewScannerService(logger),
		Discovery:  service.NewDiscoveryService(logger),
		Vuln:       vulnSvc,
		Subdomain:  service.NewSubdomainService(logger),
		Reporting:  service.NewReportingService(logger, outputDir),
		MCPContext: engagement.NewMemoryContextStore(),
	}
}

func loadAkemiArchive(path string) (*akemiarchive.File, error) {
	if path == "" {
		return nil, nil
	}
	file, err := akemiarchive.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("import .akemi archive: %w", err)
	}
	return file, nil
}
