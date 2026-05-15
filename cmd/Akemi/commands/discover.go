package commands

import (
	"context"
	"fmt"
	"strings"

	core "Akemi/internal/core"

	"github.com/spf13/cobra"
)

func newDiscoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Attack surface discovery",
		Long: `Discover the attack surface of a target through crawling, JavaScript analysis,
parameter mining, and API endpoint discovery.

Examples:
  akemi discover --url https://target.com --crawl --depth 3
  akemi discover --url https://target.com --params --js
  akemi discover --url https://target.com --api`,
		RunE: runDiscover,
	}

	cmd.Flags().StringP("url", "u", "", "Target URL (required)")
	cmd.Flags().Bool("crawl", false, "Crawl the site to discover URLs")
	cmd.Flags().Int("depth", 3, "Managed crawl depth 1-7. 1=1000 URLs, 2=2000 URLs, ... 6=6000 URLs, 7=unlimited URL budget")
	cmd.Flags().Bool("params", false, "Mine HTTP parameters from all sources")
	cmd.Flags().Bool("js", false, "Analyze JavaScript files for endpoints and secrets")
	cmd.Flags().Bool("scrape", false, "Scrape page content (title, forms, comments)")
	cmd.Flags().Bool("api", false, "Discover API endpoints and specifications")
	cmd.Flags().Bool("api-hunter", false, "Run first-class API Hunter discovery with safe-active probing")
	cmd.Flags().String("api-mode", "safe-active", "API Hunter mode: passive or safe-active")
	cmd.Flags().String("api-wordlist", "", "File with API Hunter path candidates")
	cmd.Flags().String("api-auth-cookies", "", "Semicolon-separated cookies for API Hunter requests")
	cmd.Flags().Int("api-max-candidates", 250, "Maximum API Hunter candidates to safely probe")
	cmd.Flags().Bool("all", false, "Run all discovery modules")

	// Parameter mining options
	cmd.Flags().Bool("mine-js", true, "Mine params from JavaScript")
	cmd.Flags().Bool("mine-forms", true, "Mine params from HTML forms")
	cmd.Flags().Bool("mine-json", true, "Mine params from JSON responses")
	cmd.Flags().Bool("mine-path", true, "Detect path parameters")
	cmd.Flags().Bool("active-brute", false, "Active parameter brute-forcing")

	return cmd
}

func runDiscover(cmd *cobra.Command, args []string) error {
	urlFlag, _ := cmd.Flags().GetString("url")
	if urlFlag == "" {
		return fmt.Errorf("--url is required")
	}

	ctx := context.Background()
	s := getServices()
	runAll, _ := cmd.Flags().GetBool("all")

	// Crawl
	if crawl, _ := cmd.Flags().GetBool("crawl"); crawl || runAll {
		depth, _ := cmd.Flags().GetInt("depth")
		depth = core.NormalizeCrawlDepth(depth)
		findings, err := s.Discovery.Crawl(ctx, urlFlag, depth)
		if err != nil {
			return fmt.Errorf("crawl failed: %w", err)
		}
		fmt.Printf("\n[*] Crawl Results (%d URLs):\n", len(findings))
		for _, f := range findings {
			fmt.Printf("    [%d] %s\n", f.StatusCode, f.URL)
		}
	}

	// JavaScript analysis
	if jsFlag, _ := cmd.Flags().GetBool("js"); jsFlag || runAll {
		result, err := s.Discovery.AnalyzeJS(ctx, urlFlag)
		if err != nil {
			fmt.Printf("[!] JS analysis failed: %v\n", err)
		} else {
			fmt.Printf("\n[*] JavaScript Analysis:\n")
			fmt.Printf("    Scripts: %d | Endpoints: %d | Secrets: %d | Hidden Params: %d\n",
				len(result.ScriptURLs), len(result.Endpoints),
				len(result.Secrets), len(result.HiddenParams))
			for _, secret := range result.Secrets {
				fmt.Printf("    [!] %s: %s (%s)\n", secret.Category, secret.Value, secret.SourceURL)
			}
		}
	}

	// Parameter mining
	if paramsFlag, _ := cmd.Flags().GetBool("params"); paramsFlag || runAll {
		cfg := core.MiningConfig{
			MineJS:      flagBool(cmd, "mine-js"),
			MineForms:   flagBool(cmd, "mine-forms"),
			MineJSON:    flagBool(cmd, "mine-json"),
			MinePath:    flagBool(cmd, "mine-path"),
			ActiveBrute: flagBool(cmd, "active-brute"),
		}
		result, err := s.Discovery.MineParams(ctx, urlFlag, cfg)
		if err != nil {
			fmt.Printf("[!] Parameter mining failed: %v\n", err)
		} else {
			fmt.Printf("\n[*] Parameter Mining (%d params):\n", result.TotalCount)
			for name, detail := range result.Params {
				fmt.Printf("    %s (sources: %v)\n", name, detail.Sources)
			}
		}
	}

	// API discovery
	if apiHunter, _ := cmd.Flags().GetBool("api-hunter"); apiHunter {
		mode, _ := cmd.Flags().GetString("api-mode")
		wordlist, _ := cmd.Flags().GetString("api-wordlist")
		cookiesRaw, _ := cmd.Flags().GetString("api-auth-cookies")
		maxCandidates, _ := cmd.Flags().GetInt("api-max-candidates")
		result, err := s.Discovery.HuntAPISurface(ctx, core.APIHuntRequest{
			StartURL:      urlFlag,
			Mode:          mode,
			WordlistFile:  wordlist,
			AuthCookies:   splitCookieHeader(cookiesRaw),
			MaxCandidates: maxCandidates,
			Threads:       10,
			Timeout:       rootTimeout,
		})
		if err != nil {
			fmt.Printf("[!] API Hunter failed: %v\n", err)
		} else {
			fmt.Printf("\n[*] API Hunter (%s):\n", result.Mode)
			fmt.Printf("    Endpoints: %d | Specs: %d | Params: %d | Stage Errors: %d\n",
				len(result.APIEndpoints), len(result.APISpecs), len(result.Parameters), len(result.StageErrors))
			for _, ep := range result.APIEndpoints {
				method := ep.Method
				if method == "" {
					method = "ANY"
				}
				status := ep.Status
				if status == "" && ep.StatusCode > 0 {
					status = fmt.Sprintf("%d", ep.StatusCode)
				}
				auth := ""
				if ep.AuthRequired {
					auth = " auth-required"
				}
				fmt.Printf("    [%s] %s %s (%s %.2f%s)\n", method, ep.Path, ep.APIType, status, ep.Confidence, auth)
			}
		}
	}

	if apiFlag, _ := cmd.Flags().GetBool("api"); apiFlag || runAll {
		result, err := s.Discovery.DiscoverAPISurface(ctx, urlFlag, nil)
		if err != nil {
			fmt.Printf("[!] API discovery failed: %v\n", err)
		} else {
			fmt.Printf("\n[*] API Discovery:\n")
			fmt.Printf("    Endpoints: %d | Specs: %d\n",
				len(result.APIEndpoints), len(result.APISpecs))
			for _, ep := range result.APIEndpoints {
				fmt.Printf("    [%s] %s %s\n", ep.Method, ep.Path, ep.APIType)
			}
		}
	}

	// Scrape
	if scrapeFlag, _ := cmd.Flags().GetBool("scrape"); scrapeFlag {
		result, err := s.Discovery.ScrapePage(ctx, urlFlag, nil)
		if err != nil {
			fmt.Printf("[!] Scrape failed: %v\n", err)
		} else {
			fmt.Printf("\n[*] Page Scrape:\n")
			fmt.Printf("    Title: %s\n", result.Title)
			fmt.Printf("    Description: %s\n", result.Description)
			fmt.Printf("    Links: %d | Forms: %d | Comments: %d\n",
				len(result.Links), len(result.Forms), len(result.Comments))
		}
	}

	return nil
}

func splitCookieHeader(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ";")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
