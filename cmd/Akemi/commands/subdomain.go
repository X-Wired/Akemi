package commands

import (
	"context"
	"fmt"

	core "Akemi/internal/core"

	"github.com/spf13/cobra"
)

func newSubdomainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "subdomain",
		Short: "Subdomain enumeration",
		Long: `Enumerate subdomains using passive sources (crt.sh certificate transparency logs)
and active methods (wordlist brute-force, permutation generation).

Examples:
  akemi subdomain --domain target.com
  akemi subdomain --domain target.com --wordlist subdomains.txt --threads 50
  akemi subdomain --domain target.com --crtsh --permute --alive`,
		RunE: runSubdomain,
	}

	cmd.Flags().StringP("domain", "d", "", "Target domain (required)")
	cmd.Flags().StringP("wordlist", "w", "", "Wordlist file for brute-force")
	cmd.Flags().Int("threads", 20, "Concurrent threads")
	cmd.Flags().Bool("crtsh", true, "Query crt.sh certificate transparency logs")
	cmd.Flags().Bool("alive", true, "Probe discovered subdomains for live HTTP services")
	cmd.Flags().Bool("permute", false, "Generate permutations from discovered subdomains")
	cmd.Flags().StringP("output", "o", "", "Output file for results")

	return cmd
}

func runSubdomain(cmd *cobra.Command, args []string) error {
	domain, _ := cmd.Flags().GetString("domain")
	if domain == "" {
		return fmt.Errorf("--domain is required")
	}

	ctx := context.Background()
	s := getServices()

	cfg := core.SubdomainConfig{
		WordlistFile: flagString(cmd, "wordlist"),
		Threads:      flagInt(cmd, "threads"),
		Timeout:      rootTimeout,
		UseCrtSh:     flagBool(cmd, "crtsh"),
		CheckAlive:   flagBool(cmd, "alive"),
		Permutate:    flagBool(cmd, "permute"),
	}

	fmt.Printf("\n[*] Enumerating subdomains for %s...\n", domain)

	results, err := s.Subdomain.Enumerate(ctx, domain, cfg)
	if err != nil {
		return fmt.Errorf("subdomain enumeration failed: %w", err)
	}

	alive := 0
	for _, r := range results {
		if r.IsAlive {
			alive++
		}
	}

	fmt.Printf("\n[*] Results: %d subdomains (%d alive)\n\n", len(results), alive)

	for _, r := range results {
		marker := "[*]"
		if r.IsAlive {
			marker = "[+]"
		}
		ipStr := ""
		if len(r.IPs) > 0 {
			ipStr = fmt.Sprintf(" → %v", r.IPs)
		}
		fmt.Printf("  %s %s (%s)%s\n", marker, r.Name, r.Source, ipStr)
	}

	return nil
}
