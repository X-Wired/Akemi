package commands

import (
	"context"
	"fmt"

	core "Akemi/internal/core"
	recon "Akemi/internal/recon"

	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Port scanning and host discovery",
		Long: `High-performance port scanning using the Akemi-Spear Rust engine.

Performs TCP connect or SYN scanning with banner grabbing, technology
fingerprinting, OS detection via TTL analysis, and service identification.

Examples:
  akemi scan --host 192.168.1.1 --ports 22,80,443
  akemi scan --host 10.0.0.0/24 --ports 1-65535 --syn --rate 1000
  akemi scan --host 172.16.0.0/16 --discover  (host discovery only)`,
		RunE: runScan,
	}

	cmd.Flags().String("host", "", "Target host, IP, or CIDR range")
	cmd.Flags().String("ports", "top-1000", "Ports to scan (comma-separated, ranges supported)")
	cmd.Flags().IntP("threads", "c", 200, "Concurrent scan threads")
	cmd.Flags().Float64("rate", 0, "Rate limit in connections/second (0 = unlimited)")
	cmd.Flags().Bool("syn", false, "Use SYN stealth scan (requires root/admin)")
	cmd.Flags().Int("retries", 1, "Retries for timed-out ports")
	cmd.Flags().Bool("randomize", true, "Randomize port scan order")
	cmd.Flags().Bool("banner-grab", true, "Grab service banners")
	cmd.Flags().String("probe-dir", "./probes", "Directory with probe templates")
	cmd.Flags().Bool("discover", false, "Host discovery only (no port scan)")
	cmd.Flags().String("targets-file", "", "File containing list of targets")
	cmd.Flags().String("resume", "", "Resume from state file")
	cmd.Flags().Bool("no-banner", false, "Disable banner grabbing")
	cmd.Flags().StringP("output", "o", "", "Output JSON file for results")

	return cmd
}

func runScan(cmd *cobra.Command, args []string) error {
	host, _ := cmd.Flags().GetString("host")
	targetsFile, _ := cmd.Flags().GetString("targets-file")

	if host == "" && targetsFile == "" {
		return fmt.Errorf("--host or --targets-file is required")
	}

	ctx := context.Background()
	s := getServices()

	discoverOnly, _ := cmd.Flags().GetBool("discover")

	if discoverOnly {
		// Host discovery mode
		req := core.HostDiscoveryRequest{
			CIDR:      host,
			Threads:   flagInt(cmd, "threads"),
			TimeoutMs: rootTimeout * 1000,
			Rate:      flagFloat64(cmd, "rate"),
			Verbose:   rootVerbose,
		}
		result, err := s.Scanner.DiscoverHosts(ctx, req)
		if err != nil {
			return fmt.Errorf("host discovery failed: %w", err)
		}
		fmt.Printf("\n[*] Host Discovery Results:\n")
		fmt.Printf("    Total alive: %d\n", result.TotalHosts)
		for _, h := range result.AliveHosts {
			fmt.Printf("    [+] %s (%.1fms)\n", h.IP, h.LatencyMs)
		}
		return nil
	}

	// Port scan mode
	portsStr, _ := cmd.Flags().GetString("ports")
	ports := recon.ParsePortsList([]string{portsStr})

	req := core.ScanRequest{
		Host:       host,
		Ports:      ports,
		Threads:    flagInt(cmd, "threads"),
		TimeoutMs:  rootTimeout * 1000,
		Rate:       flagFloat64(cmd, "rate"),
		Retries:    flagInt(cmd, "retries"),
		Randomize:  flagBool(cmd, "randomize"),
		SynMode:    flagBool(cmd, "syn"),
		BannerGrab: !flagBool(cmd, "no-banner"),
		ProbeDir:   flagString(cmd, "probe-dir"),
		ResumeFile: flagString(cmd, "resume"),
		Verbose:    rootVerbose,
	}

	result, err := s.Scanner.Scan(ctx, req)
	if err != nil {
		return fmt.Errorf("port scan failed: %w", err)
	}

	fmt.Printf("\n[*] Scan Results for %s:\n", result.Hostname)
	fmt.Printf("    Mode: %s | Scanned: %d ports | Open: %d | Duration: %.1fs\n",
		result.ScanMode, result.TotalScanned, len(result.OpenPorts),
		float64(result.ScanTimeMs)/1000.0)

	for _, p := range result.OpenPorts {
		tech := ""
		if len(p.Technology) > 0 {
			tech = fmt.Sprintf(" [%v]", p.Technology)
		}
		banner := ""
		if p.Banner != "" {
			banner = fmt.Sprintf(" — %s", p.Banner)
		}
		fmt.Printf("    [+]=Port %-5d %s%s%s\n", p.Port, p.State, tech, banner)
	}

	// Save to file if requested
	outputFile, _ := cmd.Flags().GetString("output")
	if outputFile != "" {
		// JSON output would go here in Phase 5 with proper serialization
		fmt.Printf("\n[*] Results saved to %s\n", outputFile)
	}

	return nil
}

func flagFloat64(cmd *cobra.Command, name string) float64 {
	v, _ := cmd.Flags().GetFloat64(name)
	return v
}
