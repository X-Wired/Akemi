package commands

import (
	"context"
	"fmt"

	core "Akemi/internal/core"

	"github.com/spf13/cobra"
)

func newProbeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Vulnerability validation using YAML templates",
		Long: `Execute vulnerability probes against a target using the YAML template engine.

Probes are organized by category: injection (SQLi, XSS, CMDi), file inclusion (LFI, RFI),
deserialization, SSRF, authentication bypasses, CVE-specific checks, and more.

Examples:
  akemi probe --url https://target.com/page?id=1
  akemi probe --url https://target.com --tags sqli,xss
  akemi probe --url https://target.com --template log4shell
  akemi probe --list`,
		RunE: runProbe,
	}

	cmd.Flags().StringP("url", "u", "", "Target URL (required)")
	cmd.Flags().String("tags", "", "Filter templates by comma-separated tags (e.g., sqli,lfi,high)")
	cmd.Flags().String("template", "", "Run a specific template by ID")
	cmd.Flags().Int("threads", 5, "Concurrent probe threads")
	cmd.Flags().String("template-dir", "./probes", "Directory containing YAML templates")
	cmd.Flags().Bool("list", false, "List all available probe templates")
	cmd.Flags().Bool("legacy", false, "Use legacy hardcoded probes instead of YAML")
	cmd.Flags().Bool("safe", false, "Only run passive/safe probes (no active exploitation)")
	cmd.Flags().Bool("fingerprint", false, "Enable passive target fingerprinting before probing (framework, WAF, API detection)")
	cmd.Flags().Bool("prioritize", false, "Adaptive template ordering by relevance (requires --fingerprint)")

	return cmd
}

func runProbe(cmd *cobra.Command, args []string) error {
	s := getServices()

	// List templates mode
	if listFlag, _ := cmd.Flags().GetBool("list"); listFlag {
		templates := s.Vuln.ListTemplates()
		fmt.Printf("\n[*] Available Probe Templates (%d):\n\n", len(templates))
		fmt.Printf("%-4s %-8s %-30s %s\n", "", "Severity", "Name", "Tags")
		fmt.Printf("%-4s %-8s %-30s %s\n", "----", "--------", "----", "----")
		for _, t := range templates {
			if t.Disabled {
				continue
			}
			tagStr := ""
			for i, tag := range t.Info.Tags {
				if i > 0 {
					tagStr += ", "
				}
				tagStr += tag
			}
			fmt.Printf("%-4s %-8s %-30s %s\n", "", t.Info.Severity, t.ID, tagStr)
		}
		return nil
	}

	urlFlag, _ := cmd.Flags().GetString("url")
	if urlFlag == "" {
		return fmt.Errorf("--url is required (or use --list to see templates)")
	}

	ctx := context.Background()

	tagsStr, _ := cmd.Flags().GetString("tags")
	templateID, _ := cmd.Flags().GetString("template")

	var tags []string
	var ids []string

	if tagsStr != "" {
		tags = splitComma(tagsStr)
	}
	if templateID != "" {
		ids = []string{templateID}
	}

	cfg := core.ProbeConfig{
		Threads:      flagInt(cmd, "threads"),
		Timeout:      rootTimeout,
		UseTemplates: !flagBool(cmd, "legacy"),
		TemplateDir:  flagString(cmd, "template-dir"),
		TemplateTags: tags,
		TemplateIDs:  ids,
		Fingerprint:  flagBool(cmd, "fingerprint"),
		Prioritize:   flagBool(cmd, "prioritize"),
	}

	findings, err := s.Vuln.Probe(ctx, urlFlag, cfg)
	if err != nil {
		return fmt.Errorf("vulnerability probe failed: %w", err)
	}

	if len(findings) == 0 {
		fmt.Println("\n[*] No vulnerabilities detected.")
		return nil
	}

	// Group by severity
	groups := map[string][]core.VulnFinding{}
	for _, f := range findings {
		groups[f.Severity] = append(groups[f.Severity], f)
	}

	fmt.Printf("\n[*] Vulnerability Probe Results (%d findings):\n\n", len(findings))

	order := []string{"critical", "high", "medium", "low", "info"}
	for _, sev := range order {
		if group, ok := groups[sev]; ok {
			fmt.Printf("  [%s] %d finding(s):\n", sev, len(group))
			for _, f := range group {
				fmt.Printf("    - %s: %s\n", f.Name, f.Description)
				if f.Evidence != "" {
					fmt.Printf("      Evidence: %s\n", truncate(f.Evidence, 80))
				}
			}
			fmt.Println()
		}
	}

	return nil
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	current := ""
	for _, ch := range s {
		if ch == ',' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
