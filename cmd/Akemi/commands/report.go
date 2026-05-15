package commands

import (
	"context"
	"fmt"
	"time"

	core "Akemi/internal/core"

	"github.com/spf13/cobra"
)

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate scan reports",
		Long: `Generate comprehensive HTML and JSON reports from scan data.

Reports include executive summaries, finding details by severity, service maps,
vulnerability breakdowns, and actionable remediation guidance.

Examples:
  akemi report --target target.com --output-dir ./results
  akemi report --target target.com --html --json`,
		RunE: runReport,
	}

	cmd.Flags().StringP("target", "t", "", "Target identifier for the report (required)")
	cmd.Flags().Bool("html", true, "Generate HTML report")
	cmd.Flags().Bool("json", false, "Generate JSON report")

	return cmd
}

func runReport(cmd *cobra.Command, args []string) error {
	target, _ := cmd.Flags().GetString("target")
	if target == "" {
		return fmt.Errorf("--target is required")
	}

	ctx := context.Background()
	s := getServices()

	now := time.Now()
	data := &core.ReportData{
		Target:    target,
		StartTime: now.Add(-5 * time.Minute), // placeholder
		EndTime:   now,
	}

	report, err := s.Reporting.GenerateReport(ctx, data)
	if err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}

	fmt.Printf("\n[*] Report Generated:\n")
	if report.HTMLPath != "" {
		fmt.Printf("    HTML: %s\n", report.HTMLPath)
	}
	if report.JSONPath != "" {
		fmt.Printf("    JSON: %s\n", report.JSONPath)
	}
	fmt.Printf("\n[*] Summary for %s:\n", report.Summary.Target)
	fmt.Printf("    Duration: %s\n", report.Summary.Duration)
	fmt.Printf("    URLs: %d | Params: %d | Subdomains: %d\n",
		report.Summary.TotalURLs, report.Summary.TotalParams, report.Summary.TotalSubdomains)
	fmt.Printf("    Vulnerabilities: %d (High: %d, Medium: %d, Low: %d)\n",
		report.Summary.TotalVulns, report.Summary.HighSeverity,
		report.Summary.MediumSeverity, report.Summary.LowSeverity)

	return nil
}
