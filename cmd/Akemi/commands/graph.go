package commands

import (
	"context"
	"fmt"
	"time"

	core "Akemi/internal/core"

	"github.com/spf13/cobra"
)

func newGraphCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Generate attack surface graph visualizations",
		Long: `Generate interactive relational graphs showing the full attack surface:
targets, discovered endpoints, parameters, vulnerabilities, and their
relationships in an explorable HTML visualization.

Also supports DOT (Graphviz) and JSON export formats.

Examples:
  akemi graph --target target.com --output-dir ./results
  akemi graph --target target.com --format dot
  akemi graph --target target.com --format html,json`,
		RunE: runGraph,
	}

	cmd.Flags().StringP("target", "t", "", "Target identifier (required)")
	cmd.Flags().String("format", "html", "Output format: html, json, dot, or comma-separated")
	cmd.Flags().String("output", "", "Custom output path")

	return cmd
}

func runGraph(cmd *cobra.Command, args []string) error {
	target, _ := cmd.Flags().GetString("target")
	if target == "" {
		return fmt.Errorf("--target is required")
	}

	ctx := context.Background()
	s := getServices()

	data := &core.ReportData{
		Target:    target,
		StartTime: time.Now().Add(-5 * time.Minute),
		EndTime:   time.Now(),
	}

	graph, err := s.Reporting.GenerateGraph(ctx, data)
	if err != nil {
		return fmt.Errorf("graph generation failed: %w", err)
	}

	fmt.Printf("\n[*] Graph Generated:\n")
	fmt.Printf("    Nodes: %d | Edges: %d\n", len(graph.Nodes), len(graph.Edges))
	fmt.Printf("\nNode Types:\n")
	typeCounts := map[string]int{}
	for _, n := range graph.Nodes {
		typeCounts[n.Type]++
	}
	for t, c := range typeCounts {
		fmt.Printf("    %s: %d\n", t, c)
	}

	return nil
}
