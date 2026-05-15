package commands

import (
	"context"
	"fmt"
	"time"

	core "Akemi/internal/core"
	"Akemi/internal/fuzz"

	"github.com/spf13/cobra"
)

func newFuzzCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fuzz",
		Short: "Web fuzzing with wordlists",
		Long: `Fuzz URL paths, query parameters, or POST data using wordlists.

Supports GET and POST fuzzing with the FUZZ placeholder, concurrency control,
and output filtering by status code, line count, word count, or character count.

Examples:
  akemi fuzz --url https://target.com/FUZZ --wordlist dirs.txt
  akemi fuzz --url https://target.com/api -m POST -d "user=FUZZ&pass=admin" --wordlist users.txt`,
		RunE: runFuzz,
	}

	cmd.Flags().StringP("url", "u", "", "Target URL with FUZZ placeholder (required)")
	cmd.Flags().StringP("method", "m", "GET", "HTTP method (GET, POST, PUT, DELETE, PATCH)")
	cmd.Flags().StringP("data", "d", "", "POST/PUT/PATCH body data with FUZZ placeholder")
	cmd.Flags().StringP("wordlist", "w", "", "Wordlist/payload file (required)")
	cmd.Flags().IntP("concurrency", "c", 10, "Number of concurrent workers")
	cmd.Flags().IntP("repeats", "r", 1, "Requests per payload")
	cmd.Flags().StringP("output", "o", "fuzz_results.txt", "Output file for results")
	cmd.Flags().String("filter-status", "", "Only show results with these status codes (comma-separated)")
	cmd.Flags().Bool("mutations", false, "Apply bit-flip and URL-encoding mutations to payloads")

	return cmd
}

func runFuzz(cmd *cobra.Command, args []string) error {
	urlFlag, _ := cmd.Flags().GetString("url")
	if urlFlag == "" {
		return fmt.Errorf("--url is required")
	}

	wordlist, _ := cmd.Flags().GetString("wordlist")
	if wordlist == "" {
		return fmt.Errorf("--wordlist is required")
	}

	ctx := context.Background()
	_ = ctx

	cfg := core.FuzzConfig{
		URL:         urlFlag,
		Method:      flagString(cmd, "method"),
		Data:        flagString(cmd, "data"),
		PayloadFile: wordlist,
		OutputFile:  flagString(cmd, "output"),
		Repeats:     flagInt(cmd, "repeats"),
		Timeout:     rootTimeout,
		Concurrency: flagInt(cmd, "concurrency"),
	}

	fmt.Printf("\n[*] Starting fuzz:\n")
	fmt.Printf("    URL: %s\n", cfg.URL)
	fmt.Printf("    Method: %s | Workers: %d | Repeats: %d\n",
		cfg.Method, cfg.Concurrency, cfg.Repeats)
	fmt.Println()

	results, elapsed, err := fuzz.RunFuzzer(cfg)
	if err != nil {
		return fmt.Errorf("fuzzing failed: %w", err)
	}

	fmt.Printf("\n[*] Fuzzing complete. %d requests in %s\n", len(results), elapsed.Round(time.Millisecond))

	// Summary
	statusCounts := map[int]int{}
	for _, r := range results {
		statusCounts[r.StatusCode]++
	}
	fmt.Println("\nStatus Code Distribution:")
	for code, count := range statusCounts {
		fmt.Printf("    %d: %d responses\n", code, count)
	}

	return nil
}
