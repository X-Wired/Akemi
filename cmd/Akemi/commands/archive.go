package commands

import (
	"encoding/json"
	"fmt"

	akemiarchive "Akemi/internal/archive"

	"github.com/spf13/cobra"
)

func newArchiveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "archive",
		Short: "Read .akemi scan archives",
		Long: `Read versioned .akemi archives exported by the interactive dashboard.

Archives contain the scan configuration, structured results, and live discovery
sections captured during the run.`,
	}

	importCmd := &cobra.Command{
		Use:     "import <file.akemi>",
		Aliases: []string{"inspect", "read"},
		Short:   "Import and inspect a .akemi archive",
		Args:    cobra.ExactArgs(1),
		RunE:    runArchiveImport,
	}
	importCmd.Flags().Bool("json", false, "Print the decoded archive as JSON")

	cmd.AddCommand(importCmd)
	return cmd
}

func runArchiveImport(cmd *cobra.Command, args []string) error {
	file, err := akemiarchive.ReadFile(args[0])
	if err != nil {
		return err
	}

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(file)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "[*] .akemi archive: %s\n", args[0])
	fmt.Fprintf(out, "    Target: %s\n", file.Config.Target)
	fmt.Fprintf(out, "    Intent: %s\n", file.Config.Intent)
	fmt.Fprintf(out, "    Exported: %s\n", file.ExportedAt.Format("2006-01-02 15:04:05 MST"))
	if file.Summary != "" {
		fmt.Fprintf(out, "    Summary: %s\n", file.Summary)
	}
	fmt.Fprintf(out, "    Ports: %d | URLs: %d | Subdomains: %d | Findings: %d\n",
		len(file.Results.Ports), len(file.Results.URLs), len(file.Results.Subdomains), len(file.Results.Findings))
	fmt.Fprintf(out, "    Endpoints: %d | Params: %d | Secrets: %d | JS files: %d\n",
		maxInt(archiveSectionCount(file, "Endpoints"), len(file.Results.APIEndpoints)+len(file.Results.APISpecs)),
		maxInt(archiveSectionCount(file, "Params"), len(file.Results.Params)),
		maxInt(archiveSectionCount(file, "Secrets"), len(file.Results.Secrets)),
		maxInt(archiveSectionCount(file, "JS Files"), archiveJSFileCount(file)))

	return nil
}

func archiveJSFileCount(file *akemiarchive.File) int {
	count := 0
	for _, capture := range file.Results.JSAnalysis {
		count += len(capture.Result.ScriptURLs)
	}
	return count
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func archiveSectionCount(file *akemiarchive.File, name string) int {
	for _, section := range file.DiscoverySections {
		if section.Name == name {
			return section.Count
		}
	}
	return 0
}
