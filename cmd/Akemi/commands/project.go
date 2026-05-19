package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"Akemi/internal/project"

	"github.com/spf13/cobra"
)

func newProjectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "project",
		Short: "Manage Akemi engagement projects",
		Long: `Create, open, and inspect Akemi engagement projects.

Projects are self-contained directories that organize all scan output,
reports, databases, and runtime state for a single engagement or
recurring target. Use projects to keep your recon results cleanly
separated and easily archivable.

Examples:
  akemi project new --name "ACME Corp" --dir ~/engagements/acme
  akemi project open ~/engagements/acme
  akemi project list
  akemi project info`,
	}

	cmd.AddCommand(newProjectNewCmd())
	cmd.AddCommand(newProjectOpenCmd())
	cmd.AddCommand(newProjectListCmd())
	cmd.AddCommand(newProjectInfoCmd())

	return cmd
}

func newProjectNewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Create a new Akemi project",
		Long: `Create a new engagement project at the specified directory.

This initializes the project directory with the standard layout:
  akemi.project.toml   — Project manifest (name, scope, targets)
  akemi.db             — SQLite database for findings and state
  archives/            — .akemi scan archive storage
  reports/             — HTML/JSON report output
  graphs/              — Graph visualization exports
  logs/                — Structured session logs
  wordlists/           — Project-specific wordlists
  probes/              — Custom YAML probe templates
  .akemi/              — Internal runtime state

After creation the project is immediately available via --project.
`,
		Example: `  akemi project new --name "ACME External" --dir ~/engagements/acme-ext
  akemi project new --name "Bug Bounty Q1" --dir ./bb-q1 --description "Quarterly bug bounty sprint"`,
		RunE: runProjectNew,
	}

	cmd.Flags().String("name", "", "Project name (required)")
	cmd.Flags().String("dir", "", "Project directory path (required)")
	cmd.Flags().String("description", "", "Short description of the engagement")

	return cmd
}

func newProjectOpenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "open [directory]",
		Short: "Open an existing Akemi project",
		Long: `Open an existing Akemi project from the given directory.

If no directory is provided, the command walks up from the current
working directory looking for an akemi.project.toml file.

Examples:
  akemi project open ~/engagements/acme-ext
  akemi project open                    # auto-detect from CWD`,
		Args: cobra.MaximumNArgs(1),
		RunE: runProjectOpen,
	}

	return cmd
}

func newProjectListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List recent Akemi projects",
		Long:  "Display recently opened Akemi projects from the global registry (~/.akemi/projects.json).",
		RunE:  runProjectList,
	}

	return cmd
}

func newProjectInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show details about the current project",
		Long:  "Display information about the currently loaded Akemi project.",
		RunE:  runProjectInfo,
	}

	return cmd
}

func runProjectNew(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	dir, _ := cmd.Flags().GetString("dir")
	description, _ := cmd.Flags().GetString("description")

	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("--name is required")
	}
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("--dir is required")
	}

	proj, err := project.CreateProject(dir, name)
	if err != nil {
		return fmt.Errorf("create project: %w", err)
	}
	defer proj.Close()

	if description != "" {
		proj.Manifest.Description = strings.TrimSpace(description)
		_ = proj.SaveManifest()
	}

	fmt.Printf(`
✅ Project created successfully!

   Name:      %s
   Location:  %s
   Database:  %s

   Directories created:
     archives/     Scan archive storage (.akemi files)
     reports/      HTML/JSON reports
     graphs/       Graph visualizations
     logs/         Session logs
     wordlists/    Custom wordlists
     probes/       Custom YAML templates
     .akemi/       Runtime state

   Launch with:
     akemi --project "%s"
     akemi interactive --project "%s"
`, proj.DisplayName(), proj.Root, proj.DatabasePath(), proj.Root, proj.Root)

	return nil
}

func runProjectOpen(cmd *cobra.Command, args []string) error {
	var dir string
	if len(args) > 0 {
		dir = args[0]
	}

	var proj *project.Project
	var err error

	if dir != "" {
		proj, err = project.OpenProject(dir)
	} else {
		proj, err = project.DetectProject("")
	}

	if err != nil {
		return fmt.Errorf("open project: %w", err)
	}
	if proj == nil {
		return fmt.Errorf("no Akemi project found — run 'akemi project new' to create one, or provide a directory")
	}
	defer proj.Close()

	stats, _ := proj.Stats()

	fmt.Printf(`
📁 Project: %s
   Location:  %s
   Database:  %s
`, proj.DisplayName(), proj.Root, proj.DatabasePath())

	if proj.Description() != "" {
		fmt.Printf("   Notes:     %s\n", proj.Description())
	}

	if stats != nil {
		fmt.Printf(`
   Sessions:  %d
   Findings:  %d
`, stats.TotalSessions, stats.TotalFindings)
		if len(stats.RecentTargets) > 0 {
			fmt.Printf("   Targets:   %s\n", strings.Join(stats.RecentTargets, ", "))
		}
	}

	if len(proj.Targets()) > 0 {
		fmt.Printf("   Scope:     %s\n", strings.Join(proj.Targets(), ", "))
	}

	fmt.Printf(`
   Launch with:
     akemi --project "%s"
`, proj.Root)

	return nil
}

func runProjectList(cmd *cobra.Command, args []string) error {
	registry, err := project.LoadRegistry()
	if err != nil {
		return fmt.Errorf("load registry: %w", err)
	}

	entries := registry.Entries()
	if len(entries) == 0 {
		fmt.Println("No recent projects found.")
		fmt.Println("Create one with: akemi project new --name <name> --dir <path>")
		return nil
	}

	fmt.Print("\n📁 Recent Akemi Projects:\n\n")
	for _, entry := range entries {
		age := time.Since(entry.LastOpened).Truncate(time.Minute)
		targets := strings.Join(entry.Targets, ", ")
		if targets == "" {
			targets = "(no targets)"
		}

		// Check if the project directory still exists.
		exists := ""
		if !project.IsProjectRoot(entry.Root) {
			exists = " [directory missing]"
		}

		fmt.Printf("  %s\n", entry.Name)
		fmt.Printf("    Path:    %s%s\n", entry.Root, exists)
		fmt.Printf("    Targets: %s\n", targets)
		fmt.Printf("    Last:    %s ago\n", age)
		fmt.Println()
	}

	return nil
}

func runProjectInfo(cmd *cobra.Command, args []string) error {
	// Try auto-detection first.
	proj, err := project.DetectProject("")
	if err != nil {
		return fmt.Errorf("detect project: %w", err)
	}
	if proj == nil {
		// Check the global services for a loaded project.
		svc := getServices()
		if svc != nil && svc.Project != nil {
			proj = svc.Project
		}
	}
	if proj == nil {
		fmt.Println("No project loaded. Start one with:")
		fmt.Println("  akemi project new --name <name> --dir <path>")
		fmt.Println("  akemi project open <path>")
		fmt.Println("  akemi --project <path>")
		return nil
	}
	defer proj.Close()

	stats, _ := proj.Stats()

	fmt.Printf(`
📁 Project: %s
   Root:      %s
   Created:   %s
   Updated:   %s
`,
		proj.DisplayName(),
		proj.Root,
		proj.CreatedAt().Format("2006-01-02 15:04"),
		proj.UpdatedAt().Format("2006-01-02 15:04"),
	)

	if proj.Description() != "" {
		fmt.Printf("   Notes:    %s\n", proj.Description())
	}
	if len(proj.Targets()) > 0 {
		fmt.Printf("   Targets:  %s\n", strings.Join(proj.Targets(), ", "))
	}
	if proj.Manifest != nil && proj.Manifest.Scope.Notes != "" {
		fmt.Printf("   Scope:    %s\n", proj.Manifest.Scope.Notes)
	}

	fmt.Println()
	fmt.Println("   Directories:")
	fmt.Printf("     Archives:    %s\n", proj.ResolvePathIfExists("archives"))
	fmt.Printf("     Reports:     %s\n", proj.ResolvePathIfExists("reports"))
	fmt.Printf("     Graphs:      %s\n", proj.ResolvePathIfExists("graphs"))
	fmt.Printf("     Logs:        %s\n", proj.ResolvePathIfExists("logs"))
	fmt.Printf("     Wordlists:   %s\n", proj.ResolvePathIfExists("wordlists"))
	fmt.Printf("     Probes:      %s\n", proj.ResolvePathIfExists("probes"))

	if stats != nil {
		fmt.Printf(`
   Statistics:
     Sessions:   %d
     Findings:   %d
`, stats.TotalSessions, stats.TotalFindings)
		if len(stats.FindingsBySev) > 0 {
			fmt.Println("     By severity:")
			for sev, count := range stats.FindingsBySev {
				fmt.Printf("       %s: %d\n", sev, count)
			}
		}
	}

	// Determine canonical path relative to home for display.
	home, _ := os.UserHomeDir()
	displayPath := proj.Root
	if home != "" {
		if rel, err := filepath.Rel(home, proj.Root); err == nil && !strings.HasPrefix(rel, "..") {
			displayPath = "~" + string(filepath.Separator) + rel
		}
	}
	fmt.Printf("\n   Launch:  akemi --project \"%s\"\n\n", displayPath)

	return nil
}
