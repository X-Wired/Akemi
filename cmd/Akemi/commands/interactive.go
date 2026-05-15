package commands

import (
	"fmt"
	"io"
	"log/slog"

	"Akemi/internal/core"
	"Akemi/internal/tui/dashboard"

	"github.com/spf13/cobra"
)

func newInteractiveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "interactive",
		Short: "Launch the interactive terminal dashboard",
		Long: `Launch Akemi's 4-panel terminal dashboard for interactive security testing.

The dashboard provides:
  ① Target Configuration — set target, ports, threads, proxy, intent
  ② Discovery — real-time results: subdomains, ports, URLs, endpoints, secrets
  ③ System Usage — live CPU, memory, network, and disk metrics
  ④ Agent / Exploit — live agent activity log and exploit findings

Navigation:
  Tab / Shift+Tab  Switch between panels
  Mouse click       Focus a panel
  Mouse drag        Resize panel borders
  Mouse scroll      Scroll within focused panel
  Ctrl+Y            Copy focused panel/selected discovery row
  Ctrl+M            Toggle mouse mode for native terminal selection
  F5 / Ctrl+O       Open DeepSeek/OpenAI API settings
  Ctrl+B            Toggle bottom status bar
  Ctrl+C            Quit`,
		RunE: runInteractive,
	}

	cmd.Flags().String("probe-dir", "./probes", "Directory containing YAML probe templates")
	cmd.Flags().String("import", "", "Load a .akemi archive into the dashboard")

	return cmd
}

func runInteractive(cmd *cobra.Command, args []string) error {
	probeDir, _ := cmd.Flags().GetString("probe-dir")
	importPath, _ := cmd.Flags().GetString("import")

	// Silence the core logger so service log messages don't spill onto stderr
	// and obscure the Bubble Tea dashboard.
	prevLogger := core.Logger()
	core.SetLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer core.SetLogger(prevLogger)

	svc := getServices()
	if probeDir != "" {
		svc.Vuln.LoadTemplates(probeDir)
	}
	initialArchive, err := loadAkemiArchive(importPath)
	if err != nil {
		return err
	}

	fmt.Println("Launching Akemi Terminal Interface...")

	dashSvc := dashboard.ConvertServices(svc.Scanner, svc.Discovery, svc.Vuln, svc.Subdomain, svc.Reporting)
	dashSvc.ArchiveDir = rootOutputDir
	dashSvc.InitialArchive = initialArchive
	dashSvc.MCPContext = svc.MCPContext
	dashSvc.AssistantLoad = buildDashboardAssistantLoad(svc, core.Logger())
	dashSvc.AssistantSetup = buildDashboardAssistantSetup(svc, core.Logger())
	dashSvc.APISettingsLoad = buildDashboardAPISettingsLoad()
	dashSvc.APISettingsTest = buildDashboardAPISettingsTest()
	dashSvc.APISettingsApply = buildDashboardAPISettingsApply(svc, core.Logger())
	if assistantSession, err := buildAssistantSession(svc, core.Logger()); err == nil {
		dashSvc.Assistant = assistantSession
	}
	return dashboard.RunDashboard(dashSvc)
}
