// Package tui provides a rich terminal user interface for Akemi
// built with Bubble Tea. It offers interactive mode selection,
// real-time scan progress, findings browsing, and report viewing.
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	core "Akemi/internal/core"
	"Akemi/internal/service"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// =============================================================================
// Styles
// =============================================================================

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#7B2FBE")).
			Padding(0, 1)

	accentStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#9D4EDD"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#04B575"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF4672"))

	warnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFB86C"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666"))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888"))

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#7B2FBE")).
			Padding(0, 1)
)

// =============================================================================
// Models
// =============================================================================

// Screen represents the current TUI view.
type Screen int

const (
	ScreenMenu Screen = iota
	ScreenScanConfig
	ScreenRunning
	ScreenResults
	ScreenFindings
	ScreenReport
)

// MenuOption represents a selectable action in the main menu.
type MenuOption struct {
	Label       string
	Description string
	Screen      Screen
}

var menuOptions = []MenuOption{
	{Label: "Quick Recon", Description: "Fast triage: port scan, crawl, headers, tech fingerprint"},
	{Label: "Full Surface Map", Description: "Complete discovery: subdomains, ports, URLs, params, JS, API"},
	{Label: "SQLi Hunt", Description: "Focused SQL injection discovery on a target URL"},
	{Label: "Vulnerability Scan", Description: "Full vulnerability assessment with exploit correlation"},
	{Label: "List Templates", Description: "Browse available YAML probe templates"},
	{Label: "View Reports", Description: "View previously generated reports"},
	{Label: "Exit", Description: "Exit Akemi TUI"},
}

// =============================================================================
// Main Model
// =============================================================================

// Model is the top-level Bubble Tea model.
type Model struct {
	// Screen state
	screen   Screen
	width    int
	height   int
	quitting bool

	// Menu
	cursor    int
	menuItems []MenuOption

	// Input
	target      string
	intent      string
	inputMode   bool
	inputVal    string
	inputPrompt string

	// Progress
	spinner   spinner.Model
	progress  progress.Model
	statusMsg string
	taskCount int
	taskDone  int

	// Results
	findings    []core.VulnFinding
	ports       []core.PortResult
	urls        []string
	subdomains  []string
	scanSummary string

	// Table
	findingsTable table.Model
	viewport      viewport.Model

	// Templates
	templates []core.ProbeTemplate

	// Services
	scanner       core.Scanner
	discoverer    core.Discoverer
	prober        core.Prober
	subEnumerator core.SubEnumerator
	reporter      core.Reporter
}

// Services holds the Phase 1 service interfaces.
type Services struct {
	Scanner       core.Scanner
	Discoverer    core.Discoverer
	Prober        core.Prober
	SubEnumerator core.SubEnumerator
	Reporter      core.Reporter
}

// NewModel creates the main TUI model.
func NewModel(svc *Services) *Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = accentStyle

	p := progress.New(progress.WithDefaultGradient())

	columns := []table.Column{
		{Title: "Severity", Width: 10},
		{Title: "Name", Width: 30},
		{Title: "Target", Width: 40},
		{Title: "Evidence", Width: 50},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(15),
	)

	ts := table.DefaultStyles()
	ts.Header = ts.Header.Bold(true).Foreground(lipgloss.Color("#7B2FBE"))
	ts.Selected = ts.Selected.Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#7B2FBE"))
	t.SetStyles(ts)

	vp := viewport.New(80, 20)
	vp.Style = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1)

	m := &Model{
		screen:        ScreenMenu,
		menuItems:     menuOptions,
		cursor:        0,
		spinner:       s,
		progress:      p,
		findingsTable: t,
		viewport:      vp,
	}

	if svc != nil {
		m.scanner = svc.Scanner
		m.discoverer = svc.Discoverer
		m.prober = svc.Prober
		m.subEnumerator = svc.SubEnumerator
		m.reporter = svc.Reporter
	}

	return m
}

// Init initializes the model.
func (m *Model) Init() tea.Cmd {
	return m.spinner.Tick
}

// Update handles messages.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.viewport.Width = msg.Width - 4
		m.viewport.Height = msg.Height - 8
		return m, nil

	case tea.KeyMsg:
		if m.inputMode {
			return m.handleInputKey(msg)
		}
		return m.handleKey(msg)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		m.progress = progressModel.(progress.Model)
		return m, cmd

	case ScanCompleteMsg:
		m.statusMsg = fmt.Sprintf("Scan complete — %s", msg.Summary)
		m.findings = msg.Findings
		m.ports = msg.Ports
		m.urls = msg.URLs
		m.subdomains = msg.Subdomains
		m.scanSummary = msg.Summary
		m.screen = ScreenResults
		m.updateFindingsTable()
		return m, nil

	case ScanProgressMsg:
		m.taskDone = msg.Done
		m.taskCount = msg.Total
		m.statusMsg = msg.Message
		cmd := m.progress.SetPercent(float64(msg.Done) / float64(msg.Total))
		return m, cmd

	case TemplatesLoadedMsg:
		m.templates = msg.Templates
		m.screen = ScreenFindings
		m.updateTemplatesView()
		return m, nil
	}

	return m, nil
}

// View renders the current screen.
func (m *Model) View() string {
	if m.quitting {
		return "Goodbye!\n"
	}

	switch m.screen {
	case ScreenMenu:
		return m.renderMenu()
	case ScreenScanConfig:
		return m.renderScanConfig()
	case ScreenRunning:
		return m.renderRunning()
	case ScreenResults:
		return m.renderResults()
	case ScreenFindings:
		return m.renderFindings()
	case ScreenReport:
		return m.renderReport()
	default:
		return m.renderMenu()
	}
}

// =============================================================================
// Menu Screen
// =============================================================================

func (m *Model) renderMenu() string {
	var sb strings.Builder

	// Header
	sb.WriteString(titleStyle.Render("🔍 Akemi Terminal Interface"))
	sb.WriteString("\n\n")
	sb.WriteString(dimStyle.Render("Select an operation mode (↑/↓ to navigate, Enter to select, q to quit)"))
	sb.WriteString("\n\n")

	// Menu items
	for i, item := range m.menuItems {
		cursor := "  "
		if i == m.cursor {
			cursor = accentStyle.Render("▶ ")
			sb.WriteString(selectedStyle.Render(fmt.Sprintf("%s %s", cursor, item.Label)))
		} else {
			sb.WriteString(fmt.Sprintf("  %s %s", cursor, dimStyle.Render(item.Label)))
		}
		sb.WriteString("\n")
		sb.WriteString(dimStyle.Render(fmt.Sprintf("     %s", item.Description)))
		sb.WriteString("\n\n")
	}

	// Help
	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("↑/↓ navigate  •  Enter select  •  q quit"))

	return sb.String()
}

// =============================================================================
// Scan Config Screen
// =============================================================================

func (m *Model) renderScanConfig() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render(fmt.Sprintf("Configure: %s", m.menuItems[m.cursor].Label)))
	sb.WriteString("\n\n")

	if m.inputMode {
		sb.WriteString(fmt.Sprintf("%s: %s", m.inputPrompt, m.inputVal))
		sb.WriteString(accentStyle.Render("█")) // Cursor
		sb.WriteString("\n\n")
		sb.WriteString(helpStyle.Render("Type value and press Enter  •  Esc to cancel"))
	} else {
		sb.WriteString(fmt.Sprintf("Target: %s", accentStyle.Render(m.target)))
		sb.WriteString("\n\n")
		sb.WriteString(helpStyle.Render("t - set target  •  Enter - run scan  •  Esc - back to menu"))
	}

	return sb.String()
}

// =============================================================================
// Running Screen
// =============================================================================

func (m *Model) renderRunning() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Running Scan..."))
	sb.WriteString("\n\n")

	// Spinner
	sb.WriteString(fmt.Sprintf("%s %s", m.spinner.View(), m.statusMsg))
	sb.WriteString("\n\n")

	// Progress bar
	if m.taskCount > 0 {
		sb.WriteString(m.progress.View())
		sb.WriteString(fmt.Sprintf("\n  %d/%d tasks", m.taskDone, m.taskCount))
	}

	sb.WriteString("\n\n")
	sb.WriteString(helpStyle.Render("Ctrl+C to cancel"))

	return sb.String()
}

// =============================================================================
// Results Screen
// =============================================================================

func (m *Model) renderResults() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Scan Results"))
	sb.WriteString("\n\n")

	sb.WriteString(m.scanSummary)
	sb.WriteString("\n\n")

	// Quick stats
	stats := fmt.Sprintf("Ports: %d | URLs: %d | Subdomains: %d | Findings: %d",
		len(m.ports), len(m.urls), len(m.subdomains), len(m.findings))
	sb.WriteString(accentStyle.Render(stats))
	sb.WriteString("\n\n")

	// Top findings
	if len(m.findings) > 0 {
		sb.WriteString(warnStyle.Render("Top Findings:"))
		sb.WriteString("\n")
		for i, f := range m.findings {
			if i >= 10 {
				break
			}
			sevStyle := getSeverityStyle(f.Severity)
			sb.WriteString(fmt.Sprintf("  %s %s — %s\n",
				sevStyle.Render(fmt.Sprintf("[%s]", f.Severity)),
				f.Name,
				dimStyle.Render(truncateStr(f.Description, 60))))
		}
	}

	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("f - view all findings  •  p - view ports  •  r - generate report  •  Esc - menu"))

	return sb.String()
}

// =============================================================================
// Findings Screen
// =============================================================================

func (m *Model) renderFindings() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Findings"))
	sb.WriteString(fmt.Sprintf(dimStyle.Render(" (%d total, ↑/↓ to select)"), len(m.findings)))
	sb.WriteString("\n\n")

	sb.WriteString(m.findingsTable.View())
	sb.WriteString("\n")
	sb.WriteString(m.viewport.View())

	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("↑/↓ select finding  •  detail pane below  •  Esc back"))

	return sb.String()
}

// =============================================================================
// Report Screen
// =============================================================================

func (m *Model) renderReport() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Report Preview"))
	sb.WriteString("\n\n")

	sb.WriteString(m.viewport.View())

	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("↑/↓ scroll  •  e export  •  Esc back"))

	return sb.String()
}

// =============================================================================
// Key Handlers
// =============================================================================

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Global quit keys
	if key == "q" || key == "ctrl+c" || key == "ctrl+x" {
		if m.screen == ScreenRunning {
			return m, tea.Quit
		}
		m.quitting = true
		return m, tea.Quit
	}

	// Global escape — back to menu
	if key == "esc" {
		if m.screen != ScreenMenu {
			m.screen = ScreenMenu
			m.inputMode = false
		}
		return m, nil
	}

	// When on findings screen, forward navigation keys to the table
	if m.screen == ScreenFindings {
		switch key {
		case "up", "down", "k", "j", "pgup", "pgdown", "u", "d", "home", "end", "g", "G":
			m.findingsTable, _ = m.findingsTable.Update(msg)
			m.updateFindingDetail()
		}
		return m, nil
	}

	switch key {
	case "up", "k":
		if m.screen == ScreenMenu && m.cursor > 0 {
			m.cursor--
		}

	case "down", "j":
		if m.screen == ScreenMenu && m.cursor < len(m.menuItems)-1 {
			m.cursor++
		}

	case "enter":
		return m.handleEnter()

	case "t":
		if m.screen == ScreenScanConfig {
			m.inputMode = true
			m.inputPrompt = "Enter target URL or domain"
			m.inputVal = m.target
		}

	case "f":
		if m.screen == ScreenResults {
			m.screen = ScreenFindings
			m.updateFindingsTable()
			m.updateFindingDetail()
		}

	case "r":
		if m.screen == ScreenResults {
			m.screen = ScreenReport
			m.updateReportView()
		}
	}

	return m, nil
}

func (m *Model) handleInputKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		m.target = m.inputVal
		m.inputMode = false
	case "esc":
		m.inputMode = false
	case "backspace":
		if len(m.inputVal) > 0 {
			m.inputVal = m.inputVal[:len(m.inputVal)-1]
		}
	default:
		if len(msg.String()) == 1 {
			m.inputVal += msg.String()
		}
	}
	return m, nil
}

func (m *Model) handleEnter() (tea.Model, tea.Cmd) {
	switch m.screen {
	case ScreenMenu:
		switch m.cursor {
		case 0: // Quick Recon
			m.intent = "quick_recon"
		case 1: // Full Surface Map
			m.intent = "full_surface_map"
		case 2: // SQLi Hunt
			m.intent = "sqli_hunt"
		case 3: // Vulnerability Scan
			m.intent = "vuln_assessment"
		case 4: // List Templates
			return m, m.loadTemplatesCmd()
		case 5: // View Reports
			m.screen = ScreenReport
			return m, nil
		case 6: // Exit
			m.quitting = true
			return m, tea.Quit
		}
		m.screen = ScreenScanConfig

	case ScreenScanConfig:
		if m.target != "" {
			m.screen = ScreenRunning
			return m, m.runScanCmd()
		}

	case ScreenResults:
		m.screen = ScreenMenu
	}

	return m, nil
}

// =============================================================================
// Commands
// =============================================================================

// ScanCompleteMsg signals scan completion.
type ScanCompleteMsg struct {
	Summary    string
	Findings   []core.VulnFinding
	Ports      []core.PortResult
	URLs       []string
	Subdomains []string
}

// ScanProgressMsg signals scan progress.
type ScanProgressMsg struct {
	Done    int
	Total   int
	Message string
}

// TemplatesLoadedMsg signals templates have been loaded.
type TemplatesLoadedMsg struct {
	Templates []core.ProbeTemplate
}

func (m *Model) loadTemplatesCmd() tea.Cmd {
	return func() tea.Msg {
		if m.prober != nil {
			templates := m.prober.ListTemplates()
			return TemplatesLoadedMsg{Templates: templates}
		}
		return TemplatesLoadedMsg{}
	}
}

func (m *Model) runScanCmd() tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		var findings []core.VulnFinding
		var ports []core.PortResult
		var urls []string
		var subdomains []string

		// Send progress updates
		// (in a real implementation, these would come from the event bus)
		total := 4
		done := 0

		// Quick recon workflow
		if m.intent == "quick_recon" {
			// 1. Port scan
			done = 1
			// progress sent via tea.Batch in real impl
			_ = done
			_ = total

			scanReq := core.ScanRequest{
				Host: m.target, Ports: []int{80, 443, 8080, 8443},
				Threads: 100, TimeoutMs: 3000, Retries: 1, BannerGrab: true,
				SuppressOutput: true,
			}
			if m.scanner != nil {
				if result, err := m.scanner.Scan(ctx, scanReq); err == nil {
					ports = result.OpenPorts
				}
			}

			// 2. Crawl
			if m.discoverer != nil {
				if crawlResult, err := m.discoverer.Crawl(ctx, m.target, 2); err == nil {
					for _, f := range crawlResult {
						urls = append(urls, f.URL)
					}
				}
			}

			// 3. Check headers via probe
			if m.prober != nil {
				probeCfg := core.ProbeConfig{
					Threads: 1, Timeout: 10, UseTemplates: true,
					TemplateTags: []string{"headers", "misconfig"},
					Fingerprint:  true,
					Prioritize:   true,
				}
				if f, err := m.prober.Probe(ctx, m.target, probeCfg); err == nil {
					findings = append(findings, f...)
				}
			}

			// 4. Tech fingerprint
			if m.prober != nil {
				techCfg := core.ProbeConfig{
					Threads: 1, Timeout: 10, UseTemplates: true,
					TemplateTags: []string{"tech", "detect"},
					Fingerprint:  true,
					Prioritize:   true,
				}
				if f, err := m.prober.Probe(ctx, m.target, techCfg); err == nil {
					findings = append(findings, f...)
				}
			}
		}

		// Subdomain enumeration
		if m.intent == "full_surface_map" {
			if m.subEnumerator != nil {
				cfg := core.SubdomainConfig{
					Threads: 20, Timeout: 10, UseCrtSh: true, CheckAlive: true,
				}
				if results, err := m.subEnumerator.Enumerate(ctx, m.target, cfg); err == nil {
					for _, r := range results {
						if r.IsAlive {
							subdomains = append(subdomains, r.Name)
						}
					}
				}
			}

			// Also run quick recon steps
			if m.discoverer != nil {
				if crawlResult, err := m.discoverer.Crawl(ctx, m.target, 3); err == nil {
					for _, f := range crawlResult {
						urls = append(urls, f.URL)
					}
				}
			}
		}

		// SQLi hunt
		if m.intent == "sqli_hunt" {
			if m.discoverer != nil {
				if crawlResult, err := m.discoverer.Crawl(ctx, m.target, 2); err == nil {
					for _, f := range crawlResult {
						urls = append(urls, f.URL)
					}
				}
			}
			if m.prober != nil {
				probeCfg := core.ProbeConfig{
					Threads: 5, Timeout: 10, UseTemplates: true,
					TemplateTags: []string{"sqli"},
					Fingerprint:  true,
					Prioritize:   true,
				}
				if f, err := m.prober.Probe(ctx, m.target, probeCfg); err == nil {
					findings = append(findings, f...)
				}
			}
		}

		// Vulnerability assessment
		if m.intent == "vuln_assessment" {
			// 1. Quick port scan for context
			scanReq := core.ScanRequest{
				Host: m.target, Ports: []int{80, 443, 8080, 8443, 3000, 5000, 8000, 9090},
				Threads: 100, TimeoutMs: 3000, Retries: 1, BannerGrab: true,
				SuppressOutput: true,
			}
			if m.scanner != nil {
				if result, err := m.scanner.Scan(ctx, scanReq); err == nil {
					ports = result.OpenPorts
				}
			}

			// 2. Crawl for URL discovery
			if m.discoverer != nil {
				if crawlResult, err := m.discoverer.Crawl(ctx, m.target, 2); err == nil {
					for _, f := range crawlResult {
						urls = append(urls, f.URL)
					}
				}
			}

			// 3. Run full vulnerability probe
			if m.prober != nil {
				probeCfg := core.ProbeConfig{
					Threads: 10, Timeout: 15, UseTemplates: true,
					Fingerprint: true,
					Prioritize:  true,
				}
				if f, err := m.prober.Probe(ctx, m.target, probeCfg); err == nil {
					findings = append(findings, f...)
				}
			}
		}

		summary := fmt.Sprintf("Scan: %s on %s\nFindings: %d | Ports: %d | URLs: %d | Subdomains: %d",
			m.intent, m.target, len(findings), len(ports), len(urls), len(subdomains))

		return ScanCompleteMsg{
			Summary:    summary,
			Findings:   findings,
			Ports:      ports,
			URLs:       urls,
			Subdomains: subdomains,
		}
	}
}

func (m *Model) updateFindingsTable() {
	rows := make([]table.Row, 0, len(m.findings))
	for _, f := range m.findings {
		rows = append(rows, table.Row{
			f.Severity,
			f.Name,
			f.Target,
			truncateStr(f.Evidence, 48),
		})
	}
	m.findingsTable.SetRows(rows)
}

func (m *Model) updateFindingDetail() {
	idx := m.findingsTable.Cursor()
	if idx < 0 || idx >= len(m.findings) {
		m.viewport.SetContent("No finding selected.")
		return
	}

	f := m.findings[idx]
	var sb strings.Builder
	sevStyle := getSeverityStyle(f.Severity)

	sb.WriteString(titleStyle.Render(f.Name))
	sb.WriteString("\n\n")
	sb.WriteString(fmt.Sprintf("Severity:     %s\n", sevStyle.Render(f.Severity)))
	sb.WriteString(fmt.Sprintf("ID:           %s\n", dimStyle.Render(f.ID)))
	sb.WriteString(fmt.Sprintf("Target:       %s\n", accentStyle.Render(f.Target)))
	sb.WriteString("\n")
	sb.WriteString(warnStyle.Render("Description:"))
	sb.WriteString("\n")
	sb.WriteString(f.Description)
	sb.WriteString("\n\n")

	if f.Evidence != "" {
		sb.WriteString(warnStyle.Render("Evidence:"))
		sb.WriteString("\n")
		sb.WriteString(dimStyle.Render(f.Evidence))
		sb.WriteString("\n\n")
	}

	if f.Remediation != "" {
		sb.WriteString(successStyle.Render("Remediation:"))
		sb.WriteString("\n")
		sb.WriteString(f.Remediation)
		sb.WriteString("\n")
	}

	m.viewport.SetContent(sb.String())
}

func (m *Model) updateTemplatesView() {
	// Clear findings table since we're showing templates
	m.findingsTable.SetRows(nil)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Available Templates: %d\n\n", len(m.templates)))
	for _, t := range m.templates {
		if t.Disabled {
			continue
		}
		sb.WriteString(fmt.Sprintf("[%s] %s\n  %s\n  Tags: %s\n\n",
			t.Info.Severity, t.ID, t.Info.Description,
			strings.Join(t.Info.Tags, ", ")))
	}
	m.viewport.SetContent(sb.String())
}

func (m *Model) updateReportView() {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Scan Report: %s\n", m.target))
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Intent: %s\n", m.intent))
	sb.WriteString(fmt.Sprintf("Findings: %d\n", len(m.findings)))
	sb.WriteString(fmt.Sprintf("Open Ports: %d\n", len(m.ports)))
	sb.WriteString(fmt.Sprintf("URLs Discovered: %d\n", len(m.urls)))
	sb.WriteString(fmt.Sprintf("Subdomains: %d\n\n", len(m.subdomains)))

	if len(m.findings) > 0 {
		sb.WriteString("─ Findings ─────────────────────────────\n\n")
		for _, f := range m.findings {
			sb.WriteString(fmt.Sprintf("[%s] %s\n", f.Severity, f.Name))
			sb.WriteString(fmt.Sprintf("  Target: %s\n", f.Target))
			sb.WriteString(fmt.Sprintf("  %s\n", f.Description))
			if f.Evidence != "" {
				sb.WriteString(fmt.Sprintf("  Evidence: %s\n", truncateStr(f.Evidence, 80)))
			}
			sb.WriteString("\n")
		}
	}
	m.viewport.SetContent(sb.String())
}

// =============================================================================
// Helpers
// =============================================================================

func getSeverityStyle(severity string) lipgloss.Style {
	switch strings.ToLower(severity) {
	case "critical":
		return errorStyle
	case "high":
		return warnStyle
	case "medium":
		return accentStyle
	default:
		return dimStyle
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// =============================================================================
// Exposed API
// =============================================================================

// RunTUI initializes the TUI with services and runs it.
func RunTUI(svc *Services) error {
	m := NewModel(svc)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// Ensure unused imports are kept for interface satisfaction
var _ = time.Now
var _ = service.ScannerService{}
var _ = fmt.Sprintf
