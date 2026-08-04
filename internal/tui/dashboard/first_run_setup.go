package dashboard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"Akemi/internal/config"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	setupFieldProjectsDir = iota
	setupFieldProvider
	setupFieldAPIKey
	setupFieldLogLevel
	setupActionSave
	setupActionSkip
	setupFieldCount
)

var setupProviderOptions = []string{
	"deepseek",
	"openai",
	"gemini",
	"anthropic",
	"ollama",
	"none",
}

var setupLogLevelOptions = []string{
	"info",
	"debug",
	"warn",
	"error",
}

// SetupCompletedMsg is emitted when the user completes first-run configuration.
type SetupCompletedMsg struct {
	ConfigPath  string
	Configured  int
	ProjectsDir string
	Provider    string
	APIKey      string
	LogLevel    string
	Error       string
}

type firstRunSetupModal struct {
	visible       bool
	focus         int
	busy          bool
	status        string
	projectsDir   string
	providerIdx   int
	apiKey        string
	logLevelIdx   int
	configPath    string
	editing       bool
	cursorVisible bool

	SaveRequested bool
}

func newFirstRunSetupModal() *firstRunSetupModal {
	return &firstRunSetupModal{
		focus:         setupFieldProjectsDir,
		projectsDir:   "Projects",
		cursorVisible: true,
		providerIdx:   0,
		logLevelIdx:   0,
		status:        "Welcome to Akemi! Configure your environment below.",
	}
}

func (m *firstRunSetupModal) open(configPath string) {
	m.visible = true
	m.cursorVisible = true
	m.focus = setupFieldProjectsDir
	m.configPath = configPath
	m.editing = false
	m.busy = false
	m.status = "First-Run Setup — Configure your system & projects directory."
}

func (m *firstRunSetupModal) close() {
	m.visible = false
	m.busy = false
	m.editing = false
}

func (m *firstRunSetupModal) handleKey(msg tea.KeyMsg) (bool, tea.Cmd) {
	if !m.visible {
		return false, nil
	}

	key := msg.String()

	if m.editing {
		switch key {
		case "enter", "esc":
			m.editing = false
		case "backspace":
			if m.focus == setupFieldProjectsDir && len(m.projectsDir) > 0 {
				m.projectsDir = m.projectsDir[:len(m.projectsDir)-1]
			} else if m.focus == setupFieldAPIKey && len(m.apiKey) > 0 {
				m.apiKey = m.apiKey[:len(m.apiKey)-1]
			}
		default:
			if len(key) == 1 {
				if m.focus == setupFieldProjectsDir {
					m.projectsDir += key
				} else if m.focus == setupFieldAPIKey {
					m.apiKey += key
				}
			}
		}
		return true, nil
	}

	switch key {
	case "up", "k":
		if m.focus > 0 {
			m.focus--
		}
	case "down", "j", "tab":
		m.focus = (m.focus + 1) % setupFieldCount
	case "left", "h":
		if m.focus == setupFieldProvider {
			m.providerIdx = (m.providerIdx - 1 + len(setupProviderOptions)) % len(setupProviderOptions)
		} else if m.focus == setupFieldLogLevel {
			m.logLevelIdx = (m.logLevelIdx - 1 + len(setupLogLevelOptions)) % len(setupLogLevelOptions)
		}
	case "right", "l":
		if m.focus == setupFieldProvider {
			m.providerIdx = (m.providerIdx + 1) % len(setupProviderOptions)
		} else if m.focus == setupFieldLogLevel {
			m.logLevelIdx = (m.logLevelIdx + 1) % len(setupLogLevelOptions)
		}
	case "enter", "space":
		if m.focus == setupFieldProjectsDir || m.focus == setupFieldAPIKey {
			m.editing = true
			return true, nil
		}
		if m.focus == setupFieldProvider {
			m.providerIdx = (m.providerIdx + 1) % len(setupProviderOptions)
			return true, nil
		}
		if m.focus == setupFieldLogLevel {
			m.logLevelIdx = (m.logLevelIdx + 1) % len(setupLogLevelOptions)
			return true, nil
		}
		if m.focus == setupActionSave {
			m.SaveRequested = true
			return true, m.completeSetupCmd(1)
		}
		if m.focus == setupActionSkip {
			m.SaveRequested = true
			return true, m.completeSetupCmd(0)
		}
	case "esc":
		m.close()
		return true, nil
	}

	return true, nil
}

func (m *firstRunSetupModal) completeSetupCmd(configured int) tea.Cmd {
	m.busy = true
	m.status = "Saving configuration..."
	pDir := strings.TrimSpace(m.projectsDir)
	if pDir == "" {
		pDir = "Projects"
	}
	provider := setupProviderOptions[m.providerIdx]
	apiKey := strings.TrimSpace(m.apiKey)
	logLevel := setupLogLevelOptions[m.logLevelIdx]
	path := m.configPath

	return func() tea.Msg {
		// Ensure workemi directory exists
		if err := config.EnsureWorkemiDirectory(); err != nil {
			return SetupCompletedMsg{Error: err.Error()}
		}

		// Create actual target projects path
		targetProjPath := pDir
		if !filepath.IsAbs(targetProjPath) {
			targetProjPath = filepath.Join(config.WorkemiDirectory(), pDir)
		}
		if err := os.MkdirAll(targetProjPath, 0700); err != nil {
			return SetupCompletedMsg{Error: fmt.Errorf("create projects directory: %w", err).Error()}
		}

		// Save configuration
		savedPath, err := config.UpdateFirstRunConfig(path, configured, pDir, provider, apiKey)
		if err != nil {
			return SetupCompletedMsg{Error: err.Error()}
		}

		return SetupCompletedMsg{
			ConfigPath:  savedPath,
			Configured:  configured,
			ProjectsDir: targetProjPath,
			Provider:    provider,
			APIKey:      apiKey,
			LogLevel:    logLevel,
		}
	}
}

func (m *firstRunSetupModal) View(width, height int) string {
	if !m.visible {
		return ""
	}

	boxWidth := min(72, max(40, width-8))

	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(PurpleLight).
		Padding(1, 2).
		Width(boxWidth)

	var sb strings.Builder
	sb.WriteString(HighlightRow.Render("  🚀 Welcome to Akemi — First-Run Configuration  "))
	sb.WriteString("\n\n")
	sb.WriteString(DimText.Render("Working Directory: "))
	sb.WriteString(AccentText.Render(config.WorkemiDirectory()))
	sb.WriteString("\n")
	sb.WriteString(DimText.Render("Configuration File: "))
	sb.WriteString(AccentText.Render(m.configPath))
	sb.WriteString("\n\n")
	sb.WriteString(DimText.Render(strings.Repeat("─", max(10, boxWidth-6))))
	sb.WriteString("\n\n")

	// Field 0: Projects Directory
	pPrefix := "  "
	pStyle := DimText
	pVal := m.projectsDir
	if pVal == "" {
		pVal = "Projects"
	}
	if m.focus == setupFieldProjectsDir {
		pPrefix = AccentText.Render("▶ ")
		pStyle = HighlightRow
		if m.editing && m.cursorVisible {
			pVal += AccentText.Render("█")
		}
	}
	sb.WriteString(fmt.Sprintf("%s%-20s %s\n", pPrefix, DimText.Render("Projects Directory:"), pStyle.Render(pVal)))
	sb.WriteString(HelpText.Render("   └─ .akemi files will be stored in: Projects/<target>/<target>.akemi"))
	sb.WriteString("\n\n")

	// Field 1: LLM Provider
	lPrefix := "  "
	if m.focus == setupFieldProvider {
		lPrefix = AccentText.Render("▶ ")
	}
	var provParts []string
	for i, opt := range setupProviderOptions {
		if i == m.providerIdx {
			provParts = append(provParts, HighlightRow.Render(fmt.Sprintf("[%s]", opt)))
		} else {
			provParts = append(provParts, DimText.Render(opt))
		}
	}
	sb.WriteString(fmt.Sprintf("%s%-20s %s\n\n", lPrefix, DimText.Render("LLM Provider:"), strings.Join(provParts, " ")))

	// Field 2: API Key
	kPrefix := "  "
	kStyle := DimText
	kVal := m.apiKey
	if kVal == "" {
		kVal = "(optional; enter LLM API key)"
	} else {
		kVal = strings.Repeat("*", len(m.apiKey))
	}
	if m.focus == setupFieldAPIKey {
		kPrefix = AccentText.Render("▶ ")
		kStyle = HighlightRow
		if m.editing && m.cursorVisible {
			kVal = m.apiKey + AccentText.Render("█")
		}
	}
	sb.WriteString(fmt.Sprintf("%s%-20s %s\n\n", kPrefix, DimText.Render("API Key:"), kStyle.Render(kVal)))

	// Field 3: Log Level
	vPrefix := "  "
	if m.focus == setupFieldLogLevel {
		vPrefix = AccentText.Render("▶ ")
	}
	var logParts []string
	for i, opt := range setupLogLevelOptions {
		if i == m.logLevelIdx {
			logParts = append(logParts, HighlightRow.Render(fmt.Sprintf("[%s]", opt)))
		} else {
			logParts = append(logParts, DimText.Render(opt))
		}
	}
	sb.WriteString(fmt.Sprintf("%s%-20s %s\n\n", vPrefix, DimText.Render("Log Level:"), strings.Join(logParts, " ")))

	sb.WriteString(DimText.Render(strings.Repeat("─", max(10, boxWidth-6))))
	sb.WriteString("\n\n")

	// Actions
	sStyle := DimText
	if m.focus == setupActionSave {
		sStyle = SuccessText
	}
	qStyle := DimText
	if m.focus == setupActionSkip {
		qStyle = HighlightRow
	}
	sb.WriteString(fmt.Sprintf("  %s    %s\n\n", sStyle.Render(" [ Complete Setup ] "), qStyle.Render(" [ Use Defaults ] ")))

	sb.WriteString(HelpText.Render(m.status))

	return borderStyle.Render(sb.String())
}
