package dashboard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"Akemi/internal/project"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Project Selector Model ────────────────────────────────────────────
//
// This is a lightweight Bubble Tea model shown at startup when the user runs
// `akemi` without --project, --no-project, or any scan flags. It offers three
// paths: create a new project, open an existing one, or proceed in single-
// session mode.

type selectorState int

const (
	selMain     selectorState = iota // top-level: pick a path
	selCreate                        // creating: enter name + directory
	selOpen                          // opening: pick from list or browse
	selDone                          // finished: return result
)

// ProjectSelectResult is returned to the caller when the selector exits.
type ProjectSelectResult struct {
	Project       *project.Project // nil for single-session
	SingleSession bool
	Cancelled     bool
}

type projectSelectorModel struct {
	width  int
	height int
	state  selectorState

	// Main menu
	cursor   int
	mainOpts []string

	// Create form
	createName string
	createDir  string
	createStep int // 0 = name, 1 = directory
	createErr  string

	// Open list
	registry    *project.Registry
	registryErr string
	openCursor  int
	openOpts    []string              // registry entry display strings
	openEntries []project.RegistryEntry
	openBrowse  bool
	browsePath  string

	// Result
	result ProjectSelectResult

	// State for async operations
	busy   bool
	status string
}

// NewProjectSelector creates the startup project-selection model.
func NewProjectSelector() *projectSelectorModel {
	reg, _ := project.LoadRegistry()

	m := &projectSelectorModel{
		state: selMain,
		mainOpts: []string{
			"Create New Project",
			"Open Existing Project",
			"Single Session (no project)",
		},
		registry: reg,
	}

	if reg != nil {
		entries := reg.Entries()
		m.openEntries = entries
		m.openOpts = make([]string, 0, len(entries)+1)
		for _, entry := range entries {
			age := time.Since(entry.LastOpened).Truncate(time.Minute)
			label := fmt.Sprintf("%s  (%s ago)", entry.Name, age)
			m.openOpts = append(m.openOpts, label)
		}
		m.openOpts = append(m.openOpts, "Browse for project directory...")
	}

	// Default create directory.
	home, _ := os.UserHomeDir()
	if home != "" {
		m.createDir = filepath.Join(home, "akemi-projects")
	}

	return m
}

func (m *projectSelectorModel) Init() tea.Cmd {
	return nil
}

func (m *projectSelectorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		if m.busy {
			// Check for async completion messages
			return m, nil
		}

		switch m.state {
		case selMain:
			return m.handleMainKey(msg)
		case selCreate:
			return m.handleCreateKey(msg)
		case selOpen:
			return m.handleOpenKey(msg)
		case selDone:
			return m, tea.Quit
		}

	case projectCreateMsg:
		m.busy = false
		if msg.err != nil {
			m.createErr = msg.err.Error()
			m.status = ""
		} else {
			m.result = ProjectSelectResult{Project: msg.proj}
			m.state = selDone
			return m, tea.Quit
		}

	case projectOpenMsg:
		m.busy = false
		if msg.err != nil {
			m.registryErr = msg.err.Error()
			m.status = ""
		} else {
			m.result = ProjectSelectResult{Project: msg.proj}
			m.state = selDone
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m *projectSelectorModel) handleMainKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.mainOpts)-1 {
			m.cursor++
		}
	case "enter", " ":
		return m.selectMainOption()
	case "ctrl+c", "esc":
		m.result = ProjectSelectResult{Cancelled: true}
		m.state = selDone
		return m, tea.Quit
	case "1":
		m.cursor = 0
		return m.selectMainOption()
	case "2":
		m.cursor = 1
		return m.selectMainOption()
	case "3":
		m.cursor = 2
		return m.selectMainOption()
	}
	return m, nil
}

func (m *projectSelectorModel) selectMainOption() (tea.Model, tea.Cmd) {
	switch m.cursor {
	case 0:
		m.state = selCreate
		m.createName = ""
		m.createStep = 0
		m.createErr = ""
	case 1:
		m.state = selOpen
		m.openCursor = 0
		m.openBrowse = false
		m.browsePath = ""
		m.registryErr = ""
	case 2:
		m.result = ProjectSelectResult{SingleSession: true}
		m.state = selDone
		return m, tea.Quit
	}
	return m, nil
}

func (m *projectSelectorModel) handleCreateKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.state = selMain
		m.createErr = ""
		return m, nil
	case "tab":
		m.createStep = (m.createStep + 1) % 2
	case "enter":
		if m.createStep == 0 {
			if strings.TrimSpace(m.createName) == "" {
				m.createErr = "Project name cannot be empty"
				return m, nil
			}
			m.createStep = 1
			m.createErr = ""
		} else {
			if strings.TrimSpace(m.createDir) == "" {
				m.createErr = "Directory cannot be empty"
				return m, nil
			}
			m.busy = true
			m.status = "Creating project..."
			return m, m.createProjectCmd()
		}
	case "backspace":
		if m.createStep == 0 {
			if len(m.createName) > 0 {
				m.createName = m.createName[:len(m.createName)-1]
			}
		} else {
			if len(m.createDir) > 0 {
				m.createDir = m.createDir[:len(m.createDir)-1]
			}
		}
		m.createErr = ""
	default:
		if len(msg.String()) == 1 {
			ch := msg.String()[0]
			if ch >= 32 && ch < 127 {
				if m.createStep == 0 {
					m.createName += msg.String()
				} else {
					m.createDir += msg.String()
				}
				m.createErr = ""
			}
		}
	}
	return m, nil
}

func (m *projectSelectorModel) handleOpenKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.openBrowse {
		return m.handleBrowseKey(msg)
	}

	switch msg.String() {
	case "up", "k":
		if m.openCursor > 0 {
			m.openCursor--
		}
	case "down", "j":
		if m.openCursor < len(m.openOpts)-1 {
			m.openCursor++
		}
	case "esc":
		m.state = selMain
		m.registryErr = ""
		return m, nil
	case "enter", " ":
		if len(m.openOpts) == 0 || m.openCursor >= len(m.openOpts)-1 {
			m.openBrowse = true
			m.browsePath = ""
		} else if m.openCursor < len(m.openEntries) {
			entry := m.openEntries[m.openCursor]
			m.busy = true
			m.status = "Opening project..."
			return m, m.openProjectCmd(entry.Root)
		}
	}
	return m, nil
}

func (m *projectSelectorModel) handleBrowseKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.openBrowse = false
		m.browsePath = ""
		m.registryErr = ""
		return m, nil
	case "enter":
		if strings.TrimSpace(m.browsePath) == "" {
			m.registryErr = "Path cannot be empty"
			return m, nil
		}
		m.busy = true
		m.status = "Opening project..."
		return m, m.openProjectCmd(m.browsePath)
	case "backspace":
		if len(m.browsePath) > 0 {
			m.browsePath = m.browsePath[:len(m.browsePath)-1]
		}
		m.registryErr = ""
	default:
		if len(msg.String()) == 1 {
			ch := msg.String()[0]
			if ch >= 32 && ch < 127 {
				m.browsePath += msg.String()
				m.registryErr = ""
			}
		}
	}
	return m, nil
}

func (m *projectSelectorModel) createProjectCmd() tea.Cmd {
	return func() tea.Msg {
		proj, err := project.CreateProject(m.createDir, m.createName)
		return projectCreateMsg{proj: proj, err: err}
	}
}

func (m *projectSelectorModel) openProjectCmd(root string) tea.Cmd {
	return func() tea.Msg {
		proj, err := project.OpenProject(root)
		return projectOpenMsg{proj: proj, err: err}
	}
}

type projectCreateMsg struct {
	proj *project.Project
	err  error
}

type projectOpenMsg struct {
	proj *project.Project
	err  error
}

// ── Views ─────────────────────────────────────────────────────────────

var (
	selectorTitleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	selectorHelpStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	selectorDimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	selectorAccentStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	selectorErrStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	selectorOKStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	selectorCursorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("5"))
	selectorInputStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("7"))
	selectorBusyStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
)

func (m *projectSelectorModel) View() string {
	if m.width < 40 {
		m.width = 40
	}

	switch m.state {
	case selMain:
		return m.viewMain()
	case selCreate:
		return m.viewCreate()
	case selOpen:
		return m.viewOpen()
	case selDone:
		return m.viewDone()
	default:
		return ""
	}
}

func (m *projectSelectorModel) viewMain() string {
	var sb strings.Builder

	sb.WriteString(selectorTitleStyle.Render("  Akemi — Attack Surface Management Framework"))
	sb.WriteString("\n\n")
	sb.WriteString("  Choose how to start:\n\n")

	for i, opt := range m.mainOpts {
		cursor := "  "
		if m.cursor == i {
			cursor = selectorCursorStyle.Render("▶ ")
		}
		line := cursor + opt
		if m.cursor == i {
			line = selectorAccentStyle.Render(line)
		}
		sb.WriteString(line + "\n")
	}

	sb.WriteString("\n")
	sb.WriteString(selectorHelpStyle.Render("  /  navigate    enter select    1/2/3 quick-select    esc quit"))
	sb.WriteString("\n")

	return centerBlock(sb.String(), m.width, m.height)
}

func (m *projectSelectorModel) viewCreate() string {
	var sb strings.Builder

	sb.WriteString(selectorTitleStyle.Render("  Create New Project"))
	sb.WriteString("\n\n")

	// Name field
	nameLabel := "  Project name: "
	if m.createStep == 0 {
		nameLabel = selectorCursorStyle.Render("▶ ") + "Project name: "
	}
	displayName := m.createName
	if displayName == "" {
		displayName = selectorDimStyle.Render("<e.g. ACME Corp External>")
	}
	sb.WriteString(nameLabel + selectorInputStyle.Render(displayName))
	sb.WriteString("\n\n")

	// Directory field
	dirLabel := "  Directory:     "
	if m.createStep == 1 {
		dirLabel = selectorCursorStyle.Render("▶ ") + "Directory:     "
	}
	displayDir := m.createDir
	if displayDir == "" {
		displayDir = selectorDimStyle.Render("<e.g. ~/engagements/acme-ext>")
	}
	sb.WriteString(dirLabel + selectorInputStyle.Render(displayDir))
	sb.WriteString("\n\n")

	if m.createErr != "" {
		sb.WriteString(selectorErrStyle.Render("   " + m.createErr))
		sb.WriteString("\n\n")
	}

	if m.busy {
		sb.WriteString(selectorBusyStyle.Render("  " + m.status))
	} else {
		sb.WriteString(selectorHelpStyle.Render("  tab switch field    enter confirm    esc back"))
	}
	sb.WriteString("\n")

	return centerBlock(sb.String(), m.width, m.height)
}

func (m *projectSelectorModel) viewOpen() string {
	if m.openBrowse {
		return m.viewBrowse()
	}

	var sb strings.Builder
	sb.WriteString(selectorTitleStyle.Render("  Open Existing Project"))
	sb.WriteString("\n\n")

	if len(m.openOpts) == 0 {
		sb.WriteString(selectorDimStyle.Render("  No recent projects found."))
		sb.WriteString("\n\n")
		sb.WriteString("  Press Enter to browse for a project directory.\n")
	} else {
		sb.WriteString("  Recent projects:\n\n")
		for i, opt := range m.openOpts {
			prefix := "    "
			if m.openCursor == i {
				prefix = selectorCursorStyle.Render("  ▶ ")
			}
			line := prefix + opt
			if m.openCursor == i {
				line = selectorAccentStyle.Render(line)
			}
			sb.WriteString(line + "\n")
		}
	}

	sb.WriteString("\n")
	if m.registryErr != "" {
		sb.WriteString(selectorErrStyle.Render("   " + m.registryErr))
		sb.WriteString("\n\n")
	}

	if m.busy {
		sb.WriteString(selectorBusyStyle.Render("  " + m.status))
	} else {
		sb.WriteString(selectorHelpStyle.Render("  /  navigate    enter select    esc back"))
	}
	sb.WriteString("\n")

	return centerBlock(sb.String(), m.width, m.height)
}

func (m *projectSelectorModel) viewBrowse() string {
	var sb strings.Builder
	sb.WriteString(selectorTitleStyle.Render("  Browse for Project"))
	sb.WriteString("\n\n")

	sb.WriteString("  Enter the path to an Akemi project directory\n")
	sb.WriteString("  (the folder containing akemi.project.toml):\n\n")

	displayPath := m.browsePath
	if displayPath == "" {
		displayPath = selectorDimStyle.Render("<e.g. ~/engagements/acme-ext>")
	}
	sb.WriteString("  " + selectorCursorStyle.Render("▶ ") + selectorInputStyle.Render(displayPath))
	sb.WriteString("\n\n")

	if m.registryErr != "" {
		sb.WriteString(selectorErrStyle.Render("   " + m.registryErr))
		sb.WriteString("\n\n")
	}

	if m.busy {
		sb.WriteString(selectorBusyStyle.Render("  " + m.status))
	} else {
		sb.WriteString(selectorHelpStyle.Render("  enter confirm    esc back"))
	}
	sb.WriteString("\n")

	return centerBlock(sb.String(), m.width, m.height)
}

func (m *projectSelectorModel) viewDone() string {
	var sb strings.Builder

	if m.result.Cancelled {
		sb.WriteString(selectorDimStyle.Render("Exiting Akemi. Goodbye!"))
		return centerBlock(sb.String(), m.width, m.height)
	}

	if m.result.SingleSession {
		sb.WriteString(selectorOKStyle.Render("Starting in single-session mode..."))
		sb.WriteString("\n")
		sb.WriteString(selectorDimStyle.Render("No project loaded. Output goes to current directory."))
		return centerBlock(sb.String(), m.width, m.height)
	}

	if m.result.Project != nil {
		sb.WriteString(selectorOKStyle.Render("Project loaded: " + m.result.Project.DisplayName()))
		sb.WriteString("\n")
		sb.WriteString(selectorDimStyle.Render(m.result.Project.Root))
		return centerBlock(sb.String(), m.width, m.height)
	}

	sb.WriteString(selectorErrStyle.Render("Failed to load project."))
	return centerBlock(sb.String(), m.width, m.height)
}

func centerBlock(content string, width, height int) string {
	lines := strings.Split(content, "\n")

	topPad := (height - len(lines)) / 2
	if topPad < 0 {
		topPad = 0
	}

	var sb strings.Builder
	for i := 0; i < topPad; i++ {
		sb.WriteString("\n")
	}

	for _, line := range lines {
		lineWidth := lipgloss.Width(line)
		leftPad := (width - lineWidth) / 2
		if leftPad < 0 {
			leftPad = 0
		}
		sb.WriteString(strings.Repeat(" ", leftPad))
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	return sb.String()
}

// ── Public API ────────────────────────────────────────────────────────

// RunProjectSelector displays the project selection screen and returns the
// user's choice. Returns nil project + SingleSession=true for single-session
// mode, or Cancelled=true if the user quit.
func RunProjectSelector() ProjectSelectResult {
	model := NewProjectSelector()
	program := tea.NewProgram(
		model,
		tea.WithAltScreen(),
	)
	final, err := program.Run()
	if err != nil {
		return ProjectSelectResult{SingleSession: true}
	}
	m, ok := final.(*projectSelectorModel)
	if !ok {
		return ProjectSelectResult{SingleSession: true}
	}
	return m.result
}
