package dashboard

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	apiFieldProvider = iota
	apiFieldModel
	apiFieldBaseURL
	apiFieldAPIKey
	apiFieldMaxTokens
	apiFieldTemperature
	apiFieldReasoning
	apiFieldThinking
	apiActionTest
	apiActionApply
	apiActionCancel
	apiFieldCount
)

type apiSettingsModal struct {
	visible bool
	focus   int
	busy    bool
	status  string

	settings        APISettings
	selectedField   int
	selectedDirty   bool
	maxTokensText   string
	temperatureText string

	LoadRequested  bool
	TestRequested  bool
	ApplyRequested bool
}

func newAPISettingsModal() *apiSettingsModal {
	m := &apiSettingsModal{
		settings:      defaultAPISettings("deepseek"),
		selectedField: -1,
		status:        "Loading API settings...",
	}
	m.syncNumericText()
	return m
}

func (m *apiSettingsModal) open() {
	m.visible = true
	m.focus = apiFieldProvider
	m.selectedField = -1
	m.selectedDirty = false
	m.busy = true
	m.status = "Loading API settings..."
	m.LoadRequested = true
}

func (m *apiSettingsModal) close() {
	m.visible = false
	m.busy = false
	m.status = ""
	m.selectedField = -1
	m.selectedDirty = false
	m.LoadRequested = false
	m.TestRequested = false
	m.ApplyRequested = false
}

func (m *apiSettingsModal) applyLoaded(settings APISettings, err string) {
	m.busy = false
	if strings.TrimSpace(err) != "" {
		m.status = err
		if strings.TrimSpace(m.settings.Provider) == "" {
			m.settings = defaultAPISettings("deepseek")
		}
		return
	}
	if strings.TrimSpace(settings.Provider) == "" {
		settings = defaultAPISettings("deepseek")
	}
	m.settings = normalizeAPISettings(settings)
	m.syncNumericText()
	m.selectedField = -1
	m.selectedDirty = false
	m.status = "DeepSeek is recommended. Apply saves these settings to akemi.conf."
}

func (m *apiSettingsModal) setStatus(status string) {
	m.busy = false
	m.status = strings.TrimSpace(status)
}

func (m *apiSettingsModal) handleKey(msg tea.KeyMsg) {
	if !m.visible {
		return
	}
	switch msg.String() {
	case "esc":
		m.close()
	case "tab", "down":
		m.moveFocus(1)
	case "shift+tab", "up":
		m.moveFocus(-1)
	case "right":
		m.moveHorizontal(1)
	case "left":
		m.moveHorizontal(-1)
	case "ctrl+t":
		if !m.busy {
			m.TestRequested = true
			m.busy = true
			m.status = "Testing provider..."
		}
	case "ctrl+s":
		if !m.busy {
			m.ApplyRequested = true
			m.busy = true
			m.status = "Applying provider settings..."
		}
	case "ctrl+u":
		if !m.busy {
			m.clearFocused()
		}
	case "enter":
		m.activateFocused()
	case "backspace", "ctrl+h":
		m.backspaceFocused()
	default:
		if !m.busy && msg.Type == tea.KeyRunes {
			for _, r := range msg.Runes {
				m.appendFocused(string(r))
			}
		}
	}
}

func (m *apiSettingsModal) moveFocus(delta int) {
	m.focus = (m.focus + delta + apiFieldCount) % apiFieldCount
	m.selectedField = -1
	m.selectedDirty = false
}

func (m *apiSettingsModal) moveHorizontal(delta int) {
	if m.busy {
		return
	}
	switch m.focus {
	case apiFieldProvider:
		m.cycleProvider()
	case apiFieldReasoning:
		m.cycleReasoning(delta)
	case apiFieldThinking:
		m.cycleThinking()
	case apiActionTest, apiActionApply, apiActionCancel:
		m.moveActionFocus(delta)
	}
	m.settings = normalizeAPISettings(m.settings)
}

func (m *apiSettingsModal) moveActionFocus(delta int) {
	actions := []int{apiActionTest, apiActionApply, apiActionCancel}
	idx := 0
	for i, action := range actions {
		if m.focus == action {
			idx = i
			break
		}
	}
	m.focus = actions[(idx+delta+len(actions))%len(actions)]
	m.selectedField = -1
	m.selectedDirty = false
}

func (m *apiSettingsModal) activateFocused() {
	if m.busy {
		return
	}
	switch m.focus {
	case apiFieldProvider:
		m.cycleProvider()
	case apiFieldReasoning:
		m.cycleReasoning(1)
	case apiFieldThinking:
		m.cycleThinking()
	case apiActionTest:
		m.TestRequested = true
		m.busy = true
		m.status = "Testing provider..."
	case apiActionApply:
		m.ApplyRequested = true
		m.busy = true
		m.status = "Applying provider settings..."
	case apiActionCancel:
		m.close()
	default:
		if isEditableAPIField(m.focus) {
			m.selectedField = m.focus
			m.selectedDirty = false
		}
	}
	m.settings = normalizeAPISettings(m.settings)
}

func (m *apiSettingsModal) cycleProvider() {
	if m.settings.Provider == "openai" {
		m.settings = mergeAPISettings(m.settings, defaultAPISettings("deepseek"))
	} else {
		m.settings = mergeAPISettings(m.settings, defaultAPISettings("openai"))
	}
	m.syncNumericText()
}

func (m *apiSettingsModal) cycleReasoning(delta int) {
	current := normalizeReasoningEffort(m.settings.ReasoningEffort)
	if delta < 0 {
		if current == "high" {
			m.settings.ReasoningEffort = "max"
		} else {
			m.settings.ReasoningEffort = "high"
		}
		return
	}
	if current == "max" {
		m.settings.ReasoningEffort = "high"
	} else {
		m.settings.ReasoningEffort = "max"
	}
}

func (m *apiSettingsModal) cycleThinking() {
	m.settings.Thinking = !m.settings.Thinking
}

func (m *apiSettingsModal) appendFocused(value string) {
	if !m.canEditFocused() {
		return
	}
	switch m.focus {
	case apiFieldModel:
		m.prepareFocusedEdit()
		m.settings.Model += value
	case apiFieldBaseURL:
		m.prepareFocusedEdit()
		m.settings.BaseURL += value
	case apiFieldAPIKey:
		m.prepareFocusedEdit()
		m.settings.APIKey += value
	case apiFieldMaxTokens:
		if value[0] >= '0' && value[0] <= '9' {
			m.prepareFocusedEdit()
			m.maxTokensText += value
		}
	case apiFieldTemperature:
		if !((value[0] >= '0' && value[0] <= '9') || value == ".") {
			return
		}
		if value == "." && m.selectedDirty && strings.Contains(m.temperatureText, ".") {
			return
		}
		m.prepareFocusedEdit()
		m.temperatureText += value
	}
}

func (m *apiSettingsModal) backspaceFocused() {
	if !m.canEditFocused() {
		return
	}
	if !m.selectedDirty {
		m.clearFocusedValue()
		m.selectedDirty = true
		return
	}
	switch m.focus {
	case apiFieldModel:
		m.settings.Model = dropLast(m.settings.Model)
	case apiFieldBaseURL:
		m.settings.BaseURL = dropLast(m.settings.BaseURL)
	case apiFieldAPIKey:
		m.settings.APIKey = dropLast(m.settings.APIKey)
	case apiFieldMaxTokens:
		m.maxTokensText = dropLast(m.maxTokensText)
	case apiFieldTemperature:
		m.temperatureText = dropLast(m.temperatureText)
	}
}

func (m *apiSettingsModal) clearFocused() {
	if !m.canEditFocused() {
		return
	}
	m.clearFocusedValue()
	m.selectedDirty = true
}

func (m *apiSettingsModal) canEditFocused() bool {
	return isEditableAPIField(m.focus) && m.selectedField == m.focus
}

func (m *apiSettingsModal) prepareFocusedEdit() {
	if m.selectedDirty {
		return
	}
	m.clearFocusedValue()
	m.selectedDirty = true
}

func (m *apiSettingsModal) clearFocusedValue() {
	switch m.focus {
	case apiFieldModel:
		m.settings.Model = ""
	case apiFieldBaseURL:
		m.settings.BaseURL = ""
	case apiFieldAPIKey:
		m.settings.APIKey = ""
	case apiFieldMaxTokens:
		m.maxTokensText = ""
	case apiFieldTemperature:
		m.temperatureText = ""
	}
}

func (m *apiSettingsModal) view(width, height int) string {
	if !m.visible {
		return ""
	}
	w := min(max(72, width-10), 92)
	if width > 0 && w > width-4 {
		w = width - 4
	}
	if w < 48 {
		w = 48
	}
	rows := []string{
		PanelTitleFocused.Render("API Settings"),
		DimText.Render("DeepSeek first, OpenAI second. Apply saves API settings to akemi.conf."),
		"",
		m.row(apiFieldProvider, "Provider", optionLabel(m.settings.Provider == "deepseek", "deepseek", "openai")),
		m.row(apiFieldModel, "Model", m.settings.Model),
		m.row(apiFieldBaseURL, "Base URL", m.settings.BaseURL),
		m.row(apiFieldAPIKey, "API Key", m.apiKeyDisplay()),
		m.row(apiFieldMaxTokens, "Max Tokens", m.maxTokensText),
		m.row(apiFieldTemperature, "Temperature", m.temperatureText),
		m.row(apiFieldReasoning, "Reasoning", optionLabel(m.reasoningValue() == "high", "high", "max")),
		m.row(apiFieldThinking, "Thinking", optionLabel(!m.settings.Thinking, "off", "on")),
		"",
		m.actionRow(),
		"",
		m.statusLine(),
		HelpText.Render("Tab fields | Enter selects text fields | Left/Right options/actions"),
		HelpText.Render("Typing edits only selected fields | Ctrl+U clear selected field"),
		HelpText.Render("Ctrl+T test | Ctrl+S apply | Esc cancel"),
	}
	body := strings.Join(rows, "\n")
	box := lipgloss.NewStyle().
		Width(w).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(PurpleLight).
		Padding(1, 2).
		Render(body)
	if width <= 0 || height <= 0 {
		return box
	}
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

func (m *apiSettingsModal) row(field int, label, value string) string {
	if value == "" && isEditableAPIField(field) {
		value = DimText.Render("<empty>")
	}
	if m.focus == field && m.selectedField == field && isEditableAPIField(field) {
		value += DimText.Render("  selected")
	}
	line := fmt.Sprintf("%-13s %s", label, value)
	if m.focus == field {
		return HighlightRow.Render(line)
	}
	return line
}

func (m *apiSettingsModal) apiKeyDisplay() string {
	if m.canEditFocused() {
		return m.settings.APIKey
	}
	return strings.Repeat("*", len(m.settings.APIKey))
}

func (m *apiSettingsModal) actionRow() string {
	actions := []struct {
		field int
		text  string
	}{
		{apiActionTest, "[ Test ]"},
		{apiActionApply, "[ Apply ]"},
		{apiActionCancel, "[ Cancel ]"},
	}
	parts := make([]string, 0, len(actions))
	for _, action := range actions {
		if m.focus == action.field {
			parts = append(parts, HighlightRow.Render(action.text))
		} else {
			parts = append(parts, AccentText.Render(action.text))
		}
	}
	return strings.Join(parts, "  ")
}

func (m *apiSettingsModal) statusLine() string {
	if strings.TrimSpace(m.status) == "" {
		return ""
	}
	if strings.Contains(strings.ToLower(m.status), "error") || strings.Contains(strings.ToLower(m.status), "failed") {
		return ErrorText.Render(m.status)
	}
	if strings.Contains(strings.ToLower(m.status), "saved") || strings.Contains(strings.ToLower(m.status), "ok") || strings.Contains(strings.ToLower(m.status), "connected") {
		return SuccessText.Render(m.status)
	}
	return WarnText.Render(m.status)
}

func (m *apiSettingsModal) reasoningValue() string {
	return normalizeReasoningEffort(m.settings.ReasoningEffort)
}

func defaultAPISettings(provider string) APISettings {
	switch provider {
	case "openai":
		return APISettings{
			Provider:        "openai",
			Model:           "gpt-4o-mini",
			BaseURL:         "https://api.openai.com/v1",
			MaxTokens:       4096,
			Temperature:     0.3,
			ReasoningEffort: "high",
		}
	default:
		return APISettings{
			Provider:        "deepseek",
			Model:           "deepseek-v4-pro",
			BaseURL:         "https://api.deepseek.com",
			MaxTokens:       4096,
			Temperature:     0.3,
			ReasoningEffort: "high",
		}
	}
}

func normalizeAPISettings(settings APISettings) APISettings {
	provider := strings.ToLower(strings.TrimSpace(settings.Provider))
	if provider != "openai" {
		provider = "deepseek"
	}
	def := defaultAPISettings(provider)
	settings.Provider = provider
	if strings.TrimSpace(settings.Model) == "" {
		settings.Model = def.Model
	}
	if strings.TrimSpace(settings.BaseURL) == "" {
		settings.BaseURL = def.BaseURL
	}
	if settings.MaxTokens <= 0 {
		settings.MaxTokens = def.MaxTokens
	}
	if settings.Temperature < 0 {
		settings.Temperature = def.Temperature
	}
	settings.ReasoningEffort = normalizeReasoningEffort(settings.ReasoningEffort)
	return settings
}

func normalizeReasoningEffort(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "max", "maximum":
		return "max"
	case "high":
		return "high"
	default:
		return "high"
	}
}

func mergeAPISettings(old, next APISettings) APISettings {
	next.APIKey = old.APIKey
	return next
}

func (m *apiSettingsModal) syncNumericText() {
	m.maxTokensText = strconv.Itoa(m.settings.MaxTokens)
	m.temperatureText = strconv.FormatFloat(m.settings.Temperature, 'f', -1, 64)
}

func (m *apiSettingsModal) currentSettings() APISettings {
	settings := m.settings
	settings.MaxTokens = parseInt(m.maxTokensText, settings.MaxTokens)
	settings.Temperature = parseFloat(m.temperatureText, settings.Temperature)
	return normalizeAPISettings(settings)
}

func isEditableAPIField(field int) bool {
	switch field {
	case apiFieldModel, apiFieldBaseURL, apiFieldAPIKey, apiFieldMaxTokens, apiFieldTemperature:
		return true
	default:
		return false
	}
}

func optionLabel(firstSelected bool, first, second string) string {
	if firstSelected {
		return fmt.Sprintf("[%s] / %s", first, second)
	}
	return fmt.Sprintf("%s / [%s]", first, second)
}

func parseInt(value string, fallback int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func parseFloat(value string, fallback float64) float64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func dropLast(value string) string {
	if value == "" {
		return ""
	}
	runes := []rune(value)
	return string(runes[:len(runes)-1])
}
