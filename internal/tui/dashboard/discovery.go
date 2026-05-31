package dashboard

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// =============================================================================
// DiscoveryPanel shows tabbed discovery sections.
// =============================================================================

// DiscoverySection represents a category of discovered items.
type DiscoverySection struct {
	Name     string
	Icon     string
	Count    int
	Items    []string // latest items for preview
	Keys     map[string]struct{}
	KeyIndex map[string]int
}

// DiscoveryPanel shows real-time discovery results.
type DiscoveryPanel struct {
	focused   bool
	width     int
	height    int
	sections  []*DiscoverySection
	activeTab int
	viewport  viewport.Model
	scrollY   int

	// Filter state
	filterMode    bool
	filterInput   string
	filteredItems []string // cached filtered view of current section

	// Detail popover state
	detailMode    bool
	detailItem    string
	detailSection string

	// Tracking summary
	totalSubdomains int
	totalPorts      int
	totalURLs       int
	totalEndpoints  int
	totalSecrets    int
	totalParams     int
	totalJSFiles    int
	totalFindings   int
	phase           string

	CopyRequested   bool
	PendingCopyText string
}

// NewDiscoveryPanel creates a new discovery panel.
func NewDiscoveryPanel() *DiscoveryPanel {
	dp := &DiscoveryPanel{
		activeTab: 0,
		sections: []*DiscoverySection{
			{Name: "Subdomains", Icon: "SUB", Count: 0, Items: make([]string, 0)},
			{Name: "Ports", Icon: "PRT", Count: 0, Items: make([]string, 0)},
			{Name: "URLs", Icon: "URL", Count: 0, Items: make([]string, 0)},
			{Name: "Endpoints", Icon: "API", Count: 0, Items: make([]string, 0)},
			{Name: "Secrets", Icon: "SEC", Count: 0, Items: make([]string, 0)},
			{Name: "Params", Icon: "PAR", Count: 0, Items: make([]string, 0)},
			{Name: "JS Files", Icon: "JS", Count: 0, Items: make([]string, 0)},
			{Name: "Findings", Icon: "FND", Count: 0, Items: make([]string, 0)},
		},
	}
	dp.viewport = viewport.New(40, 15)
	return dp
}

// SetSize updates the panel dimensions.
func (dp *DiscoveryPanel) SetSize(w, h int) {
	dp.width = w
	dp.height = h
	dp.viewport.Width = w - 6
	dp.viewport.Height = h - 8
	if dp.viewport.Width < 10 {
		dp.viewport.Width = 10
	}
	if dp.viewport.Height < 3 {
		dp.viewport.Height = 3
	}
	dp.updateViewport()
}

// Init implements tea.Model.
func (dp *DiscoveryPanel) Init() tea.Cmd {
	return nil
}

// Update handles messages.
func (dp *DiscoveryPanel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return dp.handleKey(msg)

	case tea.MouseMsg:
		return dp.handleMouse(msg)

	case ScanProgressMsg:
		// Only update the phase text (transient per-scan label).
		// Do NOT overwrite cumulative totals -- those are maintained
		// by AddItemWithKey and refreshTotalsFromSections, which
		// count across all scans, not just the current one.
		dp.phase = msg.Phase
		dp.updateViewport()
		return dp, nil

	case DiscoveryItemMsg:
		if strings.TrimSpace(msg.Phase) != "" {
			dp.phase = msg.Phase
		}
		// Auto-switch to a section when it receives its first item
		sectionIdx := dp.sectionIndex(msg.Section)
		wasEmpty := sectionIdx >= 0 && len(dp.sections[sectionIdx].Items) == 0
		if dp.AddItemWithKey(msg.Section, msg.Key, msg.Item) && wasEmpty {
			dp.activeTab = sectionIdx
			dp.scrollY = 0
			dp.filteredItems = nil
		}
		if dp.filterMode {
			dp.applyFilter()
		}
		dp.updateViewport()
		return dp, nil

	case ScanStartedMsg:
		dp.beginScan()
		return dp, nil

	case ScanDoneMsg:
		switch {
		case msg.Cancelled:
			dp.phase = "Stopped"
		case msg.Error != nil:
			dp.phase = "Error"
		default:
			dp.phase = "Complete"
		}
		// Populate from scan results
		if msg.Ports != nil {
			for _, p := range msg.Ports {
				dp.AddItemWithKey("Ports", fmt.Sprintf("%d", p.Port), formatPortResult(p))
			}
		}
		if msg.CrawlFindings != nil {
			for _, f := range msg.CrawlFindings {
				dp.AddItemWithKey("URLs", f.URL, formatCrawlFinding(f))
			}
		} else if msg.URLs != nil {
			for _, u := range msg.URLs {
				dp.AddItemWithKey("URLs", u, u)
			}
		}
		if msg.Subdomains != nil {
			for _, sub := range msg.Subdomains {
				dp.AddItemWithKey("Subdomains", sub, sub)
			}
		}
		if msg.APIEndpoints != nil {
			for _, endpoint := range msg.APIEndpoints {
				key, item := formatAPIEndpoint(endpoint)
				dp.AddItemWithKey("Endpoints", key, item)
			}
		}
		if msg.APISpecs != nil {
			for _, spec := range msg.APISpecs {
				key, item := formatAPISpec(spec)
				dp.AddItemWithKey("Endpoints", key, item)
			}
		}
		if msg.APIParameters != nil {
			for _, param := range msg.APIParameters {
				key, item := formatAPIParameter(param)
				dp.AddItemWithKey("Params", key, item)
			}
		}
		if msg.Findings != nil {
			for _, f := range msg.Findings {
				item := discoveryItemForFinding(f)
				dp.AddItemWithKey(item.Section, item.Key, item.Item)
			}
		}
		dp.refreshTotalsFromSections()
		if dp.filterMode {
			dp.applyFilter()
		}
		dp.updateViewport()
		return dp, nil
	}

	return dp, nil
}

func (dp *DiscoveryPanel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// ── Filter mode: typing, backspace, esc ──
	if dp.filterMode {
		switch key {
		case "esc":
			dp.filterMode = false
			dp.filterInput = ""
			dp.filteredItems = nil
			dp.scrollY = 0
			dp.updateViewport()
			return dp, nil
		case "backspace":
			if len(dp.filterInput) > 0 {
				dp.filterInput = dp.filterInput[:len(dp.filterInput)-1]
				dp.scrollY = 0
				dp.applyFilter()
				dp.updateViewport()
			}
			return dp, nil
		case "left", "h":
			if dp.activeTab > 0 {
				dp.activeTab--
				dp.scrollY = 0
				dp.applyFilter()
				dp.updateViewport()
			}
			return dp, nil
		case "right", "l":
			if dp.activeTab < len(dp.sections)-1 {
				dp.activeTab++
				dp.scrollY = 0
				dp.applyFilter()
				dp.updateViewport()
			}
			return dp, nil
		case "up", "k":
			if dp.scrollY > 0 {
				dp.scrollY--
				dp.updateViewport()
			}
			return dp, nil
		case "down", "j":
			items := dp.currentItems()
			if dp.scrollY < len(items)-1 {
				dp.scrollY++
				dp.updateViewport()
			}
			return dp, nil
		case "enter":
			// Enter in filter mode: ignore (keep filtering)
			return dp, nil
		case "tab":
			return dp, nil
		default:
			// Only accept printable single-character keys
			if len(key) == 1 && key[0] >= 32 && key[0] < 127 {
				dp.filterInput += key
				dp.scrollY = 0
				dp.applyFilter()
				dp.updateViewport()
			}
			return dp, nil
		}
	}

	// ── Normal mode ──
	switch key {
	case "/":
		// Enter filter mode (close detail if open)
		dp.filterMode = true
		dp.filterInput = ""
		dp.filteredItems = nil
		dp.detailMode = false
		dp.scrollY = 0
		dp.updateViewport()
	case "enter":
		items := dp.currentItems()
		if dp.detailMode {
			dp.CopyRequested = true
			dp.PendingCopyText = dp.detailItem
		} else if dp.scrollY < len(items) && len(items) > 0 {
			dp.detailMode = true
			dp.detailItem = items[dp.scrollY]
			dp.detailSection = dp.sections[dp.activeTab].Name
		}
		return dp, nil
	case "c", "y":
		if item := dp.SelectedText(); strings.TrimSpace(item) != "" {
			dp.CopyRequested = true
			dp.PendingCopyText = item
		}
		return dp, nil
	case "esc":
		// Close detail if open
		if dp.detailMode {
			dp.detailMode = false
			dp.detailItem = ""
			dp.detailSection = ""
			return dp, nil
		}
		return dp, nil
	case "left", "h":
		if dp.activeTab > 0 {
			dp.activeTab--
			dp.scrollY = 0
			dp.updateViewport()
		}
	case "right", "l":
		if dp.activeTab < len(dp.sections)-1 {
			dp.activeTab++
			dp.scrollY = 0
			dp.updateViewport()
		}
	case "up", "k":
		if dp.scrollY > 0 {
			dp.scrollY--
			dp.updateViewport()
		}
	case "down", "j":
		items := dp.currentItems()
		if dp.scrollY < len(items)-1 {
			dp.scrollY++
			dp.updateViewport()
		}
	case "tab":
		// Handled by parent
		return dp, nil
	}
	return dp, nil
}

func (dp *DiscoveryPanel) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	switch msg.Action {
	case tea.MouseActionPress:
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			if dp.scrollY > 0 {
				dp.scrollY--
				dp.updateViewport()
			}
		case tea.MouseButtonWheelDown:
			items := dp.currentItems()
			if dp.scrollY < len(items)-1 {
				dp.scrollY++
				dp.updateViewport()
			}
		case tea.MouseButtonLeft:
			// Calculate the Y offset for tab row (title=line0, filter=line1 if active, tabs=next line)
			tabY := 1
			if dp.filterMode {
				tabY = 2
			}
			if msg.Y == tabY {
				x := msg.X - 2
				tabWidth := (dp.width - 6) / len(dp.sections)
				if tabWidth < 1 {
					tabWidth = 1
				}
				clickedTab := x / tabWidth
				if clickedTab >= 0 && clickedTab < len(dp.sections) {
					dp.activeTab = clickedTab
					dp.scrollY = 0
					if dp.filterMode {
						dp.applyFilter()
					}
					dp.updateViewport()
				}
			}
		}
	}
	return dp, nil
}

func (dp *DiscoveryPanel) syncCounts() {
	dp.sections[0].Count = dp.totalSubdomains
	dp.sections[1].Count = dp.totalPorts
	dp.sections[2].Count = dp.totalURLs
	dp.sections[3].Count = dp.totalEndpoints
	dp.sections[4].Count = dp.totalSecrets
	dp.sections[5].Count = dp.totalParams
	dp.sections[6].Count = dp.totalJSFiles
	dp.sections[7].Count = dp.totalFindings
}

// currentItems returns the active item list (filtered or full).
func (dp *DiscoveryPanel) currentItems() []string {
	if dp.filterMode && dp.filteredItems != nil {
		return dp.filteredItems
	}
	return dp.sections[dp.activeTab].Items
}

// applyFilter rebuilds the filteredItems cache from the current section.
func (dp *DiscoveryPanel) applyFilter() {
	if !dp.filterMode || dp.filterInput == "" {
		dp.filteredItems = nil
		return
	}
	section := dp.sections[dp.activeTab]
	lower := strings.ToLower(dp.filterInput)
	filtered := make([]string, 0)
	for _, item := range section.Items {
		if strings.Contains(strings.ToLower(item), lower) {
			filtered = append(filtered, item)
		}
	}
	dp.filteredItems = filtered
}

// HighlightSubstring returns text with every occurrence of substring wrapped
// in the AccentText style. Matching is case-insensitive.
func HighlightSubstring(text, substring string) string {
	if substring == "" {
		return text
	}
	lower := strings.ToLower(text)
	subLower := strings.ToLower(substring)
	var result strings.Builder
	remaining := text
	remainingLower := lower
	for {
		idx := strings.Index(remainingLower, subLower)
		if idx == -1 {
			result.WriteString(remaining)
			break
		}
		// Write everything before the match as-is
		result.WriteString(remaining[:idx])
		// Write the matched portion with AccentText style
		match := remaining[idx : idx+len(substring)]
		result.WriteString(AccentText.Render(match))
		// Advance past the match
		remaining = remaining[idx+len(substring):]
		remainingLower = remainingLower[idx+len(substring):]
	}
	return result.String()
}

func (dp *DiscoveryPanel) updateViewport() {
	items := dp.currentItems()
	var sb strings.Builder
	for i, item := range items {
		if i < dp.scrollY {
			continue
		}
		if i > dp.scrollY+50 {
			break
		}
		prefix := "  "
		style := DimText
		displayText := fitCellWidth(item, max(10, dp.viewport.Width-4))
		if i == dp.scrollY {
			prefix = AccentText.Render("> ")
			style = AccentText
		}
		// Highlight matches when filtering
		if dp.filterMode && dp.filterInput != "" {
			displayText = HighlightSubstring(displayText, dp.filterInput)
		}
		sb.WriteString(style.Render(fmt.Sprintf("%s%s\n", prefix, displayText)))
	}
	if len(items) == 0 {
		if dp.filterMode && dp.filterInput != "" {
			sb.WriteString(DimText.Render(fmt.Sprintf("  No matches for \"%s\"", dp.filterInput)))
		} else {
			sb.WriteString(DimText.Render("  No items discovered yet..."))
		}
	}
	dp.viewport.SetContent(sb.String())
}

// View renders the discovery panel.
func (dp *DiscoveryPanel) View() string {
	var sb strings.Builder

	// Title
	title := PanelTitle
	if dp.focused {
		title = PanelTitleFocused
	}
	sb.WriteString(title.Render("Discovery Dashboard"))
	sb.WriteString("\n")
	if strings.TrimSpace(dp.phase) != "" {
		sb.WriteString(AccentText.Render("  " + dp.phase))
		sb.WriteString("\n")
	}

	// Filter indicator
	if dp.filterMode {
		filterLabel := AccentText.Render("[FILTER]")
		filterText := DimText.Render(fmt.Sprintf(" /%s", dp.filterInput))
		cursor := AccentText.Render("█")
		sb.WriteString(fmt.Sprintf("%s%s%s\n", filterLabel, filterText, cursor))
	}

	// Tabs
	tabs := make([]string, len(dp.sections))
	for i, section := range dp.sections {
		tabStyle := DimText
		if i == dp.activeTab {
			tabStyle = HighlightRow
		}
		tabs[i] = tabStyle.Render(fmt.Sprintf(" %s:%d ", section.Icon, section.Count))
	}
	sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, tabs...))
	sb.WriteString("\n")

	// Divider
	sb.WriteString(DimText.Render(strings.Repeat("-", max(dp.width-4, 20))))
	sb.WriteString("\n")

	// Detail popover (overlays content area)
	if dp.detailMode {
		sb.WriteString(dp.renderDetailPopover())
	} else {
		// Content
		sb.WriteString(dp.viewport.View())
	}

	return sb.String()
}

// renderDetailPopover builds a bordered box showing the selected item details.
func (dp *DiscoveryPanel) renderDetailPopover() string {
	popoverWidth := dp.width - 8
	if popoverWidth < 30 {
		popoverWidth = 30
	}
	if popoverWidth > 80 {
		popoverWidth = 80
	}

	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(PurpleLight).
		Padding(1, 2).
		Width(popoverWidth)

	var inner strings.Builder

	// Section name
	inner.WriteString(AccentText.Render(fmt.Sprintf("Section: %s", dp.detailSection)))
	inner.WriteString("\n")
	inner.WriteString(DimText.Render(strings.Repeat("─", popoverWidth-4)))
	inner.WriteString("\n\n")

	// Item content (word-wrapped manually)
	inner.WriteString(dp.detailItem)
	inner.WriteString("\n\n")

	// Hint
	inner.WriteString(DimText.Render("Press Enter to copy | Esc to close"))

	return borderStyle.Render(inner.String())
}

// Focused returns focus state.
func (dp *DiscoveryPanel) Focused() bool {
	return dp.focused
}

// Focus sets focus state.
func (dp *DiscoveryPanel) Focus(v bool) {
	dp.focused = v
}

func (dp *DiscoveryPanel) SelectedText() string {
	if dp == nil {
		return ""
	}
	if strings.TrimSpace(dp.detailItem) != "" {
		return dp.detailItem
	}
	items := dp.currentItems()
	if dp.scrollY >= 0 && dp.scrollY < len(items) {
		return items[dp.scrollY]
	}
	return ""
}

// AddItem adds an item to a specific section.
func (dp *DiscoveryPanel) AddItem(sectionName string, item string) {
	dp.AddItemWithKey(sectionName, item, item)
}

// AddItemWithKey adds an item to a section and deduplicates by key.
func (dp *DiscoveryPanel) AddItemWithKey(sectionName, key, item string) bool {
	if key == "" {
		key = item
	}
	for _, s := range dp.sections {
		if strings.EqualFold(s.Name, sectionName) {
			if s.Keys == nil {
				s.Keys = make(map[string]struct{})
			}
			if s.KeyIndex == nil {
				s.KeyIndex = make(map[string]int)
			}
			if _, exists := s.Keys[key]; exists {
				if i, ok := s.KeyIndex[key]; ok && i >= 0 && i < len(s.Items) {
					if s.Items[i] != item {
						s.Items[i] = item
					}
				}
				return false
			}
			s.Keys[key] = struct{}{}
			s.KeyIndex[key] = len(s.Items)
			s.Items = append(s.Items, item)
			s.Count = len(s.Items)
			dp.refreshTotalsFromSections()
			return true
		}
	}
	return false
}

// beginScan prepares the discovery panel for a new scan without discarding
// discoveries from previous scans. Existing items are preserved; new results
// will be merged in via AddItemWithKey which already deduplicates by key.
func (dp *DiscoveryPanel) beginScan() {
	// Keep all existing items. Only reset transient UI state.
	dp.activeTab = 0
	dp.scrollY = 0
	dp.filterMode = false
	dp.filterInput = ""
	dp.filteredItems = nil
	dp.detailMode = false
	dp.detailItem = ""
	dp.detailSection = ""
	dp.CopyRequested = false
	dp.PendingCopyText = ""
	dp.phase = "Starting"
	dp.refreshTotalsFromSections()
	dp.updateViewport()
}

// reset completely clears the discovery panel. This is used when loading
// a new archive or when the user explicitly clears the session.
func (dp *DiscoveryPanel) reset() {
	for _, s := range dp.sections {
		s.Count = 0
		s.Items = make([]string, 0)
		s.Keys = make(map[string]struct{})
		s.KeyIndex = make(map[string]int)
	}
	dp.totalSubdomains = 0
	dp.totalPorts = 0
	dp.totalURLs = 0
	dp.totalEndpoints = 0
	dp.totalSecrets = 0
	dp.totalParams = 0
	dp.totalJSFiles = 0
	dp.totalFindings = 0
	dp.activeTab = 0
	dp.scrollY = 0
	dp.filterMode = false
	dp.filterInput = ""
	dp.filteredItems = nil
	dp.detailMode = false
	dp.detailItem = ""
	dp.detailSection = ""
	dp.CopyRequested = false
	dp.PendingCopyText = ""
	dp.phase = ""
	dp.updateViewport()
}

func (dp *DiscoveryPanel) sectionIndex(sectionName string) int {
	for i, s := range dp.sections {
		if strings.EqualFold(s.Name, sectionName) {
			return i
		}
	}
	return -1
}

func (dp *DiscoveryPanel) refreshTotalsFromSections() {
	dp.totalSubdomains = len(dp.sections[0].Items)
	dp.totalPorts = len(dp.sections[1].Items)
	dp.totalURLs = len(dp.sections[2].Items)
	dp.totalEndpoints = len(dp.sections[3].Items)
	dp.totalSecrets = len(dp.sections[4].Items)
	dp.totalParams = len(dp.sections[5].Items)
	dp.totalJSFiles = len(dp.sections[6].Items)
	dp.totalFindings = len(dp.sections[7].Items)
}

func fitCellWidth(value string, width int) string {
	value = strings.TrimSpace(value)
	if width <= 0 || lipgloss.Width(value) <= width {
		return value
	}
	if width <= 3 {
		return strings.Repeat(".", max(0, width))
	}
	var out strings.Builder
	limit := width - 3
	for _, r := range value {
		next := out.String() + string(r)
		if lipgloss.Width(next) > limit {
			break
		}
		out.WriteRune(r)
	}
	return out.String() + "..."
}

// Summary returns a one-line summary of all discovery counts.
func (dp *DiscoveryPanel) Summary() string {
	parts := make([]string, 0)
	for _, s := range dp.sections {
		if s.Count > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", s.Name[:3], s.Count))
		}
	}
	if len(parts) == 0 {
		return "No discoveries yet"
	}
	return strings.Join(parts, " | ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
