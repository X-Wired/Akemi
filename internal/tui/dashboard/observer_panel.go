package dashboard

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// =============================================================================
// ObserverPanel — "🕵️ Observer Mode"
// =============================================================================
//
// Shows a live feed of discoveries alongside AI-generated suggested next
// actions. The operator watches discoveries flow in and can accept/ignore
// suggestions.

// ObserverDiscovery is a single discovery entry tracked by the Observer panel.
type ObserverDiscovery struct {
	Time       time.Time
	Section    string // "Subdomains", "Ports", "URLs", "Endpoints", "Secrets", "Params", "JS Files"
	Key        string
	Item       string
	Suggestion *AutonomySuggestion // associated suggestion, if any
}

// ObserverPanel shows a live feed of discoveries alongside AI-generated
// suggested next actions. The operator watches discoveries flow in and
// can accept / ignore suggestions.
type ObserverPanel struct {
	focused        bool
	width, height  int
	controller     *AutonomyController
	notifications  *NotificationManager
	discoveries    []ObserverDiscovery // ring buffer, max 100
	suggestions    []AutonomySuggestion
	selectedIdx    int  // which discovery is selected
	detailExpanded bool // show detail for selected item
	viewport       viewport.Model
	scrollY        int
	autoScroll     bool // auto-scroll to newest
	status         string
}

// NewObserverPanel creates a new ObserverPanel with the given controller and
// notification manager.
func NewObserverPanel(controller *AutonomyController, notifications *NotificationManager) *ObserverPanel {
	op := &ObserverPanel{
		controller:    controller,
		notifications: notifications,
		discoveries:   make([]ObserverDiscovery, 0, 100),
		suggestions:   make([]AutonomySuggestion, 0),
		selectedIdx:   0,
		autoScroll:    true,
		status:        "Waiting for discoveries...",
	}
	op.viewport = viewport.New(40, 15)
	return op
}

// SetSize updates the panel dimensions.
func (op *ObserverPanel) SetSize(w, h int) {
	op.width = w
	op.height = h
	op.viewport.Width = w - 6
	op.viewport.Height = h - 8
	if op.viewport.Width < 10 {
		op.viewport.Width = 10
	}
	if op.viewport.Height < 3 {
		op.viewport.Height = 3
	}
	op.updateViewport()
}

// Init implements tea.Model.
func (op *ObserverPanel) Init() tea.Cmd {
	return nil
}

// Update handles messages.
func (op *ObserverPanel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return op.handleKey(msg)

	case tea.MouseMsg:
		return op.handleMouse(msg)

	case DiscoveryItemMsg:
		op.addDiscovery(msg)
		op.updateViewport()
		return op, nil

	case AutonomySuggestionMsg:
		op.suggestions = append(op.suggestions, msg.Suggestions...)
		op.updateViewport()
		return op, nil

	case ScanStartedMsg:
		op.discoveries = op.discoveries[:0]
		op.suggestions = op.suggestions[:0]
		op.selectedIdx = 0
		op.scrollY = 0
		op.detailExpanded = false
		op.autoScroll = true
		op.status = fmt.Sprintf("Scanning %s...", msg.Target)
		op.updateViewport()
		return op, nil

	case ScanProgressMsg:
		op.status = fmt.Sprintf(
			"Phase: %s | SUB:%d PRT:%d URL:%d API:%d SEC:%d PAR:%d JS:%d",
			msg.Phase,
			msg.Subdomains,
			msg.Ports,
			msg.URLs,
			msg.Endpoints,
			msg.Secrets,
			msg.Params,
			msg.JSFiles,
		)
		return op, nil

	case ScanDoneMsg:
		op.status = fmt.Sprintf("Scan complete — %d discoveries captured", len(op.discoveries))
		op.updateViewport()
		return op, nil
	}

	return op, nil
}

// handleKey processes keyboard input.
func (op *ObserverPanel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	switch key {
	case "up", "k":
		if op.selectedIdx > 0 {
			op.selectedIdx--
			op.detailExpanded = false
			op.ensureVisible(op.selectedIdx)
			op.updateViewport()
		}

	case "down", "j":
		if op.selectedIdx < len(op.discoveries)-1 {
			op.selectedIdx++
			op.detailExpanded = false
			op.ensureVisible(op.selectedIdx)
			op.updateViewport()
		}

	case "enter":
		if len(op.discoveries) > 0 {
			op.detailExpanded = !op.detailExpanded
			op.updateViewport()
		}

	case "a":
		op.acceptSelected()

	case "i":
		op.ignoreSelected()

	case "A":
		op.acceptAll()

	case "s":
		op.autoScroll = !op.autoScroll
		op.updateViewport()

	case "tab":
		// Pass through to parent
		return op, nil
	}

	return op, nil
}

// handleMouse processes mouse events.
func (op *ObserverPanel) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	switch msg.Action {
	case tea.MouseActionPress:
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			if op.scrollY > 0 {
				op.scrollY--
				op.updateViewport()
			}
		case tea.MouseButtonWheelDown:
			if op.scrollY < len(op.discoveries)-1 {
				op.scrollY++
				op.updateViewport()
			}
		case tea.MouseButtonLeft:
			// Calculate which discovery row was clicked.
			headerLines := 3
			line := 0
			for i := op.scrollY; i < len(op.discoveries); i++ {
				if line >= msg.Y-headerLines {
					op.selectedIdx = i
					op.detailExpanded = false
					op.updateViewport()
					break
				}
				line++ // discovery line
				if op.discoveries[i].Suggestion != nil {
					line++ // suggestion line
				}
				if op.detailExpanded && i == op.selectedIdx {
					line += 3 // detail lines
				}
			}
		}
	}
	return op, nil
}

// View renders the Observer panel.
func (op *ObserverPanel) View() string {
	var sb strings.Builder

	// ── Title ──
	title := PanelTitle
	if op.focused {
		title = PanelTitleFocused
	}

	suggestionCount := op.countSuggestions()
	sb.WriteString(title.Render("🕵️ Observer Mode"))
	if suggestionCount > 0 {
		sb.WriteString(DimText.Render(fmt.Sprintf("   %d suggestions pending", suggestionCount)))
	}
	sb.WriteString("\n")

	// ── Divider ──
	sb.WriteString(DimText.Render(strings.Repeat("─", max(op.width-4, 20))))
	sb.WriteString("\n")

	// ── Content via viewport ──
	sb.WriteString(op.viewport.View())
	sb.WriteString("\n")

	// ── Footer ──
	sb.WriteString(DimText.Render(strings.Repeat("─", max(op.width-4, 20))))
	sb.WriteString("\n")

	autoScrollLabel := "ON"
	if !op.autoScroll {
		autoScrollLabel = "OFF"
	}
	footer := fmt.Sprintf(
		"Auto-scroll %s | %d discoveries | %d suggestions | [a]ccept [i]gnore [A]ccept all [s]croll toggle",
		autoScrollLabel,
		len(op.discoveries),
		suggestionCount,
	)
	sb.WriteString(HelpText.Render(footer))

	return sb.String()
}

// =============================================================================
// Internal helpers
// =============================================================================

// addDiscovery appends a discovery item to the ring buffer (max 100), calls
// the controller to generate a suggestion, and attaches it.
func (op *ObserverPanel) addDiscovery(item DiscoveryItemMsg) {
	d := ObserverDiscovery{
		Time:    time.Now(),
		Section: item.Section,
		Key:     item.Key,
		Item:    item.Item,
	}

	// Ask the controller to process this discovery and return suggestions.
	suggestions := op.controller.ProcessDiscovery(context.Background(), item)
	if len(suggestions) > 0 {
		d.Suggestion = &suggestions[0]
		// Accumulate additional suggestions into the global list.
		if len(suggestions) > 1 {
			op.suggestions = append(op.suggestions, suggestions[1:]...)
		}
	}

	// Ring buffer: drop oldest when at capacity.
	if len(op.discoveries) >= 100 {
		op.discoveries = op.discoveries[1:]
		// Adjust indices if they pointed to the dropped element.
		if op.selectedIdx > 0 {
			op.selectedIdx--
		}
		if op.scrollY > 0 {
			op.scrollY--
		}
	}
	op.discoveries = append(op.discoveries, d)

	// Auto-scroll to newest.
	if op.autoScroll {
		op.selectedIdx = len(op.discoveries) - 1
		op.scrollY = len(op.discoveries) - 3 // keep a few items visible above
		if op.scrollY < 0 {
			op.scrollY = 0
		}
	}

	op.status = fmt.Sprintf("Last: [%s] %s", item.Section[:min(3, len(item.Section))], item.Item)
}

// acceptSelected accepts the suggestion associated with the currently selected
// discovery.
func (op *ObserverPanel) acceptSelected() {
	if op.selectedIdx < 0 || op.selectedIdx >= len(op.discoveries) {
		return
	}

	d := &op.discoveries[op.selectedIdx]
	if d.Suggestion == nil {
		return
	}

	sug := d.Suggestion
	op.notifications.Push(InfoNotification("Observer", "Task queued: "+sug.Title))

	// Remove the suggestion from this discovery.
	d.Suggestion = nil

	// Also remove from the global suggestions list.
	op.removeSuggestion(sug.ID)

	op.updateViewport()
}

// ignoreSelected removes the suggestion from the currently selected discovery.
func (op *ObserverPanel) ignoreSelected() {
	if op.selectedIdx < 0 || op.selectedIdx >= len(op.discoveries) {
		return
	}

	d := &op.discoveries[op.selectedIdx]
	if d.Suggestion == nil {
		return
	}

	sug := d.Suggestion
	d.Suggestion = nil
	op.removeSuggestion(sug.ID)
	op.updateViewport()
}

// acceptAll accepts every pending suggestion across all discoveries and the
// global list.
func (op *ObserverPanel) acceptAll() {
	count := 0
	for i := range op.discoveries {
		if op.discoveries[i].Suggestion != nil {
			sug := op.discoveries[i].Suggestion
			op.notifications.Push(InfoNotification("Observer", "Task queued: "+sug.Title))
			op.discoveries[i].Suggestion = nil
			op.removeSuggestion(sug.ID)
			count++
		}
	}

	// Also accept orphaned suggestions not attached to any discovery.
	for _, sug := range op.suggestions {
		op.notifications.Push(InfoNotification("Observer", "Task queued: "+sug.Title))
		count++
	}
	op.suggestions = op.suggestions[:0]

	if count > 0 {
		op.notifications.Push(InfoNotification("Observer", fmt.Sprintf("%d tasks queued", count)))
	}
	op.updateViewport()
}

// removeSuggestion deletes a suggestion from the global list by ID.
func (op *ObserverPanel) removeSuggestion(id string) {
	filtered := op.suggestions[:0]
	for _, s := range op.suggestions {
		if s.ID != id {
			filtered = append(filtered, s)
		}
	}
	op.suggestions = filtered
}

// countSuggestions returns the total number of pending suggestions (both
// attached to discoveries and in the global list).
func (op *ObserverPanel) countSuggestions() int {
	count := len(op.suggestions)
	for _, d := range op.discoveries {
		if d.Suggestion != nil {
			count++
		}
	}
	return count
}

// ensureVisible adjusts scrollY so that the given index is visible in the
// viewport.
func (op *ObserverPanel) ensureVisible(idx int) {
	if idx < op.scrollY {
		op.scrollY = idx
	}
	// Estimate visible items (each discovery takes at least 1 line, up to 3
	// with suggestion + detail).
	visibleCount := op.viewport.Height
	if visibleCount < 1 {
		visibleCount = 1
	}
	if idx >= op.scrollY+visibleCount {
		op.scrollY = idx - visibleCount + 1
		if op.scrollY < 0 {
			op.scrollY = 0
		}
	}
}

// updateViewport rebuilds the viewport content from the current state.
func (op *ObserverPanel) updateViewport() {
	var sb strings.Builder

	if len(op.discoveries) == 0 {
		sb.WriteString(DimText.Render("  Waiting for discoveries..."))
		op.viewport.SetContent(sb.String())
		return
	}

	for i := op.scrollY; i < len(op.discoveries); i++ {
		if i > op.scrollY+50 {
			break
		}
		d := op.discoveries[i]

		// ── Discovery line ──
		selected := i == op.selectedIdx
		prefix := "  "
		rowStyle := DimText
		if selected {
			prefix = "▶ "
			rowStyle = HighlightRow
		}

		badge := op.sectionBadge(d.Section)
		sb.WriteString(rowStyle.Render(fmt.Sprintf("%s%s %s", prefix, badge, d.Item)))

		// Show a short arrow hint if a suggestion exists.
		if d.Suggestion != nil {
			sb.WriteString(DimText.Render(fmt.Sprintf("  ← %s", d.Suggestion.Title)))
		}
		sb.WriteString("\n")

		// ── Suggestion line ──
		if d.Suggestion != nil {
			sugPrefix := "     ↳ "
			sugStyle := DimText
			if selected {
				sugStyle = AccentText
			}
			acceptHover := "[a]"
			ignoreHover := "[i]"
			if selected {
				acceptHover = SuccessText.Render("[a]")
				ignoreHover = ErrorText.Render("[i]")
			}
			sb.WriteString(sugStyle.Render(fmt.Sprintf("%s%s", sugPrefix, d.Suggestion.Title)))
			sb.WriteString(DimText.Render(fmt.Sprintf("  %sccept %sgnore", acceptHover, ignoreHover)))
			sb.WriteString("\n")
		}

		// ── Detail expansion ──
		if op.detailExpanded && selected && d.Suggestion != nil {
			detailStyle := DimText.Copy().PaddingLeft(7)
			sb.WriteString(detailStyle.Render("Rationale: " + d.Suggestion.Rationale))
			sb.WriteString("\n")
			if d.Suggestion.Description != "" {
				sb.WriteString(detailStyle.Render("Description: " + d.Suggestion.Description))
				sb.WriteString("\n")
			}
			if d.Suggestion.SuggestedTool != "" {
				sb.WriteString(detailStyle.Render("Tool: " + d.Suggestion.SuggestedTool))
				sb.WriteString("\n")
			}
		}
	}

	op.viewport.SetContent(sb.String())
}

// sectionBadge returns a colored badge tag for the given section name.
func (op *ObserverPanel) sectionBadge(section string) string {
	var color lipgloss.Color
	tag := "   "

	switch {
	case strings.EqualFold(section, "Subdomains"):
		color = PurpleLight
		tag = "SUB"
	case strings.EqualFold(section, "Ports"):
		color = Green
		tag = "PRT"
	case strings.EqualFold(section, "URLs"):
		color = Blue
		tag = "URL"
	case strings.EqualFold(section, "Endpoints"):
		color = Orange
		tag = "API"
	case strings.EqualFold(section, "Secrets"):
		color = Red
		tag = "SEC"
	case strings.EqualFold(section, "Params"):
		color = Orange
		tag = "PAR"
	case strings.EqualFold(section, "JS Files"):
		color = Gray
		tag = " JS"
	default:
		color = Gray
		tag = strings.ToUpper(section[:min(3, len(section))])
	}

	style := lipgloss.NewStyle().
		Foreground(color).
		Bold(true)

	return fmt.Sprintf("[%s]", style.Render(tag))
}

// =============================================================================
// Focus helpers
// =============================================================================

// Focused returns whether the panel has input focus.
func (op *ObserverPanel) Focused() bool {
	return op.focused
}

// Focus sets the input focus state.
func (op *ObserverPanel) Focus(v bool) {
	op.focused = v
}
