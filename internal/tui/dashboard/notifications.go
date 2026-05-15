package dashboard

import (
	"strings"
	"sync"
	"time"

	core "Akemi/internal/core"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/uuid"
)

// =============================================================================
// Notification types & constants
// =============================================================================

// NotificationTickMsg triggers a TTL expiry check every 500ms.
type NotificationTickMsg struct{}

// Severity constants for notifications.
const (
	NotifSeverityCritical = "critical"
	NotifSeverityHigh     = "high"
	NotifSeverityMedium   = "medium"
	NotifSeverityLow      = "low"
	NotifSeverityInfo     = "info"
)

// Default TTLs assigned when a notification is created without an explicit TTL.
var defaultTTLs = map[string]time.Duration{
	NotifSeverityCritical: 30 * time.Second,
	NotifSeverityHigh:     20 * time.Second,
	NotifSeverityMedium:   10 * time.Second,
	NotifSeverityLow:      5 * time.Second,
	NotifSeverityInfo:     3 * time.Second,
}

// severityIcons maps each severity to a single-char or emoji indicator.
var severityIcons = map[string]string{
	NotifSeverityCritical: "🔴",
	NotifSeverityHigh:     "🟠",
	NotifSeverityMedium:   "🟡",
	NotifSeverityLow:      "🔵",
	NotifSeverityInfo:     "ℹ️",
}

// severityToastStyle returns the lipgloss style for a notification's title.
// Uses the existing styles from styles.go as specified:
//
//	ErrorText  → critical
//	WarnText   → high / medium
//	AccentText → low
//	DimText    → info
func severityToastStyle(severity string) lipgloss.Style {
	switch severity {
	case NotifSeverityCritical:
		return ErrorText
	case NotifSeverityHigh, NotifSeverityMedium:
		return WarnText
	case NotifSeverityLow:
		return AccentText
	case NotifSeverityInfo:
		return DimText
	default:
		return DimText
	}
}

// severityBorderColor maps severity to the lipgloss colour used for the toast border.
func severityBorderColor(severity string) lipgloss.Color {
	switch severity {
	case NotifSeverityCritical:
		return Red
	case NotifSeverityHigh:
		return Orange
	case NotifSeverityMedium:
		return Orange
	case NotifSeverityLow:
		return Blue
	case NotifSeverityInfo:
		return Gray
	default:
		return GrayDim
	}
}

// =============================================================================
// Notification
// =============================================================================

// Notification represents a single toast notification.
type Notification struct {
	Title    string
	Message  string
	Severity string        // critical | high | medium | low | info
	Time     time.Time     // when the notification was created
	TTL      time.Duration // how long to display; 0 = until manually dismissed
	ID       string        // unique identifier
}

// =============================================================================
// NotificationManager
// =============================================================================

// NotificationManager manages toast notifications with a ring buffer (max 50),
// an active toast pointer, and simultaneous display of up to maxVisible toasts.
type NotificationManager struct {
	notifications []Notification // ring buffer, cap 50
	activeID      string         // ID of the currently highlighted toast, "" if none
	maxVisible    int            // max simultaneous toasts (default 3)
	mu            sync.Mutex
}

// NewNotificationManager creates a ready-to-use NotificationManager.
func NewNotificationManager() *NotificationManager {
	return &NotificationManager{
		notifications: make([]Notification, 0, 50),
		maxVisible:    3,
	}
}

// Push adds a notification to the ring buffer. If no toast is currently
// active the newly pushed notification becomes active. When the buffer
// exceeds 50 entries the oldest entry is silently dropped.
func (nm *NotificationManager) Push(n Notification) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if n.ID == "" {
		n.ID = uuid.New().String()
	}
	if n.Time.IsZero() {
		n.Time = time.Now()
	}

	// Ring buffer: drop oldest when at capacity.
	if len(nm.notifications) >= 50 {
		// If the oldest was active, clear the active marker.
		if nm.notifications[0].ID == nm.activeID {
			nm.activeID = ""
		}
		nm.notifications = nm.notifications[1:]
	}
	nm.notifications = append(nm.notifications, n)

	if nm.activeID == "" {
		nm.activeID = n.ID
	}
}

// Dismiss clears the active notification (the one the user is currently
// looking at). Other queued notifications remain.
func (nm *NotificationManager) Dismiss() {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.activeID = ""
}

// DismissAll removes every notification immediately.
func (nm *NotificationManager) DismissAll() {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.notifications = nm.notifications[:0]
	nm.activeID = ""
}

// ActiveNotifications returns the currently visible toasts, newest first,
// limited to maxVisible. The caller gets a safe copy.
func (nm *NotificationManager) ActiveNotifications() []Notification {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if len(nm.notifications) == 0 {
		return nil
	}

	count := nm.maxVisible
	if count > len(nm.notifications) {
		count = len(nm.notifications)
	}

	result := make([]Notification, count)
	for i := 0; i < count; i++ {
		result[i] = nm.notifications[len(nm.notifications)-1-i]
	}
	return result
}

// Update handles incoming tea messages. On NotificationTickMsg it purges
// expired toasts and returns a command for the next tick if any remain.
// The returned tea.Cmd should be forwarded by the parent dashboard.
func (nm *NotificationManager) Update(msg tea.Msg) tea.Cmd {
	switch msg.(type) {
	case NotificationTickMsg:
		nm.purgeExpired()
		if nm.hasAny() {
			return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
				return NotificationTickMsg{}
			})
		}
	}
	return nil
}

// purgeExpired removes any notification whose TTL has elapsed.
func (nm *NotificationManager) purgeExpired() {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	now := time.Now()
	activeSurvived := false
	keep := nm.notifications[:0]
	for _, n := range nm.notifications {
		if n.TTL > 0 && now.Sub(n.Time) >= n.TTL {
			// Expired — drop. If this was the active toast, mark it gone.
			if n.ID == nm.activeID {
				nm.activeID = ""
			}
			continue
		}
		if n.ID == nm.activeID {
			activeSurvived = true
		}
		keep = append(keep, n)
	}
	nm.notifications = keep

	// If the active toast was purged, pick the newest remaining one.
	if !activeSurvived && nm.activeID != "" {
		// activeID was set but no matching notification survived.
		nm.activeID = ""
	}
	if nm.activeID == "" && len(nm.notifications) > 0 {
		nm.activeID = nm.notifications[len(nm.notifications)-1].ID
	}
}

// hasAny returns true when the manager holds at least one notification.
func (nm *NotificationManager) hasAny() bool {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	return len(nm.notifications) > 0
}

// =============================================================================
// View
// =============================================================================

const (
	toastWidth     = 50
	maxMessageRune = 60
)

// View renders the active toasts as an overlay intended for the top-right
// corner of the dashboard. Newest toasts appear at the top. Returns an
// empty string when there is nothing to show.
func (nm *NotificationManager) View(width int) string {
	active := nm.ActiveNotifications()
	if len(active) == 0 {
		return ""
	}

	var boxes []string
	for _, n := range active {
		icon, ok := severityIcons[n.Severity]
		if !ok {
			icon = "ℹ️"
		}

		style := severityToastStyle(n.Severity)
		borderClr := severityBorderColor(n.Severity)

		// Build content lines.
		titleLine := icon + " " + style.Bold(true).Render(n.Title)
		msgLine := DimText.Render(truncateRunes(n.Message, maxMessageRune))
		hintLine := DimText.Render("Enter to dismiss")

		content := lipgloss.JoinVertical(
			lipgloss.Left,
			titleLine,
			msgLine,
			hintLine,
		)

		box := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(borderClr).
			Width(toastWidth).
			Padding(0, 1).
			Render(content)

		boxes = append(boxes, box)
	}

	// Stack newest at top with a blank line between toasts.
	combined := lipgloss.JoinVertical(lipgloss.Right, boxes...)

	// Right-align the whole stack.
	actualW := lipgloss.Width(combined)
	pad := width - actualW
	if pad < 0 {
		pad = 0
	}

	return strings.Repeat(" ", pad) + combined
}

// =============================================================================
// Convenience constructors
// =============================================================================

// CriticalNotification creates a notification with critical severity and
// the default 30 s TTL.
func CriticalNotification(title, message string) Notification {
	return Notification{
		Title:    title,
		Message:  message,
		Severity: NotifSeverityCritical,
		TTL:      defaultTTLs[NotifSeverityCritical],
	}
}

// HighNotification creates a notification with high severity and the
// default 20 s TTL.
func HighNotification(title, message string) Notification {
	return Notification{
		Title:    title,
		Message:  message,
		Severity: NotifSeverityHigh,
		TTL:      defaultTTLs[NotifSeverityHigh],
	}
}

// InfoNotification creates a notification with info severity and the
// default 3 s TTL.
func InfoNotification(title, message string) Notification {
	return Notification{
		Title:    title,
		Message:  message,
		Severity: NotifSeverityInfo,
		TTL:      defaultTTLs[NotifSeverityInfo],
	}
}

// FindingNotification maps a core.VulnFinding to a notification. The
// severity is normalised to one of the five supported levels and an
// appropriate TTL is assigned.
func FindingNotification(finding core.VulnFinding) Notification {
	sev := strings.ToLower(finding.Severity)
	// Normalise common alternative spellings.
	switch sev {
	case "critical", "crit":
		sev = NotifSeverityCritical
	case "high":
		sev = NotifSeverityHigh
	case "medium", "med":
		sev = NotifSeverityMedium
	case "low":
		sev = NotifSeverityLow
	case "info", "informational":
		sev = NotifSeverityInfo
	default:
		sev = NotifSeverityInfo
	}

	ttl, ok := defaultTTLs[sev]
	if !ok {
		ttl = defaultTTLs[NotifSeverityInfo]
	}

	return Notification{
		Title:    finding.Name,
		Message:  finding.Description,
		Severity: sev,
		TTL:      ttl,
	}
}
