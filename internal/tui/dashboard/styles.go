// Package dashboard provides the terminal operator dashboard for Akemi
// with resizable panels, mouse support, and real-time monitoring.
package dashboard

import "github.com/charmbracelet/lipgloss"

// =============================================================================
// Color Palette (purple neon theme)
// =============================================================================

var (
	Purple      = lipgloss.Color("#7B2FBE")
	PurpleLight = lipgloss.Color("#9D4EDD")
	PurpleDim   = lipgloss.Color("#5A1E8A")
	Green       = lipgloss.Color("#04B575")
	Red         = lipgloss.Color("#FF4672")
	Orange      = lipgloss.Color("#FFB86C")
	Blue        = lipgloss.Color("#6C8EBF")
	White       = lipgloss.Color("#FFFFFF")
	Gray        = lipgloss.Color("#888888")
	GrayDim     = lipgloss.Color("#555555")
	Black       = lipgloss.Color("#1A1A2E")
)

// =============================================================================
// Base Styles
// =============================================================================

var (
	PanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(GrayDim).
			Padding(1, 2)

	PanelFocused = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(PurpleLight).
			Padding(1, 2)

	PanelTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(PurpleLight)

	PanelTitleFocused = lipgloss.NewStyle().
				Bold(true).
				Foreground(White).
				Background(Purple).
				Padding(0, 1)

	AccentText = lipgloss.NewStyle().
			Foreground(PurpleLight)

	SuccessText = lipgloss.NewStyle().
			Foreground(Green)

	ErrorText = lipgloss.NewStyle().
			Foreground(Red)

	WarnText = lipgloss.NewStyle().
			Foreground(Orange)

	DimText = lipgloss.NewStyle().
		Foreground(Gray)

	HelpText = lipgloss.NewStyle().
			Foreground(GrayDim)

	HighlightRow = lipgloss.NewStyle().
			Foreground(White).
			Background(PurpleDim)

	// Bar styles for progress indicators
	BarFull  = lipgloss.NewStyle().Foreground(Green)
	BarHigh  = lipgloss.NewStyle().Foreground(Orange)
	BarCrit  = lipgloss.NewStyle().Foreground(Red)
	BarEmpty = lipgloss.NewStyle().Foreground(GrayDim)
	BarTrack = lipgloss.NewStyle().Foreground(lipgloss.Color("#333355"))
)

// =============================================================================
// Severity Styles
// =============================================================================

func SeverityStyle(severity string) lipgloss.Style {
	switch severity {
	case "critical":
		return lipgloss.NewStyle().Foreground(Red).Bold(true)
	case "high":
		return lipgloss.NewStyle().Foreground(Red)
	case "medium":
		return lipgloss.NewStyle().Foreground(Orange)
	case "low":
		return lipgloss.NewStyle().Foreground(Blue)
	case "info":
		return lipgloss.NewStyle().Foreground(Gray)
	default:
		return DimText
	}
}

func SeverityTag(severity string) string {
	switch severity {
	case "critical":
		return "CRIT"
	case "high":
		return "HIGH"
	case "medium":
		return "MED "
	case "low":
		return "LOW "
	case "info":
		return "INFO"
	default:
		return "----"
	}
}
