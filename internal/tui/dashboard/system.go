package dashboard

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

// =============================================================================
// SystemPanel — ③ System Usage
// =============================================================================

// SystemPanel displays live system metrics.
type SystemPanel struct {
	focused bool
	width   int
	height  int

	// Current metrics
	cpuPercent    float64
	memPercent    float64
	memUsed       uint64
	memTotal      uint64
	diskPercent   float64
	diskUsed      uint64
	diskTotal     uint64
	netSentRate   float64
	netRecvRate   float64
	numGoroutines int
	uptime        time.Duration
	startTime     time.Time

	// For network rate calculation
	prevNetSent uint64
	prevNetRecv uint64
	prevNetTime time.Time

	// Tick counter for periodic CPU polling
	tickCount int
}

// NewSystemPanel creates a new system metrics panel.
func NewSystemPanel() *SystemPanel {
	return &SystemPanel{
		startTime: time.Now(),
	}
}

// SetSize updates dimensions.
func (sp *SystemPanel) SetSize(w, h int) {
	sp.width = w
	sp.height = h
}

// Init starts metrics collection.
func (sp *SystemPanel) Init() tea.Cmd {
	return tea.Batch(
		tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return SystemTickMsg{}
		}),
		sp.startCPUPoller(),
	)
}

// startCPUPoller launches a background goroutine that feeds CPU metrics.
func (sp *SystemPanel) startCPUPoller() tea.Cmd {
	return func() tea.Msg {
		// cpu.Percent blocks, so we run it in this command's goroutine.
		// The tea runtime runs commands in separate goroutines.
		// After the first call, subsequent calls with 0 interval return cached values.
		// We do an initial blocking call with a short interval.
		percents, err := cpu.Percent(500*time.Millisecond, false)
		if err != nil || len(percents) == 0 {
			return SystemMetricsMsg{CPUPercent: 0}
		}
		return SystemMetricsMsg{CPUPercent: percents[0]}
	}
}

// Update handles messages.
func (sp *SystemPanel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return sp.handleKey(msg)

	case tea.MouseMsg:
		return sp.handleMouse(msg)

	case SystemTickMsg:
		sp.tickCount++
		sp.collectMetrics()
		cmds := []tea.Cmd{
			tea.Tick(time.Second, func(t time.Time) tea.Msg {
				return SystemTickMsg{}
			}),
		}
		// Poll CPU every 5 ticks (every 5 seconds)
		if sp.tickCount%5 == 0 {
			cmds = append(cmds, sp.startCPUPoller())
		}
		return sp, tea.Batch(cmds...)

	case SystemMetricsMsg:
		if msg.CPUPercent > 0 {
			sp.cpuPercent = msg.CPUPercent
		}
		if msg.MemPercent > 0 {
			sp.memPercent = msg.MemPercent
			sp.memUsed = msg.MemUsed
			sp.memTotal = msg.MemTotal
		}
		if msg.DiskPercent > 0 {
			sp.diskPercent = msg.DiskPercent
			sp.diskUsed = msg.DiskUsed
			sp.diskTotal = msg.DiskTotal
		}
		sp.netSentRate = msg.NetSentRate
		sp.netRecvRate = msg.NetRecvRate
		sp.numGoroutines = msg.NumGoroutines
		return sp, nil
	}

	return sp, nil
}

func (sp *SystemPanel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// System panel is read-only; tab is handled by parent
	return sp, nil
}

func (sp *SystemPanel) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	return sp, nil
}

func (sp *SystemPanel) collectMetrics() {
	// Memory
	if vmem, err := mem.VirtualMemory(); err == nil {
		sp.memPercent = vmem.UsedPercent
		sp.memUsed = vmem.Used
		sp.memTotal = vmem.Total
	}

	// Disk
	if diskStat, err := disk.Usage("/"); err == nil {
		sp.diskPercent = diskStat.UsedPercent
		sp.diskUsed = diskStat.Used
		sp.diskTotal = diskStat.Total
	}

	// Network rate
	if netIO, err := net.IOCounters(false); err == nil && len(netIO) > 0 {
		now := time.Now()
		if !sp.prevNetTime.IsZero() {
			elapsed := now.Sub(sp.prevNetTime).Seconds()
			if elapsed > 0 {
				sp.netSentRate = float64(netIO[0].BytesSent-sp.prevNetSent) / elapsed
				sp.netRecvRate = float64(netIO[0].BytesRecv-sp.prevNetRecv) / elapsed
			}
		}
		sp.prevNetSent = netIO[0].BytesSent
		sp.prevNetRecv = netIO[0].BytesRecv
		sp.prevNetTime = now
	}

	// Goroutines
	sp.numGoroutines = runtime.NumGoroutine()
	sp.uptime = time.Since(sp.startTime)
}

// View renders the system panel.
func (sp *SystemPanel) View() string {
	if sp.height < 8 {
		return sp.compactChartView()
	}

	var sb strings.Builder

	title := PanelTitle
	if sp.focused {
		title = PanelTitleFocused
	}
	sb.WriteString(title.Render("③ System Usage"))
	sb.WriteString("\n\n")

	sb.WriteString(sp.renderBar("CPU", sp.cpuPercent, 100))
	sb.WriteString("\n")

	sb.WriteString(sp.renderBar("MEM", sp.memPercent, 100))
	sb.WriteString(fmt.Sprintf("  %s / %s", formatBytes(sp.memUsed), formatBytes(sp.memTotal)))
	sb.WriteString("\n")

	netLabel := DimText.Render("NET")
	sb.WriteString(fmt.Sprintf("%s  %s↑ %s↓\n",
		netLabel,
		AccentText.Render(formatBytesRate(sp.netSentRate)),
		SuccessText.Render(formatBytesRate(sp.netRecvRate))))

	sb.WriteString(sp.renderBar("DSK", sp.diskPercent, 100))
	sb.WriteString(fmt.Sprintf("  %s / %s", formatBytes(sp.diskUsed), formatBytes(sp.diskTotal)))
	sb.WriteString("\n\n")

	sb.WriteString(DimText.Render(fmt.Sprintf("  Tasks: %d  |  Uptime: %s",
		sp.numGoroutines, sp.uptime.Round(time.Second))))
	sb.WriteString("\n")

	return sb.String()
}

func (sp *SystemPanel) compactChartView() string {
	var sb strings.Builder
	title := PanelTitle
	if sp.focused {
		title = PanelTitleFocused
	}
	sb.WriteString(title.Render("System Usage"))
	if sp.height <= 1 {
		return sb.String()
	}
	sb.WriteString("\n")

	barWidth := max(4, min(8, (sp.width-18)/2))
	cpu := sp.renderMiniMetric("CPU", sp.cpuPercent, barWidth)
	mem := sp.renderMiniMetric("MEM", sp.memPercent, barWidth)
	sb.WriteString(fitCellWidth(cpu+"  "+mem, max(8, sp.width)))

	if sp.height > 2 {
		sb.WriteString("\n")
		diskMetric := sp.renderMiniMetric("DSK", sp.diskPercent, barWidth)
		netMetric := fmt.Sprintf("NET %s^ %sv", formatBytesRate(sp.netSentRate), formatBytesRate(sp.netRecvRate))
		sb.WriteString(fitCellWidth(diskMetric+"  "+netMetric, max(8, sp.width)))
	}

	if sp.height > 3 {
		sb.WriteString("\n")
		status := fmt.Sprintf("Tasks: %d | Uptime: %s", sp.numGoroutines, sp.uptime.Round(time.Second))
		sb.WriteString(DimText.Render(fitCellWidth(status, max(8, sp.width))))
	}

	return sb.String()
}

func (sp *SystemPanel) renderMiniMetric(label string, value float64, width int) string {
	filled := int((value / 100) * float64(width))
	filled = min(max(filled, 0), width)
	barStyle := BarFull
	switch {
	case value >= 80:
		barStyle = BarCrit
	case value >= 50:
		barStyle = BarHigh
	}
	bar := barStyle.Render(strings.Repeat("█", filled))
	track := BarTrack.Render(strings.Repeat("░", width-filled))
	return fmt.Sprintf("%s %s%s %.0f%%", DimText.Render(label), bar, track, value)
}

func (sp *SystemPanel) renderBar(label string, value, maxVal float64) string {
	const barWidth = 20

	labelStr := DimText.Render(fmt.Sprintf("%-4s", label))
	pct := value
	if maxVal > 0 {
		pct = (value / maxVal) * 100
	}

	filled := int((pct / 100) * barWidth)
	if filled > barWidth {
		filled = barWidth
	}
	if filled < 0 {
		filled = 0
	}

	var barStyle lipgloss.Style
	switch {
	case pct < 50:
		barStyle = BarFull
	case pct < 80:
		barStyle = BarHigh
	default:
		barStyle = BarCrit
	}

	bar := barStyle.Render(strings.Repeat("█", filled))
	track := BarTrack.Render(strings.Repeat("░", barWidth-filled))
	pctStr := DimText.Render(fmt.Sprintf(" %5.1f%%", pct))

	return fmt.Sprintf("%s %s%s%s", labelStr, bar, track, pctStr)
}

// Focused returns focus state.
func (sp *SystemPanel) Focused() bool { return sp.focused }

// Focus sets focus state.
func (sp *SystemPanel) Focus(v bool) { sp.focused = v }

// =============================================================================
// Formatting helpers
// =============================================================================

func formatBytes(bytes uint64) string {
	switch {
	case bytes >= 1<<40:
		return fmt.Sprintf("%.1f TB", float64(bytes)/(1<<40))
	case bytes >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(bytes)/(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(bytes)/(1<<10))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func formatBytesRate(bytesPerSec float64) string {
	switch {
	case bytesPerSec >= 1<<30:
		return fmt.Sprintf("%.1f GB/s", bytesPerSec/(1<<30))
	case bytesPerSec >= 1<<20:
		return fmt.Sprintf("%.1f MB/s", bytesPerSec/(1<<20))
	case bytesPerSec >= 1<<10:
		return fmt.Sprintf("%.1f KB/s", bytesPerSec/(1<<10))
	default:
		return fmt.Sprintf("%.0f B/s", bytesPerSec)
	}
}

// max returns the larger of two ints.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
