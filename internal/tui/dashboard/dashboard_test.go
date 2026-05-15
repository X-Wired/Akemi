package dashboard

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	core "Akemi/internal/core"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type blockingScanner struct {
	started chan struct{}
	done    chan struct{}
	seen    atomic.Bool
}

func (s *blockingScanner) Scan(ctx context.Context, req core.ScanRequest) (*core.ScanResult, error) {
	if s.seen.CompareAndSwap(false, true) {
		close(s.started)
	}
	select {
	case <-s.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &core.ScanResult{Hostname: req.Host, TotalScanned: len(req.Ports), ScanMode: "test"}, nil
}

func (s *blockingScanner) DiscoverHosts(ctx context.Context, req core.HostDiscoveryRequest) (*core.HostDiscoveryResult, error) {
	return &core.HostDiscoveryResult{}, nil
}

type blockingDiscoverer struct {
	crawlEntered chan struct{}
	crawlDone    chan struct{}
}

func (d *blockingDiscoverer) Crawl(ctx context.Context, startURL string, maxDepth int) ([]core.CrawlFinding, error) {
	return d.CrawlWithCallback(ctx, startURL, maxDepth, nil)
}

func (d *blockingDiscoverer) CrawlWithCallback(ctx context.Context, startURL string, maxDepth int, onFinding func(core.CrawlFinding)) ([]core.CrawlFinding, error) {
	close(d.crawlEntered)
	finding := core.CrawlFinding{URL: core.EnsureProtocol(startURL), StatusCode: 200, Title: "OK"}
	if onFinding != nil {
		onFinding(finding)
	}
	select {
	case <-d.crawlDone:
	case <-ctx.Done():
		return []core.CrawlFinding{finding}, ctx.Err()
	}
	return []core.CrawlFinding{finding}, nil
}

func (d *blockingDiscoverer) MineParams(ctx context.Context, targetURL string, cfg core.MiningConfig) (*core.ParamDiscoveryResult, error) {
	return &core.ParamDiscoveryResult{Params: map[string]core.ParamDetail{}}, nil
}

func (d *blockingDiscoverer) AnalyzeJS(ctx context.Context, pageURL string) (*core.JSAnalysisResult, error) {
	return &core.JSAnalysisResult{}, nil
}

func (d *blockingDiscoverer) ScrapePage(ctx context.Context, pageURL string, keywords []string) (*core.ScrapeResult, error) {
	return &core.ScrapeResult{}, nil
}

func (d *blockingDiscoverer) DiscoverAPISurface(ctx context.Context, startURL string, discoveredURLs []string) (*core.APISurfaceResult, error) {
	return &core.APISurfaceResult{}, nil
}

func (d *blockingDiscoverer) HuntAPISurface(ctx context.Context, req core.APIHuntRequest) (*core.APIHuntResult, error) {
	return &core.APIHuntResult{}, nil
}

func TestFullSurfaceMapEmitsLiveDiscoveryBeforePortScan(t *testing.T) {
	scanner := &blockingScanner{started: make(chan struct{}), done: make(chan struct{})}
	discoverer := &blockingDiscoverer{crawlEntered: make(chan struct{}), crawlDone: make(chan struct{})}
	events := make(chan tea.Msg, 64)
	emitter := newScanEmitter(func(msg tea.Msg) { events <- msg })

	done := make(chan error, 1)
	go func() {
		_, err := runDashboardIntentScan(context.Background(), DashboardServices{
			Scanner:    scanner,
			Discoverer: discoverer,
		}, ScanConfig{
			Target:    "example.test",
			Intent:    "full_surface_map",
			PortRange: "80,443",
			Depth:     1,
			Threads:   2,
			Timeout:   1,
		}, emitter)
		done <- err
	}()

	select {
	case <-discoverer.crawlEntered:
	case <-time.After(time.Second):
		t.Fatal("full_surface_map did not enter crawl first")
	}

	select {
	case <-scanner.started:
		t.Fatal("port scan started before live crawl had a chance to emit discovery")
	default:
	}

	deadline := time.After(time.Second)
	for {
		select {
		case msg := <-events:
			item, ok := msg.(DiscoveryItemMsg)
			if ok && item.Section == "URLs" && item.Key == "http://example.test" {
				close(discoverer.crawlDone)
				close(scanner.done)
				select {
				case err := <-done:
					if err != nil {
						t.Fatalf("scan returned error: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("scan did not finish after releasing fake services")
				}
				return
			}
		case <-deadline:
			t.Fatal("full_surface_map did not emit a live URL discovery item")
		}
	}
}

func TestFullSurfaceScanAliasUsesFullSurfaceMapWorkflow(t *testing.T) {
	if got := normalizeDashboardIntent("full_surface_scan"); got != "full_surface_map" {
		t.Fatalf("full_surface_scan should normalize to full_surface_map, got %q", got)
	}

	tp := NewTargetPanel()
	tp.fields[fieldIntent].value = "full_surface_scan"
	if got := tp.intent(); got != "full_surface_map" {
		t.Fatalf("target panel should keep alias on the full surface workflow, got %q", got)
	}
}

func TestDashboardPollContinuesAfterLiveEvent(t *testing.T) {
	d := NewDashboard(DashboardServices{})
	d.send(ScanProgressMsg{Phase: "Crawling"})

	msg, ok := d.pollEvents()().(dashboardPolledMsg)
	if !ok {
		t.Fatal("pollEvents should wrap async dashboard messages")
	}
	if progress, ok := msg.Msg.(ScanProgressMsg); !ok || progress.Phase != "Crawling" {
		t.Fatalf("unexpected polled message: %#v", msg.Msg)
	}

	if _, cmd := d.Update(msg); cmd == nil {
		t.Fatal("dashboard did not schedule the next async event poll")
	}
	if !d.polling {
		t.Fatal("dashboard event poller was not kept active after a live event")
	}
}

func TestDiscoveryRoutesVulnFindingsToFindingsTab(t *testing.T) {
	dp := NewDiscoveryPanel()
	_, _ = dp.Update(ScanDoneMsg{Findings: []core.VulnFinding{
		{Name: "Information Disclosure", Severity: "medium", Target: "http://example.test", Evidence: `Body pattern matched: (?i)stack\s*trace`},
		{Name: "Missing Security Headers", Severity: "low", Target: "http://example.test", Evidence: "missing: X-Content-Type-Options"},
	}})

	if got := dp.sections[5].Count; got != 0 {
		t.Fatalf("params tab should not receive vulnerability findings, got %d", got)
	}
	if got := dp.sections[7].Count; got != 2 {
		t.Fatalf("findings tab should receive vulnerability findings, got %d", got)
	}
}

func TestJSEndpointsDoNotPopulateAPITab(t *testing.T) {
	events := make(chan tea.Msg, 16)
	emitter := newScanEmitter(func(msg tea.Msg) { events <- msg })

	emitter.js("http://example.test", &core.JSAnalysisResult{
		ScriptURLs: []string{"http://example.test/app.js"},
		Endpoints:  []string{"/not-api-resource"},
	})

	for len(events) > 0 {
		if item, ok := (<-events).(DiscoveryItemMsg); ok && item.Section == "Endpoints" {
			t.Fatalf("JS endpoint should not populate API tab: %#v", item)
		}
	}
}

func TestTargetProgressBarFitsPanelWidth(t *testing.T) {
	tp := NewTargetPanel()
	tp.SetSize(24, 12)
	if tp.progressBar.Width > 16 {
		t.Fatalf("progress bar width should fit narrow target panel, got %d", tp.progressBar.Width)
	}
}

func TestDashboardViewFitsTerminalWhileScanning(t *testing.T) {
	d := NewDashboard(DashboardServices{})
	model, _ := d.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	d = model.(*Dashboard)
	model, _ = d.Update(ScanStartedMsg{
		Target: "https://example.test",
		Intent: "full_surface_map",
		Config: ScanConfig{Target: "https://example.test", Intent: "full_surface_map"},
	})
	d = model.(*Dashboard)
	model, _ = d.Update(ScanProgressMsg{
		Phase:     "Analyzing JavaScript",
		URLs:      12,
		Params:    7,
		Endpoints: 3,
		Findings:  2,
	})
	d = model.(*Dashboard)

	view := d.View()
	if got := lipgloss.Width(view); got > 100 {
		t.Fatalf("dashboard view width overflowed terminal: got %d", got)
	}
	if got := lipgloss.Height(view); got > 30 {
		t.Fatalf("dashboard view height overflowed terminal: got %d", got)
	}
}

func TestDashboardUsesAllocatedSpaceAndShowsTargetActions(t *testing.T) {
	d := NewDashboard(DashboardServices{})
	model, _ := d.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	d = model.(*Dashboard)

	view := d.View()
	if got := lipgloss.Width(view); got != 100 {
		t.Fatalf("dashboard should fill terminal width: got %d", got)
	}
	if got := lipgloss.Height(view); got != 30 {
		t.Fatalf("dashboard should fill terminal height: got %d", got)
	}
	for _, label := range []string{"[ Capture Auth ]", "[ Start Scan ]", "[ Save Run ]", "[ Load Run ]"} {
		if !strings.Contains(view, label) {
			t.Fatalf("target configuration should show %s", label)
		}
	}
}

func TestDashboardKeepsSystemCompactAndPrioritizesTarget(t *testing.T) {
	d := NewDashboard(DashboardServices{})
	model, _ := d.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	d = model.(*Dashboard)

	_, targetH := d.panelBounds()
	bodyH := d.bodyHeight()
	systemH := bodyH - targetH
	if targetH < 22 {
		t.Fatalf("target panel should receive most vertical space, got target height %d", targetH)
	}
	if systemH > 7 {
		t.Fatalf("system panel should stay compact at this size, got height %d", systemH)
	}
	if d.system.height > 3 {
		t.Fatalf("system content height should be compact, got %d", d.system.height)
	}
	if view := d.system.View(); !strings.Contains(view, "CPU") || !strings.Contains(view, "MEM") || !strings.Contains(view, "DSK") {
		t.Fatalf("compact system view should keep chart metrics visible: %q", view)
	}
}

func TestDashboardMouseDragResizesAndPersistsRatiosAcrossTerminalResize(t *testing.T) {
	d := NewDashboard(DashboardServices{})
	model, _ := d.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	d = model.(*Dashboard)

	leftW, topH := d.panelBounds()
	model, _ = d.Update(tea.MouseMsg{X: leftW, Y: 5, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	d = model.(*Dashboard)
	model, _ = d.Update(tea.MouseMsg{X: 52, Y: 5, Button: tea.MouseButtonLeft, Action: tea.MouseActionMotion})
	d = model.(*Dashboard)
	model, _ = d.Update(tea.MouseMsg{X: 52, Y: 5, Button: tea.MouseButtonLeft, Action: tea.MouseActionRelease})
	d = model.(*Dashboard)
	if got, _ := d.panelBounds(); got != 52 {
		t.Fatalf("vertical drag should resize left column to 52, got %d", got)
	}

	model, _ = d.Update(tea.MouseMsg{X: 5, Y: topH, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	d = model.(*Dashboard)
	model, _ = d.Update(tea.MouseMsg{X: 5, Y: 17, Button: tea.MouseButtonLeft, Action: tea.MouseActionMotion})
	d = model.(*Dashboard)
	model, _ = d.Update(tea.MouseMsg{X: 5, Y: 17, Button: tea.MouseButtonLeft, Action: tea.MouseActionRelease})
	d = model.(*Dashboard)
	if _, got := d.panelBounds(); got != 17 {
		t.Fatalf("horizontal drag should resize target panel to 17, got %d", got)
	}

	model, _ = d.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	d = model.(*Dashboard)
	resizedLeftW, resizedTopH := d.panelBounds()
	if resizedLeftW < 61 || resizedLeftW > 63 {
		t.Fatalf("left split ratio should persist across terminal resize, got %d", resizedLeftW)
	}
	if resizedTopH < 22 || resizedTopH > 24 {
		t.Fatalf("vertical split ratio should persist across terminal resize, got %d", resizedTopH)
	}
}

func TestDiscoveryEnterRequestsCopyWhenDetailOpen(t *testing.T) {
	dp := NewDiscoveryPanel()
	dp.AddItemWithKey("URLs", "https://example.test/a", "https://example.test/a")
	dp.activeTab = 2
	_, _ = dp.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !dp.detailMode {
		t.Fatal("enter should open detail for the selected discovery item")
	}
	_, _ = dp.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !dp.CopyRequested {
		t.Fatal("enter in detail mode should request copying the selected item")
	}
	if dp.PendingCopyText != "https://example.test/a" {
		t.Fatalf("unexpected copy text: %q", dp.PendingCopyText)
	}
}

func TestCopyTextForFocusStripsANSI(t *testing.T) {
	d := NewDashboard(DashboardServices{})
	model, _ := d.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	d = model.(*Dashboard)
	label, text := d.copyTextForFocus()
	if label != "target panel" {
		t.Fatalf("expected target panel copy label, got %q", label)
	}
	if strings.Contains(text, "\x1b[") {
		t.Fatalf("copied text should not contain ANSI escape sequences: %q", text)
	}
	if !strings.Contains(text, "Target Configuration") {
		t.Fatalf("copied target text missing panel title: %q", text)
	}
}
