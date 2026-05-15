package dashboard

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	core "Akemi/internal/core"

	tea "github.com/charmbracelet/bubbletea"
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
