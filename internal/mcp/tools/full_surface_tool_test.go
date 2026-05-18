package tools

import (
	"context"
	"testing"

	core "Akemi/internal/core"
	"Akemi/internal/toolbridge"
)

type fakeFullSurfaceDiscoverer struct{}

func (fakeFullSurfaceDiscoverer) Crawl(ctx context.Context, startURL string, maxDepth int) ([]core.CrawlFinding, error) {
	return []core.CrawlFinding{{URL: startURL + "/users", StatusCode: 200, Title: "Users"}}, nil
}

func (fakeFullSurfaceDiscoverer) MineParams(ctx context.Context, targetURL string, cfg core.MiningConfig) (*core.ParamDiscoveryResult, error) {
	return &core.ParamDiscoveryResult{Params: map[string]core.ParamDetail{}}, nil
}

func (fakeFullSurfaceDiscoverer) CrawlAndMine(ctx context.Context, startURL string, maxDepth int, cfg core.MiningConfig, onFinding func(core.CrawlFinding)) ([]core.CrawlFinding, *core.ParamDiscoveryResult, error) {
	findings, _ := fakeFullSurfaceDiscoverer{}.Crawl(ctx, startURL, maxDepth)
	if onFinding != nil {
		for _, f := range findings {
			onFinding(f)
		}
	}
	return findings, &core.ParamDiscoveryResult{Params: map[string]core.ParamDetail{}}, nil
}

func (fakeFullSurfaceDiscoverer) AnalyzeJS(ctx context.Context, pageURL string) (*core.JSAnalysisResult, error) {
	return &core.JSAnalysisResult{}, nil
}

func (fakeFullSurfaceDiscoverer) ScrapePage(ctx context.Context, pageURL string, keywords []string) (*core.ScrapeResult, error) {
	return &core.ScrapeResult{}, nil
}

func (fakeFullSurfaceDiscoverer) DiscoverAPISurface(ctx context.Context, startURL string, discoveredURLs []string) (*core.APISurfaceResult, error) {
	return &core.APISurfaceResult{}, nil
}

func (fakeFullSurfaceDiscoverer) HuntAPISurface(ctx context.Context, req core.APIHuntRequest) (*core.APIHuntResult, error) {
	return &core.APIHuntResult{
		Parameters: []core.APIParameterFinding{{
			Name:      "id",
			In:        "query",
			Type:      "string",
			Endpoints: []string{"/api/users"},
			Sources:   []string{"openapi"},
		}},
	}, nil
}

func TestFullSurfaceScanAliasCallsFullSurfaceMap(t *testing.T) {
	reg := NewToolRegistry(ToolRegistryConfig{
		Discoverer: fakeFullSurfaceDiscoverer{},
	})

	listed := false
	for _, tool := range reg.List() {
		if tool.Name == "akemi_full_surface_scan" {
			listed = true
			break
		}
	}
	if !listed {
		t.Fatal("akemi_full_surface_scan alias is not listed in the MCP contract")
	}

	result, err := reg.CallStructured(context.Background(), "akemi_full_surface_scan", map[string]interface{}{
		"target": "https://example.test",
		"depth":  1,
	})
	if err != nil {
		t.Fatalf("alias call failed: %v", err)
	}
	if result == nil || result.StructuredContent == nil {
		t.Fatal("alias call did not return structured full surface content")
	}
	if got := result.Meta["akemi/tool"]; got != "akemi_full_surface_map" {
		t.Fatalf("alias should record canonical tool name, got %v", got)
	}
}

func TestFullSurfaceMapToolStreamsProgressAndAPIParameters(t *testing.T) {
	var events []toolbridge.Event
	svc := &Services{
		Discoverer: fakeFullSurfaceDiscoverer{},
		EventSink: toolbridge.SinkFunc(func(ctx context.Context, event toolbridge.Event) {
			events = append(events, event)
		}),
	}

	if _, err := handleFullSurfaceMap(context.Background(), map[string]interface{}{
		"target": "https://example.test",
		"depth":  1,
	}, svc); err != nil {
		t.Fatalf("full surface map failed: %v", err)
	}

	var sawCrawlingProgress bool
	var sawAPIParameter bool
	for _, event := range events {
		if event.Phase == "Crawling" && len(event.Discoveries) == 0 {
			sawCrawlingProgress = true
		}
		for _, item := range event.Discoveries {
			if item.Section == "Params" && item.Key == "api|query|id" {
				sawAPIParameter = true
			}
		}
	}
	if !sawCrawlingProgress {
		t.Fatal("full surface map did not stream phase progress before results")
	}
	if !sawAPIParameter {
		t.Fatal("API parameters were not streamed to the dashboard bridge")
	}
}
