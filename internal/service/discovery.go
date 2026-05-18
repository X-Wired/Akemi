package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	core "Akemi/internal/core"
	recon "Akemi/internal/recon"
)

// DiscoveryService implements core.Discoverer using the recon package.
type DiscoveryService struct {
	logger *slog.Logger
}

// NewDiscoveryService creates a DiscoveryService.
func NewDiscoveryService(logger *slog.Logger) *DiscoveryService {
	if logger == nil {
		logger = core.Logger()
	}
	return &DiscoveryService{logger: logger}
}

// Crawl discovers URLs by crawling from a start URL.
func (s *DiscoveryService) Crawl(ctx context.Context, startURL string, maxDepth int) ([]core.CrawlFinding, error) {
	return s.CrawlWithCallback(ctx, startURL, maxDepth, nil)
}

// CrawlAndMine streams crawl discoveries directly into parameter mining.
// As the crawler discovers each URL it is immediately farmed out to a pool
// of MinePageParams workers. This eliminates the double-crawl problem: when
// --crawl and --params are used together the crawl happens once and param
// mining runs concurrently on the live URL stream (Phase 2.2 optimization).
func (s *DiscoveryService) CrawlAndMine(ctx context.Context, startURL string, maxDepth int, miningCfg core.MiningConfig, onFinding func(core.CrawlFinding)) ([]core.CrawlFinding, *core.ParamDiscoveryResult, error) {
	defer core.LogDuration(ctx, "Discoverer.CrawlAndMine", time.Now())
	maxDepth = core.NormalizeCrawlDepth(maxDepth)

	s.logger.InfoContext(ctx, "starting crawl-and-mine pipeline",
		slog.String("url", startURL),
		slog.Int("max_depth", maxDepth),
	)

	reconCfg := recon.MiningConfig{
		Depth:             miningCfg.Depth,
		Threads:           miningCfg.Threads,
		Timeout:           miningCfg.Timeout,
		MineJS:            miningCfg.MineJS,
		MineForms:         miningCfg.MineForms,
		MineJSONResponses: miningCfg.MineJSON,
		MinePathParams:    miningCfg.MinePath,
		ActiveBrute:       miningCfg.ActiveBrute,
		Keywords:          miningCfg.Keywords,
		MineKeywords:      miningCfg.MineKeywords,
		Quiet:             true,
	}
	if reconCfg.Threads <= 0 {
		reconCfg.Threads = 10
	}
	if reconCfg.Timeout <= 0 {
		reconCfg.Timeout = 10
	}

	urlCh := make(chan string, 200)
	client := core.CreateHTTPClient(reconCfg.Timeout)

	var mu sync.Mutex
	aggregated := make(map[string]core.ParamDetail)

	workerCount := reconCfg.Threads
	var workerWg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for pageURL := range urlCh {
				if ctx.Err() != nil {
					return
				}
				analysis := recon.MinePageParams(ctx, pageURL, reconCfg, client)
				if len(analysis.ParamDetails) == 0 {
					continue
				}
				mu.Lock()
				for name, detail := range analysis.ParamDetails {
					if existing, ok := aggregated[name]; ok {
						existing.Sources = append(existing.Sources, detail.Sources...)
						existing.Examples = append(existing.Examples, detail.Values...)
						aggregated[name] = existing
					} else {
						aggregated[name] = core.ParamDetail{
							Name:     name,
							Sources:  detail.Sources,
							Examples: detail.Values,
						}
					}
				}
				mu.Unlock()
			}
		}()
	}

	crawlFindings, crawlErr := s.CrawlWithCallback(ctx, startURL, maxDepth, func(f core.CrawlFinding) {
		if onFinding != nil {
			onFinding(f)
		}
		if f.StatusCode >= 200 && f.StatusCode < 400 {
			select {
			case urlCh <- f.URL:
			case <-ctx.Done():
			default:
			}
		}
	})

	// Signal workers: no more URLs
	close(urlCh)
	workerWg.Wait()

	paramResult := &core.ParamDiscoveryResult{
		Params:     aggregated,
		TotalCount: len(aggregated),
	}

	s.logger.InfoContext(ctx, "crawl-and-mine pipeline completed",
		slog.Int("urls_crawled", len(crawlFindings)),
		slog.Int("params_found", len(aggregated)),
	)

	return crawlFindings, paramResult, crawlErr
}

// CrawlWithCallback discovers URLs and reports each crawl result as it arrives.
func (s *DiscoveryService) CrawlWithCallback(ctx context.Context, startURL string, maxDepth int, onFinding func(core.CrawlFinding)) ([]core.CrawlFinding, error) {
	defer core.LogDuration(ctx, "Discoverer.Crawl", time.Now())
	maxDepth = core.NormalizeCrawlDepth(maxDepth)
	maxURLs := core.CrawlURLLimitForDepth(maxDepth)
	s.logger.InfoContext(ctx, "starting crawl",
		slog.String("url", startURL),
		slog.Int("max_depth", maxDepth),
		slog.Int("max_urls", maxURLs),
	)

	select {
	case <-ctx.Done():
		return nil, core.NewError("Discoverer.Crawl", startURL, ctx.Err())
	default:
	}

	detailed, err := recon.CrawlDetailedWithCallbackContext(ctx, startURL, maxDepth, func(f recon.CrawlFinding) {
		if onFinding != nil {
			onFinding(f) // Phase 1.3: no conversion — type alias
		}
	})
	if err != nil {
		s.logger.ErrorContext(ctx, "crawl failed",
			slog.String("url", startURL),
			slog.String("error", err.Error()),
			slog.Int("partial_urls_found", len(detailed)),
		)
		return detailed, core.NewError("Discoverer.Crawl", startURL, err)
	}

	s.logger.InfoContext(ctx, "crawl completed",
		slog.Int("urls_found", len(detailed)),
	)
	return detailed, nil
}

// MineParams discovers HTTP parameters from a target URL.
func (s *DiscoveryService) MineParams(ctx context.Context, targetURL string, cfg core.MiningConfig) (*core.ParamDiscoveryResult, error) {
	defer core.LogDuration(ctx, "Discoverer.MineParams", time.Now())
	s.logger.InfoContext(ctx, "mining parameters",
		slog.String("url", targetURL),
	)

	select {
	case <-ctx.Done():
		return nil, core.NewError("Discoverer.MineParams", targetURL, ctx.Err())
	default:
	}

	miningCfg := recon.MiningConfig{
		Depth:             cfg.Depth,
		Threads:           cfg.Threads,
		Timeout:           cfg.Timeout,
		MineJS:            cfg.MineJS,
		MineForms:         cfg.MineForms,
		MineJSONResponses: cfg.MineJSON,
		MinePathParams:    cfg.MinePath,
		ActiveBrute:       cfg.ActiveBrute,
		Keywords:          cfg.Keywords,
		MineKeywords:      cfg.MineKeywords,
		Quiet:             true,
	}

	result, err := recon.EnhancedDiscoverParams(targetURL, miningCfg)
	if err != nil {
		return nil, core.NewError("Discoverer.MineParams", targetURL, err)
	}

	// Convert param details
	params := make(map[string]core.ParamDetail, len(result.Params))
	for name, detail := range result.Params {
		params[name] = core.ParamDetail{
			Name:     name,
			Sources:  detail.Sources,
			Examples: detail.Values,
		}
	}

	s.logger.InfoContext(ctx, "parameter mining completed",
		slog.Int("params_found", len(params)),
	)
	return &core.ParamDiscoveryResult{
		Params:     params,
		TotalCount: len(params),
	}, nil
}

// AnalyzeJS fetches and analyzes JavaScript files.
func (s *DiscoveryService) AnalyzeJS(ctx context.Context, pageURL string) (*core.JSAnalysisResult, error) {
	defer core.LogDuration(ctx, "Discoverer.AnalyzeJS", time.Now())
	s.logger.InfoContext(ctx, "analyzing JavaScript",
		slog.String("url", pageURL),
	)

	select {
	case <-ctx.Done():
		return nil, core.NewError("Discoverer.AnalyzeJS", pageURL, ctx.Err())
	default:
	}

	result, err := recon.AnalyzeJS(pageURL)
	if err != nil {
		return nil, core.NewError("Discoverer.AnalyzeJS", pageURL, err)
	}

	// Convert secrets
	secrets := make([]core.SecretFinding, len(result.SecretFindings))
	for i, s := range result.SecretFindings {
		evidence := ""
		if len(s.Evidence) > 0 {
			evidence = strings.Join(s.Evidence, "; ")
		}
		secrets[i] = core.SecretFinding{
			Category:   s.Category,
			Value:      s.Value,
			SourceURL:  s.SourceURL,
			SourceKind: s.SourceKind,
			Evidence:   evidence,
		}
	}

	s.logger.InfoContext(ctx, "JS analysis completed",
		slog.Int("scripts", len(result.ScriptURLs)),
		slog.Int("endpoints", len(result.Endpoints)),
		slog.Int("secrets", len(secrets)),
	)
	return &core.JSAnalysisResult{
		ScriptURLs:   result.ScriptURLs,
		Endpoints:    result.Endpoints,
		Secrets:      secrets,
		HiddenParams: result.HiddenParams,
	}, nil
}

// ScrapePage scrapes a page for structured data.
func (s *DiscoveryService) ScrapePage(ctx context.Context, pageURL string, keywords []string) (*core.ScrapeResult, error) {
	defer core.LogDuration(ctx, "Discoverer.ScrapePage", time.Now())

	select {
	case <-ctx.Done():
		return nil, core.NewError("Discoverer.ScrapePage", pageURL, ctx.Err())
	default:
	}

	result, err := recon.ScrapePage(pageURL, keywords)
	if err != nil {
		return nil, core.NewError("Discoverer.ScrapePage", pageURL, err)
	}

	// Convert forms
	forms := make([]core.FormInfo, len(result.Forms))
	for i, f := range result.Forms {
		inputs := make([]core.InputField, len(f.Inputs))
		for j, inp := range f.Inputs {
			inputs[j] = core.InputField{
				Name:       inp.Name,
				Type:       inp.Type,
				Value:      inp.Value,
				Vulnerable: inp.Vulnerable,
			}
		}
		forms[i] = core.FormInfo{
			Action: f.Action,
			Method: f.Method,
			Inputs: inputs,
		}
	}

	return &core.ScrapeResult{
		Title:          result.Title,
		Description:    result.Description,
		MetaTags:       result.MetaTags,
		Links:          result.Links,
		Forms:          forms,
		Comments:       result.Comments,
		KeywordMatches: result.KeywordMatches,
	}, nil
}

// DiscoverAPISurface discovers API endpoints and specifications.
func (s *DiscoveryService) DiscoverAPISurface(ctx context.Context, startURL string, discoveredURLs []string) (*core.APISurfaceResult, error) {
	defer core.LogDuration(ctx, "Discoverer.DiscoverAPISurface", time.Now())

	select {
	case <-ctx.Done():
		return nil, core.NewError("Discoverer.DiscoverAPISurface", startURL, ctx.Err())
	default:
	}

	client := core.CreateHTTPClient(10)
	endpoints, specs, err := recon.DiscoverAPISurface(startURL, discoveredURLs, nil, client)
	if err != nil {
		return nil, core.NewError("Discoverer.DiscoverAPISurface", startURL, err)
	}

	// Phase 1.3: recon types are aliases for core types — direct use, no conversion.
	s.logger.InfoContext(ctx, "API discovery completed",
		slog.Int("endpoints", len(endpoints)),
		slog.Int("specs", len(specs)),
	)
	return &core.APISurfaceResult{
		APIEndpoints: endpoints,
		APISpecs:     specs,
	}, nil
}

// HuntAPISurface performs richer API discovery with optional safe-active probing.
func (s *DiscoveryService) HuntAPISurface(ctx context.Context, req core.APIHuntRequest) (*core.APIHuntResult, error) {
	defer core.LogDuration(ctx, "Discoverer.HuntAPISurface", time.Now())
	if strings.TrimSpace(req.StartURL) == "" {
		return nil, core.NewError("Discoverer.HuntAPISurface", req.StartURL, fmt.Errorf("start_url is required"))
	}

	select {
	case <-ctx.Done():
		return nil, core.NewError("Discoverer.HuntAPISurface", req.StartURL, ctx.Err())
	default:
	}

	client := core.CreateHTTPClientWithCookies(firstPositive(req.Timeout, 10), req.AuthCookies)
	result, err := recon.HuntAPISurface(recon.APIHuntRequest{
		StartURL:       req.StartURL,
		DiscoveredURLs: req.DiscoveredURLs,
		Mode:           req.Mode,
		Wordlist:       req.Wordlist,
		WordlistFile:   req.WordlistFile,
		AuthCookies:    req.AuthCookies,
		MaxCandidates:  req.MaxCandidates,
		Threads:        req.Threads,
		Timeout:        req.Timeout,
	}, client)
	if err != nil {
		return nil, core.NewError("Discoverer.HuntAPISurface", req.StartURL, err)
	}
	if result == nil {
		return &core.APIHuntResult{}, nil
	}

	out := &core.APIHuntResult{
		StartURL:      result.StartURL,
		Mode:          result.Mode,
		Counts:        result.Counts,
		StageErrors:   result.StageErrors,
		SourceSummary: result.SourceSummary,
		// Phase 1.3: recon types are core type aliases — direct assignment.
		APIEndpoints: result.APIEndpoints,
		APISpecs:     result.APISpecs,
		Parameters:   result.Parameters,
	}
	return out, nil
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

// Ensure DiscoveryService implements core.Discoverer at compile time.
var _ core.Discoverer = (*DiscoveryService)(nil)
