package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
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
			onFinding(convertCrawlFinding(f))
		}
	})
	findings := convertCrawlFindings(detailed)
	if err != nil {
		s.logger.ErrorContext(ctx, "crawl failed",
			slog.String("url", startURL),
			slog.String("error", err.Error()),
			slog.Int("partial_urls_found", len(findings)),
		)
		return findings, core.NewError("Discoverer.Crawl", startURL, err)
	}

	s.logger.InfoContext(ctx, "crawl completed",
		slog.Int("urls_found", len(findings)),
	)
	return findings, nil
}

func convertCrawlFindings(detailed []recon.CrawlFinding) []core.CrawlFinding {
	findings := make([]core.CrawlFinding, len(detailed))
	for i, f := range detailed {
		findings[i] = convertCrawlFinding(f)
	}
	return findings
}

func convertCrawlFinding(f recon.CrawlFinding) core.CrawlFinding {
	return core.CrawlFinding{
		URL:        f.URL,
		StatusCode: f.StatusCode,
		Depth:      f.Depth,
		SourceURL:  f.SourceURL,
		Title:      f.Status,
	}
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

	apiEndpoints := make([]core.APIEndpointFinding, len(endpoints))
	for i, ep := range endpoints {
		apiEndpoints[i] = core.APIEndpointFinding{
			URL:          ep.URL,
			Path:         ep.Path,
			Method:       ep.Method,
			APIType:      ep.APIType,
			Version:      ep.Version,
			StatusCode:   ep.StatusCode,
			Status:       ep.Status,
			ContentType:  ep.ContentType,
			AuthRequired: ep.AuthRequired,
			Confidence:   ep.Confidence,
			SourceURLs:   ep.SourceURLs,
			SourceKinds:  ep.SourceKinds,
			Evidence:     ep.Evidence,
			Parameters:   convertAPIParameters(ep.Parameters),
		}
	}

	apiSpecs := make([]core.APISpecFinding, len(specs))
	for i, sp := range specs {
		apiSpecs[i] = core.APISpecFinding{
			URL:                     sp.URL,
			APIType:                 sp.APIType,
			Format:                  sp.Format,
			Title:                   sp.Title,
			Version:                 sp.Version,
			StatusCode:              sp.StatusCode,
			Status:                  sp.Status,
			ContentType:             sp.ContentType,
			SourceURLs:              sp.SourceURLs,
			Evidence:                sp.Evidence,
			EndpointCount:           sp.EndpointCount,
			DiscoveredEndpointCount: sp.DiscoveredEndpointCount,
			CoveragePercent:         sp.CoveragePercent,
		}
	}

	s.logger.InfoContext(ctx, "API discovery completed",
		slog.Int("endpoints", len(apiEndpoints)),
		slog.Int("specs", len(apiSpecs)),
	)
	return &core.APISurfaceResult{
		APIEndpoints: apiEndpoints,
		APISpecs:     apiSpecs,
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
	}
	out.APIEndpoints = make([]core.APIEndpointFinding, len(result.APIEndpoints))
	for i, ep := range result.APIEndpoints {
		out.APIEndpoints[i] = core.APIEndpointFinding{
			URL:          ep.URL,
			Path:         ep.Path,
			Method:       ep.Method,
			APIType:      ep.APIType,
			Version:      ep.Version,
			StatusCode:   ep.StatusCode,
			Status:       ep.Status,
			ContentType:  ep.ContentType,
			AuthRequired: ep.AuthRequired,
			Confidence:   ep.Confidence,
			SourceURLs:   ep.SourceURLs,
			SourceKinds:  ep.SourceKinds,
			Evidence:     ep.Evidence,
			Parameters:   convertAPIParameters(ep.Parameters),
		}
	}
	out.APISpecs = make([]core.APISpecFinding, len(result.APISpecs))
	for i, sp := range result.APISpecs {
		out.APISpecs[i] = core.APISpecFinding{
			URL:                     sp.URL,
			APIType:                 sp.APIType,
			Format:                  sp.Format,
			Title:                   sp.Title,
			Version:                 sp.Version,
			StatusCode:              sp.StatusCode,
			Status:                  sp.Status,
			ContentType:             sp.ContentType,
			SourceURLs:              sp.SourceURLs,
			Evidence:                sp.Evidence,
			EndpointCount:           sp.EndpointCount,
			DiscoveredEndpointCount: sp.DiscoveredEndpointCount,
			CoveragePercent:         sp.CoveragePercent,
		}
	}
	out.Parameters = make([]core.APIParameterFinding, len(result.Parameters))
	for i, p := range result.Parameters {
		out.Parameters[i] = core.APIParameterFinding{
			Name:      p.Name,
			In:        p.In,
			Type:      p.Type,
			Required:  p.Required,
			Endpoints: p.Endpoints,
			Sources:   p.Sources,
		}
	}
	return out, nil
}

func convertAPIParameters(params []recon.APIParameter) []core.APIParameter {
	if len(params) == 0 {
		return nil
	}
	out := make([]core.APIParameter, len(params))
	for i, p := range params {
		out[i] = core.APIParameter{
			Name:     p.Name,
			In:       p.In,
			Required: p.Required,
			Type:     p.Type,
			Sources:  p.Sources,
		}
	}
	return out
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
