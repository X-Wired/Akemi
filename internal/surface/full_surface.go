// Package surface contains shared attack surface mapping workflows.
package surface

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	core "Akemi/internal/core"
)

// Services are the Akemi service interfaces used by the full surface map.
type Services struct {
	Scanner       core.Scanner
	Discoverer    core.Discoverer
	Prober        core.Prober
	SubEnumerator core.SubEnumerator
}

// FullSurfaceConfig mirrors the dashboard target configuration for
// full_surface_map / full_surface_scan.
type FullSurfaceConfig struct {
	Target    string
	Domain    string
	PortRange string
	Threads   int
	Timeout   int
	Depth     int
	Rate      float64
	SynMode   bool
	Randomize bool
}

// JSPageAnalysis records the page that produced a JavaScript analysis result.
type JSPageAnalysis struct {
	PageURL string                `json:"page_url"`
	Result  core.JSAnalysisResult `json:"result"`
}

// StageError captures a non-fatal workflow stage error.
type StageError struct {
	Stage string `json:"stage"`
	Error string `json:"error"`
}

// FullSurfaceResult aggregates the same result families populated by the
// dashboard full_surface_map flow.
type FullSurfaceResult struct {
	Target        string                     `json:"target"`
	StartTime     time.Time                  `json:"start_time"`
	EndTime       time.Time                  `json:"end_time"`
	PortScan      *core.ScanResult           `json:"port_scan,omitempty"`
	CrawlFindings []core.CrawlFinding        `json:"crawl_findings,omitempty"`
	Params        *core.ParamDiscoveryResult `json:"params,omitempty"`
	JSAnalysis    []JSPageAnalysis           `json:"js_analysis,omitempty"`
	APIEndpoints  []core.APIEndpointFinding  `json:"api_endpoints,omitempty"`
	APISpecs      []core.APISpecFinding      `json:"api_specs,omitempty"`
	APIParameters []core.APIParameterFinding `json:"api_parameters,omitempty"`
	Subdomains    []core.SubdomainResult     `json:"subdomains,omitempty"`
	VulnFindings  []core.VulnFinding         `json:"vuln_findings,omitempty"`
	Secrets       []core.SecretFinding       `json:"secrets,omitempty"`
	Errors        []StageError               `json:"errors,omitempty"`
	Counts        map[string]int             `json:"counts"`
	Config        map[string]interface{}     `json:"config"`
}

// Callbacks let callers stream discoveries while the workflow runs.
type Callbacks struct {
	Progress     func(stage string)
	Port         func(core.PortResult)
	CrawlFinding func(core.CrawlFinding)
	Finding      func(core.VulnFinding)
	Param        func(name string, detail core.ParamDetail)
	JSAnalysis   func(pageURL string, result *core.JSAnalysisResult)
	APIResult    func(*core.APISurfaceResult)
	APIParameter func(core.APIParameterFinding)
	Subdomain    func(core.SubdomainResult)
}

type liveCrawlDiscoverer interface {
	CrawlWithCallback(ctx context.Context, startURL string, maxDepth int, onFinding func(core.CrawlFinding)) ([]core.CrawlFinding, error)
}

type apiHunterDiscoverer interface {
	HuntAPISurface(ctx context.Context, req core.APIHuntRequest) (*core.APIHuntResult, error)
}

// RunFullSurfaceMap executes the dashboard full_surface_map service sequence:
// crawl, port scan, header/tech probes, parameter mining, JS analysis, API
// discovery, and subdomain enumeration.
func RunFullSurfaceMap(ctx context.Context, svc Services, cfg FullSurfaceConfig, cb Callbacks) (*FullSurfaceResult, error) {
	cfg = normalizeConfig(cfg)
	if strings.TrimSpace(cfg.Target) == "" {
		return nil, fmt.Errorf("target is required")
	}

	result := &FullSurfaceResult{
		Target:    cfg.Target,
		StartTime: time.Now(),
		Config: map[string]interface{}{
			"target":     cfg.Target,
			"port_range": cfg.PortRange,
			"threads":    cfg.Threads,
			"timeout":    cfg.Timeout,
			"depth":      cfg.Depth,
		},
	}
	defer func() {
		result.EndTime = time.Now()
		result.Counts = result.counts()
	}()

	checkCtx := func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}

	progress(cb, "Crawling")
	var crawledURLs []string
	if svc.Discoverer != nil {
		var findings []core.CrawlFinding
		var err error
		liveUsed := false
		if live, ok := svc.Discoverer.(liveCrawlDiscoverer); ok {
			liveUsed = true
			findings, err = live.CrawlWithCallback(ctx, cfg.Target, cfg.Depth, func(f core.CrawlFinding) {
				if cb.CrawlFinding != nil {
					cb.CrawlFinding(f)
				}
			})
		} else {
			findings, err = svc.Discoverer.Crawl(ctx, cfg.Target, cfg.Depth)
		}
		if err != nil {
			result.addError("Crawling", err)
		}
		result.CrawlFindings = append(result.CrawlFindings, findings...)
		for _, finding := range findings {
			if finding.URL != "" {
				crawledURLs = append(crawledURLs, finding.URL)
			}
			if !liveUsed && cb.CrawlFinding != nil {
				cb.CrawlFinding(finding)
			}
		}
	}
	if err := checkCtx(); err != nil {
		return result, err
	}

	progress(cb, "Port scanning")
	if svc.Scanner != nil {
		ports := ParseDashboardPorts(cfg.PortRange)
		scanReq := core.ScanRequest{
			Host:           cfg.Target,
			Ports:          ports,
			Threads:        cfg.Threads,
			TimeoutMs:      cfg.Timeout * 1000,
			Rate:           cfg.Rate,
			Retries:        1,
			SynMode:        cfg.SynMode,
			Randomize:      cfg.Randomize,
			BannerGrab:     true,
			SuppressOutput: true,
		}
		if scan, err := svc.Scanner.Scan(ctx, scanReq); err != nil {
			result.addError("Port scanning", err)
		} else if scan != nil {
			result.PortScan = scan
			for _, port := range scan.OpenPorts {
				if cb.Port != nil {
					cb.Port(port)
				}
			}
		}
	}
	if err := checkCtx(); err != nil {
		return result, err
	}

	progress(cb, "Checking headers and tech")
	if svc.Prober != nil {
		probeCfg := core.ProbeConfig{
			Threads:      cfg.Threads,
			Timeout:      cfg.Timeout,
			UseTemplates: true,
			TemplateTags: []string{"headers", "misconfig", "tech", "detect"},
		}
		if findings, err := svc.Prober.Probe(ctx, cfg.Target, probeCfg); err != nil {
			result.addError("Checking headers and tech", err)
		} else {
			result.VulnFindings = append(result.VulnFindings, findings...)
			for _, finding := range findings {
				if cb.Finding != nil {
					cb.Finding(finding)
				}
			}
		}
	}
	if err := checkCtx(); err != nil {
		return result, err
	}

	if svc.Discoverer != nil {
		progress(cb, "Mining parameters")
		miningCfg := core.MiningConfig{
			Depth:       cfg.Depth,
			Threads:     cfg.Threads,
			Timeout:     cfg.Timeout,
			MineJS:      true,
			MineForms:   true,
			MineJSON:    true,
			MinePath:    true,
			ActiveBrute: false,
		}
		if params, err := svc.Discoverer.MineParams(ctx, cfg.Target, miningCfg); err != nil {
			result.addError("Mining parameters", err)
		} else if params != nil {
			result.Params = params
			for _, name := range sortedParamNames(params.Params) {
				if cb.Param != nil {
					cb.Param(name, params.Params[name])
				}
			}
		}
		if err := checkCtx(); err != nil {
			return result, err
		}

		progress(cb, "Analyzing JavaScript")
		jsTargets := uniqueOrderedStrings(append([]string{cfg.Target}, crawledURLs...))
		for _, pageURL := range jsTargets {
			jsResult, err := svc.Discoverer.AnalyzeJS(ctx, pageURL)
			if err != nil {
				result.addError("Analyzing JavaScript", err)
			} else if jsResult != nil {
				result.JSAnalysis = append(result.JSAnalysis, JSPageAnalysis{
					PageURL: pageURL,
					Result:  *jsResult,
				})
				result.Secrets = append(result.Secrets, jsResult.Secrets...)
				result.mergeHiddenParams(pageURL, jsResult.HiddenParams)
				if cb.JSAnalysis != nil {
					cb.JSAnalysis(pageURL, jsResult)
				}
			}
			if err := checkCtx(); err != nil {
				return result, err
			}
		}

		progress(cb, "Discovering API surface")
		var apiResult *core.APISurfaceResult
		if hunter, ok := svc.Discoverer.(apiHunterDiscoverer); ok {
			huntResult, err := hunter.HuntAPISurface(ctx, core.APIHuntRequest{
				StartURL:       cfg.Target,
				DiscoveredURLs: crawledURLs,
				Mode:           "safe-active",
				MaxCandidates:  250,
				Threads:        cfg.Threads,
				Timeout:        cfg.Timeout,
			})
			if err != nil {
				result.addError("Discovering API surface", err)
			} else if huntResult != nil {
				result.APIEndpoints = append(result.APIEndpoints, huntResult.APIEndpoints...)
				result.APISpecs = append(result.APISpecs, huntResult.APISpecs...)
				result.APIParameters = append(result.APIParameters, huntResult.Parameters...)
				for _, param := range huntResult.Parameters {
					if cb.APIParameter != nil {
						cb.APIParameter(param)
					}
				}
				apiResult = &core.APISurfaceResult{APIEndpoints: huntResult.APIEndpoints, APISpecs: huntResult.APISpecs}
			}
		} else if discovered, err := svc.Discoverer.DiscoverAPISurface(ctx, cfg.Target, crawledURLs); err != nil {
			result.addError("Discovering API surface", err)
		} else {
			apiResult = discovered
			if discovered != nil {
				result.APIEndpoints = append(result.APIEndpoints, discovered.APIEndpoints...)
				result.APISpecs = append(result.APISpecs, discovered.APISpecs...)
			}
		}
		if apiResult != nil && cb.APIResult != nil {
			cb.APIResult(apiResult)
		}
	}
	if err := checkCtx(); err != nil {
		return result, err
	}

	progress(cb, "Enumerating subdomains")
	if svc.SubEnumerator != nil {
		domain := strings.TrimSpace(cfg.Domain)
		if domain == "" {
			domain = DomainFromTarget(cfg.Target)
		}
		if domain != "" {
			subCfg := core.SubdomainConfig{
				Threads:    cfg.Threads,
				Timeout:    cfg.Timeout,
				UseCrtSh:   true,
				CheckAlive: true,
			}
			if subdomains, err := svc.SubEnumerator.Enumerate(ctx, domain, subCfg); err != nil {
				result.addError("Enumerating subdomains", err)
			} else {
				result.Subdomains = append(result.Subdomains, subdomains...)
				for _, subdomain := range subdomains {
					if cb.Subdomain != nil {
						cb.Subdomain(subdomain)
					}
				}
			}
		}
	}
	if err := checkCtx(); err != nil {
		return result, err
	}

	return result, nil
}

// ParseDashboardPorts matches the target configuration dashboard semantics.
func ParseDashboardPorts(value string) []int {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "top-1000") {
		return []int{80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090}
	}
	parts := strings.Split(value, ",")
	ports := make([]int, 0, len(parts))
	seen := make(map[int]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		var port int
		fmt.Sscanf(part, "%d", &port)
		if port > 0 && port < 65536 {
			if _, ok := seen[port]; ok {
				continue
			}
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
	}
	if len(ports) == 0 {
		return []int{80, 443}
	}
	return ports
}

// DomainFromTarget extracts a domain/host for the subdomain enumeration stage.
func DomainFromTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	parsed, err := url.Parse(target)
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	if i := strings.IndexAny(target, "/:"); i >= 0 {
		target = target[:i]
	}
	return strings.TrimSpace(target)
}

// ReportData converts surface map output into the core reporting contract.
func (r *FullSurfaceResult) ReportData() *core.ReportData {
	if r == nil {
		return nil
	}
	return &core.ReportData{
		Target:        r.Target,
		StartTime:     r.StartTime,
		EndTime:       r.EndTime,
		PortScan:      r.PortScan,
		CrawlFindings: append([]core.CrawlFinding(nil), r.CrawlFindings...),
		Params:        r.Params,
		JSAnalysis:    mergedJSAnalysis(r.JSAnalysis),
		APIEndpoints:  append([]core.APIEndpointFinding(nil), r.APIEndpoints...),
		APISpecs:      append([]core.APISpecFinding(nil), r.APISpecs...),
		APIParameters: append([]core.APIParameterFinding(nil), r.APIParameters...),
		Subdomains:    append([]core.SubdomainResult(nil), r.Subdomains...),
		VulnFindings:  append([]core.VulnFinding(nil), r.VulnFindings...),
		Secrets:       append([]core.SecretFinding(nil), r.Secrets...),
	}
}

func normalizeConfig(cfg FullSurfaceConfig) FullSurfaceConfig {
	cfg.Target = strings.TrimSpace(cfg.Target)
	cfg.Domain = strings.TrimSpace(cfg.Domain)
	cfg.PortRange = strings.TrimSpace(cfg.PortRange)
	if cfg.PortRange == "" {
		cfg.PortRange = "top-1000"
	}
	if cfg.Threads <= 0 {
		cfg.Threads = 200
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10
	}
	if cfg.Depth <= 0 {
		cfg.Depth = 2
	}
	cfg.Depth = core.NormalizeCrawlDepth(cfg.Depth)
	return cfg
}

func progress(cb Callbacks, stage string) {
	if cb.Progress != nil {
		cb.Progress(stage)
	}
}

func (r *FullSurfaceResult) addError(stage string, err error) {
	if err == nil {
		return
	}
	r.Errors = append(r.Errors, StageError{Stage: stage, Error: err.Error()})
}

func (r *FullSurfaceResult) mergeHiddenParams(pageURL string, hidden []string) {
	if len(hidden) == 0 {
		return
	}
	if r.Params == nil {
		r.Params = &core.ParamDiscoveryResult{Params: map[string]core.ParamDetail{}}
	}
	if r.Params.Params == nil {
		r.Params.Params = map[string]core.ParamDetail{}
	}
	for _, name := range hidden {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, exists := r.Params.Params[name]; exists {
			continue
		}
		r.Params.Params[name] = core.ParamDetail{Name: name, Sources: []string{pageURL}}
	}
	r.Params.TotalCount = len(r.Params.Params)
}

func (r *FullSurfaceResult) counts() map[string]int {
	counts := map[string]int{
		"ports":          0,
		"urls":           len(r.CrawlFindings),
		"params":         0,
		"js_analysis":    len(r.JSAnalysis),
		"api_endpoints":  len(r.APIEndpoints),
		"api_specs":      len(r.APISpecs),
		"api_parameters": len(r.APIParameters),
		"subdomains":     len(r.Subdomains),
		"vuln_findings":  len(r.VulnFindings),
		"secrets":        len(r.Secrets),
		"stage_errors":   len(r.Errors),
	}
	if r.PortScan != nil {
		counts["ports"] = len(r.PortScan.OpenPorts)
	}
	if r.Params != nil {
		counts["params"] = len(r.Params.Params)
	}
	return counts
}

func sortedParamNames(params map[string]core.ParamDetail) []string {
	names := make([]string, 0, len(params))
	for name := range params {
		if strings.TrimSpace(name) != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func uniqueOrderedStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func mergedJSAnalysis(captures []JSPageAnalysis) *core.JSAnalysisResult {
	if len(captures) == 0 {
		return nil
	}
	out := &core.JSAnalysisResult{}
	for _, capture := range captures {
		out.ScriptURLs = append(out.ScriptURLs, capture.Result.ScriptURLs...)
		out.Endpoints = append(out.Endpoints, capture.Result.Endpoints...)
		out.Secrets = append(out.Secrets, capture.Result.Secrets...)
		out.HiddenParams = append(out.HiddenParams, capture.Result.HiddenParams...)
	}
	out.ScriptURLs = uniqueOrderedStrings(out.ScriptURLs)
	out.Endpoints = uniqueOrderedStrings(out.Endpoints)
	out.HiddenParams = uniqueOrderedStrings(out.HiddenParams)
	return out
}
