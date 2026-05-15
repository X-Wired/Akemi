package service

import (
	"context"
	"log/slog"
	"time"

	core "Akemi/internal/core"
	reporting "Akemi/internal/reporting"
)

// ReportingService implements core.Reporter using the reporting package.
type ReportingService struct {
	logger    *slog.Logger
	outputDir string
}

// NewReportingService creates a ReportingService.
func NewReportingService(logger *slog.Logger, outputDir string) *ReportingService {
	if logger == nil {
		logger = core.Logger()
	}
	if outputDir == "" {
		outputDir = "."
	}
	return &ReportingService{logger: logger, outputDir: outputDir}
}

// GenerateReport produces an HTML and/or JSON report from scan data.
func (s *ReportingService) GenerateReport(ctx context.Context, data *core.ReportData) (*core.Report, error) {
	defer core.LogDuration(ctx, "Reporter.GenerateReport", time.Now())
	s.logger.InfoContext(ctx, "generating report",
		slog.String("target", data.Target),
	)

	select {
	case <-ctx.Done():
		return nil, core.NewError("Reporter.GenerateReport", data.Target, ctx.Err())
	default:
	}

	// Convert core.ReportData to the legacy ScanReport
	scanReport := reporting.NewScanReport(data.Target)
	scanReport.StartTime = data.StartTime
	scanReport.EndTime = data.EndTime

	// Populate legacy fields from core data
	if data.PortScan != nil {
		scanReport.PortScanData = &reporting.PortScanSummary{
			Hostname:     data.PortScan.Hostname,
			IPs:          data.PortScan.IPs,
			OSHint:       data.PortScan.OSHint,
			ScanTimeMs:   data.PortScan.ScanTimeMs,
			TotalScanned: data.PortScan.TotalScanned,
			ScanMode:     data.PortScan.ScanMode,
		}
		for _, p := range data.PortScan.OpenPorts {
			scanReport.PortScanData.Results = append(scanReport.PortScanData.Results, reporting.PortScanResult{
				Port:       p.Port,
				State:      p.State,
				Banner:     p.Banner,
				Technology: p.Technology,
				Service:    p.Service,
				Version:    p.Version,
				TLS:        p.TLS,
				TLSCN:      p.TLSCN,
			})
		}
	}

	// Crawl findings
	if data.CrawlFindings != nil {
		scanReport.CrawlDetails = make([]reporting.CrawlFinding, len(data.CrawlFindings))
		for i, f := range data.CrawlFindings {
			scanReport.CrawlDetails[i] = reporting.CrawlFinding{
				URL:        f.URL,
				StatusCode: f.StatusCode,
				Status:     f.Title,
			}
		}
	}

	if len(data.APIEndpoints) > 0 {
		scanReport.APIEndpoints = make([]reporting.APIEndpointFinding, len(data.APIEndpoints))
		for i, ep := range data.APIEndpoints {
			scanReport.APIEndpoints[i] = reporting.APIEndpointFinding{
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
			}
			for _, param := range ep.Parameters {
				scanReport.APIEndpoints[i].Parameters = append(scanReport.APIEndpoints[i].Parameters, reporting.APIParameter{
					Name:     param.Name,
					In:       param.In,
					Required: param.Required,
					Type:     param.Type,
					Sources:  param.Sources,
				})
			}
		}
	}

	if len(data.APISpecs) > 0 {
		scanReport.APISpecs = make([]reporting.APISpecFinding, len(data.APISpecs))
		for i, sp := range data.APISpecs {
			scanReport.APISpecs[i] = reporting.APISpecFinding{
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
	}

	if len(data.APIParameters) > 0 {
		scanReport.APIParameters = make([]reporting.APIParameterFinding, len(data.APIParameters))
		for i, param := range data.APIParameters {
			scanReport.APIParameters[i] = reporting.APIParameterFinding{
				Name:      param.Name,
				In:        param.In,
				Type:      param.Type,
				Required:  param.Required,
				Endpoints: param.Endpoints,
				Sources:   param.Sources,
			}
		}
	}

	// Vuln findings
	if data.VulnFindings != nil {
		scanReport.VulnFindings = make([]reporting.VulnFinding, len(data.VulnFindings))
		for i, f := range data.VulnFindings {
			scanReport.VulnFindings[i] = reporting.VulnFinding{
				Severity: f.Severity,
				Evidence: f.Evidence,
				URL:      f.Target,
			}
		}
	}

	scanReport.Finalize()

	// Save report files
	report := &core.Report{
		Summary: core.ReportSummary{
			Target:     data.Target,
			Duration:   data.EndTime.Sub(data.StartTime).String(),
			TotalVulns: len(data.VulnFindings),
		},
	}

	// Generate HTML report
	reportPath := s.outputDir
	htmlErr := scanReport.SaveHTML(reportPath, nil)
	if htmlErr != nil {
		s.logger.WarnContext(ctx, "HTML report generation failed",
			slog.String("error", htmlErr.Error()),
		)
	} else {
		report.HTMLPath = reportPath + "/report.html"
	}

	// Generate JSON report
	jsonErr := scanReport.SaveJSON(reportPath)
	if jsonErr != nil {
		s.logger.WarnContext(ctx, "JSON report generation failed",
			slog.String("error", jsonErr.Error()),
		)
	} else {
		report.JSONPath = reportPath + "/report.json"
	}

	// Populate summary
	summary := scanReport.Summary()
	report.Summary = core.ReportSummary{
		Target:          summary.Target,
		Duration:        summary.Duration,
		TotalURLs:       summary.TotalURLs,
		TotalParams:     summary.TotalParams,
		TotalSubdomains: summary.TotalSubdomains,
		TotalVulns:      summary.TotalVulns,
		HighSeverity:    summary.HighSeverity,
		MediumSeverity:  summary.MediumSeverity,
		LowSeverity:     summary.LowSeverity,
		TotalSecrets:    summary.TotalSecrets,
	}

	s.logger.InfoContext(ctx, "report generated",
		slog.String("html_path", report.HTMLPath),
		slog.String("json_path", report.JSONPath),
	)
	return report, nil
}

// GenerateGraph produces a relational graph from scan data.
func (s *ReportingService) GenerateGraph(ctx context.Context, data *core.ReportData) (*core.GraphData, error) {
	defer core.LogDuration(ctx, "Reporter.GenerateGraph", time.Now())
	s.logger.InfoContext(ctx, "generating graph",
		slog.String("target", data.Target),
	)

	select {
	case <-ctx.Done():
		return nil, core.NewError("Reporter.GenerateGraph", data.Target, ctx.Err())
	default:
	}

	// Build legacy report for graph generation
	scanReport := reporting.NewScanReport(data.Target)
	scanReport.Finalize()

	graph := reporting.BuildGraph(scanReport)

	nodes := make([]core.GraphNode, len(graph.Nodes))
	for i, n := range graph.Nodes {
		nodes[i] = core.GraphNode{
			ID:    n.ID,
			Label: n.Label,
			Type:  n.Type,
		}
	}

	edges := make([]core.GraphEdge, len(graph.Edges))
	for i, e := range graph.Edges {
		edges[i] = core.GraphEdge{
			Source: e.Source,
			Target: e.Target,
			Label:  e.Label,
		}
	}

	s.logger.InfoContext(ctx, "graph generated",
		slog.Int("nodes", len(nodes)),
		slog.Int("edges", len(edges)),
	)
	return &core.GraphData{
		Nodes: nodes,
		Edges: edges,
	}, nil
}

// Ensure ReportingService implements core.Reporter at compile time.
var _ core.Reporter = (*ReportingService)(nil)
