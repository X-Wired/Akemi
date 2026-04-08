package reporting

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// graphJSONForTemplate serializes the graph into a JSON string safe for embedding in HTML.
func graphJSONForTemplate(g *ScanGraph) (string, string) {
	if g == nil || len(g.Nodes) == 0 {
		return "[]", "[]"
	}
	nodesJSON, _ := json.Marshal(g.Nodes)
	edgesJSON, _ := json.Marshal(g.Edges)
	return string(nodesJSON), string(edgesJSON)
}

// =============================================================
// ── SCAN REPORT DATA MODEL ──────────────────────────────────
// =============================================================

// ScanReport aggregates all scan data into a single exportable structure.
type ScanReport struct {
	Target          string                     `json:"target"`
	StartTime       time.Time                  `json:"start_time"`
	EndTime         time.Time                  `json:"end_time"`
	Duration        string                     `json:"duration"`
	PortScanData    *PortScanSummary           `json:"portscan_data,omitempty"`
	CrawlResults    []string                   `json:"crawl_results,omitempty"`
	CrawlDetails    []CrawlFinding             `json:"crawl_details,omitempty"`
	ScrapeData      *ScrapeResult              `json:"scrape_data,omitempty"`
	ParamMining     map[string]RichParamDetail `json:"param_mining,omitempty"`
	JSAnalysis      *JSAnalysisResult          `json:"js_analysis,omitempty"`
	ConfigResources []string                   `json:"config_resources,omitempty"`
	SecretFindings  []SecretFinding            `json:"secret_findings,omitempty"`
	APIEndpoints    []APIEndpointFinding       `json:"api_endpoints,omitempty"`
	APISpecs        []APISpecFinding           `json:"api_specs,omitempty"`
	Subdomains      []SubdomainResult          `json:"subdomains,omitempty"`
	VulnFindings    []VulnFinding              `json:"vuln_findings,omitempty"`
	FuzzResults     []FuzzResult               `json:"fuzz_results,omitempty"`
	KeywordMatches  map[string][]string        `json:"keyword_matches,omitempty"`
	ExploitMatches  []ExploitDBEntry           `json:"exploit_matches,omitempty"`
}

// ReportSummary is a computed summary for the HTML report header.
type ReportSummary struct {
	Target          string
	Duration        string
	TotalURLs       int
	TotalParams     int
	TotalSubdomains int
	TotalVulns      int
	HighSeverity    int
	MediumSeverity  int
	LowSeverity     int
	TotalSecrets    int
	TotalFuzz       int
}

// NewScanReport creates a new report for a given target.
func NewScanReport(target string) *ScanReport {
	return &ScanReport{
		Target:    target,
		StartTime: time.Now(),
	}
}

// Finalize sets the end time and duration on the report.
func (r *ScanReport) Finalize() {
	r.EndTime = time.Now()
	r.Duration = r.EndTime.Sub(r.StartTime).Round(time.Millisecond).String()
}

// Summary computes a ReportSummary from the report data.
func (r *ScanReport) Summary() ReportSummary {
	s := ReportSummary{
		Target:          r.Target,
		Duration:        r.Duration,
		TotalParams:     len(r.ParamMining),
		TotalSubdomains: len(r.Subdomains),
		TotalVulns:      len(r.VulnFindings),
		TotalFuzz:       len(r.FuzzResults),
	}
	if len(r.CrawlDetails) > 0 {
		s.TotalURLs = len(r.CrawlDetails)
	} else {
		s.TotalURLs = len(r.CrawlResults)
	}

	for _, f := range r.VulnFindings {
		switch f.Severity {
		case "HIGH":
			s.HighSeverity++
		case "MEDIUM":
			s.MediumSeverity++
		case "LOW":
			s.LowSeverity++
		}
	}

	if len(r.SecretFindings) > 0 {
		s.TotalSecrets = len(r.SecretFindings)
	} else if r.JSAnalysis != nil {
		for _, v := range r.JSAnalysis.Secrets {
			s.TotalSecrets += len(v)
		}
	}

	return s
}

// =============================================================
// ── JSON EXPORT ─────────────────────────────────────────────
// =============================================================

// SaveJSON writes the report as formatted JSON to the given path.
func (r *ScanReport) SaveJSON(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling report: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("error writing report: %w", err)
	}

	fmt.Printf("[+] JSON report saved to: %s\n", path)
	return nil
}

// =============================================================
// ── HTML EXPORT ─────────────────────────────────────────────
// =============================================================

// SaveHTML generates a self-contained HTML security report with optional embedded graph.
// WriteHTML generates a self-contained HTML security report with optional embedded graph to a writer.
func (r *ScanReport) WriteHTML(w io.Writer, graph *ScanGraph) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"upper":    strings.ToUpper,
		"join":     strings.Join,
		"severity": severityClass,
		"statusClass": func(code int) string {
			switch {
			case code >= 500:
				return "severity-high"
			case code >= 400:
				return "severity-medium"
			case code >= 300:
				return "severity-low"
			case code >= 200:
				return "severity-low"
			default:
				return "tag"
			}
		},
		"sortedCrawlDetails": func(items []CrawlFinding) []CrawlFinding {
			cloned := append([]CrawlFinding(nil), items...)
			sort.Slice(cloned, func(i, j int) bool {
				return crawlFindingLessForReport(cloned[i], cloned[j])
			})
			return cloned
		},
		"len": func(v interface{}) int {
			switch val := v.(type) {
			case []string:
				return len(val)
			case []CrawlFinding:
				return len(val)
			case []VulnFinding:
				return len(val)
			case []SubdomainResult:
				return len(val)
			case []FuzzResult:
				return len(val)
			case []SecretFinding:
				return len(val)
			case []APIEndpointFinding:
				return len(val)
			case []APISpecFinding:
				return len(val)
			case map[string]RichParamDetail:
				return len(val)
			case map[string]string:
				return len(val)
			case map[string][]string:
				return len(val)
			default:
				return 0
			}
		},
	}).Parse(htmlReportTemplate)
	if err != nil {
		return fmt.Errorf("error parsing HTML template: %w", err)
	}

	nodesJSON, edgesJSON := graphJSONForTemplate(graph)
	hasGraph := graph != nil && len(graph.Nodes) > 0

	data := struct {
		Report    *ScanReport
		Summary   ReportSummary
		HasGraph  bool
		NodesJSON template.JS
		EdgesJSON template.JS
		NodeCount int
		EdgeCount int
	}{
		Report:    r,
		Summary:   r.Summary(),
		HasGraph:  hasGraph,
		NodesJSON: template.JS(nodesJSON),
		EdgesJSON: template.JS(edgesJSON),
	}
	if hasGraph {
		data.NodeCount = len(graph.Nodes)
		data.EdgeCount = len(graph.Edges)
	}

	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("error rendering HTML: %w", err)
	}
	return nil
}

// SaveHTML wrapper
func (r *ScanReport) SaveHTML(path string, graph *ScanGraph) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("error creating HTML file: %w", err)
	}
	defer f.Close()

	if err := r.WriteHTML(f, graph); err != nil {
		return err
	}

	fmt.Printf("[+] HTML report saved to: %s\n", path)
	return nil
}

func severityClass(s string) string {
	switch strings.ToUpper(s) {
	case "HIGH":
		return "severity-high"
	case "MEDIUM":
		return "severity-medium"
	case "LOW":
		return "severity-low"
	default:
		return "severity-info"
	}
}

func crawlFindingLessForReport(left CrawlFinding, right CrawlFinding) bool {
	leftPriority := crawlFindingPriorityForReport(left.StatusCode)
	rightPriority := crawlFindingPriorityForReport(right.StatusCode)
	if leftPriority != rightPriority {
		return leftPriority < rightPriority
	}
	leftCode := normalizedStatusCodeForReport(left.StatusCode)
	rightCode := normalizedStatusCodeForReport(right.StatusCode)
	if leftCode != rightCode {
		return leftCode < rightCode
	}
	return left.URL < right.URL
}

func crawlFindingPriorityForReport(statusCode int) int {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return 0
	case statusCode == 404:
		return 2
	default:
		return 1
	}
}

func normalizedStatusCodeForReport(statusCode int) int {
	if statusCode == 0 {
		return 999
	}
	return statusCode
}

// =============================================================
// ── HTML TEMPLATE ───────────────────────────────────────────
// =============================================================

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Akemi Scan Report — {{.Summary.Target}}</title>
<style>
:root {
  --bg: #0d1117; --surface: #161b22; --surface2: #21262d;
  --border: #30363d; --text: #c9d1d9; --text-muted: #8b949e;
  --accent: #58a6ff; --high: #f85149; --medium: #d29922; --low: #3fb950;
  --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: var(--font); line-height: 1.6; padding: 2rem; }
.container { max-width: 1200px; margin: 0 auto; }
h1 { color: var(--accent); font-size: 1.8rem; margin-bottom: 0.5rem; }
h2 { color: var(--accent); font-size: 1.3rem; margin: 1.5rem 0 0.8rem; border-bottom: 1px solid var(--border); padding-bottom: 0.4rem; }
h3 { color: var(--text); font-size: 1.1rem; margin: 1rem 0 0.5rem; }
.subtitle { color: var(--text-muted); font-size: 0.9rem; }
.header { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin: 1rem 0; }
.stat-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; text-align: center; }
.stat-card .value { font-size: 2rem; font-weight: 700; color: var(--accent); }
.stat-card .label { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; }
.stat-card.high .value { color: var(--high); }
.stat-card.medium .value { color: var(--medium); }
.stat-card.low .value { color: var(--low); }
.section { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
.section-header { padding: 0.8rem 1.2rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center; background: var(--surface2); user-select: none; }
.section-header:hover { background: var(--border); }
.section-header .count { background: var(--accent); color: var(--bg); border-radius: 12px; padding: 0.1rem 0.6rem; font-size: 0.8rem; font-weight: 600; }
.section-body { padding: 1rem 1.2rem; display: none; }
.section-body.open { display: block; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th, td { padding: 0.5rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); }
th { color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
.severity-high { color: var(--high); font-weight: 700; }
.severity-medium { color: var(--medium); font-weight: 700; }
.severity-low { color: var(--low); font-weight: 700; }
.tag { display: inline-block; background: var(--surface2); border: 1px solid var(--border); border-radius: 4px; padding: 0.1rem 0.5rem; font-size: 0.75rem; margin: 0.1rem; }
.url-list { list-style: none; }
.url-list li { padding: 0.3rem 0; border-bottom: 1px solid var(--border); font-size: 0.85rem; word-break: break-all; }
.url-list li:last-child { border-bottom: none; }
.mono { font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.82rem; }
.evidence { color: var(--text-muted); font-style: italic; font-size: 0.82rem; }
.footer { text-align: center; color: var(--text-muted); font-size: 0.8rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); }
.bar { height: 8px; border-radius: 4px; margin: 0.3rem 0; }
.bar-high { background: var(--high); }
.bar-medium { background: var(--medium); }
.bar-low { background: var(--low); }
</style>
</head>
<body>
<div class="container">

<!-- HEADER -->
<div class="header">
  <h1>赤 Akemi Scan Report</h1>
  <p class="subtitle">Target: <strong>{{.Summary.Target}}</strong> · Duration: {{.Summary.Duration}} · Generated: {{.Report.EndTime.Format "2006-01-02 15:04:05 MST"}}</p>

  <div class="stats">
    <div class="stat-card"><div class="value">{{.Summary.TotalURLs}}</div><div class="label">URLs Crawled</div></div>
    <div class="stat-card"><div class="value">{{.Summary.TotalParams}}</div><div class="label">Params Found</div></div>
    <div class="stat-card"><div class="value">{{.Summary.TotalSubdomains}}</div><div class="label">Subdomains</div></div>
    <div class="stat-card high"><div class="value">{{.Summary.HighSeverity}}</div><div class="label">High Vulns</div></div>
    <div class="stat-card medium"><div class="value">{{.Summary.MediumSeverity}}</div><div class="label">Medium Vulns</div></div>
    <div class="stat-card low"><div class="value">{{.Summary.LowSeverity}}</div><div class="label">Low Vulns</div></div>
  </div>

  {{if gt .Summary.TotalVulns 0}}
  <h3>Severity Distribution</h3>
  <p style="font-size:0.9rem;">
    {{if gt .Summary.HighSeverity 0}}<span class="severity-high">■ HIGH: {{.Summary.HighSeverity}}</span>&nbsp;&nbsp;{{end}}
    {{if gt .Summary.MediumSeverity 0}}<span class="severity-medium">■ MEDIUM: {{.Summary.MediumSeverity}}</span>&nbsp;&nbsp;{{end}}
    {{if gt .Summary.LowSeverity 0}}<span class="severity-low">■ LOW: {{.Summary.LowSeverity}}</span>{{end}}
  </p>
  {{end}}
</div>

<!-- VULNERABILITIES -->
{{if .Report.VulnFindings}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>🛡️ Vulnerability Findings</span>
    <span class="count">{{len .Report.VulnFindings}}</span>
  </div>
  <div class="section-body open">
    <table>
      <tr><th>Severity</th><th>Type</th><th>Parameter</th><th>Payload</th><th>Evidence</th></tr>
      {{range .Report.VulnFindings}}
      <tr>
        <td class="{{severity .Severity}}">{{.Severity}}</td>
        <td>{{.Type}}</td>
        <td class="mono">{{.Param}}</td>
        <td class="mono">{{.Payload}}</td>
        <td class="evidence">{{.Evidence}}</td>
      </tr>
      {{end}}
    </table>
  </div>
</div>
{{end}}

<!-- PORT SCAN RESULTS -->
{{if .Report.PortScanData}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>🔍 Port Scan Results</span>
    <span class="count">{{len .Report.PortScanData.Results}} ports</span>
  </div>
  <div class="section-body open">
    <p><strong>Hostname:</strong> {{.Report.PortScanData.Hostname}}</p>
    <p><strong>Resolved IPs:</strong> {{join .Report.PortScanData.IPs ", "}}</p>
    <table>
      <tr><th>Port</th><th>State</th><th>Banner</th><th>Technology</th></tr>
      {{range .Report.PortScanData.Results}}
      <tr>
        <td class="mono">{{.Port}}</td>
        <td><span class="{{if eq .State "open"}}severity-low{{else}}severity-medium{{end}}">{{.State}}</span></td>
        <td class="mono">{{.Banner}}</td>
        <td>{{range .Technology}}<span class="tag">{{.}}</span> {{end}}</td>
      </tr>
      {{end}}
    </table>
  </div>
</div>
{{end}}

<!-- CRAWL RESULTS -->
{{if or .Report.CrawlDetails .Report.CrawlResults}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>🌐 Crawled URLs</span>
    <span class="count">{{if .Report.CrawlDetails}}{{len .Report.CrawlDetails}}{{else}}{{len .Report.CrawlResults}}{{end}}</span>
  </div>
  <div class="section-body">
    {{if .Report.CrawlDetails}}
    <table>
      <tr><th>Status</th><th>URL</th></tr>
      {{range sortedCrawlDetails .Report.CrawlDetails}}
      <tr>
        <td><span class="{{statusClass .StatusCode}}">{{.Status}}</span></td>
        <td class="mono">{{.URL}}</td>
      </tr>
      {{end}}
    </table>
    {{else}}
    <ul class="url-list">{{range .Report.CrawlResults}}<li class="mono">{{.}}</li>{{end}}</ul>
    {{end}}
  </div>
</div>
{{end}}

<!-- PARAM MINING -->
{{if .Report.ParamMining}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>🔍 Discovered Parameters</span>
    <span class="count">{{len .Report.ParamMining}}</span>
  </div>
  <div class="section-body">
    <table>
      <tr><th>Parameter</th><th>Type</th><th>Discovery</th><th>Source URLs</th><th>Values</th></tr>
      {{range $name, $detail := .Report.ParamMining}}
      <tr>
        <td class="mono">{{$name}}</td>
        <td><span class="tag">{{$detail.InferredType}}</span></td>
        <td>{{range $detail.SourceTypes}}<span class="tag">{{.}}</span> {{end}}</td>
        <td class="mono">{{join $detail.Sources ", "}}</td>
        <td class="mono">{{join $detail.Values ", "}}</td>
      </tr>
      {{end}}
    </table>
  </div>
</div>
{{end}}

<!-- JS ANALYSIS -->
{{if .Report.JSAnalysis}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>📜 JavaScript Analysis</span>
    <span class="count">{{len .Report.JSAnalysis.ScriptURLs}} scripts</span>
  </div>
  <div class="section-body">
    {{if .Report.JSAnalysis.HiddenParams}}
    <h3>Hidden Parameters ({{len .Report.JSAnalysis.HiddenParams}})</h3>
    <p class="mono">{{range .Report.JSAnalysis.HiddenParams}}<span class="tag">{{.}}</span> {{end}}</p>
    {{end}}
    {{if .Report.JSAnalysis.ScriptURLs}}
    <h3>Script Files ({{len .Report.JSAnalysis.ScriptURLs}})</h3>
    <ul class="url-list">{{range .Report.JSAnalysis.ScriptURLs}}<li class="mono">{{.}}</li>{{end}}</ul>
    {{end}}
  </div>
</div>
{{end}}

<!-- CONFIG RESOURCES -->
{{if .Report.ConfigResources}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>🧩 Config Resources</span>
    <span class="count">{{len .Report.ConfigResources}}</span>
  </div>
  <div class="section-body">
    <ul class="url-list">{{range .Report.ConfigResources}}<li class="mono">{{.}}</li>{{end}}</ul>
  </div>
</div>
{{else if and .Report.JSAnalysis .Report.JSAnalysis.ConfigResources}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>🧩 Config Resources</span>
    <span class="count">{{len .Report.JSAnalysis.ConfigResources}}</span>
  </div>
  <div class="section-body">
    <ul class="url-list">{{range .Report.JSAnalysis.ConfigResources}}<li class="mono">{{.}}</li>{{end}}</ul>
  </div>
</div>
{{end}}

<!-- API SURFACE -->
{{if or .Report.APIEndpoints .Report.APISpecs}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>🛰️ API Surface</span>
    <span class="count">{{len .Report.APIEndpoints}} endpoints · {{len .Report.APISpecs}} specs</span>
  </div>
  <div class="section-body">
    {{if .Report.APISpecs}}
    <h3>Specs ({{len .Report.APISpecs}})</h3>
    <table>
      <tr><th>Type</th><th>Status</th><th>URL</th><th>Format</th><th>Version</th><th>Endpoints</th></tr>
      {{range .Report.APISpecs}}
      <tr>
        <td><span class="tag">{{.APIType}}</span></td>
        <td><span class="{{statusClass .StatusCode}}">{{if .Status}}{{.Status}}{{else}}UNKNOWN{{end}}</span></td>
        <td class="mono">{{.URL}}</td>
        <td><span class="tag">{{.Format}}</span></td>
        <td class="mono">{{.Version}}</td>
        <td>{{.EndpointCount}}</td>
      </tr>
      {{end}}
    </table>
    {{end}}

    {{if .Report.APIEndpoints}}
    <h3>Endpoints ({{len .Report.APIEndpoints}})</h3>
    <table>
      <tr><th>Type</th><th>Status</th><th>Method</th><th>URL</th><th>Version</th><th>Sources</th></tr>
      {{range .Report.APIEndpoints}}
      <tr>
        <td><span class="tag">{{.APIType}}</span></td>
        <td><span class="{{statusClass .StatusCode}}">{{if .Status}}{{.Status}}{{else}}UNKNOWN{{end}}</span></td>
        <td><span class="tag">{{if .Method}}{{.Method}}{{else}}ANY{{end}}</span></td>
        <td class="mono">{{.URL}}</td>
        <td class="mono">{{.Version}}</td>
        <td class="mono">{{join .SourceURLs ", "}}</td>
      </tr>
      {{end}}
    </table>
    {{end}}
  </div>
</div>
{{else if and .Report.JSAnalysis (or .Report.JSAnalysis.APIEndpoints .Report.JSAnalysis.APISpecs)}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>🛰️ API Surface</span>
    <span class="count">{{len .Report.JSAnalysis.APIEndpoints}} endpoints · {{len .Report.JSAnalysis.APISpecs}} specs</span>
  </div>
  <div class="section-body">
    {{if .Report.JSAnalysis.APISpecs}}
    <h3>Specs ({{len .Report.JSAnalysis.APISpecs}})</h3>
    <table>
      <tr><th>Type</th><th>Status</th><th>URL</th><th>Format</th><th>Version</th><th>Endpoints</th></tr>
      {{range .Report.JSAnalysis.APISpecs}}
      <tr>
        <td><span class="tag">{{.APIType}}</span></td>
        <td><span class="{{statusClass .StatusCode}}">{{if .Status}}{{.Status}}{{else}}UNKNOWN{{end}}</span></td>
        <td class="mono">{{.URL}}</td>
        <td><span class="tag">{{.Format}}</span></td>
        <td class="mono">{{.Version}}</td>
        <td>{{.EndpointCount}}</td>
      </tr>
      {{end}}
    </table>
    {{end}}

    {{if .Report.JSAnalysis.APIEndpoints}}
    <h3>Endpoints ({{len .Report.JSAnalysis.APIEndpoints}})</h3>
    <table>
      <tr><th>Type</th><th>Status</th><th>Method</th><th>URL</th><th>Version</th><th>Sources</th></tr>
      {{range .Report.JSAnalysis.APIEndpoints}}
      <tr>
        <td><span class="tag">{{.APIType}}</span></td>
        <td><span class="{{statusClass .StatusCode}}">{{if .Status}}{{.Status}}{{else}}UNKNOWN{{end}}</span></td>
        <td><span class="tag">{{if .Method}}{{.Method}}{{else}}ANY{{end}}</span></td>
        <td class="mono">{{.URL}}</td>
        <td class="mono">{{.Version}}</td>
        <td class="mono">{{join .SourceURLs ", "}}</td>
      </tr>
      {{end}}
    </table>
    {{end}}
  </div>
</div>
{{end}}

<!-- SECRET FINDINGS -->
{{if .Report.SecretFindings}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>⚠️ Secret Exposure Findings</span>
    <span class="count">{{len .Report.SecretFindings}}</span>
  </div>
  <div class="section-body">
    <table>
      <tr><th>Category</th><th>Value</th><th>Source Kind</th><th>Source URL</th></tr>
      {{range .Report.SecretFindings}}
      <tr>
        <td class="severity-high">{{.Category}}</td>
        <td class="mono">{{.Value}}</td>
        <td><span class="tag">{{.SourceKind}}</span></td>
        <td class="mono">{{.SourceURL}}</td>
      </tr>
      {{end}}
    </table>
  </div>
</div>
{{else if and .Report.JSAnalysis .Report.JSAnalysis.SecretFindings}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>⚠️ Secret Exposure Findings</span>
    <span class="count">{{len .Report.JSAnalysis.SecretFindings}}</span>
  </div>
  <div class="section-body">
    <table>
      <tr><th>Category</th><th>Value</th><th>Source Kind</th><th>Source URL</th></tr>
      {{range .Report.JSAnalysis.SecretFindings}}
      <tr>
        <td class="severity-high">{{.Category}}</td>
        <td class="mono">{{.Value}}</td>
        <td><span class="tag">{{.SourceKind}}</span></td>
        <td class="mono">{{.SourceURL}}</td>
      </tr>
      {{end}}
    </table>
  </div>
</div>
{{else if and .Report.JSAnalysis .Report.JSAnalysis.Secrets}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>⚠️ Potential Secrets</span>
    <span class="count">{{len .Report.JSAnalysis.Secrets}}</span>
  </div>
  <div class="section-body">
    <table>
      <tr><th>Category</th><th>Match</th></tr>
      {{range $cat, $matches := .Report.JSAnalysis.Secrets}}
      {{range $matches}}<tr><td class="severity-high">{{$cat}}</td><td class="mono">{{.}}</td></tr>{{end}}
      {{end}}
    </table>
  </div>
</div>
{{end}}

<!-- SUBDOMAINS -->
{{if .Report.Subdomains}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>🌍 Subdomains</span>
    <span class="count">{{len .Report.Subdomains}}</span>
  </div>
  <div class="section-body">
    <table>
      <tr><th>Subdomain</th><th>IPs</th><th>Source</th><th>Status</th></tr>
      {{range .Report.Subdomains}}
      <tr>
        <td class="mono">{{.Subdomain}}</td>
        <td class="mono">{{join .IPs ", "}}</td>
        <td><span class="tag">{{.Source}}</span></td>
        <td>{{if .Alive}}<span class="severity-low">ALIVE {{.StatusCode}}</span>{{else}}<span class="tag">no HTTP</span>{{end}}</td>
      </tr>
      {{end}}
    </table>
  </div>
</div>
{{end}}

<!-- SCRAPE DATA -->
{{if .Report.ScrapeData}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>📄 Page Scrape</span>
    <span class="count">1 page</span>
  </div>
  <div class="section-body">
    <p><strong>Title:</strong> {{.Report.ScrapeData.Title}}</p>
    <p><strong>Description:</strong> {{.Report.ScrapeData.Description}}</p>
    
    {{if .Report.ScrapeData.KeywordMatches}}
    <h3>Keyword Matches ({{len .Report.ScrapeData.KeywordMatches}})</h3>
    <table>
      <tr><th>Keyword</th><th>Matches</th></tr>
      {{range $kw, $matches := .Report.ScrapeData.KeywordMatches}}
      <tr>
        <td class="severity-high">{{$kw}}</td>
        <td class="mono">
          <ul class="url-list">
            {{range $matches}}<li>{{.}}</li>{{end}}
          </ul>
        </td>
      </tr>
      {{end}}
    </table>
    {{end}}

    {{if .Report.ScrapeData.Forms}}
    <h3>Forms ({{len .Report.ScrapeData.Forms}})</h3>
    <table>
      <tr><th>Action</th><th>Method</th><th>Inputs</th></tr>
      {{range .Report.ScrapeData.Forms}}
      <tr>
        <td class="mono">{{.Action}}</td>
        <td><span class="tag">{{.Method}}</span></td>
        <td>{{range .Inputs}}<span class="tag">{{.Name}} ({{.Type}})</span> {{end}}</td>
      </tr>
      {{end}}
    </table>
    {{end}}
    {{if .Report.ScrapeData.Comments}}
    <h3>HTML Comments ({{len .Report.ScrapeData.Comments}})</h3>
    <ul class="url-list">{{range .Report.ScrapeData.Comments}}<li class="mono">&lt;!-- {{.}} --&gt;</li>{{end}}</ul>
    {{end}}
  </div>
</div>
{{end}}

<!-- FUZZ RESULTS -->
{{if .Report.FuzzResults}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>🎯 Fuzz Results</span>
    <span class="count">{{len .Report.FuzzResults}}</span>
  </div>
  <div class="section-body">
    <table>
      <tr><th>ID</th><th>Status</th><th>Lines</th><th>Words</th><th>Chars</th><th>Payload</th></tr>
      {{range .Report.FuzzResults}}
      <tr>
        <td>{{.ID}}</td>
        <td>{{.StatusCode}}</td>
        <td>{{.Lines}}</td>
        <td>{{.Words}}</td>
        <td>{{.Chars}}</td>
        <td class="mono">{{.Payload}}</td>
      </tr>
      {{end}}
    </table>
  </div>
</div>
{{end}}

<!-- RELATIONAL GRAPH -->
{{if .HasGraph}}
<div class="section">
  <div class="section-header" onclick="toggle(this)">
    <span>🕸️ Attack Surface Graph</span>
    <span class="count">{{.NodeCount}} nodes · {{.EdgeCount}} edges</span>
  </div>
  <div class="section-body open">
    <div id="graph-legend" style="display:flex;flex-wrap:wrap;gap:1rem;margin-bottom:0.8rem;font-size:0.8rem;">
      <span><span style="color:#58a6ff">●</span> Target</span>
      <span><span style="color:#3fb950">●</span> URL</span>
      <span><span style="color:#d29922">●</span> Param</span>
      <span><span style="color:#f85149">●</span> Vuln</span>
      <span><span style="color:#a371f7">●</span> Subdomain</span>
      <span><span style="color:#79c0ff">●</span> JS File</span>
      <span><span style="color:#ff7b72">●</span> Secret</span>
      <span><span style="color:#56d364">●</span> Form</span>
    </div>
    <div style="margin-bottom:0.6rem;">
      <input type="text" id="graphSearch" placeholder="Search nodes..." oninput="searchGraphNode(this.value)"
        style="background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:0.4rem 0.8rem;border-radius:5px;font-size:0.85rem;width:280px;">
    </div>
    <div id="graphContainer" style="width:100%;height:550px;border:1px solid #30363d;border-radius:6px;background:#0d1117;"></div>
    <div id="graphTooltip" style="display:none;position:fixed;z-index:25;max-width:340px;pointer-events:none;background:rgba(13,17,23,0.96);border:1px solid #30363d;border-radius:6px;padding:0.65rem 0.9rem;box-shadow:0 18px 40px rgba(0,0,0,0.35);">
      <div id="graphTooltipLabel" style="color:#58a6ff;font-weight:700;margin-bottom:0.25rem;"></div>
      <div id="graphTooltipType" style="color:#8b949e;margin-bottom:0.35rem;"></div>
      <div id="graphTooltipMeta" style="color:#c9d1d9;font-family:monospace;font-size:0.75rem;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.45;"></div>
    </div>
  </div>
</div>
{{end}}

<div class="footer">
  Generated by <strong>Akemi 2.0.0</strong> — Security Scanner &amp; Fuzzing Engine<br>
  Report created at {{.Report.EndTime.Format "2006-01-02 15:04:05"}}
</div>

</div>

{{if .HasGraph}}
<script src="https://unpkg.com/vis-network@9.1.6/standalone/umd/vis-network.min.js"></script>
{{end}}
<script>
function toggle(el) {
  const body = el.nextElementSibling;
  body.classList.toggle('open');
}

{{if .HasGraph}}
(function() {
  const typeColors = {
    target:'#58a6ff', url:'#3fb950', param:'#d29922', vuln:'#f85149',
    subdomain:'#a371f7', js_file:'#79c0ff', secret:'#ff7b72', form:'#56d364',
    config_resource:'#e3b341', api_endpoint:'#39c5bb', api_spec:'#1f6feb', technology:'#8b949e'
  };
  const typeShapes = {
    target:'star', url:'dot', param:'diamond', vuln:'triangle',
    subdomain:'hexagon', js_file:'square', secret:'triangleDown', form:'box',
    config_resource:'database', api_endpoint:'box', api_spec:'star', technology:'square'
  };

  const rawNodes = {{.NodesJSON}};
  const rawEdges = {{.EdgesJSON}};
  const container = document.getElementById('graphContainer');
  const tooltip = document.getElementById('graphTooltip');
  const tooltipLabel = document.getElementById('graphTooltipLabel');
  const tooltipType = document.getElementById('graphTooltipType');
  const tooltipMeta = document.getElementById('graphTooltipMeta');
  if (!container || !rawNodes.length) {
    window.searchGraphNode = function() {};
    return;
  }

  const graphFingerprint = function(nodes, edges) {
    let hash = 0;
    const feed = function(text) {
      for (let i = 0; i < text.length; i += 1) {
        hash = ((hash << 5) - hash + text.charCodeAt(i)) | 0;
      }
    };
    nodes.forEach(function(node) { feed(node.id + '|' + node.type + '|' + node.label); });
    edges.forEach(function(edge) { feed(edge.source + '|' + edge.target + '|' + (edge.label || '')); });
    return nodes.length + '-' + edges.length + '-' + Math.abs(hash);
  };

  const onIdle = function(callback) {
    if ('requestIdleCallback' in window) {
      window.requestIdleCallback(callback, { timeout: 1200 });
      return;
    }
    window.setTimeout(callback, 32);
  };

  const storageKey = 'akemi.report.graph.' + graphFingerprint(rawNodes, rawEdges);
  const loadCachedPositions = function() {
    try {
      const cached = window.localStorage.getItem(storageKey);
      return cached ? JSON.parse(cached) : null;
    } catch (e) {
      return null;
    }
  };
  const cachedPositions = loadCachedPositions();
  const graphIsLarge = rawNodes.length > 350 || rawEdges.length > 900;

  const visNodes = rawNodes.map(function(n) {
    const node = {
      id: n.id,
      label: n.label.length > 28 ? n.label.substring(0,28) + '…' : n.label,
      fullLabel: n.label,
      shape: typeShapes[n.type] || 'dot',
      color: { background: typeColors[n.type] || '#8b949e', border: typeColors[n.type] || '#8b949e',
               highlight: { background:'#ffffff', border: typeColors[n.type] || '#8b949e' } },
      font: { color:'#c9d1d9', size: n.type === 'target' ? 14 : 10 },
      size: n.type === 'target' ? 30 : (n.type === 'vuln' ? 20 : 12),
      nodeType: n.type,
      meta: n.meta || {}
    };
    if (cachedPositions && cachedPositions[n.id]) {
      node.x = cachedPositions[n.id].x;
      node.y = cachedPositions[n.id].y;
    }
    return node;
  });

  const visEdges = rawEdges.map(function(e, i) {
    return {
      id: 'e' + i, from: e.source, to: e.target, label: e.label, arrows: 'to',
      color: { color:'#30363d', highlight:'#58a6ff' },
      font: { color:'#8b949e', size: 8, strokeWidth: 0 },
      smooth: { type:'cubicBezier', roundness: 0.4 }
    };
  });

  let network = null;
  let searchTimer = null;
  let pendingSearch = '';

  const savePositions = function() {
    if (!network) {
      return;
    }
    try {
      const ids = visNodes.map(function(node) { return node.id; });
      const positions = network.getPositions(ids);
      window.localStorage.setItem(storageKey, JSON.stringify(positions));
    } catch (e) { /* silent */ }
  };

  const hideTooltip = function() {
    if (tooltip) {
      tooltip.style.display = 'none';
    }
  };

  const showTooltip = function(node, event) {
    if (!tooltip || !node) {
      return;
    }
    const metaLines = Object.entries(node.meta || {}).map(function(entry) {
      return entry[0] + ': ' + entry[1];
    }).join('\n');
    tooltipLabel.textContent = node.fullLabel || node.label || node.id;
    tooltipType.textContent = 'Type: ' + node.nodeType;
    tooltipMeta.textContent = metaLines;
    tooltip.style.display = 'block';
    tooltip.style.left = (event.center.x + 16) + 'px';
    tooltip.style.top = (event.center.y + 16) + 'px';
  };

  const applySearch = function(query, dataSet) {
    if (!dataSet) {
      return;
    }
    if (!query) {
      dataSet.nodes.update(visNodes.map(function(node) { return { id: node.id, opacity: 1 }; }));
      return;
    }
    const lower = query.toLowerCase();
    const updates = visNodes.map(function(node) {
      const match = node.fullLabel.toLowerCase().includes(lower) || node.nodeType.includes(lower);
      return { id: node.id, opacity: match ? 1 : 0.15 };
    });
    dataSet.nodes.update(updates);
    const found = visNodes.find(function(node) { return node.fullLabel.toLowerCase().includes(lower); });
    if (found && network) {
      network.focus(found.id, { scale: 1.2, animation: true });
    }
  };

  const initGraph = function() {
    if (network) {
      return;
    }
    onIdle(function() {
      const data = { nodes: new vis.DataSet(visNodes), edges: new vis.DataSet(visEdges) };
      const options = {
        physics: cachedPositions ? false : {
          solver:'forceAtlas2Based',
          forceAtlas2Based:{ gravitationalConstant:-60, centralGravity:0.008, springLength:150, damping:0.5 },
          stabilization:{ iterations: graphIsLarge ? 80 : 200, fit: true }
        },
        interaction: { hover:true, tooltipDelay:100, zoomView:true, dragView:true, hideEdgesOnDrag:true, hideEdgesOnZoom:true },
        layout: { improvedLayout: !graphIsLarge }
      };
      network = new vis.Network(container, data, options);
      document.getElementById('graphStats').textContent = visNodes.length + ' nodes · ' + visEdges.length + ' edges';

      if (cachedPositions) {
        network.setOptions({ physics: false });
        window.requestAnimationFrame(function() {
          network.fit({ animation: false });
        });
      } else {
        network.once('stabilizationIterationsDone', function() {
          network.setOptions({ physics: false });
          network.stopSimulation();
          savePositions();
        });
      }

      network.on('hoverNode', function(params) {
        showTooltip(data.nodes.get(params.node), params.event);
      });
      network.on('blurNode', hideTooltip);
      network.on('dragStart', hideTooltip);
      network.on('dragEnd', savePositions);

      if (pendingSearch) {
        applySearch(pendingSearch, data);
      }
      window.addEventListener('beforeunload', savePositions, { once: true });
    });
  };

  window.searchGraphNode = function(query) {
    pendingSearch = query;
    if (!network) {
      initGraph();
      return;
    }
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(function() {
      applySearch(query, network.body.data);
    }, 180);
  };

  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver(function(entries) {
      if (entries.some(function(entry) { return entry.isIntersecting; })) {
        observer.disconnect();
        initGraph();
      }
    }, { rootMargin: '120px' });
    observer.observe(container);
  } else {
    initGraph();
  }
})();
{{end}}
</script>
</body>
</html>`
