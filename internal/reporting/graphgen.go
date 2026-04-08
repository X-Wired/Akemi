package reporting

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// =============================================================
// ── GRAPH DATA MODEL ────────────────────────────────────────
// =============================================================

// ScanGraph represents the relational graph of a scan.
type ScanGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// GraphNode represents a single entity in the scan graph.
type GraphNode struct {
	ID    string            `json:"id"`
	Label string            `json:"label"`
	Type  string            `json:"type"` // target, url, param, vuln, subdomain, js_file, secret, form, config_resource, api_endpoint, api_spec
	Meta  map[string]string `json:"meta,omitempty"`
}

// GraphEdge represents a relationship between two nodes.
type GraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label"` // crawled, has_param, vulnerable_to, resolves_to, loads_script, exposes
}

// nodeID generates a deterministic short ID from a type and value.
func nodeID(nodeType, value string) string {
	h := sha256.Sum256([]byte(nodeType + ":" + value))
	return fmt.Sprintf("%s_%x", nodeType, h[:6])
}

// =============================================================
// ── GRAPH BUILDER ───────────────────────────────────────────
// =============================================================

// BuildGraph constructs a ScanGraph from a ScanReport.
func BuildGraph(report *ScanReport) *ScanGraph {
	g := &ScanGraph{}
	seen := make(map[string]bool)
	seenEdges := make(map[string]bool)

	addNode := func(n GraphNode) {
		if !seen[n.ID] {
			seen[n.ID] = true
			g.Nodes = append(g.Nodes, n)
		}
	}

	addEdge := func(src, dst, label string) {
		key := src + "|" + dst + "|" + label
		if seenEdges[key] {
			return
		}
		seenEdges[key] = true
		g.Edges = append(g.Edges, GraphEdge{Source: src, Target: dst, Label: label})
	}

	// Root target node
	targetID := nodeID("target", report.Target)
	addNode(GraphNode{
		ID:    targetID,
		Label: report.Target,
		Type:  "target",
	})

	// ── Crawl results ────────────────────────────────
	if len(report.CrawlDetails) > 0 {
		for _, finding := range report.CrawlDetails {
			urlID := nodeID("url", finding.URL)
			meta := map[string]string{"full_url": finding.URL}
			if finding.Status != "" {
				meta["status"] = finding.Status
			}
			if finding.StatusCode > 0 {
				meta["status_code"] = fmt.Sprintf("%d", finding.StatusCode)
			}
			addNode(GraphNode{
				ID:    urlID,
				Label: truncateLabel(finding.URL, 60),
				Type:  "url",
				Meta:  meta,
			})
			addEdge(targetID, urlID, "crawled")
		}
	} else {
		for _, rawURL := range report.CrawlResults {
			urlID := nodeID("url", rawURL)
			addNode(GraphNode{
				ID:    urlID,
				Label: truncateLabel(rawURL, 60),
				Type:  "url",
				Meta:  map[string]string{"full_url": rawURL},
			})
			addEdge(targetID, urlID, "crawled")
		}
	}

	// ── Param mining ─────────────────────────────────
	for paramName, detail := range report.ParamMining {
		paramID := nodeID("param", paramName)
		meta := map[string]string{
			"inferred_type": string(detail.InferredType),
		}
		if detail.Suspicious {
			meta["suspicious"] = "true"
		}
		addNode(GraphNode{
			ID:    paramID,
			Label: paramName,
			Type:  "param",
			Meta:  meta,
		})

		// Link param to its source URLs
		for _, src := range detail.Sources {
			srcID := nodeID("url", src)
			addNode(GraphNode{
				ID:    srcID,
				Label: truncateLabel(src, 60),
				Type:  "url",
			})
			addEdge(srcID, paramID, "has_param")
		}

		// If no sources, link to target
		if len(detail.Sources) == 0 {
			addEdge(targetID, paramID, "has_param")
		}
	}

	// ── JS Analysis ──────────────────────────────────
	if report.JSAnalysis != nil {
		for _, scriptURL := range report.JSAnalysis.ScriptURLs {
			jsID := nodeID("js_file", scriptURL)
			addNode(GraphNode{
				ID:    jsID,
				Label: truncateLabel(scriptURL, 50),
				Type:  "js_file",
				Meta:  map[string]string{"url": scriptURL},
			})
			addEdge(targetID, jsID, "loads_script")
		}

		for _, endpoint := range report.JSAnalysis.Endpoints {
			epID := nodeID("url", endpoint)
			addNode(GraphNode{
				ID:    epID,
				Label: endpoint,
				Type:  "url",
				Meta:  map[string]string{"source": "js_analysis"},
			})
			addEdge(targetID, epID, "js_endpoint")
		}

		for _, param := range report.JSAnalysis.HiddenParams {
			paramID := nodeID("param", param)
			addNode(GraphNode{
				ID:    paramID,
				Label: param,
				Type:  "param",
				Meta:  map[string]string{"source": "js_hidden"},
			})
			addEdge(targetID, paramID, "hidden_param")
		}

	}

	for _, resourceURL := range report.ConfigResources {
		resourceID := nodeID("config_resource", resourceURL)
		addNode(GraphNode{
			ID:    resourceID,
			Label: truncateLabel(resourceURL, 60),
			Type:  "config_resource",
			Meta:  map[string]string{"url": resourceURL},
		})
		addEdge(targetID, resourceID, "config_resource")
	}
	if len(report.ConfigResources) == 0 && report.JSAnalysis != nil {
		for _, resourceURL := range report.JSAnalysis.ConfigResources {
			resourceID := nodeID("config_resource", resourceURL)
			addNode(GraphNode{
				ID:    resourceID,
				Label: truncateLabel(resourceURL, 60),
				Type:  "config_resource",
				Meta:  map[string]string{"url": resourceURL},
			})
			addEdge(targetID, resourceID, "config_resource")
		}
	}

	for _, endpoint := range report.APIEndpoints {
		endpointID := nodeID("api_endpoint", endpoint.URL+"|"+endpoint.Method+"|"+endpoint.APIType)
		meta := map[string]string{
			"api_type": endpoint.APIType,
			"method":   endpoint.Method,
			"version":  endpoint.Version,
		}
		if endpoint.Status != "" {
			meta["status"] = endpoint.Status
		}
		if endpoint.StatusCode > 0 {
			meta["status_code"] = fmt.Sprintf("%d", endpoint.StatusCode)
		}
		addNode(GraphNode{
			ID:    endpointID,
			Label: truncateLabel(endpoint.URL, 60),
			Type:  "api_endpoint",
			Meta:  meta,
		})
		addEdge(targetID, endpointID, "api_surface")
	}
	if len(report.APIEndpoints) == 0 && report.JSAnalysis != nil {
		for _, endpoint := range report.JSAnalysis.APIEndpoints {
			endpointID := nodeID("api_endpoint", endpoint.URL+"|"+endpoint.Method+"|"+endpoint.APIType)
			meta := map[string]string{
				"api_type": endpoint.APIType,
				"method":   endpoint.Method,
				"version":  endpoint.Version,
			}
			if endpoint.Status != "" {
				meta["status"] = endpoint.Status
			}
			if endpoint.StatusCode > 0 {
				meta["status_code"] = fmt.Sprintf("%d", endpoint.StatusCode)
			}
			addNode(GraphNode{
				ID:    endpointID,
				Label: truncateLabel(endpoint.URL, 60),
				Type:  "api_endpoint",
				Meta:  meta,
			})
			addEdge(targetID, endpointID, "api_surface")
		}
	}

	for _, spec := range report.APISpecs {
		specID := nodeID("api_spec", spec.URL)
		meta := map[string]string{
			"api_type": spec.APIType,
			"format":   spec.Format,
			"version":  spec.Version,
			"title":    spec.Title,
		}
		if spec.Status != "" {
			meta["status"] = spec.Status
		}
		if spec.StatusCode > 0 {
			meta["status_code"] = fmt.Sprintf("%d", spec.StatusCode)
		}
		addNode(GraphNode{
			ID:    specID,
			Label: truncateLabel(spec.URL, 60),
			Type:  "api_spec",
			Meta:  meta,
		})
		addEdge(targetID, specID, "api_spec")
	}
	if len(report.APISpecs) == 0 && report.JSAnalysis != nil {
		for _, spec := range report.JSAnalysis.APISpecs {
			specID := nodeID("api_spec", spec.URL)
			meta := map[string]string{
				"api_type": spec.APIType,
				"format":   spec.Format,
				"version":  spec.Version,
				"title":    spec.Title,
			}
			if spec.Status != "" {
				meta["status"] = spec.Status
			}
			if spec.StatusCode > 0 {
				meta["status_code"] = fmt.Sprintf("%d", spec.StatusCode)
			}
			addNode(GraphNode{
				ID:    specID,
				Label: truncateLabel(spec.URL, 60),
				Type:  "api_spec",
				Meta:  meta,
			})
			addEdge(targetID, specID, "api_spec")
		}
	}

	if len(report.SecretFindings) > 0 {
		for _, finding := range report.SecretFindings {
			secretID := nodeID("secret", finding.Value+"|"+finding.SourceURL)
			addNode(GraphNode{
				ID:    secretID,
				Label: truncateLabel(maskSecretForGraph(finding.Value), 40),
				Type:  "secret",
				Meta: map[string]string{
					"category":    finding.Category,
					"source_url":  finding.SourceURL,
					"source_kind": finding.SourceKind,
				},
			})
			addEdge(targetID, secretID, "exposes")
		}
	} else if report.JSAnalysis != nil {
		for _, finding := range report.JSAnalysis.SecretFindings {
			secretID := nodeID("secret", finding.Value+"|"+finding.SourceURL)
			addNode(GraphNode{
				ID:    secretID,
				Label: truncateLabel(maskSecretForGraph(finding.Value), 40),
				Type:  "secret",
				Meta: map[string]string{
					"category":    finding.Category,
					"source_url":  finding.SourceURL,
					"source_kind": finding.SourceKind,
				},
			})
			addEdge(targetID, secretID, "exposes")
		}
		for category, matches := range report.JSAnalysis.Secrets {
			for _, match := range matches {
				secretID := nodeID("secret", match)
				addNode(GraphNode{
					ID:    secretID,
					Label: truncateLabel(maskSecretForGraph(match), 40),
					Type:  "secret",
					Meta:  map[string]string{"category": category},
				})
				addEdge(targetID, secretID, "exposes")
			}
		}
	}

	// ── Subdomains ───────────────────────────────────
	for _, sub := range report.Subdomains {
		subID := nodeID("subdomain", sub.Subdomain)
		meta := map[string]string{
			"source": sub.Source,
			"ips":    strings.Join(sub.IPs, ", "),
		}
		if sub.Alive {
			meta["alive"] = fmt.Sprintf("%d", sub.StatusCode)
		}
		addNode(GraphNode{
			ID:    subID,
			Label: sub.Subdomain,
			Type:  "subdomain",
			Meta:  meta,
		})
		addEdge(targetID, subID, "has_subdomain")
	}

	// ── Vulnerability findings ───────────────────────
	for i, finding := range report.VulnFindings {
		vulnID := nodeID("vuln", fmt.Sprintf("%s:%s:%d", finding.Type, finding.Param, i))
		addNode(GraphNode{
			ID:    vulnID,
			Label: fmt.Sprintf("%s (%s)", finding.Type, finding.Severity),
			Type:  "vuln",
			Meta: map[string]string{
				"severity": finding.Severity,
				"payload":  truncateLabel(finding.Payload, 60),
				"evidence": finding.Evidence,
			},
		})

		// Link vuln to its param if identifiable, otherwise to URL
		if finding.Param != "" && finding.Param != "response header" && finding.Param != "response body" && finding.Param != "POST body" {
			paramID := nodeID("param", finding.Param)
			addNode(GraphNode{
				ID:    paramID,
				Label: finding.Param,
				Type:  "param",
			})
			addEdge(paramID, vulnID, "vulnerable_to")
		} else {
			urlID := nodeID("url", finding.URL)
			addNode(GraphNode{
				ID:    urlID,
				Label: truncateLabel(finding.URL, 60),
				Type:  "url",
			})
			addEdge(urlID, vulnID, "vulnerable_to")
		}
	}

	// ── Scrape forms ────────────────────────────────
	if report.ScrapeData != nil {
		for i, form := range report.ScrapeData.Forms {
			formID := nodeID("form", fmt.Sprintf("%s:%d", form.Action, i))
			addNode(GraphNode{
				ID:    formID,
				Label: fmt.Sprintf("Form: %s [%s]", form.Action, form.Method),
				Type:  "form",
				Meta:  map[string]string{"action": form.Action, "method": form.Method},
			})
			addEdge(targetID, formID, "contains_form")

			for _, input := range form.Inputs {
				if input.Name == "" {
					continue
				}
				inputID := nodeID("param", input.Name)
				meta := map[string]string{"input_type": input.Type}
				if input.Vulnerable {
					meta["suspicious"] = "true"
				}
				addNode(GraphNode{
					ID:    inputID,
					Label: input.Name,
					Type:  "param",
					Meta:  meta,
				})
				addEdge(formID, inputID, "has_input")
			}
		}
	}

	return g
}

// truncateLabel shortens a label for display in graph nodes.
func truncateLabel(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "…"
	}
	return s
}

func maskSecretForGraph(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}

// =============================================================
// ── JSON EXPORT ─────────────────────────────────────────────
// =============================================================

// SaveGraphJSON writes the graph as D3.js-compatible JSON.
func (g *ScanGraph) SaveGraphJSON(path string) error {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling graph: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("error writing graph JSON: %w", err)
	}
	fmt.Printf("[+] Graph JSON saved to: %s\n", path)
	return nil
}

// =============================================================
// ── DOT EXPORT (Graphviz) ───────────────────────────────────
// =============================================================

// nodeColor returns a Graphviz fill color based on node type.
func nodeColor(nodeType string) string {
	switch nodeType {
	case "target":
		return "#58a6ff"
	case "url":
		return "#3fb950"
	case "param":
		return "#d29922"
	case "vuln":
		return "#f85149"
	case "subdomain":
		return "#a371f7"
	case "js_file":
		return "#79c0ff"
	case "secret":
		return "#ff7b72"
	case "form":
		return "#56d364"
	case "config_resource":
		return "#e3b341"
	case "api_endpoint":
		return "#39c5bb"
	case "api_spec":
		return "#1f6feb"
	default:
		return "#8b949e"
	}
}

// nodeShape returns a Graphviz shape based on node type.
func nodeShape(nodeType string) string {
	switch nodeType {
	case "target":
		return "doubleoctagon"
	case "url":
		return "box"
	case "param":
		return "ellipse"
	case "vuln":
		return "diamond"
	case "subdomain":
		return "hexagon"
	case "js_file":
		return "note"
	case "secret":
		return "triangle"
	case "form":
		return "component"
	case "config_resource":
		return "folder"
	case "api_endpoint":
		return "box3d"
	case "api_spec":
		return "tab"
	default:
		return "ellipse"
	}
}

// SaveGraphDOT writes the graph in Graphviz DOT format.
func (g *ScanGraph) SaveGraphDOT(path string) error {
	var sb strings.Builder

	sb.WriteString("digraph AkemiScan {\n")
	sb.WriteString("  graph [rankdir=LR, bgcolor=\"#0d1117\", fontcolor=\"#c9d1d9\", fontname=\"Segoe UI\"];\n")
	sb.WriteString("  node [style=filled, fontname=\"Segoe UI\", fontsize=10, fontcolor=\"#0d1117\"];\n")
	sb.WriteString("  edge [fontname=\"Segoe UI\", fontsize=8, fontcolor=\"#8b949e\", color=\"#30363d\"];\n\n")

	for _, node := range g.Nodes {
		label := strings.ReplaceAll(node.Label, "\"", "\\\"")
		sb.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\", shape=%s, fillcolor=\"%s\"];\n",
			node.ID, label, nodeShape(node.Type), nodeColor(node.Type)))
	}

	sb.WriteString("\n")

	for _, edge := range g.Edges {
		sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"%s\"];\n",
			edge.Source, edge.Target, edge.Label))
	}

	sb.WriteString("}\n")

	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("error writing DOT file: %w", err)
	}
	fmt.Printf("[+] Graph DOT saved to: %s\n", path)
	return nil
}

// =============================================================
// ── INTERACTIVE HTML EXPORT (vis.js) ────────────────────────
// =============================================================

// SaveGraphHTML generates a self-contained interactive HTML graph using vis.js.
func (g *ScanGraph) SaveGraphHTML(path string) error {
	nodesJSON, err := json.Marshal(g.Nodes)
	if err != nil {
		return fmt.Errorf("error marshaling nodes: %w", err)
	}
	edgesJSON, err := json.Marshal(g.Edges)
	if err != nil {
		return fmt.Errorf("error marshaling edges: %w", err)
	}

	html := fmt.Sprintf(graphHTMLTemplate, string(nodesJSON), string(edgesJSON))

	if err := os.WriteFile(path, []byte(html), 0644); err != nil {
		return fmt.Errorf("error writing graph HTML: %w", err)
	}
	fmt.Printf("[+] Interactive graph HTML saved to: %s\n", path)
	return nil
}

// =============================================================
// ── GRAPH HTML TEMPLATE ─────────────────────────────────────
// =============================================================

const graphHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Akemi Scan Graph</title>
<script src="https://unpkg.com/vis-network@9.1.6/standalone/umd/vis-network.min.js"></script>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', system-ui, sans-serif; }
#header { background: #161b22; border-bottom: 1px solid #30363d; padding: 1rem 1.5rem; display: flex; justify-content: space-between; align-items: center; }
#header h1 { color: #58a6ff; font-size: 1.3rem; }
#header .stats { color: #8b949e; font-size: 0.85rem; }
#graph { width: 100vw; height: calc(100vh - 56px); }
#legend { position: fixed; bottom: 1rem; left: 1rem; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 0.8rem; font-size: 0.75rem; z-index: 10; }
.legend-item { display: flex; align-items: center; gap: 0.5rem; margin: 0.3rem 0; }
.legend-dot { width: 12px; height: 12px; border-radius: 50%%; display: inline-block; }
#search { position: fixed; top: 4.2rem; right: 1rem; z-index: 10; }
#search input { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 0.5rem 1rem; border-radius: 6px; font-size: 0.85rem; width: 250px; }
#search input:focus { outline: none; border-color: #58a6ff; }
#tooltip { position: fixed; background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 0.6rem 1rem; font-size: 0.8rem; display: none; z-index: 20; max-width: 350px; pointer-events: none; }
#tooltip .tt-label { color: #58a6ff; font-weight: 700; margin-bottom: 0.3rem; }
#tooltip .tt-type { color: #8b949e; }
#tooltip .tt-meta { color: #c9d1d9; font-family: monospace; font-size: 0.75rem; word-break: break-all; }
</style>
</head>
<body>

<div id="header">
  <h1>赤 Akemi Scan Graph</h1>
  <div class="stats" id="graphStats"></div>
</div>

<div id="search"><input type="text" id="searchInput" placeholder="Search nodes..." oninput="searchNode(this.value)"></div>

<div id="legend">
  <div class="legend-item"><span class="legend-dot" style="background:#58a6ff"></span> Target</div>
  <div class="legend-item"><span class="legend-dot" style="background:#3fb950"></span> URL</div>
  <div class="legend-item"><span class="legend-dot" style="background:#d29922"></span> Parameter</div>
  <div class="legend-item"><span class="legend-dot" style="background:#f85149"></span> Vulnerability</div>
  <div class="legend-item"><span class="legend-dot" style="background:#a371f7"></span> Subdomain</div>
  <div class="legend-item"><span class="legend-dot" style="background:#79c0ff"></span> JS File</div>
  <div class="legend-item"><span class="legend-dot" style="background:#ff7b72"></span> Secret</div>
  <div class="legend-item"><span class="legend-dot" style="background:#56d364"></span> Form</div>
  <div class="legend-item"><span class="legend-dot" style="background:#e3b341"></span> Config Resource</div>
  <div class="legend-item"><span class="legend-dot" style="background:#39c5bb"></span> API Endpoint</div>
  <div class="legend-item"><span class="legend-dot" style="background:#1f6feb"></span> API Spec</div>
</div>

<div id="tooltip">
  <div class="tt-label" id="ttLabel"></div>
  <div class="tt-type" id="ttType"></div>
  <div class="tt-meta" id="ttMeta"></div>
</div>

<div id="graph"></div>

<script>
const typeColors = {
  target: '#58a6ff', url: '#3fb950', param: '#d29922', vuln: '#f85149',
  subdomain: '#a371f7', js_file: '#79c0ff', secret: '#ff7b72', form: '#56d364',
  config_resource: '#e3b341', api_endpoint: '#39c5bb', api_spec: '#1f6feb'
};
const typeShapes = {
  target: 'star', url: 'dot', param: 'diamond', vuln: 'triangle',
  subdomain: 'hexagon', js_file: 'square', secret: 'triangleDown', form: 'box',
  config_resource: 'database', api_endpoint: 'box', api_spec: 'star'
};

const rawNodes = %s;
const rawEdges = %s;

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

const storageKey = 'akemi.graph.' + graphFingerprint(rawNodes, rawEdges);
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
    label: n.label.length > 30 ? n.label.substring(0, 30) + '…' : n.label,
    fullLabel: n.label,
    shape: typeShapes[n.type] || 'dot',
    color: { background: typeColors[n.type] || '#8b949e', border: typeColors[n.type] || '#8b949e', highlight: { background: '#ffffff', border: typeColors[n.type] || '#8b949e' } },
    font: { color: '#c9d1d9', size: n.type === 'target' ? 14 : 10 },
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
    id: 'e' + i,
    from: e.source,
    to: e.target,
    label: e.label,
    arrows: 'to',
    color: { color: '#30363d', highlight: '#58a6ff' },
    font: { color: '#8b949e', size: 8, strokeWidth: 0 },
    smooth: { type: 'cubicBezier', roundness: 0.4 }
  };
});

const container = document.getElementById('graph');
const tooltip = document.getElementById('tooltip');
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
  tooltip.style.display = 'none';
};

const showTooltip = function(node, event) {
  if (!node) return;
  document.getElementById('ttLabel').textContent = node.fullLabel;
  document.getElementById('ttType').textContent = 'Type: ' + node.nodeType;
  const metaLines = Object.entries(node.meta).map(function(entry) { return entry[0] + ': ' + entry[1]; }).join('\n');
  document.getElementById('ttMeta').textContent = metaLines;
  tooltip.style.display = 'block';
  tooltip.style.left = (event.center.x + 15) + 'px';
  tooltip.style.top = (event.center.y + 15) + 'px';
};

const applySearch = function(query, dataSet) {
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
  const matchedNode = visNodes.find(function(node) { return node.fullLabel.toLowerCase().includes(lower); });
  if (matchedNode && network) {
    network.focus(matchedNode.id, { scale: 1.2, animation: true });
  }
};

const initGraph = function() {
  if (network || !container) {
    return;
  }
  onIdle(function() {
    const data = { nodes: new vis.DataSet(visNodes), edges: new vis.DataSet(visEdges) };
    const options = {
      physics: cachedPositions ? false : { solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -60, centralGravity: 0.008, springLength: 150, damping: 0.5 }, stabilization: { iterations: graphIsLarge ? 80 : 200, fit: true } },
      interaction: { hover: true, tooltipDelay: 100, zoomView: true, dragView: true, hideEdgesOnDrag: true, hideEdgesOnZoom: true },
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

function searchNode(query) {
  pendingSearch = query;
  window.clearTimeout(searchTimer);
  searchTimer = window.setTimeout(function() {
    if (!network) {
      initGraph();
      return;
    }
    applySearch(query, { nodes: network.body.data.nodes });
  }, 180);
}
</script>
</body>
</html>`
