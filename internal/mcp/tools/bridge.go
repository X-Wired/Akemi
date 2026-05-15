package tools

import (
	"context"
	"fmt"
	"strings"

	core "Akemi/internal/core"
	"Akemi/internal/toolbridge"
)

type liveCrawlDiscoverer interface {
	CrawlWithCallback(ctx context.Context, startURL string, maxDepth int, onFinding func(core.CrawlFinding)) ([]core.CrawlFinding, error)
}

func emitDiscoveryItems(ctx context.Context, svc *Services, toolName, phase string, items ...toolbridge.DiscoveryItem) {
	if svc == nil || svc.EventSink == nil || len(items) == 0 {
		return
	}
	normalized := make([]toolbridge.DiscoveryItem, 0, len(items))
	for _, item := range items {
		item.Section = strings.TrimSpace(item.Section)
		item.Item = strings.TrimSpace(item.Item)
		item.Key = strings.TrimSpace(item.Key)
		item.Phase = firstNonBlank(item.Phase, phase)
		if item.Section == "" || item.Item == "" {
			continue
		}
		if item.Key == "" {
			item.Key = item.Item
		}
		normalized = append(normalized, item)
	}
	if len(normalized) == 0 {
		return
	}
	svc.EventSink.Emit(ctx, toolbridge.Event{
		ToolName:    toolName,
		NativeName:  toolName,
		Phase:       phase,
		Discoveries: normalized,
	})
}

func emitProgress(ctx context.Context, svc *Services, toolName, phase string) {
	if svc == nil || svc.EventSink == nil || strings.TrimSpace(phase) == "" {
		return
	}
	svc.EventSink.Emit(ctx, toolbridge.Event{
		ToolName:   toolName,
		NativeName: toolName,
		Phase:      phase,
	})
}

func emitTargetConfig(ctx context.Context, svc *Services, toolName, phase string, target toolbridge.TargetConfig) {
	if svc == nil || svc.EventSink == nil || emptyTargetConfig(target) {
		return
	}
	svc.EventSink.Emit(ctx, toolbridge.Event{
		ToolName:   toolName,
		NativeName: toolName,
		Phase:      phase,
		Target:     &target,
	})
}

func emptyTargetConfig(target toolbridge.TargetConfig) bool {
	return !target.Clear &&
		strings.TrimSpace(target.Target) == "" &&
		strings.TrimSpace(target.Ports) == "" &&
		strings.TrimSpace(target.Proxy) == "" &&
		strings.TrimSpace(target.Intent) == "" &&
		target.Threads == nil &&
		target.Depth == nil &&
		target.Timeout == nil
}

func intPtr(value int) *int {
	if value <= 0 {
		return nil
	}
	return &value
}

func portDiscoveryItems(ports []core.PortResult) []toolbridge.DiscoveryItem {
	items := make([]toolbridge.DiscoveryItem, 0, len(ports))
	for _, p := range ports {
		items = append(items, toolbridge.DiscoveryItem{
			Section: "Ports",
			Key:     fmt.Sprintf("%d", p.Port),
			Item:    formatPortDiscovery(p),
		})
	}
	return items
}

func subdomainDiscoveryItems(results []core.SubdomainResult) []toolbridge.DiscoveryItem {
	items := make([]toolbridge.DiscoveryItem, 0, len(results))
	for _, r := range results {
		if strings.TrimSpace(r.Name) == "" {
			continue
		}
		item := r.Name
		details := make([]string, 0, 3)
		if r.Source != "" {
			details = append(details, r.Source)
		}
		if r.IsAlive {
			details = append(details, "alive")
		}
		if r.StatusCode > 0 {
			details = append(details, fmt.Sprintf("%d", r.StatusCode))
		}
		if len(details) > 0 {
			item = fmt.Sprintf("%s (%s)", item, strings.Join(details, ", "))
		}
		items = append(items, toolbridge.DiscoveryItem{Section: "Subdomains", Key: r.Name, Item: item})
	}
	return items
}

func crawlDiscoveryItem(f core.CrawlFinding) toolbridge.DiscoveryItem {
	item := f.URL
	if f.StatusCode > 0 {
		item = fmt.Sprintf("[%d] %s", f.StatusCode, f.URL)
	}
	if f.Title != "" {
		item = fmt.Sprintf("%s (%s)", item, f.Title)
	}
	return toolbridge.DiscoveryItem{Section: "URLs", Key: f.URL, Item: item}
}

func crawlDiscoveryItems(findings []core.CrawlFinding) []toolbridge.DiscoveryItem {
	items := make([]toolbridge.DiscoveryItem, 0, len(findings))
	for _, f := range findings {
		items = append(items, crawlDiscoveryItem(f))
	}
	return items
}

func paramDiscoveryItems(params map[string]core.ParamDetail) []toolbridge.DiscoveryItem {
	items := make([]toolbridge.DiscoveryItem, 0, len(params))
	for name, detail := range params {
		if strings.TrimSpace(name) == "" {
			continue
		}
		item := fmt.Sprintf("?%s=", name)
		if len(detail.Sources) > 0 {
			item = fmt.Sprintf("%s (%s)", item, strings.Join(detail.Sources, ", "))
		}
		items = append(items, toolbridge.DiscoveryItem{Section: "Params", Key: name, Item: item})
	}
	return items
}

func jsDiscoveryItems(result *core.JSAnalysisResult) []toolbridge.DiscoveryItem {
	if result == nil {
		return nil
	}
	var items []toolbridge.DiscoveryItem
	for _, scriptURL := range result.ScriptURLs {
		items = append(items, toolbridge.DiscoveryItem{Section: "JS Files", Key: scriptURL, Item: scriptURL})
	}
	for _, endpoint := range result.Endpoints {
		items = append(items, toolbridge.DiscoveryItem{Section: "Endpoints", Key: endpoint, Item: endpoint})
	}
	for _, secret := range result.Secrets {
		key := strings.Join([]string{secret.Category, secret.Value, secret.Evidence, secret.SourceURL}, "|")
		source := firstNonBlank(secret.SourceURL, secret.SourceKind, "unknown source")
		value := firstNonBlank(secret.Value, secret.Evidence, "matched secret")
		items = append(items, toolbridge.DiscoveryItem{
			Section: "Secrets",
			Key:     key,
			Item:    fmt.Sprintf("%s: %s (%s)", secret.Category, value, source),
		})
	}
	for _, param := range result.HiddenParams {
		items = append(items, toolbridge.DiscoveryItem{Section: "Params", Key: param, Item: fmt.Sprintf("?%s= (js)", param)})
	}
	return items
}

func apiDiscoveryItems(result *core.APISurfaceResult) []toolbridge.DiscoveryItem {
	if result == nil {
		return nil
	}
	items := make([]toolbridge.DiscoveryItem, 0, len(result.APIEndpoints)+len(result.APISpecs))
	for _, endpoint := range result.APIEndpoints {
		method := firstNonBlank(endpoint.Method, "ANY")
		item := fmt.Sprintf("[%s] %s", method, firstNonBlank(endpoint.URL, endpoint.Path))
		if endpoint.StatusCode > 0 {
			item = fmt.Sprintf("%s (%d)", item, endpoint.StatusCode)
		}
		if endpoint.APIType != "" {
			item = fmt.Sprintf("%s %s", item, endpoint.APIType)
		}
		if endpoint.AuthRequired {
			item = fmt.Sprintf("%s auth-required", item)
		}
		if endpoint.Confidence > 0 {
			item = fmt.Sprintf("%s confidence=%.2f", item, endpoint.Confidence)
		}
		if len(endpoint.Parameters) > 0 {
			item = fmt.Sprintf("%s params=%d", item, len(endpoint.Parameters))
		}
		items = append(items, toolbridge.DiscoveryItem{
			Section: "Endpoints",
			Key:     firstNonBlank(endpoint.URL, endpoint.Path),
			Item:    item,
		})
	}
	for _, spec := range result.APISpecs {
		item := fmt.Sprintf("[SPEC] %s", spec.URL)
		if spec.Format != "" {
			item = fmt.Sprintf("%s %s", item, spec.Format)
		}
		if spec.EndpointCount > 0 {
			item = fmt.Sprintf("%s (%d endpoints)", item, spec.EndpointCount)
		}
		if spec.DiscoveredEndpointCount > 0 {
			item = fmt.Sprintf("%s discovered=%d", item, spec.DiscoveredEndpointCount)
		}
		if spec.CoveragePercent > 0 {
			item = fmt.Sprintf("%s spec-coverage=%.0f%%", item, spec.CoveragePercent)
		}
		items = append(items, toolbridge.DiscoveryItem{Section: "Endpoints", Key: spec.URL, Item: item})
	}
	return items
}

func apiParameterDiscoveryItems(params []core.APIParameterFinding) []toolbridge.DiscoveryItem {
	items := make([]toolbridge.DiscoveryItem, 0, len(params))
	for _, param := range params {
		name := strings.TrimSpace(param.Name)
		if name == "" {
			continue
		}
		location := firstNonBlank(param.In, "api")
		details := []string{fmt.Sprintf("in=%s", location)}
		if param.Type != "" {
			details = append(details, fmt.Sprintf("type=%s", param.Type))
		}
		if param.Required {
			details = append(details, "required")
		}
		if len(param.Endpoints) > 0 {
			details = append(details, fmt.Sprintf("endpoints=%d", len(param.Endpoints)))
		}
		if len(param.Sources) > 0 {
			details = append(details, fmt.Sprintf("sources=%d", len(param.Sources)))
		}
		items = append(items, toolbridge.DiscoveryItem{
			Section: "Params",
			Key:     strings.Join([]string{"api", location, name}, "|"),
			Item:    fmt.Sprintf("[api] %s %s", name, strings.Join(details, " ")),
		})
	}
	return items
}

func formatPortDiscovery(p core.PortResult) string {
	parts := []string{fmt.Sprintf(":%d", p.Port)}
	if p.State != "" {
		parts = append(parts, p.State)
	}
	if p.Service != "" {
		parts = append(parts, p.Service)
	}
	if len(p.Technology) > 0 {
		parts = append(parts, strings.Join(p.Technology, ","))
	}
	if p.Banner != "" {
		parts = append(parts, p.Banner)
	}
	return strings.Join(parts, " ")
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
