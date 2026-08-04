// Package toolmeta contains the authoritative public tool contract used by
// MCP and agent adapters. Handlers remain compatibility-owned by their
// existing packages; this package owns the metadata that governs planning and
// safety decisions.
package toolmeta

import (
	"time"

	agenttool "Akemi/internal/agent/tool"
)

type Descriptor struct {
	Name             string
	Aliases          []string
	Category         agenttool.Category
	Risk             agenttool.RiskLevel
	ReadOnly         bool
	Destructive      bool
	OpenWorld        bool
	Idempotent       bool
	RequiresApproval bool
	Provides         []string
	Requires         []string
	DefaultTimeout   time.Duration
	MaxRetries       int
	AssistantVisible bool
}

var descriptors = map[string]Descriptor{
	"akemi_port_scan":         {Name: "akemi_port_scan", Category: agenttool.CategoryRecon, Risk: agenttool.RiskActive, ReadOnly: false, OpenWorld: true, Idempotent: true, AssistantVisible: true, Provides: []string{"open_ports", "services", "banners", "technologies"}},
	"akemi_host_discover":     {Name: "akemi_host_discover", Category: agenttool.CategoryRecon, Risk: agenttool.RiskActive, ReadOnly: false, OpenWorld: true, Idempotent: true, AssistantVisible: true, Provides: []string{"hosts"}},
	"akemi_subdomain_enum":    {Name: "akemi_subdomain_enum", Category: agenttool.CategoryRecon, Risk: agenttool.RiskPassive, ReadOnly: true, OpenWorld: true, Idempotent: true, AssistantVisible: true, Provides: []string{"subdomains"}},
	"akemi_dork":              {Name: "akemi_dork", Category: agenttool.CategoryRecon, Risk: agenttool.RiskPassive, ReadOnly: true, OpenWorld: true, Idempotent: true, AssistantVisible: true},
	"akemi_crawl":             {Name: "akemi_crawl", Category: agenttool.CategoryDiscovery, Risk: agenttool.RiskActive, ReadOnly: false, OpenWorld: true, AssistantVisible: true, Provides: []string{"urls"}},
	"akemi_full_surface_map":  {Name: "akemi_full_surface_map", Category: agenttool.CategoryDiscovery, Risk: agenttool.RiskActive, ReadOnly: false, OpenWorld: true, AssistantVisible: true, Provides: []string{"surface_map", "open_ports", "urls", "parameters", "api_endpoints", "subdomains", "findings", "secrets"}},
	"akemi_full_surface_scan": {Name: "akemi_full_surface_scan", Aliases: []string{"full_surface_scan", "full_surface_map"}, Category: agenttool.CategoryDiscovery, Risk: agenttool.RiskActive, ReadOnly: false, OpenWorld: true, AssistantVisible: true, Provides: []string{"surface_map", "open_ports", "urls", "parameters", "findings"}},
	"akemi_mine_params":       {Name: "akemi_mine_params", Category: agenttool.CategoryDiscovery, Risk: agenttool.RiskPassive, ReadOnly: false, OpenWorld: true, AssistantVisible: true, Provides: []string{"parameters"}, Requires: []string{"urls"}},
	"akemi_analyze_js":        {Name: "akemi_analyze_js", Category: agenttool.CategoryDiscovery, Risk: agenttool.RiskPassive, ReadOnly: true, OpenWorld: true, AssistantVisible: true, Provides: []string{"endpoints", "secrets", "hidden_params"}, Requires: []string{"urls"}},
	"akemi_scrape_page":       {Name: "akemi_scrape_page", Category: agenttool.CategoryDiscovery, Risk: agenttool.RiskActive, ReadOnly: false, OpenWorld: true, AssistantVisible: true},
	"akemi_discover_api":      {Name: "akemi_discover_api", Category: agenttool.CategoryDiscovery, Risk: agenttool.RiskPassive, ReadOnly: true, OpenWorld: true, AssistantVisible: true, Provides: []string{"api_endpoints", "api_specs"}, Requires: []string{"urls"}},
	"akemi_api_hunter":        {Name: "akemi_api_hunter", Category: agenttool.CategoryDiscovery, Risk: agenttool.RiskActive, ReadOnly: false, OpenWorld: true, AssistantVisible: true, Provides: []string{"api_endpoints", "api_specs", "api_parameters", "api_auth_hints"}, Requires: []string{"urls"}},
	"akemi_probe_vulns":       {Name: "akemi_probe_vulns", Category: agenttool.CategoryVulnerability, Risk: agenttool.RiskIntrusive, ReadOnly: false, OpenWorld: true, RequiresApproval: false, AssistantVisible: true, Provides: []string{"findings"}, Requires: []string{"parameters"}},
	"akemi_check_headers":     {Name: "akemi_check_headers", Category: agenttool.CategoryVulnerability, Risk: agenttool.RiskPassive, ReadOnly: true, OpenWorld: true, Idempotent: true, AssistantVisible: true, Provides: []string{"findings"}},
	"akemi_fuzz":              {Name: "akemi_fuzz", Category: agenttool.CategoryVulnerability, Risk: agenttool.RiskIntrusive, ReadOnly: false, OpenWorld: true, AssistantVisible: false},
	"akemi_auth_capture":      {Name: "akemi_auth_capture", Category: agenttool.CategoryVulnerability, Risk: agenttool.RiskIntrusive, ReadOnly: false, OpenWorld: true, RequiresApproval: true, AssistantVisible: false, Provides: []string{"auth_session"}},
	"akemi_exploit_lookup":    {Name: "akemi_exploit_lookup", Category: agenttool.CategoryExploitation, Risk: agenttool.RiskSafe, ReadOnly: true, Idempotent: true, AssistantVisible: false, Requires: []string{"technologies", "services"}},
	"akemi_generate_report":   {Name: "akemi_generate_report", Category: agenttool.CategoryReporting, Risk: agenttool.RiskSafe, ReadOnly: false, Idempotent: true, AssistantVisible: true, Provides: []string{"report"}},
	"akemi_generate_graph":    {Name: "akemi_generate_graph", Category: agenttool.CategoryReporting, Risk: agenttool.RiskSafe, ReadOnly: false, Idempotent: true, AssistantVisible: true, Provides: []string{"graph"}},
	"akemi_read_report":       {Name: "akemi_read_report", Category: agenttool.CategoryReporting, Risk: agenttool.RiskSafe, ReadOnly: true, Idempotent: true, AssistantVisible: true},
	"akemi_write_report":      {Name: "akemi_write_report", Category: agenttool.CategoryReporting, Risk: agenttool.RiskSafe, ReadOnly: false, AssistantVisible: true, Provides: []string{"report"}},
	"akemi_start_run":         {Name: "akemi_start_run", Category: agenttool.CategoryUtility, Risk: agenttool.RiskActive, ReadOnly: false, OpenWorld: true, AssistantVisible: true},
	"akemi_run_status":        {Name: "akemi_run_status", Category: agenttool.CategoryUtility, Risk: agenttool.RiskSafe, ReadOnly: true, Idempotent: true, AssistantVisible: true},
	"akemi_cancel_run":        {Name: "akemi_cancel_run", Category: agenttool.CategoryUtility, Risk: agenttool.RiskSafe, ReadOnly: false, AssistantVisible: true},
	"akemi_approve_action":    {Name: "akemi_approve_action", Category: agenttool.CategoryUtility, Risk: agenttool.RiskSafe, ReadOnly: false, AssistantVisible: true},
	"akemi_deny_action":       {Name: "akemi_deny_action", Category: agenttool.CategoryUtility, Risk: agenttool.RiskSafe, ReadOnly: false, AssistantVisible: true},
}

func Lookup(name string) (Descriptor, bool) {
	d, ok := descriptors[name]
	if !ok {
		return Descriptor{Name: name, Risk: agenttool.RiskPassive, ReadOnly: true, Idempotent: true, AssistantVisible: true}, false
	}
	return d, true
}

func Apply(t *agenttool.AgentTool) {
	if t == nil {
		return
	}
	d, _ := Lookup(t.Name)
	t.Category = d.Category
	t.RiskLevel = d.Risk
	t.IsIdempotent = d.Idempotent
	t.IsDestructive = d.Destructive
	t.RequiresApproval = d.RequiresApproval || d.Destructive
	if len(d.Provides) > 0 {
		t.Provides = append([]string(nil), d.Provides...)
	}
	if len(d.Requires) > 0 {
		t.Requires = append([]string(nil), d.Requires...)
	}
}
