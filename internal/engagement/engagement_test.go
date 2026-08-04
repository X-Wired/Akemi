package engagement

import (
	"testing"
)

func TestRequiresApprovalAutoApprovesSafeTools(t *testing.T) {
	mgr := NewManager(ApprovalAsk)

	// Safe/read-only tools must not require approval in ApprovalAsk mode
	safeTools := []string{
		"akemi_get_finding",
		"akemi_search_findings",
		"akemi_get_target",
		"akemi_read_report",
		"akemi_run_status",
		"akemi_summarize_run",
		"akemi_check_headers",
		"akemi_analyze_js",
		"akemi_subdomain_enum",
	}

	for _, tool := range safeTools {
		req := Request{ToolName: tool, Risk: "safe"}
		if mgr.RequiresApproval(req) {
			t.Errorf("RequiresApproval(%s, safe) = true; want false (auto-approved)", tool)
		}
	}

	// Aggressive/invasive/active tools must require operator approval
	aggressiveTools := []string{
		"akemi_probe_vulns",
		"akemi_auth_capture",
		"akemi_fuzz",
		"akemi_full_surface_map",
		"akemi_port_scan",
	}

	for _, tool := range aggressiveTools {
		req := Request{ToolName: tool, Risk: "active"}
		if !mgr.RequiresApproval(req) {
			t.Errorf("RequiresApproval(%s, active) = false; want true (requires approval)", tool)
		}
	}
}
