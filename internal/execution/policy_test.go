package execution

import (
	"context"
	"testing"

	agenttool "Akemi/internal/agent/tool"
	"Akemi/internal/engagement"
)

func TestValidateTargetAllowsRootSubdomain(t *testing.T) {
	scope := ScopePolicy{RootDomains: []string{"example.com"}, AllowSubdomains: true}
	if err := ValidateTarget(scope, "https://api.example.com/v1"); err != nil {
		t.Fatalf("root subdomain should be allowed: %v", err)
	}
}

func TestValidateTargetRejectsSimilarDomain(t *testing.T) {
	scope := ScopePolicy{RootDomains: []string{"example.com"}, AllowSubdomains: true}
	if err := ValidateTarget(scope, "https://example.com.evil.test"); err == nil {
		t.Fatal("similar domain should be rejected")
	}
}

func TestValidateTargetCIDRAndIPv6(t *testing.T) {
	scope := ScopePolicy{AuthorizedCIDRs: []string{"192.0.2.0/24", "2001:db8::/32"}}
	for _, target := range []string{"192.0.2.42", "2001:db8::10"} {
		if err := ValidateTarget(scope, target); err != nil {
			t.Fatalf("%s should be allowed: %v", target, err)
		}
	}
	if err := ValidateTarget(scope, "198.51.100.10"); err == nil {
		t.Fatal("out-of-scope IP should be rejected")
	}
}

func TestValidateTargetRejectsMissingScope(t *testing.T) {
	if err := ValidateTarget(ScopePolicy{}, "example.com"); err == nil {
		t.Fatal("missing scope should fail closed")
	}
}

func TestValidateRiskAllowsIntrusiveButRejectsDestructive(t *testing.T) {
	policy := DefaultPolicy()
	if err := ValidateRisk(policy, agenttool.RiskIntrusive); err != nil {
		t.Fatalf("intrusive work should be allowed by default: %v", err)
	}
	if err := ValidateRisk(policy, agenttool.RiskDestructive); err == nil {
		t.Fatal("destructive work should require approval")
	}
	policy.ApprovalMode = engagement.ApprovalAsk
	if err := ValidateRisk(policy, agenttool.RiskDestructive); err == nil {
		t.Fatal("destructive work should not be allowed by ask mode")
	}
}

func TestRequestBudgetCountsRetries(t *testing.T) {
	budget := NewRequestBudget(2)
	ctx := context.Background()
	if err := budget.Reserve(ctx); err != nil {
		t.Fatal(err)
	}
	if err := budget.Reserve(ctx); err != nil {
		t.Fatal(err)
	}
	if err := budget.Reserve(ctx); err == nil {
		t.Fatal("third request should exceed budget")
	}
}

func TestRedactValueMasksSensitiveData(t *testing.T) {
	value := map[string]interface{}{
		"target":   "example.com",
		"cookies":  []interface{}{map[string]interface{}{"name": "sid", "value": "secret"}},
		"evidence": "Authorization: Bearer abc",
	}
	redacted, notices := RedactValue(value)
	result := redacted.(map[string]interface{})
	if result["cookies"] != "[REDACTED]" {
		t.Fatalf("cookies were not redacted: %#v", result["cookies"])
	}
	if result["evidence"] != "[REDACTED]" {
		t.Fatalf("sensitive text was not redacted: %#v", result["evidence"])
	}
	if len(notices) < 2 {
		t.Fatalf("expected redaction notices, got %d", len(notices))
	}
}
