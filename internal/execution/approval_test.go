package execution

import (
	"testing"

	"Akemi/internal/engagement"
)

func TestApprovalLifecycleRedactsArgumentsAndIsBounded(t *testing.T) {
	manager := NewManager(1)
	run, err := NewRunContext("run-approval", engagement.TargetProfile{Domain: "example.test"}, ScopePolicy{RootDomains: []string{"example.test"}, AllowSubdomains: true}, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	request, err := manager.RequestApproval(run, "akemi_destructive_test", "https://example.test", map[string]interface{}{"password": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if request.Arguments["password"] != "[REDACTED]" {
		t.Fatalf("approval arguments leaked secret: %#v", request.Arguments)
	}
	if !manager.IsApprovalApproved(request.ID, "akemi_destructive_test", "https://example.test") {
		if _, ok := manager.ResolveApproval(request.ID, ApprovalApproved); !ok {
			t.Fatal("approval was not resolved")
		}
	}
	if !manager.IsApprovalApproved(request.ID, "akemi_destructive_test", "https://example.test") {
		t.Fatal("approved action was not recognized")
	}
}
