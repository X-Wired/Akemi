package results

import (
	"testing"

	"Akemi/internal/execution"
)

func TestWithLegacyFieldsPreservesTopLevelData(t *testing.T) {
	legacy := map[string]interface{}{"target": "example.com", "findings": []interface{}{}}
	envelope := New("akemi_crawl", "run-1", execution.RunCompleted, "ok", legacy)
	result := WithLegacyFields(legacy, envelope)
	if result["target"] != "example.com" {
		t.Fatal("legacy field was not preserved")
	}
	if result["_akemi"] == nil {
		t.Fatal("versioned envelope was not added")
	}
}

func TestFindingDedupKeyIsStable(t *testing.T) {
	left := Finding{Type: "vulnerability", Title: "Missing header", Target: "example.com", Severity: "low"}
	right := left
	if left.DedupKey() != right.DedupKey() {
		t.Fatal("dedup key changed for equivalent findings")
	}
}
func TestDeduplicateFindingsPrefersConfirmedEvidence(t *testing.T) {
	findings := DeduplicateFindings([]Finding{
		{Type: "xss", Title: "reflected input", Target: "https://example.test", Confidence: 0.4, Verification: VerificationSuspected},
		{Type: "xss", Title: "reflected input", Target: "https://example.test", Confidence: 0.9, Verification: VerificationConfirmed},
	})
	if len(findings) != 1 || findings[0].Verification != VerificationConfirmed || findings[0].Confidence != 0.9 {
		t.Fatalf("unexpected deduplicated findings: %#v", findings)
	}
}
