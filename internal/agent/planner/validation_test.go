package planner

import "testing"

func TestValidatePlanRejectsCycles(t *testing.T) {
	plan := &Plan{Tasks: []*TaskNode{
		{ID: "a", DependsOn: []string{"b"}},
		{ID: "b", DependsOn: []string{"a"}},
	}}
	if err := ValidatePlan(plan); err == nil {
		t.Fatal("cyclic plan should be rejected")
	}
}

func TestValidatePlanAcceptsDAG(t *testing.T) {
	plan := &Plan{Tasks: []*TaskNode{
		{ID: "a"},
		{ID: "b", DependsOn: []string{"a"}},
	}}
	if err := ValidatePlan(plan); err != nil {
		t.Fatalf("valid DAG rejected: %v", err)
	}
}
