package tools

import (
	"testing"

	"Akemi/internal/mcp"
)

func TestValidateToolArgsChecksKnownTypesAndEnums(t *testing.T) {
	schema := mcp.ToolInputSchema{
		Type:     "object",
		Required: []string{"target"},
		Properties: map[string]mcp.Property{
			"target": {Type: "string"},
			"mode":   {Type: "string", Enum: []string{"passive", "safe-active"}},
		},
	}
	if err := validateToolArgs(schema, map[string]interface{}{"target": "example.com", "mode": "safe-active", "legacy": true}); err != nil {
		t.Fatalf("valid arguments rejected: %v", err)
	}
	if err := validateToolArgs(schema, map[string]interface{}{"target": 42}); err == nil {
		t.Fatal("wrong type should be rejected")
	}
	if err := validateToolArgs(schema, map[string]interface{}{}); err == nil {
		t.Fatal("missing required value should be rejected")
	}
}
