// Package results contains the versioned, redacted result contract shared by
// MCP tools, agents, reports, and the TUI.
package results

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"Akemi/internal/execution"
)

const SchemaVersion = "1"

type VerificationState string

const (
	VerificationSuspected VerificationState = "suspected"
	VerificationConfirmed VerificationState = "confirmed"
	VerificationNotTested VerificationState = "not_tested"
)

type Evidence struct {
	Type        string `json:"type"`
	Source      string `json:"source,omitempty"`
	Location    string `json:"location,omitempty"`
	Snippet     string `json:"snippet,omitempty"`
	RequestRef  string `json:"request_ref,omitempty"`
	ResponseRef string `json:"response_ref,omitempty"`
}

type Finding struct {
	ID           string                 `json:"id,omitempty"`
	Type         string                 `json:"type,omitempty"`
	Severity     string                 `json:"severity,omitempty"`
	Title        string                 `json:"title"`
	Description  string                 `json:"description,omitempty"`
	Target       string                 `json:"target,omitempty"`
	Confidence   float64                `json:"confidence,omitempty"`
	Verification VerificationState      `json:"verification"`
	Evidence     []Evidence             `json:"evidence,omitempty"`
	Remediation  string                 `json:"remediation,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	ObservedAt   time.Time              `json:"observed_at,omitempty"`
}

func (f Finding) DedupKey() string {
	if strings.TrimSpace(f.ID) != "" {
		return f.ID
	}
	value := strings.ToLower(strings.Join([]string{f.Type, f.Title, f.Target, f.Severity}, "\x00"))
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type StageError struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
	Partial bool   `json:"partial,omitempty"`
}

type ResultMetrics struct {
	RequestsSent int           `json:"requests_sent,omitempty"`
	ItemsFound   int           `json:"items_found,omitempty"`
	ItemsTested  int           `json:"items_tested,omitempty"`
	Duration     time.Duration `json:"duration,omitempty"`
}

type RedactionNotice struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type ResultEnvelope struct {
	SchemaVersion string                 `json:"schema_version"`
	RunID         string                 `json:"run_id,omitempty"`
	ToolName      string                 `json:"tool_name"`
	Status        execution.RunStatus    `json:"status"`
	Summary       string                 `json:"summary,omitempty"`
	Data          map[string]interface{} `json:"data,omitempty"`
	Findings      []Finding              `json:"findings,omitempty"`
	Errors        []StageError           `json:"errors,omitempty"`
	Metrics       ResultMetrics          `json:"metrics"`
	Redactions    []RedactionNotice      `json:"redactions,omitempty"`
}

// DeduplicateFindings collapses equivalent findings while retaining the most
// useful evidence. Confirmed findings win over suspected findings; ties keep
// the higher-confidence record.
func DeduplicateFindings(findings []Finding) []Finding {
	if len(findings) < 2 {
		return append([]Finding(nil), findings...)
	}
	byKey := make(map[string]Finding, len(findings))
	order := make([]string, 0, len(findings))
	for _, finding := range findings {
		key := finding.DedupKey()
		current, exists := byKey[key]
		if !exists {
			order = append(order, key)
			byKey[key] = finding
			continue
		}
		if finding.Verification == VerificationConfirmed && current.Verification != VerificationConfirmed {
			byKey[key] = finding
			continue
		}
		if finding.Confidence > current.Confidence {
			byKey[key] = finding
		}
	}
	out := make([]Finding, 0, len(order))
	for _, key := range order {
		out = append(out, byKey[key])
	}
	return out
}
func New(toolName string, runID string, status execution.RunStatus, summary string, data map[string]interface{}) ResultEnvelope {
	return ResultEnvelope{SchemaVersion: SchemaVersion, RunID: runID, ToolName: toolName, Status: status, Summary: summary, Data: data}
}

// WithLegacyFields preserves an existing structured result while exposing a
// stable _akemi envelope for new consumers.
func WithLegacyFields(legacy map[string]interface{}, envelope ResultEnvelope) map[string]interface{} {
	out := make(map[string]interface{}, len(legacy)+1)
	for key, value := range legacy {
		out[key] = value
	}
	out["_akemi"] = envelope
	return out
}

func Redact(value interface{}) (interface{}, []RedactionNotice) {
	redacted, notices := execution.RedactValue(value)
	out := make([]RedactionNotice, 0, len(notices))
	for _, notice := range notices {
		out = append(out, RedactionNotice{Path: notice.Path, Reason: notice.Reason})
	}
	return redacted, out
}

func ErrorEnvelope(toolName, runID string, status execution.RunStatus, err error) ResultEnvelope {
	message := ""
	if err != nil {
		message = err.Error()
	}
	return ResultEnvelope{
		SchemaVersion: SchemaVersion,
		RunID:         runID,
		ToolName:      toolName,
		Status:        status,
		Summary:       fmt.Sprintf("%s: %s", status, message),
		Errors:        []StageError{{Stage: toolName, Message: message}},
	}
}
