// Package session manages per-target operation state across scans.
// It ensures consistency: once a crawl/discovery/API hunt is performed
// for a target in a session, it won't be re-run without explicit consent.
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Operation represents a distinct scan phase that should not be repeated
// for the same target without explicit user consent.
type Operation string

const (
	OpCrawl          Operation = "crawl"
	OpPortScan       Operation = "port_scan"
	OpParamMining    Operation = "param_mining"
	OpJSAnalysis     Operation = "js_analysis"
	OpAPIDiscovery   Operation = "api_discovery"
	OpAPIHunt        Operation = "api_hunter"
	OpSubdomainEnum  Operation = "subdomain_enum"
	OpVulnAssessment Operation = "vuln_assessment"
	OpSQLiHunt       Operation = "sqli_hunt"
	OpHeaderCheck    Operation = "header_check"
)

// AllDiscoveryOps lists every operation that falls under "discovery"
// (crawling, parameter mining, JS analysis, API discovery).
var AllDiscoveryOps = []Operation{
	OpCrawl,
	OpParamMining,
	OpJSAnalysis,
	OpAPIDiscovery,
	OpAPIHunt,
}

// AllScanOps lists every known operation.
var AllScanOps = []Operation{
	OpPortScan,
	OpCrawl,
	OpParamMining,
	OpJSAnalysis,
	OpAPIDiscovery,
	OpAPIHunt,
	OpSubdomainEnum,
	OpVulnAssessment,
	OpSQLiHunt,
	OpHeaderCheck,
}

// IntentToOps maps a scan intent to the operations it performs.
var IntentToOps = map[string][]Operation{
	"quick_recon":             {OpPortScan, OpCrawl, OpHeaderCheck},
	"full_surface_map":        {OpPortScan, OpCrawl, OpHeaderCheck, OpParamMining, OpJSAnalysis, OpAPIDiscovery, OpSubdomainEnum},
	"full_surface_scan":       {OpPortScan, OpCrawl, OpHeaderCheck, OpParamMining, OpJSAnalysis, OpAPIDiscovery, OpSubdomainEnum},
	"akemi_full_surface_map":  {OpPortScan, OpCrawl, OpHeaderCheck, OpParamMining, OpJSAnalysis, OpAPIDiscovery, OpSubdomainEnum},
	"akemi_full_surface_scan": {OpPortScan, OpCrawl, OpHeaderCheck, OpParamMining, OpJSAnalysis, OpAPIDiscovery, OpSubdomainEnum},
	"api_hunter":              {OpAPIHunt},
	"sqli_hunt":               {OpSQLiHunt},
	"vuln_assessment":         {OpVulnAssessment},
}

// CompletionRecord marks when an operation was last completed for a target.
type CompletionRecord struct {
	TargetID    string    `json:"target_id"`
	Operation   Operation `json:"operation"`
	CompletedAt time.Time `json:"completed_at"`
	SessionID   string    `json:"session_id,omitempty"`
}

// State tracks which operations have been completed per target within
// the current process lifetime. It can optionally persist to a Store.
type State struct {
	mu      sync.RWMutex
	records map[string]*CompletionRecord // key: "targetID|operation"

	// Store is an optional persistence backend (SQLite).
	store Store
}

// Store is the minimal persistence interface for session state.
// The operation parameter uses string to avoid type coupling with persist packages.
type Store interface {
	HasCompletedOperation(targetID string, op string) (bool, error)
	MarkOperationComplete(targetID string, op string) error
	ListCompletedOperations(targetID string) ([]string, error)
	Close() error
}

// New creates an in-memory session state tracker.
func New(store Store) *State {
	s := &State{
		records: make(map[string]*CompletionRecord),
		store:   store,
	}
	// If we have a store, pre-load any records it knows about.
	// (We can't enumerate all targets, but we preload nothing here;
	// checks go through the store first, then memory.)
	return s
}

// TargetID normalizes a target string into a consistent, opaque ID.
func TargetID(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")
	// Remove port if present
	if idx := strings.LastIndex(target, ":"); idx > 0 {
		// Only strip if it looks like a port (digits only after colon)
		port := target[idx+1:]
		isPort := true
		for _, c := range port {
			if c < '0' || c > '9' {
				isPort = false
				break
			}
		}
		if isPort {
			target = target[:idx]
		}
	}
	hash := sha256.Sum256([]byte(strings.ToLower(target)))
	return hex.EncodeToString(hash[:16])
}

func recordKey(targetID string, op Operation) string {
	return targetID + "|" + string(op)
}

// HasCompleted returns true if the operation has been completed for the target
// in the current session (in-memory or persisted).
func (s *State) HasCompleted(target string, op Operation) bool {
	targetID := TargetID(target)
	key := recordKey(targetID, op)

	s.mu.RLock()
	_, memExists := s.records[key]
	s.mu.RUnlock()
	if memExists {
		return true
	}

	// Check persistent store if available
	if s.store != nil {
		exists, err := s.store.HasCompletedOperation(targetID, string(op))
		if err == nil && exists {
			// Cache in memory for future fast checks
			s.mu.Lock()
			s.records[key] = &CompletionRecord{
				TargetID:  targetID,
				Operation: op,
			}
			s.mu.Unlock()
			return true
		}
	}

	return false
}

// MarkCompleted records that an operation has been completed for the target.
func (s *State) MarkCompleted(target string, op Operation) {
	targetID := TargetID(target)
	key := recordKey(targetID, op)
	record := &CompletionRecord{
		TargetID:    targetID,
		Operation:   op,
		CompletedAt: time.Now(),
	}

	s.mu.Lock()
	s.records[key] = record
	s.mu.Unlock()

	// Persist if store available
	if s.store != nil {
		_ = s.store.MarkOperationComplete(targetID, string(op))
	}
}

// HasAnyDiscoveryCompleted returns true if any discovery operation has been
// completed for the target (crawl, param mining, JS analysis, API discovery).
func (s *State) HasAnyDiscoveryCompleted(target string) bool {
	for _, op := range AllDiscoveryOps {
		if s.HasCompleted(target, op) {
			return true
		}
	}
	return false
}

// ListCompleted returns all operations completed for a target.
func (s *State) ListCompleted(target string) []Operation {
	targetID := TargetID(target)
	seen := make(map[Operation]bool)

	s.mu.RLock()
	for key := range s.records {
		if strings.HasPrefix(key, targetID+"|") {
			parts := strings.SplitN(key, "|", 2)
			if len(parts) == 2 {
				seen[Operation(parts[1])] = true
			}
		}
	}
	s.mu.RUnlock()

	// Merge from store if available
	if s.store != nil {
		ops, err := s.store.ListCompletedOperations(targetID)
		if err == nil {
			for _, op := range ops {
				seen[Operation(op)] = true
			}
		}
	}

	result := make([]Operation, 0, len(seen))
	for op := range seen {
		result = append(result, op)
	}
	return result
}

// ClearTarget removes all records for a target (allows re-running operations).
func (s *State) ClearTarget(target string) {
	targetID := TargetID(target)
	prefix := targetID + "|"

	s.mu.Lock()
	for key := range s.records {
		if strings.HasPrefix(key, prefix) {
			delete(s.records, key)
		}
	}
	s.mu.Unlock()
}

// ClearOperation removes a specific operation record for a target.
func (s *State) ClearOperation(target string, op Operation) {
	targetID := TargetID(target)
	key := recordKey(targetID, op)

	s.mu.Lock()
	delete(s.records, key)
	s.mu.Unlock()
}

// ClearAll removes all in-memory records.
func (s *State) ClearAll() {
	s.mu.Lock()
	s.records = make(map[string]*CompletionRecord)
	s.mu.Unlock()
}

// Summary returns a human-readable summary of what has been done for a target.
func (s *State) Summary(target string) string {
	ops := s.ListCompleted(target)
	if len(ops) == 0 {
		return "no operations completed yet"
	}
	names := make([]string, len(ops))
	for i, op := range ops {
		names[i] = string(op)
	}
	return fmt.Sprintf("completed: %s", strings.Join(names, ", "))
}
