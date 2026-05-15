// Package memory provides the agent's memory system with three tiers:
//   - Working memory: current session state, ephemeral
//   - Episodic memory: past findings organized by scan session
//   - Semantic memory: learned patterns and technology fingerprints
package memory

import (
	"strings"
	"sync"
	"time"

	"Akemi/internal/agent/tool"
)

// AgentMemory is the complete memory system for an agent.
type AgentMemory struct {
	working  *WorkingMemory
	episodic *EpisodicStore
	semantic *SemanticStore
	mu       sync.RWMutex
}

// NewAgentMemory creates a new memory system.
func NewAgentMemory() *AgentMemory {
	return &AgentMemory{
		working:  NewWorkingMemory(),
		episodic: NewEpisodicStore(),
		semantic: NewSemanticStore(),
	}
}

// Working returns the working memory (current session).
func (m *AgentMemory) Working() *WorkingMemory {
	return m.working
}

// Episodic returns the episodic store (past scans).
func (m *AgentMemory) Episodic() *EpisodicStore {
	return m.episodic
}

// Semantic returns the semantic store (learned patterns).
func (m *AgentMemory) Semantic() *SemanticStore {
	return m.semantic
}

// Snapshot returns a read-only copy of all current findings.
func (m *AgentMemory) Snapshot() *MemorySnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return &MemorySnapshot{
		WorkingFindings: len(m.working.Findings()),
		PastScans:       m.episodic.ScanCount(),
		PatternsLearned: m.semantic.PatternCount(),
	}
}

// MemorySnapshot is a lightweight summary of memory state.
type MemorySnapshot struct {
	WorkingFindings int `json:"working_findings"`
	PastScans       int `json:"past_scans"`
	PatternsLearned int `json:"patterns_learned"`
}

// =============================================================================
// Working Memory — current session, ephemeral
// =============================================================================

// WorkingMemory holds the state of the current agent session.
type WorkingMemory struct {
	mu           sync.RWMutex
	sessionID    string
	findings     []*tool.Finding
	toolHistory  []*ToolCallRecord
	observations []string
	hypotheses   []*Hypothesis
}

// ToolCallRecord logs a single tool invocation.
type ToolCallRecord struct {
	SequenceNum int
	ToolName    string
	Args        map[string]interface{}
	Result      *tool.ToolResult
	Duration    time.Duration
	Error       error
}

// Hypothesis represents a working theory about a target.
type Hypothesis struct {
	Statement  string   `json:"statement"`
	Evidence   []string `json:"evidence"`   // Finding IDs that support this
	Confidence float64  `json:"confidence"` // 0.0 - 1.0
	Status     string   `json:"status"`     // unverified | confirmed | rejected
}

// NewWorkingMemory creates working memory.
func NewWorkingMemory() *WorkingMemory {
	return &WorkingMemory{
		findings:   make([]*tool.Finding, 0),
		hypotheses: make([]*Hypothesis, 0),
	}
}

// SetSessionID sets the current session ID.
func (wm *WorkingMemory) SetSessionID(id string) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.sessionID = id
}

// SessionID returns the current session ID.
func (wm *WorkingMemory) SessionID() string {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	return wm.sessionID
}

// AddFinding records a new finding.
func (wm *WorkingMemory) AddFinding(f *tool.Finding) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.findings = append(wm.findings, f)
}

// Findings returns all findings in this session.
func (wm *WorkingMemory) Findings() []*tool.Finding {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	result := make([]*tool.Finding, len(wm.findings))
	copy(result, wm.findings)
	return result
}

// RecordToolCall logs a tool invocation.
func (wm *WorkingMemory) RecordToolCall(record *ToolCallRecord) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.toolHistory = append(wm.toolHistory, record)
}

// ToolHistory returns the ordered tool call history.
func (wm *WorkingMemory) ToolHistory() []*ToolCallRecord {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	result := make([]*ToolCallRecord, len(wm.toolHistory))
	copy(result, wm.toolHistory)
	return result
}

// AddObservation records a free-form observation.
func (wm *WorkingMemory) AddObservation(obs string) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.observations = append(wm.observations, obs)
}

// AddHypothesis records a new hypothesis.
func (wm *WorkingMemory) AddHypothesis(h *Hypothesis) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.hypotheses = append(wm.hypotheses, h)
}

// Hypotheses returns all hypotheses.
func (wm *WorkingMemory) Hypotheses() []*Hypothesis {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	result := make([]*Hypothesis, len(wm.hypotheses))
	copy(result, wm.hypotheses)
	return result
}

// MatchFindings returns findings matching a filter function.
func (wm *WorkingMemory) MatchFindings(fn func(*tool.Finding) bool) []*tool.Finding {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	var matched []*tool.Finding
	for _, f := range wm.findings {
		if fn(f) {
			matched = append(matched, f)
		}
	}
	return matched
}

// =============================================================================
// Episodic Memory — past scan sessions
// =============================================================================

// EpisodicStore remembers past scans and their findings.
type EpisodicStore struct {
	mu    sync.RWMutex
	scans []*ScanRecord
}

// ScanRecord represents a completed scan session.
type ScanRecord struct {
	SessionID string          `json:"session_id"`
	Target    string          `json:"target"`
	StartedAt time.Time       `json:"started_at"`
	EndedAt   time.Time       `json:"ended_at"`
	Findings  []*tool.Finding `json:"findings"`
	Status    string          `json:"status"`
}

// NewEpisodicStore creates an episodic store.
func NewEpisodicStore() *EpisodicStore {
	return &EpisodicStore{
		scans: make([]*ScanRecord, 0),
	}
}

// AddScan stores a completed scan.
func (es *EpisodicStore) AddScan(scan *ScanRecord) {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.scans = append(es.scans, scan)
}

// ScanCount returns the number of stored scans.
func (es *EpisodicStore) ScanCount() int {
	es.mu.RLock()
	defer es.mu.RUnlock()
	return len(es.scans)
}

// FindByTarget returns scans for a specific target.
func (es *EpisodicStore) FindByTarget(target string) []*ScanRecord {
	es.mu.RLock()
	defer es.mu.RUnlock()
	var matches []*ScanRecord
	for _, s := range es.scans {
		if s.Target == target {
			matches = append(matches, s)
		}
	}
	return matches
}

// MostRecent returns the most recent scan for a target.
func (es *EpisodicStore) MostRecent(target string) *ScanRecord {
	es.mu.RLock()
	defer es.mu.RUnlock()
	var latest *ScanRecord
	for _, s := range es.scans {
		if s.Target == target && (latest == nil || s.EndedAt.After(latest.EndedAt)) {
			latest = s
		}
	}
	return latest
}

// =============================================================================
// Semantic Memory — learned patterns
// =============================================================================

// SemanticStore remembers technology patterns and their security implications.
type SemanticStore struct {
	mu       sync.RWMutex
	patterns []*SecurityPattern
}

// SecurityPattern encodes "if you see X, check for Y".
type SecurityPattern struct {
	ID          string   `json:"id"`
	Condition   string   `json:"condition"` // Trigger (e.g., "wordpress + xmlrpc.php")
	Action      string   `json:"action"`    // What to check (e.g., "test for XMLRPC amplification")
	ToolName    string   `json:"tool_name"` // Which tool performs the check
	Severity    string   `json:"severity"`
	SuccessRate float64  `json:"success_rate"` // How often this yields valid findings (0-1)
	Tags        []string `json:"tags"`
}

// NewSemanticStore creates a semantic store with common patterns.
func NewSemanticStore() *SemanticStore {
	ss := &SemanticStore{
		patterns: make([]*SecurityPattern, 0),
	}
	ss.seedCommonPatterns()
	return ss
}

// seedCommonPatterns adds well-known security patterns.
func (ss *SemanticStore) seedCommonPatterns() {
	defaults := []*SecurityPattern{
		{
			ID: "wordpress-xmlrpc", Condition: "WordPress detected",
			Action:   "Test for XMLRPC amplification and user enumeration via xmlrpc.php",
			ToolName: "akemi_probe_vulns", Severity: "medium", SuccessRate: 0.6,
			Tags: []string{"wordpress", "xmlrpc"},
		},
		{
			ID: "apache-struts", Condition: "Apache Struts detected",
			Action:   "Check for CVE-2017-5638 and other Struts RCE vulnerabilities",
			ToolName: "akemi_probe_vulns", Severity: "critical", SuccessRate: 0.4,
			Tags: []string{"apache", "struts", "java", "rce"},
		},
		{
			ID: "nginx-path-traversal", Condition: "nginx with alias directive",
			Action:   "Test for path traversal via misconfigured alias directives",
			ToolName: "akemi_probe_vulns", Severity: "high", SuccessRate: 0.3,
			Tags: []string{"nginx", "path-traversal"},
		},
		{
			ID: "jwt-none-alg", Condition: "JWT in Authorization header",
			Action:   "Test for JWT algorithm confusion (none algorithm, weak HMAC)",
			ToolName: "akemi_probe_vulns", Severity: "high", SuccessRate: 0.25,
			Tags: []string{"jwt", "auth"},
		},
		{
			ID: "graphql-introspection", Condition: "GraphQL endpoint found",
			Action:   "Check for GraphQL introspection enabled and query depth limits",
			ToolName: "akemi_probe_vulns", Severity: "medium", SuccessRate: 0.5,
			Tags: []string{"graphql", "api"},
		},
		{
			ID: "api-auth-required", Condition: "API endpoint requires authentication",
			Action:   "Use captured or provided cookies before probing authenticated API routes",
			ToolName: "akemi_api_hunter", Severity: "info", SuccessRate: 0.7,
			Tags: []string{"api", "auth"},
		},
		{
			ID: "openapi-spec", Condition: "OpenAPI specification discovered",
			Action:   "Compare documented operations with live API Hunter endpoint coverage",
			ToolName: "akemi_api_hunter", Severity: "info", SuccessRate: 0.8,
			Tags: []string{"api", "openapi"},
		},
		{
			ID: "phpinfo-exposed", Condition: "PHP detected",
			Action:   "Check for exposed phpinfo.php, phpinfo(), and PHP configuration leaks",
			ToolName: "akemi_fuzz", Severity: "medium", SuccessRate: 0.35,
			Tags: []string{"php", "info-disclosure"},
		},
		{
			ID: "git-exposure", Condition: "Web server detected",
			Action:   "Check for exposed .git directories and Git repository disclosure",
			ToolName: "akemi_fuzz", Severity: "high", SuccessRate: 0.2,
			Tags: []string{"git", "info-disclosure"},
		},
		{
			ID: "default-creds", Condition: "Admin panel discovered",
			Action:   "Test for common default credentials on admin interfaces",
			ToolName: "akemi_fuzz", Severity: "critical", SuccessRate: 0.15,
			Tags: []string{"default-credentials", "auth"},
		},
	}

	for _, p := range defaults {
		ss.AddPattern(p)
	}
}

// AddPattern registers a new security pattern.
func (ss *SemanticStore) AddPattern(p *SecurityPattern) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.patterns = append(ss.patterns, p)
}

// PatternCount returns the number of known patterns.
func (ss *SemanticStore) PatternCount() int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return len(ss.patterns)
}

// MatchPatterns finds patterns whose conditions match any of the given hints.
func (ss *SemanticStore) MatchPatterns(hints []string) []*SecurityPattern {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	var matches []*SecurityPattern
	for _, hint := range hints {
		hintLower := strings.ToLower(hint)
		for _, p := range ss.patterns {
			if strings.Contains(strings.ToLower(p.Condition), hintLower) {
				matches = append(matches, p)
			}
		}
	}
	return matches
}

// AllPatterns returns all known patterns.
func (ss *SemanticStore) AllPatterns() []*SecurityPattern {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	result := make([]*SecurityPattern, len(ss.patterns))
	copy(result, ss.patterns)
	return result
}
