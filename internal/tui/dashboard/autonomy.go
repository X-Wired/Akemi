package dashboard

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	core "Akemi/internal/core"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// =============================================================================
// Autonomy Mode Constants
// =============================================================================

// AutonomyMode controls how the agent behaves during autonomous operations.
type AutonomyMode int

const (
	AutonomyManual   AutonomyMode = iota // Manual chat only (current behavior)
	AutonomyObserver                     // Watch discoveries, suggest next actions
	AutonomyHunt                         // Auto-launch follow-up tools on discoveries
	AutonomyTriage                       // Prioritize findings by exploitability
)

// String returns a human-readable label for the mode.
func (m AutonomyMode) String() string {
	switch m {
	case AutonomyManual:
		return "MANUAL"
	case AutonomyObserver:
		return "OBSERVER"
	case AutonomyHunt:
		return "HUNT"
	case AutonomyTriage:
		return "TRIAGE"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Autonomy Data Types
// =============================================================================

// AutonomySuggestion is a recommended next action for the operator or agent.
type AutonomySuggestion struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	Rationale     string `json:"rationale"`
	Priority      int    `json:"priority"` // 1=highest
	SuggestedTool string `json:"suggested_tool"`
	AutoApproved  bool   `json:"auto_approved"`
}

// AutonomyTask is a queued task for hunt mode auto-execution.
type AutonomyTask struct {
	ID             string                 `json:"id"`
	ToolName       string                 `json:"tool_name"`
	Args           map[string]interface{} `json:"args"`
	TriggerFinding string                 `json:"trigger_finding"` // what discovery triggered this
	AutoApproved   bool                   `json:"auto_approved"`
}

// AttackChain represents a series of related attack steps chained together.
type AttackChain struct {
	ID               string       `json:"id"`
	Title            string       `json:"title"`
	Description      string       `json:"description"`
	Steps            []AttackStep `json:"steps"`
	RiskScore        float64      `json:"risk_score"` // 0-100
	Severity         string       `json:"severity"`   // overall severity label
	ExploitDBMatches []string     `json:"exploitdb_matches"`
	Remediation      string       `json:"remediation,omitempty"`
}

// AttackStep is one link in an attack chain.
type AttackStep struct {
	Order          int                 `json:"order"`
	FindingType    string              `json:"finding_type"`
	Title          string              `json:"title"`
	Target         string              `json:"target"`
	Description    string              `json:"description"`
	Evidence       string              `json:"evidence"`
	Severity       string              `json:"severity"`
	IsExploitable  bool                `json:"is_exploitable"`
	ExploitMatches []core.ExploitMatch `json:"exploit_matches,omitempty"`
}

// AutonomyEvent records an autonomy decision for the log.
type AutonomyEvent struct {
	Time   time.Time    `json:"time"`
	Mode   AutonomyMode `json:"mode"`
	Action string       `json:"action"`
	Detail string       `json:"detail"`
}

// =============================================================================
// Autonomy Message Types
// =============================================================================

// AutonomyModeChangeMsg requests a mode switch.
type AutonomyModeChangeMsg struct {
	Mode AutonomyMode
}

// AutonomySuggestionMsg carries pending suggestions to the UI.
type AutonomySuggestionMsg struct {
	Suggestions []AutonomySuggestion
}

// AutonomyTaskRequestMsg carries a hunt-mode task that needs approval.
type AutonomyTaskRequestMsg struct {
	Task AutonomyTask
}

// AttackChainMsg carries correlated attack chains from triage mode.
type AttackChainMsg struct {
	Chains []AttackChain
}

// AutonomyEventMsg carries a single autonomy event for logging.
type AutonomyEventMsg struct {
	Event AutonomyEvent
}

// =============================================================================
// AutonomyController
// =============================================================================

// AutonomyController manages agent autonomy modes, suggestions, hunt tasks,
// and triage-based attack chain correlation.
type AutonomyController struct {
	mu   sync.Mutex
	mode AutonomyMode

	enabled bool

	suggestions       []AutonomySuggestion
	pendingTasks      []AutonomyTask
	findings          []core.VulnFinding
	correlationGroups []AttackChain

	// toolApprovalPolicy maps tool names to whether they are auto-approved.
	// true = auto-approved, false = requires operator approval.
	toolApprovalPolicy map[string]bool

	eventLog []AutonomyEvent

	// Counters for generating unique IDs.
	suggestionSeq int
	taskSeq       int
	chainSeq      int
}

// NewAutonomyController initializes an AutonomyController with Observer mode
// as the default and pre-populates safe-tool approval policies.
func NewAutonomyController() *AutonomyController {
	ac := &AutonomyController{
		mode:    AutonomyObserver,
		enabled: true,
		toolApprovalPolicy: map[string]bool{
			// Safe / passive recon tools — auto-approved
			"akemi_list_templates":   true,
			"akemi_check_headers":    true,
			"akemi_tech_fingerprint": true,
			"akemi_dns_lookup":       true,
			"akemi_crtsh_enum":       true,
			"akemi_whois":            true,
			// Active tools — require approval
			"akemi_port_scan":       false,
			"akemi_crawl":           false,
			"akemi_probe_vulns":     false,
			"akemi_fuzz_params":     false,
			"akemi_check_exploitdb": false,
			"akemi_brute_force":     false,
		},
		suggestions:       make([]AutonomySuggestion, 0),
		pendingTasks:      make([]AutonomyTask, 0),
		findings:          make([]core.VulnFinding, 0),
		correlationGroups: make([]AttackChain, 0),
		eventLog:          make([]AutonomyEvent, 0),
	}
	return ac
}

// =============================================================================
// Mode Management
// =============================================================================

// SetMode switches the autonomy mode and resets transient state.
func (ac *AutonomyController) SetMode(mode AutonomyMode) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	oldMode := ac.mode
	ac.mode = mode
	ac.enabled = mode != AutonomyManual

	// Reset transient state on mode switch
	ac.suggestions = ac.suggestions[:0]
	ac.pendingTasks = ac.pendingTasks[:0]
	ac.correlationGroups = ac.correlationGroups[:0]

	ac.logEvent(mode, "mode_switch", fmt.Sprintf("Switched from %s to %s", oldMode, mode))
}

// Mode returns the current autonomy mode.
func (ac *AutonomyController) Mode() AutonomyMode {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	return ac.mode
}

// Enabled returns whether autonomy features are active.
func (ac *AutonomyController) Enabled() bool {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	return ac.enabled
}

// =============================================================================
// Discovery Processing
// =============================================================================

// ProcessDiscovery analyzes a new discovery item and returns suggestions or
// hunt tasks depending on the current mode.
func (ac *AutonomyController) ProcessDiscovery(ctx context.Context, item DiscoveryItemMsg) []AutonomySuggestion {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if !ac.enabled {
		return nil
	}

	key := strings.ToLower(item.Key)
	value := strings.ToLower(item.Item)

	switch ac.mode {
	case AutonomyObserver:
		suggestions := ac.generateSuggestions(key, value)
		ac.suggestions = append(ac.suggestions, suggestions...)
		ac.logEvent(ac.mode, "suggestion_generated", fmt.Sprintf("%d suggestions for %s", len(suggestions), item.Key))
		return suggestions

	case AutonomyHunt:
		suggestions := ac.generateSuggestions(key, value)
		var huntSuggestions []AutonomySuggestion
		for _, s := range suggestions {
			task := ac.createHuntTask(s, item)
			if task != nil {
				ac.pendingTasks = append(ac.pendingTasks, *task)
				if !task.AutoApproved {
					huntSuggestions = append(huntSuggestions, s)
				}
			}
		}
		ac.logEvent(ac.mode, "hunt_tasks_queued", fmt.Sprintf("%d tasks from %s", len(suggestions), item.Key))
		return huntSuggestions

	default:
		return nil
	}
}

// generateSuggestions maps a discovery key/value to actionable suggestions.
func (ac *AutonomyController) generateSuggestions(key, value string) []AutonomySuggestion {
	var out []AutonomySuggestion

	switch {
	// Subdomain found
	case strings.Contains(key, "subdomain") || strings.Contains(key, "hostname"):
		out = append(out, ac.newSuggestion(
			"Run port scan on new subdomain",
			fmt.Sprintf("Discovered subdomain: %s. Port scanning can reveal services and attack surface.", value),
			"New subdomains often expose services not present on the main domain.",
			2,
			"akemi_port_scan",
		))

	// Open port found (SSH, RDP, etc.)
	case strings.Contains(key, "port") || strings.Contains(key, "service"):
		if isSensitivePort(value) {
			out = append(out, ac.newSuggestion(
				"Check for default credentials",
				fmt.Sprintf("Port %s is open — test for default/weak credentials on this service.", value),
				"Sensitive ports like SSH, RDP, and databases are common entry points with default creds.",
				1,
				"akemi_check_default_creds",
			))
		}
		out = append(out, ac.newSuggestion(
			"Banner grab and fingerprint service",
			fmt.Sprintf("Identify the service version on port %s for known vulnerabilities.", value),
			"Service fingerprinting enables targeted vulnerability lookups.",
			3,
			"akemi_service_fingerprint",
		))

	// API endpoint found
	case strings.Contains(key, "endpoint") || strings.Contains(key, "api") || strings.Contains(key, "url"):
		out = append(out, ac.newSuggestion(
			"Run API-specific vulnerability probes",
			fmt.Sprintf("API endpoint %s should be probed for auth issues, injection, and misconfigurations.", value),
			"API endpoints are high-value targets for IDOR, auth bypass, and injection.",
			1,
			"akemi_probe_api",
		))

	// Secret or key found
	case strings.Contains(key, "secret") || strings.Contains(key, "key") || strings.Contains(key, "token") ||
		strings.Contains(value, "api_key") || strings.Contains(value, "secret") || strings.Contains(value, "password"):
		out = append(out, ac.newSuggestion(
			"Validate if secret is still active",
			fmt.Sprintf("Secret discovered: %s — verify whether it's still valid and what access it grants.", value),
			"Exposed secrets can provide direct access to cloud resources, APIs, or internal systems.",
			1,
			"akemi_validate_secret",
		))

	// JS file found
	case strings.Contains(key, "js") || strings.Contains(key, "javascript") || strings.Contains(key, "script"):
		out = append(out, ac.newSuggestion(
			"Analyze JS for more endpoints and secrets",
			fmt.Sprintf("JavaScript file %s may contain hidden API endpoints, secrets, or hardcoded credentials.", value),
			"JS files frequently leak API routes, internal paths, and sometimes tokens or keys.",
			2,
			"akemi_analyze_js",
		))

	// Parameter found (id=, user=, etc.)
	case strings.Contains(key, "param") || strings.Contains(key, "parameter") || strings.Contains(key, "query"):
		out = append(out, ac.newSuggestion(
			"Test for SQLi/LFI on this parameter",
			fmt.Sprintf("Parameter %s should be tested for SQL injection, LFI, and other injection flaws.", value),
			"User-supplied parameters are the most common injection vectors.",
			1,
			"akemi_test_injection",
		))

	// Error page or stack trace
	case strings.Contains(key, "error") || strings.Contains(key, "stack") || strings.Contains(key, "trace") ||
		strings.Contains(value, "stack trace") || strings.Contains(value, "exception"):
		out = append(out, ac.newSuggestion(
			"Check for information disclosure",
			fmt.Sprintf("Error page or stack trace found: %s — this may leak framework versions, paths, or credentials.", value),
			"Error messages often reveal internal architecture that aids further attacks.",
			2,
			"akemi_check_info_disclosure",
		))

	// Admin panel URL
	case strings.Contains(key, "admin") || strings.Contains(value, "admin") ||
		strings.Contains(value, "dashboard") || strings.Contains(value, "console"):
		out = append(out, ac.newSuggestion(
			"Test for default credentials / auth bypass",
			fmt.Sprintf("Admin panel %s should be tested for default credentials, auth bypass, and access control issues.", value),
			"Admin interfaces are high-value targets that may have weak authentication.",
			1,
			"akemi_test_auth_bypass",
		))

	default:
		// Generic interesting discovery
		out = append(out, ac.newSuggestion(
			"Investigate discovery further",
			fmt.Sprintf("Discovery '%s' may warrant deeper investigation.", value),
			"Any new discovery can be a pivot point for further reconnaissance.",
			3,
			"",
		))
	}

	return out
}

// createHuntTask converts a suggestion into a concrete hunt-mode task.
func (ac *AutonomyController) createHuntTask(suggestion AutonomySuggestion, trigger DiscoveryItemMsg) *AutonomyTask {
	if suggestion.SuggestedTool == "" {
		return nil
	}

	ac.taskSeq++
	task := &AutonomyTask{
		ID:             fmt.Sprintf("hunt-%04d", ac.taskSeq),
		ToolName:       suggestion.SuggestedTool,
		Args:           map[string]interface{}{"target": trigger.Item},
		TriggerFinding: suggestion.Title,
		AutoApproved:   ac.toolApprovalPolicy[suggestion.SuggestedTool],
	}
	return task
}

// =============================================================================
// Scan Completion Processing
// =============================================================================

// ProcessScanComplete analyzes completed scan findings and returns correlated
// attack chains (triage mode) or summary suggestions (observer mode).
func (ac *AutonomyController) ProcessScanComplete(findings []core.VulnFinding) []AttackChain {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.findings = append(ac.findings, findings...)

	switch ac.mode {
	case AutonomyTriage:
		chains := ac.buildAttackChains(findings)
		ac.correlationGroups = append(ac.correlationGroups, chains...)
		ac.logEvent(ac.mode, "triage_complete", fmt.Sprintf("Built %d attack chains from %d findings", len(chains), len(findings)))
		return chains

	case AutonomyObserver:
		ac.generateScanSummary(findings)
		ac.logEvent(ac.mode, "scan_summary", fmt.Sprintf("Generated summary for %d findings", len(findings)))
		return nil

	default:
		return nil
	}
}

// buildAttackChains groups findings into attack chains, calculates risk scores,
// and matches with potential ExploitDB references.
func (ac *AutonomyController) buildAttackChains(findings []core.VulnFinding) []AttackChain {
	if len(findings) == 0 {
		return nil
	}

	// Group findings by target
	byTarget := make(map[string][]core.VulnFinding)
	for _, f := range findings {
		target := f.Target
		if target == "" {
			target = "unknown"
		}
		byTarget[target] = append(byTarget[target], f)
	}

	var chains []AttackChain
	for target, group := range byTarget {
		ac.chainSeq++
		chain := AttackChain{
			ID:          fmt.Sprintf("chain-%04d", ac.chainSeq),
			Title:       fmt.Sprintf("Attack Chain: %s", target),
			Description: fmt.Sprintf("Correlated findings targeting %s", target),
			Steps:       make([]AttackStep, 0, len(group)),
		}

		totalRisk := 0.0
		severityWeights := map[string]float64{
			"critical": 100,
			"high":     75,
			"medium":   50,
			"low":      25,
			"info":     10,
		}

		for _, f := range group {
			step := AttackStep{
				FindingType: f.Name,
				Description: f.Description,
				Evidence:    f.Evidence,
				Severity:    f.Severity,
			}
			chain.Steps = append(chain.Steps, step)

			if w, ok := severityWeights[strings.ToLower(f.Severity)]; ok {
				totalRisk += w
			}
		}

		// Normalize risk score to 0-100
		chain.RiskScore = totalRisk / float64(len(group))
		if chain.RiskScore > 100 {
			chain.RiskScore = 100
		}

		// Match against known exploit patterns
		chain.ExploitDBMatches = ac.matchExploitDB(group)

		chains = append(chains, chain)
	}

	// Sort chains by risk score descending
	for i := 0; i < len(chains)-1; i++ {
		for j := i + 1; j < len(chains); j++ {
			if chains[j].RiskScore > chains[i].RiskScore {
				chains[i], chains[j] = chains[j], chains[i]
			}
		}
	}

	return chains
}

// matchExploitDB returns potential ExploitDB matches based on finding names.
func (ac *AutonomyController) matchExploitDB(findings []core.VulnFinding) []string {
	// Map common vulnerability names to potential ExploitDB search terms.
	exploitPatterns := map[string]string{
		"sqli":            "SQL Injection",
		"sql injection":   "SQL Injection",
		"xss":             "Cross-Site Scripting",
		"csrf":            "CSRF",
		"lfi":             "Local File Inclusion",
		"rfi":             "Remote File Inclusion",
		"rce":             "Remote Code Execution",
		"ssrf":            "Server-Side Request Forgery",
		"idor":            "Insecure Direct Object Reference",
		"ssti":            "Server-Side Template Injection",
		"xxe":             "XML External Entity",
		"deserialization": "Insecure Deserialization",
		"upload":          "Unrestricted File Upload",
		"auth":            "Authentication Bypass",
		"default creds":   "Default Credentials",
		"open port":       "Open Port Exposure",
		"directory":       "Directory Listing",
		"information":     "Information Disclosure",
	}

	seen := make(map[string]bool)
	var matches []string
	for _, f := range findings {
		lower := strings.ToLower(f.Name + " " + f.Description)
		for pattern, label := range exploitPatterns {
			if strings.Contains(lower, pattern) && !seen[label] {
				seen[label] = true
				matches = append(matches, label)
			}
		}
	}
	return matches
}

// generateScanSummary creates summary suggestions for observer mode.
func (ac *AutonomyController) generateScanSummary(findings []core.VulnFinding) {
	critCount := 0
	highCount := 0
	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			critCount++
		case "high":
			highCount++
		}
	}

	if critCount > 0 {
		ac.suggestions = append(ac.suggestions, ac.newSuggestion(
			"Critical findings require immediate triage",
			fmt.Sprintf("%d critical finding(s) found. Switch to Triage mode to build attack chains.", critCount),
			"Critical vulnerabilities should be prioritized and correlated for maximum impact assessment.",
			1,
			"",
		))
	}
	if highCount > 0 {
		ac.suggestions = append(ac.suggestions, ac.newSuggestion(
			"High-severity findings warrant follow-up",
			fmt.Sprintf("%d high-severity finding(s). Consider deeper validation and chaining.", highCount),
			"High-severity findings often chain together into critical attack paths.",
			2,
			"",
		))
	}
	if critCount+highCount == 0 && len(findings) > 0 {
		ac.suggestions = append(ac.suggestions, ac.newSuggestion(
			"Scan complete — review findings",
			fmt.Sprintf("%d finding(s) discovered. Review for potential chaining opportunities.", len(findings)),
			"Even lower-severity findings can be chained into critical exploits.",
			3,
			"",
		))
	}
}

// =============================================================================
// Finding Processing
// =============================================================================

// ProcessFinding handles a new vulnerability finding and generates contextual
// suggestions based on the finding type.
func (ac *AutonomyController) ProcessFinding(finding core.VulnFinding) []AutonomySuggestion {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.findings = append(ac.findings, finding)

	if !ac.enabled || ac.mode == AutonomyManual {
		return nil
	}

	var suggestions []AutonomySuggestion
	lowerName := strings.ToLower(finding.Name)
	lowerDesc := strings.ToLower(finding.Description)

	switch {
	case strings.Contains(lowerName, "sqli") || strings.Contains(lowerDesc, "sql injection"):
		suggestions = append(suggestions, ac.newSuggestion(
			"Attempt SQLMap or manual exploitation",
			fmt.Sprintf("SQL injection on %s — attempt data extraction to confirm impact.", finding.Target),
			"SQLi is one of the most impactful vulnerabilities when exploitable.",
			1,
			"akemi_exploit_sqli",
		))

	case strings.Contains(lowerName, "xss") || strings.Contains(lowerDesc, "cross-site"):
		suggestions = append(suggestions, ac.newSuggestion(
			"Validate XSS with payload variants",
			fmt.Sprintf("XSS on %s — test for stored/DOM/reflected variants and cookie access.", finding.Target),
			"XSS can lead to session hijacking, phishing, and client-side attacks.",
			2,
			"akemi_validate_xss",
		))

	case strings.Contains(lowerName, "rce") || strings.Contains(lowerDesc, "remote code execution"):
		suggestions = append(suggestions, ac.newSuggestion(
			"Attempt safe RCE validation",
			fmt.Sprintf("RCE on %s — attempt a safe command (e.g., 'id', 'whoami') to confirm.", finding.Target),
			"RCE is the highest-impact finding; confirm with minimal safe commands.",
			1,
			"akemi_validate_rce",
		))

	case strings.Contains(lowerName, "ssrf") || strings.Contains(lowerDesc, "server-side request"):
		suggestions = append(suggestions, ac.newSuggestion(
			"Validate SSRF with internal service probes",
			fmt.Sprintf("SSRF on %s — probe internal metadata endpoints and services.", finding.Target),
			"SSRF can expose internal infrastructure and cloud metadata.",
			1,
			"akemi_validate_ssrf",
		))

	case strings.Contains(lowerName, "open") && strings.Contains(lowerName, "port"):
		suggestions = append(suggestions, ac.newSuggestion(
			"Enumerate services on open port",
			fmt.Sprintf("Open port finding on %s — identify service versions and known exploits.", finding.Target),
			"Open ports are the entry points for network-based attacks.",
			2,
			"akemi_enum_services",
		))

	case finding.Severity == "critical" || finding.Severity == "high":
		suggestions = append(suggestions, ac.newSuggestion(
			"Prioritize exploitation validation",
			fmt.Sprintf("%s severity finding: %s — validate exploitability immediately.", finding.Severity, finding.Name),
			"High/critical findings need immediate validation to assess real-world impact.",
			1,
			"",
		))
	}

	// In Hunt mode, queue auto-tasks for the suggestions
	if ac.mode == AutonomyHunt {
		for _, s := range suggestions {
			if s.SuggestedTool != "" && ac.toolApprovalPolicy[s.SuggestedTool] {
				ac.taskSeq++
				task := AutonomyTask{
					ID:             fmt.Sprintf("hunt-%04d", ac.taskSeq),
					ToolName:       s.SuggestedTool,
					Args:           map[string]interface{}{"target": finding.Target},
					TriggerFinding: finding.Name,
					AutoApproved:   true,
				}
				ac.pendingTasks = append(ac.pendingTasks, task)
			}
		}
	}

	ac.suggestions = append(ac.suggestions, suggestions...)
	ac.logEvent(ac.mode, "finding_processed", fmt.Sprintf("%s: %s", finding.Severity, finding.Name))

	return suggestions
}

// =============================================================================
// Query Methods
// =============================================================================

// SuggestNextActions returns the current set of pending suggestions.
func (ac *AutonomyController) SuggestNextActions(ctx context.Context) []AutonomySuggestion {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	result := make([]AutonomySuggestion, len(ac.suggestions))
	copy(result, ac.suggestions)
	return result
}

// PendingApprovalTasks returns hunt tasks that require operator approval.
func (ac *AutonomyController) PendingApprovalTasks() []AutonomyTask {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	var pending []AutonomyTask
	for _, t := range ac.pendingTasks {
		if !t.AutoApproved {
			pending = append(pending, t)
		}
	}
	return pending
}

// AutoApprovedTasks returns hunt tasks that were auto-approved and can be
// dispatched without operator intervention.
func (ac *AutonomyController) AutoApprovedTasks() []AutonomyTask {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	var approved []AutonomyTask
	for _, t := range ac.pendingTasks {
		if t.AutoApproved {
			approved = append(approved, t)
		}
	}
	return approved
}

// ClearTasks removes all pending hunt tasks.
func (ac *AutonomyController) ClearTasks() {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.pendingTasks = ac.pendingTasks[:0]
}

// ClearSuggestions removes all pending suggestions.
func (ac *AutonomyController) ClearSuggestions() {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.suggestions = ac.suggestions[:0]
}

// AttackChains returns the current set of correlated attack chains.
func (ac *AutonomyController) AttackChains() []AttackChain {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	result := make([]AttackChain, len(ac.correlationGroups))
	copy(result, ac.correlationGroups)
	return result
}

// EventLog returns a copy of the autonomy event log.
func (ac *AutonomyController) EventLog() []AutonomyEvent {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	result := make([]AutonomyEvent, len(ac.eventLog))
	copy(result, ac.eventLog)
	return result
}

// =============================================================================
// View Rendering
// =============================================================================

// View renders a compact autonomy status bar suitable for embedding in or
// below the AgentPanel.
func (ac *AutonomyController) View(width int) string {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if width < 10 {
		width = 10
	}

	// Mode badge
	modeBadge := ac.renderModeBadge()

	// Stats
	suggestionCount := len(ac.suggestions)
	taskCount := len(ac.pendingTasks)
	chainCount := len(ac.correlationGroups)

	statsParts := []string{modeBadge}

	if ac.enabled {
		statsParts = append(statsParts, fmt.Sprintf("%d suggestions", suggestionCount))
	} else {
		statsParts = append(statsParts, "manual only")
	}

	if ac.mode == AutonomyHunt {
		statsParts = append(statsParts, fmt.Sprintf("%d tasks", taskCount))
	}
	if ac.mode == AutonomyTriage {
		statsParts = append(statsParts, fmt.Sprintf("%d chains", chainCount))
		statsParts = append(statsParts, fmt.Sprintf("%d findings", len(ac.findings)))
	}

	statusText := strings.Join(statsParts, " │ ")

	// Ensure it fits in width
	if lipgloss.Width(statusText) > width-4 {
		statusText = statusText[:max(0, width-7)] + "..."
	}

	// Build the bar
	barStyle := lipgloss.NewStyle().
		Foreground(PurpleLight).
		Padding(0, 2).
		Width(width - 4).
		MaxWidth(width - 4)

	divider := lipgloss.NewStyle().
		Foreground(GrayDim).
		Render(strings.Repeat("─", max(0, width-4)))

	return divider + "\n" + barStyle.Render(statusText)
}

// renderModeBadge returns a styled badge for the current mode.
func (ac *AutonomyController) renderModeBadge() string {
	var badgeStyle lipgloss.Style
	switch ac.mode {
	case AutonomyManual:
		badgeStyle = lipgloss.NewStyle().
			Foreground(Gray).
			Bold(true)
	case AutonomyObserver:
		badgeStyle = lipgloss.NewStyle().
			Foreground(PurpleLight).
			Bold(true)
	case AutonomyHunt:
		badgeStyle = lipgloss.NewStyle().
			Foreground(Orange).
			Bold(true)
	case AutonomyTriage:
		badgeStyle = lipgloss.NewStyle().
			Foreground(Red).
			Bold(true)
	default:
		badgeStyle = lipgloss.NewStyle().Foreground(Gray)
	}

	return badgeStyle.Render("[" + ac.mode.String() + "]")
}

// =============================================================================
// Bubble Tea Update
// =============================================================================

// Update handles autonomy-related messages. Returns the updated controller
// (same instance) and any commands to dispatch.
func (ac *AutonomyController) Update(msg tea.Msg) (*AutonomyController, tea.Cmd) {
	switch msg := msg.(type) {
	case AutonomyModeChangeMsg:
		ac.SetMode(msg.Mode)
		return ac, nil

	case AutonomyTaskRequestMsg:
		ac.mu.Lock()
		ac.pendingTasks = append(ac.pendingTasks, msg.Task)
		ac.mu.Unlock()
		return ac, nil

	case AutonomySuggestionMsg:
		ac.mu.Lock()
		ac.suggestions = append(ac.suggestions, msg.Suggestions...)
		ac.mu.Unlock()
		return ac, nil

	case AttackChainMsg:
		ac.mu.Lock()
		ac.correlationGroups = append(ac.correlationGroups, msg.Chains...)
		ac.mu.Unlock()
		return ac, nil

	case AutonomyEventMsg:
		ac.mu.Lock()
		ac.eventLog = append(ac.eventLog, msg.Event)
		if len(ac.eventLog) > 200 {
			ac.eventLog = ac.eventLog[len(ac.eventLog)-200:]
		}
		ac.mu.Unlock()
		return ac, nil
	}

	return ac, nil
}

// =============================================================================
// Internal Helpers
// =============================================================================

// newSuggestion creates an AutonomySuggestion with a unique ID.
func (ac *AutonomyController) newSuggestion(title, description, rationale string, priority int, suggestedTool string) AutonomySuggestion {
	ac.suggestionSeq++
	id := fmt.Sprintf("sug-%04d", ac.suggestionSeq)
	autoApproved := false
	if suggestedTool != "" {
		autoApproved = ac.toolApprovalPolicy[suggestedTool]
	}
	return AutonomySuggestion{
		ID:            id,
		Title:         title,
		Description:   description,
		Rationale:     rationale,
		Priority:      priority,
		SuggestedTool: suggestedTool,
		AutoApproved:  autoApproved,
	}
}

// logEvent appends an autonomy event to the log, trimming if needed.
func (ac *AutonomyController) logEvent(mode AutonomyMode, action, detail string) {
	ac.eventLog = append(ac.eventLog, AutonomyEvent{
		Time:   time.Now(),
		Mode:   mode,
		Action: action,
		Detail: detail,
	})
	if len(ac.eventLog) > 500 {
		ac.eventLog = ac.eventLog[len(ac.eventLog)-500:]
	}
}

// =============================================================================
// Discovery Classification Helpers
// =============================================================================

// isSensitivePort returns true for ports that commonly have default credentials
// or are high-value for attackers.
func isSensitivePort(portValue string) bool {
	sensitivePorts := []string{
		"22",    // SSH
		"3389",  // RDP
		"3306",  // MySQL
		"5432",  // PostgreSQL
		"1433",  // MSSQL
		"27017", // MongoDB
		"6379",  // Redis
		"11211", // Memcached
		"5900",  // VNC
		"8080",  // Common admin
		"8443",  // HTTPS admin
		"9200",  // Elasticsearch
	}

	// Normalize the value for matching
	trimmed := strings.TrimSpace(portValue)
	for _, sp := range sensitivePorts {
		if strings.Contains(trimmed, sp) {
			return true
		}
	}
	return false
}
