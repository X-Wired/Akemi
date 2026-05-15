package dashboard

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	core "Akemi/internal/core"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// =============================================================================
// Correlation Result Type
// =============================================================================

// CorrelationResult is the output of a correlation run.
type CorrelationResult struct {
	Chains      []AttackChain
	TopRisks    []AttackChain // top 5 by risk score
	Summary     string
	GeneratedAt time.Time
}

// =============================================================================
// CorrelationEngine
// =============================================================================

// CorrelationEngine ingests vulnerability findings and exploit matches,
// then produces ranked attack chains by connecting related weaknesses.
type CorrelationEngine struct {
	findings       []core.VulnFinding
	chains         []AttackChain
	exploitMatches map[string][]core.ExploitMatch // finding ID → exploit matches
	mu             sync.RWMutex
}

// NewCorrelationEngine creates a ready-to-use CorrelationEngine.
func NewCorrelationEngine() *CorrelationEngine {
	return &CorrelationEngine{
		findings:       make([]core.VulnFinding, 0),
		chains:         make([]AttackChain, 0),
		exploitMatches: make(map[string][]core.ExploitMatch),
	}
}

// AddFinding appends a single vulnerability finding to the engine.
func (ce *CorrelationEngine) AddFinding(f core.VulnFinding) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.findings = append(ce.findings, f)
}

// AddFindings bulk-appends vulnerability findings.
func (ce *CorrelationEngine) AddFindings(findings []core.VulnFinding) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.findings = append(ce.findings, findings...)
}

// AddExploitMatches associates exploit-db matches with a finding.
func (ce *CorrelationEngine) AddExploitMatches(findingID string, matches []core.ExploitMatch) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.exploitMatches[findingID] = matches
}

// Findings returns a snapshot of all stored findings (thread-safe).
func (ce *CorrelationEngine) Findings() []core.VulnFinding {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	out := make([]core.VulnFinding, len(ce.findings))
	copy(out, ce.findings)
	return out
}

// Chains returns the last computed chains (thread-safe).
func (ce *CorrelationEngine) Chains() []AttackChain {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	out := make([]AttackChain, len(ce.chains))
	copy(out, ce.chains)
	return out
}

// Correlate runs the main correlation algorithm and returns ranked results.
//
// Heuristics:
//   - Group findings by Target
//   - Within each target, connect findings that share ports, URL paths,
//     technology names, or vulnerability classes.
//   - Single findings become single-step chains.
//   - Risk scores factor severity, exploitability, and chain length.
func (ce *CorrelationEngine) Correlate() CorrelationResult {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if len(ce.findings) == 0 {
		return CorrelationResult{
			Chains:      nil,
			TopRisks:    nil,
			Summary:     "No findings to correlate.",
			GeneratedAt: time.Now(),
		}
	}

	// ── Step 1: Group findings by target ──────────────────────────
	targetGroups := make(map[string][]core.VulnFinding)
	for _, f := range ce.findings {
		target := normalizeTarget(f.Target)
		targetGroups[target] = append(targetGroups[target], f)
	}

	// ── Step 2: Build chains for each target group ────────────────
	var allChains []AttackChain
	for target, group := range targetGroups {
		chains := ce.buildChainsForTarget(target, group)
		allChains = append(allChains, chains...)
	}

	// ── Step 3: Score and rank ─────────────────────────────────────
	for i := range allChains {
		allChains[i].RiskScore = ce.calculateRiskScore(&allChains[i])
		allChains[i].Severity = scoreToSeverity(allChains[i].RiskScore)
		allChains[i].Remediation = ce.generateRemediation(&allChains[i])
	}

	sort.Slice(allChains, func(i, j int) bool {
		return allChains[i].RiskScore > allChains[j].RiskScore
	})

	// ── Step 4: Build result ───────────────────────────────────────
	ce.chains = allChains

	topN := 5
	if len(allChains) < topN {
		topN = len(allChains)
	}
	topRisks := make([]AttackChain, topN)
	copy(topRisks, allChains[:topN])

	summary := buildSummary(allChains)

	return CorrelationResult{
		Chains:      allChains,
		TopRisks:    topRisks,
		Summary:     summary,
		GeneratedAt: time.Now(),
	}
}

// buildChainsForTarget groups a target's findings into connected components
// (chains) using shared connection keys.
func (ce *CorrelationEngine) buildChainsForTarget(target string, group []core.VulnFinding) []AttackChain {
	n := len(group)
	if n == 0 {
		return nil
	}
	if n == 1 {
		f := group[0]
		return []AttackChain{ce.singleStepChain(f)}
	}

	// Build adjacency list based on shared connection keys.
	adj := make([][]int, n)
	for i := range n {
		adj[i] = make([]int, 0)
	}

	// Pre-compute connection keys for each finding.
	keys := make([]map[string]struct{}, n)
	for i, f := range group {
		keys[i] = extractConnectionKeys(f)
	}

	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if shareKeys(keys[i], keys[j]) {
				adj[i] = append(adj[i], j)
				adj[j] = append(adj[j], i)
			}
		}
	}

	// Connected components via BFS.
	visited := make([]bool, n)
	var chains []AttackChain

	for i := 0; i < n; i++ {
		if visited[i] {
			continue
		}
		// BFS
		var comp []int
		queue := []int{i}
		visited[i] = true
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			comp = append(comp, cur)
			for _, nb := range adj[cur] {
				if !visited[nb] {
					visited[nb] = true
					queue = append(queue, nb)
				}
			}
		}

		// Build chain from component.
		compFindings := make([]core.VulnFinding, len(comp))
		for idx, ci := range comp {
			compFindings[idx] = group[ci]
		}
		chain := ce.buildChain(compFindings)
		chains = append(chains, chain)
	}

	return chains
}

// singleStepChain wraps a lone finding into a one-step chain.
func (ce *CorrelationEngine) singleStepChain(f core.VulnFinding) AttackChain {
	matches := ce.exploitMatches[f.ID]
	step := AttackStep{
		Order:          1,
		FindingType:    categorizeFinding(f),
		Title:          f.Name,
		Target:         f.Target,
		Description:    f.Description,
		Evidence:       f.Evidence,
		Severity:       f.Severity,
		IsExploitable:  len(matches) > 0,
		ExploitMatches: matches,
	}
	chain := AttackChain{
		ID:          fmt.Sprintf("chain-%s", f.ID),
		Title:       f.Name,
		Description: f.Description,
		Steps:       []AttackStep{step},
	}
	chain.ExploitDBMatches = collectEDBRefs(step.ExploitMatches)
	return chain
}

// buildChain constructs a chain from a connected set of findings,
// ordering steps logically (recon → service → vulnerability → exploit).
func (ce *CorrelationEngine) buildChain(findings []core.VulnFinding) AttackChain {
	// Sort steps by logical attack progression.
	sort.Slice(findings, func(i, j int) bool {
		return stepOrder(categorizeFinding(findings[i])) < stepOrder(categorizeFinding(findings[j]))
	})

	steps := make([]AttackStep, len(findings))
	var allRefs []string
	for i, f := range findings {
		matches := ce.exploitMatches[f.ID]
		step := AttackStep{
			Order:          i + 1,
			FindingType:    categorizeFinding(f),
			Title:          f.Name,
			Target:         f.Target,
			Description:    f.Description,
			Evidence:       f.Evidence,
			Severity:       f.Severity,
			IsExploitable:  len(matches) > 0,
			ExploitMatches: matches,
		}
		steps[i] = step
		allRefs = append(allRefs, collectEDBRefs(matches)...)
	}

	// Deduplicate EDB refs.
	allRefs = dedupStrings(allRefs)

	// Use the highest-severity finding's ID as the chain root.
	rootID := findings[0].ID
	rootSev := severityValue(findings[0].Severity)
	for _, f := range findings[1:] {
		if severityValue(f.Severity) > rootSev {
			rootID = f.ID
			rootSev = severityValue(f.Severity)
		}
	}

	chain := AttackChain{
		ID:               fmt.Sprintf("chain-%s", rootID),
		Title:            ce.chainTitle(findings),
		Description:      ce.chainDescription(findings),
		Steps:            steps,
		ExploitDBMatches: allRefs,
	}
	return chain
}

// chainTitle generates a descriptive title for a chain based on finding types.
func (ce *CorrelationEngine) chainTitle(findings []core.VulnFinding) string {
	types := make(map[string]int)
	for _, f := range findings {
		types[categorizeFinding(f)]++
	}

	hasPort := types["open_port"] > 0
	hasService := types["service_detected"] > 0
	hasSQLi := types["sql_injection"] > 0
	hasXSS := types["xss"] > 0
	hasSSRF := types["ssrf"] > 0
	hasCVE := types["cve_match"] > 0 || types["outdated_software"] > 0
	hasWeakAuth := types["weak_auth"] > 0 || types["default_credentials"] > 0
	hasNoRateLimit := types["no_rate_limiting"] > 0
	hasInfoDisc := types["info_disclosure"] > 0

	switch {
	case hasPort && hasService && hasSQLi:
		return "Database Compromise Attack Chain"
	case hasPort && hasService && hasWeakAuth:
		return "Service Takeover Attack Chain"
	case hasPort && hasWeakAuth && hasNoRateLimit:
		return "Brute Force Attack Chain"
	case hasCVE && hasSSRF:
		return "Known Exploit Chain"
	case hasCVE && (hasPort || hasService):
		return "Vulnerable Service Exploitation Chain"
	case hasSQLi && hasInfoDisc:
		return "Data Exfiltration Attack Chain"
	case hasXSS:
		return "Client-Side Attack Chain"
	case hasSSRF:
		return "Server-Side Request Forgery Chain"
	case hasCVE:
		return "Known Vulnerability Exploitation Chain"
	case hasWeakAuth:
		return "Authentication Bypass Attack Chain"
	case hasInfoDisc:
		return "Information Disclosure Chain"
	case hasPort && hasService:
		return "Network Service Reconnaissance Chain"
	case hasNoRateLimit:
		return "Rate Limit Abuse Chain"
	default:
		if len(findings) == 1 {
			return findings[0].Name
		}
		return fmt.Sprintf("Multi-Vector Attack Chain (%d findings)", len(findings))
	}
}

// chainDescription builds a concise description summarising the chain.
func (ce *CorrelationEngine) chainDescription(findings []core.VulnFinding) string {
	if len(findings) == 0 {
		return ""
	}
	if len(findings) == 1 {
		return findings[0].Description
	}

	types := make(map[string]int)
	for _, f := range findings {
		types[categorizeFinding(f)]++
	}

	parts := make([]string, 0)
	if types["open_port"] > 0 {
		parts = append(parts, "open ports were discovered")
	}
	if types["service_detected"] > 0 {
		parts = append(parts, "services were fingerprinted")
	}
	if types["outdated_software"] > 0 {
		parts = append(parts, "outdated software was identified")
	}
	if types["sql_injection"] > 0 {
		parts = append(parts, "SQL injection vectors exist")
	}
	if types["xss"] > 0 {
		parts = append(parts, "cross-site scripting is present")
	}
	if types["ssrf"] > 0 {
		parts = append(parts, "SSRF is exploitable")
	}
	if types["weak_auth"] > 0 {
		parts = append(parts, "authentication is weak")
	}
	if types["no_rate_limiting"] > 0 {
		parts = append(parts, "rate limiting is absent")
	}
	if types["cve_match"] > 0 {
		parts = append(parts, "known CVEs were matched")
	}

	if len(parts) == 0 {
		return fmt.Sprintf("An attack path involving %d correlated findings on %s.", len(findings), findings[0].Target)
	}
	return fmt.Sprintf("An attack path where %s on %s.", strings.Join(parts, ", "), findings[0].Target)
}

// calculateRiskScore computes a 0-100 risk score for a chain.
//
// Base score from the highest-severity step, bonuses for chain length,
// exploitability, and diversity of finding types.
func (ce *CorrelationEngine) calculateRiskScore(chain *AttackChain) float64 {
	if chain == nil || len(chain.Steps) == 0 {
		return 0
	}

	// Base score: highest individual severity score.
	baseScore := 0.0
	for _, s := range chain.Steps {
		sv := severityScore(s.Severity)
		if sv > baseScore {
			baseScore = sv
		}
	}

	// Chain-length bonus: +2 per additional step (max +20).
	lengthBonus := float64(len(chain.Steps)-1) * 2.0
	if lengthBonus > 20 {
		lengthBonus = 20
	}

	// Exploitability bonus: +5 per exploitable step (max +15).
	exploitBonus := 0.0
	for _, s := range chain.Steps {
		if s.IsExploitable {
			exploitBonus += 5
		}
	}
	if exploitBonus > 15 {
		exploitBonus = 15
	}

	// Type diversity bonus: +3 per unique finding type beyond the first (max +12).
	seenTypes := make(map[string]struct{})
	for _, s := range chain.Steps {
		seenTypes[s.FindingType] = struct{}{}
	}
	diversityBonus := float64(len(seenTypes)-1) * 3.0
	if diversityBonus > 12 {
		diversityBonus = 12
	}

	score := baseScore + lengthBonus + exploitBonus + diversityBonus
	if score > 100 {
		score = 100
	}
	if score < 5 {
		score = 5
	}
	return score
}

// generateRemediation produces human-readable remediation advice for a chain.
func (ce *CorrelationEngine) generateRemediation(chain *AttackChain) string {
	if chain == nil || len(chain.Steps) == 0 {
		return "No remediation needed."
	}

	typeSet := make(map[string]bool)
	for _, s := range chain.Steps {
		typeSet[s.FindingType] = true
	}

	var lines []string
	lines = append(lines, "Recommended remediation steps:")

	idx := 1
	if typeSet["open_port"] {
		lines = append(lines, fmt.Sprintf("  %d. Close unnecessary ports or restrict access with firewall rules.", idx))
		idx++
	}
	if typeSet["service_detected"] || typeSet["outdated_software"] {
		lines = append(lines, fmt.Sprintf("  %d. Update all services and software to the latest stable versions.", idx))
		idx++
	}
	if typeSet["sql_injection"] {
		lines = append(lines, fmt.Sprintf("  %d. Use parameterized queries / prepared statements for all database access.", idx))
		idx++
	}
	if typeSet["xss"] {
		lines = append(lines, fmt.Sprintf("  %d. Apply context-aware output encoding and Content-Security-Policy headers.", idx))
		idx++
	}
	if typeSet["ssrf"] {
		lines = append(lines, fmt.Sprintf("  %d. Validate and sanitize all user-supplied URLs; enforce an allowlist for outbound requests.", idx))
		idx++
	}
	if typeSet["weak_auth"] || typeSet["default_credentials"] {
		lines = append(lines, fmt.Sprintf("  %d. Enforce strong password policies and require multi-factor authentication.", idx))
		idx++
	}
	if typeSet["no_rate_limiting"] {
		lines = append(lines, fmt.Sprintf("  %d. Implement rate limiting on all login and API endpoints.", idx))
		idx++
	}
	if typeSet["cve_match"] {
		lines = append(lines, fmt.Sprintf("  %d. Apply vendor patches for the identified CVEs immediately.", idx))
		idx++
	}
	if typeSet["info_disclosure"] {
		lines = append(lines, fmt.Sprintf("  %d. Restrict verbose error messages and remove debug endpoints from production.", idx))
		idx++
	}
	if typeSet["missing_headers"] {
		lines = append(lines, fmt.Sprintf("  %d. Add missing security headers (HSTS, X-Frame-Options, CSP, etc.).", idx))
		idx++
	}

	if len(lines) == 1 {
		return "Apply standard security hardening practices and re-scan to verify."
	}
	return strings.Join(lines, "\n")
}

// =============================================================================
// Connection Key Helpers
// =============================================================================

// extractConnectionKeys returns a set of normalised tokens that can link
// findings together: ports, URL paths, technology names, vuln classes.
func extractConnectionKeys(f core.VulnFinding) map[string]struct{} {
	keys := make(map[string]struct{})

	combined := strings.ToLower(f.Name + " " + f.Description + " " + f.Evidence + " " + f.Target)

	// Extract port numbers.
	ports := extractPorts(combined)
	for _, p := range ports {
		keys["port:"+p] = struct{}{}
	}

	// Extract URL paths.
	paths := extractURLPaths(combined)
	for _, p := range paths {
		keys["path:"+p] = struct{}{}
	}

	// Extract technology / service names.
	techs := extractTechnologies(combined)
	for _, t := range techs {
		keys["tech:"+t] = struct{}{}
	}

	// Vulnerability class from the finding type.
	keys["class:"+categorizeFinding(f)] = struct{}{}

	return keys
}

// shareKeys returns true when two key sets have at least one key in common,
// excluding the generic "class:*" keys (which are too broad to connect on
// their own).
func shareKeys(a, b map[string]struct{}) bool {
	for k := range a {
		if strings.HasPrefix(k, "class:") {
			continue
		}
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}

// =============================================================================
// Finding Categorization
// =============================================================================

// categorizeFinding returns a machine-readable finding type based on
// keyword matching against the finding name, description, and evidence.
func categorizeFinding(f core.VulnFinding) string {
	combined := strings.ToLower(f.Name + " " + f.Description + " " + f.Evidence)

	switch {
	// Port / protocol
	case matchAny(combined,
		"open port", "port open", "listening port", "tcp port", "udp port",
		"port scan", "open tcp", "open udp"):
		return "open_port"

	// Service detection
	case matchAny(combined,
		"service detected", "service banner", "fingerprint", "version detected",
		"banner grab", "service running"):
		return "service_detected"

	// Outdated / vulnerable software
	case matchAny(combined,
		"outdated", "end of life", "end-of-life", "eol version",
		"unsupported version", "obsolete", "deprecated version"):
		return "outdated_software"

	// CVE match
	case matchAny(combined,
		"cve-", "cve ", "known vulnerability", "exploit available",
		"metasploit", "exploit-db", "public exploit"):
		return "cve_match"

	// SQL Injection
	case matchAny(combined,
		"sql injection", "sqli", "blind sql", "error-based sql",
		"union-based sql", "time-based sql", "stacked query"):
		return "sql_injection"

	// XSS
	case matchAny(combined,
		"cross-site scripting", "xss", "reflected xss", "stored xss",
		"dom xss", "dom-based xss"):
		return "xss"

	// SSRF
	case matchAny(combined,
		"ssrf", "server-side request forgery", "server side request forgery"):
		return "ssrf"

	// Weak authentication
	case matchAny(combined,
		"weak password", "weak auth", "password policy", "no password",
		"empty password", "blank password", "password hash", "plaintext password",
		"cleartext password"):
		return "weak_auth"

	// Default credentials
	case matchAny(combined,
		"default credential", "default password", "default login",
		"admin/admin", "root/root", "guest/guest"):
		return "default_credentials"

	// No rate limiting
	case matchAny(combined,
		"rate limit", "rate limiting", "no rate", "missing rate",
		"brute force", "bruteforce", "no lockout", "no throttle"):
		return "no_rate_limiting"

	// Information disclosure
	case matchAny(combined,
		"information disclosure", "info leak", "info disclosure",
		"verbose error", "stack trace", "debug mode", "directory listing",
		"source code disclosure", "sensitive data exposure", "data leak"):
		return "info_disclosure"

	// Missing security headers
	case matchAny(combined,
		"missing header", "security header", "hsts", "content-security-policy",
		"x-frame-options", "x-content-type-options", "csp header",
		"missing csp", "missing hsts", "referrer-policy"):
		return "missing_headers"

	// CSRF
	case matchAny(combined,
		"csrf", "cross-site request forgery", "xsrf", "missing csrf token",
		"no csrf"):
		return "csrf"

	// File inclusion
	case matchAny(combined,
		"lfi", "rfi", "local file inclusion", "remote file inclusion",
		"path traversal", "directory traversal", "../", "..\\"):
		return "file_inclusion"

	// Command injection
	case matchAny(combined,
		"command injection", "os command", "shell injection", "rce",
		"remote code execution", "code injection", "command exec"):
		return "command_injection"

	// Open redirect
	case matchAny(combined,
		"open redirect", "unvalidated redirect", "open redirection"):
		return "open_redirect"

	// Default case
	default:
		return "other"
	}
}

// stepOrder returns an integer ordering for attack progression.
// Lower numbers = earlier in the kill chain.
func stepOrder(findingType string) int {
	switch findingType {
	case "open_port":
		return 1
	case "service_detected":
		return 2
	case "info_disclosure":
		return 3
	case "outdated_software":
		return 4
	case "cve_match":
		return 5
	case "missing_headers":
		return 6
	case "weak_auth":
		return 7
	case "default_credentials":
		return 7
	case "no_rate_limiting":
		return 8
	case "sql_injection":
		return 9
	case "command_injection":
		return 9
	case "xss":
		return 10
	case "csrf":
		return 10
	case "ssrf":
		return 11
	case "file_inclusion":
		return 11
	case "open_redirect":
		return 12
	default:
		return 20
	}
}

// =============================================================================
// Scoring Helpers
// =============================================================================

// severityScore maps a severity label to a base score.
func severityScore(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 90
	case "high":
		return 70
	case "medium":
		return 50
	case "low":
		return 30
	case "info":
		return 10
	default:
		return 20
	}
}

// severityValue maps a severity label to an integer value for comparisons.
func severityValue(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// scoreToSeverity converts a numeric risk score back to a severity label.
func scoreToSeverity(score float64) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 65:
		return "high"
	case score >= 40:
		return "medium"
	case score >= 15:
		return "low"
	default:
		return "info"
	}
}

// =============================================================================
// Utility Helpers
// =============================================================================

// normalizeTarget trims and lowercases a target string for grouping.
func normalizeTarget(t string) string {
	t = strings.TrimSpace(t)
	t = strings.TrimSuffix(t, "/")
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "https://")
	t = strings.ToLower(t)
	return t
}

// extractPorts finds port numbers mentioned in text (e.g. "port 3306", ":22").
func extractPorts(s string) []string {
	var ports []string
	seen := make(map[string]struct{})

	// Match patterns like "port 3306", "port:3306", ":3306", "3306/tcp"
	words := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';' || r == '\n' || r == '\t' || r == '(' || r == ')'
	})
	for _, w := range words {
		w = strings.TrimSpace(w)
		w = strings.TrimSuffix(w, "/tcp")
		w = strings.TrimSuffix(w, "/udp")
		w = strings.TrimPrefix(w, ":")
		if isNumeric(w) {
			n := atoi(w, -1)
			if n >= 1 && n <= 65535 {
				if _, ok := seen[w]; !ok {
					ports = append(ports, w)
					seen[w] = struct{}{}
				}
			}
		}
	}
	return ports
}

// extractURLPaths finds URL path fragments in text.
func extractURLPaths(s string) []string {
	var paths []string
	seen := make(map[string]struct{})

	// Look for patterns like /api/users, /admin, /login
	words := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';' || r == '\n' || r == '\t' || r == '"' || r == '\''
	})
	for _, w := range words {
		w = strings.TrimSpace(w)
		if strings.HasPrefix(w, "/") && len(w) > 1 && !strings.HasPrefix(w, "//") {
			// Normalize: strip query string and fragment.
			if idx := strings.IndexAny(w, "?#"); idx >= 0 {
				w = w[:idx]
			}
			// Only keep paths that look like URL routes.
			if strings.ContainsAny(w[1:], "/") || isCommonPath(w) {
				if _, ok := seen[w]; !ok {
					paths = append(paths, w)
					seen[w] = struct{}{}
				}
			}
		}
	}
	return paths
}

// isCommonPath returns true for paths likely to be meaningful URL routes.
func isCommonPath(p string) bool {
	common := []string{
		"/api", "/admin", "/login", "/logout", "/user", "/users",
		"/upload", "/download", "/search", "/config", "/debug",
		"/wp-admin", "/wp-login", "/phpmyadmin", "/console",
	}
	for _, c := range common {
		if strings.EqualFold(p, c) {
			return true
		}
	}
	return false
}

// extractTechnologies finds technology / service names in text.
func extractTechnologies(s string) []string {
	known := []string{
		"mysql", "mariadb", "postgresql", "mongodb", "redis",
		"nginx", "apache", "iis", "tomcat", "nodejs", "node.js",
		"php", "python", "ruby", "django", "flask", "express",
		"laravel", "spring", "wordpress", "drupal", "joomla",
		"ssh", "ftp", "smtp", "dns", "telnet", "rdp", "smb",
		"openssh", "proftpd", "vsftpd", "postfix", "exim",
		"docker", "kubernetes", "k8s", "jenkins", "gitlab",
		"jquery", "react", "angular", "vue", "bootstrap",
		"openssl", "ssl", "tls",
	}
	var found []string
	seen := make(map[string]struct{})
	for _, tech := range known {
		if strings.Contains(s, tech) {
			if _, ok := seen[tech]; !ok {
				found = append(found, tech)
				seen[tech] = struct{}{}
			}
		}
	}
	return found
}

// collectEDBRefs extracts Exploit-DB IDs from a slice of ExploitMatch.
func collectEDBRefs(matches []core.ExploitMatch) []string {
	seen := make(map[string]struct{})
	var refs []string
	for _, m := range matches {
		id := extractEDBID(m.EDBURL)
		if id != "" {
			if _, ok := seen[id]; !ok {
				refs = append(refs, fmt.Sprintf("EDB-%s", id))
				seen[id] = struct{}{}
			}
		}
	}
	return refs
}

// extractEDBID pulls the numeric exploit ID from an exploit-db URL.
func extractEDBID(url string) string {
	// URL format: https://www.exploit-db.com/exploits/12345
	idx := strings.LastIndex(url, "/")
	if idx < 0 {
		return ""
	}
	id := url[idx+1:]
	if isNumeric(id) {
		return id
	}
	return ""
}

// matchAny returns true if any substring appears in the combined text.
func matchAny(combined string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(combined, sub) {
			return true
		}
	}
	return false
}

// isNumeric returns true when s consists only of digits.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// dedupStrings removes duplicates from a slice while preserving order.
func dedupStrings(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// buildSummary produces a one-line summary of correlation results.
func buildSummary(chains []AttackChain) string {
	if len(chains) == 0 {
		return "No attack chains identified."
	}
	crit := 0
	high := 0
	for _, c := range chains {
		switch c.Severity {
		case "critical":
			crit++
		case "high":
			high++
		}
	}
	if crit+high == 0 {
		return fmt.Sprintf("%d attack chain(s) identified — no critical or high risks.", len(chains))
	}
	return fmt.Sprintf("%d chain(s) — %d critical, %d high — prioritize immediate remediation.",
		len(chains), crit, high)
}

// =============================================================================
// CorrelationPanel — Terminal UI for attack chains
// =============================================================================

// CorrelationPanel displays the vulnerability correlation engine results
// in an interactive terminal panel.
type CorrelationPanel struct {
	focused        bool
	width          int
	height         int
	engine         *CorrelationEngine
	chains         []AttackChain
	selectedChain  int
	selectedStep   int
	detailExpanded bool
	viewport       viewport.Model
	scrollY        int
}

// NewCorrelationPanel creates a new correlation panel with its engine.
func NewCorrelationPanel() *CorrelationPanel {
	cp := &CorrelationPanel{
		engine:        NewCorrelationEngine(),
		selectedChain: 0,
		selectedStep:  0,
	}
	cp.viewport = viewport.New(40, 15)
	return cp
}

// Engine returns the underlying CorrelationEngine (so callers can feed data).
func (cp *CorrelationPanel) Engine() *CorrelationEngine {
	return cp.engine
}

// SetChains loads pre-computed chains for display.
func (cp *CorrelationPanel) SetChains(chains []AttackChain) {
	cp.chains = chains
	cp.selectedChain = 0
	cp.selectedStep = 0
	cp.scrollY = 0
	cp.updateViewport()
}

// SetSize updates the panel dimensions.
func (cp *CorrelationPanel) SetSize(w, h int) {
	cp.width = w
	cp.height = h
	cp.viewport.Width = w - 6
	cp.viewport.Height = h - 8
	if cp.viewport.Width < 10 {
		cp.viewport.Width = 10
	}
	if cp.viewport.Height < 3 {
		cp.viewport.Height = 3
	}
	cp.updateViewport()
}

// Init implements tea.Model.
func (cp *CorrelationPanel) Init() tea.Cmd {
	return nil
}

// Update handles keyboard and mouse events.
func (cp *CorrelationPanel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return cp.handleKey(msg)

	case tea.MouseMsg:
		return cp.handleMouse(msg)

	case ScanDoneMsg:
		// Feed findings into the engine and re-correlate.
		if msg.Findings != nil {
			cp.engine.AddFindings(msg.Findings)
		}
		result := cp.engine.Correlate()
		cp.chains = result.Chains
		cp.selectedChain = 0
		cp.selectedStep = 0
		cp.scrollY = 0
		cp.updateViewport()
		return cp, nil

	case ScanStartedMsg:
		// Reset on new scan.
		cp.engine = NewCorrelationEngine()
		cp.chains = nil
		cp.selectedChain = 0
		cp.selectedStep = 0
		cp.detailExpanded = false
		cp.scrollY = 0
		cp.updateViewport()
		return cp, nil
	}

	return cp, nil
}

func (cp *CorrelationPanel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	switch key {
	case "up", "k":
		if cp.detailExpanded {
			if cp.selectedStep > 0 {
				cp.selectedStep--
			}
		} else {
			if cp.selectedChain > 0 {
				cp.selectedChain--
			}
			// Adjust scroll.
			if cp.selectedChain < cp.scrollY {
				cp.scrollY = cp.selectedChain
			}
		}
		cp.updateViewport()
		return cp, nil

	case "down", "j":
		if cp.detailExpanded {
			if cp.selectedChain < len(cp.chains) {
				chain := cp.chains[cp.selectedChain]
				if cp.selectedStep < len(chain.Steps)-1 {
					cp.selectedStep++
				}
			}
		} else {
			if cp.selectedChain < len(cp.chains)-1 {
				cp.selectedChain++
			}
			// Adjust scroll.
			visible := cp.viewport.Height
			if cp.selectedChain >= cp.scrollY+visible {
				cp.scrollY = cp.selectedChain - visible + 1
				if cp.scrollY < 0 {
					cp.scrollY = 0
				}
			}
		}
		cp.updateViewport()
		return cp, nil

	case "enter":
		if len(cp.chains) == 0 {
			return cp, nil
		}
		cp.detailExpanded = !cp.detailExpanded
		cp.selectedStep = 0
		cp.updateViewport()
		return cp, nil

	case "esc":
		if cp.detailExpanded {
			cp.detailExpanded = false
			cp.selectedStep = 0
			cp.updateViewport()
			return cp, nil
		}
		return cp, nil

	case "tab":
		// Handled by parent.
		return cp, nil
	}

	return cp, nil
}

func (cp *CorrelationPanel) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	switch msg.Action {
	case tea.MouseActionPress:
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			if cp.scrollY > 0 {
				cp.scrollY--
				cp.updateViewport()
			}
		case tea.MouseButtonWheelDown:
			if cp.scrollY < len(cp.chains)-1 {
				cp.scrollY++
				cp.updateViewport()
			}
		case tea.MouseButtonLeft:
			// Approximate click-to-select: map Y to chain index.
			headerLines := 3 // title, help, divider
			clickedIdx := msg.Y - headerLines + cp.scrollY
			if clickedIdx >= 0 && clickedIdx < len(cp.chains) {
				cp.selectedChain = clickedIdx
				cp.detailExpanded = true
				cp.selectedStep = 0
				cp.updateViewport()
			}
		}
	}
	return cp, nil
}

// updateViewport rebuilds the scrollable content of the chain list.
func (cp *CorrelationPanel) updateViewport() {
	var sb strings.Builder

	if len(cp.chains) == 0 {
		sb.WriteString(DimText.Render("  No attack chains yet — run a scan to correlate findings."))
		cp.viewport.SetContent(sb.String())
		return
	}

	for i, chain := range cp.chains {
		if i < cp.scrollY {
			continue
		}
		if i > cp.scrollY+50 {
			break
		}

		selected := i == cp.selectedChain

		// ── Row prefix ──
		prefix := "  "
		if selected {
			prefix = AccentText.Render("▶ ")
		}

		// ── Risk score bar (ASCII) ──
		bar := riskBar(chain.RiskScore, 12)

		// ── Severity tag ──
		tag := SeverityTag(chain.Severity)
		tagStyle := SeverityStyle(chain.Severity)

		// ── Title ──
		title := chain.Title
		if selected {
			title = AccentText.Render(title)
		} else {
			title = DimText.Render(title)
		}

		// ── Step count ──
		stepInfo := DimText.Render(fmt.Sprintf("(%d steps)", len(chain.Steps)))

		sb.WriteString(fmt.Sprintf("%s%s %s %s %s\n",
			prefix, bar, tagStyle.Render(tag), title, stepInfo))

		// ── ExploitDB refs on a sub-line ──
		if len(chain.ExploitDBMatches) > 0 {
			refStr := strings.Join(chain.ExploitDBMatches, " ")
			sb.WriteString(DimText.Render(fmt.Sprintf("     ⚡ %s\n", refStr)))
		}

		// ── Expanded detail ──
		if selected && cp.detailExpanded {
			sb.WriteString(cp.renderChainDetail(chain))
		}
	}

	cp.viewport.SetContent(sb.String())
}

// renderChainDetail renders the expanded view of a chain's steps.
func (cp *CorrelationPanel) renderChainDetail(chain AttackChain) string {
	var sb strings.Builder

	// Separator
	sb.WriteString(DimText.Render("     " + strings.Repeat("─", max(cp.width-12, 20))))
	sb.WriteString("\n")

	for i, step := range chain.Steps {
		stepSelected := i == cp.selectedStep

		// Step indicator
		marker := "  "
		if stepSelected {
			marker = AccentText.Render("▸ ")
		}

		sevStyle := SeverityStyle(step.Severity)
		sevTag := SeverityTag(step.Severity)

		titleStyle := DimText
		if stepSelected {
			titleStyle = AccentText
		}

		// Exploitable marker
		exploitMarker := ""
		if step.IsExploitable {
			exploitMarker = WarnText.Render(" ⚡exploitable")
		}

		sb.WriteString(fmt.Sprintf("     %s[%d] %s %s%s\n",
			marker, step.Order, sevStyle.Render(sevTag),
			titleStyle.Render(step.Title), exploitMarker))

		// Target
		if step.Target != "" {
			sb.WriteString(DimText.Render(fmt.Sprintf("          Target: %s\n", step.Target)))
		}

		// Evidence (truncated for display)
		if step.Evidence != "" {
			ev := step.Evidence
			ev = strings.ReplaceAll(ev, "\n", " ")
			if len(ev) > 100 {
				ev = ev[:97] + "..."
			}
			sb.WriteString(DimText.Render(fmt.Sprintf("          Evidence: %s\n", ev)))
		}

		// Exploit matches inline
		if len(step.ExploitMatches) > 0 {
			for _, m := range step.ExploitMatches {
				edbID := extractEDBID(m.EDBURL)
				sb.WriteString(AccentText.Render(fmt.Sprintf("          EDB-%s: %s\n", edbID, m.Description)))
			}
		}

		sb.WriteString("\n")
	}

	// Remediation
	sb.WriteString(SuccessText.Render("     💡 Remediation:"))
	sb.WriteString("\n")
	sb.WriteString(DimText.Render(fmt.Sprintf("     %s\n", chain.Remediation)))

	return sb.String()
}

// View renders the full correlation panel.
func (cp *CorrelationPanel) View() string {
	var sb strings.Builder

	// ── Title ──
	title := PanelTitle
	if cp.focused {
		title = PanelTitleFocused
	}
	sb.WriteString(title.Render("🔗 Attack Chains"))
	sb.WriteString("\n")

	// ── Help ──
	sb.WriteString(HelpText.Render("↑↓ navigate  enter expand/collapse  tab next panel"))
	sb.WriteString("\n")

	// ── Divider ──
	sb.WriteString(DimText.Render(strings.Repeat("─", max(cp.width-4, 20))))
	sb.WriteString("\n")

	// ── Chain list (scrollable) ──
	sb.WriteString(cp.viewport.View())

	// ── Footer: summary ──
	if len(cp.chains) > 0 {
		sb.WriteString("\n")
		sb.WriteString(DimText.Render(strings.Repeat("─", max(cp.width-4, 20))))
		sb.WriteString("\n")
		critCount := 0
		highCount := 0
		for _, c := range cp.chains {
			switch c.Severity {
			case "critical":
				critCount++
			case "high":
				highCount++
			}
		}
		footer := fmt.Sprintf(" %d chains | %d critical | %d high | Enter to expand",
			len(cp.chains), critCount, highCount)
		sb.WriteString(DimText.Render(footer))
	}

	return sb.String()
}

// Focused returns whether this panel has focus.
func (cp *CorrelationPanel) Focused() bool {
	return cp.focused
}

// Focus sets the panel focus state.
func (cp *CorrelationPanel) Focus(v bool) {
	cp.focused = v
}

// =============================================================================
// Risk Bar Rendering
// =============================================================================

// riskBar renders a compact ASCII risk-score bar.
//
//	Format: [████░░░░] 85
func riskBar(score float64, width int) string {
	if width < 4 {
		width = 4
	}
	filled := int(score / 100.0 * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}

	var barStyle lipgloss.Style
	switch {
	case score >= 85:
		barStyle = BarCrit
	case score >= 65:
		barStyle = BarHigh
	case score >= 40:
		barStyle = BarFull
	default:
		barStyle = BarTrack
	}

	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < width; i++ {
		if i < filled {
			sb.WriteString(barStyle.Render("█"))
		} else {
			sb.WriteString(BarEmpty.Render("░"))
		}
	}
	sb.WriteString("]")
	sb.WriteString(fmt.Sprintf(" %3.0f", score))
	return sb.String()
}
