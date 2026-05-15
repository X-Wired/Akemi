// Package safety provides guardrails for autonomous agent operation.
// It enforces scope boundaries, rate limits, and confirmation requirements
// before any tool is allowed to execute against a target.
package safety

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"Akemi/internal/agent/tool"
)

// SafetyLayer validates that agent actions are safe before execution.
type SafetyLayer struct {
	scopeValidator   *ScopeValidator
	rateLimiter      *RateLimiter
	confirmationGate *ConfirmationGate
	maxAutoRisk      tool.RiskLevel
}

// NewSafetyLayer creates a safety layer with the given configuration.
func NewSafetyLayer(allowedDomains, allowedCIDRs, blockedDomains []string, maxRPM int) *SafetyLayer {
	return NewSafetyLayerWithPolicy(allowedDomains, allowedCIDRs, blockedDomains, maxRPM, tool.RiskActive)
}

// NewSafetyLayerWithPolicy creates a safety layer with an autonomous risk ceiling.
func NewSafetyLayerWithPolicy(allowedDomains, allowedCIDRs, blockedDomains []string, maxRPM int, maxAutoRisk tool.RiskLevel) *SafetyLayer {
	if maxAutoRisk == "" {
		maxAutoRisk = tool.RiskActive
	}
	return &SafetyLayer{
		scopeValidator:   NewScopeValidator(allowedDomains, allowedCIDRs, blockedDomains),
		rateLimiter:      NewRateLimiter(maxRPM),
		confirmationGate: NewConfirmationGate(),
		maxAutoRisk:      maxAutoRisk,
	}
}

// ValidateTask checks whether a task can be executed safely.
// Returns nil if the task is approved, or an error describing why it was denied.
func (s *SafetyLayer) ValidateTask(toolName string, args map[string]interface{}, riskLevel tool.RiskLevel) error {
	// 1. Extract target from args
	target := extractTarget(toolName, args)
	if target == "" {
		return fmt.Errorf("no target specified in task arguments")
	}

	// 2. Scope validation
	if err := s.scopeValidator.Validate(target); err != nil {
		return fmt.Errorf("scope violation: %w", err)
	}

	// 3. Rate limiting
	if err := s.rateLimiter.Allow(target); err != nil {
		return fmt.Errorf("rate limit: %w", err)
	}

	// 4. Autonomous risk ceiling
	if !tool.RiskAllowed(s.maxAutoRisk, riskLevel) {
		if s.confirmationGate.RequiresApproval(toolName, riskLevel) {
			return fmt.Errorf("tool %s (risk: %s) requires approval above %s", toolName, riskLevel, s.maxAutoRisk)
		}
		return fmt.Errorf("tool %s risk %s exceeds approved maximum %s", toolName, riskLevel, s.maxAutoRisk)
	}

	return nil
}

// ValidateTarget checks if a target is within authorized scope.
func (s *SafetyLayer) ValidateTarget(target string) error {
	return s.scopeValidator.Validate(target)
}

// IsDestructive checks if a risk level requires confirmation.
func (s *SafetyLayer) IsDestructive(riskLevel tool.RiskLevel) bool {
	return riskLevel == tool.RiskDestructive
}

// =============================================================================
// Scope Validator
// =============================================================================

// ScopeValidator ensures targets are within authorized bounds.
type ScopeValidator struct {
	allowedDomains []string
	allowedCIDRs   []*net.IPNet
	blockedDomains []string
}

// NewScopeValidator creates a scope validator.
func NewScopeValidator(allowedDomains, allowedCIDRs, blockedDomains []string) *ScopeValidator {
	sv := &ScopeValidator{
		allowedDomains: allowedDomains,
		blockedDomains: blockedDomains,
	}

	for _, cidr := range allowedCIDRs {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err == nil {
			sv.allowedCIDRs = append(sv.allowedCIDRs, ipNet)
		}
	}

	return sv
}

// Validate checks if a target is allowed.
// Fail-closed: if no allow rules are configured, everything is denied.
func (sv *ScopeValidator) Validate(target string) error {
	target = strings.TrimSpace(target)
	normalized := NormalizeTargetHost(target)
	if normalized == "" {
		return fmt.Errorf("target %s is not a valid host, URL, IP, or CIDR", target)
	}

	// Check blocked list first (deny takes precedence)
	for _, blocked := range sv.blockedDomains {
		if matchDomain(normalized, blocked) {
			return fmt.Errorf("target %s is explicitly blocked", target)
		}
	}

	// If no allow rules configured, fail-closed
	if len(sv.allowedDomains) == 0 && len(sv.allowedCIDRs) == 0 {
		// No scope configured — allow everything (explicitly opt-in required for agent mode)
		return fmt.Errorf("no authorized scope configured")
	}

	// Check domain allow list
	for _, domain := range sv.allowedDomains {
		if matchDomain(normalized, domain) {
			return nil
		}
	}

	// Check CIDR allow list
	targetIP := net.ParseIP(normalized)
	if targetIP != nil {
		for _, cidr := range sv.allowedCIDRs {
			if cidr.Contains(targetIP) {
				return nil
			}
		}
	}
	if _, targetNet, err := net.ParseCIDR(normalized); err == nil {
		for _, cidr := range sv.allowedCIDRs {
			if cidr.Contains(targetNet.IP) {
				return nil
			}
		}
	}

	return fmt.Errorf("target %s is not in authorized scope", target)
}

// NormalizeTargetHost extracts a comparable host/IP/CIDR from a URL or target string.
func NormalizeTargetHost(target string) string {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return ""
	}

	if _, _, err := net.ParseCIDR(target); err == nil {
		return target
	}

	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err == nil && parsed.Hostname() != "" {
			return strings.Trim(parsed.Hostname(), "[]")
		}
	}

	if host, _, err := net.SplitHostPort(target); err == nil {
		return strings.Trim(host, "[]")
	}

	if idx := strings.IndexAny(target, "/?#"); idx >= 0 {
		target = target[:idx]
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}

	return strings.Trim(target, "[]")
}

// matchDomain checks if a target matches a domain pattern.
func matchDomain(target, pattern string) bool {
	target = NormalizeTargetHost(target)
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if !strings.HasPrefix(pattern, "*.") {
		pattern = NormalizeTargetHost(pattern)
	}

	// Exact match
	if target == pattern {
		return true
	}

	// Wildcard: *.example.com matches sub.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		if strings.HasSuffix(target, suffix) {
			return true
		}
	}

	return false
}

// =============================================================================
// Rate Limiter
// =============================================================================

// RateLimiter prevents excessive requests to a target.
type RateLimiter struct {
	mu     sync.Mutex
	limits map[string]*targetLimiter
	maxRPM int
}

type targetLimiter struct {
	count       int
	windowStart time.Time
}

// NewRateLimiter creates a rate limiter.
func NewRateLimiter(maxRequestsPerMinute int) *RateLimiter {
	if maxRequestsPerMinute <= 0 {
		maxRequestsPerMinute = 300 // Sensible default
	}
	return &RateLimiter{
		limits: make(map[string]*targetLimiter),
		maxRPM: maxRequestsPerMinute,
	}
}

// Allow checks if a request to the target is within rate limits.
func (rl *RateLimiter) Allow(target string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	key := normalizeTargetForRateLimit(target)
	limiter, ok := rl.limits[key]
	if !ok || time.Since(limiter.windowStart) > time.Minute {
		rl.limits[key] = &targetLimiter{count: 1, windowStart: time.Now()}
		return nil
	}

	limiter.count++
	if limiter.count > rl.maxRPM {
		return fmt.Errorf("rate limit exceeded for %s (%d requests/min)", key, rl.maxRPM)
	}

	return nil
}

func normalizeTargetForRateLimit(target string) string {
	return NormalizeTargetHost(target)
}

// =============================================================================
// Confirmation Gate
// =============================================================================

// ConfirmationGate requires human approval for dangerous operations.
type ConfirmationGate struct {
	alwaysRequireApproval []string // Tool names that always need approval
	destructiveRiskLevels []tool.RiskLevel
}

// NewConfirmationGate creates a confirmation gate with sensible defaults.
func NewConfirmationGate() *ConfirmationGate {
	return &ConfirmationGate{
		alwaysRequireApproval: []string{
			"akemi_probe_vulns",  // Active exploitation
			"akemi_auth_capture", // Credential handling
		},
		destructiveRiskLevels: []tool.RiskLevel{
			tool.RiskDestructive,
		},
	}
}

// RequiresApproval checks if a tool needs human sign-off.
func (cg *ConfirmationGate) RequiresApproval(toolName string, riskLevel tool.RiskLevel) bool {
	// Check always-require list
	for _, name := range cg.alwaysRequireApproval {
		if name == toolName {
			return true
		}
	}

	// Check risk level
	for _, rl := range cg.destructiveRiskLevels {
		if rl == riskLevel {
			return true
		}
	}

	return false
}

// =============================================================================
// Helpers
// =============================================================================

// extractTarget pulls the target identifier from task arguments.
func extractTarget(toolName string, args map[string]interface{}) string {
	// Try common target arg names in priority order
	candidates := []string{"url", "urls", "target", "domain", "host", "cidr"}
	for _, key := range candidates {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
			if list, ok := v.([]string); ok && len(list) > 0 {
				return list[0]
			}
			if list, ok := v.([]interface{}); ok {
				for _, item := range list {
					if s, ok := item.(string); ok && s != "" {
						return s
					}
				}
			}
		}
	}
	return ""
}
