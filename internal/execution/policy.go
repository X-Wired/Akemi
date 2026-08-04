// Package execution contains the shared safety and lifecycle boundary used by
// MCP tools, agents, the assistant, and the TUI.
package execution

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	agenttool "Akemi/internal/agent/tool"
	"Akemi/internal/engagement"
)

// RunStatus is the lifecycle state of a tool or scan run.
type RunStatus string

const (
	RunQueued           RunStatus = "queued"
	RunRunning          RunStatus = "running"
	RunCompleted        RunStatus = "completed"
	RunPartial          RunStatus = "partial"
	RunCancelled        RunStatus = "cancelled"
	RunDenied           RunStatus = "denied"
	RunFailed           RunStatus = "failed"
	RunTimeout          RunStatus = "timeout"
	RunApprovalRequired RunStatus = "approval_required"
)

// ScopePolicy describes which network targets an engagement authorizes.
// RootDomains authorize their subdomains when AllowSubdomains is true. Exact
// hosts and CIDRs remain explicit allow-list entries.
type ScopePolicy struct {
	RootDomains     []string `json:"root_domains,omitempty"`
	ExactHosts      []string `json:"exact_hosts,omitempty"`
	AuthorizedCIDRs []string `json:"authorized_cidrs,omitempty"`
	AllowSubdomains bool     `json:"allow_subdomains,omitempty"`
}

// AuthSessionRef deliberately contains only an identifier. Raw cookies,
// tokens, and credentials must never be copied into a RunContext.
type AuthSessionRef struct {
	ID       string `json:"id,omitempty"`
	TargetID string `json:"target_id,omitempty"`
}

// ExecutionPolicy contains the limits and authorization mode for one run.
type ExecutionPolicy struct {
	MaxRisk               agenttool.RiskLevel     `json:"max_risk"`
	ApprovalMode          engagement.ApprovalMode `json:"approval_mode"`
	MaxConcurrentTasks    int                     `json:"max_concurrent_tasks"`
	AllowDestructive      bool                    `json:"allow_destructive"`
	MaxConcurrentRequests int                     `json:"max_concurrent_requests"`
	MaxRequests           int                     `json:"max_requests"`
	MaxResponseBytes      int64                   `json:"max_response_bytes"`
	MaxToolDuration       time.Duration           `json:"max_tool_duration"`
}

// DefaultPolicy returns the stable 2.1 defaults. Active and intrusive work is
// autonomous inside scope; destructive work remains approval-gated by risk
// checks in the executor.
func DefaultPolicy() ExecutionPolicy {
	return ExecutionPolicy{
		MaxRisk:               agenttool.RiskIntrusive,
		ApprovalMode:          engagement.ApprovalAllow,
		MaxConcurrentRequests: 32,
		AllowDestructive:      false,
		MaxConcurrentTasks:    5,
		MaxRequests:           10000,
		MaxResponseBytes:      4 << 20,
		MaxToolDuration:       30 * time.Minute,
	}
}

// RunContext is immutable execution context passed to a run. Callers should
// treat it as read-only after creation.
type RunContext struct {
	ID          string                   `json:"id"`
	Target      engagement.TargetProfile `json:"target"`
	Scope       ScopePolicy              `json:"scope"`
	Policy      ExecutionPolicy          `json:"policy"`
	AuthSession AuthSessionRef           `json:"auth_session,omitempty"`
	StartedAt   time.Time                `json:"started_at"`
	limiter     *runLimiter              `json:"-"`
}

// NewRunContext builds and normalizes a run context from the existing target
// profile. Legacy target fields are mapped into the new scope policy.
func NewRunContext(id string, target engagement.TargetProfile, scope ScopePolicy, policy ExecutionPolicy) (*RunContext, error) {
	target = normalizeTarget(target)
	scope = NormalizeScope(scope, target)
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("run id is required")
	}
	if policy.MaxRisk == "" {
		policy.MaxRisk = agenttool.RiskIntrusive
	}
	if policy.ApprovalMode == "" {
		policy.ApprovalMode = engagement.ApprovalAllow
	}
	if policy.MaxConcurrentTasks <= 0 {
		policy.MaxConcurrentTasks = DefaultPolicy().MaxConcurrentTasks
	}
	if policy.MaxConcurrentRequests <= 0 {
		policy.MaxConcurrentRequests = DefaultPolicy().MaxConcurrentRequests
	}
	if policy.MaxRequests <= 0 {
		policy.MaxRequests = DefaultPolicy().MaxRequests
	}
	if policy.MaxResponseBytes <= 0 {
		policy.MaxResponseBytes = DefaultPolicy().MaxResponseBytes
	}
	if policy.MaxToolDuration <= 0 {
		policy.MaxToolDuration = DefaultPolicy().MaxToolDuration
	}
	return &RunContext{ID: id, Target: target, Scope: scope, Policy: policy, StartedAt: time.Now(), limiter: newRunLimiter(policy)}, nil
}

type runLimiter struct {
	budget *RequestBudget
	sem    chan struct{}
}

func newRunLimiter(policy ExecutionPolicy) *runLimiter {
	limit := policy.MaxConcurrentRequests
	if limit <= 0 {
		limit = DefaultPolicy().MaxConcurrentRequests
	}
	return &runLimiter{budget: NewRequestBudget(policy.MaxRequests), sem: make(chan struct{}, limit)}
}

func (r *RunContext) reserveRequest(ctx context.Context) (func(), error) {
	if r == nil {
		return func() {}, nil
	}
	if r.limiter == nil {
		r.limiter = newRunLimiter(r.Policy)
	}
	if err := r.limiter.budget.Reserve(ctx); err != nil {
		return nil, err
	}
	select {
	case r.limiter.sem <- struct{}{}:
		return func() { <-r.limiter.sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ReserveRequest reserves one actual network attempt and one concurrent-request
// slot. The returned function must be called when the response body is closed.
func (r *RunContext) ReserveRequest(ctx context.Context) (func(), error) {
	return r.reserveRequest(ctx)
}

// NormalizeScope maps the legacy TargetProfile fields into a predictable
// scope. Existing Domain entries become root domains and Hosts remain exact.
func NormalizeScope(scope ScopePolicy, target engagement.TargetProfile) ScopePolicy {
	scope.RootDomains = cleanHosts(append(scope.RootDomains, target.Domain))
	scope.ExactHosts = cleanHosts(append(scope.ExactHosts, target.Hosts...))
	scope.AuthorizedCIDRs = cleanStrings(append(scope.AuthorizedCIDRs, target.CIDRs...))
	if len(scope.RootDomains) > 0 {
		scope.AllowSubdomains = true
	}
	return scope
}

// ValidateTarget checks a target against the engagement scope. It accepts
// URLs, hostnames, IPs, and CIDR ranges, while preventing user-controlled
// targets from expanding authorization.
func ValidateTarget(scope ScopePolicy, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("target is required")
	}
	if len(scope.RootDomains) == 0 && len(scope.ExactHosts) == 0 && len(scope.AuthorizedCIDRs) == 0 {
		return fmt.Errorf("target scope is not configured")
	}
	host, cidr, err := targetHostAndCIDR(raw)
	if err != nil {
		return err
	}
	if cidr != nil {
		for _, allowed := range scope.AuthorizedCIDRs {
			_, network, parseErr := net.ParseCIDR(allowed)
			if parseErr == nil && cidrWithin(cidr, network) {
				return nil
			}
		}
		return fmt.Errorf("target %q is outside the authorized CIDR scope", raw)
	}
	host = normalizeHost(host)
	if host == "" {
		return fmt.Errorf("target %q has no host", raw)
	}
	for _, exact := range scope.ExactHosts {
		if host == normalizeHost(exact) {
			return nil
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, allowed := range scope.AuthorizedCIDRs {
			_, network, parseErr := net.ParseCIDR(allowed)
			if parseErr == nil && network.Contains(ip) {
				return nil
			}
		}
		return fmt.Errorf("target %q is outside the authorized IP scope", raw)
	}
	for _, root := range scope.RootDomains {
		root = normalizeHost(root)
		if host == root || (scope.AllowSubdomains && strings.HasSuffix(host, "."+root)) {
			return nil
		}
	}
	return fmt.Errorf("target %q is outside the authorized domain scope", raw)
}

// ValidateTargets validates every target in a list and returns the first
// violation with its index.
func ValidateTargets(scope ScopePolicy, targets []string) error {
	for i, target := range targets {
		if err := ValidateTarget(scope, target); err != nil {
			return fmt.Errorf("target[%d]: %w", i, err)
		}
	}
	return nil
}

// ValidateRisk enforces the configured risk ceiling.
func ValidateRisk(policy ExecutionPolicy, actual agenttool.RiskLevel) error {
	if actual == "" {
		actual = agenttool.RiskActive
	}
	if policy.MaxRisk == "" {
		policy.MaxRisk = agenttool.RiskIntrusive
	}
	if !agenttool.RiskAllowed(policy.MaxRisk, actual) {
		return fmt.Errorf("risk %q exceeds approved ceiling %q", actual, policy.MaxRisk)
	}
	if actual == agenttool.RiskDestructive && !policy.AllowDestructive {
		return fmt.Errorf("destructive operation requires approval")
	}
	return nil
}

// RequestBudget accounts for actual network attempts. Retries must call
// Reserve before issuing another request.
type RequestBudget struct {
	mu        sync.Mutex
	limit     int
	reserved  int
	remaining chan struct{}
}

func NewRequestBudget(limit int) *RequestBudget {
	if limit <= 0 {
		limit = DefaultPolicy().MaxRequests
	}
	return &RequestBudget{limit: limit}
}

// Reserve reserves one request slot or returns an error when the run budget is
// exhausted. The context is checked before the reservation.
func (b *RequestBudget) Reserve(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reserved >= b.limit {
		return fmt.Errorf("request budget exhausted (%d)", b.limit)
	}
	b.reserved++
	return nil
}

func (b *RequestBudget) Used() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reserved
}

func targetHostAndCIDR(raw string) (string, *net.IPNet, error) {
	if _, network, err := net.ParseCIDR(raw); err == nil {
		return "", network, nil
	}
	if ip := net.ParseIP(raw); ip != nil {
		return raw, nil, nil
	}
	value := raw
	if !strings.Contains(value, "://") {
		value = "//" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", nil, fmt.Errorf("invalid target %q: %w", raw, err)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", nil, fmt.Errorf("invalid target %q", raw)
	}
	return host, nil, nil
}

func cidrWithin(candidate, allowed *net.IPNet) bool {
	if candidate == nil || allowed == nil {
		return false
	}
	return allowed.Contains(candidate.IP) && allowed.Contains(lastIP(candidate))
}

func lastIP(network *net.IPNet) net.IP {
	last := append(net.IP(nil), network.IP...)
	for i := range last {
		last[i] |= ^network.Mask[i]
	}
	return last
}

func normalizeTarget(target engagement.TargetProfile) engagement.TargetProfile {
	target.BaseURL = strings.TrimSpace(target.BaseURL)
	target.Domain = normalizeHost(target.Domain)
	target.Hosts = cleanHosts(target.Hosts)
	target.CIDRs = cleanStrings(target.CIDRs)
	return target
}

func normalizeHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimSuffix(value, ".")
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil {
			value = strings.ToLower(parsed.Hostname())
		}
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return strings.Trim(value, "[]")
}

func cleanHosts(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = normalizeHost(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func cleanStrings(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
