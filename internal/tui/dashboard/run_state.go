package dashboard

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	core "Akemi/internal/core"
	"Akemi/internal/engagement"
	"Akemi/internal/execution"
)

func effectiveScopeSummary(scope execution.ScopePolicy) string {
	parts := make([]string, 0, 3)
	if len(scope.RootDomains) > 0 {
		parts = append(parts, "domains="+strings.Join(scope.RootDomains, ","))
	}
	if len(scope.ExactHosts) > 0 {
		parts = append(parts, "hosts="+strings.Join(scope.ExactHosts, ","))
	}
	if len(scope.AuthorizedCIDRs) > 0 {
		parts = append(parts, "cidrs="+strings.Join(scope.AuthorizedCIDRs, ","))
	}
	if len(parts) == 0 {
		return "none (fail closed)"
	}
	return strings.Join(parts, " ")
}
func dashboardRunContext(cfg ScanConfig, policy execution.ExecutionPolicy) (*execution.RunContext, error) {
	rawTarget := strings.TrimSpace(cfg.Target)
	if rawTarget == "" {
		return nil, fmt.Errorf("target is required")
	}
	target := engagement.TargetProfile{BaseURL: core.EnsureProtocol(rawTarget)}
	scope := execution.ScopePolicy{}
	if _, network, err := net.ParseCIDR(rawTarget); err == nil && network != nil {
		target.BaseURL = rawTarget
		target.CIDRs = []string{rawTarget}
		scope.AuthorizedCIDRs = []string{rawTarget}
	} else {
		candidate := rawTarget
		if !strings.Contains(candidate, "://") {
			candidate = "//" + candidate
		}
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Hostname() == "" {
			return nil, fmt.Errorf("invalid target %q", rawTarget)
		}
		host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		if net.ParseIP(host) != nil {
			target.Hosts = []string{host}
			scope.ExactHosts = []string{host}
		} else {
			target.Domain = host
			scope.RootDomains = []string{host}
			scope.AllowSubdomains = true
		}
	}
	if policy.MaxRisk == "" {
		policy = execution.DefaultPolicy()
	}
	return execution.NewRunContext(fmt.Sprintf("tui-%d", time.Now().UnixNano()), target, scope, policy)
}
