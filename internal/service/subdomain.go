package service

import (
	"context"
	"log/slog"
	"time"

	core "Akemi/internal/core"
	recon "Akemi/internal/recon"
)

// SubdomainService implements core.SubEnumerator using the recon package.
type SubdomainService struct {
	logger *slog.Logger
}

// NewSubdomainService creates a SubdomainService.
func NewSubdomainService(logger *slog.Logger) *SubdomainService {
	if logger == nil {
		logger = core.Logger()
	}
	return &SubdomainService{logger: logger}
}

// Enumerate discovers subdomains using passive and active methods.
func (s *SubdomainService) Enumerate(ctx context.Context, domain string, cfg core.SubdomainConfig) ([]core.SubdomainResult, error) {
	defer core.LogDuration(ctx, "SubEnumerator.Enumerate", time.Now())
	s.logger.InfoContext(ctx, "enumerating subdomains",
		slog.String("domain", domain),
	)

	select {
	case <-ctx.Done():
		return nil, core.NewError("SubEnumerator.Enumerate", domain, ctx.Err())
	default:
	}

	subCfg := recon.SubdomainConfig{
		WordlistFile: cfg.WordlistFile,
		Threads:      cfg.Threads,
		Timeout:      cfg.Timeout,
		UseCrtSh:     cfg.UseCrtSh,
		CheckAlive:   cfg.CheckAlive,
		Permutate:    cfg.Permutate,
		Quiet:        true,
	}

	results, err := recon.EnumerateSubdomains(domain, subCfg)
	if err != nil {
		s.logger.ErrorContext(ctx, "subdomain enumeration failed",
			slog.String("domain", domain),
			slog.String("error", err.Error()),
		)
		return nil, core.NewError("SubEnumerator.Enumerate", domain, err)
	}

	subdomains := make([]core.SubdomainResult, len(results))
	for i, r := range results {
		subdomains[i] = core.SubdomainResult{
			Name:       r.Subdomain,
			Source:     r.Source,
			IPs:        r.IPs,
			IsAlive:    r.Alive,
			StatusCode: r.StatusCode,
		}
	}

	s.logger.InfoContext(ctx, "subdomain enumeration completed",
		slog.Int("subdomains_found", len(subdomains)),
	)
	return subdomains, nil
}

// Ensure SubdomainService implements core.SubEnumerator at compile time.
var _ core.SubEnumerator = (*SubdomainService)(nil)
