package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	core "Akemi/internal/core"
	recon "Akemi/internal/recon"
)

// ScannerService implements core.Scanner by wrapping the existing recon package.
type ScannerService struct {
	logger *slog.Logger
}

// NewScannerService creates a ScannerService.
func NewScannerService(logger *slog.Logger) *ScannerService {
	if logger == nil {
		logger = core.Logger()
	}
	return &ScannerService{logger: logger}
}

// Scan performs a port scan via the configured engine (Rust or Go fallback).
func (s *ScannerService) Scan(ctx context.Context, req core.ScanRequest) (*core.ScanResult, error) {
	defer core.LogDuration(ctx, "Scanner.Scan", time.Now())
	s.logger.InfoContext(ctx, "starting port scan",
		slog.String("host", req.Host),
		slog.Int("port_count", len(req.Ports)),
	)

	scanner := &recon.PortScanner{
		Host:           req.Host,
		Threads:        req.Threads,
		TimeoutS:       req.TimeoutMs / 1000,
		Ports:          req.Ports,
		ProbeDir:       req.ProbeDir,
		BannerGrab:     req.BannerGrab,
		Rate:           req.Rate,
		SynMode:        req.SynMode,
		Retries:        req.Retries,
		Randomize:      req.Randomize,
		Resume:         req.ResumeFile,
		Verbose:        req.Verbose,
		SuppressOutput: req.SuppressOutput,
	}

	// Check context cancellation before starting
	select {
	case <-ctx.Done():
		return nil, core.NewError("Scanner.Scan", req.Host, ctx.Err())
	default:
	}

	// Run the scan (this blocks — in Phase 5 we'd make this async with a task queue)
	summary, err := scanner.Run()
	if err != nil {
		s.logger.ErrorContext(ctx, "port scan failed",
			slog.String("host", req.Host),
			slog.String("error", err.Error()),
		)
		return nil, core.NewError("Scanner.Scan", req.Host, err)
	}

	// Convert legacy type to canonical core type
	result := &core.ScanResult{
		Hostname:     summary.Hostname,
		IPs:          summary.IPs,
		OSHint:       summary.OSHint,
		ScanTimeMs:   summary.ScanTimeMs,
		TotalScanned: firstPositive(summary.TotalScanned, len(req.Ports)),
		ScanMode:     firstNonEmpty(summary.ScanMode, scanModeString(req.SynMode)),
	}
	if summary.TTL != nil {
		result.TTL = int(*summary.TTL)
	}

	for _, r := range summary.Results {
		result.OpenPorts = append(result.OpenPorts, core.PortResult{
			Port:        r.Port,
			State:       r.State,
			Banner:      r.Banner,
			Technology:  r.Technology,
			TechMatches: convertTechMatches(r.TechMatches),
			Service:     r.Service,
			Version:     r.Version,
			TLS:         r.TLS,
			TLSCN:       r.TLSCN,
		})
	}

	s.logger.InfoContext(ctx, "port scan completed",
		slog.Int("open_ports", len(result.OpenPorts)),
	)
	return result, nil
}

// DiscoverHosts performs host discovery on a CIDR range.
func (s *ScannerService) DiscoverHosts(ctx context.Context, req core.HostDiscoveryRequest) (*core.HostDiscoveryResult, error) {
	defer core.LogDuration(ctx, "Scanner.DiscoverHosts", time.Now())
	s.logger.InfoContext(ctx, "starting host discovery",
		slog.String("cidr", req.CIDR),
	)

	// Use the port scanner with NoPorts mode for host discovery
	scanner := &recon.PortScanner{
		Host:     req.CIDR,
		Threads:  req.Threads,
		TimeoutS: req.TimeoutMs / 1000,
		Rate:     req.Rate,
		Verbose:  req.Verbose,
		NoPorts:  true,
	}

	select {
	case <-ctx.Done():
		return nil, core.NewError("Scanner.DiscoverHosts", req.CIDR, ctx.Err())
	default:
	}

	summary, err := scanner.Run()
	if err != nil {
		return nil, core.NewError("Scanner.DiscoverHosts", req.CIDR, err)
	}

	result := &core.HostDiscoveryResult{
		ScanTimeMs: summary.ScanTimeMs,
	}
	if len(summary.AliveHosts) > 0 {
		for _, host := range summary.AliveHosts {
			result.AliveHosts = append(result.AliveHosts, core.AliveHost{
				IP:        host.IP,
				Alive:     host.Alive,
				LatencyMs: host.LatencyMs,
				RDNS:      host.RDNS,
				Method:    host.Method,
			})
		}
		result.TotalHosts = len(result.AliveHosts)
	} else {
		for _, ip := range summary.IPs {
			result.AliveHosts = append(result.AliveHosts, core.AliveHost{
				IP:     ip,
				Alive:  true,
				Method: "unknown",
			})
		}
		result.TotalHosts = len(result.AliveHosts)
	}

	s.logger.InfoContext(ctx, "host discovery completed",
		slog.Int("alive_hosts", result.TotalHosts),
	)
	return result, nil
}

// Ensure ScannerService implements core.Scanner at compile time.
var _ core.Scanner = (*ScannerService)(nil)

func convertTechMatches(matches []recon.TechMatch) []core.TechMatch {
	if len(matches) == 0 {
		return nil
	}
	out := make([]core.TechMatch, len(matches))
	for i, match := range matches {
		version := ""
		if match.Version != nil {
			version = *match.Version
		}
		out[i] = core.TechMatch{
			Name:       match.Name,
			Category:   match.Category,
			Confidence: match.Confidence,
			Version:    version,
			Evidence:   match.Evidence,
			Source:     match.Source,
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// helper to determine scan mode string
func scanModeString(syn bool) string {
	if syn {
		return "syn"
	}
	return "connect"
}

// unused but kept for documentation
var _ = fmt.Sprintf
