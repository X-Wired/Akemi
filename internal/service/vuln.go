package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	core "Akemi/internal/core"
	vuln "Akemi/internal/vuln"
)

// VulnService implements core.Prober using the vuln package.
type VulnService struct {
	logger    *slog.Logger
	templates []core.ProbeTemplate
}

// NewVulnService creates a VulnService and loads probe templates.
func NewVulnService(logger *slog.Logger, templateDir string) (*VulnService, error) {
	if logger == nil {
		logger = core.Logger()
	}

	svc := &VulnService{logger: logger}

	if templateDir != "" {
		if err := svc.LoadTemplates(templateDir); err != nil {
			return svc, err
		}
	}

	return svc, nil
}

// LoadTemplates loads YAML probe templates from a directory.
func (s *VulnService) LoadTemplates(dir string) error {
	resolvedDir := core.ResolveProbeTemplateDir(dir)
	loaded, err := vuln.LoadTemplates(resolvedDir)
	if err != nil {
		s.logger.Warn("failed to load probe templates",
			slog.String("dir", resolvedDir),
			slog.String("error", err.Error()),
		)
		return core.NewWarnError("Prober.LoadTemplates", resolvedDir, err)
	}

	s.templates = make([]core.ProbeTemplate, len(loaded))
	for i, t := range loaded {
		s.templates[i] = core.ProbeTemplate{
			ID:       t.ID,
			Disabled: t.Disabled,
			Info: core.TemplateInfo{
				Name:        t.Info.Name,
				Severity:    t.Info.Severity,
				Description: t.Info.Description,
				Tags:        t.Info.Tags,
				Author:      t.Info.Author,
			},
			Protocol:  t.Protocol,
			Ports:     t.Ports,
			Inject:    t.Inject,
			Detection: t.Detection,
			Payloads:  t.Payloads,
			Matchers: core.TemplateMatchers{
				BodyPatterns:   t.Matchers.BodyPatterns,
				BannerPatterns: t.Matchers.BannerPatterns,
				StatusCodes:    t.Matchers.StatusCodes,
				Headers:        t.Matchers.Headers,
			},
		}
	}

	s.logger.Info("probe templates loaded",
		slog.Int("count", len(s.templates)),
		slog.String("dir", resolvedDir),
	)
	return nil
}

// ListTemplates returns all loaded probe templates.
func (s *VulnService) ListTemplates() []core.ProbeTemplate {
	return s.templates
}

// FilterTemplates returns templates matching the given tags or IDs.
func (s *VulnService) FilterTemplates(tags []string, ids []string) []core.ProbeTemplate {
	legacy := make([]vuln.ProbeTemplate, len(s.templates))
	for i, t := range s.templates {
		legacy[i] = vuln.ProbeTemplate{
			ID:       t.ID,
			Disabled: t.Disabled,
			Info: vuln.TemplateInfo{
				Name:        t.Info.Name,
				Severity:    t.Info.Severity,
				Description: t.Info.Description,
				Tags:        t.Info.Tags,
				Author:      t.Info.Author,
			},
			Matchers: vuln.Matchers{
				BodyPatterns:   t.Matchers.BodyPatterns,
				BannerPatterns: t.Matchers.BannerPatterns,
				StatusCodes:    t.Matchers.StatusCodes,
				Headers:        t.Matchers.Headers,
			},
		}
	}

	filtered := vuln.FilterTemplates(legacy, tags, ids)

	result := make([]core.ProbeTemplate, len(filtered))
	for i, f := range filtered {
		result[i] = s.legacyToCore(f)
	}
	return result
}

// Probe executes vulnerability probes against a target URL.
func (s *VulnService) Probe(ctx context.Context, targetURL string, cfg core.ProbeConfig) ([]core.VulnFinding, error) {
	defer core.LogDuration(ctx, "Prober.Probe", time.Now())
	s.logger.InfoContext(ctx, "running vulnerability probes",
		slog.String("url", targetURL),
		slog.Int("threads", cfg.Threads),
	)

	select {
	case <-ctx.Done():
		return nil, core.NewError("Prober.Probe", targetURL, ctx.Err())
	default:
	}

	probeCfg := vuln.ProbeConfig{
		Threads:      cfg.Threads,
		Timeout:      cfg.Timeout,
		UseTemplates: cfg.UseTemplates,
		TemplateDir:  cfg.TemplateDir,
		TemplateTags: cfg.TemplateTags,
		TemplateIDs:  cfg.TemplateIDs,
		Quiet:        true,
	}

	findings, err := vuln.ProbeParams(targetURL, probeCfg)
	if err != nil {
		s.logger.ErrorContext(ctx, "vulnerability probe failed",
			slog.String("url", targetURL),
			slog.String("error", err.Error()),
		)
		return nil, core.NewError("Prober.Probe", targetURL, err)
	}

	result := make([]core.VulnFinding, len(findings))
	for i, f := range findings {
		result[i] = core.VulnFinding{
			ID:          f.TemplateID,
			Name:        string(f.Type),
			Severity:    f.Severity,
			Description: fmt.Sprintf("%s via %s parameter '%s'", f.Type, f.Inject, f.Param),
			Target:      f.URL,
			Evidence:    f.Evidence,
			Remediation: "",
		}
	}

	s.logger.InfoContext(ctx, "vulnerability probe completed",
		slog.Int("findings", len(result)),
	)
	return result, nil
}

// legacyToCore converts a legacy ProbeTemplate to a core ProbeTemplate.
func (s *VulnService) legacyToCore(t vuln.ProbeTemplate) core.ProbeTemplate {
	return core.ProbeTemplate{
		ID:       t.ID,
		Disabled: t.Disabled,
		Info: core.TemplateInfo{
			Name:        t.Info.Name,
			Severity:    t.Info.Severity,
			Description: t.Info.Description,
			Tags:        t.Info.Tags,
			Author:      t.Info.Author,
		},
		Protocol:  t.Protocol,
		Ports:     t.Ports,
		Inject:    t.Inject,
		Detection: t.Detection,
		Payloads:  t.Payloads,
		Matchers: core.TemplateMatchers{
			BodyPatterns:   t.Matchers.BodyPatterns,
			BannerPatterns: t.Matchers.BannerPatterns,
			StatusCodes:    t.Matchers.StatusCodes,
			Headers:        t.Matchers.Headers,
		},
	}
}

// Ensure VulnService implements core.Prober at compile time.
var _ core.Prober = (*VulnService)(nil)
