package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	akemiarchive "Akemi/internal/archive"
	"Akemi/internal/config"
	core "Akemi/internal/core"
	"Akemi/internal/engagement"
	"Akemi/internal/mcp"
	"Akemi/internal/surface"
)

func handleReadProjectFindings(ctx context.Context, args map[string]interface{}, svc *Services) ([]mcp.ContentBlock, error) {
	_ = ctx
	specifiedPath := strings.TrimSpace(getString(args, "path"))
	targetFilter := strings.ToLower(strings.TrimSpace(getString(args, "target")))
	maxBytes := int64(getInt(args, "max_bytes", 5242880))

	searchDirs := []string{}
	if specifiedPath != "" {
		searchDirs = append(searchDirs, specifiedPath)
	} else {
		if svc != nil && strings.TrimSpace(svc.WorkspaceDir) != "" {
			searchDirs = append(searchDirs, svc.WorkspaceDir)
		}
		searchDirs = append(searchDirs,
			filepath.Join(config.WorkemiDirectory(), "Projects"),
			config.WorkemiDirectory(),
			reportRoot(svc),
			".",
		)
	}

	type archiveMatch struct {
		Path string
		File *akemiarchive.File
	}

	var foundArchives []archiveMatch
	var foundReportFiles []string
	seenPaths := make(map[string]bool)

	for _, dir := range searchDirs {
		if dir == "" || seenPaths[dir] {
			continue
		}
		seenPaths[dir] = true
		info, err := os.Stat(dir)
		if err != nil {
			continue
		}

		if !info.IsDir() {
			if strings.HasSuffix(strings.ToLower(dir), ".akemi") {
				if arch, err := akemiarchive.ReadFile(dir); err == nil {
					foundArchives = append(foundArchives, archiveMatch{Path: dir, File: arch})
				}
			} else {
				foundReportFiles = append(foundReportFiles, dir)
			}
			continue
		}

		_ = filepath.Walk(dir, func(p string, f os.FileInfo, walkErr error) error {
			if walkErr != nil || f == nil || f.IsDir() {
				return nil
			}
			lower := strings.ToLower(f.Name())
			if strings.HasSuffix(lower, ".akemi") {
				if !seenPaths[p] {
					seenPaths[p] = true
					if arch, err := akemiarchive.ReadFile(p); err == nil {
						foundArchives = append(foundArchives, archiveMatch{Path: p, File: arch})
					}
				}
			} else if strings.HasSuffix(lower, ".md") || strings.HasSuffix(lower, ".json") {
				if !seenPaths[p] && (strings.Contains(lower, "report") || strings.Contains(lower, "finding") || strings.Contains(lower, "result")) {
					seenPaths[p] = true
					foundReportFiles = append(foundReportFiles, p)
				}
			}
			return nil
		})
	}

	if targetFilter != "" {
		var filtered []archiveMatch
		for _, am := range foundArchives {
			if strings.Contains(strings.ToLower(am.File.Config.Target), targetFilter) ||
				strings.Contains(strings.ToLower(am.Path), targetFilter) {
				filtered = append(filtered, am)
			}
		}
		foundArchives = filtered
	}

	var sb strings.Builder
	sb.WriteString("# Project Findings & Workspace Inspection Report\n\n")

	allFindings := []core.VulnFinding{}
	allPorts := []core.PortResult{}
	allSubdomains := []string{}
	allURLs := []string{}
	allSecrets := []core.SecretFinding{}
	allEndpoints := []core.APIEndpointFinding{}
	allParams := map[string]core.ParamDetail{}
	var lastTarget string

	for _, am := range foundArchives {
		arch := am.File
		target := arch.Config.Target
		if target != "" {
			lastTarget = target
		}
		sb.WriteString(fmt.Sprintf("## Archive: `%s` (Target: `%s`)\n", filepath.Base(am.Path), target))
		if arch.Summary != "" {
			sb.WriteString(fmt.Sprintf("- **Summary**: %s\n", arch.Summary))
		}
		sb.WriteString(fmt.Sprintf("- **Exported**: %s\n", arch.ExportedAt.Format(time.RFC3339)))
		if len(arch.Counts) > 0 {
			sb.WriteString(fmt.Sprintf("- **Counts**: findings=%d, subdomains=%d, ports=%d, urls=%d, secrets=%d, api_endpoints=%d\n",
				arch.Counts["findings"], arch.Counts["subdomains"], arch.Counts["ports"], arch.Counts["urls"], arch.Counts["secrets"], arch.Counts["api_endpoints"]))
		}
		sb.WriteString("\n")

		allFindings = append(allFindings, arch.Results.Findings...)
		allPorts = append(allPorts, arch.Results.Ports...)
		allSubdomains = append(allSubdomains, arch.Results.Subdomains...)
		allURLs = append(allURLs, arch.Results.URLs...)
		allSecrets = append(allSecrets, arch.Results.Secrets...)
		allEndpoints = append(allEndpoints, arch.Results.APIEndpoints...)
		for k, v := range arch.Results.Params {
			allParams[k] = v
		}

		if svc != nil && svc.State != nil && target != "" {
			surfRes := &surface.FullSurfaceResult{
				Target:        target,
				StartTime:     arch.ExportedAt,
				EndTime:       arch.ExportedAt,
				CrawlFindings: arch.Results.CrawlFindings,
				VulnFindings:  arch.Results.Findings,
				Secrets:       arch.Results.Secrets,
				APIEndpoints:  arch.Results.APIEndpoints,
				APISpecs:      arch.Results.APISpecs,
				APIParameters: arch.Results.APIParameters,
				Subdomains:    makeSubdomainResults(arch.Results.Subdomains),
				Counts:        arch.Counts,
			}
			if len(arch.Results.Ports) > 0 {
				surfRes.PortScan = &core.ScanResult{Hostname: target, OpenPorts: arch.Results.Ports}
			}

			structured := map[string]interface{}{
				"target":        target,
				"intent":        arch.Config.Intent,
				"counts":        arch.Counts,
				"vuln_findings": arch.Results.Findings,
				"subdomains":    arch.Results.Subdomains,
				"api_endpoints": arch.Results.APIEndpoints,
				"secrets":       arch.Results.Secrets,
				"params":        arch.Results.Params,
			}
			svc.State.RecordToolResult("akemi_full_surface_map", fmt.Sprintf("Loaded from project archive %s", am.Path), structured)

			if svc.Context != nil {
				domain := surface.DomainFromTarget(target)
				var hosts []string
				if domain != "" {
					hosts = []string{domain}
				}
				_ = svc.Context.SetTarget(context.Background(), engagement.TargetProfile{
					Name:    target,
					BaseURL: target,
					Domain:  domain,
					Hosts:   hosts,
				})
			}
		}
	}

	if len(allFindings) > 0 {
		sb.WriteString(fmt.Sprintf("### Vulnerability Findings (%d total)\n\n", len(allFindings)))
		for i, f := range allFindings {
			title := f.Name
			if title == "" {
				title = f.ID
			}
			sb.WriteString(fmt.Sprintf("#### %d. [%s] %s\n", i+1, strings.ToUpper(f.Severity), title))
			if f.ID != "" {
				sb.WriteString(fmt.Sprintf("- **ID**: `%s`\n", f.ID))
			}
			if f.Target != "" {
				sb.WriteString(fmt.Sprintf("- **Target**: `%s`\n", f.Target))
			}
			if f.Description != "" {
				sb.WriteString(fmt.Sprintf("- **Description**: %s\n", f.Description))
			}
			if f.Evidence != "" {
				sb.WriteString(fmt.Sprintf("- **Evidence**: `%s`\n", f.Evidence))
			}
			if f.Remediation != "" {
				sb.WriteString(fmt.Sprintf("- **Remediation**: %s\n", f.Remediation))
			}
			sb.WriteString("\n")
		}
	} else if len(foundArchives) == 0 {
		sb.WriteString("No `.akemi` project archives were found in the inspected search directories.\n\n")
	} else {
		sb.WriteString("Archives were found, but contain 0 vulnerability findings.\n\n")
	}

	if len(foundReportFiles) > 0 {
		sb.WriteString(fmt.Sprintf("### Report Files Discovered (%d)\n", len(foundReportFiles)))
		for _, rf := range foundReportFiles {
			sb.WriteString(fmt.Sprintf("- `%s`\n", rf))
		}
		sb.WriteString("\n")

		if len(foundReportFiles) == 1 || specifiedPath != "" {
			rPath := foundReportFiles[0]
			if data, err := os.ReadFile(rPath); err == nil {
				if int64(len(data)) > maxBytes {
					data = data[:maxBytes]
				}
				sb.WriteString(fmt.Sprintf("#### Content of `%s`:\n```markdown\n%s\n```\n", filepath.Base(rPath), string(data)))
			}
		}
	}

	if lastTarget != "" {
		sb.WriteString(fmt.Sprintf("\nActive target scope automatically loaded into context: `%s`\n", lastTarget))
	}

	return []mcp.ContentBlock{mcp.TextContent(sb.String())}, nil
}

func makeSubdomainResults(names []string) []core.SubdomainResult {
	out := make([]core.SubdomainResult, len(names))
	for i, name := range names {
		out[i] = core.SubdomainResult{Name: name}
	}
	return out
}
