package reporting

import "strings"

// redactedReport returns a deep-enough copy for safe external export. The
// in-memory report remains useful to the local operator, while JSON/HTML
// artifacts never become a credential dump by default.
func redactedReport(in *ScanReport) *ScanReport {
	if in == nil {
		return nil
	}
	out := *in
	out.SecretFindings = cloneSecretFindings(in.SecretFindings)
	for i := range out.FuzzResults {
		out.FuzzResults[i].Payload = maskSensitive(out.FuzzResults[i].Payload)
		out.FuzzResults[i].Error = maskSensitive(out.FuzzResults[i].Error)
	}
	for i := range out.VulnFindings {
		finding := &out.VulnFindings[i]
		finding.Payload = maskSensitive(finding.Payload)
		finding.Evidence = maskSensitive(finding.Evidence)
		finding.Inject = maskSensitive(finding.Inject)
		finding.Request.Body = maskSensitive(finding.Request.Body)
		finding.Request.Inject = maskSensitive(finding.Request.Inject)
		if finding.Request.Headers != nil {
			headers := make(map[string]string, len(finding.Request.Headers))
			for key, value := range finding.Request.Headers {
				headers[key] = maskSensitive(value)
			}
			finding.Request.Headers = headers
		}
	}
	if in.JSAnalysis != nil {
		analysis := *in.JSAnalysis
		analysis.ScriptURLs = append([]string(nil), in.JSAnalysis.ScriptURLs...)
		analysis.Endpoints = append([]string(nil), in.JSAnalysis.Endpoints...)
		analysis.HiddenParams = append([]string(nil), in.JSAnalysis.HiddenParams...)
		analysis.ConfigResources = append([]string(nil), in.JSAnalysis.ConfigResources...)
		analysis.Secrets = make(map[string][]string, len(in.JSAnalysis.Secrets))
		for category, values := range in.JSAnalysis.Secrets {
			masked := make([]string, len(values))
			for i, value := range values {
				masked[i] = maskSensitive(value)
			}
			analysis.Secrets[category] = masked
		}
		analysis.SecretFindings = cloneSecretFindings(in.JSAnalysis.SecretFindings)
		analysis.APIEndpoints = append([]APIEndpointFinding(nil), in.JSAnalysis.APIEndpoints...)
		analysis.APISpecs = append([]APISpecFinding(nil), in.JSAnalysis.APISpecs...)
		out.JSAnalysis = &analysis
	}
	if in.AuthWorkflow != nil {
		auth := *in.AuthWorkflow
		auth.Cookies = maskList(in.AuthWorkflow.Cookies)
		auth.CSRFTokens = maskList(in.AuthWorkflow.CSRFTokens)
		auth.RedirectChain = append([]string(nil), in.AuthWorkflow.RedirectChain...)
		out.AuthWorkflow = &auth
	}
	return &out
}

func cloneSecretFindings(in []SecretFinding) []SecretFinding {
	if in == nil {
		return nil
	}
	out := make([]SecretFinding, len(in))
	for i, finding := range in {
		out[i] = finding
		out[i].Value = maskSensitive(finding.Value)
		out[i].Evidence = maskList(finding.Evidence)
	}
	return out
}

func maskList(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = maskSensitive(value)
	}
	return out
}

func maskSensitive(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	if len(value) <= 4 {
		return "[REDACTED]"
	}
	return value[:2] + "…" + value[len(value)-2:]
}
