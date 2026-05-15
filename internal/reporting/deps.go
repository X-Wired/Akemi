package reporting

import (
	core "Akemi/internal/core"
	"Akemi/internal/dothound"
	exploit "Akemi/internal/exploit"
	recon "Akemi/internal/recon"
	vuln "Akemi/internal/vuln"
)

type PortScanSummary = recon.PortScanSummary
type PortScanResult = recon.PortScanResult
type CrawlFinding = recon.CrawlFinding
type ScrapeResult = recon.ScrapeResult
type ParamSource = recon.ParamSource
type RichParamDetail = recon.RichParamDetail
type JSAnalysisResult = recon.JSAnalysisResult
type SecretFinding = recon.SecretFinding
type APIEndpointFinding = recon.APIEndpointFinding
type APISpecFinding = recon.APISpecFinding
type APIParameter = recon.APIParameter
type APIParameterFinding = recon.APIParameterFinding
type SubdomainResult = recon.SubdomainResult
type VulnFinding = vuln.VulnFinding
type FuzzResult = core.FuzzResult
type ExploitDBEntry = exploit.ExploitDBEntry
type AuthSession = dothound.AuthSession
type WorkflowGraph = dothound.WorkflowGraph
