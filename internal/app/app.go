package app

import (
	ui "Akemi/internal/cli/ui"
	core "Akemi/internal/core"
	exploit "Akemi/internal/exploit"
	"Akemi/internal/fuzz"
	proxy "Akemi/internal/platform/proxy"
	recon "Akemi/internal/recon"
	"Akemi/internal/reporting"
	vuln "Akemi/internal/vuln"
	"net/http"
	"time"
)

type ExploitDB = exploit.ExploitDB
type ExploitDBEntry = exploit.ExploitDBEntry
type ExploitMatchResult = exploit.ExploitMatchResult
type ScanReport = reporting.ScanReport
type CrawlFinding = recon.CrawlFinding
type DorkConfig = recon.DorkConfig
type MiningConfig = recon.MiningConfig
type DiscoveryResult = recon.DiscoveryResult
type JSAnalysisResult = recon.JSAnalysisResult
type SecretFinding = recon.SecretFinding
type APIEndpointFinding = recon.APIEndpointFinding
type APISpecFinding = recon.APISpecFinding
type SubdomainConfig = recon.SubdomainConfig
type ProbeConfig = vuln.ProbeConfig
type PortScanner = recon.PortScanner
type FuzzConfig = core.FuzzConfig

const Top1000Ports = recon.Top1000Ports

func PrintASCIIArtNeon() { ui.PrintASCIIArtNeon() }
func ConfigureProxy(rawProxy string, rawNoProxy string) error {
	return proxy.ConfigureProxy(rawProxy, rawNoProxy)
}
func DisableProxy()              { proxy.DisableProxy() }
func ValidateActiveProxy() error { return proxy.ValidateActiveProxy() }
func ProxyEnabled() bool         { return proxy.ProxyEnabled() }
func ActiveProxyDisplay() string { return proxy.ActiveProxyDisplay() }
func ActiveProxySource() string  { return proxy.ActiveProxySource() }
func ActiveNoProxy() string      { return proxy.ActiveNoProxy() }
func CheckActiveProxyConnectivity(timeout int) error {
	return proxy.CheckActiveProxyConnectivity(timeout)
}
func LoadTemplates(dir string) ([]vuln.ProbeTemplate, error) { return vuln.LoadTemplates(dir) }
func ListTemplates(templates []vuln.ProbeTemplate)           { vuln.ListTemplates(templates) }
func PerformDork(cfg recon.DorkConfig) ([]string, error)     { return recon.PerformDork(cfg) }
func EnsureProtocol(raw string) string                       { return core.EnsureProtocol(raw) }
func Contains(slice []string, val string) bool               { return core.Contains(slice, val) }
func NewScanReport(target string) *reporting.ScanReport      { return reporting.NewScanReport(target) }
func ParsePortsList(defs []string) []int                     { return recon.ParsePortsList(defs) }
func LoadExploitDB(csvPath string) (*exploit.ExploitDB, error) {
	return exploit.LoadExploitDB(csvPath)
}
func MatchExploitsToScan(db *exploit.ExploitDB, portScan *recon.PortScanSummary, maxPerService int) []exploit.ExploitMatchResult {
	return exploit.MatchExploitsToScan(db, portScan, maxPerService)
}
func PrintExploitMatches(results []exploit.ExploitMatchResult) { exploit.PrintExploitMatches(results) }
func Crawl(startURL string, maxDepth int) ([]string, error)    { return recon.Crawl(startURL, maxDepth) }
func CrawlDetailed(startURL string, maxDepth int) ([]recon.CrawlFinding, error) {
	return recon.CrawlDetailed(startURL, maxDepth)
}
func EnhancedDiscoverParams(rawURL string, cfg recon.MiningConfig) (*recon.DiscoveryResult, error) {
	return recon.EnhancedDiscoverParams(rawURL, cfg)
}
func PrintParamMiningResult(params map[string]recon.RichParamDetail) {
	recon.PrintParamMiningResult(params)
}
func ScrapePage(pageURL string, keywords []string) (*recon.ScrapeResult, error) {
	return recon.ScrapePage(pageURL, keywords)
}
func AnalyzeJS(pageURL string) (*recon.JSAnalysisResult, error) { return recon.AnalyzeJS(pageURL) }
func DiscoverAPISurface(startURL string, discoveredURLs []string, configResources []string, client *http.Client) ([]recon.APIEndpointFinding, []recon.APISpecFinding, error) {
	return recon.DiscoverAPISurface(startURL, discoveredURLs, configResources, client)
}
func PrintJSAnalysisResult(result *recon.JSAnalysisResult) { recon.PrintJSAnalysisResult(result) }
func EnumerateSubdomains(domain string, cfg recon.SubdomainConfig) ([]recon.SubdomainResult, error) {
	return recon.EnumerateSubdomains(domain, cfg)
}
func PrintSubdomainSummary(results []recon.SubdomainResult) { recon.PrintSubdomainSummary(results) }
func ProbeParams(rawURL string, cfg vuln.ProbeConfig) ([]vuln.VulnFinding, error) {
	return vuln.ProbeParams(rawURL, cfg)
}
func PrintVulnSummary(findings []vuln.VulnFinding) { vuln.PrintVulnSummary(findings) }
func BuildGraph(report *reporting.ScanReport) *reporting.ScanGraph {
	return reporting.BuildGraph(report)
}
func RunFuzzer(cfg core.FuzzConfig) ([]core.FuzzResult, time.Duration, error) {
	return fuzz.RunFuzzer(cfg)
}
func CreateHTTPClient(timeout int) *http.Client { return core.CreateHTTPClient(timeout) }
