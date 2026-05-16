package recon

import (
	core "Akemi/internal/core"
	proxy "Akemi/internal/platform/proxy"
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// PortScanResult holds details of an open port.
type PortScanResult struct {
	Port        int         `json:"port"`
	State       string      `json:"state"`
	Banner      string      `json:"banner,omitempty"`
	Technology  []string    `json:"technology,omitempty"`
	TechMatches []TechMatch `json:"tech_matches,omitempty"`
	Service     string      `json:"service,omitempty"`
	Version     string      `json:"version,omitempty"`
	TLS         bool        `json:"tls"`
	TLSCN       string      `json:"tls_cn,omitempty"`
}

// TechMatch represents a structured technology detection with confidence scoring.
type TechMatch struct {
	Name       string  `json:"name"`
	Category   string  `json:"category"`
	Confidence float32 `json:"confidence"`
	Version    *string `json:"version,omitempty"`
	Evidence   string  `json:"evidence"`
	Source     string  `json:"source"`
}

// PortScanSummary aggregates the scanned host's data.
type PortScanSummary struct {
	Hostname     string            `json:"hostname"`
	IPs          []string          `json:"ips"`
	RDNS         map[string]string `json:"rdns,omitempty"`
	OSHint       string            `json:"os_hint,omitempty"`
	TTL          *uint32           `json:"ttl,omitempty"`
	Results      []PortScanResult  `json:"results"`
	AliveHosts   []AliveHostResult `json:"alive_hosts,omitempty"`
	ScanTimeMs   int64             `json:"scan_time_ms,omitempty"`
	TotalScanned int               `json:"total_scanned,omitempty"`
	ScanMode     string            `json:"scan_mode,omitempty"`
}

// AliveHostResult is the Rust host-discovery JSON mapped into Go.
type AliveHostResult struct {
	IP        string  `json:"ip"`
	Alive     bool    `json:"alive"`
	LatencyMs float64 `json:"latency_ms"`
	RDNS      string  `json:"rdns,omitempty"`
	Method    string  `json:"method"`
}

// PortScanner orchestrates port scanning via the Rust Akemi-Spear binary.
type PortScanner struct {
	Host       string
	Threads    int
	TimeoutS   int // seconds
	Ports      []int
	ProbeDir   string
	BannerGrab bool

	// New masscan-inspired options
	Rate      float64 // connections per second (0 = unlimited)
	SynMode   bool    // use SYN scan (needs admin)
	Retries   int     // retry count for timeouts
	Randomize bool    // shuffle port order
	Resume    string  // path to resume state file
	Verbose   bool    // show progress/headers in scanner
	NoPorts   bool    // skip port scanning, host discovery only

	// SuppressOutput silences all fmt.Print* output from the scanner.
	// Use this when running under a TUI that manages its own display.
	SuppressOutput bool
}

func (s *PortScanner) printf(format string, args ...interface{}) {
	if !s.SuppressOutput {
		fmt.Printf(format, args...)
	}
}

func (s *PortScanner) println(args ...interface{}) {
	if !s.SuppressOutput {
		fmt.Println(args...)
	}
}

// ParsePortsList ensures unique sorted ports
func ParsePortsList(defs []string) []int {
	portMap := make(map[int]bool)
	for _, def := range defs {
		for _, part := range strings.Split(def, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if strings.EqualFold(part, "top-1000") || strings.EqualFold(part, "top1000") {
				for _, port := range ParsePortsList([]string{Top1000Ports}) {
					portMap[port] = true
				}
				continue
			}
			if strings.Contains(part, "-") {
				parts := strings.Split(part, "-")
				if len(parts) == 2 {
					start, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
					end, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
					if start > 0 && end > 0 && start <= end {
						for i := start; i <= end; i++ {
							portMap[i] = true
						}
					}
				}
				continue
			}
			p, err := strconv.Atoi(part)
			if err == nil && p > 0 && p <= 65535 {
				portMap[p] = true
			}
		}
	}
	var ports []int
	for p := range portMap {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// scanRequest is the JSON contract sent to Akemi-Spear via stdin.
type scanRequest struct {
	Host             string  `json:"host"`
	Ports            []int   `json:"ports"`
	Threads          int     `json:"threads"`
	TimeoutMs        int     `json:"timeout_ms"`
	Rate             float64 `json:"rate"`
	Retries          int     `json:"retries"`
	Randomize        bool    `json:"randomize"`
	SynMode          bool    `json:"syn_mode"`
	BannerGrab       bool    `json:"banner_grab"`
	ProbeTemplateDir string  `json:"probe_templates_dir"`
	ResumeFile       string  `json:"resume_file"`
	Verbose          bool    `json:"verbose"`
	NoPort           bool    `json:"no_port"`
}

// scanResult is the JSON contract received from Akemi-Spear via stdout.
type scanResult struct {
	Hostname     string            `json:"hostname"`
	IPs          []string          `json:"ips"`
	RDNS         map[string]string `json:"rdns,omitempty"`
	OpenPorts    []scanResultPort  `json:"open_ports"`
	ScanTimeMs   int64             `json:"scan_time_ms"`
	TotalScanned int               `json:"total_scanned"`
	ScanMode     string            `json:"scan_mode"`
	OSHint       *string           `json:"os_hint,omitempty"`
	TTL          *uint32           `json:"ttl,omitempty"`
}

type scanResultPort struct {
	Port        int         `json:"port"`
	State       string      `json:"state"`
	Banner      *string     `json:"banner,omitempty"`
	Technology  []string    `json:"technology,omitempty"`
	TechMatches []TechMatch `json:"tech_matches,omitempty"`
	Service     *string     `json:"service,omitempty"`
	Version     *string     `json:"version,omitempty"`
	TLS         bool        `json:"tls"`
	TLSCN       *string     `json:"tls_cn,omitempty"`
}

type hostDiscoveryScanResult struct {
	TotalHosts int               `json:"total_hosts"`
	AliveHosts []AliveHostResult `json:"alive_hosts"`
	ScanTimeMs int64             `json:"scan_time_ms"`
}

// findScannerBinary locates the Akemi-Spear binary.
// Search order: same directory as Akemi binary → PATH.
func findScannerBinary() string {
	exeName := "Akemi-Spear"
	if isWindows() {
		exeName = "Akemi-Spear.exe"
	}

	// First, check in the Akemi-Spear build output (most likely for developers)
	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, "Akemi-Spear", "target", "release", exeName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		candidate = filepath.Join(cwd, "Akemi-Spear", "target", "debug", exeName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// Then, check same directory as our binary (distribution mode)
	if selfPath, err := os.Executable(); err == nil {
		dir := filepath.Dir(selfPath)
		candidate := filepath.Join(dir, exeName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// Also check CWD
	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, exeName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// Fall back to PATH
	if p, err := exec.LookPath(exeName); err == nil {
		return p
	}

	return ""
}

func isWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}

// extractHost parses a target string that may be a URL and returns the bare
// hostname. If the string is already a plain host or IP, it is returned as-is.
func extractHost(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
			return parsed.Hostname()
		}
	}
	return target
}

// Run executes the port scan by invoking the Rust Akemi-Spear binary.
func (s *PortScanner) Run() (*PortScanSummary, error) {
	// Normalise the host: strip URL scheme so the Rust scanner receives a
	// bare hostname or IP.
	s.Host = extractHost(s.Host)

	if proxy.ProxyEnabled() {
		if s.SynMode {
			return nil, fmt.Errorf("SYN scan is incompatible with proxy transport; disable the proxy or use connect scan")
		}
		return nil, fmt.Errorf("port scanning is not available through a proxy (%s); unset the proxy and retry", proxy.ActiveProxyDisplay())
	}

	binPath := findScannerBinary()
	if binPath == "" {
		return nil, fmt.Errorf("Akemi-Spear binary not found; build it with: cd Akemi-Spear && cargo build --release")
	}

	if s.NoPorts {
		s.printf("\n[*] Starting Host Discovery on %s (via Rust engine)\n", s.Host)
		s.printf("[*] Scanner: %s\n", binPath)
		s.printf("[*] Threads=%d, Rate=%.0f/s\n", s.Threads, s.Rate)
	} else {
		s.printf("\n[*] Starting Port Scan on %s (via Rust engine)\n", s.Host)
		s.printf("[*] Scanner: %s\n", binPath)
		s.printf("[*] Scanning %d ports, %d threads, rate=%.0f/s\n", len(s.Ports), s.Threads, s.Rate)
	}

	// Convert ports to uint16 list for JSON
	portsU16 := make([]int, len(s.Ports))
	copy(portsU16, s.Ports)

	probeDir := s.ProbeDir
	if probeDir == "" {
		probeDir = "./probes"
	}
	probeDir = core.ResolveProbeTemplateDir(probeDir)

	req := scanRequest{
		Host:             s.Host,
		Ports:            portsU16,
		Threads:          s.Threads,
		TimeoutMs:        s.TimeoutS * 1000,
		Rate:             s.Rate,
		Retries:          s.Retries,
		Randomize:        s.Randomize,
		SynMode:          s.SynMode,
		BannerGrab:       s.BannerGrab,
		ProbeTemplateDir: probeDir,
		ResumeFile:       s.Resume,
		Verbose:          s.Verbose,
		NoPort:           s.NoPorts,
	}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("error marshaling scan request: %w", err)
	}

	// Execute the Rust scanner
	cmd := exec.Command(binPath, "--stdin")
	cmd.Stdin = strings.NewReader(string(reqJSON))

	// Capture stderr for progress/log output (display in real-time)
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("error creating stderr pipe: %w", err)
	}

	// Capture stdout for JSON result
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("error creating stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting Akemi-Spear: %w", err)
	}

	// Stream stderr to console in real-time
	stderrDone := make(chan struct{})
	var stderrBuf strings.Builder
	go func() {
		defer close(stderrDone)
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			stderrBuf.WriteString(line)
			stderrBuf.WriteString("\n")
			s.println(line)
		}
	}()

	// Read full stdout (the JSON result)
	var stdoutBuf strings.Builder
	stdoutScanner := bufio.NewScanner(stdoutPipe)
	stdoutScanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer
	for stdoutScanner.Scan() {
		stdoutBuf.WriteString(stdoutScanner.Text())
		stdoutBuf.WriteString("\n")
	}

	if err := cmd.Wait(); err != nil {
		<-stderrDone
		stderrText := strings.TrimSpace(stderrBuf.String())
		if stderrText != "" {
			return nil, fmt.Errorf("Akemi-Spear failed: %s", stderrText)
		}
		return nil, fmt.Errorf("Akemi-Spear exited with error: %w", err)
	}
	<-stderrDone

	// Parse the JSON result
	if s.NoPorts {
		var result hostDiscoveryScanResult
		if err := json.Unmarshal([]byte(stdoutBuf.String()), &result); err != nil {
			return nil, fmt.Errorf("error parsing host discovery JSON: %w\nRaw output: %s", err, stdoutBuf.String())
		}
		ips := make([]string, 0, len(result.AliveHosts))
		for _, host := range result.AliveHosts {
			if host.Alive {
				ips = append(ips, host.IP)
			}
		}
		return &PortScanSummary{
			Hostname:     s.Host,
			IPs:          ips,
			AliveHosts:   result.AliveHosts,
			ScanTimeMs:   result.ScanTimeMs,
			TotalScanned: result.TotalHosts,
			ScanMode:     "host-discovery",
		}, nil
	}

	var result scanResult
	if err := json.Unmarshal([]byte(stdoutBuf.String()), &result); err != nil {
		return nil, fmt.Errorf("error parsing scan result JSON: %w\nRaw output: %s", err, stdoutBuf.String())
	}

	// Convert to PortScanSummary
	summary := &PortScanSummary{
		Hostname:     result.Hostname,
		IPs:          result.IPs,
		RDNS:         result.RDNS,
		ScanTimeMs:   result.ScanTimeMs,
		TotalScanned: result.TotalScanned,
		ScanMode:     result.ScanMode,
	}
	if result.OSHint != nil {
		summary.OSHint = *result.OSHint
	}
	summary.TTL = result.TTL

	for _, p := range result.OpenPorts {
		banner := ""
		if p.Banner != nil {
			banner = *p.Banner
		}
		service := ""
		if p.Service != nil {
			service = *p.Service
		}
		version := ""
		if p.Version != nil {
			version = *p.Version
		}
		tlsCN := ""
		if p.TLSCN != nil {
			tlsCN = *p.TLSCN
		}
		summary.Results = append(summary.Results, PortScanResult{
			Port:        p.Port,
			State:       p.State,
			Banner:      banner,
			Technology:  p.Technology,
			TechMatches: p.TechMatches,
			Service:     service,
			Version:     version,
			TLS:         p.TLS,
			TLSCN:       tlsCN,
		})
	}

	s.printf("[*] Port scan completed via Rust engine (%s mode). Found %d open ports in %.2fs.\n",
		result.ScanMode, len(result.OpenPorts), float64(result.ScanTimeMs)/1000.0)

	return summary, nil
}
