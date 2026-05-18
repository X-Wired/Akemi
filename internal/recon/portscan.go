package recon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	core "Akemi/internal/core"
	proxy "Akemi/internal/platform/proxy"
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
// Search order: same directory as Akemi binary → build output dirs → CWD → PATH.
// Returns the path and a list of locations that were checked (for diagnostics).
func findScannerBinary() (string, []string) {
	exeName := "Akemi-Spear"
	if isWindows() {
		exeName = "Akemi-Spear.exe"
	}

	var searched []string

	// 1. Same directory as the Akemi binary (distribution mode)
	if selfPath, err := os.Executable(); err == nil {
		dir := filepath.Dir(selfPath)
		candidate := filepath.Join(dir, exeName)
		searched = append(searched, candidate)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// 2. Release build output (most likely for developers)
	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, "Akemi-Spear", "target", "release", exeName)
		searched = append(searched, candidate)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		candidate = filepath.Join(cwd, "Akemi-Spear", "target", "debug", exeName)
		searched = append(searched, candidate)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// 3. Current working directory
	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, exeName)
		searched = append(searched, candidate)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// 4. Fall back to PATH
	if p, err := exec.LookPath(exeName); err == nil {
		return p, nil
	}
	searched = append(searched, "$PATH (not found)")

	return "", searched
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

// resolveHostIPs resolves a hostname to IPv4 addresses (Go-native path).
func resolveHostIPs(host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}
	return addrs, nil
}

// =============================================================================
// Run — dispatches to Go-native or Rust engine based on scan size
// =============================================================================

// Run executes the port scan. For small connect scans (≤50 ports, no SYN,
// no banner grab, no resume) a lightweight Go-native goroutine scanner is
// used, avoiding ~200 ms of process-spawn + JSON-pipe overhead (Phase 1.4).
// All other scans use the full Rust Akemi-Spear engine.
func (s *PortScanner) Run() (*PortScanSummary, error) {
	s.Host = extractHost(s.Host)

	if proxy.ProxyEnabled() {
		if s.SynMode {
			return nil, fmt.Errorf("SYN scan is incompatible with proxy transport; disable the proxy or use connect scan")
		}
		return nil, fmt.Errorf("port scanning is not available through a proxy (%s); unset the proxy and retry", proxy.ActiveProxyDisplay())
	}

	// ── Phase 1.4: Go-native fast path ──────────────────────────
	if s.canUseGoNative() {
		return s.runGoNative()
	}

	return s.runRustEngine()
}

// canUseGoNative returns true when the scan is small enough to run
// in-process without spawning the Rust binary.
func (s *PortScanner) canUseGoNative() bool {
	if s.SynMode || s.BannerGrab || s.NoPorts || s.Resume != "" {
		return false
	}
	return len(s.Ports) <= 50
}

// runGoNative performs a lightweight TCP connect scan using goroutines.
func (s *PortScanner) runGoNative() (*PortScanSummary, error) {
	start := time.Now()

	ips, err := resolveHostIPs(s.Host)
	if err != nil {
		return nil, fmt.Errorf("go-native scan: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("go-native scan: no IPs resolved for %s", s.Host)
	}

	if s.Threads <= 0 {
		s.Threads = 10
	}

	s.printf("\n[*] Starting Port Scan on %s (Go-native, %d ports, %d threads)\n",
		s.Host, len(s.Ports), s.Threads)

	// Build port list (respect randomize)
	ports := make([]int, len(s.Ports))
	copy(ports, s.Ports)
	if s.Randomize {
		rand.Shuffle(len(ports), func(i, j int) {
			ports[i], ports[j] = ports[j], ports[i]
		})
	}

	timeout := time.Duration(s.TimeoutS) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	dialer := &net.Dialer{Timeout: timeout}

	var mu sync.Mutex
	var openPorts []PortScanResult
	sem := make(chan struct{}, s.Threads)
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			target := net.JoinHostPort(ips[0], strconv.Itoa(p))
			conn, err := dialer.DialContext(context.Background(), "tcp", target)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, PortScanResult{
					Port:  p,
					State: "open",
				})
				mu.Unlock()
				s.printf("   \033[32m[+]\033[0m Port %-5d open\n", p)
			}
		}(port)
	}

	wg.Wait()

	// Sort results by port number for consistent output
	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	elapsed := time.Since(start)

	s.printf("[*] Port scan completed via Go-native engine. Found %d open ports in %.2fs.\n",
		len(openPorts), elapsed.Seconds())

	return &PortScanSummary{
		Hostname:     s.Host,
		IPs:          ips,
		Results:      openPorts,
		ScanTimeMs:   elapsed.Milliseconds(),
		TotalScanned: len(ports),
		ScanMode:     "connect",
	}, nil
}

// runRustEngine invokes the external Akemi-Spear binary (original path).
func (s *PortScanner) runRustEngine() (*PortScanSummary, error) {
	binPath, searched := findScannerBinary()
	if binPath == "" {
		return nil, fmt.Errorf(
			"Akemi-Spear binary not found. Searched:\n  %s\nBuild it with: cd Akemi-Spear && cargo build --release",
			strings.Join(searched, "\n  "),
		)
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

	// Execute the Rust scanner with a timeout guard.
	// Compute a reasonable upper bound: (ports * timeout_ms per port / threads) + 60s overhead
	scanTimeout := time.Duration(s.TimeoutS)*time.Second*time.Duration(len(s.Ports))/
		time.Duration(max(s.Threads, 1)) + 60*time.Second
	if scanTimeout < 30*time.Second {
		scanTimeout = 30 * time.Second
	}
	if scanTimeout > 30*time.Minute {
		scanTimeout = 30 * time.Minute
	}

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

	// Timeout guardian: kill the process if it exceeds the computed timeout
	timeoutTimer := time.AfterFunc(scanTimeout, func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	})

	if err := cmd.Wait(); err != nil {
		timeoutTimer.Stop()
		<-stderrDone
		stderrText := strings.TrimSpace(stderrBuf.String())
		if stderrText != "" {
			return nil, fmt.Errorf("Akemi-Spear failed: %s", stderrText)
		}
		return nil, fmt.Errorf("Akemi-Spear exited with error: %w", err)
	}
	timeoutTimer.Stop()
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
