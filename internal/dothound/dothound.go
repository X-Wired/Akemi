package dothound

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ── Binary discovery ────────────────────────────────────────────────

// findDotHoundBinary locates the DotHound binary.
// Search order: same directory as Akemi binary → PATH → DotHound/target/release.
func findDotHoundBinary() string {
	exeName := "dothound"
	if isWindows() {
		exeName = "dothound.exe"
	}

	// 1. Check same directory as our binary (distribution mode).
	if selfPath, err := os.Executable(); err == nil {
		dir := filepath.Dir(selfPath)
		candidate := filepath.Join(dir, exeName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// 2. Check CWD.
	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, exeName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// 3. Check DotHound build output (most likely for developers).
	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, "DotHound", "target", "release", exeName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		candidate = filepath.Join(cwd, "DotHound", "target", "debug", exeName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// 4. Fall back to PATH.
	if p, err := exec.LookPath(exeName); err == nil {
		return p
	}

	return ""
}

func isWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}

func logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
}

// ── Public API ──────────────────────────────────────────────────────

// CaptureLogin runs a headless login capture via DotHound.
// It spawns the DotHound binary with --stdin, sends the capture command as JSON,
// and parses the JSON response.
func CaptureLogin(targetURL, username, password string) (*AuthSession, error) {
	return CaptureLoginWithOptions(targetURL, username, password, StdinOptions{
		IncludeSecrets:      false,
		MaxBodyCaptureBytes: 64 * 1024,
	})
}

// CaptureLoginWithOptions runs a headless login capture with custom options.
func CaptureLoginWithOptions(targetURL, username, password string, opts StdinOptions) (*AuthSession, error) {
	binPath := findDotHoundBinary()
	if binPath == "" {
		return nil, fmt.Errorf(
			"DotHound binary not found. Build it with: cd DotHound && cargo build --release")
	}

	cmd := StdinCommand{
		Command:   "capture_login",
		TargetURL: targetURL,
		Username:  username,
		Password:  password,
		Options:   opts,
	}

	cmdJSON, err := json.Marshal(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal command: %w", err)
	}

	logf("[dothound] Spawning %s --stdin\n", binPath)
	logf("[dothound] Target: %s\n", targetURL)

	// Run DotHound with --stdin.
	execCmd := exec.Command(binPath, "--stdin")
	execCmd.Stdin = strings.NewReader(string(cmdJSON))
	execCmd.Stderr = os.Stderr // Proxy real-time progress to stderr.

	// Capture stdout for the JSON result.
	stdout, err := execCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("DotHound exited with error: %w\nStderr may have details above", err)
	}

	// Parse the JSON response.
	var response StdinResponse
	if err := json.Unmarshal(stdout, &response); err != nil {
		return nil, fmt.Errorf("failed to parse DotHound response: %w\nRaw output: %s", err, string(stdout))
	}

	if response.Status == "error" {
		return nil, fmt.Errorf("DotHound capture failed: %s", response.Error)
	}

	// Build the AuthSession from the response.
	session := &AuthSession{
		TargetURL:      targetURL,
		AuthSuccess:    false,
		CapturedAt:     time.Now(),
		WorkflowPath:   response.WorkflowPath,
		HTMLReportPath: response.HTMLPath,
	}

	if response.Summary != nil {
		session.AuthSuccess = response.Summary.AuthSuccess
		session.Cookies = response.Summary.SessionCookies
		session.CSRFTokens = response.Summary.CSRFTokens
		session.RedirectChain = response.Summary.RedirectChain
	}

	logf("[dothound] Capture complete. Auth success: %v, exchanges: %d\n",
		session.AuthSuccess,
		func() int {
			if response.Summary != nil {
				return response.Summary.TotalExchanges
			}
			return 0
		}())

	if response.WorkflowPath != "" {
		logf("[dothound] Workflow saved to: %s\n", response.WorkflowPath)
	}
	if response.HTMLPath != "" {
		logf("[dothound] HTML report saved to: %s\n", response.HTMLPath)
	}

	return session, nil
}

// StartDaemonProxy starts DotHound in daemon mode, returning the proxy URL and CA cert PEM.
// The caller is responsible for calling ShutdownDaemonProxy when done.
func StartDaemonProxy() (proxyURL string, caCertPEM string, err error) {
	binPath := findDotHoundBinary()
	if binPath == "" {
		return "", "", fmt.Errorf("DotHound binary not found")
	}

	cmd := StdinCommand{
		Command: "start_proxy",
		Options: StdinOptions{
			IncludeSecrets:      false,
			MaxBodyCaptureBytes: 64 * 1024,
		},
	}

	cmdJSON, err := json.Marshal(cmd)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal command: %w", err)
	}

	logf("[dothound] Starting daemon proxy...\n")

	execCmd := exec.Command(binPath, "--stdin")
	execCmd.Stdin = strings.NewReader(string(cmdJSON))
	execCmd.Stderr = os.Stderr

	stdout, err := execCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("DotHound daemon start failed: %w", err)
	}

	var response StdinResponse
	if err := json.Unmarshal(stdout, &response); err != nil {
		return "", "", fmt.Errorf("failed to parse daemon response: %w", err)
	}

	if response.Status != "ok" {
		return "", "", fmt.Errorf("daemon start failed: %s", response.Error)
	}

	logf("[dothound] Daemon proxy listening on %s\n", response.ProxyURL)
	return response.ProxyURL, response.CACertPEM, nil
}

// DaemonProxy holds the state for a running DotHound daemon.
type DaemonProxy struct {
	ProxyURL  string
	CACertPEM string
	cmd       *exec.Cmd
}

// StartDaemonProxyBackground starts DotHound in --daemon mode as a background process.
func StartDaemonProxyBackground() (*DaemonProxy, error) {
	binPath := findDotHoundBinary()
	if binPath == "" {
		return nil, fmt.Errorf("DotHound binary not found")
	}

	logf("[dothound] Starting background daemon proxy...\n")

	cmd := exec.Command(binPath, "--daemon")
	cmd.Stderr = os.Stderr

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start daemon: %w", err)
	}

	// Read the first line (JSON with proxy URL).
	var buf strings.Builder
	bufioReader := bufio.NewReader(stdoutPipe)
	line, err := bufioReader.ReadString('\n')
	if err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("failed to read daemon response: %w", err)
	}
	buf.WriteString(line)

	var response StdinResponse
	if err := json.Unmarshal([]byte(buf.String()), &response); err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("failed to parse daemon response: %w", err)
	}

	if response.Status != "ok" {
		cmd.Process.Kill()
		return nil, fmt.Errorf("daemon start failed: %s", response.Error)
	}

	logf("[dothound] Daemon proxy listening on %s\n", response.ProxyURL)

	return &DaemonProxy{
		ProxyURL:  response.ProxyURL,
		CACertPEM: response.CACertPEM,
		cmd:       cmd,
	}, nil
}

// Shutdown sends the shutdown command and waits for the process to exit.
func (d *DaemonProxy) Shutdown() (*StdinResponse, error) {
	if d.cmd == nil || d.cmd.Process == nil {
		return nil, fmt.Errorf("daemon not running")
	}

	shutdownCmd := StdinCommand{Command: "shutdown"}
	cmdJSON, _ := json.Marshal(shutdownCmd)

	// Send shutdown command via stdin.
	stdin, err := d.cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}
	stdin.Write(cmdJSON)
	stdin.Close()

	// Read the final JSON response from stdout.
	var buf strings.Builder
	stdoutPipe, _ := d.cmd.StdoutPipe()
	if stdoutPipe != nil {
		bufioReader := bufio.NewReader(stdoutPipe)
		for {
			line, err := bufioReader.ReadString('\n')
			buf.WriteString(line)
			if err != nil {
				break
			}
		}
	}

	d.cmd.Wait()

	var response StdinResponse
	if buf.Len() > 0 {
		json.Unmarshal([]byte(buf.String()), &response)
	}

	if response.WorkflowPath != "" {
		logf("[dothound] Workflow saved to: %s\n", response.WorkflowPath)
	}

	return &response, nil
}

// LoadWorkflowGraph loads a DotHound capture JSON file and returns the parsed graph.
func LoadWorkflowGraph(path string) (*WorkflowGraph, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read workflow file: %w", err)
	}

	var graph WorkflowGraph
	if err := json.Unmarshal(data, &graph); err != nil {
		return nil, fmt.Errorf("failed to parse workflow graph: %w", err)
	}

	return &graph, nil
}

// CookiesToHeader formats session cookies as a single Cookie header value.
func (s *AuthSession) CookiesToHeader() string {
	if len(s.Cookies) == 0 {
		return ""
	}

	var parts []string
	for _, c := range s.Cookies {
		// Each cookie string is like "session=abc123; Path=/; HttpOnly"
		// Extract just the name=value part.
		if idx := strings.Index(c, ";"); idx >= 0 {
			parts = append(parts, strings.TrimSpace(c[:idx]))
		} else {
			parts = append(parts, strings.TrimSpace(c))
		}
	}

	return strings.Join(parts, "; ")
}
