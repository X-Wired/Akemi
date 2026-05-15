package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type HTTPClientOptions struct {
	InsecureTLS     bool
	DisableRedirect bool
	DefaultHeaders  map[string]string
}

var (
	proxyConfigMu   sync.RWMutex
	proxyOverride   string
	noProxyOverride string
	proxyDisabled   bool
)

const defaultProxyConfigRelativePath = "config/proxy.txt"

func ConfigureProxy(rawProxy string, rawNoProxy string) error {
	rawProxy = strings.TrimSpace(rawProxy)
	if rawProxy != "" {
		normalized, err := normalizeProxyConfigEntry(rawProxy)
		if err != nil {
			return err
		}
		rawProxy = normalized
	}
	if rawProxy != "" {
		if _, err := parseProxyURL(rawProxy); err != nil {
			return err
		}
	}

	proxyConfigMu.Lock()
	defer proxyConfigMu.Unlock()
	proxyOverride = rawProxy
	noProxyOverride = strings.TrimSpace(rawNoProxy)
	proxyDisabled = false
	return nil
}

func DisableProxy() {
	proxyConfigMu.Lock()
	defer proxyConfigMu.Unlock()
	proxyDisabled = true
}

func ValidateActiveProxy() error {
	_, err := activeProxyChainURLs()
	return err
}

func ProxyEnabled() bool {
	return len(ActiveProxyChain()) > 0
}

func ActiveProxyURL() string {
	chain, _ := activeProxyChainRaw()
	if len(chain) == 0 {
		return ""
	}
	return chain[0]
}

func ActiveProxyChain() []string {
	chain, _ := activeProxyChainRaw()
	return append([]string(nil), chain...)
}

func ActiveProxyDisplay() string {
	chain := ActiveProxyChain()
	if len(chain) == 0 {
		return ""
	}
	return strings.Join(chain, " -> ")
}

func ActiveProxySource() string {
	_, source := activeProxyChainRaw()
	return source
}

func ActiveNoProxy() string {
	proxyConfigMu.RLock()
	override := noProxyOverride
	proxyConfigMu.RUnlock()
	if override != "" {
		return override
	}

	return firstNonEmptyEnv(
		"AKEMI_NO_PROXY",
		"NO_PROXY",
		"no_proxy",
	)
}

func CheckActiveProxyConnectivity(timeout int) error {
	if !ProxyEnabled() {
		return nil
	}

	client := CreateHTTPClientWithOptions(timeout, HTTPClientOptions{
		DisableRedirect: true,
	})
	for _, probeURL := range []string{
		"https://api.ipify.org?format=json",
		"http://api.ipify.org",
	} {
		req, err := http.NewRequest("GET", probeURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Akemi-Proxy-Check/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			return nil
		}
	}

	source := ActiveProxySource()
	if source == "" {
		source = "configured source"
	}
	return fmt.Errorf("proxy health check failed for %s (%s)", ActiveProxyDisplay(), source)
}

func CreateHTTPClientWithOptions(timeout int, opts HTTPClientOptions) *http.Client {
	if timeout <= 0 {
		timeout = 10
	}

	clientTimeout := time.Duration(timeout) * time.Second
	baseDialer := &net.Dialer{
		Timeout:   clientTimeout,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		DialContext:           baseDialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   clientTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if opts.InsecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	proxyChain, err := activeProxyChainURLs()
	if err == nil && len(proxyChain) > 0 {
		switch {
		case len(proxyChain) == 1 && (strings.EqualFold(proxyChain[0].Scheme, "http") || strings.EqualFold(proxyChain[0].Scheme, "https")):
			transport.Proxy = func(req *http.Request) (*url.URL, error) {
				if ShouldBypassProxy(req.URL.Host) {
					return nil, nil
				}
				return proxyChain[0], nil
			}
		default:
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialThroughProxyChain(ctx, baseDialer, proxyChain, network, address)
			}
		}
	}

	var rt http.RoundTripper = transport
	if len(opts.DefaultHeaders) > 0 {
		rt = &headerTransport{
			base:    transport,
			headers: opts.DefaultHeaders,
		}
	}

	client := &http.Client{
		Timeout:   clientTimeout,
		Transport: rt,
	}
	if opts.DisableRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

// headerTransport injects default headers into every request.
type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range t.headers {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
	return t.base.RoundTrip(req)
}

func DialContextWithProxy(ctx context.Context, network string, address string) (net.Conn, error) {
	if network == "" {
		network = "tcp"
	}

	dialer := &net.Dialer{
		KeepAlive: 30 * time.Second,
	}
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Timeout = time.Until(deadline)
		if dialer.Timeout < 0 {
			dialer.Timeout = 0
		}
	}

	if ShouldBypassProxy(address) {
		return dialer.DialContext(ctx, network, address)
	}

	proxyChain, err := activeProxyChainURLs()
	if err != nil {
		return nil, err
	}
	if len(proxyChain) == 0 {
		return dialer.DialContext(ctx, network, address)
	}
	return dialThroughProxyChain(ctx, dialer, proxyChain, network, address)
}

func ShouldBypassProxy(hostOrAddress string) bool {
	host := normalizeProxyHost(hostOrAddress)
	if host == "" {
		return false
	}

	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}

	rawNoProxy := ActiveNoProxy()
	if rawNoProxy == "" {
		return false
	}

	for _, entry := range strings.Split(rawNoProxy, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == "*" {
			return true
		}

		candidate := normalizeProxyHost(entry)
		if candidate == "" {
			continue
		}
		if host == candidate {
			return true
		}

		candidate = strings.TrimPrefix(candidate, ".")
		if candidate != "" && strings.HasSuffix(host, "."+candidate) {
			return true
		}
	}

	return false
}

func parseProxyURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("proxy URL must include scheme and host")
	}

	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "socks5", "socks5h":
		return parsed, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", parsed.Scheme)
	}
}

func activeProxyURL() (*url.URL, error) {
	chain, err := activeProxyChainURLs()
	if err != nil || len(chain) == 0 {
		return nil, err
	}
	return chain[0], nil
}

func activeProxyChainURLs() ([]*url.URL, error) {
	rawChain, _ := activeProxyChainRaw()
	if len(rawChain) == 0 {
		return nil, nil
	}
	chain := make([]*url.URL, 0, len(rawChain))
	for _, raw := range rawChain {
		parsed, err := parseProxyURL(strings.TrimSpace(raw))
		if err != nil {
			return nil, err
		}
		chain = append(chain, parsed)
	}
	return chain, nil
}

func activeProxyChainRaw() ([]string, string) {
	proxyConfigMu.RLock()
	override := proxyOverride
	disabled := proxyDisabled
	proxyConfigMu.RUnlock()

	if disabled {
		return nil, ""
	}
	if override != "" {
		return []string{override}, "flag"
	}
	if value, envName := firstNonEmptyEnvWithSource(
		"AKEMI_PROXY",
		"ALL_PROXY",
		"all_proxy",
		"HTTPS_PROXY",
		"https_proxy",
		"HTTP_PROXY",
		"http_proxy",
	); value != "" {
		normalized, err := normalizeProxyConfigEntry(value)
		if err == nil {
			return []string{normalized}, "env:" + envName
		}
		return []string{value}, "env:" + envName
	}
	if values, path, err := readProxyFromConfiguredFile(); len(values) > 0 || err != nil {
		if err == nil {
			return values, "file:" + path
		}
		return values, "file:" + path
	}
	return nil, ""
}

func readProxyFromConfiguredFile() ([]string, string, error) {
	for _, path := range proxyConfigCandidates() {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		value, err := readProxyFromFile(path)
		if err != nil {
			return nil, path, err
		}
		return value, path, nil
	}
	return nil, "", nil
}

func readProxyFromFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var chain []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		normalized, err := normalizeProxyConfigEntry(line)
		if err != nil {
			return []string{line}, err
		}
		chain = append(chain, normalized)
	}
	return chain, nil
}

func proxyConfigCandidates() []string {
	var candidates []string
	if configured := strings.TrimSpace(os.Getenv("AKEMI_PROXY_FILE")); configured != "" {
		candidates = append(candidates, configured)
	}

	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		dir := cwd
		for {
			candidates = append(candidates, filepath.Join(dir, defaultProxyConfigRelativePath))
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	candidates = append(candidates, defaultProxyConfigRelativePath)
	return uniqueStrings(candidates)
}

func normalizeProxyConfigEntry(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if strings.Contains(raw, "://") {
		return raw, nil
	}

	parts := strings.Split(raw, ":")
	switch len(parts) {
	case 2:
		return "http://" + raw, nil
	case 4:
		proxyURL := &url.URL{
			Scheme: "http",
			Host:   net.JoinHostPort(parts[0], parts[1]),
			User:   url.UserPassword(parts[2], parts[3]),
		}
		return proxyURL.String(), nil
	default:
		return "", fmt.Errorf("unsupported proxy entry format: %q", raw)
	}
}

func firstNonEmptyEnvWithSource(names ...string) (string, string) {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value, name
		}
	}
	return "", ""
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	var result []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func dialThroughProxyChain(
	ctx context.Context,
	baseDialer *net.Dialer,
	proxyChain []*url.URL,
	network string,
	address string,
) (net.Conn, error) {
	if len(proxyChain) == 0 {
		return baseDialer.DialContext(ctx, network, address)
	}

	conn, err := baseDialer.DialContext(ctx, "tcp", proxyChain[0].Host)
	if err != nil {
		return nil, err
	}

	currentConn := conn
	for idx, proxyURL := range proxyChain {
		nextHop := address
		if idx+1 < len(proxyChain) {
			nextHop = proxyChain[idx+1].Host
		}

		nextConn, err := dialViaProxyHop(ctx, currentConn, proxyURL, nextHop)
		if err != nil {
			currentConn.Close()
			return nil, err
		}
		currentConn = nextConn
	}

	return currentConn, nil
}

func dialViaProxyHop(ctx context.Context, conn net.Conn, proxyURL *url.URL, address string) (net.Conn, error) {
	switch strings.ToLower(proxyURL.Scheme) {
	case "http", "https":
		return connectViaHTTPProxy(ctx, conn, proxyURL, address)
	case "socks5", "socks5h":
		return connectViaSOCKS5Proxy(ctx, conn, proxyURL, address)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme for dialing: %s", proxyURL.Scheme)
	}
}

func connectViaHTTPProxy(ctx context.Context, conn net.Conn, proxyURL *url.URL, address string) (net.Conn, error) {
	if strings.EqualFold(proxyURL.Scheme, "https") {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: proxyURL.Hostname(),
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", address, address)
	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		connectReq += "Proxy-Authorization: Basic " + token + "\r\n"
	}
	connectReq += "\r\n"

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.Contains(statusLine, " 200 ") && !strings.HasPrefix(statusLine, "HTTP/1.1 200") && !strings.HasPrefix(statusLine, "HTTP/1.0 200") {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(statusLine))
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		if line == "\r\n" {
			break
		}
	}

	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func connectViaSOCKS5Proxy(ctx context.Context, conn net.Conn, proxyURL *url.URL, address string) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	methods := []byte{0x00}
	needsAuth := proxyURL.User != nil && proxyURL.User.Username() != ""
	if needsAuth {
		methods = []byte{0x00, 0x02}
	}

	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		conn.Close()
		return nil, err
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, err
	}
	if reply[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("invalid SOCKS5 proxy version: %d", reply[0])
	}
	if reply[1] == 0xFF {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 proxy rejected authentication methods")
	}

	if reply[1] == 0x02 {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		if len(username) > 255 || len(password) > 255 {
			conn.Close()
			return nil, fmt.Errorf("SOCKS5 credentials exceed 255 bytes")
		}
		authReq := []byte{0x01, byte(len(username))}
		authReq = append(authReq, []byte(username)...)
		authReq = append(authReq, byte(len(password)))
		authReq = append(authReq, []byte(password)...)
		if _, err := conn.Write(authReq); err != nil {
			conn.Close()
			return nil, err
		}

		authReply := make([]byte, 2)
		if _, err := io.ReadFull(conn, authReply); err != nil {
			conn.Close()
			return nil, err
		}
		if authReply[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("SOCKS5 authentication failed")
		}
	}

	host, port, err := splitHostPort(address)
	if err != nil {
		conn.Close()
		return nil, err
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			req = append(req, 0x01)
			req = append(req, ipv4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("SOCKS5 hostname exceeds 255 bytes")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		conn.Close()
		return nil, err
	}
	if header[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 CONNECT failed with status 0x%02x", header[1])
	}

	addrLen := 0
	switch header[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		size := make([]byte, 1)
		if _, err := io.ReadFull(conn, size); err != nil {
			conn.Close()
			return nil, err
		}
		addrLen = int(size[0])
	default:
		conn.Close()
		return nil, fmt.Errorf("invalid SOCKS5 address type 0x%02x", header[3])
	}

	discard := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, discard); err != nil {
		conn.Close()
		return nil, err
	}

	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func splitHostPort(address string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	portNum, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return "", 0, err
	}
	return strings.Trim(host, "[]"), portNum, nil
}

func normalizeProxyHost(hostOrAddress string) string {
	host := strings.TrimSpace(hostOrAddress)
	if host == "" {
		return ""
	}
	if parsed, err := url.Parse(host); err == nil && parsed.Host != "" {
		host = parsed.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

func firstNonEmptyEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}
