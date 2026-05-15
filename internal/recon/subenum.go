package recon

import (
	core "Akemi/internal/core"
	"Akemi/internal/fuzz"
	proxy "Akemi/internal/platform/proxy"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SubdomainResult holds the details of a discovered subdomain.
type SubdomainResult struct {
	Subdomain  string
	IPs        []string
	Source     string // "bruteforce", "crtsh", "permutation"
	Alive      bool   // True if HTTP/HTTPS responded
	StatusCode int
}

// SubdomainConfig holds options for the enumerator.
type SubdomainConfig struct {
	Threads      int
	Timeout      int
	WordlistFile string // Path to subdomain wordlist
	CheckAlive   bool   // Probe HTTP/HTTPS for live hosts
	UseCrtSh     bool   // Query crt.sh certificate transparency logs
	Permutate    bool   // Generate permutations from found subdomains
	Quiet        bool   // Suppress terminal progress output when embedded in TUI/service flows
}

// Common subdomain wordlist used when no file is provided.
var defaultSubdomainWords = []string{
	"www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
	"beta", "app", "portal", "dashboard", "vpn", "remote", "ssh",
	"git", "gitlab", "github", "jenkins", "ci", "cd", "build",
	"db", "mysql", "postgres", "redis", "mongo", "elastic",
	"cdn", "static", "assets", "media", "img", "images",
	"shop", "store", "blog", "forum", "support", "help", "docs",
	"internal", "intranet", "corp", "private", "old", "new", "v2",
	"auth", "login", "sso", "oauth", "id", "accounts",
	"m", "mobile", "wap", "webmail", "smtp", "pop", "imap",
	"ns1", "ns2", "mx", "mx1", "mx2",
	"monitor", "status", "health", "grafana", "kibana", "elk",
}

// Permutation templates applied to each found subdomain word.
var permutationTemplates = []string{
	"%s-dev", "%s-staging", "%s-test", "%s-prod", "%s-old",
	"%s-new", "%s-v2", "%s-api", "%s-internal", "dev-%s",
	"staging-%s", "test-%s", "new-%s", "old-%s", "api-%s",
}

// crtShResponse is the structure returned by crt.sh JSON API.
type crtShResponse struct {
	NameValue string `json:"name_value"`
}

// --- Core DNS Resolution ---

// resolveSubdomain attempts to resolve a hostname and returns its IPs.
func resolveSubdomain(hostname string, timeout int) ([]string, error) {
	// Use standard LookupHost with a deadline via a goroutine + channel
	type result struct {
		addrs []string
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		addrs, err := net.LookupHost(hostname)
		ch <- result{addrs, err}
	}()
	select {
	case res := <-ch:
		return res.addrs, res.err
	case <-time.After(time.Duration(timeout) * time.Second):
		return nil, fmt.Errorf("DNS timeout for %s", hostname)
	}
}

// checkAlive probes a subdomain over HTTP and HTTPS to see if it responds.
func checkAlive(subdomain string, timeout int) (bool, int) {
	client := proxy.CreateHTTPClientWithOptions(timeout, proxy.HTTPClientOptions{
		InsecureTLS:     true,
		DisableRedirect: true,
	})
	proxyMode := proxy.ProxyEnabled()

	for _, scheme := range []string{"https", "http"} {
		resp, err := client.Get(fmt.Sprintf("%s://%s", scheme, subdomain))
		if err == nil {
			if proxyMode && isProxyGeneratedResponse(resp) {
				resp.Body.Close()
				continue
			}
			if proxyMode && resp.StatusCode >= http.StatusInternalServerError {
				resp.Body.Close()
				continue
			}
			resp.Body.Close()
			return true, resp.StatusCode
		}
	}
	return false, 0
}

func isProxyGeneratedResponse(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.Header.Get("X-Webshare-Error") != "" || resp.Header.Get("X-Webshare-Reason") != "" {
		return true
	}
	if strings.EqualFold(resp.Header.Get("Proxy-Connection"), "close") && resp.StatusCode >= http.StatusBadRequest {
		return true
	}
	return false
}

// --- Certificate Transparency (crt.sh) ---

// queryCrtSh queries crt.sh for known subdomains via cert transparency logs.
func queryCrtSh(domain string, timeout int) ([]string, error) {
	client := core.CreateHTTPClient(timeout)
	apiURL := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("error querying crt.sh: %w", err)
	}
	defer resp.Body.Close()

	var entries []crtShResponse
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("error decoding crt.sh response: %w", err)
	}

	seen := make(map[string]bool)
	var subdomains []string

	for _, entry := range entries {
		// crt.sh can return multiple names separated by newlines
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			// Skip wildcards and the apex domain itself
			if strings.HasPrefix(name, "*") || name == domain {
				continue
			}
			if strings.HasSuffix(name, "."+domain) && !seen[name] {
				seen[name] = true
				subdomains = append(subdomains, name)
			}
		}
	}

	return subdomains, nil
}

// --- Permutation Generation ---

// generatePermutations creates subdomain variations from already-found words.
func generatePermutations(found []string, domain string) []string {
	wordSet := make(map[string]bool)
	// Extract the word part (strip the domain suffix)
	for _, sub := range found {
		word := strings.TrimSuffix(sub, "."+domain)
		wordSet[word] = true
	}

	seen := make(map[string]bool)
	var perms []string

	for word := range wordSet {
		for _, tmpl := range permutationTemplates {
			candidate := fmt.Sprintf(tmpl+".%s", word, domain)
			if !seen[candidate] {
				seen[candidate] = true
				perms = append(perms, candidate)
			}
		}
	}
	return perms
}

// --- Main Entry Point ---

// EnumerateSubdomains is the main entry point for subdomain enumeration.
// It combines brute-force DNS, crt.sh, and optional permutation in one pass.
func EnumerateSubdomains(domain string, cfg SubdomainConfig) ([]SubdomainResult, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	// Strip protocol if user passed a URL
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.Split(domain, "/")[0]

	if cfg.Threads == 0 {
		cfg.Threads = 20
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5
	}
	proxyMode := proxy.ProxyEnabled()
	if proxyMode && !cfg.CheckAlive {
		if !cfg.Quiet {
			fmt.Println("[proxy] Subdomain enumeration in proxy mode requires HTTP validation. Enabling alive checks.")
		}
		cfg.CheckAlive = true
	}

	if !cfg.Quiet {
		fmt.Printf("\n[*] Starting subdomain enumeration for: %s\n", domain)
		fmt.Printf("%s\n", strings.Repeat("-", 50))
	}
	if proxyMode && !cfg.Quiet {
		fmt.Printf("[proxy] Routing web validation via %s (direct DNS resolution disabled)\n", proxy.ActiveProxyDisplay())
	}

	// Build candidate list
	var candidates []string

	// 1. Wordlist (file or built-in)
	if cfg.WordlistFile != "" {
		words, err := loadWordlist(cfg.WordlistFile)
		if err != nil && cfg.Quiet {
			candidates = appendSubdomains(candidates, defaultSubdomainWords, domain)
		} else if err != nil {
			fmt.Printf("[!] Error loading wordlist: %v — using built-in list\n", err)
			candidates = appendSubdomains(candidates, defaultSubdomainWords, domain)
		} else {
			candidates = appendSubdomains(candidates, words, domain)
			if !cfg.Quiet {
				fmt.Printf("[+] Loaded %d words from wordlist\n", len(words))
			}
		}
	} else {
		candidates = appendSubdomains(candidates, defaultSubdomainWords, domain)
		if !cfg.Quiet {
			fmt.Printf("[+] Using built-in wordlist (%d words)\n", len(defaultSubdomainWords))
		}
	}

	// 2. crt.sh passive recon
	var crtshFound []string
	if cfg.UseCrtSh {
		if !cfg.Quiet {
			fmt.Println("[*] Querying crt.sh certificate transparency logs...")
		}
		crtSubs, err := queryCrtSh(domain, cfg.Timeout*2)
		if err != nil {
			if !cfg.Quiet {
				fmt.Printf("[!] crt.sh error: %v\n", err)
			}
		} else {
			if !cfg.Quiet {
				fmt.Printf("[+] crt.sh returned %d subdomains\n", len(crtSubs))
			}
			crtshFound = crtSubs
			for _, sub := range crtSubs {
				if !contains(candidates, sub) {
					candidates = append(candidates, sub)
				}
			}
		}
	}

	// 3. Permutations from crt.sh results
	if cfg.Permutate && len(crtshFound) > 0 {
		perms := generatePermutations(crtshFound, domain)
		if !cfg.Quiet {
			fmt.Printf("[+] Generated %d permutation candidates\n", len(perms))
		}
		for _, p := range perms {
			if !contains(candidates, p) {
				candidates = append(candidates, p)
			}
		}
	}

	if !cfg.Quiet {
		fmt.Printf("[*] Total candidates to probe: %d\n\n", len(candidates))
	}

	// Resolve all candidates concurrently
	var results []SubdomainResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Threads)

	for _, candidate := range candidates {
		wg.Add(1)
		go func(hostname string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			source := "bruteforce"
			if contains(crtshFound, hostname) {
				source = "crtsh"
			}
			if cfg.Permutate {
				for _, tmpl := range permutationTemplates {
					word := strings.TrimSuffix(hostname, "."+domain)
					if fmt.Sprintf(tmpl, word)+"."+domain == hostname {
						source = "permutation"
						break
					}
				}
			}

			result := SubdomainResult{
				Subdomain: hostname,
				Source:    source,
			}

			if proxyMode {
				alive, code := checkAlive(hostname, cfg.Timeout)
				if !alive {
					return
				}
				result.Alive = true
				result.StatusCode = code
			} else {
				ips, err := resolveSubdomain(hostname, cfg.Timeout)
				if err != nil {
					return // Does not resolve — skip silently
				}
				result.IPs = ips

				// Optionally probe HTTP/HTTPS
				if cfg.CheckAlive {
					alive, code := checkAlive(hostname, cfg.Timeout)
					result.Alive = alive
					result.StatusCode = code
				}
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

			if !cfg.Quiet {
				printSubdomainResult(result, cfg.CheckAlive)
			}
		}(candidate)
	}

	wg.Wait()
	return results, nil
}

// --- Helpers ---

// loadWordlist reads lines from a file into a string slice.
func loadWordlist(path string) ([]string, error) {
	payloadChan, err := fuzz.LazyReadPayloadsFromFile(path)
	if err != nil {
		return nil, err
	}
	var words []string
	for word := range payloadChan {
		word = strings.TrimSpace(word)
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}
	return words, nil
}

// appendSubdomains converts a word list into fully qualified subdomain candidates.
func appendSubdomains(existing []string, words []string, domain string) []string {
	for _, word := range words {
		fqdn := fmt.Sprintf("%s.%s", strings.ToLower(strings.TrimSpace(word)), domain)
		if !contains(existing, fqdn) {
			existing = append(existing, fqdn)
		}
	}
	return existing
}

// printSubdomainResult logs a discovered subdomain to stdout.
func printSubdomainResult(r SubdomainResult, showAlive bool) {
	aliveStr := ""
	if showAlive {
		if r.Alive {
			aliveStr = fmt.Sprintf(" [ALIVE %d]", r.StatusCode)
		} else {
			aliveStr = " [no HTTP]"
		}
	}
	fmt.Printf("[+] %-45s  IPs: %-20s  src: %s%s\n",
		r.Subdomain,
		strings.Join(r.IPs, ", "),
		r.Source,
		aliveStr,
	)
}

// PrintSubdomainSummary prints a final grouped summary of all found subdomains.
func PrintSubdomainSummary(results []SubdomainResult) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("  SUBDOMAIN ENUMERATION SUMMARY — %d found\n", len(results))
	fmt.Printf("%s\n", strings.Repeat("=", 60))

	alive := 0
	bySource := make(map[string]int)
	for _, r := range results {
		bySource[r.Source]++
		if r.Alive {
			alive++
		}
	}

	for src, count := range bySource {
		fmt.Printf("  Source %-15s : %d\n", src, count)
	}
	if alive > 0 {
		fmt.Printf("  Live HTTP hosts  : %d\n", alive)
	}

	fmt.Printf("\n  Full list:\n")
	for _, r := range results {
		fmt.Printf("    %s  ->  %s\n", r.Subdomain, strings.Join(r.IPs, ", "))
	}
}
