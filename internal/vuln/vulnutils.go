package vuln

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ── Timed Request Helper ─────────────────────────────────────

// TimedResponse wraps a standard http.Response with timing info.
type TimedResponse struct {
	Response *http.Response
	Body     []byte
	BodyStr  string
	Elapsed  time.Duration
}

// timedGET performs a GET request and returns the response with timing.
func timedGET(client *http.Client, url string) (*TimedResponse, error) {
	start := time.Now()
	resp, err := client.Get(url)
	elapsed := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &TimedResponse{
			Response: resp,
			Elapsed:  elapsed,
		}, err
	}

	return &TimedResponse{
		Response: resp,
		Body:     body,
		BodyStr:  string(body),
		Elapsed:  elapsed,
	}, nil
}

// sendPOSTWithBody performs a POST request with a custom body and content type.
func sendPOSTWithBody(client *http.Client, url string, contentType string, body string) (*TimedResponse, error) {
	start := time.Now()
	resp, err := client.Post(url, contentType, strings.NewReader(body))
	elapsed := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return &TimedResponse{
			Response: resp,
			Elapsed:  elapsed,
		}, err
	}

	return &TimedResponse{
		Response: resp,
		Body:     respBody,
		BodyStr:  string(respBody),
		Elapsed:  elapsed,
	}, nil
}

// sendRequestWithHeaders performs a GET request with custom headers injected.
func sendRequestWithHeaders(client *http.Client, url string, headers map[string]string) (*TimedResponse, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &TimedResponse{
			Response: resp,
			Elapsed:  elapsed,
		}, err
	}

	return &TimedResponse{
		Response: resp,
		Body:     body,
		BodyStr:  string(body),
		Elapsed:  elapsed,
	}, nil
}

// ── Pattern Matching Helpers ────────────────────────────────

// containsAnyPattern checks if text matches any of the provided regex patterns.
// Returns the first matching pattern string, or "" if none match.
func containsAnyPattern(text string, patterns []*regexp.Regexp) string {
	for _, p := range patterns {
		if p.MatchString(text) {
			return p.String()
		}
	}
	return ""
}

// compilePatterns compiles a list of regex strings, skipping invalid ones.
func compilePatterns(raw []string) []*regexp.Regexp {
	var compiled []*regexp.Regexp
	for _, pattern := range raw {
		re, err := regexp.Compile(pattern)
		if err != nil {
			fmt.Printf("[!] Invalid regex in template: %s — %v\n", pattern, err)
			continue
		}
		compiled = append(compiled, re)
	}
	return compiled
}

// matchingPatterns returns every regex pattern that matched the text.
func matchingPatterns(text string, patterns []*regexp.Regexp) []string {
	var matches []string
	for _, p := range patterns {
		if p.MatchString(text) {
			matches = append(matches, p.String())
		}
	}
	return matches
}

// newPatternMatches returns only the patterns that appear in candidate but not in baseline.
func newPatternMatches(candidate string, baseline string, patterns []*regexp.Regexp) []string {
	if len(patterns) == 0 {
		return nil
	}

	baselineMatches := make(map[string]struct{})
	for _, match := range matchingPatterns(baseline, patterns) {
		baselineMatches[match] = struct{}{}
	}

	var newMatches []string
	for _, match := range matchingPatterns(candidate, patterns) {
		if _, seen := baselineMatches[match]; seen {
			continue
		}
		newMatches = append(newMatches, match)
	}
	return newMatches
}

// ── Template Variable Replacement ───────────────────────────

// generateRandomHex returns a random hex string of the given byte length.
func generateRandomHex(byteLen int) string {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// replaceTemplateVars substitutes template variables in a payload string.
// Community Edition keeps OOB placeholders inert but still normalizes them.
func replaceTemplateVars(payload string, target string) string {
	payload = strings.ReplaceAll(payload, "{{TARGET}}", target)
	payload = strings.ReplaceAll(payload, "{{RANDOM}}", generateRandomHex(8))
	payload = strings.ReplaceAll(payload, "{{OOB_URL}}", "http://127.0.0.1:9999/disabled")
	payload = strings.ReplaceAll(payload, "{{OOB_DOMAIN}}", "disabled.localhost")
	return payload
}

// ── Response Header Helpers ─────────────────────────────────

// headerContains checks if a response header contains a specific substring.
func headerContains(resp *http.Response, headerName string, substring string) bool {
	val := resp.Header.Get(headerName)
	return val != "" && strings.Contains(strings.ToLower(val), strings.ToLower(substring))
}

// headerEquals checks if a response header equals a specific value (case-insensitive).
func headerEquals(resp *http.Response, headerName string, expected string) bool {
	val := resp.Header.Get(headerName)
	return strings.EqualFold(val, expected)
}

// headerMissing checks if a response header is absent.
func headerMissing(resp *http.Response, headerName string) bool {
	return resp.Header.Get(headerName) == ""
}

func headerExpectationMatches(resp *http.Response, headerName string, expected string) bool {
	if resp == nil {
		return false
	}
	if expected == "MISSING" {
		return headerMissing(resp, headerName)
	}
	return headerContains(resp, headerName, expected)
}

func matchingExpectedHeaders(resp *http.Response, expected map[string]string) []string {
	if resp == nil {
		return nil
	}

	var evidence []string
	for headerName, headerValue := range expected {
		if !headerExpectationMatches(resp, headerName, headerValue) {
			return nil
		}
		actual := resp.Header.Get(headerName)
		if actual == "" {
			actual = "MISSING"
		}
		evidence = append(evidence, fmt.Sprintf("%s=%q", headerName, actual))
	}
	sort.Strings(evidence)
	return evidence
}

func expectedHeadersIntroduceNewSignal(baseline *http.Response, candidate *http.Response, expected map[string]string) bool {
	if candidate == nil {
		return false
	}
	if baseline == nil {
		return true
	}

	for headerName, headerValue := range expected {
		baseMatched := headerExpectationMatches(baseline, headerName, headerValue)
		candidateMatched := headerExpectationMatches(candidate, headerName, headerValue)
		if candidateMatched && !baseMatched {
			return true
		}

		if candidateMatched && baseline.Header.Get(headerName) != candidate.Header.Get(headerName) {
			return true
		}
	}
	return false
}

func responseMeaningfullyDiffers(baseline *TimedResponse, candidate *TimedResponse) bool {
	if baseline == nil || baseline.Response == nil {
		return candidate != nil && candidate.Response != nil
	}
	if candidate == nil || candidate.Response == nil {
		return false
	}

	if baseline.Response.StatusCode != candidate.Response.StatusCode {
		return true
	}

	if baseline.Response.Header.Get("Location") != candidate.Response.Header.Get("Location") {
		return true
	}

	if !strings.EqualFold(baseline.Response.Header.Get("Content-Type"), candidate.Response.Header.Get("Content-Type")) {
		return true
	}

	bodyDelta := len(baseline.Body) - len(candidate.Body)
	if bodyDelta < 0 {
		bodyDelta = -bodyDelta
	}

	return bodyDelta > 32
}

func medianDuration(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}

	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i] < ordered[j]
	})

	mid := len(ordered) / 2
	if len(ordered)%2 == 1 {
		return ordered[mid]
	}
	return (ordered[mid-1] + ordered[mid]) / 2
}

func measureMedianDuration(samples int, doRequest func() (*TimedResponse, error)) (time.Duration, error) {
	if samples < 1 {
		samples = 1
	}

	durations := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		resp, err := doRequest()
		if err != nil {
			return 0, err
		}
		durations = append(durations, resp.Elapsed)
	}

	return medianDuration(durations), nil
}
