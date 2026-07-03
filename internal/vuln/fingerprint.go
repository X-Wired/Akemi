package vuln

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	core "Akemi/internal/core"
)

// =============================================================
// ── APPLICATION FINGERPRINTING ENGINE ────────────────────────
// =============================================================
//
// FingerprintTarget performs passive analysis of the target application
// before any vulnerability probes are launched. It populates a
// TargetContext that downstream phases (template prioritization,
// WAF evasion, probe chaining) consume.
//
// All detection is strictly passive — a single baseline GET request
// followed by analysis of response headers, body, and URL structure.

// FingerprintTarget analyses the target URL and returns a populated
// TargetContext with detected technologies, framework, language,
// WAF presence, API exposure, authentication scheme, and parameter
// classification.
func FingerprintTarget(rawURL string, candidateParams []string, client *http.Client) (*core.TargetContext, error) {
	rawURL = core.EnsureProtocol(rawURL)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: error parsing URL: %w", err)
	}

	ctx := &core.TargetContext{
		URL: rawURL,
	}

	// Fetch baseline response
	resp, err := timedGET(client, rawURL)
	if err != nil {
		// Continue with partial fingerprinting even if request fails
		// (URL structure analysis can still work)
		resp = nil
	}

	// ── Step 1: Server header ────────────────────────────
	if resp != nil && resp.Response != nil {
		ctx.Server = resp.Response.Header.Get("Server")
	}

	// ── Step 2: Framework & language detection ───────────
	detectFramework(ctx, resp)
	detectLanguage(ctx)

	// ── Step 3: WAF / CDN detection ──────────────────────
	detectWAF(ctx, resp)

	// ── Step 4: API exposure detection ───────────────────
	ctx.APIExposure = detectAPIExposure(parsed, resp)

	// ── Step 5: Auth scheme detection ────────────────────
	detectAuthScheme(ctx, resp)

	// ── Step 6: Session cookie identification ────────────
	if resp != nil && resp.Response != nil {
		ctx.SessionCookies = detectSessionCookies(resp.Response)
	}

	// ── Step 7: CSRF token detection ─────────────────────
	ctx.CSRFParam = detectCSRF(resp)

	// ── Step 8: Tech stack aggregation ───────────────────
	buildTechStack(ctx)

	// ── Step 9: Parameter profiling ──────────────────────
	if len(candidateParams) > 0 || (parsed != nil && len(parsed.Query()) > 0) {
		params := mergeParamNames(parsed.Query(), candidateParams)
		ctx.ParameterProfile = profileParameters(params, parsed.Query())
	}

	return ctx, nil
}

// =============================================================
// ── FRAMEWORK DETECTION ─────────────────────────────────────
// =============================================================

// frameworkSignatures maps detectable signals to (framework, language, confidence).
type frameworkSignature struct {
	framework string
	language  string
	patterns  []frameworkPattern
}

type frameworkPattern struct {
	source string // "header", "cookie", "meta", "body", "path"
	key    string // header name, cookie prefix, meta name
	match  string // substring or regex to match
	isRe   bool   // if true, match is a regex
}

var frameworkSignatures = []frameworkSignature{
	{
		framework: "Django",
		language:  "python",
		patterns: []frameworkPattern{
			{source: "cookie", key: "", match: `(?i)csrftoken=`},
			{source: "cookie", key: "", match: `(?i)sessionid=`},
			{source: "header", key: "X-Frame-Options", match: "SAMEORIGIN"},
			{source: "meta", key: "generator", match: "Django"},
		},
	},
	{
		framework: "Rails",
		language:  "ruby",
		patterns: []frameworkPattern{
			{source: "cookie", key: "", match: `(?i)_session=`},
			{source: "header", key: "X-Request-Id", match: ""},
			{source: "header", key: "X-Runtime", match: ""},
			{source: "body", key: "", match: `(?i)<meta name="csrf-param"`},
		},
	},
	{
		framework: "Laravel",
		language:  "php",
		patterns: []frameworkPattern{
			{source: "cookie", key: "", match: `(?i)laravel_session=`},
			{source: "cookie", key: "", match: `(?i)XSRF-TOKEN=`},
			{source: "header", key: "X-Powered-By", match: "Laravel"},
			{source: "body", key: "", match: `(?i)<meta name="csrf-token"`},
		},
	},
	{
		framework: "Symfony",
		language:  "php",
		patterns: []frameworkPattern{
			{source: "cookie", key: "", match: `(?i)PHPSESSID=`},
			{source: "header", key: "X-Debug-Token-Link", match: ""},
			{source: "header", key: "X-Debug-Token", match: ""},
		},
	},
	{
		framework: "WordPress",
		language:  "php",
		patterns: []frameworkPattern{
			{source: "header", key: "X-Powered-By", match: "WordPress"},
			{source: "body", key: "", match: `(?i)wp-content`},
			{source: "body", key: "", match: `(?i)wp-includes`},
			{source: "meta", key: "generator", match: "WordPress"},
		},
	},
	{
		framework: "Spring Boot",
		language:  "java",
		patterns: []frameworkPattern{
			{source: "cookie", key: "", match: `(?i)JSESSIONID=`},
			{source: "header", key: "X-Application-Context", match: ""},
			{source: "body", key: "", match: `(?i)Whitelabel Error Page`},
			{source: "body", key: "", match: `(?i){"timestamp":`},
		},
	},
	{
		framework: "Express",
		language:  "javascript",
		patterns: []frameworkPattern{
			{source: "header", key: "X-Powered-By", match: "Express"},
			{source: "header", key: "x-powered-by", match: "Express"},
			{source: "cookie", key: "", match: `(?i)connect\.sid=`},
		},
	},
	{
		framework: "Next.js",
		language:  "javascript",
		patterns: []frameworkPattern{
			{source: "header", key: "x-powered-by", match: "Next.js"},
			{source: "body", key: "", match: `(?i)__NEXT_DATA__`},
			{source: "body", key: "", match: `(?i)<div id="__next">`},
		},
	},
	{
		framework: "ASP.NET",
		language:  "csharp",
		patterns: []frameworkPattern{
			{source: "header", key: "X-Powered-By", match: "ASP.NET"},
			{source: "header", key: "X-AspNet-Version", match: ""},
			{source: "header", key: "X-AspNetMvc-Version", match: ""},
			{source: "cookie", key: "", match: `(?i)\.AspNet\.`},
			{source: "cookie", key: "", match: `(?i)ASPsessionid`},
			{source: "body", key: "", match: `(?i)__VIEWSTATE`},
			{source: "body", key: "", match: `(?i)__RequestVerificationToken`},
		},
	},
	{
		framework: "Flask",
		language:  "python",
		patterns: []frameworkPattern{
			{source: "header", key: "Server", match: "Werkzeug"},
			{source: "cookie", key: "", match: `(?i)session=`},
		},
	},
	{
		framework: "Gin / Go",
		language:  "go",
		patterns: []frameworkPattern{
			{source: "header", key: "Server", match: "Gin"},
		},
	},
}

func detectFramework(ctx *core.TargetContext, resp *TimedResponse) {
	if resp == nil || resp.Response == nil {
		return
	}

	// Collect evidence from response
	headers := resp.Response.Header
	cookies := headers.Values("Set-Cookie")
	cookieStr := strings.Join(cookies, "; ")
	bodyStr := resp.BodyStr

	bestScore := 0
	for _, sig := range frameworkSignatures {
		score := 0
		for _, pat := range sig.patterns {
			switch pat.source {
			case "header":
				val := headers.Get(pat.key)
				if pat.key != "" && val != "" {
					if pat.match == "" {
						score++
					} else if strings.Contains(strings.ToLower(val), strings.ToLower(pat.match)) {
						score += 2
					}
				}
			case "cookie":
				if pat.isRe {
					re := regexp.MustCompile(pat.match)
					if re.MatchString(cookieStr) {
						score++
					}
				} else if strings.Contains(strings.ToLower(cookieStr), strings.ToLower(pat.match)) {
					score++
				}
			case "meta":
				re := regexp.MustCompile(fmt.Sprintf(`(?i)<meta[^>]+name=["']%s["'][^>]+content=["']([^"']*%s[^"']*)["']`,
					regexp.QuoteMeta(pat.key), regexp.QuoteMeta(pat.match)))
				if re.MatchString(bodyStr) {
					score++
				}
			case "body":
				if pat.isRe {
					re := regexp.MustCompile(pat.match)
					if re.MatchString(bodyStr) {
						score++
					}
				} else if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(pat.match)) {
					score++
				}
			}
		}
		if score > bestScore {
			bestScore = score
			ctx.Framework = sig.framework
			ctx.Language = sig.language
		}
	}

	// ── Language fallback from X-Powered-By ──────────────
	if ctx.Language == "" {
		xpb := strings.ToLower(headers.Get("X-Powered-By"))
		switch {
		case strings.Contains(xpb, "php"):
			ctx.Language = "php"
		case strings.Contains(xpb, "express"):
			ctx.Language = "javascript"
		case strings.Contains(xpb, "asp.net"):
			ctx.Language = "csharp"
		}
	}
}

func detectLanguage(ctx *core.TargetContext) {
	// Language may have been set by framework detection already
	if ctx.Language != "" {
		return
	}

	// Fallback: infer from Server header
	server := strings.ToLower(ctx.Server)
	switch {
	case strings.Contains(server, "php"):
		ctx.Language = "php"
	case strings.Contains(server, "python") || strings.Contains(server, "werkzeug") || strings.Contains(server, "gunicorn") || strings.Contains(server, "uvicorn"):
		ctx.Language = "python"
	case strings.Contains(server, "tomcat") || strings.Contains(server, "jetty") || strings.Contains(server, "jboss") || strings.Contains(server, "glassfish"):
		ctx.Language = "java"
	case strings.Contains(server, "iis") || strings.Contains(server, "microsoft"):
		ctx.Language = "csharp"
	case strings.Contains(server, "nginx") || strings.Contains(server, "apache") || strings.Contains(server, "caddy"):
		// Generic reverse proxies — can't determine language from server alone
	}
}

// =============================================================
// ── WAF / CDN DETECTION ─────────────────────────────────────
// =============================================================

type wafSignature struct {
	name       string
	confidence float64
	patterns   []wafPattern
}

type wafPattern struct {
	source string // "header_key", "header_value", "body", "cookie", "status"
	key    string
	match  string // substring
	isRe   bool
}

var wafSignatures = []wafSignature{
	{
		name: "Cloudflare", confidence: 0.95,
		patterns: []wafPattern{
			{source: "header_key", key: "cf-ray", match: ""},
			{source: "header_key", key: "cf-cache-status", match: ""},
			{source: "header_key", key: "cf-connecting-ip", match: ""},
			{source: "header_value", key: "Server", match: "cloudflare"},
			{source: "cookie", key: "", match: "__cfduid"},
			{source: "cookie", key: "", match: "cf_clearance"},
		},
	},
	{
		name: "AWS CloudFront", confidence: 0.90,
		patterns: []wafPattern{
			{source: "header_key", key: "x-amz-cf-id", match: ""},
			{source: "header_key", key: "x-amz-cf-pop", match: ""},
			{source: "header_value", key: "Server", match: "CloudFront"},
		},
	},
	{
		name: "AWS WAF", confidence: 0.70,
		patterns: []wafPattern{
			{source: "header_key", key: "x-amzn-waf-", match: ""}, // prefix match
			{source: "header_key", key: "x-amzn-requestid", match: ""},
		},
	},
	{
		name: "Akamai", confidence: 0.85,
		patterns: []wafPattern{
			{source: "header_key", key: "x-akamai-", match: ""}, // prefix match
			{source: "header_key", key: "x-akamai-transformed", match: ""},
			{source: "cookie", key: "", match: "ak_bmsc"},
		},
	},
	{
		name: "Imperva / Incapsula", confidence: 0.85,
		patterns: []wafPattern{
			{source: "header_key", key: "x-iinfo", match: ""},
			{source: "header_key", key: "x-cdn", match: "Incapsula"},
			{source: "cookie", key: "", match: "incap_ses_"},
			{source: "cookie", key: "", match: "visid_incap_"},
			{source: "body", key: "", match: "Incapsula incident", isRe: false},
		},
	},
	{
		name: "Sucuri", confidence: 0.85,
		patterns: []wafPattern{
			{source: "header_key", key: "x-sucuri-id", match: ""},
			{source: "header_key", key: "x-sucuri-cache", match: ""},
			{source: "header_value", key: "Server", match: "Sucuri"},
			{source: "body", key: "", match: "Sucuri WebSite Firewall", isRe: false},
		},
	},
	{
		name: "F5 BIG-IP", confidence: 0.80,
		patterns: []wafPattern{
			{source: "cookie", key: "", match: "BIGipServer"},
			{source: "cookie", key: "", match: "F5_ST"},
			{source: "cookie", key: "", match: "TS[0-9a-f]{6}"},
			{source: "header_value", key: "Server", match: "BIG-IP"},
		},
	},
	{
		name: "ModSecurity", confidence: 0.60,
		patterns: []wafPattern{
			{source: "header_value", key: "Server", match: "Mod_Security"},
			{source: "body", key: "", match: "This error was generated by Mod_Security", isRe: false},
			{source: "body", key: "", match: "ModSecurity", isRe: false},
		},
	},
	{
		name: "Fastly", confidence: 0.85,
		patterns: []wafPattern{
			{source: "header_key", key: "x-served-by", match: ""},
			{source: "header_key", key: "x-cache", match: ""},
			{source: "header_key", key: "x-cache-hits", match: ""},
			{source: "header_key", key: "x-timer", match: ""},
			{source: "header_value", key: "Server", match: "Fastly"},
			{source: "header_key", key: "fastly-", match: ""},
		},
	},
	{
		name: "Barracuda", confidence: 0.75,
		patterns: []wafPattern{
			{source: "cookie", key: "", match: "barra_counter_session"},
			{source: "cookie", key: "", match: "BNI__BARRACUDA"},
		},
	},
	{
		name: "Fortinet FortiWeb", confidence: 0.75,
		patterns: []wafPattern{
			{source: "cookie", key: "", match: "FORTIWAFSID"},
			{source: "header_key", key: "x-fortiweb-", match: ""},
		},
	},
	{
		name: "Citrix NetScaler", confidence: 0.80,
		patterns: []wafPattern{
			{source: "cookie", key: "", match: "NSC_"},
			{source: "cookie", key: "", match: "ns_gw"},
			{source: "header_key", key: "x-ns-", match: ""},
		},
	},
}

func detectWAF(ctx *core.TargetContext, resp *TimedResponse) {
	if resp == nil || resp.Response == nil {
		return
	}

	headers := resp.Response.Header
	cookies := strings.Join(headers.Values("Set-Cookie"), "; ")
	bodyStr := resp.BodyStr

	bestConfidence := 0.0
	bestName := ""

	for _, sig := range wafSignatures {
		hits := 0
		total := len(sig.patterns)

		for _, pat := range sig.patterns {
			switch pat.source {
			case "header_key":
				// Check if any header key matches (prefix or exact)
				for key := range headers {
					if pat.match == "" && strings.EqualFold(key, pat.key) {
						hits++
						break
					}
					if pat.match != "" && strings.HasPrefix(strings.ToLower(key), strings.ToLower(pat.key)) {
						hits++
						break
					}
				}
			case "header_value":
				val := strings.ToLower(headers.Get(pat.key))
				if val != "" && strings.Contains(val, strings.ToLower(pat.match)) {
					hits++
				}
			case "cookie":
				if pat.isRe {
					re := regexp.MustCompile(pat.match)
					if re.MatchString(cookies) {
						hits++
					}
				} else if strings.Contains(strings.ToLower(cookies), strings.ToLower(pat.match)) {
					hits++
				}
			case "body":
				if pat.isRe {
					re := regexp.MustCompile(pat.match)
					if re.MatchString(bodyStr) {
						hits++
					}
				} else if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(pat.match)) {
					hits++
				}
			}
		}

		if hits > 0 {
			confidence := sig.confidence * (float64(hits) / float64(total))
			if confidence > 1.0 {
				confidence = 1.0
			}
			if confidence > bestConfidence {
				bestConfidence = confidence
				bestName = sig.name
			}
		}
	}

	if bestName != "" {
		ctx.WAF = bestName
		ctx.WAFConfidence = bestConfidence
	}
}

// =============================================================
// ── API EXPOSURE DETECTION ───────────────────────────────────
// =============================================================

func detectAPIExposure(parsed *url.URL, resp *TimedResponse) string {
	if parsed == nil {
		return ""
	}

	path := parsed.Path

	// URL path patterns
	switch {
	case strings.Contains(path, "/graphql"):
		return "graphql"
	case strings.Contains(path, "/api/") || strings.Contains(path, "/v1/") ||
		strings.Contains(path, "/v2/") || strings.Contains(path, "/rest/"):
		return "rest"
	case strings.Contains(path, "/soap/") || strings.HasSuffix(path, ".wsdl") ||
		strings.Contains(path, "/services/"):
		return "soap"
	case strings.Contains(path, "/.well-known/"):
		return "oidc"
	}

	// Response body hints — GraphQL introspection
	if resp != nil && resp.BodyStr != "" {
		body := resp.BodyStr
		if strings.Contains(body, `"__schema"`) || strings.Contains(body, `graphql`) {
			return "graphql"
		}
		if strings.Contains(body, `<wsdl:`) || strings.Contains(body, `<soap:`) {
			return "soap"
		}
		if strings.Contains(body, `"swagger"`) || strings.Contains(body, `openapi`) ||
			strings.Contains(body, `"paths"`) && strings.Contains(body, `"responses"`) {
			return "rest"
		}
	}

	return ""
}

// =============================================================
// ── AUTH SCHEME DETECTION ────────────────────────────────────
// =============================================================

func detectAuthScheme(ctx *core.TargetContext, resp *TimedResponse) {
	if resp == nil || resp.Response == nil {
		return
	}

	headers := resp.Response.Header
	cookies := headers.Values("Set-Cookie")

	// Check for JWT in Authorization or cookies
	for _, c := range cookies {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(c)), "jwt=") {
			ctx.AuthScheme = "jwt"
			return
		}
	}

	// Session cookie detection
	for _, c := range cookies {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "session") || strings.Contains(lower, "sess") ||
			strings.Contains(lower, "sid=") || strings.Contains(lower, "auth=") {
			ctx.AuthScheme = "session"
			return
		}
	}

	// Check for OAuth2 endpoints in body
	if resp.BodyStr != "" {
		body := strings.ToLower(resp.BodyStr)
		if strings.Contains(body, "authorize") && strings.Contains(body, "client_id") {
			ctx.AuthScheme = "oauth2"
			return
		}
		if strings.Contains(body, "/login") || strings.Contains(body, "username") && strings.Contains(body, "password") {
			ctx.AuthScheme = "session" // has login form
			return
		}
	}

	// Check WWW-Authenticate header
	if auth := headers.Get("WWW-Authenticate"); auth != "" {
		lower := strings.ToLower(auth)
		switch {
		case strings.HasPrefix(lower, "basic"):
			ctx.AuthScheme = "basic"
		case strings.HasPrefix(lower, "bearer"):
			ctx.AuthScheme = "jwt"
		case strings.HasPrefix(lower, "digest"):
			ctx.AuthScheme = "basic"
		}
	}
}

// =============================================================
// ── SESSION COOKIE DETECTION ─────────────────────────────────
// =============================================================

// sessionCookiePatterns matches cookie names that are likely session tokens.
var sessionCookiePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^session`),
	regexp.MustCompile(`(?i)^sess`),
	regexp.MustCompile(`(?i)^sid$`),
	regexp.MustCompile(`(?i)^auth`),
	regexp.MustCompile(`(?i)^token`),
	regexp.MustCompile(`(?i)^jwt`),
	regexp.MustCompile(`(?i)^remember`),
	regexp.MustCompile(`(?i)^connect\.sid$`),
	regexp.MustCompile(`(?i)^JSESSIONID$`),
	regexp.MustCompile(`(?i)^PHPSESSID$`),
	regexp.MustCompile(`(?i)^laravel_session$`),
	regexp.MustCompile(`(?i)^\.AspNet\.`),
	regexp.MustCompile(`(?i)^ASPsessionid`),
}

func detectSessionCookies(resp *http.Response) []string {
	var sessions []string
	seen := map[string]bool{}

	for _, raw := range resp.Header.Values("Set-Cookie") {
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if name == "" || seen[name] {
			continue
		}

		for _, pat := range sessionCookiePatterns {
			if pat.MatchString(name) {
				sessions = append(sessions, name)
				seen[name] = true
				break
			}
		}
	}
	return sessions
}

// =============================================================
// ── CSRF TOKEN DETECTION ─────────────────────────────────────
// =============================================================

// csrfParamPatterns identifies HTML form/meta elements that hold CSRF tokens.
var csrfMetaPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<meta[^>]+name=["']csrf[^"']*["'][^>]+content=["']([^"']+)["']`),
	regexp.MustCompile(`(?i)<input[^>]+name=["']csrf[^"']*["'][^>]+value=["']([^"']+)["']`),
	regexp.MustCompile(`(?i)<input[^>]+name=["']_token["'][^>]+value=["']([^"']+)["']`),
	regexp.MustCompile(`(?i)<input[^>]+name=["']__RequestVerificationToken["']`),
	regexp.MustCompile(`(?i)csrf_token\s*[=:]\s*["']([^"']+)["']`),
}

func detectCSRF(resp *TimedResponse) string {
	if resp == nil || resp.BodyStr == "" {
		return ""
	}

	for _, re := range csrfMetaPatterns {
		if matches := re.FindStringSubmatch(resp.BodyStr); len(matches) > 0 {
			return strings.TrimSpace(matches[0])
		}
	}
	return ""
}

// =============================================================
// ── TECH STACK AGGREGATION ───────────────────────────────────
// =============================================================

func buildTechStack(ctx *core.TargetContext) {
	seen := map[string]bool{}
	add := func(val string) {
		val = strings.TrimSpace(val)
		if val == "" || seen[val] {
			return
		}
		seen[val] = true
		ctx.TechStack = append(ctx.TechStack, val)
	}

	if ctx.Framework != "" {
		add(ctx.Framework)
	}
	if ctx.Language != "" {
		add(ctx.Language)
	}
	if ctx.Server != "" {
		add(ctx.Server)
	}
	if ctx.WAF != "" {
		add("WAF:" + ctx.WAF)
	}
	if ctx.APIExposure != "" {
		add("API:" + ctx.APIExposure)
	}
	if ctx.AuthScheme != "" {
		add("Auth:" + ctx.AuthScheme)
	}
	if ctx.CSRFParam != "" {
		add("CSRF:enabled")
	}
}

// =============================================================
// ── PARAMETER PROFILING ──────────────────────────────────────
// =============================================================

type paramClassRule struct {
	category      string
	namePatterns  []string // substring matches against param name
	valuePatterns []string // substring matches against param value
	priorityTags  []string // e.g. ["sqli", "nosqli", "idor"]
}

var paramClassificationRules = []paramClassRule{
	{
		category:      "numeric_id",
		namePatterns:  []string{"id", "uid", "pid", "item", "page_id", "ref", "product", "user_id", "account", "order"},
		valuePatterns: []string{}, // value is numeric (checked in code)
		priorityTags:  []string{"sqli", "nosqli", "idor", "xpath"},
	},
	{
		category:      "callback",
		namePatterns:  []string{"callback", "webhook", "notify_url", "notify", "hook", "ping", "event"},
		valuePatterns: []string{},
		priorityTags:  []string{"ssrf"},
	},
	{
		category:      "redirect_url",
		namePatterns:  []string{"redirect", "url", "next", "return", "goto", "target", "continue", "dest", "uri", "link", "path", "forward"},
		valuePatterns: []string{"http", "://", "%2F%2F"},
		priorityTags:  []string{"ssrf", "open_redirect", "lfi"},
	},
	{
		category:      "search_query",
		namePatterns:  []string{"q", "query", "search", "keyword", "keywords", "filter", "term", "text", "find", "lookup"},
		valuePatterns: []string{},
		priorityTags:  []string{"xss", "ssti", "sqli", "cmdi"},
	},
	{
		category:      "file_path",
		namePatterns:  []string{"file", "path", "dir", "folder", "template", "include", "page", "view", "doc", "document"},
		valuePatterns: []string{".", "/", "\\", ".."},
		priorityTags:  []string{"lfi", "rfi", "path_traversal"},
	},
	{
		category:      "email_user",
		namePatterns:  []string{"email", "user", "username", "login", "name", "mail"},
		valuePatterns: []string{"@"},
		priorityTags:  []string{"sqli", "nosqli", "ldap", "xss"},
	},
	{
		category:      "token_hash",
		namePatterns:  []string{"token", "csrf", "nonce", "hash", "signature", "state", "code", "key", "secret", "apikey", "api_key"},
		valuePatterns: []string{},
		priorityTags:  []string{"jwt", "idor"},
	},
	{
		category:      "format_export",
		namePatterns:  []string{"format", "export", "type", "output", "view", "mode", "content_type"},
		valuePatterns: []string{"csv", "pdf", "xml", "json", "excel", "xls"},
		priorityTags:  []string{"xxe", "csv_injection"},
	},
	{
		category:      "sort_order",
		namePatterns:  []string{"sort", "order", "dir", "direction", "sort_by", "order_by", "by", "column", "field"},
		valuePatterns: []string{"asc", "desc", "ASC", "DESC"},
		priorityTags:  []string{"sqli"},
	},
	{
		category:      "debug_admin",
		namePatterns:  []string{"debug", "admin", "test", "dev", "preview", "draft"},
		valuePatterns: []string{"true", "1", "on", "yes"},
		priorityTags:  []string{"auth_bypass"},
	},
	{
		category:      "language_locale",
		namePatterns:  []string{"lang", "language", "locale", "l10n", "i18n", "country", "region"},
		valuePatterns: []string{},
		priorityTags:  []string{"lfi", "ssti"},
	},
}

func profileParameters(paramNames []string, existing url.Values) *core.ParameterProfile {
	if len(paramNames) == 0 {
		return nil
	}

	profile := &core.ParameterProfile{
		Parameters: make([]core.ParameterClass, 0, len(paramNames)),
	}

	for _, name := range paramNames {
		values, ok := existing[name]
		sampleValue := ""
		if ok && len(values) > 0 {
			sampleValue = values[0]
		}

		pc := classifyParameter(name, sampleValue)
		profile.Parameters = append(profile.Parameters, pc)
	}

	return profile
}

func classifyParameter(name string, value string) core.ParameterClass {
	nameLower := strings.ToLower(strings.TrimSpace(name))
	valueLower := strings.ToLower(strings.TrimSpace(value))

	for _, rule := range paramClassificationRules {
		nameMatch := false
		for _, pat := range rule.namePatterns {
			if strings.Contains(nameLower, pat) {
				nameMatch = true
				break
			}
		}
		if !nameMatch {
			continue
		}

		// If value patterns are specified and a value is present,
		// at least one must match. When value is empty (e.g. candidate
		// params discovered by the recon phase), skip value enforcement.
		if len(rule.valuePatterns) > 0 && valueLower != "" {
			valueMatch := false
			for _, pat := range rule.valuePatterns {
				if strings.Contains(valueLower, pat) {
					valueMatch = true
					break
				}
			}
			if !valueMatch {
				continue
			}
		}

		// Special case: numeric_id category requires the value to be numeric
		if rule.category == "numeric_id" {
			if value == "" || isNumeric(value) {
				return core.ParameterClass{
					Name:         name,
					Category:     rule.category,
					SampleValue:  value,
					PriorityTags: rule.priorityTags,
				}
			}
			continue
		}

		return core.ParameterClass{
			Name:         name,
			Category:     rule.category,
			SampleValue:  value,
			PriorityTags: rule.priorityTags,
		}
	}

	// No specific classification — generic
	return core.ParameterClass{
		Name:     name,
		Category: "generic",
	}
}

func isNumeric(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// ── Fingerprinting helpers ──────────────────────────────────

// FingerprintSummary returns a human-readable summary of the target context.
func FingerprintSummary(ctx *core.TargetContext) string {
	if ctx == nil {
		return "  No fingerprint data available."
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("  URL:          %s\n", ctx.URL))

	if ctx.Framework != "" {
		b.WriteString(fmt.Sprintf("  Framework:    %s\n", ctx.Framework))
	}
	if ctx.Language != "" {
		b.WriteString(fmt.Sprintf("  Language:     %s\n", ctx.Language))
	}
	if ctx.Server != "" {
		b.WriteString(fmt.Sprintf("  Server:       %s\n", ctx.Server))
	}
	if ctx.WAF != "" {
		b.WriteString(fmt.Sprintf("  WAF:          %s (confidence: %.0f%%)\n", ctx.WAF, ctx.WAFConfidence*100))
	}
	if ctx.APIExposure != "" {
		b.WriteString(fmt.Sprintf("  API Type:     %s\n", ctx.APIExposure))
	}
	if ctx.AuthScheme != "" {
		b.WriteString(fmt.Sprintf("  Auth Scheme:  %s\n", ctx.AuthScheme))
	}
	if len(ctx.SessionCookies) > 0 {
		b.WriteString(fmt.Sprintf("  Sessions:     %s\n", strings.Join(ctx.SessionCookies, ", ")))
	}
	if ctx.CSRFParam != "" {
		b.WriteString("  CSRF:         token detected in page\n")
	}
	if len(ctx.TechStack) > 0 {
		b.WriteString(fmt.Sprintf("  Tech Stack:   [%s]\n", strings.Join(ctx.TechStack, ", ")))
	}
	if ctx.ParameterProfile != nil && len(ctx.ParameterProfile.Parameters) > 0 {
		b.WriteString("  Parameters:\n")
		for _, p := range ctx.ParameterProfile.Parameters {
			tags := ""
			if len(p.PriorityTags) > 0 {
				tags = fmt.Sprintf(" → priority probes: %s", strings.Join(p.PriorityTags, ", "))
			}
			b.WriteString(fmt.Sprintf("    %-20s %-14s%s\n", p.Name, "["+p.Category+"]", tags))
		}
	}

	return b.String()
}

// PrintFingerprintSummary outputs the fingerprinting results to stdout
// in a formatted block suitable for CLI output.
func PrintFingerprintSummary(ctx *core.TargetContext) {
	if ctx == nil {
		return
	}
	fmt.Println()
	fmt.Println("[*] ── Target Fingerprint ──")
	fmt.Print(FingerprintSummary(ctx))
	fmt.Println(strings.Repeat("-", 55))
}
