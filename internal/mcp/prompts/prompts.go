package prompts

import (
	"fmt"
	"strings"

	"Akemi/internal/mcp"
)

// PromptProvider manages MCP prompt templates — pre-built conversation
// starters that guide LLMs through security testing workflows.
type PromptProvider struct {
	prompts map[string]*RegisteredPrompt
}

// RegisteredPrompt pairs MCP metadata with a render function.
type RegisteredPrompt struct {
	Prompt mcp.Prompt
	Render func(args map[string]string) (*mcp.PromptGetResult, error)
}

// NewPromptProvider creates a prompt provider with standard templates.
func NewPromptProvider() *PromptProvider {
	pp := &PromptProvider{
		prompts: make(map[string]*RegisteredPrompt),
	}
	pp.registerAll()
	return pp
}

// List returns all available prompts.
func (pp *PromptProvider) List() []mcp.Prompt {
	prompts := make([]mcp.Prompt, 0, len(pp.prompts))
	for _, rp := range pp.prompts {
		prompts = append(prompts, rp.Prompt)
	}
	return prompts
}

// Get renders a prompt template with the given arguments.
func (pp *PromptProvider) Get(name string, args map[string]string) (*mcp.PromptGetResult, error) {
	rp, ok := pp.prompts[name]
	if !ok {
		return nil, fmt.Errorf("prompt not found: %s", name)
	}

	return rp.Render(args)
}

func (pp *PromptProvider) registerAll() {
	// ── Attack Surface Mapping ───────────────────────────
	pp.register(RegisteredPrompt{
		Prompt: mcp.Prompt{
			Name:        "attack_surface_mapping",
			Description: "Guide for performing complete attack surface mapping of a target. Covers subdomain enumeration, port scanning, web crawling, JS analysis, and API discovery.",
			Arguments: []mcp.PromptArgument{
				{Name: "target", Description: "Target domain or IP", Required: true},
			},
		},
		Render: func(args map[string]string) (*mcp.PromptGetResult, error) {
			target := args["target"]
			return &mcp.PromptGetResult{
				Description: fmt.Sprintf("Complete attack surface mapping workflow for %s", target),
				Messages: []mcp.PromptMessage{
					{
						Role: "user",
						Content: mcp.ContentBlock{
							Type: "text",
							Text: fmt.Sprintf(`You are performing a comprehensive attack surface mapping of %s. Follow this methodology:

## Step 1: Full Surface Mapping
Use akemi_full_surface_map or its akemi_full_surface_scan alias to run the dedicated dashboard workflow. It performs managed crawling, port scanning, header/tech checks, parameter mining, JavaScript analysis, API discovery, and subdomain enumeration in one tool call.

## Step 2: Vulnerability Assessment
Use akemi_list_templates to see what vulnerability classes can be tested.
Use akemi_probe_vulns with appropriate tags based on the discovered technology stack.
Use akemi_check_headers for security header and CORS audits.

## Step 3: Reporting
Use akemi_write_report for narrative report drafts, and akemi_generate_report / akemi_generate_graph for generated artifacts.

Important: Only test targets you are authorized to test. Document all findings systematically.`, target),
						},
					},
				},
			}, nil
		},
	})

	// ── SQL Injection Hunting ───────────────────────────
	pp.register(RegisteredPrompt{
		Prompt: mcp.Prompt{
			Name:        "sqli_hunting",
			Description: "Focused SQL injection discovery workflow: crawl, mine parameters, and probe with SQLi-specific templates.",
			Arguments: []mcp.PromptArgument{
				{Name: "target", Description: "Target URL with parameters (e.g., https://target.com/page?id=1)", Required: true},
			},
		},
		Render: func(args map[string]string) (*mcp.PromptGetResult, error) {
			target := args["target"]
			return &mcp.PromptGetResult{
				Description: fmt.Sprintf("SQL injection hunting on %s", target),
				Messages: []mcp.PromptMessage{
					{
						Role: "user",
						Content: mcp.ContentBlock{
							Type: "text",
							Text: fmt.Sprintf(`Hunt for SQL injection vulnerabilities on %s:

1. Use akemi_crawl on the target with a managed depth to discover additional URLs with parameters.
2. Use akemi_mine_params to identify all injectable parameters.
3. Use akemi_tech_fingerprint to identify the backend database technology.
4. Use akemi_probe_vulns with tags="sqli" to test all SQLi templates.
5. For each finding, analyze the evidence to determine if it's a true positive.
6. Use akemi_exploit_lookup to find known exploits for the detected database version.

Remember: SQL injection testing can be destructive. Test on authorized targets only.`, target),
						},
					},
				},
			}, nil
		},
	})

	// ── Vulnerability Assessment Report ──────────────────
	pp.register(RegisteredPrompt{
		Prompt: mcp.Prompt{
			Name:        "vulnerability_report",
			Description: "Generate a professional vulnerability assessment report from scan findings. Summarizes discoveries by severity with remediation recommendations.",
			Arguments: []mcp.PromptArgument{
				{Name: "target", Description: "Target name", Required: true},
			},
		},
		Render: func(args map[string]string) (*mcp.PromptGetResult, error) {
			target := args["target"]
			return &mcp.PromptGetResult{
				Description: fmt.Sprintf("Vulnerability assessment report for %s", target),
				Messages: []mcp.PromptMessage{
					{
						Role: "user",
						Content: mcp.ContentBlock{
							Type: "text",
							Text: fmt.Sprintf(`Generate a professional vulnerability assessment report for %s. Use the following tools to gather data:

1. Use akemi_generate_report to get the summary statistics.
2. Review the findings and present them in this structure:

## Executive Summary
- Brief overview of the engagement
- Total findings by severity
- Key risk areas identified

## Methodology
- Tools and techniques used
- Scope of the assessment

## Detailed Findings
For each finding, provide:
- Title and severity
- Affected endpoint/parameter
- Evidence (request/response snippets)
- Impact assessment
- Remediation steps

## Recommendations
- Prioritized list of fixes
- Long-term security improvements

Use clear, professional language suitable for both technical and non-technical stakeholders.`, target),
						},
					},
				},
			}, nil
		},
	})

	// ── Quick Recon ─────────────────────────────────────
	pp.register(RegisteredPrompt{
		Prompt: mcp.Prompt{
			Name:        "quick_recon",
			Description: "Fast initial reconnaissance: port scan top ports, crawl main page, check headers. Get a rapid overview of the target's security posture.",
			Arguments: []mcp.PromptArgument{
				{Name: "target", Description: "Target URL or IP", Required: true},
			},
		},
		Render: func(args map[string]string) (*mcp.PromptGetResult, error) {
			target := args["target"]
			return &mcp.PromptGetResult{
				Description: fmt.Sprintf("Quick reconnaissance of %s", target),
				Messages: []mcp.PromptMessage{
					{
						Role: "user",
						Content: mcp.ContentBlock{
							Type: "text",
							Text: fmt.Sprintf(`Perform a rapid initial reconnaissance of %s:

1. Use akemi_port_scan with default settings to identify open ports and services.
2. Use akemi_crawl with depth=2 to discover the main pages (capped at 2000 URLs).
3. Use akemi_check_headers to audit security headers.
4. Use akemi_tech_fingerprint to identify the technology stack.
5. Summarize the key findings and suggest the most promising areas for deeper investigation.

Focus on speed — this is a triage, not a full assessment. Highlight anything that warrants immediate attention.`, target),
						},
					},
				},
			}, nil
		},
	})

	// ── API Security Review ─────────────────────────────
	pp.register(RegisteredPrompt{
		Prompt: mcp.Prompt{
			Name:        "api_security_review",
			Description: "API-focused security assessment: discover API endpoints, check for common API vulnerabilities, and review API specifications for security gaps.",
			Arguments: []mcp.PromptArgument{
				{Name: "target", Description: "Target URL (API base URL)", Required: true},
			},
		},
		Render: func(args map[string]string) (*mcp.PromptGetResult, error) {
			target := args["target"]
			return &mcp.PromptGetResult{
				Description: fmt.Sprintf("API security review of %s", target),
				Messages: []mcp.PromptMessage{
					{
						Role: "user",
						Content: mcp.ContentBlock{
							Type: "text",
							Text: fmt.Sprintf(`Perform an API-focused security review of %s:

1. Use akemi_discover_api to find all API endpoints and specifications.
2. For any OpenAPI/Swagger specs found, review for:
   - Missing authentication on sensitive endpoints
   - Excessive data exposure in responses
   - Lack of rate limiting indicators
   - Deprecated endpoints still accessible
3. Use akemi_crawl on the API base to discover undocumented endpoints.
4. Use akemi_probe_vulns with tags="injection,auth,jwt" to test for common API vulnerabilities.
5. Check for GraphQL endpoints and test for introspection leaks.

Focus on authorization flaws, injection points, and information disclosure in API responses.`, target),
						},
					},
				},
			}, nil
		},
	})

	// ── Authentication Workflow Analysis ─────────────────
	pp.register(RegisteredPrompt{
		Prompt: mcp.Prompt{
			Name:        "auth_workflow_analysis",
			Description: "Analyze authentication flows: capture login, test session management, check for JWT weaknesses, and identify authorization bypass opportunities.",
			Arguments: []mcp.PromptArgument{
				{Name: "target", Description: "Login page URL", Required: true},
			},
		},
		Render: func(args map[string]string) (*mcp.PromptGetResult, error) {
			target := args["target"]
			return &mcp.PromptGetResult{
				Description: fmt.Sprintf("Authentication workflow analysis for %s", target),
				Messages: []mcp.PromptMessage{
					{
						Role: "user",
						Content: mcp.ContentBlock{
							Type: "text",
							Text: fmt.Sprintf(`Analyze the authentication workflow of %s:

1. Use akemi_auth_capture to record the full login workflow (requires credentials).
2. Analyze the captured workflow for:
   - Session cookie flags (HttpOnly, Secure, SameSite)
   - CSRF token presence and rotation
   - Password transmission security
   - Redirect validation (open redirect after login?)
3. Use akemi_probe_vulns with tags="auth,jwt,idor" to test for specific auth vulnerabilities.
4. Check for:
   - Session fixation
   - Missing account lockout
   - User enumeration via error messages
   - JWT algorithm confusion if JWTs are used

Document the entire auth flow and flag any weaknesses found.`, target),
						},
					},
				},
			}, nil
		},
	})
}

func (pp *PromptProvider) register(rp RegisteredPrompt) {
	pp.prompts[rp.Prompt.Name] = &rp
}

// CollectPromptNames returns a comma-separated list for logging.
func (pp *PromptProvider) CollectPromptNames() string {
	names := make([]string, 0, len(pp.prompts))
	for _, rp := range pp.prompts {
		names = append(names, rp.Prompt.Name)
	}
	return strings.Join(names, ", ")
}
