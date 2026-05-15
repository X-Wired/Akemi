package dothound

import "time"

// ── JSON protocol types (mirrors DotHound's stdin.rs) ──────────────

// StdinCommand is the command sent to DotHound via stdin.
type StdinCommand struct {
	Command   string       `json:"command"`
	TargetURL string       `json:"target_url,omitempty"`
	Username  string       `json:"username,omitempty"`
	Password  string       `json:"password,omitempty"`
	Options   StdinOptions `json:"options,omitempty"`
}

// StdinOptions configures the capture behavior.
type StdinOptions struct {
	IncludeSecrets      bool `json:"include_secrets"`
	MaxBodyCaptureBytes int  `json:"max_body_capture_bytes"`
}

// StdinResponse is the response received from DotHound via stdout.
type StdinResponse struct {
	Status       string        `json:"status"`
	WorkflowPath string        `json:"workflow_path,omitempty"`
	HTMLPath     string        `json:"html_path,omitempty"`
	ProxyURL     string        `json:"proxy_url,omitempty"`
	CACertPEM    string        `json:"ca_cert_pem,omitempty"`
	Summary      *StdinSummary `json:"summary,omitempty"`
	Error        string        `json:"error,omitempty"`
}

// StdinSummary contains the captured workflow summary.
type StdinSummary struct {
	TotalExchanges int      `json:"total_exchanges"`
	HTTPExchanges  int      `json:"http_exchanges"`
	HTTPSTunnels   int      `json:"https_tunnels"`
	SessionCookies []string `json:"session_cookies"`
	CSRFTokens     []string `json:"csrf_tokens"`
	AuthSuccess    bool     `json:"auth_success"`
	RedirectChain  []string `json:"redirect_chain"`
}

// ── Workflow graph types (for loading capture JSON) ────────────────

// WorkflowGraph represents a DotHound capture JSON file.
type WorkflowGraph struct {
	Schema      string             `json:"schema"`
	GeneratedBy string             `json:"generated_by"`
	StartedAt   int64              `json:"started_at_unix_ms"`
	CompletedAt int64              `json:"completed_at_unix_ms"`
	StartURL    string             `json:"start_url"`
	Redaction   RedactionPolicy    `json:"redaction"`
	Summary     WorkflowSummary    `json:"summary"`
	Nodes       []WorkflowNode     `json:"nodes"`
	Edges       []WorkflowEdge     `json:"edges"`
	Exchanges   []CapturedExchange `json:"exchanges"`
}

// RedactionPolicy describes the redaction mode.
type RedactionPolicy struct {
	Mode                    string `json:"mode"`
	SensitiveValuesIncluded bool   `json:"sensitive_values_included"`
}

// WorkflowSummary holds aggregate counts.
type WorkflowSummary struct {
	TotalExchanges int `json:"total_exchanges"`
	HTTPExchanges  int `json:"http_exchanges"`
	HTTPSTunnels   int `json:"https_tunnels"`
}

// WorkflowNode is a step in the workflow graph.
type WorkflowNode struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	ExchangeID string `json:"exchange_id"`
}

// WorkflowEdge connects two nodes.
type WorkflowEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// CapturedExchange is a single HTTP exchange.
type CapturedExchange struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	StartedAt  int64             `json:"started_at_unix_ms"`
	FinishedAt int64             `json:"finished_at_unix_ms"`
	ClientAddr string            `json:"client_addr"`
	Request    CapturedRequest   `json:"request"`
	Response   *CapturedResponse `json:"response,omitempty"`
	Notes      []string          `json:"notes"`
}

// CapturedRequest holds the HTTP request details.
type CapturedRequest struct {
	Method  string           `json:"method"`
	Target  string           `json:"target"`
	Version string           `json:"version"`
	Headers []CapturedHeader `json:"headers"`
	Body    *CapturedBody    `json:"body,omitempty"`
}

// CapturedResponse holds the HTTP response details.
type CapturedResponse struct {
	StatusCode int              `json:"status_code"`
	Reason     string           `json:"reason"`
	Version    string           `json:"version"`
	Headers    []CapturedHeader `json:"headers"`
	Body       *CapturedBody    `json:"body,omitempty"`
}

// CapturedHeader is a single HTTP header with redaction metadata.
type CapturedHeader struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Sensitive   bool   `json:"sensitive"`
	ValueSHA256 string `json:"value_sha256,omitempty"`
}

// CapturedBody holds the HTTP body with capture metadata.
type CapturedBody struct {
	ContentType   string `json:"content_type,omitempty"`
	BytesSeen     int    `json:"bytes_seen"`
	BytesCaptured int    `json:"bytes_captured"`
	Truncated     bool   `json:"truncated"`
	Text          string `json:"text,omitempty"`
	Sensitive     bool   `json:"sensitive"`
}

// ── AuthSession extracted from a DotHound capture ──────────────────

// AuthSession holds cookies and tokens extracted from a login workflow.
type AuthSession struct {
	TargetURL      string    `json:"target_url"`
	AuthSuccess    bool      `json:"auth_success"`
	Cookies        []string  `json:"cookies"`
	CSRFTokens     []string  `json:"csrf_tokens"`
	RedirectChain  []string  `json:"redirect_chain"`
	CapturedAt     time.Time `json:"captured_at"`
	WorkflowPath   string    `json:"workflow_path"`
	HTMLReportPath string    `json:"html_report_path"`
}
