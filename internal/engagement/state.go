package engagement

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TargetProfile is the active operator-defined target context used by MCP tools.
type TargetProfile struct {
	ID      string   `json:"id,omitempty"`
	Name    string   `json:"name,omitempty"`
	BaseURL string   `json:"base_url,omitempty"`
	Domain  string   `json:"domain,omitempty"`
	Hosts   []string `json:"hosts,omitempty"`
	CIDRs   []string `json:"cidrs,omitempty"`
	Notes   string   `json:"notes,omitempty"`
}

// ScanDefaults stores optional defaults applied when MCP tool args are omitted.
type ScanDefaults struct {
	Ports       string   `json:"ports,omitempty"`
	Threads     int      `json:"threads,omitempty"`
	Timeout     int      `json:"timeout,omitempty"`
	Depth       int      `json:"depth,omitempty"`
	VulnTags    []string `json:"vuln_tags,omitempty"`
	TemplateID  string   `json:"template_id,omitempty"`
	MineJS      *bool    `json:"mine_js,omitempty"`
	MineForms   *bool    `json:"mine_forms,omitempty"`
	MineJSON    *bool    `json:"mine_json,omitempty"`
	MinePath    *bool    `json:"mine_path,omitempty"`
	ActiveBrute *bool    `json:"active_brute,omitempty"`
}

// ParameterRecord represents a configured or discovered parameter for a target.
type ParameterRecord struct {
	TargetID    string `json:"target_id,omitempty"`
	Endpoint    string `json:"endpoint,omitempty"`
	Method      string `json:"method,omitempty"`
	Name        string `json:"name"`
	Location    string `json:"location,omitempty"`
	SampleValue string `json:"sample_value,omitempty"`
	Source      string `json:"source,omitempty"`
}

// AuthSession stores a captured authenticated browser/session context for a target.
type AuthSession struct {
	TargetID       string    `json:"target_id,omitempty"`
	TargetURL      string    `json:"target_url,omitempty"`
	Source         string    `json:"source,omitempty"`
	AuthSuccess    bool      `json:"auth_success"`
	Cookies        []string  `json:"cookies,omitempty"`
	CSRFTokens     []string  `json:"csrf_tokens,omitempty"`
	RedirectChain  []string  `json:"redirect_chain,omitempty"`
	CapturedAt     time.Time `json:"captured_at,omitempty"`
	WorkflowPath   string    `json:"workflow_path,omitempty"`
	HTMLReportPath string    `json:"html_report_path,omitempty"`
}

// EngagementContext is the snapshot persisted in .akemi archives.
type EngagementContext struct {
	ActiveTarget *TargetProfile    `json:"active_target,omitempty"`
	Defaults     ScanDefaults      `json:"defaults,omitempty"`
	AuthSession  *AuthSession      `json:"auth_session,omitempty"`
	Parameters   []ParameterRecord `json:"parameters,omitempty"`
}

// ContextStore is a process-local store for MCP engagement context.
type ContextStore interface {
	SetTarget(ctx context.Context, target TargetProfile) error
	GetActiveTarget(ctx context.Context) (*TargetProfile, error)
	SetDefaults(ctx context.Context, defaults ScanDefaults) error
	GetDefaults(ctx context.Context) (ScanDefaults, error)
	SetAuthSession(ctx context.Context, session AuthSession) error
	GetAuthSession(ctx context.Context) (*AuthSession, error)
	ClearAuthSession(ctx context.Context) error
	AddParameters(ctx context.Context, targetID string, params []ParameterRecord) error
	ListParameters(ctx context.Context, targetID string) ([]ParameterRecord, error)
	Clear(ctx context.Context) error
	Snapshot(ctx context.Context) (EngagementContext, error)
	Replace(ctx context.Context, snapshot EngagementContext) error
}

// MemoryContextStore keeps engagement context in memory for one process.
type MemoryContextStore struct {
	mu  sync.RWMutex
	ctx EngagementContext
}

// NewMemoryContextStore creates an empty in-memory engagement context store.
func NewMemoryContextStore() *MemoryContextStore {
	return &MemoryContextStore{}
}

func (s *MemoryContextStore) SetTarget(ctx context.Context, target TargetProfile) error {
	_ = ctx
	target = normalizeTarget(target)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx.ActiveTarget = &target
	return nil
}

func (s *MemoryContextStore) GetActiveTarget(ctx context.Context) (*TargetProfile, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ctx.ActiveTarget == nil {
		return nil, nil
	}
	target := cloneTarget(*s.ctx.ActiveTarget)
	return &target, nil
}

func (s *MemoryContextStore) SetDefaults(ctx context.Context, defaults ScanDefaults) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx.Defaults = cloneDefaults(defaults)
	return nil
}

func (s *MemoryContextStore) GetDefaults(ctx context.Context) (ScanDefaults, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneDefaults(s.ctx.Defaults), nil
}

func (s *MemoryContextStore) SetAuthSession(ctx context.Context, session AuthSession) error {
	_ = ctx
	session = normalizeAuthSession(session)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx.AuthSession = &session
	return nil
}

func (s *MemoryContextStore) GetAuthSession(ctx context.Context) (*AuthSession, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ctx.AuthSession == nil {
		return nil, nil
	}
	session := cloneAuthSession(*s.ctx.AuthSession)
	return &session, nil
}

func (s *MemoryContextStore) ClearAuthSession(ctx context.Context) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx.AuthSession = nil
	return nil
}

func (s *MemoryContextStore) AddParameters(ctx context.Context, targetID string, params []ParameterRecord) error {
	_ = ctx
	targetID = strings.TrimSpace(targetID)
	cleaned := make([]ParameterRecord, 0, len(params))
	for _, p := range params {
		p.TargetID = firstNonEmptyString(p.TargetID, targetID)
		p.Name = strings.TrimSpace(p.Name)
		if p.Name == "" {
			continue
		}
		p.Method = strings.ToUpper(strings.TrimSpace(p.Method))
		p.Location = strings.ToLower(strings.TrimSpace(p.Location))
		cleaned = append(cleaned, p)
	}
	if len(cleaned) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx.Parameters = append(s.ctx.Parameters, cleaned...)
	return nil
}

func (s *MemoryContextStore) ListParameters(ctx context.Context, targetID string) ([]ParameterRecord, error) {
	_ = ctx
	targetID = strings.TrimSpace(targetID)
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]ParameterRecord, 0, len(s.ctx.Parameters))
	for _, p := range s.ctx.Parameters {
		if targetID != "" && p.TargetID != "" && p.TargetID != targetID {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *MemoryContextStore) Clear(ctx context.Context) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx = EngagementContext{}
	return nil
}

func (s *MemoryContextStore) Snapshot(ctx context.Context) (EngagementContext, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneContext(s.ctx), nil
}

func (s *MemoryContextStore) Replace(ctx context.Context, snapshot EngagementContext) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx = cloneContext(snapshot)
	if s.ctx.ActiveTarget != nil {
		target := normalizeTarget(*s.ctx.ActiveTarget)
		s.ctx.ActiveTarget = &target
	}
	if s.ctx.AuthSession != nil {
		session := normalizeAuthSession(*s.ctx.AuthSession)
		s.ctx.AuthSession = &session
	}
	return nil
}

func normalizeTarget(target TargetProfile) TargetProfile {
	target.ID = strings.TrimSpace(target.ID)
	target.Name = strings.TrimSpace(target.Name)
	target.BaseURL = strings.TrimSpace(target.BaseURL)
	target.Domain = strings.TrimSpace(target.Domain)
	target.Notes = strings.TrimSpace(target.Notes)
	target.Hosts = cleanStringList(target.Hosts)
	target.CIDRs = cleanStringList(target.CIDRs)

	if target.Domain == "" && target.BaseURL != "" {
		if parsed, err := url.Parse(target.BaseURL); err == nil {
			target.Domain = parsed.Hostname()
		}
	}
	if target.ID == "" {
		target.ID = makeTargetID(firstNonEmptyString(target.Name, target.Domain, target.BaseURL, firstString(target.Hosts), firstString(target.CIDRs)))
	}
	return target
}

func makeTargetID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	id := strings.Trim(b.String(), "-._")
	if id == "" {
		return "target"
	}
	return id
}

func normalizeAuthSession(session AuthSession) AuthSession {
	session.TargetID = strings.TrimSpace(session.TargetID)
	session.TargetURL = strings.TrimSpace(session.TargetURL)
	session.Source = strings.TrimSpace(session.Source)
	session.WorkflowPath = strings.TrimSpace(session.WorkflowPath)
	session.HTMLReportPath = strings.TrimSpace(session.HTMLReportPath)
	session.Cookies = cleanStringList(session.Cookies)
	session.CSRFTokens = cleanStringList(session.CSRFTokens)
	session.RedirectChain = cleanStringList(session.RedirectChain)
	if session.Source == "" {
		session.Source = "dothound"
	}
	return session
}

func cloneContext(in EngagementContext) EngagementContext {
	out := EngagementContext{
		Defaults:   cloneDefaults(in.Defaults),
		Parameters: append([]ParameterRecord(nil), in.Parameters...),
	}
	if in.ActiveTarget != nil {
		target := cloneTarget(*in.ActiveTarget)
		out.ActiveTarget = &target
	}
	if in.AuthSession != nil {
		session := cloneAuthSession(*in.AuthSession)
		out.AuthSession = &session
	}
	return out
}

func cloneTarget(in TargetProfile) TargetProfile {
	in.Hosts = append([]string(nil), in.Hosts...)
	in.CIDRs = append([]string(nil), in.CIDRs...)
	return in
}

func cloneDefaults(in ScanDefaults) ScanDefaults {
	out := in
	out.VulnTags = append([]string(nil), in.VulnTags...)
	out.MineJS = cloneBoolPtr(in.MineJS)
	out.MineForms = cloneBoolPtr(in.MineForms)
	out.MineJSON = cloneBoolPtr(in.MineJSON)
	out.MinePath = cloneBoolPtr(in.MinePath)
	out.ActiveBrute = cloneBoolPtr(in.ActiveBrute)
	return out
}

func cloneAuthSession(in AuthSession) AuthSession {
	in.Cookies = append([]string(nil), in.Cookies...)
	in.CSRFTokens = append([]string(nil), in.CSRFTokens...)
	in.RedirectChain = append([]string(nil), in.RedirectChain...)
	return in
}

func cloneBoolPtr(in *bool) *bool {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}

func cleanStringList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
