// Package assistant coordinates LLM chat, MCP tool calls, and approval gates.
package assistant

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"Akemi/internal/engagement"
	"Akemi/internal/llm"
	"Akemi/internal/mcpclient"
	"Akemi/internal/toolbridge"
)

const systemPrompt = `You are Akemi's security assistant inside a professional pentesting dashboard.
Help the operator understand findings, plan next steps, and use tools only when useful.
Never claim a tool ran unless a tool result is present.
Before tool execution, Akemi will ask the operator for approval. Keep tool arguments scoped to the current engagement target and avoid destructive actions.
When a tool fails, treat the failure as evidence: continue with another useful tool or action if one is available, or ask the operator to retry with corrected arguments or setup steps if the failed tool is still required.`

const toolFollowupTimeout = 5 * time.Hour

const maxToolMessageChars = 12000

// Session owns one conversational assistant state.
type Session struct {
	client         llm.Client
	router         *mcpclient.Router
	approvals      *engagement.Manager
	messages       []llm.Message
	transcript     []TranscriptEntry
	summary        string
	history        HistoryStore
	provider       ProviderMetadata
	conversationID string
	pending        *PendingApproval
	maxTokens      int
	temperature    float64
}

// Config configures an assistant session.
type Config struct {
	MaxTokens      int
	Temperature    float64
	HistoryStore   HistoryStore
	ConversationID string
	Provider       ProviderMetadata
}

// PendingApproval is a model-requested tool call awaiting the operator.
type PendingApproval struct {
	Request          engagement.Request
	ToolCall         llm.ToolCall
	SkippedToolCalls []llm.ToolCall
}

// ToolRun returns this pending approval as a UI-facing tool lifecycle event.
func (p *PendingApproval) ToolRun(status string) *ToolRunInfo {
	return toolRunInfoFromPending(p, status)
}

// ToolRunInfo is a compact UI-facing description of an LLM-requested tool run.
type ToolRunInfo struct {
	ToolName         string
	ServerName       string
	NativeName       string
	ArgumentsSummary string
	Status           string
}

// TurnResult is returned after a user message or approval decision.
type TurnResult struct {
	Assistant       string
	PendingApproval *PendingApproval
	ToolResult      string
	ToolRun         *ToolRunInfo
}

// NewSession creates a new assistant session.
func NewSession(client llm.Client, router *mcpclient.Router, approvals *engagement.Manager, cfg Config) *Session {
	if approvals == nil {
		approvals = engagement.NewManager(engagement.ApprovalAsk)
	}
	s := &Session{
		client:         client,
		router:         router,
		approvals:      approvals,
		history:        cfg.HistoryStore,
		provider:       cfg.Provider,
		conversationID: strings.TrimSpace(cfg.ConversationID),
		maxTokens:      cfg.MaxTokens,
		temperature:    cfg.Temperature,
	}
	if s.conversationID != "" {
		s.loadHistory(context.Background(), s.conversationID)
	} else {
		s.conversationID = NewConversationID()
	}
	return s
}

// Available reports whether the session can talk to an LLM.
func (s *Session) Available() bool {
	return s != nil && s.client != nil
}

// Submit sends a user message to the model.
func (s *Session) Submit(ctx context.Context, userMessage, dashboardContext string) (*TurnResult, error) {
	if !s.Available() {
		return nil, fmt.Errorf("assistant is not configured")
	}
	if s.pending != nil {
		return &TurnResult{PendingApproval: s.pending, ToolRun: toolRunInfoFromPending(s.pending, "requested")}, nil
	}
	s.messages = append(s.messages, llm.Message{Role: "user", Content: userMessage})
	s.addTranscript("user", userMessage)
	s.saveHistory(ctx)
	return s.complete(ctx, dashboardContext)
}

// ApprovePending executes the pending tool call once and resumes the model.
func (s *Session) ApprovePending(ctx context.Context) (*TurnResult, error) {
	if s.pending == nil {
		return &TurnResult{Assistant: "No pending tool approval."}, nil
	}
	pending := s.pending
	s.pending = nil

	if s.router == nil {
		s.messages = append(s.messages, llm.Message{
			Role:       "tool",
			ToolCallID: pending.ToolCall.ID,
			Content:    "Tool execution failed: tool router is not configured",
		})
		s.appendSkippedToolResults(pending)
		s.saveHistory(ctx)
		return &TurnResult{ToolResult: "tool router is not configured", ToolRun: toolRunInfoFromPending(pending, "failed")}, nil
	}
	result, err := s.router.Execute(ctx, pending.ToolCall.Function.Name, pending.ToolCall.Function.Arguments)
	if err != nil {
		toolText := toolFailureContent(err)
		s.messages = append(s.messages, llm.Message{
			Role:       "tool",
			ToolCallID: pending.ToolCall.ID,
			Content:    toolText,
		})
		s.appendSkippedToolResults(pending)
		s.addTranscript("tool", "[error] "+err.Error())
		s.saveHistory(ctx)
		turn, completeErr := s.completeAfterTool(ctx)
		if turn == nil {
			turn = &TurnResult{}
		}
		turn.ToolResult = "[error] " + err.Error()
		turn.ToolRun = toolRunInfoFromPending(pending, "failed")
		if completeErr != nil {
			turn.Assistant = "The tool failed, and I could not ask the model for the next step: " + completeErr.Error()
			return turn, nil
		}
		return turn, nil
	}

	toolText := result.Text
	if toolText == "" {
		toolText = "(tool returned no text content)"
	}
	assistantToolText := compactToolResultForAssistant(result.Ref.NativeName, toolText)
	if len(result.Structured) > 0 {
		assistantToolText += "\n\nStructured result is available through MCP structuredContent and akemi://scan/current/summary."
	}
	s.messages = append(s.messages, llm.Message{
		Role:       "tool",
		ToolCallID: pending.ToolCall.ID,
		Content:    assistantToolText,
	})
	s.appendSkippedToolResults(pending)
	s.addTranscript("tool", "result: "+assistantToolText)
	s.saveHistory(ctx)
	turn, err := s.completeAfterTool(ctx)
	if turn != nil {
		turn.ToolResult = assistantToolText
		turn.ToolRun = toolRunInfoFromPending(pending, "completed")
	}
	return turn, err
}

// DenyPending records a denial and resumes the model.
func (s *Session) DenyPending(ctx context.Context) (*TurnResult, error) {
	if s.pending == nil {
		return &TurnResult{Assistant: "No pending tool approval."}, nil
	}
	pending := s.pending
	s.pending = nil
	s.messages = append(s.messages, llm.Message{
		Role:       "tool",
		ToolCallID: pending.ToolCall.ID,
		Content:    "The operator denied this tool call. Continue without executing it.",
	})
	s.appendSkippedToolResults(pending)
	s.addTranscript("tool", "denied "+pending.Request.Summary())
	s.saveHistory(ctx)
	turn, err := s.complete(ctx, "")
	if turn != nil {
		turn.ToolRun = toolRunInfoFromPending(pending, "denied")
	}
	return turn, err
}

// ToolsSummary returns a compact list for dashboard display.
func (s *Session) ToolsSummary() string {
	if s == nil || s.router == nil {
		return "No MCP tools connected."
	}
	refs := s.router.ListRefs()
	if len(refs) == 0 {
		return "No MCP tools connected."
	}
	var lines []string
	for _, ref := range refs {
		lines = append(lines, fmt.Sprintf("- %s [%s] - %s", ref.LLMName, ref.Risk, shortDescription(ref.Tool.Description)))
	}
	return strings.Join(lines, "\n")
}

// PendingToolRun returns the currently pending tool in a UI-friendly shape.
func (s *Session) PendingToolRun(status string) *ToolRunInfo {
	if s == nil || s.pending == nil {
		return nil
	}
	return toolRunInfoFromPending(s.pending, status)
}

// SetToolEventSink connects assistant-owned in-process tools to a UI bridge.
func (s *Session) SetToolEventSink(sink toolbridge.Sink) {
	if s == nil || s.router == nil {
		return
	}
	s.router.SetToolEventSink(sink)
}

// Transcript returns the visible chat transcript restored from history.
func (s *Session) Transcript() []TranscriptEntry {
	if s == nil {
		return nil
	}
	return append([]TranscriptEntry(nil), s.transcript...)
}

// ConversationID returns the active conversation identifier.
func (s *Session) ConversationID() string {
	if s == nil {
		return ""
	}
	return s.conversationID
}

// HistoryList returns titled saved conversations for picker UIs.
func (s *Session) HistoryList(ctx context.Context) []ConversationSummary {
	if s == nil || s.history == nil {
		return nil
	}
	items, err := s.history.List(ctx)
	if err != nil {
		return nil
	}
	return items
}

// LoadConversation replaces the active assistant state with a saved conversation.
func (s *Session) LoadConversation(ctx context.Context, conversationID string) error {
	if s == nil || s.history == nil {
		return fmt.Errorf("assistant history is not configured")
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return fmt.Errorf("conversation id is required")
	}
	snapshot, err := s.history.LoadConversation(ctx, conversationID)
	if err != nil {
		return err
	}
	if snapshot == nil {
		return fmt.Errorf("conversation %q not found", conversationID)
	}
	s.applySnapshot(snapshot)
	return nil
}

// ClearHistory resets active conversation memory while preserving older saved chats.
func (s *Session) ClearHistory(ctx context.Context) error {
	return s.StartNewConversation(ctx)
}

// StartNewConversation switches to a fresh active chat while preserving saved chats.
func (s *Session) StartNewConversation(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.messages = nil
	s.transcript = nil
	s.summary = ""
	s.pending = nil
	s.conversationID = NewConversationID()
	return ctxErr(ctx)
}

func (s *Session) complete(ctx context.Context, dashboardContext string) (*TurnResult, error) {
	tools := []llm.ToolDefinition(nil)
	if s.router != nil {
		tools = s.router.ToolDefinitions()
	}
	resp, err := s.client.Chat(ctx, llm.ChatRequest{
		Messages:    s.requestMessages(dashboardContext),
		Tools:       tools,
		MaxTokens:   s.maxTokens,
		Temperature: s.temperature,
	})
	if err != nil {
		return nil, err
	}
	resp.Message = normalizeToolCallIDs(resp.Message)
	s.messages = append(s.messages, resp.Message)
	if strings.TrimSpace(resp.Message.Content) != "" {
		s.addTranscript("assistant", resp.Message.Content)
	}

	if len(resp.Message.ToolCalls) > 0 {
		toolCall := resp.Message.ToolCalls[0]
		if s.router == nil {
			s.appendUnexecutedToolCalls(resp.Message.ToolCalls, "Tool execution failed: tool router is not configured")
			return nil, fmt.Errorf("tool router is not configured")
		}
		ref, ok := s.router.Lookup(toolCall.Function.Name)
		if !ok {
			s.appendUnexecutedToolCalls(resp.Message.ToolCalls, "Tool execution failed: requested tool is not available")
			return nil, fmt.Errorf("model requested unknown tool %q", toolCall.Function.Name)
		}
		req := engagement.Request{
			ID:          firstNonEmpty(toolCall.ID, fmt.Sprintf("tool-%d", time.Now().UnixNano())),
			ToolName:    ref.LLMName,
			ServerName:  ref.ServerName,
			NativeName:  ref.NativeName,
			Risk:        ref.Risk,
			Arguments:   toolCall.Function.Arguments,
			RequestedAt: time.Now(),
		}
		pending := &PendingApproval{
			Request:          req,
			ToolCall:         toolCall,
			SkippedToolCalls: append([]llm.ToolCall(nil), resp.Message.ToolCalls[1:]...),
		}
		if s.approvals.RequiresApproval(req) {
			s.pending = pending
			return &TurnResult{PendingApproval: pending, ToolRun: toolRunInfoFromPending(pending, "requested")}, nil
		}
		s.pending = pending
		return s.ApprovePending(ctx)
	}

	s.compactHistory()
	s.saveHistory(ctx)
	return &TurnResult{Assistant: resp.Message.Content}, nil
}

func (s *Session) completeAfterTool(ctx context.Context) (*TurnResult, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
	}
	base := context.Background()
	if ctx != nil {
		base = context.WithoutCancel(ctx)
	}
	followupCtx, cancel := context.WithTimeout(base, toolFollowupTimeout)
	defer cancel()
	return s.complete(followupCtx, "")
}

func (s *Session) appendSkippedToolResults(pending *PendingApproval) {
	if pending == nil {
		return
	}
	for _, toolCall := range pending.SkippedToolCalls {
		if strings.TrimSpace(toolCall.ID) == "" {
			continue
		}
		s.messages = append(s.messages, llm.Message{
			Role:       "tool",
			ToolCallID: toolCall.ID,
			Content:    "Tool call not executed: Akemi runs one approved dashboard tool at a time. Continue with the available tool result or request the next tool separately.",
		})
	}
}

func (s *Session) appendUnexecutedToolCalls(toolCalls []llm.ToolCall, content string) {
	for _, toolCall := range toolCalls {
		if strings.TrimSpace(toolCall.ID) == "" {
			continue
		}
		s.messages = append(s.messages, llm.Message{
			Role:       "tool",
			ToolCallID: toolCall.ID,
			Content:    content,
		})
	}
}

func (s *Session) requestMessages(dashboardContext string) []llm.Message {
	out := []llm.Message{{Role: "system", Content: systemPrompt}}
	if strings.TrimSpace(s.summary) != "" {
		out = append(out, llm.Message{
			Role:    "system",
			Content: "Conversation memory summary:\n" + s.summary,
		})
	}
	if strings.TrimSpace(dashboardContext) != "" {
		out = append(out, llm.Message{
			Role:    "system",
			Content: "Current Akemi dashboard context:\n" + dashboardContext,
		})
	}
	out = append(out, s.messages...)
	return out
}

func (s *Session) loadHistory(ctx context.Context, conversationID string) {
	if s.history == nil {
		if s.conversationID == "" {
			s.conversationID = NewConversationID()
		}
		return
	}
	var snapshot *ConversationSnapshot
	var err error
	if strings.TrimSpace(conversationID) != "" {
		snapshot, err = s.history.LoadConversation(ctx, conversationID)
	} else {
		snapshot, err = s.history.Load(ctx)
	}
	if err != nil || snapshot == nil {
		if s.conversationID == "" {
			s.conversationID = NewConversationID()
		}
		return
	}
	s.applySnapshot(snapshot)
	s.compactHistory()
}

func (s *Session) applySnapshot(snapshot *ConversationSnapshot) {
	if s == nil || snapshot == nil {
		return
	}
	s.conversationID = firstNonEmpty(snapshot.ConversationID, s.conversationID, NewConversationID())
	s.messages = sanitizeHistoryMessages(snapshot.Messages)
	s.transcript = append([]TranscriptEntry(nil), snapshot.Transcript...)
	s.summary = strings.TrimSpace(snapshot.Summary)
	s.pending = nil
	if s.provider.Provider == "" {
		s.provider = snapshot.Provider
	}
}

func (s *Session) saveHistory(ctx context.Context) {
	if s == nil || s.history == nil {
		return
	}
	s.compactHistory()
	if strings.TrimSpace(s.conversationID) == "" {
		s.conversationID = NewConversationID()
	}
	_ = s.history.Save(ctx, &ConversationSnapshot{
		Version:        historySchemaVersion,
		ConversationID: s.conversationID,
		Title:          "",
		Summary:        s.summary,
		Messages:       append([]llm.Message(nil), s.messages...),
		Transcript:     append([]TranscriptEntry(nil), s.transcript...),
		Provider:       s.provider,
	})
}

func (s *Session) saveEmptyHistory(ctx context.Context) error {
	if s == nil || s.history == nil {
		return nil
	}
	if strings.TrimSpace(s.conversationID) == "" {
		s.conversationID = NewConversationID()
	}
	return s.history.Save(ctx, &ConversationSnapshot{
		Version:        historySchemaVersion,
		ConversationID: s.conversationID,
		Title:          "New chat",
		Provider:       s.provider,
	})
}

func (s *Session) compactHistory() {
	if s == nil {
		return
	}
	s.messages = trimCompleteMessages(s.messages, 80)
	if len(s.transcript) > maxChatEntriesPersisted {
		s.transcript = s.transcript[len(s.transcript)-maxChatEntriesPersisted:]
	}
	s.updateSummary()
}

const maxChatEntriesPersisted = 200

func (s *Session) updateSummary() {
	if len(s.messages) <= 40 {
		return
	}
	cut := len(s.messages) - 40
	for cut > 0 && s.messages[cut].Role == "tool" {
		cut--
	}
	if cut <= 0 {
		return
	}
	var parts []string
	if strings.TrimSpace(s.summary) != "" {
		parts = append(parts, s.summary)
	}
	for _, msg := range s.messages[:cut] {
		switch msg.Role {
		case "user", "assistant", "tool":
			text := strings.TrimSpace(msg.Content)
			if text == "" && len(msg.ToolCalls) > 0 {
				text = fmt.Sprintf("requested %d tool call(s)", len(msg.ToolCalls))
			}
			if text != "" {
				parts = append(parts, fmt.Sprintf("%s: %s", msg.Role, truncateSummary(text, 180)))
			}
		}
	}
	s.summary = truncateSummary(strings.Join(parts, "\n"), 6000)
	s.messages = s.messages[cut:]
}

func sanitizeHistoryMessages(messages []llm.Message) []llm.Message {
	out := make([]llm.Message, 0, len(messages))
	for _, msg := range messages {
		if msg.Role == "system" {
			continue
		}
		out = append(out, msg)
	}
	return trimCompleteMessages(out, 80)
}

func trimCompleteMessages(messages []llm.Message, maxMessages int) []llm.Message {
	if maxMessages <= 0 || len(messages) <= maxMessages {
		return append([]llm.Message(nil), messages...)
	}
	start := len(messages) - maxMessages
	for start < len(messages) && messages[start].Role == "tool" {
		start++
	}
	if start >= len(messages) {
		start = 0
	}
	return append([]llm.Message(nil), messages[start:]...)
}

func (s *Session) addTranscript(role, message string) {
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}
	s.transcript = append(s.transcript, TranscriptEntry{
		Time:    time.Now(),
		Role:    role,
		Message: message,
	})
	if len(s.transcript) > maxChatEntriesPersisted {
		s.transcript = s.transcript[len(s.transcript)-maxChatEntriesPersisted:]
	}
}

func truncateSummary(value string, maxLen int) string {
	value = strings.Join(strings.Fields(value), " ")
	if maxLen > 0 && len(value) > maxLen {
		return value[:maxLen] + "..."
	}
	return value
}

func toolFailureContent(err error) string {
	if err == nil {
		return "Tool execution failed. Continue with another useful action, or ask the operator to retry if this tool is still required."
	}
	return "Tool execution failed: " + err.Error() + "\n\nContinue with the next useful action if possible. If this same tool is still required, ask the operator to retry with corrected arguments, loaded templates, or setup steps."
}

func compactToolResultForAssistant(toolName, text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return "(tool returned no text content)"
	}
	if beforeRaw, _, ok := strings.Cut(text, "\n--- RAW JSON ---"); ok {
		text = strings.TrimSpace(beforeRaw)
		if toolName != "" {
			text += fmt.Sprintf("\n\n[%s raw JSON omitted from assistant chat history. Use the .akemi archive or discovery panel for full structured results.]", toolName)
		} else {
			text += "\n\n[Raw JSON omitted from assistant chat history. Use the .akemi archive or discovery panel for full structured results.]"
		}
	}
	if len(text) > maxToolMessageChars {
		text = text[:maxToolMessageChars] + "\n\n[Tool result truncated from assistant chat history to keep later chat turns responsive.]"
	}
	return text
}

func normalizeToolCallIDs(message llm.Message) llm.Message {
	for i := range message.ToolCalls {
		if strings.TrimSpace(message.ToolCalls[i].ID) == "" {
			message.ToolCalls[i].ID = fmt.Sprintf("tool-%d-%d", time.Now().UnixNano(), i)
		}
	}
	return message
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func toolRunInfoFromPending(pending *PendingApproval, status string) *ToolRunInfo {
	if pending == nil {
		return nil
	}
	return &ToolRunInfo{
		ToolName:         pending.Request.ToolName,
		ServerName:       pending.Request.ServerName,
		NativeName:       pending.Request.NativeName,
		ArgumentsSummary: compactToolArgs(pending.Request.Arguments),
		Status:           status,
	}
}

func compactToolArgs(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "{}"
	}
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 240 {
		return value[:237] + "..."
	}
	return value
}

func shortDescription(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "No description"
	}
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 96 {
		return value[:93] + "..."
	}
	return value
}
