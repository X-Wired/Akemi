package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"Akemi/internal/llm"
)

const historySchemaVersion = 1

// ProviderMetadata captures the active non-secret LLM settings for a saved chat.
type ProviderMetadata struct {
	Provider string `json:"provider,omitempty"`
	Model    string `json:"model,omitempty"`
	BaseURL  string `json:"base_url,omitempty"`
}

// TranscriptEntry is the visible assistant chat transcript persisted for the TUI.
type TranscriptEntry struct {
	Time    time.Time `json:"time"`
	Role    string    `json:"role"`
	Message string    `json:"message"`
}

// ConversationSummary is a compact row for chat history pickers.
type ConversationSummary struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	UpdatedAt time.Time `json:"updated_at"`
	Provider  string    `json:"provider,omitempty"`
	Messages  int       `json:"messages"`
}

// ConversationSnapshot is the on-disk assistant history contract.
type ConversationSnapshot struct {
	Version        int               `json:"version"`
	ConversationID string            `json:"conversation_id,omitempty"`
	Title          string            `json:"title,omitempty"`
	Summary        string            `json:"summary,omitempty"`
	Messages       []llm.Message     `json:"messages,omitempty"`
	Transcript     []TranscriptEntry `json:"transcript,omitempty"`
	Provider       ProviderMetadata  `json:"provider,omitempty"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

type conversationArchive struct {
	Version              int                    `json:"version"`
	ActiveConversationID string                 `json:"active_conversation_id,omitempty"`
	Conversations        []ConversationSnapshot `json:"conversations,omitempty"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

// HistoryStore persists assistant conversation state.
type HistoryStore interface {
	Load(ctx context.Context) (*ConversationSnapshot, error)
	LoadConversation(ctx context.Context, conversationID string) (*ConversationSnapshot, error)
	List(ctx context.Context) ([]ConversationSummary, error)
	Save(ctx context.Context, snapshot *ConversationSnapshot) error
	Clear(ctx context.Context) error
}

// FileHistoryStore persists assistant history as private JSON on disk.
type FileHistoryStore struct {
	path string
}

// NewFileHistoryStore creates a file-backed history store.
func NewFileHistoryStore(path string) *FileHistoryStore {
	return &FileHistoryStore{path: filepath.Clean(path)}
}

// DefaultHistoryPath returns the workspace assistant history path.
// When outputDir is empty, it defaults to the current working directory.
func DefaultHistoryPath(outputDir string) string {
	outputDir = strings.TrimSpace(outputDir)
	if outputDir == "" {
		outputDir = "."
	}
	return filepath.Join(outputDir, ".akemi", "assistant-history.json")
}

// ProjectHistoryPath returns the assistant history path scoped to an Akemi
// project's state directory. When projectRoot is empty, it falls back to
// DefaultHistoryPath with the current working directory.
func ProjectHistoryPath(projectRoot string) string {
	projectRoot = strings.TrimSpace(projectRoot)
	if projectRoot == "" {
		return DefaultHistoryPath(".")
	}
	return filepath.Join(projectRoot, ".akemi", "assistant-history.json")
}

// Path returns the configured store path.
func (s *FileHistoryStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Load reads the current history file.
func (s *FileHistoryStore) Load(ctx context.Context) (*ConversationSnapshot, error) {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return nil, nil
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	archive, err := s.readArchive(ctx)
	if err != nil {
		return nil, err
	}
	if len(archive.Conversations) == 0 {
		return nil, nil
	}
	if strings.TrimSpace(archive.ActiveConversationID) != "" {
		if snapshot := findConversation(archive.Conversations, archive.ActiveConversationID); snapshot != nil {
			return cloneConversation(snapshot), nil
		}
	}
	return cloneConversation(newestConversation(archive.Conversations)), nil
}

// LoadConversation reads a specific conversation and marks it active.
func (s *FileHistoryStore) LoadConversation(ctx context.Context, conversationID string) (*ConversationSnapshot, error) {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return nil, nil
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return s.Load(ctx)
	}
	archive, err := s.readArchive(ctx)
	if err != nil {
		return nil, err
	}
	snapshot := findConversation(archive.Conversations, conversationID)
	if snapshot == nil {
		return nil, fmt.Errorf("conversation %q not found", conversationID)
	}
	archive.ActiveConversationID = conversationID
	if err := s.writeArchive(ctx, archive); err != nil {
		return nil, err
	}
	return cloneConversation(snapshot), nil
}

// List returns saved conversations sorted by most recent update first.
func (s *FileHistoryStore) List(ctx context.Context) ([]ConversationSummary, error) {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return nil, nil
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	archive, err := s.readArchive(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]ConversationSummary, 0, len(archive.Conversations))
	for _, snapshot := range archive.Conversations {
		if len(snapshot.Transcript) == 0 && len(snapshot.Messages) == 0 {
			continue
		}
		items = append(items, ConversationSummary{
			ID:        snapshot.ConversationID,
			Title:     conversationTitle(&snapshot),
			UpdatedAt: snapshot.UpdatedAt,
			Provider:  snapshot.Provider.Provider,
			Messages:  len(snapshot.Transcript),
		})
	}
	sortConversationSummaries(items)
	return items, nil
}

func (s *FileHistoryStore) readArchive(ctx context.Context) (*conversationArchive, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return &conversationArchive{Version: historySchemaVersion}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open assistant history: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read assistant history: %w", err)
	}
	var probe struct {
		Conversations json.RawMessage `json:"conversations"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("decode assistant history: %w", err)
	}
	if len(probe.Conversations) > 0 {
		var archive conversationArchive
		if err := json.Unmarshal(data, &archive); err != nil {
			return nil, fmt.Errorf("decode assistant history archive: %w", err)
		}
		normalizeArchive(&archive)
		return &archive, nil
	}

	var snapshot ConversationSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, fmt.Errorf("decode assistant history: %w", err)
	}
	normalizeConversation(&snapshot)
	return &conversationArchive{
		Version:              historySchemaVersion,
		ActiveConversationID: snapshot.ConversationID,
		Conversations:        []ConversationSnapshot{snapshot},
		UpdatedAt:            snapshot.UpdatedAt,
	}, nil
}

// Save writes the history file with private permissions.
func (s *FileHistoryStore) Save(ctx context.Context, snapshot *ConversationSnapshot) error {
	if s == nil || strings.TrimSpace(s.path) == "" || snapshot == nil {
		return nil
	}
	if err := ctxErr(ctx); err != nil {
		return err
	}
	archive, err := s.readArchive(ctx)
	if err != nil {
		return err
	}
	normalizeConversation(snapshot)
	snapshot.UpdatedAt = time.Now().UTC()
	archive.ActiveConversationID = snapshot.ConversationID
	replaced := false
	for i := range archive.Conversations {
		if archive.Conversations[i].ConversationID == snapshot.ConversationID {
			archive.Conversations[i] = *cloneConversation(snapshot)
			replaced = true
			break
		}
	}
	if !replaced {
		archive.Conversations = append(archive.Conversations, *cloneConversation(snapshot))
	}
	return s.writeArchive(ctx, archive)
}

// Clear starts a fresh active conversation while preserving saved conversations.
func (s *FileHistoryStore) Clear(ctx context.Context) error {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return nil
	}
	if err := ctxErr(ctx); err != nil {
		return err
	}
	archive, err := s.readArchive(ctx)
	if err != nil {
		return err
	}
	empty := ConversationSnapshot{
		Version:        historySchemaVersion,
		ConversationID: NewConversationID(),
		Title:          "New chat",
		UpdatedAt:      time.Now().UTC(),
	}
	archive.ActiveConversationID = empty.ConversationID
	archive.Conversations = append(archive.Conversations, empty)
	return s.writeArchive(ctx, archive)
}

func (s *FileHistoryStore) writeArchive(ctx context.Context, archive *conversationArchive) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	if archive == nil {
		archive = &conversationArchive{}
	}
	normalizeArchive(archive)
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create assistant history directory: %w", err)
	}
	archive.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(archive, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal assistant history: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("write assistant history: %w", err)
	}
	_ = os.Chmod(s.path, 0o600)
	return nil
}

// NewConversationID returns a stable-enough local conversation identifier.
func NewConversationID() string {
	now := time.Now().UTC()
	return fmt.Sprintf("chat-%s-%06d", now.Format("20060102-150405"), now.UnixNano()%1_000_000)
}

func normalizeArchive(archive *conversationArchive) {
	if archive.Version == 0 {
		archive.Version = historySchemaVersion
	}
	for i := range archive.Conversations {
		normalizeConversation(&archive.Conversations[i])
	}
}

func normalizeConversation(snapshot *ConversationSnapshot) {
	if snapshot.Version == 0 {
		snapshot.Version = historySchemaVersion
	}
	if strings.TrimSpace(snapshot.ConversationID) == "" {
		snapshot.ConversationID = NewConversationID()
	}
	if snapshot.UpdatedAt.IsZero() {
		snapshot.UpdatedAt = time.Now().UTC()
	}
	snapshot.Title = conversationTitle(snapshot)
}

func conversationTitle(snapshot *ConversationSnapshot) string {
	if snapshot == nil {
		return "New chat"
	}
	if title := cleanConversationTitle(snapshot.Title); title != "" && title != "New chat" {
		return title
	}
	for _, entry := range snapshot.Transcript {
		if entry.Role == "user" {
			if title := cleanConversationTitle(entry.Message); title != "" {
				return title
			}
		}
	}
	for _, entry := range snapshot.Transcript {
		if title := cleanConversationTitle(entry.Message); title != "" {
			return title
		}
	}
	for _, msg := range snapshot.Messages {
		if msg.Role == "user" {
			if title := cleanConversationTitle(msg.Content); title != "" {
				return title
			}
		}
	}
	return "New chat"
}

func cleanConversationTitle(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return ""
	}
	words := strings.Fields(value)
	if len(words) > 7 {
		value = strings.Join(words[:7], " ")
	}
	runes := []rune(value)
	if len(runes) > 54 {
		value = string(runes[:51]) + "..."
	}
	return value
}

func findConversation(conversations []ConversationSnapshot, id string) *ConversationSnapshot {
	for i := range conversations {
		if conversations[i].ConversationID == id {
			return &conversations[i]
		}
	}
	return nil
}

func newestConversation(conversations []ConversationSnapshot) *ConversationSnapshot {
	if len(conversations) == 0 {
		return nil
	}
	newest := &conversations[0]
	for i := 1; i < len(conversations); i++ {
		if conversations[i].UpdatedAt.After(newest.UpdatedAt) {
			newest = &conversations[i]
		}
	}
	return newest
}

func cloneConversation(snapshot *ConversationSnapshot) *ConversationSnapshot {
	if snapshot == nil {
		return nil
	}
	cloned := *snapshot
	cloned.Messages = append([]llm.Message(nil), snapshot.Messages...)
	cloned.Transcript = append([]TranscriptEntry(nil), snapshot.Transcript...)
	return &cloned
}

func sortConversationSummaries(items []ConversationSummary) {
	for i := 1; i < len(items); i++ {
		item := items[i]
		j := i - 1
		for j >= 0 && items[j].UpdatedAt.Before(item.UpdatedAt) {
			items[j+1] = items[j]
			j--
		}
		items[j+1] = item
	}
}

func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
