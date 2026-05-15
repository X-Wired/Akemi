// Package state stores lightweight MCP runtime state for resources and jobs.
package state

import (
	"context"
	"strings"
	"sync"
	"time"

	"Akemi/internal/engagement"
)

// Store keeps the latest MCP-visible engagement and tool output state.
type Store struct {
	mu        sync.RWMutex
	context   engagement.ContextStore
	lastTool  ToolRecord
	byTool    map[string]ToolRecord
	jobs      map[string]JobRecord
	artifacts map[string]ArtifactRecord
}

// ToolRecord captures one completed tool call.
type ToolRecord struct {
	ToolName          string                 `json:"tool_name"`
	Summary           string                 `json:"summary"`
	StructuredContent map[string]interface{} `json:"structured_content,omitempty"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

// JobRecord captures a long-running MCP job.
type JobRecord struct {
	ID          string                 `json:"id"`
	Kind        string                 `json:"kind"`
	Status      string                 `json:"status"`
	Target      string                 `json:"target,omitempty"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Summary     string                 `json:"summary,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Progress    string                 `json:"progress,omitempty"`
	Result      map[string]interface{} `json:"result,omitempty"`
}

// ArtifactRecord captures a tool-generated artifact.
type ArtifactRecord struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Path      string    `json:"path,omitempty"`
	Content   string    `json:"content,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NewStore creates a runtime state store.
func NewStore(ctxStore engagement.ContextStore) *Store {
	return &Store{
		context:   ctxStore,
		byTool:    make(map[string]ToolRecord),
		jobs:      make(map[string]JobRecord),
		artifacts: make(map[string]ArtifactRecord),
	}
}

// SetContextStore updates the engagement context backing resources.
func (s *Store) SetContextStore(ctxStore engagement.ContextStore) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.context = ctxStore
}

// ContextStore returns the configured engagement context store.
func (s *Store) ContextStore() engagement.ContextStore {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.context
}

// RecordToolResult records a completed tool result.
func (s *Store) RecordToolResult(toolName, summary string, structured map[string]interface{}) {
	if s == nil {
		return
	}
	record := ToolRecord{
		ToolName:          toolName,
		Summary:           strings.TrimSpace(summary),
		StructuredContent: cloneMap(structured),
		UpdatedAt:         time.Now(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastTool = record
	s.byTool[toolName] = record
}

// UpsertJob stores a job record.
func (s *Store) UpsertJob(job JobRecord) {
	if s == nil || job.ID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[job.ID] = cloneJob(job)
}

// Job returns one job record.
func (s *Store) Job(id string) (JobRecord, bool) {
	if s == nil {
		return JobRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.jobs[id]
	return cloneJob(job), ok
}

// Jobs returns all known jobs.
func (s *Store) Jobs() []JobRecord {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	jobs := make([]JobRecord, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, cloneJob(job))
	}
	return jobs
}

// PutArtifact stores an artifact.
func (s *Store) PutArtifact(artifact ArtifactRecord) {
	if s == nil || artifact.ID == "" {
		return
	}
	if artifact.UpdatedAt.IsZero() {
		artifact.UpdatedAt = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.artifacts[artifact.ID] = artifact
}

// Artifact returns one artifact.
func (s *Store) Artifact(id string) (ArtifactRecord, bool) {
	if s == nil {
		return ArtifactRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	artifact, ok := s.artifacts[id]
	return artifact, ok
}

// Snapshot returns a resource-friendly state snapshot.
func (s *Store) Snapshot(ctx context.Context) map[string]interface{} {
	out := map[string]interface{}{}
	if s == nil {
		return out
	}
	s.mu.RLock()
	contextStore := s.context
	lastTool := s.lastTool
	byTool := make(map[string]ToolRecord, len(s.byTool))
	for k, v := range s.byTool {
		byTool[k] = v
	}
	jobs := make(map[string]JobRecord, len(s.jobs))
	for k, v := range s.jobs {
		jobs[k] = cloneJob(v)
	}
	artifacts := make(map[string]ArtifactRecord, len(s.artifacts))
	for k, v := range s.artifacts {
		artifacts[k] = v
	}
	s.mu.RUnlock()

	if contextStore != nil {
		if snapshot, err := contextStore.Snapshot(ctx); err == nil {
			out["engagement"] = snapshot
		}
	}
	out["last_tool"] = lastTool
	out["tools"] = byTool
	out["jobs"] = jobs
	out["artifacts"] = artifacts
	return out
}

// LastStructured returns the most recent structured content for a tool.
func (s *Store) LastStructured(toolName string) map[string]interface{} {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.byTool[toolName]
	if !ok {
		return nil
	}
	return cloneMap(record.StructuredContent)
}

func cloneJob(job JobRecord) JobRecord {
	job.Result = cloneMap(job.Result)
	return job
}

func cloneMap(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
