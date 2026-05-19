package project

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// registrySchemaVersion is bumped when the registry format changes.
const registrySchemaVersion = 1

// Registry persists a list of recently opened projects so the operator can
// quickly reopen a previous engagement without browsing the filesystem.
// The registry lives at ~/.akemi/projects.json.
type Registry struct {
	path     string
	entries  []RegistryEntry
	modified bool
}

// RegistryEntry describes one project in the recent-projects list.
type RegistryEntry struct {
	Name       string    `json:"name"`
	Root       string    `json:"root"`
	Targets    []string  `json:"targets,omitempty"`
	LastOpened time.Time `json:"last_opened"`
	CreatedAt  time.Time `json:"created_at"`
}

// registryFile is the on-disk format of the projects registry.
type registryFile struct {
	SchemaVersion int             `json:"schema_version"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Projects      []RegistryEntry `json:"projects"`
}

// GlobalRegistryPath returns the canonical path to the projects registry.
// On all platforms this is ~/.akemi/projects.json.
func GlobalRegistryPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".akemi", "projects.json"), nil
}

// LoadRegistry reads the projects registry from disk. If the file does not
// exist, an empty registry is returned without error.
func LoadRegistry() (*Registry, error) {
	path, err := GlobalRegistryPath()
	if err != nil {
		return nil, err
	}

	r := &Registry{
		path:    path,
		entries: []RegistryEntry{},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil // empty registry is valid
		}
		return nil, fmt.Errorf("read registry: %w", err)
	}

	var file registryFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse registry: %w", err)
	}

	r.entries = file.Projects
	r.deduplicate()
	r.sortByLastOpened()
	return r, nil
}

// Save writes the registry to disk with private permissions. Only call this
// if the registry was modified; it's a no-op otherwise.
func (r *Registry) Save() error {
	if r == nil || !r.modified {
		return nil
	}
	if r.path == "" {
		var err error
		r.path, err = GlobalRegistryPath()
		if err != nil {
			return err
		}
	}

	r.deduplicate()
	r.sortByLastOpened()

	dir := filepath.Dir(r.path)
	if err := os.MkdirAll(dir, DefaultDirPermissions); err != nil {
		return fmt.Errorf("create registry directory: %w", err)
	}

	file := registryFile{
		SchemaVersion: registrySchemaVersion,
		UpdatedAt:     time.Now().UTC(),
		Projects:      r.entries,
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal registry: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(r.path, data, DefaultFilePermissions); err != nil {
		return fmt.Errorf("write registry: %w", err)
	}

	r.modified = false
	return nil
}

// AddOrUpdate records a project in the registry. If the project root already
// exists in the registry, its entry is updated (name, targets, last_opened).
// Otherwise a new entry is appended.
func (r *Registry) AddOrUpdate(proj *Project) {
	if r == nil || proj == nil || proj.Root == "" {
		return
	}

	now := time.Now().UTC()
	root := filepath.Clean(proj.Root)

	for i := range r.entries {
		if filepath.Clean(r.entries[i].Root) == root {
			r.entries[i].Name = proj.Name()
			r.entries[i].Targets = proj.Targets()
			r.entries[i].LastOpened = now
			if r.entries[i].CreatedAt.IsZero() && proj.Manifest != nil {
				r.entries[i].CreatedAt = proj.Manifest.CreatedAt
			}
			r.modified = true
			return
		}
	}

	// New entry.
	entry := RegistryEntry{
		Name:       proj.Name(),
		Root:       root,
		Targets:    proj.Targets(),
		LastOpened: now,
	}
	if proj.Manifest != nil {
		entry.CreatedAt = proj.Manifest.CreatedAt
	}
	r.entries = append(r.entries, entry)
	r.modified = true
}

// Remove deletes a project from the registry by root path. The project
// directory itself is not touched — only the registry entry is removed.
func (r *Registry) Remove(root string) {
	if r == nil || root == "" {
		return
	}
	root = filepath.Clean(root)
	filtered := make([]RegistryEntry, 0, len(r.entries))
	for _, entry := range r.entries {
		if filepath.Clean(entry.Root) == root {
			r.modified = true
			continue
		}
		filtered = append(filtered, entry)
	}
	r.entries = filtered
}

// Entries returns a copy of the registry entries sorted by last opened
// (most recent first).
func (r *Registry) Entries() []RegistryEntry {
	if r == nil {
		return nil
	}
	r.sortByLastOpened()
	out := make([]RegistryEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

// FindByRoot looks up a registry entry by its absolute root path.
func (r *Registry) FindByRoot(root string) (*RegistryEntry, bool) {
	if r == nil || root == "" {
		return nil, false
	}
	root = filepath.Clean(root)
	for i := range r.entries {
		if filepath.Clean(r.entries[i].Root) == root {
			return &r.entries[i], true
		}
	}
	return nil, false
}

// Len returns the number of entries in the registry.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.entries)
}

// deduplicate removes entries with the same root path, keeping the most
// recently opened one.
func (r *Registry) deduplicate() {
	seen := make(map[string]int, len(r.entries)) // root -> index of best entry
	for i := range r.entries {
		root := filepath.Clean(r.entries[i].Root)
		if existing, ok := seen[root]; ok {
			// Keep the entry with the most recent LastOpened.
			if r.entries[i].LastOpened.After(r.entries[existing].LastOpened) {
				seen[root] = i
			}
		} else {
			seen[root] = i
		}
	}
	filtered := make([]RegistryEntry, 0, len(seen))
	for _, idx := range seen {
		filtered = append(filtered, r.entries[idx])
	}
	r.entries = filtered
}

// sortByLastOpened sorts entries by LastOpened descending (most recent first).
func (r *Registry) sortByLastOpened() {
	sort.Slice(r.entries, func(i, j int) bool {
		return r.entries[i].LastOpened.After(r.entries[j].LastOpened)
	})
}

// Name returns the project name from the manifest (safe for display).
func (p *Project) Name() string {
	if p == nil || p.Manifest == nil {
		return ""
	}
	return p.Manifest.Name
}

// Targets returns the project targets from the manifest.
func (p *Project) Targets() []string {
	if p == nil || p.Manifest == nil {
		return nil
	}
	return p.Manifest.Targets
}

// Description returns the project description.
func (p *Project) Description() string {
	if p == nil || p.Manifest == nil {
		return ""
	}
	return strings.TrimSpace(p.Manifest.Description)
}

// CreatedAt returns when the project was first created.
func (p *Project) CreatedAt() time.Time {
	if p == nil || p.Manifest == nil {
		return time.Time{}
	}
	return p.Manifest.CreatedAt
}

// UpdatedAt returns when the project was last modified.
func (p *Project) UpdatedAt() time.Time {
	if p == nil || p.Manifest == nil {
		return time.Time{}
	}
	return p.Manifest.UpdatedAt
}
