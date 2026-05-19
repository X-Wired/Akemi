package project

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"Akemi/internal/persist"
)

// Project represents an Akemi engagement project — a self-contained directory
// that groups all scan output, reports, state, and configuration for a single
// engagement or recurring target.
//
// A project is valid when:
//   - Root points to an existing directory
//   - An akemi.project.toml manifest exists at Root
//   - The standard directory layout exists (created on demand)
//
// When Project is nil, Akemi operates in single-session mode with no
// project-scoped persistence.
type Project struct {
	Root     string           // Absolute path to the project root directory
	Manifest *ProjectManifest // Loaded from akemi.project.toml; never nil for a valid project
	DB       *persist.DB      // Project-scoped SQLite connection (nil until opened)
}

// ── Constructors ──────────────────────────────────────────────────────

// CreateProject initializes a new Akemi project at the given directory.
// It creates the directory tree, writes the manifest, opens the database,
// and registers the project in the global registry.
//
// The provided name is sanitized into a filesystem-safe form. The directory
// must not already contain a valid project (akemi.project.toml).
func CreateProject(root string, name string) (*Project, error) {
	root, err := validateRoot(root)
	if err != nil {
		return nil, err
	}

	// Ensure the directory exists (or create it).
	if err := os.MkdirAll(root, DefaultDirPermissions); err != nil {
		return nil, fmt.Errorf("create project directory: %w", err)
	}

	// Refuse to overwrite an existing project.
	manifestPath := filepath.Join(root, "akemi.project.toml")
	if _, err := os.Stat(manifestPath); err == nil {
		return nil, fmt.Errorf("project already exists at %s (akemi.project.toml found)", root)
	}

	manifest := NewManifest(name)
	if err := WriteManifest(manifestPath, manifest); err != nil {
		return nil, fmt.Errorf("write manifest: %w", err)
	}

	// Create the standard directory layout.
	if err := ensureDirectories(root, manifest.Paths); err != nil {
		return nil, fmt.Errorf("create project directories: %w", err)
	}

	// Open the project-scoped database.
	dbPath := filepath.Join(root, "akemi.db")
	db, err := persist.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open project database: %w", err)
	}

	proj := &Project{
		Root:     root,
		Manifest: manifest,
		DB:       db,
	}

	// Register in the global projects list.
	registry, err := LoadRegistry()
	if err == nil {
		registry.AddOrUpdate(proj)
		_ = registry.Save()
	}

	return proj, nil
}

// OpenProject opens an existing Akemi project from the given directory.
// It validates the manifest, opens the database, ensures the directory
// layout exists, updates the registry, and touches the manifest.
func OpenProject(root string) (*Project, error) {
	root, err := validateRoot(root)
	if err != nil {
		return nil, err
	}

	manifestPath := filepath.Join(root, "akemi.project.toml")
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("not a valid Akemi project at %s: %w", root, err)
	}

	// Ensure the standard layout exists (operator might have deleted a folder).
	if err := ensureDirectories(root, manifest.Paths); err != nil {
		return nil, fmt.Errorf("ensure project directories: %w", err)
	}

	// Open the database.
	dbPath := filepath.Join(root, "akemi.db")
	db, err := persist.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open project database: %w", err)
	}

	proj := &Project{
		Root:     root,
		Manifest: manifest,
		DB:       db,
	}

	// Touch and register.
	manifest.Touch()
	_ = WriteManifest(manifestPath, manifest)

	registry, err := LoadRegistry()
	if err == nil {
		registry.AddOrUpdate(proj)
		_ = registry.Save()
	}

	return proj, nil
}

// DetectProject walks up from the current working directory (or the provided
// hint) looking for an akemi.project.toml. Returns nil if no project is found.
// This is used for the "auto-detect" behavior when the user runs akemi inside
// a project directory without explicitly passing --project.
func DetectProject(hint string) (*Project, error) {
	start := hint
	if start == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, nil // can't detect, not an error
		}
		start = wd
	}

	start, err := filepath.Abs(start)
	if err != nil {
		return nil, nil
	}

	// Walk up the directory tree looking for akemi.project.toml.
	for {
		manifestPath := filepath.Join(start, "akemi.project.toml")
		if info, err := os.Stat(manifestPath); err == nil && !info.IsDir() {
			return OpenProject(start)
		}

		parent := filepath.Dir(start)
		if parent == start {
			break // reached filesystem root
		}
		start = parent
	}

	return nil, nil
}

// ── Lifecycle ─────────────────────────────────────────────────────────

// Close releases resources held by the project (database connection, etc.).
// It is safe to call on a nil Project.
func (p *Project) Close() error {
	if p == nil {
		return nil
	}
	if p.DB != nil {
		if err := p.DB.Close(); err != nil {
			return fmt.Errorf("close project database: %w", err)
		}
		p.DB = nil
	}
	return nil
}

// SaveManifest writes the current manifest back to disk. Call this after
// mutating the manifest (e.g., adding targets, changing scope).
func (p *Project) SaveManifest() error {
	if p == nil || p.Manifest == nil {
		return fmt.Errorf("no project loaded")
	}
	p.Manifest.Touch()
	return WriteManifest(p.ManifestPath(), p.Manifest)
}

// AddTarget appends a target to the manifest and persists it.
func (p *Project) AddTarget(target string) error {
	if p == nil || p.Manifest == nil {
		return fmt.Errorf("no project loaded")
	}
	p.Manifest.AddTarget(target)
	return p.SaveManifest()
}

// ── Queries ───────────────────────────────────────────────────────────

// IsSingleSession reports whether the project is nil (single-session mode).
func (p *Project) IsSingleSession() bool {
	return p == nil
}

// DisplayName returns the project name for UI purposes. Falls back to the
// directory name if the manifest is missing.
func (p *Project) DisplayName() string {
	if p == nil {
		return "Single Session"
	}
	if p.Manifest != nil && p.Manifest.Name != "" {
		return p.Manifest.Name
	}
	return filepath.Base(p.Root)
}

// Stats returns basic statistics about the project: number of scan sessions,
// total findings, and the last activity timestamp.
func (p *Project) Stats() (*ProjectStats, error) {
	if p == nil || p.DB == nil {
		return nil, fmt.Errorf("no project database available")
	}
	dbStats, err := p.DB.GetStats()
	if err != nil {
		return nil, fmt.Errorf("query project stats: %w", err)
	}
	return &ProjectStats{
		TotalSessions: dbStats.TotalSessions,
		TotalFindings: dbStats.TotalFindings,
		FindingsBySev: dbStats.FindingsBySev,
		RecentTargets: dbStats.RecentTargets,
	}, nil
}

// ProjectStats holds aggregate statistics for a project.
type ProjectStats struct {
	TotalSessions int
	TotalFindings int
	FindingsBySev map[string]int
	RecentTargets []string
	LastActivity  time.Time
}

// ── Helpers ───────────────────────────────────────────────────────────

// validateRoot validates and normalizes a user-provided project root path.
func validateRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("project directory is required")
	}

	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve project path: %w", err)
	}

	// Clean the path to remove trailing separators and redundant dots.
	abs = filepath.Clean(abs)

	// Security: refuse to create projects at filesystem roots.
	if abs == "/" || abs == "\\" || len(abs) <= 3 && strings.HasSuffix(abs, ":\\") {
		return "", fmt.Errorf("refusing to create project at filesystem root")
	}

	// The directory can exist or be created later. We only check that the
	// parent is writable if the directory already exists.
	if info, err := os.Stat(abs); err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("%s exists but is not a directory", abs)
		}
	} else if os.IsNotExist(err) {
		// Parent must exist and be writable.
		parent := filepath.Dir(abs)
		if parentInfo, err := os.Stat(parent); err != nil || !parentInfo.IsDir() {
			return "", fmt.Errorf("parent directory %s does not exist", parent)
		}
	}

	return abs, nil
}

// IsProjectRoot checks whether the given directory contains an
// akemi.project.toml — a quick way to test if a path is a valid project.
func IsProjectRoot(path string) bool {
	info, err := os.Stat(filepath.Join(path, "akemi.project.toml"))
	return err == nil && !info.IsDir()
}
