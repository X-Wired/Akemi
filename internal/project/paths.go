// Package project manages Akemi engagement projects — organized, self-contained
// directories that group all scan archives, reports, graphs, logs, wordlists,
// and runtime state for a single engagement or recurring target.
//
// A project is defined by an akemi.project.toml manifest at its root. Once
// opened, every output Akemi produces routes into the project's directory
// tree instead of scattering files across the current working directory.
package project

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultDirPermissions are applied to project directories (owner-only).
const DefaultDirPermissions = 0o700

// DefaultFilePermissions are applied to sensitive project files (owner-only).
const DefaultFilePermissions = 0o600

// defaultLayout maps logical categories to their default directory names
// inside a project root. These are used as fallbacks when the manifest does
// not specify custom paths.
var defaultLayout = map[string]string{
	"archives":    "archives",
	"reports":     "reports",
	"graphs":      "graphs",
	"logs":        "logs",
	"wordlists":   "wordlists",
	"probes":      "probes",
	"screenshots": "screenshots",
	"dothound":    "dothound",
	"state":       ".akemi",
}

// ResolvePath returns the absolute path for a logical category within the
// project. If the project is nil, it falls back to a relative default under
// the current working directory (single-session mode).
func (p *Project) ResolvePath(category string) string {
	return p.resolvePath(category, true)
}

// ResolvePathIfExists is like ResolvePath but creates the directory only if
// the project is non-nil. In single-session mode it returns the fallback
// without creating anything.
func (p *Project) ResolvePathIfExists(category string) string {
	return p.resolvePath(category, false)
}

func (p *Project) resolvePath(category string, create bool) string {
	rel, ok := defaultLayout[category]
	if !ok {
		rel = category
	}

	if p != nil && p.Root != "" {
		// Check if the manifest overrides this category's path.
		if override := p.manifestPath(category); override != "" {
			rel = override
		}
		abs := filepath.Join(p.Root, rel)
		if create {
			_ = os.MkdirAll(abs, DefaultDirPermissions)
		}
		return abs
	}

	// Single-session fallback: use current working directory.
	if wd, err := os.Getwd(); err == nil {
		abs := filepath.Join(wd, rel)
		if create {
			_ = os.MkdirAll(abs, DefaultDirPermissions)
		}
		return abs
	}
	return rel
}

// manifestPath returns the configured relative path for a category, or empty
// string if the manifest uses defaults.
func (p *Project) manifestPath(category string) string {
	if p == nil || p.Manifest == nil {
		return ""
	}
	paths := p.Manifest.Paths
	switch category {
	case "archives":
		return strings.TrimSpace(paths.Archives)
	case "reports":
		return strings.TrimSpace(paths.Reports)
	case "graphs":
		return strings.TrimSpace(paths.Graphs)
	case "logs":
		return strings.TrimSpace(paths.Logs)
	case "wordlists":
		return strings.TrimSpace(paths.Wordlists)
	case "probes":
		return strings.TrimSpace(paths.Probes)
	case "screenshots":
		return strings.TrimSpace(paths.Screenshots)
	case "dothound":
		return strings.TrimSpace(paths.DotHound)
	case "state":
		return strings.TrimSpace(paths.State)
	default:
		return ""
	}
}

// DatabasePath returns the absolute path to the project's SQLite database.
func (p *Project) DatabasePath() string {
	if p == nil || p.Root == "" {
		return "akemi.db"
	}
	return filepath.Join(p.Root, "akemi.db")
}

// ManifestPath returns the absolute path to the project's manifest file.
func (p *Project) ManifestPath() string {
	if p == nil || p.Root == "" {
		return ""
	}
	return filepath.Join(p.Root, "akemi.project.toml")
}

// ensureDirectories creates every directory in the project layout.
func ensureDirectories(root string, paths ManifestPaths) error {
	dirs := []string{
		nonEmpty(paths.Archives, "archives"),
		nonEmpty(paths.Reports, "reports"),
		nonEmpty(paths.Graphs, "graphs"),
		nonEmpty(paths.Logs, "logs"),
		nonEmpty(paths.Wordlists, "wordlists"),
		nonEmpty(paths.Probes, "probes"),
		nonEmpty(paths.Screenshots, "screenshots"),
		nonEmpty(paths.DotHound, "dothound"),
		nonEmpty(paths.State, ".akemi"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(root, dir), DefaultDirPermissions); err != nil {
			return err
		}
	}
	return nil
}

func nonEmpty(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
