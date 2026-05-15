// Package reportfiles provides scoped filesystem access for report artifacts.
package reportfiles

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const MaxReportBytes int64 = 5 << 20

var allowedExtensions = map[string]struct{}{
	".csv":      {},
	".html":     {},
	".json":     {},
	".md":       {},
	".markdown": {},
	".txt":      {},
}

// Read reads a report artifact from root. Paths must be relative and stay under
// root.
func Read(root, path string, maxBytes int64) (string, []byte, error) {
	if maxBytes <= 0 || maxBytes > MaxReportBytes {
		maxBytes = MaxReportBytes
	}
	resolved, err := Resolve(root, path, false)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", nil, fmt.Errorf("stat report: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", nil, fmt.Errorf("report path must not be a symlink")
	}
	if info.IsDir() {
		return "", nil, fmt.Errorf("report path is a directory")
	}
	if info.Size() > maxBytes {
		return "", nil, fmt.Errorf("report is too large: %d bytes", info.Size())
	}
	file, err := os.Open(resolved)
	if err != nil {
		return "", nil, fmt.Errorf("open report: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return "", nil, fmt.Errorf("read report: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return "", nil, fmt.Errorf("report exceeds %d bytes", maxBytes)
	}
	return resolved, data, nil
}

// Write writes a report artifact under root. Paths must be relative and stay
// under root.
func Write(root, path, content string, overwrite bool) (string, int, error) {
	if int64(len(content)) > MaxReportBytes {
		return "", 0, fmt.Errorf("report content exceeds %d bytes", MaxReportBytes)
	}
	resolved, err := Resolve(root, path, true)
	if err != nil {
		return "", 0, err
	}
	if err := os.MkdirAll(filepath.Dir(resolved), 0o700); err != nil {
		return "", 0, fmt.Errorf("create report directory: %w", err)
	}
	if err := ensureParentUnderRoot(root, filepath.Dir(resolved)); err != nil {
		return "", 0, err
	}
	if info, err := os.Lstat(resolved); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", 0, fmt.Errorf("report path must not be a symlink")
		}
		if info.IsDir() {
			return "", 0, fmt.Errorf("report path is a directory")
		}
		if !overwrite {
			return "", 0, fmt.Errorf("report already exists")
		}
	} else if !os.IsNotExist(err) {
		return "", 0, fmt.Errorf("stat report: %w", err)
	}
	if err := os.WriteFile(resolved, []byte(content), 0o600); err != nil {
		return "", 0, fmt.Errorf("write report: %w", err)
	}
	return resolved, len(content), nil
}

// Resolve validates and resolves a relative report path under root.
func Resolve(root, path string, forWrite bool) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		root = "."
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("report path is required")
	}
	if filepath.IsAbs(path) {
		return "", fmt.Errorf("report path must be relative to the report directory")
	}
	clean := filepath.Clean(path)
	if clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", fmt.Errorf("report path must stay inside the report directory")
	}
	if _, ok := allowedExtensions[strings.ToLower(filepath.Ext(clean))]; !ok {
		return "", fmt.Errorf("unsupported report extension %q", filepath.Ext(clean))
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve report directory: %w", err)
	}
	if err := os.MkdirAll(absRoot, 0o700); err != nil {
		return "", fmt.Errorf("create report directory: %w", err)
	}
	resolved := filepath.Join(absRoot, clean)
	absResolved, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve report path: %w", err)
	}
	if err := ensureUnderRoot(absRoot, absResolved); err != nil {
		return "", err
	}
	if !forWrite {
		evalRoot, rootErr := filepath.EvalSymlinks(absRoot)
		evalPath, pathErr := filepath.EvalSymlinks(absResolved)
		if rootErr == nil && pathErr == nil {
			if err := ensureUnderRoot(evalRoot, evalPath); err != nil {
				return "", err
			}
		}
	}
	return absResolved, nil
}

func ensureUnderRoot(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return fmt.Errorf("compare report path: %w", err)
	}
	if rel == "." || rel == "" {
		return nil
	}
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		return fmt.Errorf("report path must stay inside the report directory")
	}
	return nil
}

func ensureParentUnderRoot(root, parent string) error {
	root = strings.TrimSpace(root)
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve report directory: %w", err)
	}
	evalRoot, rootErr := filepath.EvalSymlinks(absRoot)
	evalParent, parentErr := filepath.EvalSymlinks(parent)
	if rootErr != nil || parentErr != nil {
		return nil
	}
	return ensureUnderRoot(evalRoot, evalParent)
}
