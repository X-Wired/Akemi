package core

import (
	"io/fs"
	"os"
	"path/filepath"
)

// ResolveProbeTemplateDir tries to locate the probes directory even when the
// current working directory is not the repository root.
func ResolveProbeTemplateDir(dir string) string {
	if dir == "" {
		dir = "./probes"
	}

	if filepath.IsAbs(dir) {
		return dir
	}

	var existingFallback string
	for _, base := range candidateBaseDirs() {
		candidate := filepath.Clean(filepath.Join(base, dir))
		if !dirExists(candidate) {
			continue
		}
		if existingFallback == "" {
			existingFallback = candidate
		}
		if dirContainsProbeTemplates(candidate) {
			return candidate
		}
	}

	if existingFallback != "" {
		return existingFallback
	}

	return dir
}

func candidateBaseDirs() []string {
	var bases []string
	seen := make(map[string]struct{})

	addBaseChain := func(start string) {
		start = filepath.Clean(start)
		for i := 0; i < 6; i++ {
			if _, ok := seen[start]; ok {
				// continue walking parents in case a higher level is new
			} else {
				seen[start] = struct{}{}
				bases = append(bases, start)
			}
			parent := filepath.Dir(start)
			if parent == start {
				return
			}
			start = parent
		}
	}

	if wd, err := os.Getwd(); err == nil {
		addBaseChain(wd)
	}
	if exePath, err := os.Executable(); err == nil {
		addBaseChain(filepath.Dir(exePath))
	}

	return bases
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func dirContainsProbeTemplates(path string) bool {
	found := false
	_ = filepath.WalkDir(path, func(current string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := filepath.Ext(d.Name())
		if ext == ".yml" || ext == ".yaml" {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}
