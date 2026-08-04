package archive

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLoadLatestArchiveFindsNewestNestedArchive(t *testing.T) {
	root := t.TempDir()
	earlier := New(ScanConfig{Target: "https://earlier.example"}, "earlier", Results{}, nil)
	earlier.ExportedAt = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	earlierPath := filepath.Join(root, "earlier.example", "earlier.example.akemi")
	if err := WriteFile(earlierPath, earlier); err != nil {
		t.Fatalf("write earlier archive: %v", err)
	}

	latest := New(ScanConfig{Target: "https://latest.example"}, "latest", Results{}, nil)
	latest.ExportedAt = time.Date(2026, time.January, 2, 0, 0, 0, 0, time.UTC)
	latestPath := filepath.Join(root, "nested", "latest.example", "latest.example.akemi")
	if err := WriteFile(latestPath, latest); err != nil {
		t.Fatalf("write latest archive: %v", err)
	}

	loaded, path, err := LoadLatestArchive(root)
	if err != nil {
		t.Fatalf("load latest archive: %v", err)
	}
	if path != latestPath {
		t.Fatalf("loaded path = %q, want %q", path, latestPath)
	}
	if loaded == nil || loaded.Config.Target != "https://latest.example" {
		t.Fatalf("loaded archive = %#v, want latest archive", loaded)
	}
}

func TestLoadLatestArchiveReturnsNoArchiveForMissingDirectory(t *testing.T) {
	file, path, err := LoadLatestArchive(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatalf("missing archive directory should not fail: %v", err)
	}
	if file != nil || path != "" {
		t.Fatalf("missing archive directory = (%#v, %q), want (nil, empty)", file, path)
	}
}
