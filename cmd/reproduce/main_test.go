package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestDiscoverSourceFilesIncludesUntrackedGoFiles(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	// testdata is ignored by the Go tool, so the probe file cannot become a
	// package that concurrently running tests would load.
	const name = "cmd/reproduce/testdata/reproduce-discovery-test.go"
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("package probe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })

	files, err := discoverSourceFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{name, "go.mod", "go.sum", "cmd/reproduce/main_test.go"} {
		if !slices.Contains(files, required) {
			t.Errorf("source list does not contain %q", required)
		}
	}
}

func TestPublishEvidenceReplacesBothArtifacts(t *testing.T) {
	dir := t.TempDir()
	if err := publishEvidence(dir, []byte("output"), []byte("result")); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"test-output.txt": "output", "results.json": "result"} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}
