package gofiles

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWalk(t *testing.T) {
	t.Chdir(filepath.Join("..", "..", ".."))
	files, err := Walk([]string{"./...", "tools/internal/gofiles"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f.Path] {
			t.Errorf("duplicate %s", f.Path)
		}
		seen[f.Path] = true
		if filepath.Base(filepath.Dir(f.Path)) == "testdata" {
			t.Errorf("walked testdata: %s", f.Path)
		}
	}
	if !seen["tools/internal/gofiles/gofiles.go"] || !seen["cmd/sarifix/main.go"] {
		t.Errorf("missing files: %d walked", len(files))
	}
	if seen["tools/internal/gofiles/gofiles_test.go"] {
		t.Error("walked a test file")
	}
	gen, err := Walk([]string{"tools/doccheck/testdata/gen"})
	if err != nil || len(gen) != 1 || !gen[0].Generated {
		t.Errorf("generated detection: %v %+v", err, gen)
	}
	mod, err := ModulePath()
	if err != nil || mod != "github.com/rossedman/sarifix" {
		t.Errorf("module %q %v", mod, err)
	}
}

func TestWalkErrors(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("bad.go", []byte("package"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Walk([]string{"."}); err == nil {
		t.Error("parse error swallowed")
	}
	if _, err := ModulePath(); err == nil {
		t.Error("missing go.mod accepted")
	}
	if err := os.WriteFile("go.mod", []byte("go 1.27\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ModulePath(); err == nil {
		t.Error("go.mod without module accepted")
	}
}
