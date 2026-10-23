package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
	var out, errb bytes.Buffer
	// Run from the module root so go.mod is found.
	t.Chdir(filepath.Join("..", ".."))
	if code := run([]string{"tools/doccheck/testdata/gen"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	if got := out.String(); got != "github.com/rossedman/sarifix/tools/doccheck/testdata/gen/gen.go:\n" {
		t.Errorf("got %q", got)
	}
	out.Reset()
	if code := run(nil, &out, &errb); code != 0 || out.String() != "#no-generated-files#\n" {
		t.Errorf("default: %d %q", code, out.String())
	}
	if code := run([]string{"nope"}, &out, &errb); code != 2 {
		t.Errorf("bad dir: %d", code)
	}
	t.Chdir(t.TempDir())
	if err := os.WriteFile("x.go", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run(nil, &out, &errb); code != 2 {
		t.Errorf("no go.mod: %d", code)
	}
}
