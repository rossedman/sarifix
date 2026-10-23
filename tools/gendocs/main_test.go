package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	t.Parallel()
	out := t.TempDir()
	stale := filepath.Join(out, "commands", "sarifix_gone.md")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	if code := run([]string{"-out", out}, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	for _, name := range []string{"sarifix.md", "sarifix_scan.md", "sarifix_diff.md", "sarifix_config_validate.md", "sarifix_version.md"} {
		data, err := os.ReadFile(filepath.Join(out, "commands", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(data, []byte("---\ntitle: ")) {
			t.Errorf("%s: no front matter", name)
		}
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("stale page kept")
	}
	ref, err := os.ReadFile(filepath.Join(out, "config.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| `scanners[].timeout` | duration | `5m` |", "## `publish`", "### `publish.pr`", "| `limits.retries` | int | `2` |", "| `scanners[].name` | string | required |"} {
		if !strings.Contains(string(ref), want) {
			t.Errorf("config.md lacks %q", want)
		}
	}
}

func TestRunErrors(t *testing.T) {
	t.Parallel()
	var errb bytes.Buffer
	if code := run([]string{"-bogus"}, &errb); code != 2 {
		t.Errorf("bad flag: %d", code)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"-out", file}, &errb); code != 1 {
		t.Errorf("out is a file: %d", code)
	}
	ro := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ro, "config.md", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"-out", ro}, &errb); code != 1 {
		t.Errorf("config.md is a dir: %d", code)
	}
}
