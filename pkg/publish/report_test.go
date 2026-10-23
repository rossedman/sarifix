package publish

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rossedman/sarifix/pkg/config"
	"github.com/rossedman/sarifix/pkg/finding"
	"github.com/rossedman/sarifix/pkg/plan"
	"github.com/rossedman/sarifix/pkg/sarif"
)

func TestReport(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "testdata")
	log, _, err := sarif.LoadFile(filepath.Join(root, "sarif", "basic", "golangci-lint.sarif"), sarif.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ex, err := finding.NewExtractor(filepath.Join(root, "repos", "basic"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Scanners = []config.Scanner{{Name: "golangci-lint", Match: []string{"golangci-lint"}}}
	cfg.Rules.Allow = []string{"golangci-lint/errcheck"}
	p := plan.Build(cfg, ex.Extract(log), plan.Options{})

	dir := t.TempDir()
	files, err := Report(dir, log, p)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(files.SARIF)
	if err != nil {
		t.Fatal(err)
	}
	if err := sarif.Validate(data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"branch": "sarifix/golangci-lint/errcheck"`) {
		t.Errorf("no status in %s", data)
	}
	sum, err := os.ReadFile(files.Summary)
	if err != nil || !strings.Contains(string(sum), `"batched": 1`) {
		t.Errorf("summary %s %v", sum, err)
	}

	// Unwritable locations fail with the step named.
	if _, err := Report("/dev/null/x", log, p); err == nil || !strings.Contains(err.Error(), "enriched SARIF") {
		t.Errorf("sarif error: %v", err)
	}
	blocked := t.TempDir()
	if err := os.Mkdir(filepath.Join(blocked, ReportSummary), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Report(blocked, log, p); err == nil || !strings.Contains(err.Error(), "summary") {
		t.Errorf("summary error: %v", err)
	}
}
