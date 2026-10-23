package baseline

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/rossedman/sarifix/pkg/finding"
	"github.com/rossedman/sarifix/pkg/sarif"
)

// load extracts the findings for one fixture repo.
func load(t testing.TB, repo string) []finding.Finding {
	t.Helper()
	log, warns, err := sarif.LoadGlobs([]string{filepath.Join("..", "..", "testdata", "sarif", repo, "*.sarif")}, sarif.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warns {
		t.Errorf("warning: %s", w)
	}
	ex, err := finding.NewExtractor(filepath.Join("..", "..", "testdata", "repos", repo))
	if err != nil {
		t.Fatal(err)
	}
	return ex.Extract(log)
}

// keys returns sorted rule keys of fs.
func keys(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, finding.RuleKey(f.Tool, f.RuleID))
	}
	slices.Sort(out)
	return out
}

// TestShiftedLines diffs real scanner output for the basic fixture repo
// against the same repo with lines inserted above every finding.
func TestShiftedLines(t *testing.T) {
	t.Parallel()
	base, head := load(t, "basic"), load(t, "shifted")
	if len(base) != 28 || len(head) != 28 {
		t.Fatalf("got %d base and %d head findings, want 28 each", len(base), len(head))
	}
	d := Compare(base, head)
	// Checkov reports these two rules against the whole Dockerfile, so the
	// inserted lines are inside their region: a real content change.
	wholeFile := []string{"Checkov/CKV_DOCKER_2", "Checkov/CKV_DOCKER_3"}
	if got := keys(d.New); !slices.Equal(got, wholeFile) {
		t.Errorf("new = %v, want %v", got, wholeFile)
	}
	if got := keys(d.Fixed); !slices.Equal(got, wholeFile) {
		t.Errorf("fixed = %v, want %v", got, wholeFile)
	}
	if len(d.Unchanged) != 26 {
		t.Errorf("unchanged = %d, want 26", len(d.Unchanged))
	}
	// Each scanner whose findings moved still matches them. (The custom
	// tool's FROM line stays on line 1 in the shifted fixture.)
	moved := map[string]bool{}
	for _, f := range d.Unchanged {
		for _, b := range base {
			if b.Fingerprint == f.Fingerprint && b.StartLine != f.StartLine {
				moved[f.Tool] = true
			}
		}
	}
	for _, tool := range []string{"Trivy", "Checkov", "golangci-lint"} {
		if !moved[tool] {
			t.Errorf("no shifted-but-unchanged finding for %s", tool)
		}
	}
}

func TestCompareMultiset(t *testing.T) {
	t.Parallel()
	f := func(fp string) finding.Finding { return finding.Finding{Fingerprint: fp} }
	d := Compare(
		[]finding.Finding{f("a"), f("b"), f("b")},
		[]finding.Finding{f("b"), f("c"), f("c")},
	)
	if len(d.Unchanged) != 1 || len(d.New) != 2 || len(d.Fixed) != 2 {
		t.Fatalf("got %+v", d)
	}
	if d.Fixed[0].Fingerprint != "a" || d.Fixed[1].Fingerprint != "b" {
		t.Errorf("fixed = %+v", d.Fixed)
	}
	if got := NewOnly(nil, []finding.Finding{f("x")}); len(got) != 1 {
		t.Errorf("NewOnly = %+v", got)
	}
}

func BenchmarkCompare(b *testing.B) {
	base := make([]finding.Finding, 100_000)
	head := make([]finding.Finding, 100_000)
	for i := range base {
		base[i].Fingerprint = fmt.Sprintf("fp%d:1", i)
		head[i].Fingerprint = fmt.Sprintf("fp%d:1", i+10_000)
	}
	b.ReportAllocs()
	for b.Loop() {
		Compare(base, head)
	}
}
