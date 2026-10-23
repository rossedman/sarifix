package plan

import (
	"slices"
	"testing"

	"github.com/rossedman/sarifix/pkg/config"
	"github.com/rossedman/sarifix/pkg/finding"
)

// f builds a located finding with a unique fingerprint.
func f(tool, rule, level, path, fp string) finding.Finding {
	return finding.Finding{Tool: tool, RuleID: rule, Level: level, Path: path, StartLine: 1, Fingerprint: fp}
}

func TestBuild(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Scanners = []config.Scanner{{Name: "trivy", Match: []string{"Trivy"}}}
	cfg.Rules.Allow = []string{"trivy/*"}
	cfg.Limits.BatchesPerRun = 1
	fs := []finding.Finding{
		f("Trivy", "A", "error", "a", "1"),
		f("Trivy", "B", "warning", "b", "2"),
		f("Trivy", "C", "error", "c", "3"),
		f("Other", "X", "error", "x", "4"),
		f("Trivy", "A", "error", "a2", "5"),
	}
	p := Build(cfg, fs, Options{Baseline: []finding.Finding{f("Trivy", "C", "error", "c", "3")}})
	var got []string
	for _, e := range p.Entries {
		got = append(got, e.Status.Status+":"+e.Status.Batch+":"+e.Status.Reason)
	}
	want := []string{"batched:trivy/A:", "deferred:trivy/B:", "skipped::in_baseline", "skipped::unrouted", "batched:trivy/A:"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v", got)
	}
	if e := p.Entries[0].Status; e.Branch != "sarifix/trivy/a" || e.RuleKey != "trivy/A" || e.Scanner != "trivy" || e.Fingerprint != "1" {
		t.Errorf("status %+v", e)
	}
	s := p.Summarize()
	if s.Findings != 5 || s.Batched != 2 || s.Deferred != 1 || len(s.Run) != 1 || len(s.Later) != 1 || s.Later[0].Key != "trivy/B" {
		t.Errorf("summary %+v", s)
	}
	if got := s.SkipCounts(); len(got) != 2 || got[0] != (SkipCount{"unrouted", 1}) || got[1] != (SkipCount{"in_baseline", 1}) {
		t.Errorf("skip counts %+v", got)
	}
	p.Annotate() // entries without a SARIF run are skipped, not a panic
}

func BenchmarkBuild(b *testing.B) {
	cfg := config.Default()
	cfg.Scanners = []config.Scanner{{Name: "trivy", Match: []string{"Trivy"}}}
	cfg.Rules.Allow = []string{"trivy/*"}
	var fs []finding.Finding
	for i := range 10_000 {
		fs = append(fs, f("Trivy", string(rune('A'+i%20)), "error", string(rune('a'+i%26)), string(rune(i))))
	}
	b.ReportAllocs()
	for b.Loop() {
		Build(cfg, fs, Options{})
	}
}
