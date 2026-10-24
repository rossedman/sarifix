package group

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/rossedman/sarifix/pkg/config"
	"github.com/rossedman/sarifix/pkg/finding"
	"github.com/rossedman/sarifix/pkg/policy"
)

// item builds a fixable item.
func item(scanner, rule, level, path string, line int) policy.Item {
	return policy.Item{
		Finding: finding.Finding{Tool: scanner, RuleID: rule, Level: level, Path: path, StartLine: line, Fingerprint: fmt.Sprintf("%s:%d", path, line)},
		Scanner: scanner,
	}
}

// limits returns batch limits.
func limits(files, findings, batches int) config.Limits {
	return config.Limits{FilesPerBatch: files, FindingsPerBatch: findings, BatchesPerRun: batches}
}

// ids lists batch IDs.
func ids(bs []Batch) []string {
	var out []string
	for _, b := range bs {
		out = append(out, b.ID())
	}
	return out
}

func TestBatchesGroupOrderAndCap(t *testing.T) {
	t.Parallel()
	camp := item("migrate", "OLD", "warning", "Dockerfile", 1)
	camp.Campaign = "base-v4"
	skipped := item("trivy", "SKIP", "error", "x", 1)
	skipped.Skip = policy.ReasonNotAllowed
	items := []policy.Item{
		item("trivy", "B", "warning", "a.tf", 1),
		item("trivy", "A", "error", "a.tf", 2),
		item("trivy", "B", "warning", "b.tf", 1),
		item("checkov", "C", "error", "a.tf", 3),
		item("trivy", "N", "note", "a.tf", 4),
		camp, skipped,
	}
	r := Batches(items, limits(10, 25, 3))
	// error before warning before note; ties: more findings first, then key.
	if got := ids(r.Run); !slices.Equal(got, []string{"checkov/C", "trivy/A", "trivy/B"}) {
		t.Errorf("run = %v", got)
	}
	if got := ids(r.Deferred); !slices.Equal(got, []string{"base-v4", "trivy/N"}) {
		t.Errorf("deferred = %v", got)
	}
	b := r.Run[2]
	if b.Scanner != "trivy" || b.RuleID != "B" || b.Level != "warning" || !slices.Equal(b.Files, []string{"a.tf", "b.tf"}) || len(b.Findings) != 2 {
		t.Errorf("trivy/B = %+v", b)
	}
	c := r.Deferred[0]
	if c.Campaign != "base-v4" || c.RuleID != "" || c.Branch("sarifix") != "sarifix/campaign/base-v4" {
		t.Errorf("campaign batch = %+v", c)
	}
	if r := Batches(items, limits(10, 25, 0)); len(r.Run) != 0 || len(r.Deferred) != 5 {
		t.Errorf("zero cap: %d run, %d deferred", len(r.Run), len(r.Deferred))
	}
	if r := Batches(nil, limits(1, 1, 1)); len(r.Run) != 0 || len(r.Deferred) != 0 {
		t.Error("empty input made batches")
	}
}

func TestBatchesGroupBy(t *testing.T) {
	t.Parallel()
	camp := item("trivy", "OLD", "error", "k8s.yaml", 9)
	camp.Campaign = "base-v4"
	items := []policy.Item{
		// Three trivy rules only in k8s.yaml, one only in other.yaml.
		item("trivy", "A", "warning", "k8s.yaml", 1),
		item("trivy", "B", "note", "k8s.yaml", 2),
		item("trivy", "C", "note", "k8s.yaml", 3),
		item("trivy", "A", "warning", "k8s.yaml", 4),
		item("trivy", "D", "warning", "other.yaml", 1),
		// A semgrep rule across two files, and one only in a.go.
		item("semgrep", "tls", "warning", "a.go", 1),
		item("semgrep", "tls", "warning", "b.go", 1),
		item("semgrep", "xss", "warning", "a.go", 2),
		camp,
	}
	all := func(r Result) []string { return append(ids(r.Run), ids(r.Deferred)...) }
	lim := limits(10, 25, 10)

	if got := all(Batches(items, lim)); !slices.Equal(got,
		[]string{"base-v4", "semgrep/tls", "trivy/A", "semgrep/xss", "trivy/D", "trivy/B", "trivy/C"}) {
		t.Errorf("rule = %v", got)
	}

	lim.GroupBy = config.GroupByAuto
	r := Batches(items, lim)
	// k8s.yaml's single-file rules merge; other.yaml and a.go have one each.
	if got := all(r); !slices.Equal(got, []string{"base-v4", "trivy:k8s.yaml", "semgrep/tls", "semgrep/xss", "trivy/D"}) {
		t.Errorf("auto = %v", got)
	}
	f := r.Run[1]
	if f.File != "k8s.yaml" || f.RuleID != "" || f.Level != "warning" || len(f.Findings) != 4 ||
		!slices.Equal(f.Rules, []string{"trivy/A", "trivy/B", "trivy/C"}) || !slices.Equal(f.Files, []string{"k8s.yaml"}) {
		t.Errorf("file batch = %+v", f)
	}
	if got := f.Branch("sarifix"); got != "sarifix/file/trivy/k8s.yaml" {
		t.Errorf("branch = %q", got)
	}
	if b := r.Run[2]; !slices.Equal(b.Rules, []string{"semgrep/tls"}) {
		t.Errorf("rule batch rules = %v", b.Rules)
	}

	lim.GroupBy = config.GroupByFile
	if got := all(Batches(items, lim)); !slices.Equal(got,
		[]string{"base-v4", "trivy:k8s.yaml", "semgrep:a.go", "semgrep:b.go", "trivy:other.yaml"}) {
		t.Errorf("file = %v", got)
	}
	// A file batch over findings_per_batch splits into parts.
	lim.FindingsPerBatch = 3
	if got := ids(Batches(items[:4], lim).Run); !slices.Equal(got, []string{"trivy:k8s.yaml", "trivy:k8s.yaml#2"}) {
		t.Errorf("split file = %v", got)
	}
}

func TestSplit(t *testing.T) {
	t.Parallel()
	var items []policy.Item
	// 3 files: a has 5 findings, b has 1, c has 2. Input order is shuffled.
	for _, x := range []struct {
		path string
		line int
	}{{"c", 2}, {"a", 5}, {"b", 1}, {"a", 1}, {"a", 3}, {"c", 1}, {"a", 2}, {"a", 4}} {
		items = append(items, item("t", "R", "error", x.path, x.line))
	}
	tests := []struct {
		files, findings int
		want            []string // each part as "file:line,..."
	}{
		{10, 25, []string{"a:1,a:2,a:3,a:4,a:5,b:1,c:1,c:2"}},
		{1, 25, []string{"a:1,a:2,a:3,a:4,a:5", "b:1", "c:1,c:2"}},
		{10, 3, []string{"a:1,a:2,a:3", "a:4,a:5,b:1", "c:1,c:2"}},
		{2, 6, []string{"a:1,a:2,a:3,a:4,a:5,b:1", "c:1,c:2"}},
		{0, 0, []string{"a:1", "a:2", "a:3", "a:4", "a:5", "b:1", "c:1", "c:2"}},
	}
	for _, tt := range tests {
		var got []string
		for _, part := range split(items, tt.files, tt.findings) {
			var s []string
			for _, it := range part {
				s = append(s, fmt.Sprintf("%s:%d", it.Path, it.StartLine))
			}
			got = append(got, strings.Join(s, ","))
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("files=%d findings=%d:\n got %q\nwant %q", tt.files, tt.findings, got, tt.want)
		}
	}
	// Parts of one key get numbered IDs and branches.
	r := Batches(items, limits(1, 25, 5))
	if got := ids(r.Run); !slices.Equal(got, []string{"t/R", "t/R#2", "t/R#3"}) {
		t.Errorf("ids = %v", got)
	}
	if got := r.Run[1].Branch("fix"); got != "fix/t/r-2" || r.Run[0].Branch("fix") != "fix/t/r" {
		t.Errorf("branch = %q", got)
	}
}

func TestSlug(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"errcheck":    "errcheck",
		"DS-0002":     "ds-0002",
		"CKV_AWS_144": "ckv_aws_144",
		"v1.2":        "v1.2",
	}
	for in, want := range tests {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
	// Changes beyond case get a hash, so these don't collide.
	a, b := Slug("go/sql-injection"), Slug("go-sql-injection")
	if a == b || !strings.HasPrefix(a, "go-sql-injection-") || b != "go-sql-injection" {
		t.Errorf("collision handling: %q %q", a, b)
	}
	if got := Slug("../..//"); len(got) != 6 {
		t.Errorf("all-unsafe slug = %q", got)
	}
	if got := Slug(""); len(got) != 6 {
		t.Errorf("empty slug = %q", got)
	}
	if got := Slug("x.lock"); !strings.HasPrefix(got, "x.lock-") {
		t.Errorf(".lock slug = %q", got)
	}
	if got := Slug("a..b"); !strings.HasPrefix(got, "a.b-") {
		t.Errorf("double dot = %q", got)
	}
	long := Slug(strings.Repeat("x", 100))
	if len(long) != maxSlug+7 {
		t.Errorf("long slug %q (%d)", long, len(long))
	}
}

func FuzzSlug(f *testing.F) {
	for _, s := range []string{"DS-0002", "go/sql-injection", "../x", "a..b", "CKV2_AWS_6", "日本", "", "x.lock"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := Slug(s)
		if got == "" || len(got) > maxSlug+7 {
			t.Fatalf("Slug(%q) = %q", s, got)
		}
		// Safe as one git ref component.
		for _, r := range got {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789._-", r) {
				t.Fatalf("Slug(%q) = %q has %q", s, got, r)
			}
		}
		if strings.Contains(got, "..") || strings.HasPrefix(got, ".") || strings.HasPrefix(got, "-") || strings.HasSuffix(got, ".") || strings.HasSuffix(got, ".lock") {
			t.Fatalf("Slug(%q) = %q is not a valid ref component", s, got)
		}
		if Slug(s) != got {
			t.Fatal("not deterministic")
		}
	})
}

func BenchmarkBatches(b *testing.B) {
	var items []policy.Item
	for i := range 20_000 {
		items = append(items, item("checkov", fmt.Sprintf("CKV_%d", i%50), "error", fmt.Sprintf("m%d/main.tf", i%400), i))
	}
	lim := limits(10, 25, 5)
	b.ReportAllocs()
	for b.Loop() {
		Batches(items, lim)
	}
}
