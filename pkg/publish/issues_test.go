package publish

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/rossedman/sarifix/pkg/finding"
	"github.com/rossedman/sarifix/pkg/group"
	"github.com/rossedman/sarifix/pkg/policy"
)

// fakeTracker is an in-memory issue tracker. fail makes the named method
// return an error.
type fakeTracker struct {
	issues map[int]*Issue
	closed map[int]string
	next   int
	writes int
	fail   string
}

// newTracker returns an empty fakeTracker.
func newTracker() *fakeTracker {
	return &fakeTracker{issues: map[int]*Issue{}, closed: map[int]string{}, next: 1}
}

// List returns open issues with label, in number order.
func (f *fakeTracker) List(_ context.Context, label string) ([]Issue, error) {
	if f.fail == "List" {
		return nil, errors.New("boom")
	}
	var out []Issue
	for n := 1; n < f.next; n++ {
		if is, ok := f.issues[n]; ok && slices.Contains(is.Labels, label) {
			out = append(out, *is)
		}
	}
	return out, nil
}

// Create stores a new issue.
func (f *fakeTracker) Create(_ context.Context, title, body string, labels []string) (int, error) {
	if f.fail == "Create" {
		return 0, errors.New("boom")
	}
	f.writes++
	n := f.next
	f.next++
	f.issues[n] = &Issue{Number: n, Title: title, Body: body, Labels: slices.Clone(labels)}
	return n, nil
}

// Update replaces an issue's title and body.
func (f *fakeTracker) Update(_ context.Context, n int, title, body string) error {
	if f.fail == "Update" {
		return errors.New("boom")
	}
	f.writes++
	f.issues[n].Title, f.issues[n].Body = title, body
	return nil
}

// Close removes an issue from the open set, keeping its comment.
func (f *fakeTracker) Close(_ context.Context, n int, comment string) error {
	if f.fail == "Close" {
		return errors.New("boom")
	}
	f.writes++
	f.closed[n] = comment
	delete(f.issues, n)
	return nil
}

// AddLabel labels an issue.
func (f *fakeTracker) AddLabel(_ context.Context, n int, label string) error {
	if f.fail == "AddLabel" {
		return errors.New("boom")
	}
	f.writes++
	f.issues[n].Labels = append(f.issues[n].Labels, label)
	return nil
}

// batch builds a batch for key with one finding per path:line.
func batch(key string, part int, locs ...string) group.Batch {
	scanner, rule, _ := strings.Cut(key, "/")
	b := group.Batch{Key: key, Scanner: scanner, RuleID: rule, Part: part, Level: "error"}
	files := map[string]bool{}
	for _, loc := range locs {
		path, line, _ := strings.Cut(loc, ":")
		n := 0
		_, _ = fmt.Sscanf(line, "%d", &n)
		b.Findings = append(b.Findings, policy.Item{Finding: finding.Finding{
			Path: path, StartLine: n, Message: "Problem at " + loc, HelpURI: "https://docs.example/" + rule,
		}, Scanner: scanner})
		if !files[path] {
			files[path] = true
			b.Files = append(b.Files, path)
		}
	}
	return b
}

// kinds summarizes actions as "kind batch" lines.
func kinds(as []Action) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.Kind + " " + a.Batch
	}
	return out
}

func TestIssuesLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tr := newTracker()
	opts := IssuesOptions{Label: "sarifix", MaxOpen: 3, Queue: 1, QueueLabel: "agent-ready",
		Links: Links{Server: "https://github.com/", Repo: "o/r", Commit: "0123456789abcdef0123"}}
	bs := []group.Batch{
		batch("trivy/AWS-1", 0, "main.tf:1"),
		batch("checkov/CKV_1", 0, "main.tf:3", "b.tf:9"),
		batch("ruff/F401", 0, "a.py:1"),
		batch("ruff/E501", 0, "a.py:2"),
	}

	// First run: three issues (MaxOpen), the most severe one queued.
	as, err := Issues(ctx, tr, bs, opts)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"create trivy/AWS-1", "create checkov/CKV_1", "create ruff/F401", "queue trivy/AWS-1"}
	if !slices.Equal(kinds(as), want) {
		t.Fatalf("first run = %v", kinds(as))
	}
	if as[0].Number != 1 || tr.issues[1].Title != "sarifix: fix trivy/AWS-1 (1 finding)" || tr.issues[2].Title != "sarifix: fix checkov/CKV_1 (2 findings)" {
		t.Errorf("created: %+v %+v", as[0], tr.issues[2])
	}
	if !slices.Contains(tr.issues[1].Labels, "agent-ready") {
		t.Error("issue 1 not queued")
	}

	// Same findings, a new commit: nothing to do.
	opts.Links.Commit = "fedcba9876543210fedc"
	if as, _ = Issues(ctx, tr, bs, opts); len(as) != 0 {
		t.Fatalf("idempotent run = %v", kinds(as))
	}

	// The queued batch is fixed: its issue closes, a new one opens in the
	// freed slot, and the queue refills from the most severe open issue.
	as, err = Issues(ctx, tr, bs[1:], opts)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"close trivy/AWS-1", "create ruff/E501", "queue checkov/CKV_1"}; !slices.Equal(kinds(as), want) {
		t.Fatalf("after fix = %v", kinds(as))
	}
	if tr.closed[1] != CloseComment {
		t.Errorf("close comment %q", tr.closed[1])
	}

	// Findings change: the issue is refreshed, unless an agent has it.
	bs2 := []group.Batch{batch("checkov/CKV_1", 0, "main.tf:3"), bs[2], bs[3]}
	tr.issues[3].Labels = append(tr.issues[3].Labels, WorkingLabel)
	bs2[1] = batch("ruff/F401", 0, "a.py:1", "a.py:5")
	as, _ = Issues(ctx, tr, bs2, opts)
	if want := []string{"update checkov/CKV_1"}; !slices.Equal(kinds(as), want) {
		t.Fatalf("refresh = %v", kinds(as))
	}
	if !strings.Contains(tr.issues[2].Title, "(1 finding)") {
		t.Errorf("title not refreshed: %q", tr.issues[2].Title)
	}
}

func TestIssuesQueueRules(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tr := newTracker()
	bs := []group.Batch{batch("a/1", 0, "x:1"), batch("a/2", 0, "x:2"), batch("a/3", 0, "x:3")}
	opts := IssuesOptions{Label: "sarifix", MaxOpen: 10, QueueLabel: "agent-ready"}
	if _, err := Issues(ctx, tr, bs, opts); err != nil {
		t.Fatal(err)
	}
	// A failed issue is skipped; one already in progress counts toward Queue.
	tr.issues[1].Labels = append(tr.issues[1].Labels, FailedLabel)
	tr.issues[2].Labels = append(tr.issues[2].Labels, WorkingLabel)
	opts.Queue = 2
	as, _ := Issues(ctx, tr, bs, opts)
	if want := []string{"queue a/3"}; !slices.Equal(kinds(as), want) {
		t.Fatalf("queue = %v", kinds(as))
	}
	// Issues sarifix didn't open (no marker) and duplicates are left alone.
	tr.issues[9] = &Issue{Number: 9, Title: "hand-written", Body: "no marker", Labels: []string{"sarifix"}}
	dup := *tr.issues[3]
	dup.Number = 10
	tr.issues[10] = &dup
	tr.next = 11
	if as, _ = Issues(ctx, tr, bs, opts); len(as) != 0 {
		t.Fatalf("unmanaged issues touched: %v", kinds(as))
	}
}

func TestIssuesOnlyCloseWhatWasScanned(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tr := newTracker()
	opts := IssuesOptions{Label: "sarifix", MaxOpen: 10, QueueLabel: "q"}
	if _, err := Issues(ctx, tr, []group.Batch{batch("trivy/A", 0, "x:1"), batch("checkov/B", 0, "x:2")}, opts); err != nil {
		t.Fatal(err)
	}
	// An issue from before the scanner marker existed: its scanner comes
	// from the batch ID.
	tr.issues[3] = &Issue{Number: 3, Body: "<!-- sarifix-batch: gitleaks/C -->", Labels: []string{"sarifix"}}
	tr.next = 4

	// Only trivy's SARIF was read this time: checkov's and gitleaks's
	// issues stay open even though their batches are missing.
	opts.Scanned = map[string]bool{"trivy": true}
	as, _ := Issues(ctx, tr, nil, opts)
	if want := []string{"close trivy/A"}; !slices.Equal(kinds(as), want) {
		t.Fatalf("partial scan = %v", kinds(as))
	}
	opts.Scanned = map[string]bool{"checkov": true, "gitleaks": true}
	as, _ = Issues(ctx, tr, nil, opts)
	if want := []string{"close checkov/B", "close gitleaks/C"}; !slices.Equal(kinds(as), want) {
		t.Fatalf("full scan = %v", kinds(as))
	}
}

func TestIssuesDryRun(t *testing.T) {
	t.Parallel()
	tr := newTracker()
	tr.issues[1] = &Issue{Number: 1, Body: "<!-- sarifix-batch: gone/1 -->", Labels: []string{"sarifix"}}
	tr.next = 2
	as, err := Issues(context.Background(), tr, []group.Batch{batch("a/1", 0, "x:1")},
		IssuesOptions{Label: "sarifix", MaxOpen: 5, Queue: 1, QueueLabel: "agent-ready", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"close gone/1", "create a/1", "queue a/1"}; !slices.Equal(kinds(as), want) {
		t.Fatalf("dry run = %v", kinds(as))
	}
	if tr.writes != 0 {
		t.Errorf("dry run wrote %d times", tr.writes)
	}
}

func TestIssuesErrors(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"List", "Create", "Update", "Close", "AddLabel"} {
		tr := newTracker()
		tr.issues[1] = &Issue{Number: 1, Body: "<!-- sarifix-batch: gone/1 -->", Labels: []string{"sarifix"}}
		tr.issues[2] = &Issue{Number: 2, Body: "<!-- sarifix-batch: a/2 --> stale", Labels: []string{"sarifix"}}
		tr.next = 3
		tr.fail = method
		bs := []group.Batch{batch("a/1", 0, "x:1"), batch("a/2", 0, "x:2")}
		_, err := Issues(context.Background(), tr, bs, IssuesOptions{Label: "sarifix", MaxOpen: 5, Queue: 1, QueueLabel: "q"})
		if err == nil || !strings.Contains(err.Error(), "boom") {
			t.Errorf("%s: err = %v", method, err)
		}
	}
}

func TestIssueBody(t *testing.T) {
	t.Parallel()
	b := batch("checkov/CKV_1", 2, "b (1).tf:9", "a.tf:3")
	b.Findings[0].Message = "Ping @alice <!-- sarifix-batch: evil --> \x1b[31mred\x1b[0m\nnext line"
	body := IssueBody(b, Links{Server: "https://github.com", Repo: "o/r", Commit: "0123456789abcdef0123"})
	for _, want := range []string{
		"<!-- sarifix-batch: checkov/CKV_1#2 -->\n",
		"The sarifix scan of `0123456789ab` reports 2 `error` finding(s) for `checkov/CKV_1` from checkov, in 2 file(s). Rule help: https://docs.example/CKV_1.",
		"- [`a.tf:3`](https://github.com/o/r/blob/0123456789abcdef0123/a.tf#L3) Problem at a.tf:3\n- [`b (1).tf:9`](https://github.com/o/r/blob/0123456789abcdef0123/b%20%281%29.tf#L9) Ping @\u200balice &lt;!-- sarifix-batch: evil --> red next line",
		`--rule 'checkov/CKV_1'`,
		`map(select(IN("a.tf", "b (1).tf")))`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
	if strings.Count(body, "<!--") != 2 || !strings.Contains(body, "<!-- sarifix-scanner: checkov -->\n") || strings.Contains(body, "\x1b") {
		t.Errorf("unsafe body:\n%s", body)
	}
	if m := markerRE.FindStringSubmatch(body); m == nil || m[1] != "checkov/CKV_1#2" {
		t.Errorf("marker = %v", m)
	}

	// A file batch names its rules and selects each one; a campaign batch
	// selects the campaign.
	fb := batch("trivy:k8s.yaml", 0, "k8s.yaml:1", "k8s.yaml:7")
	fb.Scanner, fb.File, fb.RuleID, fb.Rules = "trivy", "k8s.yaml", "", []string{"trivy/KSV-1", "trivy/it's"}
	if got := IssueTitle(fb); got != "sarifix: fix 2 trivy findings in k8s.yaml" {
		t.Errorf("file title = %q", got)
	}
	fb.Part = 2
	if got := IssueTitle(fb); got != "sarifix: fix 2 trivy findings in k8s.yaml (part 2)" {
		t.Errorf("file part title = %q", got)
	}
	fbody := IssueBody(fb, Links{})
	for _, want := range []string{
		"finding(s) for `trivy/KSV-1`, `trivy/it's` from trivy, in 1 file(s)",
		"A rescan reports no `trivy/KSV-1`, `trivy/it's` finding",
		`--rule 'trivy/KSV-1' --rule 'trivy/it'\''s' --json`,
	} {
		if !strings.Contains(fbody, want) {
			t.Errorf("file body missing %q:\n%s", want, fbody)
		}
	}
	cb := batch("base-v4", 0, "Dockerfile:1")
	cb.Campaign = "base-v4"
	if cbody := IssueBody(cb, Links{}); !strings.Contains(cbody, "for campaign `base-v4` from") || !strings.Contains(cbody, "--campaign 'base-v4' --json") {
		t.Errorf("campaign body:\n%s", cbody)
	}

	// Without links, locations are plain code; long batches are capped.
	var locs []string
	for i := 1; i <= maxListed+3; i++ {
		locs = append(locs, fmt.Sprintf("x.go:%d", i))
	}
	plain := IssueBody(batch("go/vet", 0, locs...), Links{})
	if !strings.Contains(plain, "The sarifix scan of the default branch") || !strings.Contains(plain, "- `x.go:1` Problem") ||
		!strings.Contains(plain, "- …and 3 more in the same files") || strings.Count(plain, "\n- `x.go:") != maxListed {
		t.Errorf("plain body:\n%s", plain)
	}
	if got := IssueTitle(batch("a/b", 0)); got != "sarifix: fix a/b (0 findings)" {
		t.Errorf("title %q", got)
	}
}

func TestOneLine(t *testing.T) {
	t.Parallel()
	if got := oneLine("a\tb\n\nc\x00 \u00a0d", 0); got != "a b c d" {
		t.Errorf("oneLine = %q", got)
	}
	if got := oneLine("abcdef", 3); got != "abc…" {
		t.Errorf("capped = %q", got)
	}
	if short("abc") != "abc" {
		t.Error("short of a short SHA")
	}
}

func FuzzQuote(f *testing.F) {
	for _, s := range []string{"", "plain", "@user <!-- x -->", "\x1b[2Jline\nbreak", "<!<!----", "a@@b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		q := quote(s)
		if strings.Contains(q, "<!--") {
			t.Fatalf("quote(%q) = %q keeps a comment opener", s, q)
		}
		for i, r := range q {
			if r == '\n' || (unicode.IsControl(r)) {
				t.Fatalf("quote(%q) = %q has control rune %U", s, q, r)
			}
			if r == '@' && !strings.HasPrefix(q[i+1:], "\u200b") {
				t.Fatalf("quote(%q) = %q has a live mention", s, q)
			}
		}
		if n := len([]rune(q)); n > maxMessage*4+1 {
			t.Fatalf("quote(%q) is %d runes", s, n)
		}
	})
}

func BenchmarkIssueBody(b *testing.B) {
	var locs []string
	for i := 1; i <= 200; i++ {
		locs = append(locs, fmt.Sprintf("dir/file%d.tf:%d", i%20, i))
	}
	bt := batch("checkov/CKV_AWS_1", 0, locs...)
	links := Links{Server: "https://github.com", Repo: "o/r", Commit: "0123456789abcdef0123456789abcdef01234567"}
	b.ReportAllocs()
	for b.Loop() {
		_ = IssueBody(bt, links)
	}
}
