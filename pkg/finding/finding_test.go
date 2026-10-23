package finding

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rossedman/sarifix/internal/testutil"
	"github.com/rossedman/sarifix/pkg/sarif"
)

// testdata is the repo-level testdata directory.
var testdata = filepath.Join("..", "..", "testdata")

// extract loads one SARIF fixture and extracts it against root.
func extract(t testing.TB, file, root string) ([]Finding, *sarif.Log) {
	t.Helper()
	log, warns, err := sarif.LoadFile(filepath.Join(testdata, "sarif", file), sarif.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) > 0 {
		t.Fatalf("warnings: %v", warns)
	}
	ex, err := NewExtractor(root)
	if err != nil {
		t.Fatal(err)
	}
	return ex.Extract(log), log
}

func TestExtractRealScanners(t *testing.T) {
	t.Parallel()
	root := filepath.Join(testdata, "repos", "basic")
	tests := []struct {
		file, tool, rule, path string
		line                   int
		level, snippet         string
	}{
		{"basic/trivy.sarif", "Trivy", "DS-0025", "Dockerfile", 2, "error", "RUN apk add curl"},
		{"basic/checkov.sarif", "Checkov", "CKV_AWS_24", "main.tf", 5, "error", `resource "aws_security_group" "web" {`},
		{"basic/golangci-lint.sarif", "golangci-lint", "errcheck", "main.go", 8, "error", "f.Close()"},
		{"basic/image-migrate.sarif", "image-migrate", "DEPRECATED_BASE", "Dockerfile", 1, "warning", "FROM alpine:3.18"},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			t.Parallel()
			fs, _ := extract(t, tt.file, root)
			var f *Finding
			for i := range fs {
				if fs[i].RuleID == tt.rule {
					f = &fs[i]
				}
			}
			if f == nil {
				t.Fatalf("no %s finding", tt.rule)
			}
			if f.Tool != tt.tool || f.Path != tt.path || f.StartLine != tt.line || f.Level != tt.level {
				t.Errorf("got %+v", *f)
			}
			if !strings.Contains(f.Snippet, tt.snippet) {
				t.Errorf("snippet %q lacks %q", f.Snippet, tt.snippet)
			}
			if f.Message == "" || f.Fingerprint == "" || !f.Located() {
				t.Errorf("incomplete finding %+v", *f)
			}
		})
	}
}

func TestExtractEdgeCases(t *testing.T) {
	t.Parallel()
	fs, _ := extract(t, "broken/edge.sarif", t.TempDir())
	if len(fs) != 7 { // the kind=pass result is not a finding
		t.Fatalf("got %d findings", len(fs))
	}
	dup1, dup2 := fs[0], fs[1]
	if dup1.Path != "src/a.go" || dup1.Snippet != "  same   line  " || dup1.HelpText != "**help one**" {
		t.Errorf("dup1 %+v", dup1)
	}
	// Same tool, rule, path and collapsed snippet: distinct by occurrence.
	if dup1.Fingerprint == dup2.Fingerprint || strings.TrimSuffix(dup1.Fingerprint, ":1") != strings.TrimSuffix(dup2.Fingerprint, ":2") {
		t.Errorf("occurrence numbering: %s %s", dup1.Fingerprint, dup2.Fingerprint)
	}
	md := fs[2]
	if md.Path != "b c.tf" || md.Message != "md only" || md.Level != "note" || md.HelpText != "full zero" || md.StartLine != 0 {
		t.Errorf("markdown/default level: %+v", md)
	}
	if empty := fs[3]; empty.Message != "rule zero" || empty.Located() {
		t.Errorf("message fallback: %+v", empty)
	}
	if esc := fs[4]; esc.Located() || esc.Level != "error" {
		t.Errorf("escaping path should be unlocated: %+v", esc)
	}
	// The first location's scheme is not file and the second's base chain is
	// cyclic, so neither yields a path.
	if loop := fs[5]; loop.RuleID != "R1" || loop.Located() {
		t.Errorf("loop: %+v", loop)
	}
	if ref := fs[6]; ref.RuleID != "R9" || ref.HelpText != "" || ref.Level != "warning" {
		t.Errorf("rule ref: %+v", ref)
	}
}

func TestFingerprintSources(t *testing.T) {
	t.Parallel()
	str := func(s string) *string { return &s }
	mk := func(pf map[string]string, snippet, msg string) Finding {
		return Finding{Tool: "t", RuleID: "r", Path: "p", Snippet: snippet, Message: msg, Raw: &sarif.Result{PartialFingerprints: pf, RuleID: str("r")}}
	}
	fp := func(f Finding) string { return baseFingerprint(&f) }

	// primaryLocationLineHash wins, and GitHub's ":N" suffix is ignored.
	if fp(mk(map[string]string{"primaryLocationLineHash": "h:1"}, "a", "")) != fp(mk(map[string]string{"primaryLocationLineHash": "h:7", "x": "y"}, "b", "")) {
		t.Error("primaryLocationLineHash not preferred")
	}
	// Other tool fingerprints come next and ignore snippets.
	if fp(mk(map[string]string{"k": "v"}, "a", "")) != fp(mk(map[string]string{"k": "v", FingerprintKey: "z"}, "b", "")) {
		t.Error("tool partial fingerprints not used")
	}
	// Snippet hash: whitespace never matters.
	if fp(mk(nil, "a  b\n\tc", "")) != fp(mk(nil, " a b c ", "")) {
		t.Error("whitespace changed the fingerprint")
	}
	// sarifix/v1 stands in for a snippet that can no longer be read.
	withSnippet := mk(nil, "x = 1", "")
	recorded := mk(map[string]string{FingerprintKey: SnippetHash("t", "r", "p", "x = 1")}, "", "")
	if fp(withSnippet) != fp(recorded) {
		t.Error("sarifix/v1 does not match the snippet hash")
	}
	// No snippet, no fingerprints: the message is used.
	if fp(mk(nil, "", "m1")) == fp(mk(nil, "", "m2")) {
		t.Error("message fallback ignored")
	}
	if stripOccurrence("abc") != "abc" || stripOccurrence("a:b") != "a:b" || stripOccurrence("ab:12") != "ab" {
		t.Error("stripOccurrence")
	}
}

func TestAnnotateRoundTrip(t *testing.T) {
	t.Parallel()
	root := filepath.Join(testdata, "repos", "basic")
	fs, log := extract(t, "basic/golangci-lint.sarif", root)
	Annotate(append(fs, Finding{})) // a finding with no run is skipped
	var buf bytes.Buffer
	if err := log.Write(&buf); err != nil {
		t.Fatal(err)
	}
	// Re-read without file access: the recorded fingerprint still matches.
	again, _, err := sarif.Parse(buf.Bytes(), "annotated", sarif.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ex := &Extractor{Normalizer: &sarif.Normalizer{Root: "/nowhere"}}
	got := ex.Extract(again)
	if len(got) != 1 || got[0].Snippet != "" || got[0].Fingerprint != fs[0].Fingerprint {
		t.Fatalf("got %+v, want fingerprint %s", got, fs[0].Fingerprint)
	}
}

func TestLines(t *testing.T) {
	t.Parallel()
	calls := 0
	ex := &Extractor{ReadFile: func(string) ([]byte, error) {
		calls++
		return []byte("one\ntwo\nthree"), nil
	}}
	if got := ex.lines("f", 2, 9); got != "two\nthree" {
		t.Errorf("got %q", got)
	}
	if got := ex.lines("f", 5, 5); got != "" {
		t.Errorf("past end: %q", got)
	}
	if calls != 1 {
		t.Errorf("file read %d times", calls)
	}
	big := &Extractor{ReadFile: func(string) ([]byte, error) {
		return bytes.Repeat([]byte("x\n"), 1000), nil
	}}
	if n := strings.Count(big.lines("f", 1, 1000), "\n") + 1; n != maxSnippetLines {
		t.Errorf("snippet has %d lines", n)
	}
	missing := &Extractor{ReadFile: func(string) ([]byte, error) { return nil, errors.New("nope") }}
	if missing.lines("f", 1, 1) != "" || (&Extractor{}).lines("f", 1, 1) != "" {
		t.Error("unreadable file gave a snippet")
	}
}

func TestHelpers(t *testing.T) {
	t.Parallel()
	if RuleKey("trivy", "DS-0002") != "trivy/DS-0002" {
		t.Error("RuleKey")
	}
	for lv, want := range map[string]int{"error": 3, "warning": 2, "note": 1, "none": 0, "bogus": 0} {
		if LevelRank(lv) != want {
			t.Errorf("LevelRank(%q)", lv)
		}
	}
	if CollapseSpace("\n a \t b \n") != "a b" || CollapseSpace("") != "" {
		t.Error("CollapseSpace")
	}
	if lookupRule(&sarif.Run{}, &sarif.Result{}) != nil {
		t.Error("rule found with no driver")
	}
	if _, err := NewExtractor("\x00"); err == nil {
		t.Skip("filepath.Abs accepted NUL") // platform dependent
	}
}

func FuzzFingerprint(f *testing.F) {
	f.Add("trivy", "DS-0002", "Dockerfile", "FROM alpine:3.18", 1)
	f.Add("checkov", "CKV_AWS_24", "main.tf", "resource \"x\" {\n  a = 1\n}", 5)
	f.Add("", "", "", "", 0)
	f.Fuzz(func(t *testing.T, tool, rule, path, snippet string, line int) {
		a := Finding{Tool: tool, RuleID: rule, Path: path, Snippet: snippet, StartLine: line}
		b := a
		b.StartLine, b.EndLine = line+100, line+200
		b.Snippet = "  " + strings.ReplaceAll(snippet, " ", "\n\t ") + "\n"
		fs := []Finding{a, b}
		assignFingerprints(fs)
		// Line numbers and whitespace never change identity; occurrence
		// numbering keeps the two copies distinct.
		if strings.TrimSuffix(fs[0].Fingerprint, ":1") != strings.TrimSuffix(fs[1].Fingerprint, ":2") {
			t.Fatalf("fingerprints differ: %q %q", fs[0].Fingerprint, fs[1].Fingerprint)
		}
		if fs[0].Fingerprint == fs[1].Fingerprint {
			t.Fatal("duplicates share a fingerprint")
		}
		if got := SnippetHash(tool, rule, path, snippet); got == SnippetHash(tool+"x", rule, path, snippet) {
			t.Fatal("tool not part of the hash")
		}
	})
}

func BenchmarkExtract50MB(b *testing.B) {
	data := testutil.LargeSARIF(50 << 20)
	log, _, err := sarif.Parse(data, "bench", sarif.Options{SkipValidation: true})
	if err != nil {
		b.Fatal(err)
	}
	ex := &Extractor{Normalizer: &sarif.Normalizer{Root: "/repo"}}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if fs := ex.Extract(log); len(fs) == 0 {
			b.Fatal("no findings")
		}
	}
}

func BenchmarkSnippetHash(b *testing.B) {
	snippet := strings.Repeat("resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"name\"\n}\n", 4)
	b.ReportAllocs()
	for b.Loop() {
		SnippetHash("checkov", "CKV_AWS_18", "modules/m1/main.tf", snippet)
	}
}
