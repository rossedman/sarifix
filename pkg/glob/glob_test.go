package glob

import (
	"path"
	"strings"
	"testing"
)

func TestMatchPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pat, name string
		want      bool
	}{
		{".github/workflows/**", ".github/workflows/ci.yml", true},
		{".github/workflows/**", ".github/workflows/a/b.yml", true},
		{".github/workflows/**", ".github/ci.yml", false},
		{"vendor/**", "vendor/x/y.go", true},
		{"vendor/**", "src/vendor/x.go", false},
		{"**/*_generated.go", "a_generated.go", true},
		{"**/*_generated.go", "pkg/x/a_generated.go", true},
		{"**/*_generated.go", "pkg/x/a.go", false},
		{"*.go", "a.go", true},
		{"*.go", "pkg/a.go", false},
		{"pkg/**/testdata/**", "pkg/a/b/testdata/c/d", true},
		{"**", "anything/at/all", true},
		{"a/**/b", "a/b", true},
		{"[ab].tf", "a.tf", true},
		{"[", "[", false},
		{"a**b", "ab", false},
		{"[^0]", "/", false},
		{"a[^x]b", "a/b", false},
	}
	for _, tt := range tests {
		if got := MatchPath(tt.pat, tt.name); got != tt.want {
			t.Errorf("MatchPath(%q, %q) = %v, want %v", tt.pat, tt.name, got, tt.want)
		}
	}
}

func TestMatchKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pat, key string
		want     bool
	}{
		{"checkov/CKV_AWS_*", "checkov/CKV_AWS_20", true},
		{"checkov/CKV_AWS_*", "checkov/CKV2_AWS_6", false},
		{"*/secrets-*", "trivy/secrets-aws", true},
		{"*/secrets-*", "trivy/x/secrets-aws", true},
		{"codeql/go/*", "codeql/go/sql-injection", true},
		{"trivy/DS-0002", "trivy/DS-0002", true},
		{"trivy/DS-0002", "trivy/DS-00021", false},
		{"*", "a/b", true},
		{"[", "[", false},
	}
	for _, tt := range tests {
		if got := MatchKey(tt.pat, tt.key); got != tt.want {
			t.Errorf("MatchKey(%q, %q) = %v, want %v", tt.pat, tt.key, got, tt.want)
		}
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"", "[", "a/[b", "x**"} {
		if ValidatePath(p) == nil {
			t.Errorf("ValidatePath(%q) accepted", p)
		}
	}
	for _, p := range []string{"", "[", "a/[b"} {
		if ValidateKey(p) == nil {
			t.Errorf("ValidateKey(%q) accepted", p)
		}
	}
	for _, p := range []string{"**", "a/**/b", "*.go"} {
		if err := ValidatePath(p); err != nil {
			t.Errorf("ValidatePath(%q) = %v", p, err)
		}
	}
}

func FuzzMatchPath(f *testing.F) {
	for _, s := range [][2]string{{"**/*.go", "a/b.go"}, {"vendor/**", "vendor/x"}, {"[a-c]?/**", "b1/z"}, {"a/**/**/b", "a/x/y/b"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pat, name string) {
		got := MatchPath(pat, name)
		// Without "**", and on a single segment, the result agrees with
		// path.Match. (Across segments it differs on purpose: path.Match
		// lets a class like [^0] match "/", MatchPath never does.)
		if ValidatePath(pat) == nil && !strings.Contains(pat, "**") && !strings.Contains(name, "/") {
			want, _ := path.Match(pat, name)
			if got != want {
				t.Fatalf("MatchPath(%q, %q) = %v, path.Match = %v", pat, name, got, want)
			}
		}
		// A character class never matches the separator.
		if MatchPath(pat, name) && strings.Count(pat, "/") != strings.Count(name, "/") && !strings.Contains(pat, "**") {
			t.Fatalf("MatchPath(%q, %q) crossed a segment", pat, name)
		}
		// "**/" in front can only widen a match.
		if got && ValidatePath(pat) == nil && !MatchPath("**/"+pat, name) {
			t.Fatalf("**/%q lost a match on %q", pat, name)
		}
	})
}

func BenchmarkMatchPath(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		MatchPath("**/*_generated.go", "pkg/a/b/c/d/zz_generated.go")
		MatchPath(".github/workflows/**", "modules/network/main.tf")
	}
}

func BenchmarkMatchKey(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		MatchKey("checkov/CKV_AWS_*", "checkov/CKV_AWS_144")
		MatchKey("*/secrets-*", "trivy/DS-0002")
	}
}
