package sarif

import (
	"path"
	"strings"
	"testing"
)

// str returns a pointer to s.
func str(s string) *string { return &s }

func TestNormalizerResolve(t *testing.T) {
	t.Parallel()
	n := &Normalizer{Root: "/repo", CIRoots: DefaultCIRoots}
	tests := []struct {
		base, uri, want string
		ok              bool
	}{
		{"", "main.go", "main.go", true},
		{"", "./a/../b/c.go", "b/c.go", true},
		{"", "file:///repo/pkg/x.go", "pkg/x.go", true},
		{"", "/repo/pkg/x.go", "pkg/x.go", true},
		{"", "file:///home/runner/work/sarifix/sarifix/pkg/x.go", "pkg/x.go", true},
		{"", "/github/workspace/Dockerfile", "Dockerfile", true},
		{"", "/builds/group/proj/a.tf", "a.tf", true},
		{"", "file:///elsewhere/x.go", "", false},
		{"", "/repo", "", false},
		{"", "../escape.go", "", false},
		{"", "https://example.com/x.go", "", false},
		{"", "", "", false},
		{"", "file://", "", false},
		{"", "a%20b.go", "a b.go", true},
		{"", `pkg\win\x.go`, "pkg/win/x.go", true},
		{"", "C:/agent/x.go", "", false},
		{"", "file:///C:/agent/x.go", "", false},
		{"", "%zz", "%zz", true},
		{"/other/checkout", "Dockerfile", "Dockerfile", true},
		{"/repo/sub", "x.go", "sub/x.go", true},
		{"/other", "../x.go", "", false},
		{"rel", "x.go", "rel/x.go", true},
	}
	for _, tt := range tests {
		got, ok := n.Resolve(tt.base, tt.uri)
		if got != tt.want || ok != tt.ok {
			t.Errorf("Resolve(%q, %q) = %q, %v; want %q, %v", tt.base, tt.uri, got, ok, tt.want, tt.ok)
		}
	}
}

func TestNormalizerPathBaseIDs(t *testing.T) {
	t.Parallel()
	n := &Normalizer{Root: "/repo"}
	run := &Run{OriginalUriBaseIds: map[string]ArtifactLocation{
		"ROOT": {URI: str("file:///repo/")},
		"SRC":  {URI: str("src/"), URIBaseID: str("ROOT")},
		"LOOP": {URI: str("x/"), URIBaseID: str("LOOP")},
		"BAD":  {URI: str("https://x/")},
		"NONE": {},
	}}
	tests := []struct {
		loc  *ArtifactLocation
		want string
		ok   bool
	}{
		{&ArtifactLocation{URI: str("a.go"), URIBaseID: str("SRC")}, "src/a.go", true},
		{&ArtifactLocation{URI: str("a.go"), URIBaseID: str("ROOT")}, "a.go", true},
		{&ArtifactLocation{URI: str("a.go"), URIBaseID: str("LOOP")}, "", false},
		{&ArtifactLocation{URI: str("a.go"), URIBaseID: str("MISSING")}, "a.go", true},
		{&ArtifactLocation{URI: str("a.go"), URIBaseID: str("BAD")}, "a.go", true},
		{&ArtifactLocation{URI: str("a.go"), URIBaseID: str("NONE")}, "a.go", true},
		{&ArtifactLocation{}, "", false},
		{nil, "", false},
	}
	for i, tt := range tests {
		got, ok := n.Path(run, tt.loc)
		if got != tt.want || ok != tt.ok {
			t.Errorf("%d: Path = %q, %v; want %q, %v", i, got, ok, tt.want, tt.ok)
		}
	}
	if _, ok := n.Path(nil, &ArtifactLocation{URI: str("x"), URIBaseID: str("ROOT")}); !ok {
		t.Error("nil run should still resolve relative URIs")
	}
}

func TestNewNormalizer(t *testing.T) {
	t.Setenv("GITHUB_WORKSPACE", "/gh/ws")
	n, err := NewNormalizer(".")
	if err != nil {
		t.Fatal(err)
	}
	if !path.IsAbs(n.Root) || n.CIRoots[0] != "/gh/ws" {
		t.Errorf("%+v", n)
	}
	if got, ok := n.Resolve("", "/gh/ws/a/b.go"); !ok || got != "a/b.go" {
		t.Errorf("GITHUB_WORKSPACE not used: %q %v", got, ok)
	}
	root := &Normalizer{Root: "/"}
	if _, ok := root.Resolve("", "/etc/passwd"); ok {
		t.Error("root '/' must not make every path relative")
	}
}

func FuzzNormalize(f *testing.F) {
	for _, s := range [][2]string{{"", "main.go"}, {"/other", "Dockerfile"}, {"", "file:///repo/a/../../x"}, {"", "/home/runner/work/a/b/c"}, {"rel", "..%2f..%2fx"}} {
		f.Add(s[0], s[1])
	}
	n := &Normalizer{Root: "/repo", CIRoots: DefaultCIRoots}
	f.Fuzz(func(t *testing.T, base, uri string) {
		got, ok := n.Resolve(base, uri)
		if !ok {
			return
		}
		if got == "" || strings.HasPrefix(got, "/") || got == ".." || strings.HasPrefix(got, "../") || path.Clean(got) != got {
			t.Fatalf("Resolve(%q, %q) = %q: not a clean repo-relative path", base, uri, got)
		}
	})
}

func BenchmarkResolve(b *testing.B) {
	n := &Normalizer{Root: "/home/user/repo", CIRoots: DefaultCIRoots}
	uris := []string{"pkg/x/main.go", "file:///home/user/repo/modules/a/main.tf", "/home/runner/work/r/r/Dockerfile", "file:///elsewhere/x"}
	b.ReportAllocs()
	for b.Loop() {
		for _, u := range uris {
			n.Resolve("", u)
		}
	}
}
