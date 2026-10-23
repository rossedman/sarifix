package placeholder

import (
	"reflect"
	"strings"
	"testing"
)

func TestExpandArgs(t *testing.T) {
	t.Parallel()
	v := Vars{Out: "/o/x.sarif", OutDir: "/o", Dir: "/r/sub", Repo: "/r", Paths: []string{"a.go", "b c.go"}}
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"plain", []string{"trivy", "config"}, []string{"trivy", "config"}},
		{"out", []string{"-o", "{out}"}, []string{"-o", "/o/x.sarif"}},
		{"embedded", []string{"--output.sarif.path={out}"}, []string{"--output.sarif.path=/o/x.sarif"}},
		{"paths element", []string{"lint", "{paths}", "--x"}, []string{"lint", "a.go", "b c.go", "--x"}},
		{"paths embedded", []string{"--files={paths}"}, []string{"--files=a.go b c.go"}},
		{"literal braces", []string{`{"a":1}`, "{ out }", "{}"}, []string{`{"a":1}`, "{ out }", "{}"}},
		{"many", []string{"{repo}:{dir}:{outdir}"}, []string{"/r:/r/sub:/o"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ExpandArgs(tt.in, v)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExpandArgsNoPaths(t *testing.T) {
	t.Parallel()
	got, err := ExpandArgs([]string{"x", "{paths}"}, Vars{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"x"}) {
		t.Errorf("got %q", got)
	}
}

func TestUnknown(t *testing.T) {
	t.Parallel()
	if got := Unknown("{out}-{bogus}-{dir}-{nope}"); !reflect.DeepEqual(got, []string{"bogus", "nope"}) {
		t.Errorf("got %q", got)
	}
	if _, err := ExpandArgs([]string{"{bogus}"}, Vars{}); err == nil || !strings.Contains(err.Error(), "{bogus}") {
		t.Errorf("want unknown placeholder error, got %v", err)
	}
	if _, err := Expand("{a}{b}", Vars{}); err == nil || !strings.Contains(err.Error(), "{a}") {
		t.Errorf("want first unknown reported, got %v", err)
	}
}

func FuzzExpand(f *testing.F) {
	for _, s := range []string{"{out}", "--x={paths}", `{"k":"{dir}"}`, "{{out}}", "{", "}", "{bogus}", "a{repo}b{outdir}c"} {
		f.Add(s)
	}
	// Mapping each placeholder to its own token makes Expand the identity, so
	// any change to the text outside placeholders is a bug.
	self := Vars{Out: "{out}", OutDir: "{outdir}", Dir: "{dir}", Repo: "{repo}", Paths: []string{"{paths}"}}
	v := Vars{Out: "O", OutDir: "D", Dir: "R", Repo: "R", Paths: []string{"p1", "p2"}}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := Expand(s, self)
		if len(Unknown(s)) > 0 {
			if err == nil {
				t.Fatalf("Expand(%q) accepted unknown placeholder", s)
			}
			return
		}
		if err != nil {
			t.Fatalf("Expand(%q): %v", s, err)
		}
		if got != s {
			t.Fatalf("identity Expand(%q) = %q", s, got)
		}
		// With brace-free values, no known placeholder token survives unless
		// the input built one from literal braces around an expansion.
		got, err = Expand(s, v)
		if err != nil {
			t.Fatalf("Expand(%q): %v", s, err)
		}
		if !strings.Contains(s, "{{") && len(Find(got)) > len(Find(s)) {
			t.Fatalf("Expand(%q) = %q created placeholders", s, got)
		}
	})
}

func BenchmarkExpandArgs(b *testing.B) {
	args := []string{"checkov", "-d", "{dir}", "-o", "sarif", "--output-file-path", "{outdir}", "--files={paths}", "{paths}"}
	v := Vars{Out: "/o/x.sarif", OutDir: "/o", Dir: "/r", Repo: "/r", Paths: []string{"a.tf", "b.tf", "c.tf"}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ExpandArgs(args, v); err != nil {
			b.Fatal(err)
		}
	}
}
