package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func FuzzParse(f *testing.F) {
	for _, p := range []string{filepath.Join("..", "..", "examples", "sarifix.yaml"), filepath.Join("testdata", "org.yaml"), filepath.Join("testdata", "repo.yaml")} {
		data, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte("version: 1\nscanners: [{name: a, command: ['{x}']}]\n"))
	f.Add([]byte("a: &x [*x]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := Parse("fuzz.yaml", data)
		var es *Errors
		if err != nil {
			if !errors.As(err, &es) {
				t.Fatalf("Parse returned %T, want *Errors: %v", err, err)
			}
			return
		}
		// Whatever parses validates without panicking, reports *Errors, and
		// always denies workflow edits.
		if err := l.Validate(ValidateOptions{Strict: true}); err != nil && !errors.As(err, &es) {
			t.Fatalf("Validate returned %T", err)
		}
		if !contains(l.Paths.Deny, ".github/workflows/**") {
			t.Fatal("workflows not denied")
		}
	})
}

func BenchmarkLoadAndValidate(b *testing.B) {
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "sarifix.yaml"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		l, err := Parse("bench.yaml", data)
		if err != nil {
			b.Fatal(err)
		}
		if err := l.Validate(ValidateOptions{Strict: true}); err != nil {
			b.Fatal(err)
		}
	}
}
