package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	t.Parallel()
	var out, errb bytes.Buffer
	if code := run([]string{"testdata/good", "testdata/gen"}, &out, &errb); code != 0 {
		t.Fatalf("good code=%d out=%s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"testdata/bad"}, &out, &errb); code != 1 {
		t.Fatalf("bad code=%d", code)
	}
	for _, want := range []string{
		"testdata/bad/bad.go:5: Undocumented has no doc comment",
		`testdata/bad/bad.go:8: doc comment for Named must start with "Named"`,
		"testdata/bad/bad.go:10: T.Method has no doc comment",
		"testdata/bad/bad.go:12: T.PtrMethod has no doc comment",
		"package testdata/bad has no package comment",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	if code := run([]string{"testdata/missing"}, &out, &errb); code != 2 {
		t.Errorf("missing dir code=%d", code)
	}
}
