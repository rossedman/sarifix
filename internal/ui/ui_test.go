package ui

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"charm.land/fang/v2"
	"charm.land/lipgloss/v2"
)

func TestSanitize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		max  int
		want string
	}{
		{"plain", 0, "plain"},
		{"line one\nline two\t end", 0, "line one line two end"},
		{"\x1b[31mred\x1b[0m and \x1b]8;;http://x\x07link\x1b]8;;\x07", 0, "red and link"},
		{"bell\x07 nul\x00 del\x7f", 0, "bell nul del"},
		{"abcdef", 3, "abc…"},
		{"  spaced   out  ", 0, "spaced out"},
	}
	for _, tt := range tests {
		if got := Sanitize(tt.in, tt.max); got != tt.want {
			t.Errorf("Sanitize(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
		}
	}
}

func FuzzSanitize(f *testing.F) {
	for _, s := range []string{"x", "\x1b[2J\x1b[H", "a\nb", "\x1b]0;title\x07", "日本語"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := Sanitize(s, 50)
		for _, r := range got {
			if r < 0x20 || r == 0x7f || r == 0x1b {
				t.Fatalf("Sanitize(%q) = %q keeps control rune %U", s, got, r)
			}
		}
		if n := len([]rune(got)); n > 51 {
			t.Fatalf("Sanitize(%q) is %d runes", s, n)
		}
	})
}

func TestStylesAndScheme(t *testing.T) {
	t.Parallel()
	for _, dark := range []bool{true, false} {
		s := NewStyles(dark)
		if s.Title.Render("x") == "" || s.Finding.Render("y") == "" {
			t.Error("empty render")
		}
	}
	cs := ColorScheme(lipgloss.LightDark(true))
	if cs.Title == nil || cs.ErrorHeader[1] == nil {
		t.Error("scheme not filled")
	}
}

func TestWriterStripsColorWhenPiped(t *testing.T) {
	var buf bytes.Buffer
	w := Writer(&buf)
	_, _ = w.Write([]byte(NewStyles(true).Bad.Render("boom")))
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("ANSI kept for non-TTY writer: %q", buf.String())
	}
	if IsTerminal(os.Stdin) && IsTerminal(os.Stdout) {
		t.Skip("running in a terminal")
	}
	if !IsDark() {
		t.Error("IsDark should default to true without a terminal")
	}
}

func TestNewLogger(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	lg, err := NewLogger(&buf, "INFO", true)
	if err != nil {
		t.Fatal(err)
	}
	lg.Debug("hidden")
	lg.Info("shown", "k", "v")
	if out := buf.String(); strings.Contains(out, "hidden") || !strings.Contains(out, `"k":"v"`) {
		t.Errorf("log output %q", out)
	}
	if _, err := NewLogger(&buf, "loud", false); err == nil {
		t.Error("bad level accepted")
	}
}

func TestErrorHandlerPlainOffTerminal(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	ErrorHandler(&buf, fang.Styles{}, errors.New("/tmp/x/sarifix.yaml:4: scanners[0]: bad"))
	if buf.String() != "Error: /tmp/x/sarifix.yaml:4: scanners[0]: bad\n" {
		t.Errorf("got %q", buf.String())
	}
	f, err := os.CreateTemp(t.TempDir(), "err")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // test file
	ErrorHandler(f, fang.Styles{}, errors.New("a\nb"))
	data, _ := os.ReadFile(f.Name())
	if string(data) != "Error: a\nb\n" {
		t.Errorf("file: %q", data)
	}
}

func BenchmarkSanitize(b *testing.B) {
	msg := strings.Repeat("Artifact: Dockerfile\nType: dockerfile\n\x1b[31mSeverity: HIGH\x1b[0m ", 20)
	b.ReportAllocs()
	for b.Loop() {
		Sanitize(msg, 120)
	}
}
