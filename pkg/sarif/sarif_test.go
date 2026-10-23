package sarif

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rossedman/sarifix/internal/testutil"
)

// fixtures is the repo's SARIF fixture directory.
var fixtures = filepath.Join("..", "..", "testdata", "sarif")

func TestLoadRealScanners(t *testing.T) {
	t.Parallel()
	want := map[string]int{"Trivy": 14, "Checkov": 12, "golangci-lint": 1, "image-migrate": 1}
	log, warns, err := LoadGlobs([]string{filepath.Join(fixtures, "basic", "*.sarif")}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) > 0 {
		t.Fatalf("warnings: %v", warns)
	}
	got := map[string]int{}
	for _, r := range log.Runs {
		got[r.Driver()] += len(r.Run.Results)
		if r.Source == "" {
			t.Error("run without source")
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %d results, want %d", k, got[k], v)
		}
	}
}

func TestPartialSARIFDegrades(t *testing.T) {
	t.Parallel()
	log, warns, err := LoadGlobs([]string{filepath.Join(fixtures, "broken", "*.sarif")}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var drivers []string
	for _, r := range log.Runs {
		drivers = append(drivers, r.Driver())
	}
	if strings.Join(drivers, ",") != "edge,good-tool" {
		t.Errorf("loaded runs %v", drivers)
	}
	text := ""
	for _, w := range warns {
		text += w.String() + "\n"
	}
	for _, want := range []string{
		"not-json.sarif: not a SARIF log",
		`old-version.sarif: unsupported SARIF version "2.0.0"`,
		"partial.sarif: run 1: skipped: invalid SARIF",
		"partial.sarif: run 2: skipped: invalid SARIF",
		"partial.sarif: run 3: skipped: invalid SARIF: runs.0.tool.driver: name is required",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing warning %q in:\n%s", want, text)
		}
	}
}

func TestSkipValidation(t *testing.T) {
	t.Parallel()
	log, warns, err := LoadFile(filepath.Join(fixtures, "broken", "partial.sarif"), Options{SkipValidation: true})
	if err != nil {
		t.Fatal(err)
	}
	// Without the schema, the bad level and missing tool slip through to the
	// structural checks, which still reject runs with no driver name.
	if len(log.Runs) != 2 || len(warns) != 2 {
		t.Errorf("runs=%d warns=%v", len(log.Runs), warns)
	}
}

func TestExpandErrors(t *testing.T) {
	t.Parallel()
	if _, err := Expand([]string{filepath.Join(t.TempDir(), "*.sarif")}); !errors.Is(err, ErrNoFiles) {
		t.Errorf("want ErrNoFiles, got %v", err)
	}
	if _, err := Expand([]string{"["}); err == nil {
		t.Error("bad pattern accepted")
	}
	files, err := Expand([]string{filepath.Join(fixtures, "basic", "trivy.sarif"), filepath.Join(fixtures, "basic", "t*.sarif"), fixtures})
	if err != nil || len(files) != 1 {
		t.Errorf("files=%v err=%v", files, err)
	}
	if _, _, err := LoadGlobs([]string{"/nonexistent/*.sarif"}, Options{}); !errors.Is(err, ErrNoFiles) {
		t.Errorf("LoadGlobs: %v", err)
	}
	if _, _, err := LoadFile("/nonexistent.sarif", Options{}); err == nil {
		t.Error("missing file accepted")
	}
	if _, _, err := Read(errReader{}, "x", Options{}); err == nil {
		t.Error("read error swallowed")
	}
}

// errReader always fails.
type errReader struct{}

// Read returns an error.
func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestWriteRoundTrip(t *testing.T) {
	t.Parallel()
	log, _, err := LoadFile(filepath.Join(fixtures, "basic", "checkov.sarif"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "sub", "out.sarif")
	log.Runs[0].AddPartialFingerprint(0, "sarifix/v1", "abc")
	log.Runs[0].AddPartialFingerprint(99, "sarifix/v1", "ignored")
	log.Runs[0].SetResultProperty(0, "sarifix", map[string]any{"status": "skipped"})
	log.Runs[0].SetResultProperty(-1, "sarifix", "ignored")
	if err := log.WriteFile(p); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(data); err != nil {
		t.Fatalf("written SARIF invalid: %v", err)
	}
	again, warns, err := Parse(data, p, Options{})
	if err != nil || len(warns) > 0 || len(again.Runs) != 1 || len(again.Runs[0].Run.Results) != 12 {
		t.Fatalf("round trip: %v %v", err, warns)
	}
	if got := again.Runs[0].Run.Results[0].PartialFingerprints["sarifix/v1"]; got != "abc" {
		t.Errorf("patch not written: %q", got)
	}
	if !strings.Contains(string(data), `"status": "skipped"`) {
		t.Error("property patch not written")
	}
	// Unpatched fields are byte-for-byte what the tool wrote.
	if strings.Contains(string(data), `"enabled": false`) || strings.Contains(string(data), `"language"`) {
		t.Error("zero values leaked into output")
	}
	if err := log.WriteFile(filepath.Join(p, "x")); err == nil {
		t.Error("write under a file accepted")
	}
}

func TestValidateReportsCappedErrors(t *testing.T) {
	t.Parallel()
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[` +
		`{"level":"a","message":{}},{"level":"b","message":{}},{"level":"c","message":{}},{"level":"d","message":{}}]}]}`
	err := Validate([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "more") {
		t.Errorf("got %v", err)
	}
	if err := Validate([]byte("not json")); err == nil {
		t.Error("garbage validated")
	}
	if DriverName(nil) != "" || DriverName(&Run{}) != "" {
		t.Error("DriverName on empty run")
	}
}

func FuzzParse(f *testing.F) {
	for _, name := range []string{"basic/golangci-lint.sarif", "basic/image-migrate.sarif", "broken/partial.sarif", "broken/edge.sarif"} {
		data, err := os.ReadFile(filepath.Join(fixtures, name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`{"version":"2.1.0","runs":[null]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		log, _, err := Parse(data, "fuzz", Options{})
		if err != nil {
			return
		}
		for _, r := range log.Runs {
			if r.Driver() == "" {
				t.Fatal("accepted a run with no driver name")
			}
		}
		// Anything accepted must write back out as schema-valid SARIF.
		for _, r := range log.Runs {
			r.AddPartialFingerprint(0, "sarifix/v1", "fuzz")
		}
		var buf bytes.Buffer
		if err := log.Write(&buf); err != nil {
			t.Fatal(err)
		}
		if err := Validate(buf.Bytes()); err != nil {
			t.Fatalf("accepted input writes invalid SARIF: %v\n%s", err, buf.Bytes())
		}
	})
}

func BenchmarkParse50MB(b *testing.B) {
	data := testutil.LargeSARIF(50 << 20)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := Parse(data, "bench", Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParse50MBNoValidate(b *testing.B) {
	data := testutil.LargeSARIF(50 << 20)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := Parse(data, "bench", Options{SkipValidation: true}); err != nil {
			b.Fatal(err)
		}
	}
}
