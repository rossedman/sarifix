package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rossedman/sarifix/pkg/config"
	"github.com/rossedman/sarifix/pkg/sarif"
)

// fake returns a config for testdata/fake.sh in the given mode.
func fake(t *testing.T, mode string, extra ...string) config.Scanner {
	t.Helper()
	script, err := filepath.Abs(filepath.Join("testdata", "fake.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return config.Scanner{
		Name:    "fake",
		Match:   []string{"Fake"},
		Command: append([]string{script, mode, "{out}"}, extra...),
		Output:  "{out}",
		Workdir: "{repo}",
		Timeout: config.Duration(10 * time.Second),
	}
}

// request returns a ScanRequest rooted in a temp repo.
func request(t *testing.T) ScanRequest {
	t.Helper()
	repo := t.TempDir()
	return ScanRequest{Repo: repo, OutDir: filepath.Join(repo, "out")}
}

func TestScanModes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mode    string
		results int
		wantErr string
	}{
		{"ok", 1, ""},
		{"findings", 1, ""},
		{"fail", 0, "boom: bad flag"},
		{"silent", 0, "wrote no SARIF output"},
		{"garbage", 0, "not a SARIF log"},
		{"empty", 0, "name is required"},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			t.Parallel()
			log, err := NewExec(fake(t, tt.mode)).Scan(context.Background(), request(t))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(log.Runs) != 1 || len(log.Runs[0].Run.Results) != tt.results {
				t.Fatalf("got %+v", log.Runs)
			}
		})
	}
}

func TestScanTimeout(t *testing.T) {
	t.Parallel()
	spec := fake(t, "sleep")
	spec.Timeout = config.Duration(100 * time.Millisecond)
	start := time.Now()
	_, err := NewExec(spec).Scan(context.Background(), request(t))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Error("timeout not enforced")
	}
}

func TestScanPlaceholdersEnvWorkdir(t *testing.T) {
	t.Parallel()
	req := request(t)
	sub := filepath.Join(req.Repo, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	req.Dir = sub
	req.Paths = []string{"a.go", "b.go"}
	spec := fake(t, "env", "{paths}", "--dir={dir}")
	spec.Workdir = "sub"
	spec.Env = map[string]string{"FAKE_MSG": "from {repo}"}
	e := NewExec(spec)
	e.Environ = []string{"PATH=" + os.Getenv("PATH")}
	log, err := e.Scan(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if msg := *log.Runs[0].Run.Results[0].Message.Text; msg != "from "+req.Repo {
		t.Errorf("env not expanded: %q", msg)
	}
	argv, err := os.ReadFile(filepath.Join(req.OutDir, "argv.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if want := sub + " a.go b.go --dir=" + sub + "\n"; string(argv) != want {
		t.Errorf("argv = %q, want %q", argv, want)
	}
}

func TestScanCustomOutputAndStaleFile(t *testing.T) {
	t.Parallel()
	req := request(t)
	spec := fake(t, "silent")
	spec.Output = "{outdir}/custom.sarif"
	if err := os.MkdirAll(req.OutDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(req.OutDir, "custom.sarif")
	if err := os.WriteFile(stale, []byte(`{"version":"2.1.0","runs":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewExec(spec).Scan(context.Background(), req); !errors.Is(err, ErrNoOutput) {
		t.Fatalf("stale output was used: %v", err)
	}
	spec.Output = "rel.sarif"
	spec.Command = []string{"sh", "-c", `echo '{"version":"2.1.0","runs":[]}' > rel.sarif`}
	if _, err := NewExec(spec).Scan(context.Background(), req); err != nil {
		t.Fatalf("relative output: %v", err)
	}
}

func TestScanBadTemplates(t *testing.T) {
	t.Parallel()
	for _, mut := range []func(*config.Scanner){
		func(s *config.Scanner) { s.Command = []string{"x", "{nope}"} },
		func(s *config.Scanner) { s.Command = []string{"{paths}"} },
		func(s *config.Scanner) { s.Output = "{nope}" },
		func(s *config.Scanner) { s.Workdir = "{nope}" },
		func(s *config.Scanner) { s.Env = map[string]string{"A": "{nope}"} },
		func(s *config.Scanner) { s.Command = []string{"/nonexistent/tool"} },
	} {
		spec := fake(t, "ok")
		mut(&spec)
		if _, err := NewExec(spec).Scan(context.Background(), request(t)); err == nil {
			t.Errorf("accepted %+v", spec)
		}
	}
	req := request(t)
	req.OutDir = "/dev/null/x"
	if _, err := NewExec(fake(t, "ok")).Scan(context.Background(), req); err == nil {
		t.Error("bad outdir accepted")
	}
}

func TestRegistry(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Scanners: []config.Scanner{
		{Name: "trivy", Match: []string{"Trivy"}},
		{Name: "checkov", Match: []string{"Checkov", "checkov-legacy"}},
	}}
	r := NewRegistry(cfg)
	if len(r.All()) != 2 {
		t.Fatal("scanners missing")
	}
	if s, ok := r.Route("TRIVY"); !ok || s.Name() != "trivy" {
		t.Error("case-insensitive route failed")
	}
	if s, ok := r.Route("checkov-legacy"); !ok || s.Name() != "checkov" {
		t.Error("second match value")
	}
	if _, ok := r.Route("golangci-lint"); ok {
		t.Error("unmatched tool routed")
	}
	if s, ok := r.Get("checkov"); !ok || s.Name() != "checkov" {
		t.Error("Get")
	}
	if _, ok := r.Get("nope"); ok {
		t.Error("Get unknown")
	}
	f := &stub{name: "x"}
	if s, ok := NewRegistryOf(f).Route("X"); !ok || s != f {
		t.Error("NewRegistryOf")
	}
	if tail(strings.Repeat("a", stderrTail+10)) != "..."+strings.Repeat("a", stderrTail) {
		t.Error("tail")
	}
}

// stub is a minimal Scanner fake.
type stub struct{ name string }

// Name returns the stub's name.
func (s *stub) Name() string { return s.name }

// Matches matches the upper-cased name.
func (s *stub) Matches(d string) bool { return d == strings.ToUpper(s.name) }

// Scan returns an empty log.
func (s *stub) Scan(context.Context, ScanRequest) (*sarif.Log, error) { return &sarif.Log{}, nil }
