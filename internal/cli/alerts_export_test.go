package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// alertsConfig runs trivy and imports CodeQL's alerts.
const alertsConfig = `version: 1
scanners:
  - name: trivy
    match: [Trivy]
    command: ["true"]
  - name: codeql
    match: [CodeQL]
rules:
  allow: ["codeql/*"]
  min_level: note
`

// alertsJSON is what the fake code scanning API returns: two CodeQL alerts
// and one Trivy alert, which sarifix's own scan already covers.
const alertsJSON = `[
 {"number": 1, "html_url": "https://github.example/acme/infra/security/code-scanning/1",
  "rule": {"id": "go/sql-injection", "severity": "error", "description": "SQL built from user input"},
  "tool": {"name": "CodeQL", "version": "2.20.0"},
  "most_recent_instance": {"message": {"text": "This query depends on a user-provided value."}, "location": {"path": "a.go", "start_line": 2, "end_line": 2}}},
 {"number": 2, "html_url": "https://github.example/acme/infra/security/code-scanning/2",
  "rule": {"id": "go/sql-injection", "severity": "error", "description": "SQL built from user input"},
  "tool": {"name": "CodeQL", "version": "2.20.0"},
  "most_recent_instance": {"message": {"text": "This query depends on a user-provided value."}, "location": {"path": "a.go", "start_line": 3, "end_line": 3}}},
 {"number": 3, "rule": {"id": "DS-0002", "severity": "error"}, "tool": {"name": "Trivy"},
  "most_recent_instance": {"message": {"text": "No USER"}, "location": {"path": "Dockerfile", "start_line": 1}}}
]`

// alertsRepo writes a repo with alertsConfig and a Go file the alerts point at.
func alertsRepo(t *testing.T, cfg string) string {
	t.Helper()
	dir := writeConfig(t, cfg)
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\nvar q = \"SELECT \" + x\nvar r = \"SELECT \" + y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// alertsAPI serves code scanning alerts and hands other calls to g.
func alertsAPI(t *testing.T, g *fakeGitHub, status int) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	githubEnv(t, g)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/infra/code-scanning/alerts" {
			g.ServeHTTP(w, r)
			return
		}
		calls.Add(1)
		w.WriteHeader(status)
		if status != http.StatusOK {
			_, _ = io.WriteString(w, `{"message":"Advanced Security must be enabled for this repository"}`)
			return
		}
		_, _ = io.WriteString(w, alertsJSON)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("GITHUB_API_URL", srv.URL)
	return &calls
}

func TestAlertsExport(t *testing.T) {
	g := &fakeGitHub{}
	calls := alertsAPI(t, g, http.StatusOK)
	dir := alertsRepo(t, alertsConfig)

	out, errOut, code := run(t, "alerts", "export", "--repo", dir)
	if code != 0 {
		t.Fatalf("export: %d %s", code, errOut)
	}
	if !strings.Contains(out, "codeql 2 open alerts") || calls.Load() != 1 {
		t.Errorf("output %q, %d calls", out, calls.Load())
	}
	data, err := os.ReadFile(filepath.Join(dir, "sarif", "code-scanning.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"name": "CodeQL"`) || strings.Contains(string(data), "DS-0002") {
		t.Errorf("SARIF:\n%s", data)
	}

	// The alerts become one issue, written for a scanner sarifix can't run.
	out, errOut, code = run(t, "fix", "--mode", "issues", "--repo", dir, "--config", filepath.Join(dir, "sarifix.yaml"),
		"--sarif", filepath.Join(dir, "sarif", "*.sarif"))
	if code != 0 || !strings.Contains(out, "opened #1") || len(g.issues) != 1 {
		t.Fatalf("issues: %d %s %s", code, out, errOut)
	}
	if !strings.Contains(errOut, "no SARIF from this scanner") || !strings.Contains(errOut, "trivy") {
		t.Errorf("want a warning about trivy's missing SARIF: %s", errOut)
	}
	body := g.issues[0]["body"].(string)
	for _, want := range []string{"Code scanning, on `0123456789ab`, reports 2 `error` finding(s) for `codeql/go/sql-injection`",
		"codeql runs in CI, not through sarifix", "no dismissing alerts"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}

	// JSON, and a path outside the repo.
	abs := filepath.Join(t.TempDir(), "out", "alerts.sarif")
	out, _, code = run(t, "alerts", "export", "--repo", dir, "--out", abs, "--json")
	var res alertsExport
	if err := json.Unmarshal([]byte(out), &res); code != 0 || err != nil || res.Out != abs || len(res.Scanners) != 1 || res.Scanners[0].Alerts != 2 {
		t.Errorf("json: %d %v %+v", code, err, res)
	}
}

func TestAlertsExportWithoutImportedScanners(t *testing.T) {
	calls := alertsAPI(t, &fakeGitHub{}, http.StatusOK)
	dir := alertsRepo(t, "version: 1\nscanners:\n  - name: trivy\n    command: [\"true\"]\n")
	out, _, code := run(t, "alerts", "export", "--repo", dir, "--json")
	var res alertsExport
	if err := json.Unmarshal([]byte(out), &res); code != 0 || err != nil || res.Out != "" || res.Scanners == nil || len(res.Scanners) != 0 || calls.Load() != 0 {
		t.Errorf("%d %q, %d calls", code, out, calls.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, "sarif")); !os.IsNotExist(err) {
		t.Errorf("wrote output: %v", err)
	}
	if out, _, code := run(t, "alerts", "export", "--repo", dir); code != 0 || out != "" {
		t.Errorf("text: %d %q", code, out)
	}
}

func TestAlertsExportErrors(t *testing.T) {
	alertsAPI(t, &fakeGitHub{}, http.StatusForbidden)
	dir := alertsRepo(t, alertsConfig)
	_, errOut, code := run(t, "alerts", "export", "--repo", dir)
	if code != ExitRuntime || !strings.Contains(errOut, "Advanced Security must be enabled") {
		t.Errorf("api error: %d %s", code, errOut)
	}
	t.Setenv("GITHUB_REPOSITORY", "")
	if _, errOut, code := run(t, "alerts", "export", "--repo", dir); code != ExitConfig || !strings.Contains(errOut, "--github-repo") {
		t.Errorf("no repo: %d %s", code, errOut)
	}
	if _, _, code := run(t, "alerts", "export", "--repo", dir, "--config", filepath.Join(dir, "missing.yaml")); code != ExitConfig {
		t.Errorf("bad config: %d", code)
	}
}

func TestScanSkipsImportedScanners(t *testing.T) {
	t.Parallel()
	dir := alertsRepo(t, alertsConfig)
	out, errOut, code := run(t, "scan", "--repo", dir, "--dry-run")
	if code != 0 || !strings.Contains(out, "trivy") || strings.Contains(out, "codeql") {
		t.Errorf("scan: %d %s %s", code, out, errOut)
	}
	if _, errOut, code := run(t, "scan", "--repo", dir, "--scanner", "codeql"); code != ExitConfig || !strings.Contains(errOut, "has no command") {
		t.Errorf("named imported scanner: %d %s", code, errOut)
	}
	only := alertsRepo(t, "version: 1\nscanners:\n  - name: codeql\n    match: [CodeQL]\n")
	if _, errOut, code := run(t, "scan", "--repo", only); code != ExitConfig || !strings.Contains(errOut, "no scanners with a command") {
		t.Errorf("only imported: %d %s", code, errOut)
	}
}
