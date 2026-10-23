package cli

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rossedman/sarifix/pkg/plan"
	"github.com/rossedman/sarifix/pkg/sarif"
)

// update rewrites golden files: go test ./internal/cli -run Golden -update
var update = flag.Bool("update", false, "rewrite golden files")

// golden compares got with testdata/plan/<name>, or rewrites it with -update.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join(testdata, "plan", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from golden; run with -update and review the diff.\ngot:\n%s", name, got)
	}
}

// planArgs runs a command against the plan fixture.
func planArgs(cmd ...string) []string {
	return append(cmd,
		"--repo", filepath.Join(testdata, "repos", "basic"),
		"--config", filepath.Join(testdata, "plan", "sarifix.yaml"),
		"--sarif", filepath.Join(testdata, "sarif", "basic", "*.sarif"),
		"--sarif", filepath.Join(testdata, "sarif", "broken", "edge.sarif"),
	)
}

func TestPlanGolden(t *testing.T) {
	t.Parallel()
	out, errOut, code := run(t, planArgs("plan")...)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	golden(t, "plan.txt", out)

	out, _, _ = run(t, append(planArgs("plan"), "--details")...)
	golden(t, "plan-details.txt", out)

	out, _, _ = run(t, append(planArgs("plan"), "--json")...)
	golden(t, "plan.json", out)
}

func TestPlanSelection(t *testing.T) {
	t.Parallel()
	summary := func(args ...string) plan.Summary {
		t.Helper()
		out, errOut, code := run(t, append(planArgs("plan", "--json"), args...)...)
		if code != 0 {
			t.Fatalf("code %d: %s", code, errOut)
		}
		var s plan.Summary
		if err := json.Unmarshal([]byte(out), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := summary("--rule", "trivy/DS-*")
	if len(s.Run) != 2 || s.Run[0].Key != "trivy/DS-0002" || s.Skipped["not_selected"] == 0 {
		t.Errorf("--rule: %+v", s)
	}
	s = summary("--campaign", "base-image-2026q4")
	if len(s.Run) != 1 || s.Run[0].Branch != "sarifix/campaign/base-image-2026q4" || s.Batched != 1 {
		t.Errorf("--campaign: %+v", s)
	}
	// With the basic scan as baseline, nothing in it is new.
	s = summary("--baseline", filepath.Join(testdata, "sarif", "basic", "*.sarif"))
	if s.Batched != 0 || s.Deferred != 0 || s.Skipped["in_baseline"] == 0 {
		t.Errorf("--baseline: %+v", s)
	}
	// The shifted fixture's SARIF has no recorded fingerprints, so its lines
	// must be read from its own checkout to match.
	s = summary("--baseline", filepath.Join(testdata, "sarif", "shifted", "*.sarif"), "--baseline-root", filepath.Join(testdata, "repos", "shifted"))
	if s.Skipped["in_baseline"] != 27 {
		t.Errorf("--baseline-root: %+v", s.Skipped)
	}

	for _, tc := range []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"--campaign", "nope"}, ExitConfig, `unknown campaign "nope"`},
		{[]string{"--rule", "a/["}, ExitConfig, "bad --rule glob"},
		{[]string{"--baseline", "/nonexistent/*.sarif"}, ExitRuntime, "no SARIF files matched"},
	} {
		_, errOut, code := run(t, append(planArgs("plan"), tc.args...)...)
		if code != tc.code || !strings.Contains(errOut, tc.msg) {
			t.Errorf("%v: code %d, stderr %s", tc.args, code, errOut)
		}
	}
	if _, _, code := run(t, "plan", "--repo", t.TempDir(), "--sarif", "x"); code != ExitConfig {
		t.Errorf("missing config: %d", code)
	}
	if _, _, code := run(t, "plan", "--config", filepath.Join(testdata, "plan", "sarifix.yaml"), "--sarif", "/nonexistent/*.sarif"); code != ExitRuntime {
		t.Errorf("missing sarif: %d", code)
	}
}

func TestFixReport(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	out, errOut, code := run(t, append(planArgs("fix", "--mode", "report"), "--out-dir", dir)...)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if !strings.Contains(out, "4 batched in 4 batches") || !strings.Contains(out, "sarifix.sarif") {
		t.Errorf("output: %s", out)
	}
	summary, err := os.ReadFile(filepath.Join(dir, "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "summary.json", string(summary))

	data, err := os.ReadFile(filepath.Join(dir, "sarifix.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sarif.Validate(data); err != nil {
		t.Fatalf("enriched SARIF fails the schema: %v", err)
	}
	// Every result that is a finding carries properties.sarifix.
	log, warns, err := sarif.Parse(data, "report", sarif.Options{})
	if err != nil || len(warns) > 0 {
		t.Fatalf("%v %v", err, warns)
	}
	statuses := map[string]int{}
	for _, r := range log.Runs {
		for _, res := range r.Run.Results {
			if res.Kind == "pass" {
				continue
			}
			if res.Properties == nil || res.Properties.Properties["sarifix"] == nil {
				t.Fatalf("%s: result without properties.sarifix", r.Driver())
			}
			st, _ := res.Properties.Properties["sarifix"].(map[string]any)
			statuses[st["status"].(string)]++
		}
	}
	if statuses["batched"] != 4 || statuses["deferred"] != 11 || statuses["skipped"] != 20 {
		t.Errorf("statuses = %v", statuses)
	}

	out, _, code = run(t, append(planArgs("fix", "--json"), "--out-dir", t.TempDir())...)
	var res fixReport
	if err := json.Unmarshal([]byte(out), &res); err != nil || code != 0 || res.Mode != "report" || res.Batch != 4 {
		t.Errorf("json: %v %s", err, out)
	}
}

func TestFixModes(t *testing.T) {
	t.Parallel()
	for mode, want := range map[string]string{"pr": "phase 3", "local": "phase 2", "review": "phase 4"} {
		_, errOut, code := run(t, planArgs("fix", "--mode", mode)...)
		if code != ExitRuntime || !strings.Contains(errOut, want) {
			t.Errorf("%s: code %d %s", mode, code, errOut)
		}
	}
	if _, errOut, code := run(t, planArgs("fix", "--mode", "yolo")...); code != ExitConfig || !strings.Contains(errOut, `unknown --mode "yolo"`) {
		t.Errorf("unknown mode: %d %s", code, errOut)
	}
	if _, _, code := run(t, append(planArgs("fix"), "--rule", "a/[")...); code != ExitConfig {
		t.Errorf("bad rule: %d", code)
	}
	if _, _, code := run(t, append(planArgs("fix"), "--out-dir", "/dev/null/x")...); code != ExitRuntime {
		t.Errorf("unwritable out dir: %d", code)
	}
}
