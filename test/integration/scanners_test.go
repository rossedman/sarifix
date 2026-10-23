//go:build integration

// Package integration runs sarifix against real scanner binaries over the
// fixture repos. It needs trivy, checkov and golangci-lint on PATH:
//
//	go test -tags integration ./test/integration/
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rossedman/sarifix/internal/cli"
)

// root is the module root.
var root = func() string {
	p, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		panic(err)
	}
	return p
}()

// copyDir copies the fixture repo src to a new temp dir.
func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	if out, err := exec.Command("cp", "-R", src+"/.", dst).CombinedOutput(); err != nil {
		t.Fatalf("cp: %v %s", err, out)
	}
	return dst
}

// sarifix runs the CLI in-process and returns stdout.
func sarifix(t *testing.T, args ...string) string {
	t.Helper()
	var out, errb bytes.Buffer
	if err := cli.Execute(context.Background(), args, &out, &errb); err != nil {
		t.Fatalf("sarifix %s: %v\n%s", strings.Join(args, " "), err, errb.String())
	}
	return out.String()
}

// TestRealScanners scans the basic fixture with real tools, then diffs the
// fresh output against a scan of the shifted fixture: moved findings match.
func TestRealScanners(t *testing.T) {
	for _, tool := range []string{"trivy", "checkov", "golangci-lint"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s not on PATH", tool)
		}
	}
	cfg := filepath.Join(t.TempDir(), "sarifix.yaml")
	example, err := os.ReadFile(filepath.Join(root, "examples", "sarifix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	example = bytes.ReplaceAll(example, []byte("./tools/image-migrate.sh"), []byte(filepath.Join(root, "testdata", "tools", "image-migrate.sh")))
	if err := os.WriteFile(cfg, example, 0o600); err != nil {
		t.Fatal(err)
	}

	scans := map[string]string{}
	for _, repo := range []string{"basic", "shifted"} {
		dir := copyDir(t, filepath.Join(root, "testdata", "repos", repo))
		out := filepath.Join(t.TempDir(), repo)
		var res []struct {
			Scanner  string `json:"scanner"`
			Findings int    `json:"findings"`
		}
		if err := json.Unmarshal([]byte(sarifix(t, "scan", "--repo", dir, "--config", cfg, "--out-dir", out, "--json")), &res); err != nil {
			t.Fatal(err)
		}
		if len(res) != 4 {
			t.Fatalf("%s: %d scanners ran", repo, len(res))
		}
		for _, r := range res {
			if r.Findings == 0 {
				t.Errorf("%s: %s found nothing", repo, r.Scanner)
			}
		}
		scans[repo] = out
	}

	var d struct {
		Counts map[string]int `json:"counts"`
		New    []struct {
			Tool   string `json:"tool"`
			RuleID string `json:"ruleId"`
		} `json:"new"`
	}
	// Neither side can read files here (--repo is empty), so matching relies
	// on the sarifix/v1 fingerprints scan recorded.
	out := sarifix(t, "diff", "--repo", t.TempDir(), "--base", filepath.Join(scans["basic"], "*.sarif"), "--head", filepath.Join(scans["shifted"], "*.sarif"), "--json")
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatal(err)
	}
	for _, f := range d.New {
		// Whole-file Dockerfile checks legitimately change when lines are added.
		if f.Tool == "Checkov" && strings.HasPrefix(f.RuleID, "CKV_DOCKER_") {
			continue
		}
		t.Errorf("shifted finding reported as new: %s/%s", f.Tool, f.RuleID)
	}
	if d.Counts["unchanged"] < 20 {
		t.Errorf("only %d unchanged findings", d.Counts["unchanged"])
	}
}
