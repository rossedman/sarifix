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
		t.Errorf("shifted finding reported as new: %s/%s", f.Tool, f.RuleID)
	}
	if d.Counts["unchanged"] < 25 {
		t.Errorf("only %d unchanged findings", d.Counts["unchanged"])
	}
}

// TestCheckWithRealScanners commits the basic fixture, then adds an
// unhardened S3 bucket and checks that sarifix check reports only the new
// bucket's findings, never the fixture's existing ones.
func TestCheckWithRealScanners(t *testing.T) {
	dir := copyDir(t, filepath.Join(root, "testdata", "repos", "basic"))
	cfg, err := os.ReadFile(filepath.Join(root, "examples", "sarifix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg = bytes.ReplaceAll(cfg, []byte("./tools/image-migrate.sh"), []byte(filepath.Join(root, "testdata", "tools", "image-migrate.sh")))
	if err := os.WriteFile(filepath.Join(dir, "sarifix.yaml"), cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "base"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	if out := sarifix(t, "check", "--repo", dir, "--json"); !strings.Contains(out, `"new": []`) {
		t.Fatalf("clean tree reported findings:\n%s", out)
	}

	bucket := "resource \"aws_s3_bucket\" \"exports\" {\n  bucket = \"exports\"\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "exports.tf"), []byte(bucket), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	err = cli.Execute(context.Background(), []string{"check", "--repo", dir, "--json"}, &out, &errb)
	if code := cli.ExitCode(err); code != cli.ExitFindings {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var res struct {
		New []struct {
			RuleKey string `json:"ruleKey"`
			Path    string `json:"path"`
		} `json:"new"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	scanners := map[string]bool{}
	for _, f := range res.New {
		if f.Path != "exports.tf" {
			t.Errorf("pre-existing finding reported: %+v", f)
		}
		scanners[strings.SplitN(f.RuleKey, "/", 2)[0]] = true
	}
	if !scanners["trivy"] || !scanners["checkov"] {
		t.Errorf("want findings from trivy and checkov, got %v", res.New)
	}
}
