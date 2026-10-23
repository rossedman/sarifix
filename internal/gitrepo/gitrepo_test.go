package gitrepo

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// run executes a command in dir and fails the test on error.
func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
}

func TestRepo(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	run(t, dir, "git", "init", "-q")
	if _, err := Resolve(ctx, dir, "HEAD"); !errors.Is(err, ErrNoCommits) {
		t.Errorf("empty repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-qm", "one")

	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := Root(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.EvalSymlinks(dir); root != want && root != dir {
		t.Errorf("root = %q", root)
	}
	common, err := CommonDir(ctx, dir)
	if err != nil || filepath.Base(common) != ".git" || !filepath.IsAbs(common) {
		t.Errorf("common dir = %q, %v", common, err)
	}
	sha, err := Resolve(ctx, dir, "HEAD")
	if err != nil || len(sha) != 40 {
		t.Fatalf("sha = %q, %v", sha, err)
	}
	if _, err := Resolve(ctx, dir, "--output=/tmp/x"); err == nil || !strings.Contains(err.Error(), "invalid revision") {
		t.Errorf("option-like revision: %v", err)
	}
	if _, err := Resolve(ctx, dir, "nope"); err == nil {
		t.Error("unknown revision resolved")
	}

	wt := filepath.Join(t.TempDir(), "wt")
	if err := AddWorktree(ctx, dir, wt, sha); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(wt, "a.txt")); err != nil || string(data) != "one\n" {
		t.Errorf("worktree content %q %v", data, err)
	}
	// A worktree shares the common dir.
	if c2, err := CommonDir(ctx, wt); err != nil || c2 != common {
		t.Errorf("worktree common dir = %q, want %q (%v)", c2, common, err)
	}
	if err := RemoveWorktree(ctx, dir, wt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(wt); !os.IsNotExist(err) {
		t.Error("worktree not removed")
	}
	if err := AddWorktree(ctx, dir, wt, "0000000000000000000000000000000000000000"); err == nil {
		t.Error("bad sha accepted")
	}

	notRepo := t.TempDir()
	if _, err := Root(ctx, notRepo); !errors.Is(err, ErrNotARepo) {
		t.Errorf("Root outside repo: %v", err)
	}
	if _, err := CommonDir(ctx, notRepo); !errors.Is(err, ErrNotARepo) {
		t.Errorf("CommonDir outside repo: %v", err)
	}
}
