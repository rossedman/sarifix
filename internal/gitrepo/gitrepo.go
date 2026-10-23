// Package gitrepo runs the few git commands sarifix needs: finding the repo,
// resolving a revision, and checking one out into a temporary worktree.
package gitrepo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrNotARepo means the directory is not inside a git work tree.
var ErrNotARepo = errors.New("not inside a git repository")

// ErrNoCommits means the repository has no commit to compare against yet.
var ErrNoCommits = errors.New("repository has no commits")

// git runs git in dir and returns trimmed stdout.
func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // fixed subcommands; Resolve rejects revisions that look like options
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// Root returns the top-level directory of the work tree containing dir.
func Root(ctx context.Context, dir string) (string, error) {
	out, err := git(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", ErrNotARepo
	}
	return out, nil
}

// CommonDir returns the absolute git directory shared by all worktrees, a
// place to keep caches that are never committed or scanned.
func CommonDir(ctx context.Context, dir string) (string, error) {
	out, err := git(ctx, dir, "rev-parse", "--git-common-dir")
	if err != nil {
		return "", ErrNotARepo
	}
	if !filepath.IsAbs(out) {
		out = filepath.Join(dir, out)
	}
	return filepath.Clean(out), nil
}

// Resolve returns the full commit SHA for rev. A rev starting with "-" is
// rejected so it can't be read as a git option.
func Resolve(ctx context.Context, dir, rev string) (string, error) {
	if strings.HasPrefix(rev, "-") {
		return "", fmt.Errorf("invalid revision %q", rev)
	}
	out, err := git(ctx, dir, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err != nil {
		if rev == "HEAD" {
			return "", ErrNoCommits
		}
		return "", fmt.Errorf("unknown revision %q", rev)
	}
	return out, nil
}

// AddWorktree checks out sha, detached, at path.
func AddWorktree(ctx context.Context, dir, path, sha string) error {
	_, err := git(ctx, dir, "worktree", "add", "--detach", "--quiet", path, sha)
	return err
}

// RemoveWorktree removes a worktree made by AddWorktree.
func RemoveWorktree(ctx context.Context, dir, path string) error {
	_, err := git(ctx, dir, "worktree", "remove", "--force", path)
	return err
}
