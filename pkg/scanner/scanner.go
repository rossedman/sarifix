// Package scanner runs configured SARIF-emitting tools and routes SARIF runs
// to the scanner that owns them.
package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rossedman/sarifix/pkg/config"
	"github.com/rossedman/sarifix/pkg/placeholder"
	"github.com/rossedman/sarifix/pkg/sarif"
)

// Scanner is one SARIF producer.
type Scanner interface {
	// Name is the scanner's configured name.
	Name() string
	// Matches reports whether a SARIF tool.driver.name belongs to it.
	Matches(driverName string) bool
	// Scan runs the tool and returns the SARIF it wrote.
	Scan(ctx context.Context, req ScanRequest) (*sarif.Log, error)
}

// ScanRequest says what to scan and where to write output.
type ScanRequest struct {
	// Repo is the absolute repo root ({repo}).
	Repo string
	// Dir is the absolute directory to scan ({dir}); defaults to Repo.
	Dir string
	// Paths are repo-relative files to scan ({paths}), for changed scope.
	Paths []string
	// OutDir is where the tool writes SARIF ({outdir}).
	OutDir string
	// Validate SARIF output against the schema.
	Options sarif.Options
}

// Exec runs a scanner described by config as a subprocess, without a shell.
type Exec struct {
	Spec config.Scanner
	// Environ is the base environment; nil means os.Environ().
	Environ []string
}

// NewExec returns an Exec scanner for spec.
func NewExec(spec config.Scanner) *Exec {
	return &Exec{Spec: spec}
}

// Name returns the configured name.
func (e *Exec) Name() string { return e.Spec.Name }

// Matches compares driver names case-insensitively against match values.
func (e *Exec) Matches(driverName string) bool {
	for _, m := range e.Spec.Match {
		if strings.EqualFold(m, driverName) {
			return true
		}
	}
	return false
}

// ErrNoOutput means the tool exited without writing SARIF.
var ErrNoOutput = errors.New("scanner wrote no SARIF output")

// stderrTail bounds how much tool stderr is kept in errors.
const stderrTail = 2048

// Scan expands the command, runs it and loads its SARIF. Many scanners exit
// non-zero when they find something, so the exit status only counts as a
// failure when no SARIF was written.
func (e *Exec) Scan(ctx context.Context, req ScanRequest) (*sarif.Log, error) {
	if req.Dir == "" {
		req.Dir = req.Repo
	}
	if err := os.MkdirAll(req.OutDir, 0o750); err != nil {
		return nil, err
	}
	vars := placeholder.Vars{
		Out:    filepath.Join(req.OutDir, e.Spec.Name+".sarif"),
		OutDir: req.OutDir,
		Dir:    req.Dir,
		Repo:   req.Repo,
		Paths:  req.Paths,
	}
	argv, err := placeholder.ExpandArgs(e.Spec.Command, vars)
	if err != nil {
		return nil, err
	}
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	output, err := placeholder.Expand(e.Spec.Output, vars)
	if err != nil {
		return nil, err
	}
	workdir, err := placeholder.Expand(e.Spec.Workdir, vars)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(workdir) {
		workdir = filepath.Join(req.Repo, workdir)
	}
	if !filepath.IsAbs(output) {
		output = filepath.Join(workdir, output)
	}
	env, err := e.env(vars)
	if err != nil {
		return nil, err
	}
	// Remove stale output so an old file is never mistaken for this run's.
	if err := os.Remove(output); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if t := e.Spec.Timeout.Std(); t > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv comes from the repo's own config
	cmd.Dir = workdir
	cmd.Env = env
	cmd.WaitDelay = 5 * time.Second
	isolate(cmd)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s: %w", e.Spec.Name, ctx.Err())
	}
	if _, statErr := os.Stat(output); statErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("%s: %w: %s", e.Spec.Name, runErr, tail(stderr.String()))
		}
		return nil, fmt.Errorf("%s: %w at %s", e.Spec.Name, ErrNoOutput, output)
	}
	log, warns, err := sarif.LoadFile(output, req.Options)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", e.Spec.Name, err)
	}
	if len(log.Runs) == 0 && len(warns) > 0 {
		return nil, fmt.Errorf("%s: %s", e.Spec.Name, warns[0].Msg)
	}
	return log, nil
}

// env builds the subprocess environment with expanded extra variables.
func (e *Exec) env(vars placeholder.Vars) ([]string, error) {
	base := e.Environ
	if base == nil {
		base = os.Environ()
	}
	env := append([]string(nil), base...)
	keys := make([]string, 0, len(e.Spec.Env))
	for k := range e.Spec.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, err := placeholder.Expand(e.Spec.Env[k], vars)
		if err != nil {
			return nil, err
		}
		env = append(env, k+"="+v)
	}
	return env, nil
}

// tail returns the last stderrTail bytes of s, trimmed.
func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > stderrTail {
		s = "..." + s[len(s)-stderrTail:]
	}
	return s
}

// Registry holds the configured scanners in order.
type Registry struct {
	scanners []Scanner
}

// NewRegistry builds Exec scanners for every configured scanner.
func NewRegistry(cfg *config.Config) *Registry {
	r := &Registry{}
	for _, s := range cfg.Scanners {
		r.scanners = append(r.scanners, NewExec(s))
	}
	return r
}

// NewRegistryOf builds a registry from existing scanners (used with fakes).
func NewRegistryOf(s ...Scanner) *Registry {
	return &Registry{scanners: s}
}

// All returns every scanner in config order.
func (r *Registry) All() []Scanner {
	return r.scanners
}

// Get returns the scanner with the given name.
func (r *Registry) Get(name string) (Scanner, bool) {
	for _, s := range r.scanners {
		if s.Name() == name {
			return s, true
		}
	}
	return nil, false
}

// Route returns the scanner that owns a SARIF run, by tool.driver.name.
func (r *Registry) Route(driverName string) (Scanner, bool) {
	for _, s := range r.scanners {
		if s.Matches(driverName) {
			return s, true
		}
	}
	return nil, false
}
