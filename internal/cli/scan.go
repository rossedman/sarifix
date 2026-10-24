package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rossedman/sarifix/internal/ui"
	"github.com/rossedman/sarifix/pkg/config"
	"github.com/rossedman/sarifix/pkg/finding"
	"github.com/rossedman/sarifix/pkg/placeholder"
	"github.com/rossedman/sarifix/pkg/scanner"
)

// init registers the scan command.
func init() { register("", newScanCmd) }

// scanResult is one scanner's outcome, also the --json shape.
type scanResult struct {
	Scanner  string   `json:"scanner"`
	Output   string   `json:"output,omitempty"`
	Command  []string `json:"command,omitempty"`
	Runs     int      `json:"runs"`
	Findings int      `json:"findings"`
	Seconds  float64  `json:"seconds"`
	Error    string   `json:"error,omitempty"`
}

// newScanCmd runs configured scanners and writes SARIF.
func newScanCmd(a *app) *cobra.Command {
	var names []string
	var outDir string
	var dryRun bool
	c := &cobra.Command{
		Use:   "scan",
		Short: "Run configured scanners and write SARIF",
		Long: `Run every scanner in sarifix.yaml (or the ones named with --scanner) over the
whole repo and write one SARIF file per scanner to --out-dir, named
<scanner>.sarif. Each result gets a sarifix/v1 partial fingerprint so later
diffs match findings without needing the files.

A scanner that exits non-zero but writes SARIF counts as a success, since
most tools exit non-zero when they find something.`,
		Example: `  sarifix scan
  sarifix scan --scanner trivy --out-dir sarif/
  sarifix scan --dry-run`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			l, err := a.loadConfig(config.ValidateOptions{})
			if err != nil {
				return err
			}
			repo, err := a.repo()
			if err != nil {
				return err
			}
			if !filepath.IsAbs(outDir) {
				outDir = filepath.Join(repo, outDir)
			}
			specs, err := selectScanners(l.Config, names)
			if err != nil {
				return &ExitError{Code: ExitConfig, Err: err}
			}
			var results []scanResult
			failed := 0
			for _, spec := range specs {
				var r scanResult
				if dryRun {
					r = planScan(spec, repo, outDir)
				} else {
					r = a.runScan(cmd, spec, repo, outDir)
				}
				if r.Error != "" {
					failed++
				}
				results = append(results, r)
			}
			if err := a.printScan(results, dryRun); err != nil {
				return err
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d scanners failed", failed, len(results))
			}
			return nil
		},
	}
	c.Flags().StringSliceVar(&names, "scanner", nil, "only run these scanners (repeatable)")
	c.Flags().StringVar(&outDir, "out-dir", "sarif", "directory for <scanner>.sarif files, relative to --repo")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "print the commands that would run, run nothing")
	return c
}

// selectScanners returns the named scanners, or every scanner with a
// command. Imported scanners have nothing to run.
func selectScanners(cfg *config.Config, names []string) ([]config.Scanner, error) {
	if len(cfg.Runnable()) == 0 {
		return nil, errors.New("no scanners with a command in sarifix.yaml")
	}
	if len(names) == 0 {
		return cfg.Runnable(), nil
	}
	var out []config.Scanner
	for _, n := range names {
		s, ok := cfg.Scanner(n)
		if !ok {
			return nil, fmt.Errorf("unknown scanner %q", n)
		}
		if s.Imported() {
			return nil, fmt.Errorf("scanner %q has no command: its findings come from code scanning (sarifix alerts export)", n)
		}
		out = append(out, *s)
	}
	return out, nil
}

// planScan reports the expanded command without running it.
func planScan(spec config.Scanner, repo, outDir string) scanResult {
	r := scanResult{Scanner: spec.Name, Output: filepath.Join(outDir, spec.Name+".sarif")}
	tmp := filepath.Join(outDir, ".tmp", spec.Name)
	argv, err := placeholder.ExpandArgs(spec.Command, placeholder.Vars{
		Out: filepath.Join(tmp, spec.Name+".sarif"), OutDir: tmp, Dir: repo, Repo: repo,
	})
	if err != nil {
		r.Error = err.Error()
	}
	r.Command = argv
	return r
}

// runScan runs one scanner into a private temp dir, then writes the
// fingerprinted SARIF to outDir/<name>.sarif.
func (a *app) runScan(cmd *cobra.Command, spec config.Scanner, repo, outDir string) scanResult {
	r := scanResult{Scanner: spec.Name}
	start := time.Now()
	defer func() { r.Seconds = time.Since(start).Round(time.Millisecond).Seconds() }()
	fail := func(err error) scanResult {
		r.Error = err.Error()
		a.log.Error("scanner failed", "scanner", spec.Name, "err", err)
		return r
	}
	tmp, err := os.MkdirTemp("", "sarifix-scan-")
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(tmp) //nolint:errcheck // best-effort cleanup
	a.log.Debug("running scanner", "scanner", spec.Name)
	log, err := scanner.NewExec(spec).Scan(cmd.Context(), scanner.ScanRequest{Repo: repo, Dir: repo, OutDir: tmp})
	if err != nil {
		return fail(err)
	}
	ex, err := finding.NewExtractor(repo)
	if err != nil {
		return fail(err)
	}
	fs := ex.Extract(log)
	finding.Annotate(fs)
	r.Runs, r.Findings = len(log.Runs), len(fs)
	r.Output = filepath.Join(outDir, spec.Name+".sarif")
	if err := log.WriteFile(r.Output); err != nil {
		return fail(err)
	}
	a.log.Info("scanned", "scanner", spec.Name, "findings", r.Findings)
	return r
}

// printScan renders scan results.
func (a *app) printScan(results []scanResult, dryRun bool) error {
	if a.jsonOut() {
		return a.writeJSON(results)
	}
	s := a.styles
	w := a.out()
	for _, r := range results {
		var line string
		switch {
		case r.Error != "":
			line = fmt.Sprintf("%s %s %s", s.Bad.Render("✗"), s.Key.Render(r.Scanner), s.Dim.Render(ui.Sanitize(r.Error, 300)))
		case dryRun:
			line = fmt.Sprintf("%s %s %s", s.Dim.Render("→"), s.Key.Render(r.Scanner), s.Text.Render(strings.Join(r.Command, " ")))
		default:
			line = fmt.Sprintf("%s %s %s %s %s", s.Fixed.Render("✓"), s.Key.Render(r.Scanner),
				s.Finding.Render(plural(r.Findings, "finding")), s.Dim.Render("→"), s.Path.Render(display(r.Output)))
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

// plural formats a count with a singular or plural noun ("batch" becomes
// "batches").
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	suffix := "s"
	if strings.HasSuffix(noun, "ch") || strings.HasSuffix(noun, "s") || strings.HasSuffix(noun, "x") {
		suffix = "es"
	}
	return fmt.Sprintf("%d %s%s", n, noun, suffix)
}
