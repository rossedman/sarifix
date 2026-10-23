package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/rossedman/sarifix/pkg/publish"
)

// init registers the fix command.
func init() { register("", newFixCmd) }

// modePhase says which roadmap phase brings each mode not yet built.
var modePhase = map[string]int{"local": 2, "pr": 3, "review": 4}

// fixReport is the --json shape of fix --mode report.
type fixReport struct {
	Mode  string              `json:"mode"`
	Files publish.ReportFiles `json:"files"`
	Batch int                 `json:"batches"`
}

// newFixCmd runs the pipeline. Only report mode exists so far.
func newFixCmd(a *app) *cobra.Command {
	var sel selection
	var mode, outDir string
	c := &cobra.Command{
		Use:   "fix",
		Short: "Run the fix pipeline (report mode today)",
		Long: `Run the full pipeline: ingest SARIF, filter, group, fix, verify, publish.

Modes:
  report  write enriched SARIF (properties.sarifix on every finding, with
          its status, reason and batch) and a JSON summary; no edits
  local   leave verified fixes in the working tree (phase 2, planned)
  pr      open one PR per batch (phase 3, planned)
  review  post suggested changes on a PR (phase 4, planned)`,
		Example: `  sarifix fix --mode report --sarif 'sarif/*.sarif'
  sarifix fix --mode report --sarif 'sarif/*.sarif' --out-dir out/ --json`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if phase, ok := modePhase[mode]; ok {
				return fmt.Errorf("--mode %s is not built yet (roadmap phase %d); use --mode report", mode, phase)
			}
			if mode != "report" {
				return &ExitError{Code: ExitConfig, Err: fmt.Errorf("unknown --mode %q (want report, local, pr or review)", mode)}
			}
			p, log, err := a.buildPlan(sel)
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
			files, err := publish.Report(outDir, log, p)
			if err != nil {
				return err
			}
			if a.jsonOut() {
				return a.writeJSON(fixReport{Mode: mode, Files: files, Batch: len(p.Batches.Run)})
			}
			w := a.out()
			if err := a.printPlan(w, p, false, sel); err != nil {
				return err
			}
			s := a.styles
			_, err = fmt.Fprintf(w, "\n%s %s\n%s %s\n", s.Fixed.Render("✓"), s.Path.Render(display(files.SARIF)),
				s.Fixed.Render("✓"), s.Path.Render(display(files.Summary)))
			return err
		},
	}
	sel.addFlags(c)
	c.Flags().StringVar(&mode, "mode", "report", "report, local, pr or review")
	c.Flags().StringVar(&outDir, "out-dir", "sarifix-report", "report mode: directory for sarifix.sarif and summary.json, relative to --repo")
	return c
}
