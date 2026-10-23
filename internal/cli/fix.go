package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/rossedman/sarifix/internal/github"
	"github.com/rossedman/sarifix/internal/gitrepo"
	"github.com/rossedman/sarifix/internal/ui"
	"github.com/rossedman/sarifix/pkg/config"
	"github.com/rossedman/sarifix/pkg/group"
	"github.com/rossedman/sarifix/pkg/plan"
	"github.com/rossedman/sarifix/pkg/policy"
	"github.com/rossedman/sarifix/pkg/publish"
	"github.com/rossedman/sarifix/pkg/sarif"
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

// fixIssues is the --json shape of fix --mode issues.
type fixIssues struct {
	Mode    string           `json:"mode"`
	Repo    string           `json:"repo"`
	DryRun  bool             `json:"dryRun"`
	Actions []publish.Action `json:"actions"`
}

// issueFlags are fix's --mode issues flags. Negative numbers mean "use
// sarifix.yaml".
type issueFlags struct {
	repo    string
	dryRun  bool
	maxOpen int
	queue   int
}

// newFixCmd runs the pipeline in report or issues mode.
func newFixCmd(a *app) *cobra.Command {
	var sel selection
	var mode, outDir string
	var iss issueFlags
	c := &cobra.Command{
		Use:   "fix",
		Short: "Run the fix pipeline (report and issues modes today)",
		Long: `Run the full pipeline: ingest SARIF, filter, group, fix, verify, publish.

Modes:
  report  write enriched SARIF (properties.sarifix on every finding, with
          its status, reason and batch) and a JSON summary; no edits
  issues  keep one GitHub issue per batch, in the agent-ready format: open
          new ones (up to publish.issues.max_open), refresh changed ones,
          close fixed ones, and label publish.issues.queue of them for an
          agent queue; needs GITHUB_TOKEN and GITHUB_REPOSITORY (or
          --github-repo)
  local   leave verified fixes in the working tree (phase 2, planned)
  pr      open one PR per batch (phase 3, planned)
  review  post suggested changes on a PR (phase 4, planned)`,
		Example: `  sarifix fix --mode report --sarif 'sarif/*.sarif'
  sarifix fix --mode report --sarif 'sarif/*.sarif' --out-dir out/ --json
  sarifix fix --mode issues --sarif 'sarif/*.sarif' --dry-run
  sarifix fix --mode issues --sarif 'sarif/*.sarif' --queue 1`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if phase, ok := modePhase[mode]; ok {
				return fmt.Errorf("--mode %s is not built yet (roadmap phase %d); use --mode report or issues", mode, phase)
			}
			if mode != "report" && mode != "issues" {
				return &ExitError{Code: ExitConfig, Err: fmt.Errorf("unknown --mode %q (want report, issues, local, pr or review)", mode)}
			}
			p, log, err := a.buildPlan(sel)
			if err != nil {
				return err
			}
			if mode == "issues" {
				return a.fixIssues(cmd, p, log, iss)
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
	c.Flags().StringVar(&mode, "mode", "report", "report, issues, local, pr or review")
	c.Flags().StringVar(&outDir, "out-dir", "sarifix-report", "report mode: directory for sarifix.sarif and summary.json, relative to --repo")
	c.Flags().StringVar(&iss.repo, "github-repo", "", "issues mode: owner/name (default $GITHUB_REPOSITORY)")
	c.Flags().BoolVar(&iss.dryRun, "dry-run", false, "issues mode: print what would change without writing to GitHub")
	c.Flags().IntVar(&iss.maxOpen, "max-open", -1, "issues mode: most open batch issues (default publish.issues.max_open)")
	c.Flags().IntVar(&iss.queue, "queue", -1, "issues mode: issues to keep labeled for an agent (default publish.issues.queue)")
	return c
}

// fixIssues syncs one GitHub issue per batch and reports what changed.
func (a *app) fixIssues(cmd *cobra.Command, p *plan.Plan, log *sarif.Log, f issueFlags) error {
	l, err := a.loadConfig(config.ValidateOptions{})
	if err != nil {
		return err
	}
	cfg := l.Publish.Issues
	if f.maxOpen >= 0 {
		cfg.MaxOpen = f.maxOpen
	}
	if f.queue >= 0 {
		cfg.Queue = f.queue
	}
	if cfg.MaxOpen < 1 || cfg.Queue > cfg.MaxOpen {
		return &ExitError{Code: ExitConfig, Err: fmt.Errorf("--queue (%d) must be between 0 and --max-open (%d), and --max-open at least 1", cfg.Queue, cfg.MaxOpen)}
	}
	gh, err := github.FromEnv(f.repo)
	if err != nil {
		return &ExitError{Code: ExitConfig, Err: err}
	}
	ctx := cmd.Context()
	links := publish.Links{Server: os.Getenv("GITHUB_SERVER_URL"), Repo: gh.Repo, Commit: os.Getenv("GITHUB_SHA")}
	if links.Server == "" {
		links.Server = "https://github.com"
	}
	if links.Commit == "" {
		if repo, err := a.repo(); err == nil {
			links.Commit, _ = gitrepo.Resolve(ctx, repo, "HEAD")
		}
	}
	if !f.dryRun {
		if err := gh.EnsureLabel(ctx, cfg.Label, "5319e7", "Found by sarifix: one issue per batch of findings"); err != nil {
			return err
		}
		if cfg.Queue > 0 {
			if err := gh.EnsureLabel(ctx, cfg.QueueLabel, "0e8a16", "Ready for an agent to fix"); err != nil {
				return err
			}
		}
	}
	batches := append(append([]group.Batch(nil), p.Batches.Run...), p.Batches.Deferred...)
	scanned := scannedBy(l.Config, log)
	for _, s := range l.Scanners {
		if !scanned[s.Name] {
			a.log.Warn("no SARIF from this scanner, so its issues stay open", "scanner", s.Name)
		}
	}
	actions, err := publish.Issues(ctx, gh, batches, publish.IssuesOptions{
		Label: cfg.Label, MaxOpen: cfg.MaxOpen, Queue: cfg.Queue, QueueLabel: cfg.QueueLabel, Links: links,
		Scanned: scanned, DryRun: f.dryRun,
	})
	if a.jsonOut() {
		if err != nil {
			return err
		}
		return a.writeJSON(fixIssues{Mode: "issues", Repo: gh.Repo, DryRun: f.dryRun, Actions: nonNilActions(actions)})
	}
	// On error, still show what was done before it.
	printIssueActions(a, a.out(), gh.Repo, f.dryRun, len(batches), actions, err == nil)
	return err
}

// scannedBy names the configured scanners that have a run in log.
func scannedBy(cfg *config.Config, log *sarif.Log) map[string]bool {
	pol := policy.New(cfg, policy.Options{})
	out := map[string]bool{}
	for _, r := range log.Runs {
		if name, ok := pol.Route(r.Driver()); ok {
			out[name] = true
		}
	}
	return out
}

// nonNilActions returns as, or an empty list, so JSON shows [] not null.
func nonNilActions(as []publish.Action) []publish.Action {
	if as == nil {
		return []publish.Action{}
	}
	return as
}

// printIssueActions lists what fix --mode issues changed, one line each.
func printIssueActions(a *app, w io.Writer, repo string, dryRun bool, batches int, actions []publish.Action, done bool) {
	s := a.styles
	verb := map[string]string{publish.ActionCreate: "opened", publish.ActionUpdate: "updated", publish.ActionClose: "closed", publish.ActionQueue: "queued"}
	if dryRun {
		verb = map[string]string{publish.ActionCreate: "would open", publish.ActionUpdate: "would update", publish.ActionClose: "would close", publish.ActionQueue: "would queue"}
	}
	for _, act := range actions {
		ref := ""
		if act.Number > 0 {
			ref = fmt.Sprintf(" #%d", act.Number)
		}
		_, _ = fmt.Fprintf(w, "%s %s%s %s\n", s.Fixed.Render("✓"), verb[act.Kind], ref, s.Key.Render(ui.Sanitize(act.Batch, 0)))
	}
	if len(actions) == 0 && done {
		_, _ = fmt.Fprintf(w, "%s %s issues already match %d batches\n", s.Fixed.Render("✓"), repo, batches)
	}
}
