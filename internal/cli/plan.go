package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rossedman/sarifix/internal/ui"
	"github.com/rossedman/sarifix/pkg/config"
	"github.com/rossedman/sarifix/pkg/finding"
	"github.com/rossedman/sarifix/pkg/glob"
	"github.com/rossedman/sarifix/pkg/plan"
	"github.com/rossedman/sarifix/pkg/sarif"
)

// init registers the plan command.
func init() { register("", newPlanCmd) }

// selection holds the flags plan and fix share.
type selection struct {
	sarif        []string
	baseline     []string
	baselineRoot string
	rules        []string
	campaign     string
}

// addFlags registers the shared selection flags on c.
func (s *selection) addFlags(c *cobra.Command) {
	c.Flags().StringSliceVar(&s.sarif, "sarif", nil, "SARIF files or globs to read (required)")
	c.Flags().StringSliceVar(&s.baseline, "baseline", nil, "SARIF of the base scan; findings also in it are skipped")
	c.Flags().StringVar(&s.baselineRoot, "baseline-root", "", "checkout the baseline was scanned in, for SARIF that 'sarifix scan' didn't write (default --repo)")
	c.Flags().StringSliceVar(&s.rules, "rule", nil, "only rule keys matching these globs, like trivy/DS-*")
	c.Flags().StringVar(&s.campaign, "campaign", "", "only findings in this campaign")
	_ = c.MarkFlagRequired("sarif")
}

// newPlanCmd shows the batches a fix run would attempt.
func newPlanCmd(a *app) *cobra.Command {
	var sel selection
	var details bool
	c := &cobra.Command{
		Use:   "plan",
		Short: "Show the batches a fix run would attempt, and why findings are skipped",
		Long: `Read SARIF, apply sarifix.yaml's rules, and print the batches a fix run would
attempt, in order, plus a count of skipped findings by reason. No agent is
called and nothing is written.

Batches group findings by <scanner>/<ruleId> (or campaign), split to respect
limits.files_per_batch and limits.findings_per_batch, ordered by severity
then size. Batches over limits.batches_per_run are listed as deferred.`,
		Example: `  sarifix plan --sarif 'sarif/*.sarif'
  sarifix plan --sarif 'sarif/*.sarif' --rule 'checkov/*' --details
  sarifix plan --sarif pr.sarif --baseline base.sarif --json`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			p, _, err := a.buildPlan(sel)
			if err != nil {
				return err
			}
			if a.jsonOut() {
				return a.writeJSON(p.Summarize())
			}
			return a.printPlan(a.out(), p, details)
		},
	}
	sel.addFlags(c)
	c.Flags().BoolVar(&details, "details", false, "list every finding under its batch, and every skipped finding")
	return c
}

// buildPlan loads config and SARIF and builds the plan.
func (a *app) buildPlan(sel selection) (*plan.Plan, *sarif.Log, error) {
	l, err := a.loadConfig(config.ValidateOptions{})
	if err != nil {
		return nil, nil, err
	}
	if sel.campaign != "" {
		found := false
		for _, c := range l.Campaigns {
			found = found || c.ID == sel.campaign
		}
		if !found {
			return nil, nil, &ExitError{Code: ExitConfig, Err: fmt.Errorf("unknown campaign %q", sel.campaign)}
		}
	}
	for _, g := range sel.rules {
		if err := glob.ValidateKey(g); err != nil {
			return nil, nil, &ExitError{Code: ExitConfig, Err: fmt.Errorf("bad --rule glob %q: %w", g, err)}
		}
	}
	repo, err := a.repo()
	if err != nil {
		return nil, nil, err
	}
	log, fs, err := a.loadLog(sel.sarif, repo)
	if err != nil {
		return nil, nil, err
	}
	var base []finding.Finding
	if len(sel.baseline) > 0 {
		root := sel.baselineRoot
		if root == "" {
			root = repo
		}
		if _, base, err = a.loadLog(sel.baseline, root); err != nil {
			return nil, nil, err
		}
	}
	p := plan.Build(l.Config, fs, plan.Options{Rules: sel.rules, Campaign: sel.campaign, Baseline: base})
	return p, log, nil
}

// printPlan renders a plan for people.
func (a *app) printPlan(w io.Writer, p *plan.Plan, details bool) error {
	s := a.styles
	sum := p.Summarize()
	skipped := sum.Findings - sum.Batched - sum.Deferred
	if _, err := fmt.Fprintf(w, "%s  %s  %s  %s\n",
		s.Text.Render(plural(sum.Findings, "finding")),
		s.Fixed.Render(fmt.Sprintf("%d batched in %s", sum.Batched, plural(len(sum.Run), "batch"))),
		s.Finding.Render(fmt.Sprintf("%d deferred", sum.Deferred)),
		s.Dim.Render(fmt.Sprintf("%d skipped", skipped))); err != nil {
		return err
	}
	byBatch := map[string][]plan.Entry{}
	for _, e := range p.Entries {
		if e.Status.Batch != "" {
			byBatch[e.Status.Batch] = append(byBatch[e.Status.Batch], e)
		}
	}
	sections := []struct {
		title   string
		batches []plan.BatchSummary
	}{{"Batches", sum.Run}, {"Deferred (over limits.batches_per_run)", sum.Later}}
	idWidth, sizeWidth := 0, 0
	for _, b := range append(append([]plan.BatchSummary(nil), sum.Run...), sum.Later...) {
		idWidth = max(idWidth, len(ui.Sanitize(b.ID, 80)))
		sizeWidth = max(sizeWidth, len(batchSize(b)))
	}
	for _, sec := range sections {
		if len(sec.batches) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "\n%s\n", s.Header.Render(sec.title)); err != nil {
			return err
		}
		numWidth := len(fmt.Sprint(len(sec.batches))) + 1
		indent := strings.Repeat(" ", 3+numWidth)
		for i, b := range sec.batches {
			if _, err := fmt.Fprintf(w, "  %s %s %s %s %s %s\n",
				s.Dim.Render(fmt.Sprintf("%*s", numWidth, fmt.Sprintf("%d.", i+1))),
				s.Key.Render(fmt.Sprintf("%-*s", idWidth, ui.Sanitize(b.ID, 80))),
				levelStyle(a, fmt.Sprintf("%-7s", b.Level)),
				s.Text.Render(fmt.Sprintf("%-*s", sizeWidth, batchSize(b))),
				s.Dim.Render("→"),
				s.Brand.Render(ui.Sanitize(b.Branch, 120))); err != nil {
				return err
			}
			if details {
				for _, e := range byBatch[b.ID] {
					if err := a.printEntry(w, indent, e); err != nil {
						return err
					}
				}
			} else if _, err := fmt.Fprintf(w, "%s%s\n", indent, s.Dim.Render(ui.Sanitize(strings.Join(b.Files, ", "), 200))); err != nil {
				return err
			}
		}
	}
	counts := sum.SkipCounts()
	if len(counts) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\n%s\n", s.Header.Render("Skipped")); err != nil {
		return err
	}
	width := 0
	for _, c := range counts {
		width = max(width, len(c.Reason))
	}
	for _, c := range counts {
		if _, err := fmt.Fprintf(w, "  %s %s\n", s.Text.Render(fmt.Sprintf("%-*s", width, c.Reason)), s.Dim.Render(fmt.Sprint(c.Count))); err != nil {
			return err
		}
		if !details {
			continue
		}
		for _, e := range p.Entries {
			if e.Status.Status == plan.StatusSkipped && e.Status.Reason == c.Reason {
				if err := a.printEntry(w, "     ", e); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// batchSize describes a batch's size, like "3 findings in 2 files".
func batchSize(b plan.BatchSummary) string {
	return plural(b.Findings, "finding") + " in " + plural(len(b.Files), "file")
}

// printEntry renders one finding with its detail.
func (a *app) printEntry(w io.Writer, indent string, e plan.Entry) error {
	s := a.styles
	loc := "(no location)"
	if e.Located() {
		loc = fmt.Sprintf("%s:%d", ui.Sanitize(e.Path, 0), e.StartLine)
	}
	detail := ""
	if e.Status.Detail != "" {
		detail = " " + s.Dim.Render("("+ui.Sanitize(e.Status.Detail, 80)+")")
	}
	_, err := fmt.Fprintf(w, "%s%s %s%s\n", indent, s.Key.Render(ui.Sanitize(e.Status.RuleKey, 80)), s.Path.Render(loc), detail)
	return err
}

// levelStyle renders a (possibly padded) SARIF level in its severity color.
func levelStyle(a *app, level string) string {
	switch strings.TrimSpace(level) {
	case finding.LevelError:
		return a.styles.Bad.Render(level)
	case finding.LevelWarning:
		return a.styles.Finding.Render(level)
	}
	return a.styles.Dim.Render(level)
}
