package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/rossedman/sarifix/internal/ui"
	"github.com/rossedman/sarifix/pkg/baseline"
	"github.com/rossedman/sarifix/pkg/finding"
	"github.com/rossedman/sarifix/pkg/sarif"
)

// init registers the diff command.
func init() { register("", newDiffCmd) }

// diffJSON is the --json shape of diff.
type diffJSON struct {
	Counts struct {
		New       int `json:"new"`
		Fixed     int `json:"fixed"`
		Unchanged int `json:"unchanged"`
	} `json:"counts"`
	baseline.Diff
}

// maxMessage is how much of an untrusted message human output shows.
const maxMessage = 120

// newDiffCmd compares two SARIF sets by fingerprint.
func newDiffCmd(a *app) *cobra.Command {
	var base, head []string
	var baseRoot string
	var all bool
	c := &cobra.Command{
		Use:   "diff",
		Short: "Print new, fixed and unchanged findings by fingerprint",
		Long: `Compare a base and a head SARIF set by fingerprint. Line numbers never count,
so findings that only moved are unchanged.

Fingerprints come from primaryLocationLineHash when the tool provides it,
then other partialFingerprints, then a hash of the flagged lines. The lines
come from the SARIF snippet; else the sarifix/v1 fingerprint that 'sarifix
scan' recorded is used; else they are read from the files: under --repo for
head and --base-root for base (default --repo).`,
		Example: `  sarifix diff --base main.sarif --head pr.sarif
  sarifix diff --base 'base/*.sarif' --head 'sarif/*.sarif' --json`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			repo, err := a.repo()
			if err != nil {
				return err
			}
			if baseRoot == "" {
				baseRoot = repo
			}
			bf, err := a.loadFindings(base, baseRoot)
			if err != nil {
				return err
			}
			hf, err := a.loadFindings(head, repo)
			if err != nil {
				return err
			}
			d := baseline.Compare(bf, hf)
			if a.jsonOut() {
				var out diffJSON
				out.Diff = d
				out.Counts.New, out.Counts.Fixed, out.Counts.Unchanged = len(d.New), len(d.Fixed), len(d.Unchanged)
				return a.writeJSON(out)
			}
			return a.printDiff(d, all)
		},
	}
	c.Flags().StringSliceVar(&base, "base", nil, "base SARIF files or globs (required)")
	c.Flags().StringSliceVar(&head, "head", nil, "head SARIF files or globs (required)")
	c.Flags().StringVar(&baseRoot, "base-root", "", "checkout of the base commit, for reading snippets (default --repo)")
	c.Flags().BoolVar(&all, "unchanged", false, "also list unchanged findings")
	_ = c.MarkFlagRequired("base")
	_ = c.MarkFlagRequired("head")
	return c
}

// loadFindings loads SARIF globs and extracts findings against root.
func (a *app) loadFindings(globs []string, root string) ([]finding.Finding, error) {
	_, fs, err := a.loadLog(globs, root)
	return fs, err
}

// loadLog loads SARIF globs, logs skipped inputs, and extracts findings
// against root.
func (a *app) loadLog(globs []string, root string) (*sarif.Log, []finding.Finding, error) {
	log, warns, err := sarif.LoadGlobs(globs, sarif.Options{})
	if err != nil {
		if errors.Is(err, sarif.ErrNoFiles) {
			return nil, nil, &ExitError{Code: ExitRuntime, Err: err}
		}
		return nil, nil, err
	}
	for _, w := range warns {
		a.log.Warn("SARIF input skipped", "source", w.Source, "run", w.Run, "reason", ui.Sanitize(w.Msg, 200))
	}
	ex, err := finding.NewExtractor(root)
	if err != nil {
		return nil, nil, err
	}
	return log, ex.Extract(log), nil
}

// printDiff renders a diff for people.
func (a *app) printDiff(d baseline.Diff, all bool) error {
	s := a.styles
	w := a.out()
	if _, err := fmt.Fprintf(w, "%s  %s  %s\n",
		s.Finding.Render(fmt.Sprintf("%d new", len(d.New))),
		s.Fixed.Render(fmt.Sprintf("%d fixed", len(d.Fixed))),
		s.Dim.Render(fmt.Sprintf("%d unchanged", len(d.Unchanged)))); err != nil {
		return err
	}
	sections := []struct {
		title string
		mark  string
		fs    []finding.Finding
		show  bool
	}{
		{"New", s.Finding.Render("+"), d.New, true},
		{"Fixed", s.Fixed.Render("-"), d.Fixed, true},
		{"Unchanged", s.Dim.Render("="), d.Unchanged, all},
	}
	for _, sec := range sections {
		if !sec.show || len(sec.fs) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "\n%s\n", s.Header.Render(sec.title)); err != nil {
			return err
		}
		for _, f := range sec.fs {
			if err := a.printFinding(w, sec.mark, f); err != nil {
				return err
			}
		}
	}
	return nil
}

// printFinding renders one finding line.
func (a *app) printFinding(w io.Writer, mark string, f finding.Finding) error {
	s := a.styles
	loc := "(no location)"
	if f.Located() {
		loc = ui.Sanitize(f.Path, 0)
		if f.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.StartLine)
		}
	}
	_, err := fmt.Fprintf(w, "  %s %s %s %s\n", mark,
		s.Key.Render(ui.Sanitize(finding.RuleKey(f.Tool, f.RuleID), 80)),
		s.Path.Render(loc),
		s.Dim.Render(ui.Sanitize(f.Message, maxMessage)))
	return err
}
