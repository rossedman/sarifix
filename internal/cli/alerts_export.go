package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/rossedman/sarifix/internal/github"
	"github.com/rossedman/sarifix/pkg/config"
	"github.com/rossedman/sarifix/pkg/policy"
)

// init registers alerts export.
func init() { register("alerts", newAlertsExportCmd) }

// alertsExport is the JSON result of alerts export.
type alertsExport struct {
	Out      string               `json:"out,omitempty"`
	Scanners []alertsExportCounts `json:"scanners"`
}

// alertsExportCounts is how many alerts one imported scanner got.
type alertsExportCounts struct {
	Scanner string `json:"scanner"`
	Alerts  int    `json:"alerts"`
}

// newAlertsExportCmd writes open code scanning alerts as SARIF.
func newAlertsExportCmd(a *app) *cobra.Command {
	var out, repo, ref string
	c := &cobra.Command{
		Use:   "export",
		Short: "Write open code scanning alerts as SARIF for imported scanners",
		Long: `Read the repository's open code scanning alerts and write the ones that
belong to imported scanners as one SARIF file, for plan and fix to read
alongside sarifix's own scan. An imported scanner is one in sarifix.yaml
with no command, such as CodeQL: sarifix never runs it, and its alerts
already in code scanning become batches and issues like any other finding.

Each imported scanner gets a run even when it has no open alerts, so issues
mode knows it was read and closes its fixed issues. Alerts from tools that
no imported scanner matches are left out: sarifix's own scan already covers
the scanners it runs. With no imported scanners, it writes nothing and
calls no API.

Needs GITHUB_TOKEN (or GH_TOKEN) with security-events read, and
GITHUB_REPOSITORY or --github-repo.`,
		Example: `  sarifix alerts export --github-repo acme/infra
  sarifix alerts export --out /tmp/alerts.sarif
  sarifix fix --mode issues --sarif 'sarif/*.sarif' --dry-run`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			l, err := a.loadConfig(config.ValidateOptions{})
			if err != nil {
				return err
			}
			var imported []config.Scanner
			for _, s := range l.Scanners {
				if s.Imported() {
					imported = append(imported, s)
				}
			}
			res := alertsExport{Scanners: []alertsExportCounts{}}
			if len(imported) == 0 {
				a.log.Info("no imported scanners (scanners without a command) in sarifix.yaml; nothing to export")
				if a.jsonOut() {
					return a.writeJSON(res)
				}
				return nil
			}
			gh, err := github.FromEnv(repo)
			if err != nil {
				return &ExitError{Code: ExitConfig, Err: err}
			}
			alerts, err := gh.Alerts(cmd.Context(), ref)
			if err != nil {
				return err
			}
			runs := make([]github.AlertRun, len(imported))
			index := map[string]int{}
			for i, s := range imported {
				runs[i].Tool = s.Match[0]
				index[s.Name] = i
			}
			pol := policy.New(l.Config, policy.Options{})
			for _, al := range alerts {
				name, ok := pol.Route(al.Tool.Name)
				i, imp := index[name]
				if !ok || !imp {
					continue
				}
				runs[i].Tool, runs[i].Version = al.Tool.Name, al.Tool.Version
				runs[i].Alerts = append(runs[i].Alerts, al)
			}
			var buf bytes.Buffer
			if err := github.WriteSARIF(&buf, runs); err != nil {
				return err
			}
			if !filepath.IsAbs(out) {
				root, err := a.repo()
				if err != nil {
					return err
				}
				out = filepath.Join(root, out)
			}
			if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
				return err
			}
			if err := os.WriteFile(out, buf.Bytes(), 0o600); err != nil {
				return err
			}
			res.Out = out
			for i, s := range imported {
				res.Scanners = append(res.Scanners, alertsExportCounts{Scanner: s.Name, Alerts: len(runs[i].Alerts)})
			}
			if a.jsonOut() {
				return a.writeJSON(res)
			}
			st := a.styles
			for _, n := range res.Scanners {
				noun := "alerts"
				if n.Alerts == 1 {
					noun = "alert"
				}
				if _, err := fmt.Fprintf(a.out(), "%s %s %d open %s → %s\n", st.Fixed.Render("✓"), st.Key.Render(n.Scanner),
					n.Alerts, noun, st.Path.Render(display(out))); err != nil {
					return err
				}
			}
			return nil
		},
	}
	c.Flags().StringVar(&out, "out", "sarif/code-scanning.sarif", "SARIF file to write, relative to --repo")
	c.Flags().StringVar(&repo, "github-repo", "", "owner/name (default $GITHUB_REPOSITORY)")
	c.Flags().StringVar(&ref, "ref", "", "the Git ref whose alerts to read, such as refs/heads/main (default: the default branch)")
	return c
}
