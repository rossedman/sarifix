package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/rossedman/sarifix/pkg/config"
)

// init registers config validate.
func init() { register("config", newConfigValidateCmd) }

// newConfigValidateCmd validates the config and prints resolved values.
func newConfigValidateCmd(a *app) *cobra.Command {
	var strict, quiet bool
	c := &cobra.Command{
		Use:   "validate",
		Short: "Validate config and print resolved values",
		Long: `Load sarifix.yaml (layered over --org-config when given), apply defaults,
validate it and print the resolved config. Errors name the file, the key
path and the line. Exits 2 when the config is invalid.`,
		Example: `  sarifix config validate
  sarifix config validate --strict --org-config org/sarifix.yaml
  sarifix config validate --json | jq .scanners`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			l, err := a.loadConfig(config.ValidateOptions{Strict: strict})
			if err != nil {
				return err
			}
			if a.jsonOut() {
				return a.writeJSON(l.Config)
			}
			s := a.styles
			w := a.out()
			for _, f := range l.Files {
				if _, err := fmt.Fprintf(w, "%s %s\n", s.Fixed.Render("✓"), s.Path.Render(display(f.Name))); err != nil {
					return err
				}
			}
			if quiet {
				return nil
			}
			out, err := yaml.Marshal(l.Config)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(w, "%s\n%s", s.Header.Render("# resolved config"), out)
			return err
		},
	}
	c.Flags().BoolVar(&strict, "strict", false, "also reject rules.allow globs that match no configured scanner")
	c.Flags().BoolVarP(&quiet, "quiet", "q", false, "only report validity, don't print the resolved config")
	return c
}
