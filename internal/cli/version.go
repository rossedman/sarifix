package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/rossedman/sarifix/internal/version"
)

// init registers the version command.
func init() { register("", newVersionCmd) }

// newVersionCmd prints build information.
func newVersionCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit and build date",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			info := version.Get()
			if a.jsonOut() {
				return a.writeJSON(info)
			}
			s := a.styles
			_, err := fmt.Fprintf(a.out(), "%s %s\n%s %s\n%s %s\n",
				s.Title.Render("sarifix"), s.Text.Render(info.Version),
				s.Dim.Render("commit"), s.Text.Render(orNone(info.Commit)),
				s.Dim.Render("built "), s.Text.Render(orNone(info.Date)))
			return err
		},
	}
}

// orNone shows "unknown" for empty build fields.
func orNone(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
