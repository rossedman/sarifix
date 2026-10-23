package cli

import "github.com/spf13/cobra"

// init registers the config parent command.
func init() { register("", newConfigCmd) }

// newConfigCmd groups config subcommands.
func newConfigCmd(*app) *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Inspect and validate sarifix.yaml",
		Args:  cobra.NoArgs,
	}
}
