package cli

import "github.com/spf13/cobra"

// init registers the alerts parent command.
func init() { register("", newAlertsCmd) }

// newAlertsCmd groups code scanning alert subcommands.
func newAlertsCmd(*app) *cobra.Command {
	return &cobra.Command{
		Use:   "alerts",
		Short: "Bring GitHub code scanning alerts into sarifix",
		Args:  cobra.NoArgs,
	}
}
