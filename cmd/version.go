package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var version = "0.5.0" // set by build: -ldflags "-X github.com/jimididit/mac-compass/cmd.version=..."

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(cmd.OutOrStdout(), "mac-compass", version)
		return nil
	},
}
