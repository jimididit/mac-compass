package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(triageCmd)
}

var triageCmd = &cobra.Command{
	Use:   "triage",
	Short: "Run quick triage commands (run first)",
	Long:  "Runs quick triage checks from the catalog: SIP status, Gatekeeper, KEXTs, persistence locations.",
	RunE:  func(cmd *cobra.Command, args []string) error { return runSection(cmd, "triage") },
}
