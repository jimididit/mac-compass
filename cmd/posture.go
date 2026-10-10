package cmd

import (
	"github.com/jimididit/mac-compass/internal/catalog"
	"github.com/spf13/cobra"
)

// postureView makes a run print the hardening posture instead of raw check output and findings.
var postureView bool

func init() {
	rootCmd.AddCommand(postureCmd)
}

var postureCmd = &cobra.Command{
	Use:   "posture",
	Short: "Score the Mac against hardening controls",
	Long: "Runs every read-only check and scores the result against a list of hardening controls drawn from the " +
		"macOS Security Compliance Project (the source of the CIS and NIST macOS benchmarks). " +
		"Use --json for the full control list, including each control's mSCP rule id.",
	RunE: func(cmd *cobra.Command, args []string) error {
		postureView = true
		cat, err := catalog.Load()
		if err != nil {
			return err
		}
		return runSections(cmd, cat.Sections())
	},
}
