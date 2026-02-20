package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jimididit/mac-compass/internal/catalog"
	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/runner"
	"github.com/spf13/cobra"
)

var (
	runAllYes bool
)

func init() {
	runAllCmd.Flags().BoolVarP(&runAllYes, "yes", "y", false, "Skip confirmation prompt")
}

var runAllCmd = &cobra.Command{
	Use:   "run-all",
	Short: "Run all safe checks",
	Long:  "Run checks from all sections (triage, processes, kernel, persistence, network, security-tools, advanced, harden). Prompts for confirmation unless -y.",
	RunE:  runRunAll,
}

func runRunAll(cmd *cobra.Command, args []string) error {
	cat, err := catalog.Load()
	if err != nil {
		return err
	}
	sections := cat.Sections()
	var total int
	for _, s := range sections {
		total += len(cat.BySection(s))
	}
	if !runAllYes {
		fmt.Fprintf(cmd.OutOrStdout(), "This will run %d checks across %d sections. Some require sudo.\n", total, len(sections))
		fmt.Fprint(cmd.OutOrStdout(), "Continue? [y/N]: ")
		scanner := bufio.NewScanner(cmd.InOrStdin())
		if !scanner.Scan() {
			return nil
		}
		if !strings.EqualFold(strings.TrimSpace(scanner.Text()), "y") {
			cmd.Println("Aborted.")
			return nil
		}
	}
	opts := runner.Options{
		Timeout:   timeout,
		UseSudo:   !noSudo,
		SkipSudo:  noSudo,
		VMMode:    vmMode,
		OutWriter: cmd.OutOrStdout(),
		ErrWriter: cmd.ErrOrStderr(),
	}
	ctx := cmd.Context()

	if jsonOutput {
		var allResults []output.SectionResult
		for _, sectionID := range sections {
			checks := cat.BySection(sectionID)
			var sectionChecks []output.CheckResult
			for _, ch := range checks {
				stdout, stderr, runErr := runner.RunCheckCapture(ctx, ch, opts)
				cr := output.CheckResult{Section: sectionID, Name: ch.Name, Stdout: stdout, Stderr: stderr}
				if runErr != nil {
					cr.Ok = false
					cr.Error = runErr.Error()
				} else {
					cr.Ok = true
				}
				sectionChecks = append(sectionChecks, cr)
			}
			allResults = append(allResults, output.SectionResult{Section: sectionID, Checks: sectionChecks})
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(allResults)
	}

	for _, sectionID := range sections {
		fmt.Fprintf(cmd.OutOrStdout(), "\n========== %s ==========\n", sectionID)
		if err := runSection(cmd, sectionID); err != nil {
			return err
		}
	}
	return nil
}
