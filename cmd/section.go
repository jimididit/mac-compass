package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/jimididit/mac-compass/internal/catalog"
	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/runner"
	"github.com/spf13/cobra"
)

// runSection loads the catalog, runs all checks for sectionID, and writes output to cmd.
func runSection(cmd *cobra.Command, sectionID string) error {
	cat, err := catalog.Load()
	if err != nil {
		return err
	}
	checks := cat.BySection(sectionID)
	if len(checks) == 0 {
		cmd.Printf("No checks for section %q in catalog.\n", sectionID)
		return nil
	}
	opts := runner.Options{
		Timeout:   timeout,
		UseSudo:   !noSudo,
		SkipSudo:  noSudo,
		VMMode:    vmMode,
		OutWriter: cmd.OutOrStdout(),
		ErrWriter: cmd.ErrOrStderr(),
	}
	if reportPath != "" && !jsonOutput {
		f, err := os.OpenFile(reportPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("open report file: %w", err)
		}
		defer f.Close()
		opts.OutWriter = io.MultiWriter(opts.OutWriter, f)
		opts.ErrWriter = io.MultiWriter(opts.ErrWriter, f)
	}
	ctx := cmd.Context()

	if jsonOutput {
		var results []output.CheckResult
		for _, ch := range checks {
			stdout, stderr, runErr := runner.RunCheckCapture(ctx, ch, opts)
			cr := output.CheckResult{Section: sectionID, Name: ch.Name, Stdout: stdout, Stderr: stderr}
			if runErr != nil {
				cr.Ok = false
				cr.Error = runErr.Error()
			} else {
				cr.Ok = true
			}
			results = append(results, cr)
		}
		sectionResults := []output.SectionResult{{Section: sectionID, Checks: results}}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(sectionResults)
	}

	for _, ch := range checks {
		fmt.Fprintf(cmd.OutOrStdout(), "\n--- %s ---\n", ch.Name)
		if ch.Description != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "# %s\n", ch.Description)
		}
		if err := runner.RunCheck(ctx, ch, opts); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "  error: %v\n", err)
		}
	}
	fmt.Fprintln(cmd.OutOrStdout())
	return nil
}

