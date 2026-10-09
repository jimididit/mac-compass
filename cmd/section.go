package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/jimididit/mac-compass/internal/catalog"
	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/runner"
	"github.com/spf13/cobra"
)

// errChecksFailed is returned (and mapped to exit status 1) when any check failed.
var errChecksFailed = errors.New("one or more checks failed")

// requireDarwin refuses to run checks on non-macOS hosts unless overridden for development.
func requireDarwin() error {
	if runtime.GOOS == "darwin" || os.Getenv("MAC_COMPASS_ALLOW_NON_DARWIN") == "1" {
		return nil
	}
	return fmt.Errorf("mac-compass checks only run on macOS (detected %s); set MAC_COMPASS_ALLOW_NON_DARWIN=1 to override", runtime.GOOS)
}

// runnerOptions builds runner options from the global flags.
func runnerOptions(cmd *cobra.Command) runner.Options {
	return runner.Options{
		Timeout:         timeout,
		UseSudo:         !noSudo,
		SkipSudo:        noSudo,
		VMMode:          vmMode,
		MacOSMajor:      runner.DetectMacOSMajor(),
		SudoAllowPrompt: hasTTY(),
		OutWriter:       cmd.OutOrStdout(),
		ErrWriter:       cmd.ErrOrStderr(),
	}
}

func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

// collectSection runs every check in a section, capturing results for JSON output.
func collectSection(ctx context.Context, sectionID string, checks []catalog.Check, opts runner.Options) []output.CheckResult {
	results := make([]output.CheckResult, 0, len(checks))
	for _, ch := range checks {
		res := runner.Run(ctx, ch, opts, nil, nil)
		cr := output.CheckResult{
			Section:    sectionID,
			Name:       ch.Name,
			Ok:         res.Err == nil && !res.Skipped,
			Skipped:    res.Skipped,
			SkipReason: res.SkipReason,
			ExitCode:   res.ExitCode,
			DurationMS: res.Duration.Milliseconds(),
			Stdout:     res.Stdout,
			Stderr:     res.Stderr,
		}
		if res.Err != nil && !res.Skipped {
			cr.Error = res.Err.Error()
		}
		results = append(results, cr)
	}
	return results
}

func countFailed(results []output.CheckResult) int {
	n := 0
	for _, r := range results {
		if !r.Ok && !r.Skipped {
			n++
		}
	}
	return n
}

// openReport opens the --report file (mode 0600: reports contain sensitive host data).
func openReport() (*os.File, error) {
	f, err := os.OpenFile(reportPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open report file: %w", err)
	}
	if err := f.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		f.Close()
		return nil, fmt.Errorf("restrict report file: %w", err)
	}
	return f, nil
}

// runSection loads the catalog, runs all checks for sectionID, and writes output to cmd.
func runSection(cmd *cobra.Command, sectionID string) error {
	if err := requireDarwin(); err != nil {
		return err
	}
	cat, err := catalog.Load()
	if err != nil {
		return err
	}
	checks := cat.BySection(sectionID)
	if len(checks) == 0 {
		cmd.Printf("No checks for section %q in catalog.\n", sectionID)
		return nil
	}
	opts := runnerOptions(cmd)
	if reportPath != "" && !jsonOutput {
		f, err := openReport()
		if err != nil {
			return err
		}
		defer f.Close()
		opts.OutWriter = io.MultiWriter(opts.OutWriter, f)
		opts.ErrWriter = io.MultiWriter(opts.ErrWriter, f)
	}
	ctx := cmdContext(cmd)

	if jsonOutput {
		results := collectSection(ctx, sectionID, checks, opts)
		if err := output.WriteJSON(cmd.OutOrStdout(), []output.SectionResult{{Section: sectionID, Checks: results}}); err != nil {
			return err
		}
		return failedErr(cmd, countFailed(results))
	}

	failed := 0
	for _, ch := range checks {
		fmt.Fprintf(cmd.OutOrStdout(), "\n--- %s ---\n", ch.Name)
		if ch.Description != "" {
			fmt.Fprintf(opts.OutWriter, "# %s\n", ch.Description)
		}
		if err := runner.RunCheck(ctx, ch, opts); err != nil {
			if errors.Is(err, runner.ErrSkipped) {
				fmt.Fprintf(opts.ErrWriter, "  skipped: requires sudo\n")
				continue
			}
			failed++
			fmt.Fprintf(opts.ErrWriter, "  error: %v\n", err)
		}
	}
	fmt.Fprintln(opts.OutWriter)
	return failedErr(cmd, failed)
}

// failedErr maps a failure count to errChecksFailed, silencing cobra's usage dump.
func failedErr(cmd *cobra.Command, failed int) error {
	if failed == 0 {
		return nil
	}
	cmd.SilenceUsage = true
	return fmt.Errorf("%w (%d)", errChecksFailed, failed)
}

// hasTTY reports whether the process has a controlling terminal (so sudo can prompt for a password).
func hasTTY() bool {
	f, err := os.Open("/dev/tty")
	if err != nil {
		return false
	}
	f.Close()
	return true
}
