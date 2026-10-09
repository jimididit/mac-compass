package cmd

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/jimididit/mac-compass/internal/baseline"
	"github.com/jimididit/mac-compass/internal/catalog"
	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/redact"
	"github.com/jimididit/mac-compass/internal/runner"
	"github.com/spf13/cobra"
)

var snapshotOut string

func init() {
	snapshotCmd.Flags().StringVarP(&snapshotOut, "out", "o", "", "Write the snapshot to this file (mode 0600) instead of stdout")
	rootCmd.AddCommand(snapshotCmd, compareCmd)
}

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Record a baseline of persistence items, listeners, extensions and settings",
	Long: "Runs the inventory checks and writes a normalized JSON snapshot. Take one on a known-good " +
		"machine, then use 'mac-compass compare' later to see exactly what was added, removed or changed. " +
		"Use the same sudo setting for both snapshots: privileged checks are not comparable with unprivileged ones.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		snap, err := takeSnapshot(cmd)
		if err != nil {
			return err
		}
		if redactOutput {
			redact.ForCurrentUser().Snapshot(&snap)
		}
		w := cmd.OutOrStdout()
		if snapshotOut != "" {
			f, err := os.OpenFile(snapshotOut, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return fmt.Errorf("open snapshot file: %w", err)
			}
			defer f.Close()
			if err := f.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
				return fmt.Errorf("restrict snapshot file: %w", err)
			}
			w = f
		}
		if err := snap.Write(w); err != nil {
			return err
		}
		if snapshotOut != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "Snapshot of %d checks written to %s\n", len(snap.Checks), snapshotOut)
		}
		return nil
	},
}

var compareCmd = &cobra.Command{
	Use:   "compare BASELINE.json [CURRENT.json]",
	Short: "Compare the system (or a second snapshot) against a baseline",
	Long: "Shows what changed since the baseline: new persistence items, listeners, extensions and " +
		"changed settings are findings; removals are informational. With one argument a fresh snapshot " +
		"of this Mac is taken. Use --fail-on to exit 2 on findings, and --json for a machine-readable report.",
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		threshold, err := parseFailOn(failOn)
		if err != nil {
			return err
		}
		old, err := readSnapshot(args[0])
		if err != nil {
			return err
		}
		var cur baseline.Snapshot
		if len(args) == 2 {
			cur, err = readSnapshot(args[1])
		} else {
			cur, err = takeSnapshot(cmd)
		}
		if err != nil {
			return err
		}
		res := baseline.Compare(old, cur)
		var red redact.Redactor
		if redactOutput {
			red = redact.ForCurrentUser()
		}
		rep := output.Report{
			SchemaVersion: output.SchemaVersion,
			Tool:          output.ToolInfo{Name: "mac-compass", Version: version},
			Host:          cur.Host,
			StartedAt:     time.Now().UTC(),
			SudoEnabled:   cur.SudoEnabled,
			Findings:      res.Findings,
		}
		if err := applySuppressions(&rep); err != nil {
			return err
		}
		rep.Summarize()
		red.Report(&rep)
		if err := writeExtraReports(rep); err != nil {
			return err
		}
		if jsonOutput {
			if err := output.WriteJSON(cmd.OutOrStdout(), rep); err != nil {
				return err
			}
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Baseline: %s (macOS %s, %s)\nCurrent:  %s (macOS %s, %s)\n",
				old.TakenAt.Format(time.RFC3339), old.Host.MacOSVersion, old.Host.Arch,
				cur.TakenAt.Format(time.RFC3339), cur.Host.MacOSVersion, cur.Host.Arch)
			fmt.Fprintf(cmd.OutOrStdout(), "Compared %d checks", res.Compared)
			if n := len(res.NotComparable); n > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "; %d not comparable (missing from one side, e.g. different sudo use)", n)
			}
			fmt.Fprintln(cmd.OutOrStdout())
			writeFindings(cmd.OutOrStdout(), rep)
		}
		return exitError(cmd, rep, threshold)
	},
}

func readSnapshot(path string) (baseline.Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return baseline.Snapshot{}, err
	}
	defer f.Close()
	s, err := baseline.Read(f)
	if err != nil {
		return s, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// takeSnapshot runs only the checks that feed the baseline and normalizes their output.
func takeSnapshot(cmd *cobra.Command) (baseline.Snapshot, error) {
	if err := requireDarwin(); err != nil {
		return baseline.Snapshot{}, err
	}
	cat, err := catalog.Load()
	if err != nil {
		return baseline.Snapshot{}, err
	}
	sys := runner.DetectMacOS()
	opts := runnerOptions(cmd, sys.Major)
	ctx := cmdContext(cmd)
	started := time.Now()

	var sections []output.SectionResult
	for _, id := range cat.Sections() {
		var checks []catalog.Check
		for _, ch := range cat.BySection(id) {
			if baseline.HasExtractor(ch.ID) {
				checks = append(checks, ch)
			}
		}
		if len(checks) > 0 {
			sections = append(sections, output.SectionResult{Section: id, Checks: executeSection(ctx, id, checks, opts, false)})
		}
	}
	host, _ := os.Hostname()
	return baseline.FromSections(
		output.ToolInfo{Name: "mac-compass", Version: version},
		output.HostInfo{Hostname: host, OS: runtime.GOOS, MacOSVersion: sys.Version, MacOSBuild: sys.Build, Arch: runner.HostArch()},
		!noSudo, started, sections), nil
}
