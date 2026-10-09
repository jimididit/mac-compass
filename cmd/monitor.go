package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jimididit/mac-compass/internal/baseline"
	"github.com/jimididit/mac-compass/internal/monitor"
	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/runner"
	"github.com/jimididit/mac-compass/internal/suppress"
	"github.com/spf13/cobra"
)

var (
	monStateDir  string
	monScope     string
	monEvery     time.Duration
	monNotifyOn  string
	monRebase    bool
	monNoNotify  bool
	monLaunchDir string
	monNoLoad    bool
	monPurge     bool
)

func init() {
	monitorCmd.PersistentFlags().StringVar(&monStateDir, "state-dir", "", "Folder for the monitor's baseline, state and logs (default depends on scope)")
	monitorCmd.PersistentFlags().StringVar(&monScope, "scope", "user", "user: a LaunchAgent for you (notifications, unprivileged checks); system: a root LaunchDaemon (full checks, log only)")
	monitorCmd.PersistentFlags().StringVar(&monLaunchDir, "launch-dir", "", "Folder for the launchd plist (default depends on scope)")
	_ = monitorCmd.PersistentFlags().MarkHidden("launch-dir")

	monitorRunCmd.Flags().StringVar(&monNotifyOn, "notify-on", "medium", "Alert on new findings at or above this severity (low|medium|high|critical)")
	monitorRunCmd.Flags().BoolVar(&monRebase, "rebaseline", false, "Discard the monitor's baseline and take a new one now")
	monitorRunCmd.Flags().BoolVar(&monNoNotify, "no-notify", false, "Do not show desktop notifications (alerts are still logged)")

	monitorInstallCmd.Flags().DurationVar(&monEvery, "every", time.Hour, "How often to run (minimum 5m)")
	monitorInstallCmd.Flags().StringVar(&monNotifyOn, "notify-on", "medium", "Alert on new findings at or above this severity")
	monitorInstallCmd.Flags().BoolVar(&monNoLoad, "no-load", false, "Write the plist but do not load it into launchd")
	monitorUninstallCmd.Flags().BoolVar(&monPurge, "purge", false, "Also delete the monitor's baseline, history and logs")

	monitorCmd.AddCommand(monitorRunCmd, monitorInstallCmd, monitorUninstallCmd, monitorStatusCmd)
	rootCmd.AddCommand(monitorCmd)
}

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Watch for changes on a schedule and alert when something new and serious appears",
	Long: "Runs mac-compass periodically through launchd. The first run records a baseline of this Mac; every later " +
		"run compares against it and alerts only when the set of serious new findings changes, so the same problem " +
		"is not announced every hour.\n\n" +
		"  install   schedule it (a LaunchAgent for you by default; --scope system for a root LaunchDaemon)\n" +
		"  status    show whether it is installed and what it last saw\n" +
		"  run       one cycle, which launchd calls; you can also run it by hand\n" +
		"  uninstall remove it\n\n" +
		"User scope shows desktop notifications but can only run unprivileged checks. System scope runs everything " +
		"as root but cannot show notifications; alerts go to the log and the state folder.",
}

// defaultStateDir picks the state folder for the scope (or for root, when run as root).
func defaultStateDir(scope monitor.Scope) string {
	if scope == monitor.ScopeSystem {
		return "/Library/Application Support/mac-compass"
	}
	home, _ := runner.InvokingUserHome()
	return filepath.Join(home, "Library", "Application Support", "mac-compass")
}

func monitorScopeValue() (monitor.Scope, error) {
	switch monitor.Scope(monScope) {
	case monitor.ScopeUser, monitor.ScopeSystem:
		return monitor.Scope(monScope), nil
	}
	return "", fmt.Errorf("--scope must be user or system (got %q)", monScope)
}

var monitorRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run one monitoring cycle",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireDarwin(); err != nil {
			return err
		}
		threshold, err := parseFailOn(monNotifyOn)
		if err != nil {
			return fmt.Errorf("--notify-on: %w", err)
		}
		dir := monStateDir
		if dir == "" {
			scope := monitor.ScopeUser
			if os.Geteuid() == 0 {
				scope = monitor.ScopeSystem
			}
			dir = defaultStateDir(scope)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		monitor.TrimLog(filepath.Join(dir, "monitor.log"))

		o := monitor.Options{
			StateDir:  dir,
			Threshold: threshold,
			Rebase:    monRebase,
			Snapshot:  func(context.Context) (baseline.Snapshot, error) { return takeSnapshot(cmd) },
		}
		// Desktop notifications only work from a user session; a root daemon logs instead.
		if os.Geteuid() != 0 && !monNoNotify {
			o.Notify = monitor.OSANotifier
		}
		if suppressFile != "" {
			rules, err := suppress.Load(suppressFile)
			if err != nil {
				return fmt.Errorf("--suppress %s: %w", suppressFile, err)
			}
			o.Filter = func(fs []output.Finding) []output.Finding {
				return suppress.Apply(rules, fs, time.Now()).Kept
			}
		}

		res, err := monitor.Run(cmdContext(cmd), o)
		w := cmd.OutOrStdout()
		st := res.State
		fmt.Fprintf(w, "%s mac-compass monitor: %s (run %d)\n", st.LastRun.Format(time.RFC3339), st.LastResult, st.Runs)
		if err != nil {
			cmd.SilenceUsage = true
			return err
		}
		if st.LastResult == "baselined" {
			fmt.Fprintln(w, "  baseline recorded; later runs report what changed")
		}
		if st.LastResult == "alert-active" {
			fmt.Fprintln(w, "  findings from an earlier alert are still present; no new alert")
		}
		if res.Alerted {
			fmt.Fprintf(w, "  ALERT: %s\n  %s\n", res.Title, res.Body)
			for _, f := range res.Findings {
				if f.Status == output.StatusFail {
					fmt.Fprintf(w, "  - [%s] %s\n", f.Severity, f.Title)
				}
			}
		}
		if st.LastError != "" {
			fmt.Fprintf(w, "  note: %s\n", st.LastError)
		}
		return nil
	},
}

// launchctl runs /bin/launchctl and returns its combined output.
func launchctl(args ...string) (string, error) {
	cmd := exec.Command("/bin/launchctl", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// domain is the launchd domain a job of the scope lives in.
func domain(scope monitor.Scope) string {
	if scope == monitor.ScopeSystem {
		return "system"
	}
	return fmt.Sprintf("gui/%d", os.Getuid())
}

var monitorInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Schedule the monitor with launchd",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireDarwin(); err != nil {
			return err
		}
		scope, err := monitorScopeValue()
		if err != nil {
			return err
		}
		if _, err := parseFailOn(monNotifyOn); err != nil {
			return fmt.Errorf("--notify-on: %w", err)
		}
		if scope == monitor.ScopeSystem && os.Geteuid() != 0 {
			return fmt.Errorf("--scope system installs a root daemon; run it with sudo")
		}
		if scope == monitor.ScopeUser && os.Geteuid() == 0 {
			return fmt.Errorf("--scope user installs a LaunchAgent for your own account; run it without sudo")
		}
		bin, err := os.Executable()
		if err != nil {
			return err
		}
		if bin, err = filepath.EvalSymlinks(bin); err != nil {
			return err
		}
		if scope == monitor.ScopeSystem {
			if err := monitor.CheckRootTrusted(bin, monitor.OSStat); err != nil {
				return fmt.Errorf("refusing to install a root daemon: %w", err)
			}
		}

		stateDir := monStateDir
		if stateDir == "" {
			stateDir = defaultStateDir(scope)
		}
		if stateDir, err = filepath.Abs(stateDir); err != nil {
			return err
		}
		extra := []string{"--notify-on", monNotifyOn}
		if scope == monitor.ScopeUser {
			extra = append(extra, "--no-sudo")
		}
		if vmMode {
			extra = append(extra, "--vm")
		}
		if suppressFile != "" {
			abs, err := filepath.Abs(suppressFile)
			if err != nil {
				return err
			}
			if _, err := suppress.Load(abs); err != nil {
				return fmt.Errorf("--suppress %s: %w", suppressFile, err)
			}
			extra = append(extra, "--suppress", abs)
		}
		spec := monitor.JobSpec{Binary: bin, StateDir: stateDir, Interval: monEvery, Args: extra}
		plist, err := monitor.Plist(spec)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return err
		}
		home, _ := runner.InvokingUserHome()
		launchDir := monLaunchDir
		if launchDir == "" {
			launchDir = monitor.LaunchDir(scope, home)
		}
		if err := os.MkdirAll(launchDir, 0o755); err != nil {
			return err
		}
		plistPath := monitor.PlistPath(launchDir)
		if err := os.WriteFile(plistPath, plist, 0o644); err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "Wrote %s\nState and logs: %s\n", plistPath, stateDir)

		if monNoLoad {
			fmt.Fprintf(w, "Not loaded (--no-load). To load it: launchctl bootstrap %s %s\n", domain(scope), monitor.Quote([]string{plistPath}))
			return nil
		}
		_, _ = launchctl("bootout", domain(scope)+"/"+monitor.Label) // replace an earlier install; failure just means it was not loaded
		if out, err := launchctl("bootstrap", domain(scope), plistPath); err != nil {
			return fmt.Errorf("launchctl bootstrap failed: %v: %s\nThe plist is written; load it from a logged-in desktop session with:\n  launchctl bootstrap %s %s", err, out, domain(scope), monitor.Quote([]string{plistPath}))
		}
		fmt.Fprintf(w, "Loaded. It runs now (recording a baseline) and then every %v.\n", monEvery)
		if scope == monitor.ScopeSystem {
			fmt.Fprintln(w, "System scope cannot show notifications; check 'mac-compass monitor status --scope system' and the log.")
		}
		return nil
	},
}

var monitorUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the scheduled monitor",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		scope, err := monitorScopeValue()
		if err != nil {
			return err
		}
		if scope == monitor.ScopeSystem && os.Geteuid() != 0 {
			return fmt.Errorf("--scope system needs sudo")
		}
		home, _ := runner.InvokingUserHome()
		launchDir := monLaunchDir
		if launchDir == "" {
			launchDir = monitor.LaunchDir(scope, home)
		}
		plistPath := monitor.PlistPath(launchDir)
		w := cmd.OutOrStdout()
		if _, err := os.Stat(plistPath); err != nil {
			fmt.Fprintf(w, "Not installed (%s does not exist).\n", plistPath)
		} else {
			_, _ = launchctl("bootout", domain(scope)+"/"+monitor.Label)
			if err := os.Remove(plistPath); err != nil {
				return err
			}
			fmt.Fprintf(w, "Removed %s\n", plistPath)
		}
		if monPurge {
			dir := monStateDir
			if dir == "" {
				dir = defaultStateDir(scope)
			}
			if err := os.RemoveAll(dir); err != nil {
				return err
			}
			fmt.Fprintf(w, "Deleted %s\n", dir)
		}
		return nil
	},
}

var monitorStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether the monitor is installed and what it last saw",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		scope, err := monitorScopeValue()
		if err != nil {
			return err
		}
		home, _ := runner.InvokingUserHome()
		launchDir := monLaunchDir
		if launchDir == "" {
			launchDir = monitor.LaunchDir(scope, home)
		}
		plistPath := monitor.PlistPath(launchDir)
		dir := monStateDir
		if dir == "" {
			dir = defaultStateDir(scope)
		}
		w := cmd.OutOrStdout()
		_, installed := os.Stat(plistPath)
		loaded := false
		if installed == nil {
			_, lerr := launchctl("print", domain(scope)+"/"+monitor.Label)
			loaded = lerr == nil
		}
		fmt.Fprintf(w, "scope:      %s\nplist:      %s (%s)\nloaded:     %v\nstate dir:  %s\n", scope, plistPath, yesNo(installed == nil, "present", "missing"), loaded, dir)

		st, err := monitor.LoadState(dir)
		if err != nil {
			return err
		}
		if st.Runs == 0 {
			fmt.Fprintln(w, "last run:   never")
			return nil
		}
		fmt.Fprintf(w, "last run:   %s (%s ago), result %s, %d run(s) so far\n", st.LastRun.Format(time.RFC3339), time.Since(st.LastRun).Round(time.Minute), st.LastResult, st.Runs)
		fmt.Fprintf(w, "baseline:   taken %s\n", st.BaselineTaken.Format(time.RFC3339))
		if !st.LastAlert.IsZero() {
			fmt.Fprintf(w, "last alert: %s\n", st.LastAlert.Format(time.RFC3339))
			if scope == monitor.ScopeUser {
				fmt.Fprintln(w, "            (no banner? macOS attributes these to Script Editor: allow it in System Settings > Notifications, and check Focus is off)")
			}
		}
		if st.LastError != "" {
			fmt.Fprintf(w, "last error: %s\n", st.LastError)
		}
		if rep, ok := monitor.LoadLatest(dir); ok && rep.Summary.Fail > 0 {
			fmt.Fprintf(w, "\nOpen findings since the baseline (%d):\n", rep.Summary.Fail)
			for _, f := range rep.Findings {
				if f.Status == output.StatusFail {
					fmt.Fprintf(w, "  [%s] %s\n", f.Severity, f.Title)
				}
			}
		}
		return nil
	},
}

func yesNo(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}
