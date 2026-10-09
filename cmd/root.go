package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var (
	noSudo       bool
	vmMode       bool
	timeout      time.Duration
	jsonOutput   bool
	reportPath   string
	failOn       string
	redactOutput bool
	suppressFile string
	htmlPath     string
	sarifPath    string
	progress     bool
)

var rootCmd = &cobra.Command{
	Use:   "mac-compass",
	Short: "macOS compromise detection CLI",
	Long:  "Interactive CLI for running macOS security and compromise detection checks. Guides you through triage, process analysis, kernel checks, persistence, network, and more.",
}

func init() {
	rootCmd.RunE = runInteractive
	rootCmd.PersistentFlags().BoolVar(&noSudo, "no-sudo", false, "Skip checks that require sudo")
	rootCmd.PersistentFlags().BoolVar(&vmMode, "vm", false, "VM mode: skip checks that require hardware (e.g. T2)")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 90*time.Second, "Per-check timeout")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	rootCmd.PersistentFlags().StringVar(&reportPath, "report", "", "Also write human-readable output to file")
	rootCmd.PersistentFlags().StringVar(&failOn, "fail-on", "", "Exit 2 if any finding is at or above this severity (info|low|medium|high|critical)")
	rootCmd.PersistentFlags().BoolVar(&redactOutput, "redact", false, "Mask the host name and your user name in output, reports and snapshots")
	rootCmd.PersistentFlags().StringVar(&suppressFile, "suppress", "", "YAML file of reviewed findings to accept (id, optional match, reason, optional expires)")
	rootCmd.PersistentFlags().StringVar(&htmlPath, "html", "", "Also write a self-contained HTML report to this file (mode 0600)")
	rootCmd.PersistentFlags().StringVar(&sarifPath, "sarif", "", "Also write a SARIF 2.1.0 report to this file (mode 0600)")
	rootCmd.PersistentFlags().BoolVar(&progress, "progress", false, "Print one line per check to stderr as it finishes (useful on slow machines and in CI logs)")
	rootCmd.CompletionOptions.DisableDefaultCmd = false
	rootCmd.SilenceErrors = true // Execute prints the error once
	// Arguments and flags are validated before this runs, so usage is still shown for those mistakes but
	// not for runtime failures such as an unreadable file.
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) { cmd.SilenceUsage = true }
	addStubCommands()
}

func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := rootCmd.ExecuteContext(ctx)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, errFindingsThreshold) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func runInteractive(cmd *cobra.Command, args []string) error {
	fmt.Fprintln(cmd.OutOrStdout(), "mac-compass - macOS compromise detection")
	fmt.Fprintln(cmd.OutOrStdout(), "")
	fmt.Fprintln(cmd.OutOrStdout(), "Sections:")
	fmt.Fprintln(cmd.OutOrStdout(), "  1. triage       - Quick triage (run first)")
	fmt.Fprintln(cmd.OutOrStdout(), "  2. processes    - Process & memory analysis")
	fmt.Fprintln(cmd.OutOrStdout(), "  3. kernel       - Kernel extensions & rootkit checks")
	fmt.Fprintln(cmd.OutOrStdout(), "  4. persistence  - File system & persistence")
	fmt.Fprintln(cmd.OutOrStdout(), "  5. network      - Network & monitoring")
	fmt.Fprintln(cmd.OutOrStdout(), "  6. security-tools - Security tools & verification")
	fmt.Fprintln(cmd.OutOrStdout(), "  7. advanced     - Advanced detection")
	fmt.Fprintln(cmd.OutOrStdout(), "  8. checklist    - Incident response checklist")
	fmt.Fprintln(cmd.OutOrStdout(), "  9. harden       - Preventive measures")
	fmt.Fprintln(cmd.OutOrStdout(), " 10. refs         - References & resources")
	fmt.Fprintln(cmd.OutOrStdout(), " 11. run-all      - Run all read-only checks")
	fmt.Fprintln(cmd.OutOrStdout(), " 12. accounts     - Accounts and access")
	fmt.Fprintln(cmd.OutOrStdout(), " 13. snapshot     - Record a baseline (see also: compare)")
	fmt.Fprintln(cmd.OutOrStdout(), "  q. quit")
	scanner := bufio.NewScanner(cmd.InOrStdin())
	for {
		fmt.Fprint(cmd.OutOrStdout(), "\nEnter number or name (q to quit, Enter for help): ")
		if !scanner.Scan() {
			fmt.Fprintln(cmd.OutOrStdout())
			return nil
		}
		choice := strings.ToLower(strings.TrimSpace(scanner.Text()))
		switch choice {
		case "":
			return cmd.Help()
		case "q", "quit", "exit":
			return nil
		}
		subName := choiceToSubcommand(choice)
		sub, _, _ := rootCmd.Find([]string{subName})
		if subName == "" || sub == nil || sub == rootCmd || sub.RunE == nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Unknown choice: %q. Use 'mac-compass --help' for subcommands.\n", choice)
			continue
		}
		// Call RunE directly so Cobra does not re-parse os.Args and show the menu again.
		// A failing section must not end the session, so report the error and show the menu again.
		if err := sub.RunE(sub, nil); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), err)
		}
	}
}

func choiceToSubcommand(choice string) string {
	switch choice {
	case "1", "triage":
		return "triage"
	case "2", "processes":
		return "processes"
	case "3", "kernel":
		return "kernel"
	case "4", "persistence":
		return "persistence"
	case "5", "network":
		return "network"
	case "6", "security-tools":
		return "security-tools"
	case "7", "advanced":
		return "advanced"
	case "8", "checklist":
		return "checklist"
	case "9", "harden":
		return "harden"
	case "10", "refs":
		return "refs"
	case "11", "run-all":
		return "run-all"
	case "12", "accounts":
		return "accounts"
	case "13", "snapshot":
		return "snapshot"
	default:
		return ""
	}
}
