package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	noSudo     bool
	vmMode     bool
	timeout    time.Duration
	jsonOutput bool
	reportPath string
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
	rootCmd.CompletionOptions.DisableDefaultCmd = false
	addStubCommands()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
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
	fmt.Fprintln(cmd.OutOrStdout(), " 11. run-all      - Run all safe checks")
	fmt.Fprintln(cmd.OutOrStdout(), "")
	fmt.Fprint(cmd.OutOrStdout(), "Enter number or subcommand (or press Enter for help): ")
	scanner := bufio.NewScanner(cmd.InOrStdin())
	if !scanner.Scan() {
		return nil
	}
	choice := strings.TrimSpace(scanner.Text())
	if choice == "" {
		return cmd.Help()
	}
	// Delegate to subcommand by name or number (call RunE directly so Cobra doesn't re-parse os.Args and show the menu again)
	subName := choiceToSubcommand(choice)
	if subName != "" {
		sub, _, _ := rootCmd.Find([]string{subName})
		if sub != nil && sub != rootCmd {
			sub.SetArgs(args)
			if sub.RunE != nil {
				return sub.RunE(sub, args)
			}
			if sub.Run != nil {
				sub.Run(sub, args)
				return nil
			}
		}
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Unknown choice: %q. Use 'mac-compass --help' for subcommands.\n", choice)
	return nil
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
	default:
		return ""
	}
}
