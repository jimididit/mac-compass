package cmd

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/jimididit/mac-compass/internal/catalog"
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
	Short: "Run all read-only checks",
	Long:  "Run checks from all sections (triage, processes, kernel, persistence, network, security-tools, advanced, harden). Prompts for confirmation unless -y. Exits 1 if any check fails.",
	RunE:  runRunAll,
}

func runRunAll(cmd *cobra.Command, args []string) error {
	if err := requireDarwin(); err != nil {
		return err
	}
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

	return runSections(cmd, sections)
}
