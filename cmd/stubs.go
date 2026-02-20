package cmd

import (
	"github.com/spf13/cobra"
)

func addStubCommands() {
	sections := []struct {
		name  string
		short string
		long  string
	}{
		{"processes", "Process & memory analysis", "Run process and memory checks from the catalog."},
		{"kernel", "Kernel extensions & rootkit checks", "Run kernel extension and rootkit checks."},
		{"persistence", "File system & persistence analysis", "Run persistence and file system checks."},
		{"network", "Network & system monitoring", "Run network and monitoring checks."},
		{"security-tools", "Security tools & verification", "Run built-in security tool checks."},
		{"advanced", "Advanced detection techniques", "Run advanced detection checks."},
		{"harden", "Preventive / hardening measures", "Run hardening/preventive checks."},
	}
	for _, s := range sections {
		sectionID := s.name
		sub := &cobra.Command{
			Use:   s.name,
			Short: s.short,
			Long:  s.long,
			RunE: func(cmd *cobra.Command, args []string) error {
				return runSection(cmd, sectionID)
			},
		}
		rootCmd.AddCommand(sub)
	}
	rootCmd.AddCommand(checklistCmd)
	rootCmd.AddCommand(refsCmd)
	rootCmd.AddCommand(runAllCmd)
}
