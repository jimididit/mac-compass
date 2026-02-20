package cmd

import (
	"github.com/spf13/cobra"
)

var checklistCmd = &cobra.Command{
	Use:   "checklist",
	Short: "Incident response checklist",
	Long:  "Display the incident response checklist when you suspect a compromise (display only, no commands run).",
	RunE:  runChecklist,
}

func runChecklist(cmd *cobra.Command, args []string) error {
	cmd.Println("When you suspect a compromise:")
	cmd.Println("")
	cmd.Println("  1. Document everything — Take screenshots, save command outputs")
	cmd.Println("  2. Preserve volatile data — Memory, running processes, network connections")
	cmd.Println("  3. Isolate the system — Disconnect from network if necessary")
	cmd.Println("  4. Do NOT shut down — May lose valuable forensic evidence")
	cmd.Println("  5. Create forensic image — Use dd, Carbon Copy Cloner, or commercial solutions")
	cmd.Println("  6. Collect logs — System, application, and security logs")
	cmd.Println("  7. Analyze persistence — Check all auto-start locations")
	cmd.Println("  8. Review network activity — Historical and current connections")
	cmd.Println("  9. Check for lateral movement — Review network logs, other systems")
	cmd.Println(" 10. Contact security team — Follow organizational incident response procedures")
	cmd.Println("")
	return nil
}
