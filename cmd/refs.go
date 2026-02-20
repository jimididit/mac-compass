package cmd

import (
	"github.com/spf13/cobra"
)

var refsCmd = &cobra.Command{
	Use:   "refs",
	Short: "References & resources",
	Long:  "Display references and resources for macOS security and compromise detection.",
	RunE:  runRefs,
}

func runRefs(cmd *cobra.Command, args []string) error {
	cmd.Println("Official Apple Security")
	cmd.Println("  Apple Platform Security Guide: https://support.apple.com/guide/security/welcome/web")
	cmd.Println("  Apple Security Updates: https://support.apple.com/en-us/HT201222")
	cmd.Println("")
	cmd.Println("Guides")
	cmd.Println("  macOS Security and Privacy Guide: https://github.com/drduh/macOS-Security-and-Privacy-Guide")
	cmd.Println("")
	cmd.Println("Tools")
	cmd.Println("  Objective-See: https://objective-see.com/products.html")
	cmd.Println("  osquery: https://osquery.io/")
	cmd.Println("  OSSEC: https://www.ossec.net/")
	cmd.Println("  Santa: https://github.com/google/santa")
	cmd.Println("")
	cmd.Println("Community")
	cmd.Println("  macOS Security Awesome: https://github.com/kai5263499/osx-security-awesome")
	cmd.Println("  Mac4n6: https://www.mac4n6.com/")
	cmd.Println("")
	cmd.Println("Detection")
	cmd.Println("  MITRE ATT&CK macOS: https://attack.mitre.org/matrices/enterprise/macos/")
	cmd.Println("  Sigma (macOS): https://github.com/SigmaHQ/sigma/tree/master/rules/macos")
	cmd.Println("  YARA macOS: https://github.com/Yara-Rules/rules/tree/master/malware")
	cmd.Println("")
	return nil
}
