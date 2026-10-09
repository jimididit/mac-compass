package cmd

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/jimididit/mac-compass/internal/baseline"
	"github.com/jimididit/mac-compass/internal/catalog"
	"github.com/jimididit/mac-compass/internal/evidence"
	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/redact"
	"github.com/jimididit/mac-compass/internal/render"
	"github.com/jimididit/mac-compass/internal/runner"
	"github.com/spf13/cobra"
)

var (
	collectOut   string
	verifyExpect string
)

func init() {
	collectCmd.Flags().StringVarP(&collectOut, "out", "o", "", "Folder to create for the bundle (default: ./mac-compass-evidence-<UTC timestamp>)")
	verifyCmd.Flags().StringVar(&verifyExpect, "expect", "", "The bundle SHA-256 you recorded when it was collected; the bundle must match it")
	rootCmd.AddCommand(collectCmd, verifyCmd)
}

var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Run every check and save the results as a hashed evidence bundle",
	Long: "Runs every section and writes a folder holding report.json, snapshot.json, findings.txt and the raw " +
		"output of each check, with a SHA-256 manifest. The folder is private to you (mode 0700). " +
		"Record the printed bundle hash somewhere other than this Mac: that is what lets you prove later, with " +
		"'mac-compass verify --expect', that nothing in the bundle changed. Write to an external drive with --out " +
		"if you can. Use --redact to mask the host and user name inside the bundle.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireDarwin(); err != nil {
			return err
		}
		cat, err := catalog.Load()
		if err != nil {
			return err
		}
		sys := runner.DetectMacOS()
		opts := runnerOptions(cmd, sys.Major)
		ctx := cmdContext(cmd)
		started := time.Now()

		var sections []output.SectionResult
		for _, id := range cat.Sections() {
			sections = append(sections, output.SectionResult{Section: id, Checks: executeSection(ctx, id, cat.BySection(id), opts, false)})
		}
		rep := buildReport(sections, sys, started)
		if err := applySuppressions(&rep); err != nil {
			return err
		}
		rep.Summarize()
		snap := baseline.FromSections(rep.Tool, rep.Host, !noSudo, started, sections)

		var findingsText bytes.Buffer
		writeFindings(&findingsText, rep)

		in := evidence.Input{Report: rep, Snapshot: snap, FindingsText: findingsText.String()}
		if redactOutput {
			red := redact.ForCurrentUser()
			red.Report(&in.Report)
			red.Snapshot(&in.Snapshot)
			in.Redact = red.String
		}
		if page, err := render.HTML(in.Report); err == nil {
			in.HTML = page
		}
		dir := collectOut
		if dir == "" {
			dir = "mac-compass-evidence-" + started.UTC().Format("20060102T150405Z")
		}
		m, hash, err := evidence.Write(dir, in)
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "Evidence bundle written to %s (%d files, mode 0700)\n\n", dir, len(m.Files))
		fmt.Fprintf(w, "  bundle SHA-256: %s\n\n", hash)
		fmt.Fprintln(w, "Record that hash somewhere other than this Mac (a note, a ticket, an email to yourself).")
		fmt.Fprintf(w, "Later: mac-compass verify %s --expect %s\n", dir, hash)
		fmt.Fprintf(w, "\n%d finding(s) failed; highest severity: %s\n", rep.Summary.Fail, orNone(string(rep.Summary.HighestSeverity)))
		return exitError(cmd, rep, "")
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify BUNDLE_FOLDER",
	Short: "Check that an evidence bundle is exactly what was collected",
	Long: "Re-hashes every file listed in the bundle's manifest and looks for missing, changed and extra files. " +
		"Pass --expect with the bundle hash you recorded at collection time to also prove the manifest itself is unchanged. " +
		"Exits 1 if anything does not match.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := evidence.Verify(args[0])
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		m := res.Manifest
		fmt.Fprintf(w, "Bundle from %s (%s, macOS %s), collected %s\n", m.Host.Hostname, m.Host.Arch, m.Host.MacOSVersion, m.CreatedAt.Format(time.RFC3339))
		fmt.Fprintf(w, "%d files listed; bundle SHA-256: %s\n", len(m.Files), res.BundleHash)

		problems := 0
		report := func(label string, items []string) {
			for _, p := range items {
				problems++
				fmt.Fprintf(w, "  %s: %s\n", label, p)
			}
		}
		report("CHANGED", res.Mismatched)
		report("MISSING", res.Missing)
		report("UNLISTED", res.Extra)
		if res.BadHash {
			problems++
			fmt.Fprintln(w, "  MANIFEST.sha256 does not match MANIFEST.json")
		}
		if want := strings.ToLower(strings.TrimSpace(verifyExpect)); want != "" {
			if want != res.BundleHash {
				problems++
				fmt.Fprintf(w, "  The bundle hash does not match the one you recorded:\n    expected %s\n    found    %s\n", want, res.BundleHash)
			} else {
				fmt.Fprintln(w, "Bundle hash matches the value you recorded.")
			}
		} else {
			fmt.Fprintln(w, "No --expect hash given: this proves the files match the manifest, not that the manifest is the original.")
		}
		if problems > 0 {
			cmd.SilenceUsage = true
			return fmt.Errorf("verification failed: %d problem(s)", problems)
		}
		fmt.Fprintln(w, "OK: every file matches the manifest.")
		return nil
	},
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
