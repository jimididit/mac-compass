package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/jimididit/mac-compass/internal/catalog"
	"github.com/jimididit/mac-compass/internal/findings"
	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/posture"
	"github.com/jimididit/mac-compass/internal/redact"
	"github.com/jimididit/mac-compass/internal/render"
	"github.com/jimididit/mac-compass/internal/runner"
	"github.com/jimididit/mac-compass/internal/suppress"
	"github.com/spf13/cobra"
)

var (
	// errChecksFailed maps to exit status 1: a check could not run or failed.
	errChecksFailed = errors.New("one or more checks failed")
	// errFindingsThreshold maps to exit status 2: a finding met the --fail-on severity.
	errFindingsThreshold = errors.New("findings at or above the --fail-on severity")
)

// requireDarwin refuses to run checks on non-macOS hosts unless overridden for development.
func requireDarwin() error {
	if runtime.GOOS == "darwin" || os.Getenv("MAC_COMPASS_ALLOW_NON_DARWIN") == "1" {
		return nil
	}
	return fmt.Errorf("mac-compass checks only run on macOS (detected %s); set MAC_COMPASS_ALLOW_NON_DARWIN=1 to override", runtime.GOOS)
}

// runnerOptions builds runner options from the global flags.
func runnerOptions(cmd *cobra.Command, macMajor int) runner.Options {
	return runner.Options{
		Timeout:         timeout,
		UseSudo:         !noSudo,
		SkipSudo:        noSudo,
		VMMode:          vmMode,
		MacOSMajor:      macMajor,
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
	if err := chownToInvoker(reportPath); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// executeSection runs every check in a section. With stream set it prints each check's
// output as it is produced (text mode); results are always captured for findings.
func executeSection(ctx context.Context, sectionID string, checks []catalog.Check, opts runner.Options, stream bool) []output.CheckResult {
	results := make([]output.CheckResult, 0, len(checks))
	for _, ch := range checks {
		var out, errw io.Writer
		if stream {
			fmt.Fprintf(opts.OutWriter, "\n--- %s ---\n", ch.Name)
			if ch.Description != "" {
				fmt.Fprintf(opts.OutWriter, "# %s\n", ch.Description)
			}
			out, errw = opts.OutWriter, opts.ErrWriter
		}
		res := runner.Run(ctx, ch, opts, out, errw)
		if progress {
			fmt.Fprintf(opts.ErrWriter, "[%s] %s %.1fs\n", ch.ID, progressStatus(res), res.Duration.Seconds())
		}
		if stream {
			switch {
			case res.Skipped:
				fmt.Fprintf(opts.ErrWriter, "  skipped: %s\n", res.SkipReason)
			case res.Err != nil:
				fmt.Fprintf(opts.ErrWriter, "  error: %v\n", res.Err)
			}
		}
		cr := output.CheckResult{
			ID:         ch.ID,
			Section:    sectionID,
			Name:       ch.Name,
			Attack:     ch.Attack,
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

func progressStatus(res runner.Result) string {
	switch {
	case res.Skipped:
		return "skipped"
	case res.Err != nil:
		return "failed"
	}
	return "ok"
}

// runSection runs one catalog section (used by the per-section subcommands).
func runSection(cmd *cobra.Command, sectionID string) error {
	return runSections(cmd, []string{sectionID})
}

// runSections runs the given sections, evaluates findings, and writes JSON or text.
func runSections(cmd *cobra.Command, sectionIDs []string) error {
	if err := requireDarwin(); err != nil {
		return err
	}
	threshold, err := parseFailOn(failOn)
	if err != nil {
		return err
	}
	cat, err := catalog.Load()
	if err != nil {
		return err
	}
	sys := runner.DetectMacOS()
	opts := runnerOptions(cmd, sys.Major)
	if reportPath != "" && !jsonOutput {
		f, err := openReport()
		if err != nil {
			return err
		}
		defer f.Close()
		opts.OutWriter = io.MultiWriter(opts.OutWriter, f)
		opts.ErrWriter = io.MultiWriter(opts.ErrWriter, f)
	}
	var red redact.Redactor
	if redactOutput {
		red = redact.ForCurrentUser()
		outW, errW := red.Writer(opts.OutWriter), red.Writer(opts.ErrWriter)
		defer outW.Flush()
		defer errW.Flush()
		opts.OutWriter, opts.ErrWriter = outW, errW
	}
	ctx := cmdContext(cmd)
	started := time.Now()

	var sections []output.SectionResult
	for _, id := range sectionIDs {
		checks := cat.BySection(id)
		if len(checks) == 0 {
			cmd.Printf("No checks for section %q in catalog.\n", id)
			continue
		}
		if len(sectionIDs) > 1 && !jsonOutput && !postureView {
			fmt.Fprintf(opts.OutWriter, "\n========== %s ==========\n", id)
		}
		sections = append(sections, output.SectionResult{Section: id, Checks: executeSection(ctx, id, checks, opts, !jsonOutput && !postureView)})
	}

	rep := buildReport(sections, sys, started)
	if err := applySuppressions(&rep); err != nil {
		return err
	}
	rep.Summarize()
	if p := posture.Assess(rep.Findings, rep.Suppressed); p.Passed+p.Failed+p.Accepted > 0 {
		rep.Posture = &p
	}
	red.Report(&rep)
	if err := writeExtraReports(rep); err != nil {
		return err
	}

	if jsonOutput {
		if err := output.WriteJSON(cmd.OutOrStdout(), rep); err != nil {
			return err
		}
	} else if postureView {
		writePosture(opts.OutWriter, rep)
	} else {
		writeFindings(opts.OutWriter, rep)
	}
	return exitError(cmd, rep, threshold)
}

// writeExtraReports writes the --html and --sarif outputs, if requested. Reports hold host details,
// so the files are private to the user.
func writeExtraReports(rep output.Report) error {
	write := func(path string, render func(output.Report) ([]byte, error)) error {
		if path == "" {
			return nil
		}
		data, err := render(rep)
		if err != nil {
			return err
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o600); err != nil && runtime.GOOS != "windows" {
			return err
		}
		return nil
	}
	if err := write(htmlPath, render.HTML); err != nil {
		return fmt.Errorf("--html: %w", err)
	}
	if err := write(sarifPath, render.SARIF); err != nil {
		return fmt.Errorf("--sarif: %w", err)
	}
	return chownToInvoker(htmlPath, sarifPath)
}

// buildReport assembles the report for a finished run, with findings evaluated.
func buildReport(sections []output.SectionResult, sys runner.MacOSInfo, started time.Time) output.Report {
	host, _ := os.Hostname()
	return output.Report{
		SchemaVersion: output.SchemaVersion,
		Tool:          output.ToolInfo{Name: "mac-compass", Version: version},
		Host:          output.HostInfo{Hostname: host, OS: runtime.GOOS, MacOSVersion: sys.Version, MacOSBuild: sys.Build, Arch: runner.HostArch()},
		StartedAt:     started.UTC(),
		DurationMS:    time.Since(started).Milliseconds(),
		SudoEnabled:   !noSudo,
		VMMode:        vmMode,
		Sections:      sections,
		Findings:      findings.Evaluate(sections),
	}
}

// exitError maps a finished report to the process outcome.
func exitError(cmd *cobra.Command, rep output.Report, threshold output.Severity) error {
	if threshold != "" && rep.Summary.HighestSeverity.Rank() >= threshold.Rank() {
		cmd.SilenceUsage = true
		return fmt.Errorf("%w (%s): highest is %s", errFindingsThreshold, threshold, rep.Summary.HighestSeverity)
	}
	if rep.Summary.ChecksFailed > 0 {
		cmd.SilenceUsage = true
		return fmt.Errorf("%w (%d)", errChecksFailed, rep.Summary.ChecksFailed)
	}
	return nil
}

// parseFailOn validates --fail-on; empty means never fail on findings.
func parseFailOn(s string) (output.Severity, error) {
	if s == "" {
		return "", nil
	}
	sev := output.Severity(strings.ToLower(s))
	if sev.Rank() == 0 {
		return "", fmt.Errorf("--fail-on must be one of info, low, medium, high, critical (got %q)", s)
	}
	return sev, nil
}

// applySuppressions moves findings accepted in the --suppress file out of the active results.
func applySuppressions(rep *output.Report) error {
	if suppressFile == "" {
		return nil
	}
	rules, err := suppress.Load(suppressFile)
	if err != nil {
		return fmt.Errorf("--suppress %s: %w", suppressFile, err)
	}
	res := suppress.Apply(rules, rep.Findings, time.Now())
	rep.Findings = append(res.Kept, res.Notices...)
	rep.Suppressed = res.Suppressed
	return nil
}

// writeFindings prints the human-readable findings summary.
func writeFindings(w io.Writer, rep output.Report) {
	fmt.Fprint(w, "\n========== Findings ==========\n")
	shown := 0
	for _, f := range rep.Findings {
		if f.Status == output.StatusPass {
			continue
		}
		shown++
		tag := string(f.Status)
		if f.Status == output.StatusFail {
			tag = string(f.Severity)
		}
		fmt.Fprintf(w, "[%s] %s\n", strings.ToUpper(tag), f.Title)
		if f.Detail != "" {
			fmt.Fprintf(w, "    %s\n", strings.ReplaceAll(f.Detail, "\n", "\n    "))
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "    fix: %s\n", f.Remediation)
		}
	}
	if shown == 0 {
		fmt.Fprintln(w, "No findings.")
	}
	if n := len(rep.Suppressed); n > 0 {
		fmt.Fprintf(w, "\n%d finding(s) accepted by your suppressions file:\n", n)
		for _, s := range rep.Suppressed {
			fmt.Fprintf(w, "    %s: %s (%s)\n", s.ID, s.Title, s.Reason)
		}
	}
	s := rep.Summary
	var sev []string
	for _, v := range []output.Severity{output.SeverityCritical, output.SeverityHigh, output.SeverityMedium, output.SeverityLow, output.SeverityInfo} {
		if n := s.FailBySeverity[v]; n > 0 {
			sev = append(sev, fmt.Sprintf("%d %s", n, v))
		}
	}
	failed := fmt.Sprintf("%d failed", s.Fail)
	if len(sev) > 0 {
		failed += " (" + strings.Join(sev, ", ") + ")"
	}
	fmt.Fprintf(w, "\n%s, %d passed, %d info, %d errors; checks: %d ok, %d skipped, %d failed\n",
		failed, s.Pass, s.Info, s.Error, s.ChecksOK, s.ChecksSkipped, s.ChecksFailed)
	if p := rep.Posture; p != nil && p.Passed+p.Failed > 0 {
		fmt.Fprintf(w, "Hardening posture: %d/100 (run 'mac-compass posture' for the control list)\n", p.Score)
	}
}

// postureMarks are the status tags in the posture list.
var postureMarks = map[string]string{
	posture.StatusPass: "PASS", posture.StatusFail: "FAIL", posture.StatusAccepted: "ACCEPTED", posture.StatusNotAssessed: "N/A",
}

// writePosture prints the hardening controls and the score.
func writePosture(w io.Writer, rep output.Report) {
	p := rep.Posture
	if p == nil || p.Passed+p.Failed == 0 {
		fmt.Fprintln(w, "No hardening control could be assessed, so there is no score. Run again without --no-sudo.")
		return
	}
	fmt.Fprint(w, "\n========== Hardening posture ==========\n")
	for _, c := range p.Controls {
		fmt.Fprintf(w, "[%s] %s\n", postureMarks[c.Status], c.Title)
		if c.Status == posture.StatusFail && c.Remediation != "" {
			fmt.Fprintf(w, "    fix: %s\n", c.Remediation)
		}
	}
	fmt.Fprintf(w, "\nScore: %d/100 (%d pass, %d fail, %d accepted, %d not assessed)\n", p.Score, p.Passed, p.Failed, p.Accepted, p.NotAssessed)
	fmt.Fprintln(w, "Controls follow the macOS Security Compliance Project (mSCP), the source of the CIS and NIST macOS benchmarks.")
	fmt.Fprintln(w, "The score covers the subset that mac-compass can read. It is a guide, not a compliance result.")
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
