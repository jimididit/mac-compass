package cmd

import (
	"bytes"
	"errors"
	"github.com/jimididit/mac-compass/internal/baseline"
	"github.com/jimididit/mac-compass/internal/evidence"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jimididit/mac-compass/internal/output"
	"github.com/spf13/cobra"
)

func TestParseFailOn(t *testing.T) {
	for in, want := range map[string]output.Severity{"": "", "high": output.SeverityHigh, "LOW": output.SeverityLow, "critical": output.SeverityCritical} {
		got, err := parseFailOn(in)
		if err != nil || got != want {
			t.Errorf("parseFailOn(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := parseFailOn("severe"); err == nil {
		t.Error("unknown severity should be rejected")
	}
}

func reportWith(highest output.Severity, checksFailed int) output.Report {
	return output.Report{Summary: output.Summary{HighestSeverity: highest, ChecksFailed: checksFailed}}
}

func TestExitError(t *testing.T) {
	cmd := &cobra.Command{}
	cases := []struct {
		name      string
		rep       output.Report
		threshold output.Severity
		want      error
	}{
		{"clean", reportWith("", 0), "", nil},
		{"findings but no threshold", reportWith(output.SeverityHigh, 0), "", nil},
		{"below threshold", reportWith(output.SeverityLow, 0), output.SeverityHigh, nil},
		{"at threshold", reportWith(output.SeverityHigh, 0), output.SeverityHigh, errFindingsThreshold},
		{"above threshold", reportWith(output.SeverityCritical, 0), output.SeverityMedium, errFindingsThreshold},
		{"failed checks", reportWith("", 2), "", errChecksFailed},
		{"threshold wins over failed checks", reportWith(output.SeverityHigh, 2), output.SeverityHigh, errFindingsThreshold},
	}
	for _, c := range cases {
		err := exitError(cmd, c.rep, c.threshold)
		if !errors.Is(err, c.want) && !(err == nil && c.want == nil) {
			t.Errorf("%s: got %v; want %v", c.name, err, c.want)
		}
	}
}

func TestWriteFindings(t *testing.T) {
	rep := output.Report{Findings: []output.Finding{
		{Status: output.StatusFail, Severity: output.SeverityHigh, Title: "SIP disabled", Detail: "a\nb", Remediation: "csrutil enable"},
		{Status: output.StatusPass, Title: "Gatekeeper on"},
		{Status: output.StatusInfo, Title: "2 third-party items"},
	}}
	rep.Summarize()
	var buf bytes.Buffer
	writeFindings(&buf, rep)
	s := buf.String()
	for _, want := range []string{"[HIGH] SIP disabled", "    a\n    b", "fix: csrutil enable", "[INFO] 2 third-party items", "1 failed (1 high), 1 passed, 1 info"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "Gatekeeper on") {
		t.Error("passing findings must not be listed")
	}
}

func TestWriteFindings_None(t *testing.T) {
	var buf bytes.Buffer
	writeFindings(&buf, output.Report{})
	if !strings.Contains(buf.String(), "No findings.") {
		t.Errorf("want 'No findings.': %s", buf.String())
	}
}

func TestApplySuppressions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.yaml")
	if err := os.WriteFile(path, []byte("suppressions:\n  - {id: network.firewall, reason: 'MDM manages it'}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep := output.Report{Findings: []output.Finding{
		{ID: "network.firewall", Status: output.StatusFail, Severity: output.SeverityMedium, Title: "Application firewall is off"},
		{ID: "triage.sip", Status: output.StatusFail, Severity: output.SeverityHigh, Title: "SIP disabled"},
	}}
	suppressFile = path
	defer func() { suppressFile = "" }()
	if err := applySuppressions(&rep); err != nil {
		t.Fatal(err)
	}
	rep.Summarize()
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "triage.sip" || rep.Summary.Suppressed != 1 || rep.Summary.FailBySeverity[output.SeverityMedium] != 0 {
		t.Errorf("suppressed finding must leave the summary and fail-on: %+v", rep)
	}
	var buf bytes.Buffer
	writeFindings(&buf, rep)
	if !strings.Contains(buf.String(), "1 finding(s) accepted") || !strings.Contains(buf.String(), "MDM manages it") {
		t.Errorf("accepted findings must be listed with their reason:\n%s", buf.String())
	}
	if err := exitError(&cobra.Command{}, rep, output.SeverityHigh); err == nil {
		t.Error("the remaining high finding must still trip --fail-on high")
	}
	only := output.Report{Findings: []output.Finding{{ID: "network.firewall", Status: output.StatusFail, Severity: output.SeverityMedium, Title: "off"}}}
	if err := applySuppressions(&only); err != nil {
		t.Fatal(err)
	}
	only.Summarize()
	if err := exitError(&cobra.Command{}, only, output.SeverityMedium); err != nil {
		t.Errorf("an accepted medium finding must not trip --fail-on medium: %v", err)
	}

	suppressFile = filepath.Join(dir, "missing.yaml")
	if err := applySuppressions(&rep); err == nil {
		t.Error("a missing suppressions file must be an error, not silently ignored")
	}
}

func runCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	_ = rootCmd.Flags().Set("help", "false")
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return out.String(), err
}

func TestVerifyCommand(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	rep := output.Report{
		SchemaVersion: output.SchemaVersion,
		Tool:          output.ToolInfo{Name: "mac-compass", Version: "test"},
		Host:          output.HostInfo{Hostname: "host", Arch: "arm64", MacOSVersion: "26.0"},
		Sections: []output.SectionResult{{Section: "triage", Checks: []output.CheckResult{
			{ID: "triage.sip", Section: "triage", Name: "SIP", Ok: true, Stdout: "enabled\n"}}}},
	}
	snap := baseline.FromSections(rep.Tool, rep.Host, true, time.Unix(0, 0), rep.Sections)
	_, hash, err := evidence.Write(dir, evidence.Input{Report: rep, Snapshot: snap, FindingsText: "No findings.\n"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { verifyExpect = "" }()

	out, err := runCmd(t, "verify", dir, "--expect", hash)
	if err != nil || !strings.Contains(out, "OK: every file matches") || !strings.Contains(out, "matches the value you recorded") {
		t.Fatalf("intact bundle: %v\n%s", err, out)
	}
	out, err = runCmd(t, "verify", dir, "--expect", strings.Repeat("0", 64))
	if err == nil || !strings.Contains(out, "does not match the one you recorded") {
		t.Errorf("a wrong recorded hash must fail: %v\n%s", err, out)
	}
	verifyExpect = ""
	out, err = runCmd(t, "verify", dir)
	if err != nil || !strings.Contains(out, "proves the files match the manifest, not that the manifest is the original") {
		t.Errorf("without --expect the limit must be stated: %v\n%s", err, out)
	}

	if err := os.WriteFile(filepath.Join(dir, "raw", "triage.sip.txt"), []byte("edited"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = runCmd(t, "verify", dir)
	if err == nil || !strings.Contains(out, "CHANGED: raw/triage.sip.txt") {
		t.Errorf("tampering must be reported: %v\n%s", err, out)
	}
	if _, err := runCmd(t, "verify", filepath.Join(t.TempDir(), "nothing")); err == nil {
		t.Error("a folder that is not a bundle must be an error")
	}
}

func TestCollectNeedsMacOS(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("collect runs for real on macOS")
	}
	t.Setenv("MAC_COMPASS_ALLOW_NON_DARWIN", "")
	if _, err := runCmd(t, "collect", "-o", filepath.Join(t.TempDir(), "b")); err == nil {
		t.Error("collect must refuse to run off macOS")
	}
}

func TestWriteExtraReports(t *testing.T) {
	dir := t.TempDir()
	htmlPath, sarifPath = filepath.Join(dir, "r.html"), filepath.Join(dir, "r.sarif")
	defer func() { htmlPath, sarifPath = "", "" }()
	rep := output.Report{
		Tool: output.ToolInfo{Name: "mac-compass", Version: "t"},
		Findings: []output.Finding{
			{ID: "triage.sip", CheckID: "triage.sip", Status: output.StatusFail, Severity: output.SeverityHigh, Title: "SIP is off"},
		},
	}
	rep.Summarize()
	if err := writeExtraReports(rep); err != nil {
		t.Fatal(err)
	}
	h, _ := os.ReadFile(htmlPath)
	s, _ := os.ReadFile(sarifPath)
	if !strings.Contains(string(h), "SIP is off") || !strings.Contains(string(s), `"version": "2.1.0"`) || !strings.Contains(string(s), "triage.sip") {
		t.Errorf("reports not written correctly:\n%s\n%s", h, s)
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{htmlPath, sarifPath} {
			if info, _ := os.Stat(p); info.Mode().Perm()&0o077 != 0 {
				t.Errorf("%s must be private: %v", p, info.Mode())
			}
		}
	}
	htmlPath = filepath.Join(dir, "no-such-dir", "r.html")
	if err := writeExtraReports(rep); err == nil || !strings.Contains(err.Error(), "--html") {
		t.Errorf("a write failure must name the flag: %v", err)
	}
	htmlPath, sarifPath = "", ""
	if err := writeExtraReports(rep); err != nil {
		t.Errorf("no flags, nothing to do: %v", err)
	}
}

func TestMonitorInstallStatusUninstall(t *testing.T) {
	t.Setenv("MAC_COMPASS_ALLOW_NON_DARWIN", "1")
	dir := t.TempDir()
	launch, state := filepath.Join(dir, "launch"), filepath.Join(dir, "state")
	defer func() { monScope, monLaunchDir, monStateDir, monNoLoad, monPurge = "user", "", "", false, false }()

	out, err := runCmd(t, "monitor", "install", "--no-load", "--launch-dir", launch, "--state-dir", state, "--every", "30m", "--notify-on", "high")
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	plist, err := os.ReadFile(filepath.Join(launch, "io.github.jimididit.mac-compass.monitor.plist"))
	if err != nil {
		t.Fatalf("plist not written: %v", err)
	}
	for _, want := range []string{"<integer>1800</integer>", "<string>--notify-on</string>", "<string>high</string>", "<string>--no-sudo</string>", "<string>monitor</string>"} {
		if !strings.Contains(string(plist), want) {
			t.Errorf("plist missing %q", want)
		}
	}
	if fi, err := os.Stat(state); err != nil || !fi.IsDir() {
		t.Errorf("state folder not created: %v", err)
	}

	out, err = runCmd(t, "monitor", "status", "--launch-dir", launch, "--state-dir", state)
	if err != nil || !strings.Contains(out, "(present)") || !strings.Contains(out, "last run:   never") {
		t.Errorf("status: %v\n%s", err, out)
	}

	out, err = runCmd(t, "monitor", "uninstall", "--launch-dir", launch, "--state-dir", state, "--purge")
	if err != nil || !strings.Contains(out, "Removed") {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(launch, "io.github.jimididit.mac-compass.monitor.plist")); err == nil {
		t.Error("plist must be removed")
	}
	if _, err := os.Stat(state); err == nil {
		t.Error("--purge must delete the state folder")
	}
	out, _ = runCmd(t, "monitor", "uninstall", "--launch-dir", launch, "--state-dir", state)
	if !strings.Contains(out, "Not installed") {
		t.Errorf("uninstalling twice should say so: %s", out)
	}
}

func TestMonitorInstallValidation(t *testing.T) {
	t.Setenv("MAC_COMPASS_ALLOW_NON_DARWIN", "1")
	dir := t.TempDir()
	defer func() { monScope, monLaunchDir, monStateDir, monNoLoad = "user", "", "", false }()
	base := []string{"monitor", "install", "--no-load", "--launch-dir", filepath.Join(dir, "l"), "--state-dir", filepath.Join(dir, "s")}
	for name, extra := range map[string][]string{
		"too frequent":   {"--every", "1m"},
		"bad scope":      {"--scope", "global"},
		"bad notify-on":  {"--notify-on", "severe"},
		"system no sudo": {"--scope", "system"},
	} {
		if out, err := runCmd(t, append(append([]string{}, base...), extra...)...); err == nil {
			t.Errorf("%s must be rejected:\n%s", name, out)
		}
		monScope, monEvery, monNotifyOn = "user", time.Hour, "medium"
	}
}
