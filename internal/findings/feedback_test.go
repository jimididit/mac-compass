package findings

import (
	"strings"
	"testing"

	"github.com/jimididit/mac-compass/internal/monitor"
	"github.com/jimididit/mac-compass/internal/output"
)

func TestSoftwareUpdateUpToDateOnStderr(t *testing.T) {
	r := res("harden.softwareupdate-list", "Software Update Tool\n\nFinding available software\n")
	r.Stderr = "No new software available.\n"
	if f := one(t, eval(t, r)); f.Status != output.StatusPass {
		t.Errorf("macOS 15 prints the all-clear on stderr: %+v", f)
	}
	r.Stderr = ""
	if f := one(t, eval(t, r)); f.Status != output.StatusInfo {
		t.Errorf("no all-clear anywhere stays 'not recognised': %+v", f)
	}
}

func TestErrorHints(t *testing.T) {
	tcc := output.CheckResult{ID: "security-tools.tcc-system", Name: "Privacy grants", Error: "exit status 1", Stderr: "Error: unable to open database: authorization denied"}
	f := one(t, eval(t, tcc))
	if f.Status != output.StatusError || !strings.Contains(f.Remediation, "Full Disk Access") {
		t.Errorf("TCC failure should explain Full Disk Access: %+v", f)
	}
	slow := output.CheckResult{ID: "persistence.login-items", Name: "Login items", Error: "timeout after 20s"}
	if f := one(t, eval(t, slow)); !strings.Contains(f.Remediation, "--timeout") {
		t.Errorf("timeouts should say what to do: %+v", f)
	}
	plain := output.CheckResult{ID: "triage.sip", Name: "SIP", Error: "exit status 2"}
	if f := one(t, eval(t, plain)); f.Remediation != "" {
		t.Errorf("unknown failures get no invented advice: %+v", f)
	}
}

func TestProcessSignatures_HiddenFolderSeverity(t *testing.T) {
	data := procRows(
		"me\t/Users/me/.cache/gitstatus/gitstatusd\t1\tunsigned\t-\t-\t-\thidden-location",
		"me\t/Library/.stash/agent\t1\tunsigned\t-\t-\t-\thidden-location",
		"me\t/tmp/x\t1\tunsigned\t-\t-\t-\ttemp-location",
	)
	var high, medium string
	for _, f := range eval(t, res("processes.signatures", data)) {
		switch {
		case f.Status == output.StatusFail && f.Severity == output.SeverityHigh:
			high = f.Detail
		case f.Status == output.StatusFail && strings.Contains(f.Title, "hidden folder in a home directory"):
			medium = f.Detail
		}
	}
	if !strings.Contains(medium, ".cache/gitstatus") || strings.Contains(medium, "/Library/.stash") {
		t.Errorf("a developer tool cache in the home folder is medium: %q", medium)
	}
	if !strings.Contains(high, "/Library/.stash/agent") || !strings.Contains(high, "/tmp/x") || strings.Contains(high, ".cache/gitstatus") {
		t.Errorf("hidden folders outside home, and temp folders, stay high: %q", high)
	}
}

func TestLaunchdTargets_MonitorJobIsNotAFinding(t *testing.T) {
	if monitorLabel != monitor.Label {
		t.Fatalf("monitorLabel %q must match monitor.Label %q", monitorLabel, monitor.Label)
	}
	data := rows("user-agent\t" + monitor.Label + "\t/Users/me/Library/LaunchAgents/m.plist\t/Users/me/bin/mac-compass\tunsigned\t-\t-\t-\trunatload")
	f := one(t, eval(t, res("persistence.launchd-targets", data)))
	if f.Status != output.StatusInfo || !strings.Contains(f.Detail, "1 mac-compass monitor job") {
		t.Errorf("the monitor's own job is counted, never flagged: %+v", f)
	}
}
