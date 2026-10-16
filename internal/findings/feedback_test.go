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

// Whatever Rich's Mac reports, the advice must match the cause the check observed.
func TestTCCHintNamesTheObservedCause(t *testing.T) {
	cases := []struct {
		name, stderr string
		want         []string
		not          []string
	}{
		{"no Full Disk Access", "Error: unable to open database \"/x\": authorization denied\nfull-disk-access: denied\n",
			[]string{"has no Full Disk Access", "Command+Q"}, []string{"management profile"}},
		{"access granted but still refused", "Error: unable to open database file\nfull-disk-access: granted\n",
			[]string{"has Full Disk Access, but macOS still refuses", "management profile"}, []string{"Command+Q"}},
		{"could not tell (older output)", "Error: unable to open database: authorization denied\nfull-disk-access: unknown\n",
			[]string{"Command+Q", "management profile"}, nil},
		{"no diagnostic line at all", "Error: unable to open database: authorization denied",
			[]string{"Command+Q", "management profile"}, nil},
	}
	for _, c := range cases {
		for _, id := range []string{"security-tools.tcc-system", "security-tools.tcc-user"} {
			r := output.CheckResult{ID: id, Name: "Privacy grants", Error: "exit status 1", Stderr: c.stderr}
			f := one(t, eval(t, r))
			if f.Status != output.StatusError {
				t.Fatalf("%s/%s: want an error finding, got %+v", c.name, id, f)
			}
			for _, w := range c.want {
				if !strings.Contains(f.Remediation, w) {
					t.Errorf("%s/%s: advice should contain %q: %s", c.name, id, w, f.Remediation)
				}
			}
			for _, n := range c.not {
				if strings.Contains(f.Remediation, n) {
					t.Errorf("%s/%s: advice must not contain %q: %s", c.name, id, n, f.Remediation)
				}
			}
		}
	}
}

// A Mac with no per-user privacy database (all permissions pre-approved by a profile) has no per-user
// grants; that is an answer, not a failure.
func TestTCCUserDatabaseAbsentIsNotAnError(t *testing.T) {
	r := res("security-tools.tcc-user", "tcc-db: absent\n")
	f := one(t, eval(t, r))
	if f.Status != output.StatusPass || !strings.Contains(f.Title, "no privacy database") {
		t.Errorf("absent database: %+v", f)
	}
	rows := res("security-tools.tcc-user", "kTCCServiceAccessibility|com.vendor.app|0\n")
	if f := one(t, eval(t, rows)); f.Status != output.StatusInfo {
		t.Errorf("a normal grant is still reported: %+v", f)
	}
}
