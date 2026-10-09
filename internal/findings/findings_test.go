package findings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimididit/mac-compass/internal/output"
)

// fixture loads captured stdout (and stderr) from a real GitHub-hosted macOS runner.
func fixture(t *testing.T, dir, id string) output.CheckResult {
	t.Helper()
	read := func(ext string) string {
		b, err := os.ReadFile(filepath.Join("testdata", dir, id+ext))
		if err != nil {
			if os.IsNotExist(err) {
				return ""
			}
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}
	return output.CheckResult{ID: id, Name: id, Ok: true, Stdout: read(".stdout"), Stderr: read(".stderr")}
}

func eval(t *testing.T, r output.CheckResult) []output.Finding {
	t.Helper()
	return Evaluate([]output.SectionResult{{Section: "x", Checks: []output.CheckResult{r}}})
}

func one(t *testing.T, fs []output.Finding) output.Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(fs), fs)
	}
	return fs[0]
}

// The hosted runners are deliberately weak machines: SIP, firewall and FileVault off.
func TestRealRunnerOutput(t *testing.T) {
	want := map[string]struct {
		status output.Status
		sev    output.Severity
	}{
		"triage.sip":                    {output.StatusFail, output.SeverityHigh},
		"triage.sip-authenticated-root": {output.StatusPass, ""},
		"triage.gatekeeper":             {output.StatusPass, ""},
		"triage.kext-non-apple":         {output.StatusPass, ""},
		"processes.launchctl-dyld":      {output.StatusPass, ""},
		"kernel.system-extensions":      {output.StatusPass, ""},
		"kernel.nvram-boot-args":        {output.StatusPass, ""},
		"persistence.crontab":           {output.StatusPass, ""},
		"network.firewall":              {output.StatusFail, output.SeverityMedium},
		"security-tools.filevault":      {output.StatusFail, output.SeverityMedium},
		"network.listening-tcp":         {output.StatusFail, output.SeverityLow}, // Remote Login (SSH)
		"harden.softwareupdate-list":    {output.StatusFail, output.SeverityLow},
		"harden.auto-update-settings":   {output.StatusFail, output.SeverityLow},
		"triage.launchdaemons":          {output.StatusInfo, ""},
		"triage.launchagents-system":    {output.StatusInfo, ""},
	}
	for _, dir := range []string{"macos26-arm64", "macos15-arm64"} {
		for id, w := range want {
			t.Run(dir+"/"+id, func(t *testing.T) {
				f := one(t, eval(t, fixture(t, dir, id)))
				if f.Status != w.status || f.Severity != w.sev {
					t.Errorf("got %s/%s %q; want %s/%s", f.Status, f.Severity, f.Title, w.status, w.sev)
				}
				if f.CheckID != id {
					t.Errorf("CheckID = %q", f.CheckID)
				}
				if f.Status == output.StatusFail && f.Remediation == "" {
					t.Error("failing finding must carry a remediation")
				}
			})
		}
	}
}

func TestRealRunner_Details(t *testing.T) {
	ssh := one(t, eval(t, fixture(t, "macos26-arm64", "network.listening-tcp")))
	if !strings.Contains(ssh.Title, "SSH") {
		t.Errorf("SSH listener not named: %q", ssh.Title)
	}
	upd := one(t, eval(t, fixture(t, "macos26-arm64", "harden.softwareupdate-list")))
	if !strings.Contains(upd.Title, "update(s) available") || !strings.Contains(upd.Detail, "macOS") {
		t.Errorf("update finding wrong: %+v", upd)
	}
	ld := one(t, eval(t, fixture(t, "macos26-arm64", "triage.launchdaemons")))
	if !strings.Contains(ld.Detail, "com.veertu.anka.addons.plist") || strings.Contains(ld.Detail, "total") {
		t.Errorf("launchdaemon detail wrong: %q", ld.Detail)
	}
}

func res(id, stdout string) output.CheckResult {
	return output.CheckResult{ID: id, Name: id, Ok: true, Stdout: stdout}
}

func TestHealthyAndBadStates(t *testing.T) {
	cases := []struct {
		name   string
		r      output.CheckResult
		status output.Status
		sev    output.Severity
	}{
		{"sip on", res("triage.sip", "System Integrity Protection status: enabled.\n"), output.StatusPass, ""},
		{"sip custom", res("triage.sip", "System Integrity Protection status: unknown (Custom Configuration).\n"), output.StatusFail, output.SeverityMedium},
		{"sip junk", res("triage.sip", "???"), output.StatusInfo, ""},
		{"authroot off", res("triage.sip-authenticated-root", "Authenticated Root status: disabled\n"), output.StatusFail, output.SeverityMedium},
		{"gatekeeper off", res("triage.gatekeeper", "assessments disabled\n"), output.StatusFail, output.SeverityHigh},
		{"kext present", res("triage.kext-non-apple", "Index Refs Address Size Wired Name\n  120    0 0xffff 0x1000 0x1000 com.evil.kext (1.0)\n"), output.StatusFail, output.SeverityMedium},
		{"dyld set", res("processes.launchctl-dyld", "DYLD_INSERT_LIBRARIES => /tmp/x.dylib\n"), output.StatusFail, output.SeverityHigh},
		{"sysext some", res("kernel.system-extensions", "2 extension(s)\n--- com.apple.system_extension.endpoint_security\n"), output.StatusInfo, ""},
		{"bootargs evil", res("kernel.nvram-boot-args", "boot-args\tamfi_get_out_of_my_way=1\n"), output.StatusFail, output.SeverityHigh},
		{"bootargs custom", res("kernel.nvram-boot-args", "boot-args\t-v\n"), output.StatusFail, output.SeverityLow},
		{"cron entry", res("persistence.crontab", "# header\n* * * * * /tmp/x.sh\n"), output.StatusFail, output.SeverityLow},
		{"cron comments only", res("persistence.crontab", "# header\n"), output.StatusPass, ""},
		{"firewall on", res("network.firewall", "Firewall is enabled. (State = 1)\n"), output.StatusPass, ""},
		{"filevault on", res("security-tools.filevault", "FileVault is On.\n"), output.StatusPass, ""},
		{"up to date", res("harden.softwareupdate-list", "Software Update Tool\n\nFinding available software\nNo new software available.\n"), output.StatusPass, ""},
		{"auto update on", res("harden.auto-update-settings", "{\n    AutomaticDownload = 1;\n    CriticalUpdateInstall = 1;\n    ConfigDataInstall = 1;\n}\n"), output.StatusPass, ""},
		{"auto update key missing", res("harden.auto-update-settings", "{\n    LastResultCode = 0;\n}\n"), output.StatusPass, ""},
		{"only loopback listeners", res("network.listening-tcp", "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nnode 9 me 5u IPv4 0x1 0t0 TCP 127.0.0.1:3000 (LISTEN)\n"), output.StatusPass, ""},
		{"vnc listener", res("network.listening-tcp", "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nlaunchd 1 root 5u IPv4 0x1 0t0 TCP *:5900 (LISTEN)\n"), output.StatusFail, output.SeverityLow},
		{"apple-only daemons", res("triage.launchdaemons", "total 8\n-rw-r--r--  1 root  wheel  100 Jan  1 00:00 com.apple.foo.plist\n"), output.StatusPass, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := one(t, eval(t, c.r))
			if f.Status != c.status || f.Severity != c.sev {
				t.Errorf("got %s/%s %q; want %s/%s", f.Status, f.Severity, f.Title, c.status, c.sev)
			}
		})
	}
}

func TestFailedAndSkippedChecks(t *testing.T) {
	failed := output.CheckResult{ID: "triage.sip", Name: "SIP status", Ok: false, Error: "exit status 2", Stderr: "boom\nmore"}
	f := one(t, eval(t, failed))
	if f.Status != output.StatusError || !strings.Contains(f.Detail, "boom") {
		t.Errorf("failed check should be an error finding: %+v", f)
	}
	skipped := output.CheckResult{ID: "triage.sip", Skipped: true}
	if fs := eval(t, skipped); len(fs) != 0 {
		t.Errorf("skipped check must yield no findings: %+v", fs)
	}
	if fs := eval(t, res("no.evaluator", "whatever")); len(fs) != 0 {
		t.Errorf("check without evaluator must yield nothing: %+v", fs)
	}
}

func TestSortedMostSevereFirst(t *testing.T) {
	fs := Evaluate([]output.SectionResult{{Checks: []output.CheckResult{
		res("triage.gatekeeper", "assessments enabled"),                            // pass
		res("persistence.crontab", "* * * * * x"),                                  // low
		res("triage.sip", "System Integrity Protection status: disabled."),         // high
		res("network.firewall", "Firewall is disabled. (State = 0)"),               // medium
		{ID: "triage.sip-authenticated-root", Name: "x", Ok: false, Error: "boom"}, // error
	}}})
	var got []string
	for _, f := range fs {
		got = append(got, string(f.Status)+"/"+string(f.Severity))
	}
	want := "fail/high fail/medium fail/low error/ pass/"
	if strings.Join(got, " ") != want {
		t.Errorf("order = %v; want %s", got, want)
	}
}
