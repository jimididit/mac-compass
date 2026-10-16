package baseline

import (
	"bytes"
	"github.com/jimididit/mac-compass/internal/runner"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jimididit/mac-compass/internal/output"
)

func res(id, stdout string) output.CheckResult {
	return output.CheckResult{ID: id, Name: id, Ok: true, Stdout: stdout}
}

func snap(host output.HostInfo, rs ...output.CheckResult) Snapshot {
	return FromSections(output.ToolInfo{Name: "t"}, host, true, time.Unix(0, 0),
		[]output.SectionResult{{Section: "x", Checks: rs}})
}

func fixture(t *testing.T, dir, id string) output.CheckResult {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "findings", "testdata", dir, id+".stdout"))
	if err != nil {
		t.Fatal(err)
	}
	return res(id, strings.ReplaceAll(string(b), "\r\n", "\n"))
}

func TestExtractors_RealRunnerOutput(t *testing.T) {
	s := snap(output.HostInfo{},
		fixture(t, "macos26-arm64", "triage.sip"),
		fixture(t, "macos26-arm64", "triage.launchdaemons"),
		fixture(t, "macos26-arm64", "network.listening-tcp"),
		fixture(t, "macos26-arm64", "harden.auto-update-settings"),
		fixture(t, "macos26-arm64", "kernel.system-extensions"),
		fixture(t, "macos26-arm64", "triage.kext-non-apple"),
	)
	if got := s.Checks["triage.sip"]; got.Kind != KindState || len(got.Items) != 1 || !strings.Contains(got.Items[0], "disabled") {
		t.Errorf("sip: %+v", got)
	}
	ld := s.Checks["triage.launchdaemons"]
	if ld.Kind != KindSet || len(ld.Items) != 7 || !contains(ld.Items, "com.veertu.anka.addons.plist") || contains(ld.Items, "total") {
		t.Errorf("launchdaemons: %+v", ld)
	}
	if tcp := s.Checks["network.listening-tcp"]; len(tcp.Items) != 1 || !strings.HasPrefix(tcp.Items[0], "TCP launchd root ") {
		t.Errorf("tcp must drop pid/fd and de-duplicate IPv4/IPv6 rows: %+v", tcp)
	}
	au := s.Checks["harden.auto-update-settings"].Items
	if len(au) != 1 || !strings.Contains(au[0], "CriticalUpdateInstall=0") || strings.Contains(au[0], "2026") {
		t.Errorf("auto-update must keep only stable switches: %v", au)
	}
	if got := s.Checks["kernel.system-extensions"]; len(got.Items) != 0 {
		t.Errorf("sysext: %+v", got)
	}
	if got := s.Checks["triage.kext-non-apple"]; len(got.Items) != 0 {
		t.Errorf("kext header must be ignored: %+v", got)
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func TestExtractors_Synthetic(t *testing.T) {
	s := snap(output.HostInfo{},
		res("network.listening-udp", "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nmDNSRespo 400 _mdns 7u IPv4 0x1 0t0 UDP *:5353\nmDNSRespo 400 _mdns 8u IPv6 0x2 0t0 UDP *:5353\n"),
		res("network.dns", "resolver #1\n  nameserver[0] : 1.1.1.1\n  nameserver[1] : 8.8.8.8\n"),
		res("persistence.login-items", "Dropbox, Slack\n"),
		res("persistence.crontab", "# comment\n*/5 * * * * /tmp/x.sh\n"),
		res("triage.kext-non-apple", "Index Refs Address Size Wired Name (Version) UUID <Linked Against>\n  120  0 0xffffff80 0x1000 0x1000 com.evil.kext (1.2.3) ABCD <5 3>\n"),
		res("kernel.kext-loaded", "Index Refs Address Size Wired Name (Version) UUID <Linked Against>\n   1  0 0xffffff80 0x1000 0x1000 com.apple.filesystems.autofs (3.0) AAAA <5>\n 120  0 0xffffff80 0x1000 0x1000 com.evil.kext (1.2.3) ABCD <5 3>\n"),
		res("kernel.system-extensions", "1 extension(s)\n--- com.apple.system_extension.endpoint_security\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n*\t*\tABCDE12345\tcom.vendor.es (1.0/1)\tES Agent\t[activated enabled]\n"),
	)
	check := func(id string, want ...string) {
		t.Helper()
		got := s.Checks[id].Items
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s = %q; want %q", id, got, want)
		}
	}
	check("network.listening-udp", "UDP mDNSRespo _mdns *:5353")
	check("network.dns", "nameserver 1.1.1.1", "nameserver 8.8.8.8")
	check("persistence.login-items", "Dropbox", "Slack")
	check("persistence.crontab", "*/5 * * * * /tmp/x.sh")
	check("triage.kext-non-apple", "com.evil.kext (1.2.3)")
	// Apple's on-demand extensions come and go on an untouched Mac, so they are not part of the baseline.
	check("kernel.kext-loaded", "com.evil.kext (1.2.3)")
	if got := s.Checks["kernel.system-extensions"].Items; len(got) != 1 || !strings.Contains(got[0], "com.vendor.es") {
		t.Errorf("sysext rows: %q", got)
	}
}

func TestFromSections_SkipsFailedSkippedAndUnknown(t *testing.T) {
	s := snap(output.HostInfo{},
		output.CheckResult{ID: "triage.sip", Ok: false, Error: "boom"},
		output.CheckResult{ID: "network.firewall", Skipped: true},
		res("no.extractor", "x"),
		res("triage.gatekeeper", "assessments enabled"),
	)
	if len(s.Checks) != 1 || s.Checks["triage.gatekeeper"].Items[0] != "assessments enabled" {
		t.Errorf("checks = %+v", s.Checks)
	}
}

func find(t *testing.T, r Result, id string, status output.Status) output.Finding {
	t.Helper()
	for _, f := range r.Findings {
		if f.ID == id && f.Status == status {
			return f
		}
	}
	t.Fatalf("no %s finding for %s in %+v", status, id, r.Findings)
	return output.Finding{}
}

func TestCompare(t *testing.T) {
	host := output.HostInfo{Hostname: "mac", MacOSVersion: "26.6.2"}
	old := snap(host,
		res("triage.sip", "System Integrity Protection status: enabled."),
		res("triage.launchdaemons", "total 8\n-rw-r--r--  1 root  wheel  100 Jan  1 00:00 good.plist\n-rw-r--r--  1 root  wheel  100 Jan  1 00:00 gone.plist\n"),
		res("network.listening-tcp", "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nsshd 9 root 3u IPv4 0x1 0t0 TCP *:22 (LISTEN)\n"),
		res("network.firewall", "Firewall is enabled. (State = 1)"),
	)
	cur := snap(host,
		res("triage.sip", "System Integrity Protection status: disabled."),
		res("triage.launchdaemons", "total 8\n-rw-r--r--  1 root  wheel  100 Jan  1 00:00 good.plist\n-rw-r--r--  1 root  wheel  999 Feb  2 00:00 evil.plist\n"),
		res("network.listening-tcp", "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nsshd 77 root 5u IPv4 0x9 0t0 TCP *:22 (LISTEN)\nnc 88 me 4u IPv4 0x2 0t0 TCP *:4444 (LISTEN)\n"),
		res("network.firewall", "Firewall is enabled. (State = 1)"),
	)
	r := Compare(old, cur)
	if r.Compared != 4 {
		t.Errorf("compared %d; want 4", r.Compared)
	}
	if f := find(t, r, "triage.sip", output.StatusFail); f.Severity != output.SeverityHigh || !strings.Contains(f.Detail, "enabled") || !strings.Contains(f.Detail, "disabled") {
		t.Errorf("sip change: %+v", f)
	}
	if f := find(t, r, "triage.launchdaemons", output.StatusFail); !strings.Contains(f.Detail, "+ evil.plist") || strings.Contains(f.Detail, "good.plist") {
		t.Errorf("new daemon: %+v", f)
	}
	if f := find(t, r, "triage.launchdaemons", output.StatusInfo); !strings.Contains(f.Detail, "- gone.plist") {
		t.Errorf("removed daemon: %+v", f)
	}
	if f := find(t, r, "network.listening-tcp", output.StatusFail); !strings.Contains(f.Detail, "4444") || strings.Contains(f.Detail, ":22") {
		t.Errorf("new listener must not include unchanged sshd despite new pid: %+v", f)
	}
	for _, f := range r.Findings {
		if f.ID == "network.firewall" {
			t.Errorf("unchanged setting must not produce a finding: %+v", f)
		}
	}
}

func TestCompare_Identical(t *testing.T) {
	a := snap(output.HostInfo{Hostname: "m", MacOSVersion: "26.6.2"}, res("triage.gatekeeper", "assessments enabled"))
	if r := Compare(a, a); len(r.Findings) != 0 || r.Compared != 1 {
		t.Errorf("identical snapshots must be clean: %+v", r)
	}
}

func TestCompare_HostAndVersionAreInfo(t *testing.T) {
	a := snap(output.HostInfo{Hostname: "a", MacOSVersion: "26.6.1"}, res("triage.gatekeeper", "assessments enabled"))
	b := snap(output.HostInfo{Hostname: "b", MacOSVersion: "26.6.2"}, res("triage.gatekeeper", "assessments enabled"))
	b.SudoEnabled = false
	r := Compare(a, b)
	find(t, r, "baseline.macos-version", output.StatusInfo)
	find(t, r, "baseline.hostname", output.StatusInfo)
	find(t, r, "baseline.sudo", output.StatusInfo)
	for _, f := range r.Findings {
		if f.Status == output.StatusFail {
			t.Errorf("host/version differences must not fail: %+v", f)
		}
	}
}

func TestCompare_NotComparable(t *testing.T) {
	a := snap(output.HostInfo{}, res("triage.gatekeeper", "assessments enabled"), res("network.firewall", "Firewall is enabled."))
	b := snap(output.HostInfo{}, res("triage.gatekeeper", "assessments enabled"))
	r := Compare(a, b)
	if r.Compared != 1 || len(r.NotComparable) != 1 || r.NotComparable[0] != "network.firewall" {
		t.Errorf("result: %+v", r)
	}
}

func TestReadWrite_RoundTripAndSchemaGuard(t *testing.T) {
	s := snap(output.HostInfo{Hostname: "m"}, res("triage.gatekeeper", "assessments enabled"))
	var buf bytes.Buffer
	if err := s.Write(&buf); err != nil {
		t.Fatal(err)
	}
	got, err := Read(bytes.NewReader(buf.Bytes()))
	if err != nil || got.Checks["triage.gatekeeper"].Items[0] != "assessments enabled" || got.Host.Hostname != "m" {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	if _, err := Read(strings.NewReader(`{"schema_version": 99, "checks": {}}`)); err == nil {
		t.Error("unknown schema version must be rejected")
	}
	if _, err := Read(strings.NewReader(`not json`)); err == nil {
		t.Error("garbage must be rejected")
	}
	if _, err := Read(strings.NewReader(`{"schema_version": 1}`)); err == nil {
		t.Error("snapshot without checks must be rejected")
	}
}

func TestEveryExtractorHasMetaAndCatalogID(t *testing.T) {
	for id := range extractors {
		if _, ok := metas[id]; !ok {
			t.Errorf("extractor %s has no meta (label/severity)", id)
		}
	}
}

func TestAccessExtractors(t *testing.T) {
	s := snap(output.HostInfo{},
		res("accounts.local-users", "_spotlight 89\nroot 0\nbackdoor 0\nalice 501\n"),
		res("accounts.admin-group", "GroupMembership: root alice\n"),
		res("persistence.shell-rc", "abc123  /Users/me/.zshrc\n"),
		res("persistence.hosts", "127.0.0.1\tlocalhost\n1.2.3.4   evil.test\n"),
		res("network.proxy", "<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : 10.0.0.9\n  ExceptionsList : <array> {\n  }\n}\n"),
		res("security-tools.mdm-enrollment", "Enrolled via DEP: No\nMDM enrollment: No\n"),
		res("accounts.guest", ""),
	)
	eq := func(id, want string) {
		t.Helper()
		if got := strings.Join(s.Checks[id].Items, "|"); got != want {
			t.Errorf("%s = %q; want %q", id, got, want)
		}
	}
	eq("accounts.local-users", "alice 501|backdoor 0|root 0")
	eq("accounts.admin-group", "alice|root")
	eq("persistence.shell-rc", "abc123  /Users/me/.zshrc")
	eq("persistence.hosts", "1.2.3.4 evil.test|127.0.0.1 localhost")
	eq("network.proxy", "HTTPEnable : 1|HTTPProxy : 10.0.0.9")
	eq("security-tools.mdm-enrollment", "Enrolled via DEP: No; MDM enrollment: No")
	if s.Checks["accounts.guest"].Kind != KindState {
		t.Error("guest must be a state entry")
	}
}

func TestCompare_NewAdminAndModifiedShellRC(t *testing.T) {
	old := snap(output.HostInfo{},
		res("accounts.admin-group", "GroupMembership: root alice\n"),
		res("persistence.shell-rc", "aaa  /Users/me/.zshrc\n"),
	)
	cur := snap(output.HostInfo{},
		res("accounts.admin-group", "GroupMembership: root alice mallory\n"),
		res("persistence.shell-rc", "bbb  /Users/me/.zshrc\n"),
	)
	r := Compare(old, cur)
	if f := find(t, r, "accounts.admin-group", output.StatusFail); f.Severity != output.SeverityHigh || !strings.Contains(f.Detail, "+ mallory") {
		t.Errorf("new admin: %+v", f)
	}
	if f := find(t, r, "persistence.shell-rc", output.StatusFail); !strings.Contains(f.Detail, "+ bbb  /Users/me/.zshrc") {
		t.Errorf("modified rc must appear as a new hash line: %+v", f)
	}
}

func TestBTMExtractor_RealRunnerOutput(t *testing.T) {
	s := snap(output.HostInfo{}, fixture(t, "macos26-arm64", "persistence.btm"))
	items := s.Checks["persistence.btm"].Items
	if len(items) < 4 {
		t.Fatalf("too few items: %v", items)
	}
	found := false
	for _, it := range items {
		if strings.HasPrefix(it, "developer |") {
			t.Errorf("developer grouping leaked: %q", it)
		}
		if strings.HasPrefix(it, "legacy daemon | ankaupd.sh | ") && strings.HasSuffix(it, "| enabled") {
			found = true
		}
	}
	if !found {
		t.Errorf("ankaupd.sh daemon missing: %v", items)
	}
}

func TestCompare_ImprovementIsInfoNotFailure(t *testing.T) {
	bad := snap(output.HostInfo{},
		res("triage.sip", "System Integrity Protection status: disabled."),
		res("network.firewall", "Firewall is disabled. (State = 0)"),
		res("kernel.nvram-boot-args", "boot-args\t-v\n"),
		res("accounts.autologin", "alice\n"),
	)
	good := snap(output.HostInfo{},
		res("triage.sip", "System Integrity Protection status: enabled."),
		res("network.firewall", "Firewall is enabled. (State = 1)"),
		res("kernel.nvram-boot-args", "boot-args\t\n"),
		res("accounts.autologin", ""),
	)
	r := Compare(bad, good)
	for _, id := range []string{"triage.sip", "network.firewall", "kernel.nvram-boot-args", "accounts.autologin"} {
		if f := find(t, r, id, output.StatusInfo); !strings.Contains(f.Title, "improved") {
			t.Errorf("%s: %+v", id, f)
		}
	}
	for _, f := range r.Findings {
		if f.Status == output.StatusFail {
			t.Errorf("an improvement must not fail: %+v", f)
		}
	}
	// And the reverse direction still fails.
	r = Compare(good, bad)
	find(t, r, "triage.sip", output.StatusFail)
	find(t, r, "network.firewall", output.StatusFail)
}

func TestLaunchTargetsExtractorAndSignerChange(t *testing.T) {
	hdr := runner.LaunchdHeader + "\n"
	old := snap(output.HostInfo{}, res("persistence.launchd-targets", hdr+
		"daemon\tcom.foo\t/Library/LaunchDaemons/f.plist\t/Library/Foo/foo\tdeveloper-id\tABCDE12345\tDeveloper ID Application: Foo (ABCDE12345)\tnotarized\trunatload\n"))
	cur := snap(output.HostInfo{}, res("persistence.launchd-targets", hdr+
		"daemon\tcom.foo\t/Library/LaunchDaemons/f.plist\t/Library/Foo/foo\tdeveloper-id\tFFFFF00000\tDeveloper ID Application: Other (FFFFF00000)\tdeveloper-id\trunatload,keepalive\n"))
	if got := old.Checks["persistence.launchd-targets"].Items; len(got) != 1 || got[0] != "daemon | com.foo | /Library/Foo/foo | developer-id | ABCDE12345" {
		t.Fatalf("items: %q", got)
	}
	r := Compare(old, cur)
	if f := find(t, r, "persistence.launchd-targets", output.StatusFail); f.Severity != output.SeverityHigh || !strings.Contains(f.Detail, "+ daemon | com.foo | /Library/Foo/foo | developer-id | FFFFF00000") {
		t.Errorf("a changed signing team must be a high finding: %+v", f)
	}
	same := snap(output.HostInfo{}, res("persistence.launchd-targets", hdr+
		"daemon\tcom.foo\t/Library/LaunchDaemons/f.plist\t/Library/Foo/foo\tdeveloper-id\tABCDE12345\tDeveloper ID Application: Foo (ABCDE12345)\tdeveloper-id\t-\n"))
	if r := Compare(old, same); len(r.Findings) != 0 {
		t.Errorf("notarization and flag changes alone must not be reported: %+v", r.Findings)
	}
}

func integrityRow(label, plistSHA, program, sha, state, sig, team, signer string) string {
	return strings.Join([]string{"daemon", label, "/Library/LaunchDaemons/" + label + ".plist", plistSHA, program, sha, state, sig, team, signer}, "\t")
}

func integritySnap(rows ...string) Snapshot {
	out := runner.IntegrityHeader + "\n" + strings.Join(rows, "\n") + "\n"
	return snap(output.HostInfo{}, res("persistence.launch-integrity", out))
}

func TestLaunchIntegrityDiff(t *testing.T) {
	dev := func(sha, sig string) string {
		return integrityRow("com.foo", "p1", "/Library/Foo/foo", sha, "developer-id", sig, "ABCDE12345", "Developer ID Application: Foo Inc")
	}
	titles := func(r Result) string {
		var s []string
		for _, f := range r.Findings {
			s = append(s, string(f.Status)+"/"+string(f.Severity)+" "+f.Detail)
		}
		return strings.Join(s, " | ")
	}
	base := integritySnap(dev("h1", "valid"))

	if r := Compare(base, integritySnap(dev("h1", "valid"))); len(r.Findings) != 0 {
		t.Errorf("an unchanged item must produce nothing: %s", titles(r))
	}
	// A routine update: the hash changes, the developer signature still verifies.
	r := Compare(base, integritySnap(dev("h2", "valid")))
	if len(r.Findings) != 1 || r.Findings[0].Status != output.StatusInfo {
		t.Errorf("a signed update is informational only: %s", titles(r))
	}
	// The same file modified after signing: the signature stops verifying.
	r = Compare(base, integritySnap(dev("h2", "invalid")))
	if len(r.Findings) != 1 || r.Findings[0].Severity != output.SeverityHigh || !strings.Contains(r.Findings[0].Detail, "no longer verifies") {
		t.Errorf("a broken signature is high: %s", titles(r))
	}
	// Re-signed by someone else.
	other := integrityRow("com.foo", "p1", "/Library/Foo/foo", "h2", "developer-id", "valid", "ZZZZZ99999", "Developer ID Application: Other Inc")
	r = Compare(base, integritySnap(other))
	if len(r.Findings) != 1 || r.Findings[0].Severity != output.SeverityHigh || !strings.Contains(r.Findings[0].Detail, "signer changed") {
		t.Errorf("a changed signer is high: %s", titles(r))
	}
	// Same program, new launch arguments: only the plist changed.
	edited := integrityRow("com.foo", "p2", "/Library/Foo/foo", "h1", "developer-id", "valid", "ABCDE12345", "Developer ID Application: Foo Inc")
	r = Compare(base, integritySnap(edited))
	if len(r.Findings) != 1 || r.Findings[0].Severity != output.SeverityMedium || !strings.Contains(r.Findings[0].Detail, "plist") {
		t.Errorf("a changed plist is medium: %s", titles(r))
	}
	// A script has no signature, so a changed script is medium.
	scriptOld := integritySnap(integrityRow("com.s", "p1", "/usr/local/bin/run.sh", "s1", "script", "-", "-", "-"))
	scriptNew := integritySnap(integrityRow("com.s", "p1", "/usr/local/bin/run.sh", "s2", "script", "-", "-", "-"))
	if r := Compare(scriptOld, scriptNew); len(r.Findings) != 1 || r.Findings[0].Severity != output.SeverityMedium {
		t.Errorf("a changed unsigned program is medium: %s", titles(r))
	}
}

// The monitor's own job changes whenever it is reinstalled or updated; it is not part of the comparison.
func TestLaunchIntegrityIgnoresMonitorJob(t *testing.T) {
	s := integritySnap(integrityRow(runner.MonitorLabel, "p1", "/x/mac-compass", "h1", "adhoc", "valid", "-", "-"))
	if got := s.Checks["persistence.launch-integrity"].Items; len(got) != 0 {
		t.Errorf("monitor job should be left out: %v", got)
	}
}

func appRow(path, id, version, state, team, signer, cdhash string) string {
	return strings.Join([]string{path, id, version, state, team, signer, cdhash}, "\t")
}

func appSnap(rows ...string) Snapshot {
	return snap(output.HostInfo{}, res("advanced.applications", runner.AppsHeader+"\n"+strings.Join(rows, "\n")+"\n"))
}

func TestApplicationDiff(t *testing.T) {
	app := func(version, cd string) string {
		return appRow("/Applications/Foo.app", "com.foo.app", version, "developer-id", "ABCDE12345", "Developer ID Application: Foo Inc", cd)
	}
	base := appSnap(app("1.0", "aaa"))
	one := func(r Result) output.Finding {
		t.Helper()
		if len(r.Findings) != 1 {
			t.Fatalf("want 1 finding, got %+v", r.Findings)
		}
		return r.Findings[0]
	}

	if r := Compare(base, appSnap(app("1.0", "aaa"))); len(r.Findings) != 0 {
		t.Errorf("unchanged apps produce nothing: %+v", r.Findings)
	}
	if f := one(Compare(base, appSnap(app("1.1", "bbb")))); f.Status != output.StatusInfo || !strings.Contains(f.Detail, "updated 1.0 -> 1.1") {
		t.Errorf("a new version from the same signer is informational: %+v", f)
	}
	if f := one(Compare(base, appSnap(app("1.0", "bbb")))); f.Severity != output.SeverityMedium || !strings.Contains(f.Detail, "without a version change") {
		t.Errorf("changed contents under the same version is medium: %+v", f)
	}
	resigned := appRow("/Applications/Foo.app", "com.foo.app", "1.0", "developer-id", "ZZZZZ99999", "Developer ID Application: Other Inc", "aaa")
	if f := one(Compare(base, appSnap(resigned))); f.Severity != output.SeverityHigh || !strings.Contains(f.Detail, "signer changed") {
		t.Errorf("a different signer is high: %+v", f)
	}
	// New and removed applications.
	added := appSnap(app("1.0", "aaa"), appRow("/Applications/New.app", "com.new", "2.0", "developer-id", "QQQQQ11111", "Developer ID Application: New Inc", "ccc"))
	f := one(Compare(base, added))
	if f.Status != output.StatusFail || f.Severity != output.SeverityLow || !strings.Contains(f.Detail, "/Applications/New.app") {
		t.Errorf("a new application is low: %+v", f)
	}
	f = one(Compare(added, base))
	if f.Status != output.StatusInfo || !strings.Contains(f.Title, "removed") {
		t.Errorf("a removed application is informational: %+v", f)
	}
}
