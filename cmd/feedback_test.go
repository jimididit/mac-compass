package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jimididit/mac-compass/internal/baseline"
	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/redact"
	"github.com/jimididit/mac-compass/internal/runner"
)

func snapWith(accounts string) baseline.Snapshot {
	return baseline.FromSections(output.ToolInfo{}, output.HostInfo{Hostname: "alices-mbp.local"}, false, time.Unix(0, 0),
		[]output.SectionResult{{Checks: []output.CheckResult{
			{ID: "accounts.local-users", Ok: true, Stdout: accounts},
			{ID: "persistence.shell-rc", Ok: true, Stdout: "abc123  /Users/alice/.zshrc\n"},
		}}})
}

// A masked baseline compared against a live snapshot used to report every item that mentions the user
// as both new and removed.
func TestCompareWithRedactedBaseline(t *testing.T) {
	red := redact.New("alices-mbp.local", "alice")
	old := snapWith("alice 501\n")
	red.Snapshot(&old)
	if !old.Redacted || old.Checks["accounts.local-users"].Items[0] != "[user] 501" {
		t.Fatalf("baseline should be masked: %+v", old)
	}

	cur := snapWith("alice 501\n") // live, unmasked
	alignRedaction(old, &cur, red)
	if r := baseline.Compare(old, cur); len(r.Findings) != 0 {
		t.Errorf("an untouched machine must compare clean against its masked baseline: %+v", r.Findings)
	}

	// A real change is still found afterwards.
	cur = snapWith("alice 501\nmallory 502\n")
	alignRedaction(old, &cur, red)
	r := baseline.Compare(old, cur)
	if len(r.Findings) != 1 || !strings.Contains(r.Findings[0].Detail, "+ mallory 502") {
		t.Errorf("a new account must still be reported: %+v", r.Findings)
	}

	// An unmasked baseline is left alone.
	plain := snapWith("alice 501\n")
	live := snapWith("alice 501\n")
	alignRedaction(plain, &live, red)
	if live.Redacted || live.Checks["accounts.local-users"].Items[0] != "alice 501" {
		t.Errorf("an unmasked baseline must not mask the live side: %+v", live)
	}
}

func TestProgressStatus(t *testing.T) {
	cases := map[string]runner.Result{
		"ok":      {},
		"skipped": {Skipped: true},
		"failed":  {Err: os.ErrInvalid},
	}
	for want, res := range cases {
		if got := progressStatus(res); got != want {
			t.Errorf("progressStatus(%+v) = %s; want %s", res, got, want)
		}
	}
}

func TestChownToInvokerIsHarmlessWhenNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("x"), 0o600)
	if err := chownToInvoker(p, "", "/nonexistent/never-touched"); err != nil {
		t.Errorf("a non-root run must do nothing: %v", err)
	}
}

// Runtime failures must not print the whole usage text.
func TestNoUsageOnRuntimeError(t *testing.T) {
	out, err := runCmd(t, "verify", filepath.Join(t.TempDir(), "not-a-bundle"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(out, "Usage:") {
		t.Errorf("usage dumped for a runtime error:\n%s", out)
	}
	// A genuine usage mistake still shows usage. (Reset the shared command: each real run is a fresh process.)
	verifyCmd.SilenceUsage, rootCmd.SilenceUsage = false, false
	out, err = runCmd(t, "verify")
	if err == nil || !strings.Contains(out, "Usage:") {
		t.Errorf("a missing argument should still show usage: %v\n%s", err, out)
	}
}

func TestWritePosture(t *testing.T) {
	var b strings.Builder
	writePosture(&b, output.Report{})
	if !strings.Contains(b.String(), "no score") {
		t.Errorf("nothing assessed must not print a score:\n%s", b.String())
	}

	rep := output.Report{Posture: &output.Posture{Score: 60, Passed: 1, Failed: 1, Controls: []output.PostureControl{
		{ID: "triage.sip", Title: "SIP is on", Status: "pass"},
		{ID: "network.firewall", Title: "Firewall is on", Status: "fail", Remediation: "turn it on"},
	}}}
	b.Reset()
	writePosture(&b, rep)
	for _, want := range []string{"[PASS] SIP is on", "[FAIL] Firewall is on", "fix: turn it on", "Score: 60/100"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}
}
