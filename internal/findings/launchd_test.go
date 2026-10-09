package findings

import (
	"strings"
	"testing"

	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/runner"
)

func rows(lines ...string) string {
	return runner.LaunchdHeader + "\n" + strings.Join(lines, "\n") + "\n"
}

const (
	apple   = "daemon\tcom.apple.x\t/Library/LaunchDaemons/a.plist\t/usr/libexec/x\tapple\t-\t-\tapple\trunatload"
	devID   = "daemon\tcom.foo\t/Library/LaunchDaemons/f.plist\t/Library/Foo/foo\tdeveloper-id\tABCDE12345\tDeveloper ID Application: Foo Inc (ABCDE12345)\tnotarized\trunatload,keepalive"
	devIDNN = "agent\tcom.bar\t/Library/LaunchAgents/b.plist\t/Library/Bar/bar\tdeveloper-id\tZZZZZ99999\tDeveloper ID Application: Bar (ZZZZZ99999)\tdeveloper-id\t-"
)

func TestLaunchdTargets_AllGoodIsOnlyASummary(t *testing.T) {
	f := one(t, eval(t, res("persistence.launchd-targets", rows(apple, devID, devIDNN))))
	if f.Status != output.StatusInfo || !strings.Contains(f.Title, "3 launch item(s) checked") ||
		!strings.Contains(f.Detail, "1 Apple") || !strings.Contains(f.Detail, "1 Developer ID, notarized") || !strings.Contains(f.Detail, "1 Developer ID, not notarized") {
		t.Errorf("summary: %+v", f)
	}
}

func TestLaunchdTargets_RiskyItems(t *testing.T) {
	data := rows(apple, devID,
		"daemon\tcom.evil\t/Library/LaunchDaemons/e.plist\t/tmp/.x/payload\tunsigned\t-\t-\trejected\ttemp-location,runatload",
		"user-agent\tcom.hidden\t/Users/me/Library/LaunchAgents/h.plist\t/Users/me/.cache/agent\tdeveloper-id\tQ1\tDeveloper ID Application: Q (Q1)\tnotarized\thidden-location",
		"daemon\tcom.nosig\t/Library/LaunchDaemons/n.plist\t/opt/tool/tool\tunsigned\t-\t-\trejected\trunatload",
		"agent\tcom.adhoc\t/Library/LaunchAgents/ad.plist\t/usr/local/bin/mytool\tadhoc\t-\t-\trejected\t-",
		"daemon\tcom.gone\t/Library/LaunchDaemons/g.plist\t/opt/removed/app\tmissing\t-\t-\t-\t-",
		"daemon\tcom.script\t/Library/LaunchDaemons/s.plist\t/bin/sh\tscript\t-\t-\t-\tinterpreter,inline-command,keepalive",
	)
	fs := eval(t, res("persistence.launchd-targets", data))
	by := map[string]output.Finding{}
	for _, f := range fs {
		by[string(f.Severity)+"/"+string(f.Status)] = f
	}
	high := by["high/fail"]
	if !strings.Contains(high.Title, "2 launch item(s) run a program from a temporary or hidden location") ||
		!strings.Contains(high.Detail, "com.evil") || !strings.Contains(high.Detail, "com.hidden") || !strings.Contains(high.Detail, "[hidden location]") {
		t.Errorf("high: %+v", high)
	}
	if med := by["medium/fail"]; !strings.Contains(med.Title, "1 launch item(s) run an unsigned program") || !strings.Contains(med.Detail, "com.nosig") || strings.Contains(med.Detail, "com.evil") {
		t.Errorf("an item already flagged for its location must not repeat in the unsigned list: %+v", med)
	}
	lows := 0
	for _, f := range fs {
		if f.Severity == output.SeverityLow {
			lows++
		}
	}
	if lows != 3 {
		t.Errorf("want 3 low findings (adhoc, missing, script); got %d: %+v", lows, fs)
	}
	if fs[0].Severity != output.SeverityHigh {
		t.Errorf("most severe finding must sort first: %+v", fs[0])
	}
	for _, f := range fs {
		if f.Status == output.StatusFail && f.Remediation == "" {
			t.Errorf("failing finding needs a remediation: %+v", f)
		}
	}
}

func TestLaunchdTargets_EmptyAndMalformed(t *testing.T) {
	if f := one(t, eval(t, res("persistence.launchd-targets", runner.LaunchdHeader+"\n"))); f.Status != output.StatusPass {
		t.Errorf("no items: %+v", f)
	}
	if f := one(t, eval(t, res("persistence.launchd-targets", rows("not\ta\tvalid\trow")))); f.Status != output.StatusPass {
		t.Errorf("malformed rows are ignored: %+v", f)
	}
}

// Real output from a hosted macOS 26 runner: Apple tools, notarized Developer ID daemons and shell
// scripts, with nothing unsigned or in a risky location.
func TestLaunchdTargets_RealRunnerOutput(t *testing.T) {
	r := fixture(t, "macos26-arm64", "persistence.launchd-targets")
	fs := eval(t, r)
	if len(fs) != 2 {
		t.Fatalf("want a script finding and a summary, got %+v", fs)
	}
	if fs[0].Status != output.StatusFail || fs[0].Severity != output.SeverityLow || !strings.Contains(fs[0].Title, "3 launch item(s) run a shell script") {
		t.Errorf("script finding: %+v", fs[0])
	}
	for _, label := range []string{"change-hostname", "ankaupd", "runner-provisioner"} {
		if !strings.Contains(fs[0].Detail, label) {
			t.Errorf("script finding should list %s: %s", label, fs[0].Detail)
		}
	}
	sum := fs[1]
	for _, want := range []string{"4 Apple", "5 Developer ID, notarized", "3 script"} {
		if !strings.Contains(sum.Detail, want) {
			t.Errorf("summary lacks %q: %q", want, sum.Detail)
		}
	}
}
