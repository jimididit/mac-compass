package findings

import (
	"strings"
	"testing"

	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/runner"
)

func procRows(lines ...string) string {
	return runner.ProcessHeader + "\n" + strings.Join(lines, "\n") + "\n"
}

func TestProcessSignatures_Healthy(t *testing.T) {
	data := procRows(
		"root\t/sbin/launchd\t1\tapple\t-\t-\tapple\t-",
		"me\t/Applications/Foo.app/Contents/MacOS/Foo\t3\tdeveloper-id\tABCDE12345\tDeveloper ID Application: Foo\tnotarized\t-",
		"me\t/Users/me/go/bin/tool\t1\tadhoc\t-\t-\t-\t-",
	)
	f := one(t, eval(t, res("processes.signatures", data)))
	if f.Status != output.StatusInfo || !strings.Contains(f.Title, "3 distinct running program(s)") ||
		!strings.Contains(f.Detail, "1 Apple") || !strings.Contains(f.Detail, "1 adhoc") {
		t.Errorf("a healthy machine (ad-hoc dev tools included) produces only a summary: %+v", f)
	}
}

func TestProcessSignatures_Risky(t *testing.T) {
	data := procRows(
		"root\t/sbin/launchd\t1\tapple\t-\t-\tapple\t-",
		"me\t/tmp/.evil\t1\tunsigned\t-\t-\t-\ttemp-location,hidden-location",
		"root\t/Users/me/tool\t2\tadhoc\t-\t-\t-\troot-from-user-dir",
		"me\t/opt/deleted/app\t1\tmissing\t-\t-\t-\t-",
		"me\t/opt/vendor/agent\t1\tunsigned\t-\t-\t-\t-",
	)
	fs := eval(t, res("processes.signatures", data))
	if fs[0].Severity != output.SeverityHigh || !strings.Contains(fs[0].Detail, "/tmp/.evil") {
		t.Fatalf("risky location must sort first: %+v", fs)
	}
	var titles []string
	for _, f := range fs {
		titles = append(titles, f.Title)
		if f.Status == output.StatusFail && f.Remediation == "" {
			t.Errorf("failing finding needs a remediation: %+v", f)
		}
	}
	all := strings.Join(titles, " | ")
	for _, want := range []string{"started from a temporary or hidden location", "run as root from a user's home folder", "no longer exist on disk", "are unsigned"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing finding %q in: %s", want, all)
		}
	}
	for _, f := range fs {
		if strings.Contains(f.Title, "are unsigned") && strings.Contains(f.Detail, "/tmp/.evil") {
			t.Error("a program already reported for its location must not repeat as unsigned")
		}
	}
}

func TestProcessSignatures_Empty(t *testing.T) {
	if f := one(t, eval(t, res("processes.signatures", runner.ProcessHeader+"\n"))); f.Status != output.StatusInfo {
		t.Errorf("%+v", f)
	}
}
