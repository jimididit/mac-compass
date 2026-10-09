package redact

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jimididit/mac-compass/internal/baseline"
	"github.com/jimididit/mac-compass/internal/output"
)

func TestString(t *testing.T) {
	r := New("alices-mbp.local", "alice")
	cases := map[string]string{
		"/Users/alice/Library/LaunchAgents": "/Users/[user]/Library/LaunchAgents",
		"host alices-mbp.local up":          "host [host] up",
		"short alices-mbp only":             "short [host] only",
		"alicesmith is another user":        "alicesmith is another user", // word boundary
		"no identifiers here":               "no identifiers here",
	}
	for in, want := range cases {
		if got := r.String(in); got != want {
			t.Errorf("String(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestNew_IgnoresGenericNames(t *testing.T) {
	r := New("a", "root")
	if got := r.String("a root a"); got != "a root a" {
		t.Errorf("generic names must not be masked: %q", got)
	}
	var zero Redactor
	if zero.String("x") != "x" {
		t.Error("zero value redacts nothing")
	}
	if New("", "runner").String("runner") != "runner" {
		t.Error("the CI account name is not a person")
	}
}

func TestReportAndSnapshot(t *testing.T) {
	r := New("box.local", "alice")
	rep := output.Report{
		Host:     output.HostInfo{Hostname: "box.local"},
		Sections: []output.SectionResult{{Checks: []output.CheckResult{{Stdout: "/Users/alice/.zshrc", Stderr: "box.local", Error: "alice failed"}}}},
		Findings: []output.Finding{{Title: "alice's agent", Detail: "/Users/alice/x", Remediation: "ask alice"}},
	}
	r.Report(&rep)
	blob := rep.Host.Hostname + rep.Sections[0].Checks[0].Stdout + rep.Sections[0].Checks[0].Stderr + rep.Sections[0].Checks[0].Error +
		rep.Findings[0].Title + rep.Findings[0].Detail + rep.Findings[0].Remediation
	if strings.Contains(blob, "alice") || strings.Contains(blob, "box.local") {
		t.Errorf("report still identifies the user or host: %s", blob)
	}

	s := baseline.FromSections(output.ToolInfo{}, output.HostInfo{Hostname: "box.local"}, true, time.Unix(0, 0), []output.SectionResult{{Checks: []output.CheckResult{
		{ID: "persistence.shell-rc", Ok: true, Stdout: "abc  /Users/alice/.zshrc\n"},
	}}})
	r.Snapshot(&s)
	if s.Host.Hostname != "[host]" || s.Checks["persistence.shell-rc"].Items[0] != "abc  /Users/[user]/.zshrc" {
		t.Errorf("snapshot not redacted: %+v", s)
	}
}

func TestLineWriter_SplitAcrossWrites(t *testing.T) {
	var out bytes.Buffer
	w := New("box.local", "alice").Writer(&out)
	for _, chunk := range []string{"/Users/al", "ice/x\nhost box", ".local\ntail ali", "ce"} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	want := "/Users/[user]/x\nhost [host]\ntail [user]"
	if out.String() != want {
		t.Errorf("got %q; want %q", out.String(), want)
	}
}
