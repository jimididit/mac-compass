package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
