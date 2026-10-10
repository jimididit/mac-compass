package render

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jimididit/mac-compass/internal/output"
)

func sampleReport() output.Report {
	rep := output.Report{
		SchemaVersion: output.SchemaVersion,
		Tool:          output.ToolInfo{Name: "mac-compass", Version: "0.3.0"},
		Host:          output.HostInfo{Hostname: "alices-mbp.local", OS: "darwin", Arch: "arm64", MacOSVersion: "26.6.2", MacOSBuild: "25G83"},
		StartedAt:     time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC),
		SudoEnabled:   true,
		Sections: []output.SectionResult{{Section: "triage", Checks: []output.CheckResult{
			{ID: "triage.sip", Name: "SIP status", Ok: true, DurationMS: 120},
			{ID: "network.firewall", Name: "Firewall", Ok: false, ExitCode: 2, DurationMS: 30},
			{ID: "x.skipped", Name: "Hardware", Skipped: true, SkipReason: "requires hardware (VM mode)"},
		}}},
		Findings: []output.Finding{
			{ID: "triage.sip", CheckID: "triage.sip", Status: output.StatusFail, Severity: output.SeverityHigh, Title: "System Integrity Protection is disabled",
				Detail: "SIP protects system files.", Remediation: "Run csrutil enable", Attack: []string{"T1562.001"}},
			{ID: "network.firewall", CheckID: "network.firewall", Status: output.StatusFail, Severity: output.SeverityMedium, Title: "Application firewall is off"},
			{ID: "persistence.crontab", CheckID: "persistence.crontab", Status: output.StatusFail, Severity: output.SeverityLow, Title: "1 crontab entry"},
			{ID: "triage.launchdaemons", CheckID: "triage.launchdaemons", Status: output.StatusInfo, Title: "3 third-party items"},
			{ID: "kernel.x", CheckID: "kernel.x", Status: output.StatusError, Title: "Check could not run"},
			{ID: "triage.gatekeeper", CheckID: "triage.gatekeeper", Status: output.StatusPass, Title: "Gatekeeper is enabled"},
		},
		Suppressed: []output.Suppressed{{Finding: output.Finding{ID: "network.proxy", Title: "A proxy is configured"}, Reason: "corporate proxy"}},
	}
	rep.Summarize()
	return rep
}

func TestHTML_Posture(t *testing.T) {
	rep := sampleReport()
	b, err := HTML(rep)
	if err != nil || strings.Contains(string(b), "Hardening posture") {
		t.Fatalf("no posture in the report, so no posture section: %v", err)
	}
	rep.Posture = &output.Posture{Score: 60, Passed: 1, Failed: 1, NotAssessed: 1, Controls: []output.PostureControl{
		{ID: "triage.sip", Title: "SIP is on", Status: "pass", MSCP: "os_sip_enable"},
		{ID: "network.firewall", Title: "Firewall is on", Status: "fail", Remediation: "turn it on"},
		{ID: "triage.gatekeeper", Title: "Gatekeeper is on", Status: "not-assessed"},
	}}
	b, err = HTML(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Hardening posture", "60/100", "SIP is on", "os_sip_enable", "Fix: turn it on", "1 not assessed"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

func TestHTML_Content(t *testing.T) {
	b, err := HTML(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	h := string(b)
	for _, want := range []string{
		"<title>mac-compass report</title>", "alices-mbp.local", "macOS 26.6.2 (25G83)", "arm64", "2026-10-09 12:00 UTC",
		"System Integrity Protection is disabled", "Run csrutil enable", `href="https://attack.mitre.org/techniques/T1562/001/"`,
		"Application firewall is off", "For your information", "Checks that could not run",
		"Accepted by your suppressions file", "corporate proxy", "requires hardware (VM mode)",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if strings.Contains(h, "Gatekeeper is enabled") {
		t.Error("passing findings must not be listed")
	}
	if strings.Index(h, "System Integrity Protection is disabled") > strings.Index(h, "Application firewall is off") {
		t.Error("higher severity must come first")
	}
}

func TestHTML_IsSelfContainedAndSafe(t *testing.T) {
	rep := sampleReport()
	rep.Findings = append(rep.Findings, output.Finding{
		ID: "evil.x", CheckID: "evil.x", Status: output.StatusFail, Severity: output.SeverityHigh,
		Title:       `<script>alert("t")</script>`,
		Detail:      `</pre><img src=x onerror=alert(1)>`,
		Remediation: `<b onmouseover=alert(2)>x</b>`,
		Attack:      []string{`T1"><script>alert(3)</script>`},
	})
	rep.Host.Hostname = `<svg onload=alert(4)>`
	b, err := HTML(rep)
	if err != nil {
		t.Fatal(err)
	}
	h := string(b)
	// Hostile text must appear only as escaped characters, never as live tags or attributes.
	for _, bad := range []string{"<script", "<img", "<svg", "<b onmouseover", `"><script`} {
		if strings.Contains(h, bad) {
			t.Errorf("unescaped hostile content %q in output", bad)
		}
	}
	if !strings.Contains(h, "&lt;script&gt;alert(") {
		t.Error("hostile text should be present, escaped, so the finding is still readable")
	}
	if !strings.Contains(h, `Content-Security-Policy`) || !strings.Contains(h, "default-src 'none'") {
		t.Error("the page must forbid scripts and network requests")
	}
	for _, ext := range []string{"<link", "<iframe", "<object", "<embed", "@import", "url("} {
		if strings.Contains(h, ext) {
			t.Errorf("page must not load external resources: found %q", ext)
		}
	}
}

func TestHTML_EmptyReport(t *testing.T) {
	b, err := HTML(output.Report{})
	if err != nil || !strings.Contains(string(b), "No findings.") {
		t.Errorf("empty report: %v", err)
	}
}

func TestSARIF_Structure(t *testing.T) {
	b, err := SARIF(sampleReport())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID         string         `json:"id"`
						Properties map[string]any `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string                `json:"ruleId"`
				Level     string                `json:"level"`
				Kind      string                `json:"kind"`
				Message   struct{ Text string } `json:"message"`
				Locations []struct {
					LogicalLocations []struct{ Name string } `json:"logicalLocations"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if doc.Version != "2.1.0" || !strings.Contains(doc.Schema, "sarif-2.1.0") || len(doc.Runs) != 1 {
		t.Fatalf("header: %+v", doc)
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "mac-compass" {
		t.Errorf("driver: %+v", run.Tool.Driver)
	}
	if len(run.Results) != 5 {
		t.Fatalf("want 5 results (pass omitted), got %d", len(run.Results))
	}
	rules := map[string]bool{}
	for _, r := range run.Tool.Driver.Rules {
		if rules[r.ID] {
			t.Errorf("duplicate rule %s", r.ID)
		}
		rules[r.ID] = true
	}
	levels := map[string]string{}
	for _, r := range run.Results {
		if !rules[r.RuleID] {
			t.Errorf("result for undeclared rule %s", r.RuleID)
		}
		if len(r.Locations) != 1 || r.Locations[0].LogicalLocations[0].Name != "alices-mbp.local" {
			t.Errorf("location: %+v", r.Locations)
		}
		if len(r.PartialFingerprints["macCompass/v1"]) != 32 {
			t.Errorf("fingerprint: %+v", r.PartialFingerprints)
		}
		levels[r.RuleID] = r.Level + "/" + r.Kind
	}
	want := map[string]string{
		"triage.sip": "error/fail", "network.firewall": "warning/fail", "persistence.crontab": "note/fail",
		"triage.launchdaemons": "note/informational", "kernel.x": "warning/fail",
	}
	for id, w := range want {
		if levels[id] != w {
			t.Errorf("%s = %s; want %s", id, levels[id], w)
		}
	}
	if !strings.Contains(string(b), "external/mitre-attack/t1562.001") {
		t.Error("ATT&CK id must be carried as a tag")
	}
	var msg string
	for _, r := range run.Results {
		if r.RuleID == "triage.sip" {
			msg = r.Message.Text
		}
	}
	if !strings.Contains(msg, "SIP protects system files.") || !strings.Contains(msg, "Fix: Run csrutil enable") {
		t.Errorf("message: %q", msg)
	}
}

func TestSARIF_FingerprintIsStableAndIgnoresDetail(t *testing.T) {
	a := output.Finding{ID: "x.y", CheckID: "x.y", Title: "T", Detail: "one"}
	b := a
	b.Detail = "two"
	if fingerprint(a) != fingerprint(b) {
		t.Error("detail must not change the fingerprint")
	}
	c := a
	c.Title = "other"
	if fingerprint(a) == fingerprint(c) {
		t.Error("a different finding must have a different fingerprint")
	}
}

func TestSARIF_NoFindings(t *testing.T) {
	b, err := SARIF(output.Report{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"results": []`) {
		t.Errorf("an empty run must still list results as []: %s", b)
	}
}
