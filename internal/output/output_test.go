package output

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSeverityRank(t *testing.T) {
	order := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if order[i].Rank() <= order[i-1].Rank() {
			t.Errorf("%s should outrank %s", order[i], order[i-1])
		}
	}
	if Severity("bogus").Rank() != 0 {
		t.Error("unknown severity must rank 0")
	}
}

func TestSummarize(t *testing.T) {
	r := Report{
		Sections: []SectionResult{{Section: "triage", Checks: []CheckResult{
			{Ok: true}, {Skipped: true}, {Ok: false, Error: "boom"},
		}}},
		Findings: []Finding{
			{Status: StatusPass}, {Status: StatusInfo}, {Status: StatusError},
			{Status: StatusFail, Severity: SeverityLow},
			{Status: StatusFail, Severity: SeverityHigh},
			{Status: StatusFail, Severity: SeverityHigh},
		},
	}
	r.Summarize()
	s := r.Summary
	if s.ChecksOK != 1 || s.ChecksSkipped != 1 || s.ChecksFailed != 1 {
		t.Errorf("check counts wrong: %+v", s)
	}
	if s.Pass != 1 || s.Info != 1 || s.Error != 1 || s.Fail != 3 {
		t.Errorf("finding counts wrong: %+v", s)
	}
	if s.FailBySeverity[SeverityHigh] != 2 || s.FailBySeverity[SeverityLow] != 1 || s.HighestSeverity != SeverityHigh {
		t.Errorf("severity summary wrong: %+v", s)
	}
}

func TestWriteJSON_RoundTrip(t *testing.T) {
	r := Report{
		SchemaVersion: SchemaVersion,
		Tool:          ToolInfo{Name: "mac-compass", Version: "test"},
		Host:          HostInfo{OS: "darwin", Arch: "arm64", MacOSVersion: "26.6.2"},
		Sections: []SectionResult{{Section: "triage", Checks: []CheckResult{
			{ID: "triage.sip", Section: "triage", Name: "SIP status", Ok: true, Stdout: "enabled"},
		}}},
		Findings: []Finding{{ID: "triage.sip", CheckID: "triage.sip", Status: StatusPass, Title: "SIP enabled"}},
	}
	r.Summarize()
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	var got Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SchemaVersion != SchemaVersion || got.Host.MacOSVersion != "26.6.2" ||
		len(got.Sections) != 1 || got.Sections[0].Checks[0].ID != "triage.sip" ||
		len(got.Findings) != 1 || got.Summary.Pass != 1 {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestWriteJSON_EmptyListsAreArrays(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, Report{}); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte(`"findings": []`)) || !bytes.Contains(buf.Bytes(), []byte(`"sections": []`)) {
		t.Errorf("empty lists must serialize as [], got: %s", s)
	}
}
