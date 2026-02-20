package output

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	sections := []SectionResult{
		{
			Section: "triage",
			Checks: []CheckResult{
				{Section: "triage", Name: "SIP status", Ok: true, Stdout: "enabled"},
				{Section: "triage", Name: "Gatekeeper", Ok: false, Error: "exit status 1"},
			},
		},
	}
	var buf bytes.Buffer
	err := WriteJSON(&buf, sections)
	if err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("WriteJSON wrote nothing")
	}
	// Round-trip
	var decoded []SectionResult
	if err := json.NewDecoder(&buf).Decode(&decoded); err != nil {
		t.Fatalf("decode written JSON: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded %d sections; want 1", len(decoded))
	}
	if decoded[0].Section != "triage" {
		t.Errorf("section = %q; want \"triage\"", decoded[0].Section)
	}
	if len(decoded[0].Checks) != 2 {
		t.Fatalf("decoded %d checks; want 2", len(decoded[0].Checks))
	}
	if decoded[0].Checks[0].Name != "SIP status" || !decoded[0].Checks[0].Ok {
		t.Errorf("first check: name=%q ok=%v", decoded[0].Checks[0].Name, decoded[0].Checks[0].Ok)
	}
	if decoded[0].Checks[1].Name != "Gatekeeper" || decoded[0].Checks[1].Ok {
		t.Errorf("second check: name=%q ok=%v", decoded[0].Checks[1].Name, decoded[0].Checks[1].Ok)
	}
}

func TestWriteJSON_Empty(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, nil)
	if err != nil {
		t.Fatalf("WriteJSON(nil): %v", err)
	}
	var decoded []SectionResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded != nil {
		t.Errorf("decoded nil input as %v", decoded)
	}
}
