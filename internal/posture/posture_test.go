package posture

import (
	"strings"
	"testing"

	"github.com/jimididit/mac-compass/internal/findings"
	"github.com/jimididit/mac-compass/internal/output"
)

func f(check string, st output.Status) output.Finding {
	return output.Finding{ID: check, CheckID: check, Status: st, Remediation: "do " + check}
}

func status(p output.Posture, id string) string {
	for _, c := range p.Controls {
		if c.ID == id {
			return c.Status
		}
	}
	return "missing"
}

func TestScoreIsWeighted(t *testing.T) {
	// SIP (weight 3) passes, firewall (weight 2) fails: 3 of 5.
	p := Assess([]output.Finding{f("triage.sip", output.StatusPass), f("network.firewall", output.StatusFail)}, nil)
	if p.Score != 60 || p.Passed != 1 || p.Failed != 1 {
		t.Errorf("want 60 with 1 pass and 1 fail, got %+v", p)
	}
	if status(p, "network.firewall") != StatusFail || status(p, "triage.gatekeeper") != StatusNotAssessed {
		t.Errorf("wrong statuses: %+v", p.Controls)
	}
}

func TestUnassessedControlsDoNotCount(t *testing.T) {
	p := Assess([]output.Finding{f("triage.sip", output.StatusInfo), f("triage.gatekeeper", output.StatusError)}, nil)
	if p.Passed+p.Failed != 0 || p.Score != 0 || p.NotAssessed != len(Controls) {
		t.Errorf("nothing assessed expected: %+v", p)
	}
}

func TestAcceptedFailureIsNotScored(t *testing.T) {
	acc := output.Suppressed{Finding: f("network.firewall", output.StatusFail), Reason: "managed elsewhere"}
	p := Assess([]output.Finding{f("triage.sip", output.StatusPass)}, []output.Suppressed{acc})
	if status(p, "network.firewall") != StatusAccepted || p.Accepted != 1 || p.Score != 100 {
		t.Errorf("an accepted failure must leave the score alone: %+v", p)
	}
}

func TestAnyFailureFailsTheControl(t *testing.T) {
	p := Assess([]output.Finding{f("network.listening-tcp", output.StatusFail), f("network.listening-tcp", output.StatusInfo)}, nil)
	if status(p, "network.listening-tcp") != StatusFail {
		t.Errorf("one failing finding fails the control: %+v", p.Controls)
	}
}

func TestFailureCarriesRemediation(t *testing.T) {
	bare := output.Finding{CheckID: "triage.gatekeeper", Status: output.StatusFail}
	p := Assess([]output.Finding{bare}, nil)
	for _, c := range p.Controls {
		if c.ID == "triage.gatekeeper" && c.Remediation == "" {
			t.Error("a failing control should always say how to fix it")
		}
	}
}

// Every control must read a finding that an evaluator really produces, or it could never be assessed.
func TestControlsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Controls {
		if seen[c.ID] {
			t.Errorf("duplicate control %s", c.ID)
		}
		seen[c.ID] = true
		if !findings.HasEvaluator(c.ID) {
			t.Errorf("%s has no findings evaluator, so it could never be assessed", c.ID)
		}
		if c.Weight < 1 || c.Weight > 3 {
			t.Errorf("%s: weight %d outside 1-3", c.ID, c.Weight)
		}
		if c.MSCP != "" && strings.ContainsAny(c.MSCP, " -ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			t.Errorf("%s: mSCP rule id %q should be lowercase with underscores", c.ID, c.MSCP)
		}
	}
}
