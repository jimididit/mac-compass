package suppress

import (
	"strings"
	"testing"
	"time"

	"github.com/jimididit/mac-compass/internal/output"
)

var day = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func fail(id, title, detail string) output.Finding {
	return output.Finding{ID: id, CheckID: id, Status: output.StatusFail, Severity: output.SeverityMedium, Title: title, Detail: detail}
}

func rules(t *testing.T, y string) []Rule {
	t.Helper()
	r, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestWholeCheckSuppression(t *testing.T) {
	r := rules(t, "suppressions:\n  - {id: network.firewall, reason: 'managed by MDM'}\n")
	res := Apply(r, []output.Finding{fail("network.firewall", "Firewall off", ""), fail("triage.sip", "SIP off", "")}, day)
	if len(res.Kept) != 1 || res.Kept[0].ID != "triage.sip" {
		t.Errorf("kept: %+v", res.Kept)
	}
	if len(res.Suppressed) != 1 || res.Suppressed[0].Reason != "managed by MDM" || res.Suppressed[0].ID != "network.firewall" {
		t.Errorf("suppressed: %+v", res.Suppressed)
	}
}

func TestMatchSuppressesOnlyReviewedLines(t *testing.T) {
	detail := "Accessibility: /bin/bash\nScreen Recording: /tmp/dropper\nAccessibility: /usr/bin/osascript"
	r := rules(t, "suppressions:\n  - {id: security-tools.tcc-system, match: /bin/bash, reason: 'CI shell, reviewed'}\n")
	res := Apply(r, []output.Finding{fail("security-tools.tcc-system", "3 binaries granted access", detail)}, day)
	if len(res.Kept) != 1 {
		t.Fatalf("finding with unreviewed lines must stay: %+v", res.Kept)
	}
	k := res.Kept[0]
	if strings.Contains(k.Detail, "/bin/bash") || !strings.Contains(k.Detail, "/tmp/dropper") || !strings.Contains(k.Detail, "osascript") {
		t.Errorf("only the reviewed line should go: %q", k.Detail)
	}
	if !strings.Contains(k.Title, "[1 accepted]") {
		t.Errorf("title should say how many were accepted: %q", k.Title)
	}
	if len(res.Suppressed) != 1 || !strings.Contains(res.Suppressed[0].Detail, "/bin/bash") {
		t.Errorf("accepted line must be recorded: %+v", res.Suppressed)
	}
}

func TestMatchAllLinesSuppressesFinding(t *testing.T) {
	r := rules(t, "suppressions:\n  - {id: persistence.hosts, match: dsm12, reason: 'vm hostname'}\n")
	res := Apply(r, []output.Finding{fail("persistence.hosts", "1 custom entry", "192.168.64.15 dsm12-abc.local")}, day)
	if len(res.Kept) != 0 || len(res.Suppressed) != 1 {
		t.Errorf("kept=%+v suppressed=%+v", res.Kept, res.Suppressed)
	}
}

func TestMatchIsCaseInsensitiveAndFindsNothingElse(t *testing.T) {
	r := rules(t, "suppressions:\n  - {id: persistence.hosts, match: NOPE, reason: x}\n")
	f := fail("persistence.hosts", "1 custom entry", "1.2.3.4 evil.test")
	if res := Apply(r, []output.Finding{f}, day); len(res.Kept) != 1 || len(res.Suppressed) != 0 {
		t.Errorf("non-matching rule must change nothing: %+v", res)
	}
	r = rules(t, "suppressions:\n  - {id: persistence.hosts, match: EVIL.TEST, reason: x}\n")
	if res := Apply(r, []output.Finding{f}, day); len(res.Kept) != 0 {
		t.Errorf("match must be case-insensitive: %+v", res)
	}
}

func TestMatchOnTitleWhenNoDetail(t *testing.T) {
	r := rules(t, "suppressions:\n  - {id: kernel.nvram-boot-args, match: preempt, reason: 'runner image'}\n")
	res := Apply(r, []output.Finding{fail("kernel.nvram-boot-args", "Custom NVRAM boot-args set: preempt=10", "")}, day)
	if len(res.Kept) != 0 || len(res.Suppressed) != 1 {
		t.Errorf("%+v", res)
	}
}

func TestExpiredRuleIsIgnoredAndFlagged(t *testing.T) {
	r := rules(t, "suppressions:\n  - {id: network.firewall, reason: 'until audit', expires: 2026-10-08}\n")
	res := Apply(r, []output.Finding{fail("network.firewall", "Firewall off", "")}, day)
	if len(res.Kept) != 1 || len(res.Suppressed) != 0 {
		t.Errorf("expired rule must not suppress: %+v", res)
	}
	if len(res.Notices) != 1 || res.Notices[0].Status != output.StatusInfo || !strings.Contains(res.Notices[0].Title, "expired on 2026-10-08") || !strings.Contains(res.Notices[0].Detail, "until audit") {
		t.Errorf("expiry notice: %+v", res.Notices)
	}
	// The expiry day itself still applies.
	r = rules(t, "suppressions:\n  - {id: network.firewall, reason: x, expires: 2026-10-09}\n")
	if res := Apply(r, []output.Finding{fail("network.firewall", "Firewall off", "")}, day); len(res.Kept) != 0 {
		t.Errorf("rule is valid through its expiry day: %+v", res)
	}
}

func TestParseValidation(t *testing.T) {
	bad := map[string]string{
		"no reason":       "suppressions:\n  - {id: network.firewall}\n",
		"blank reason":    "suppressions:\n  - {id: network.firewall, reason: '  '}\n",
		"bad id":          "suppressions:\n  - {id: Firewall, reason: x}\n",
		"missing id":      "suppressions:\n  - {reason: x}\n",
		"bad date":        "suppressions:\n  - {id: network.firewall, reason: x, expires: tomorrow}\n",
		"unknown key":     "suppressions:\n  - {id: network.firewall, reason: x, why: y}\n",
		"unknown top key": "suppress:\n  - {id: network.firewall, reason: x}\n",
	}
	for name, y := range bad {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if r, err := Parse([]byte("suppressions: []\n")); err != nil || len(r) != 0 {
		t.Errorf("empty list must be valid: %v %v", r, err)
	}
}
