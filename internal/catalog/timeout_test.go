package catalog

import (
	"testing"
	"time"
)

func TestTimeoutField(t *testing.T) {
	if _, err := Parse([]byte("checks:\n  - {id: triage.a, section: triage, name: a, command: /bin/true, timeout: 15s}\n")); err != nil {
		t.Errorf("valid timeout rejected: %v", err)
	}
	if _, err := Parse([]byte("checks:\n  - {id: triage.a, section: triage, name: a, command: /bin/true, timeout: -5s}\n")); err == nil {
		t.Error("negative timeout must be rejected")
	}
	cat, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range cat.Checks {
		if ch.ID == "persistence.login-items" && (ch.Timeout <= 0 || ch.Timeout > 30*time.Second) {
			t.Errorf("login-items must be capped well below the default: %v", ch.Timeout)
		}
	}
}
