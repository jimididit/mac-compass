//go:build darwin

package catalog

import (
	"os"
	"testing"
)

// Every absolute command path in the catalog must exist on the macOS running the test.
func TestCatalogCommandsExistOnMac(t *testing.T) {
	cat, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range cat.Checks {
		if ch.Command == "" || ch.RequiresHardware {
			continue
		}
		if _, err := os.Stat(ch.Command); err != nil {
			t.Errorf("%s/%s: %v", ch.Section, ch.Name, err)
		}
	}
}
