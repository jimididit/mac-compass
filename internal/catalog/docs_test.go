package catalog

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// docs/checks.md is the user-facing reference; it must list every check in the catalog.
func TestChecksDocListsEveryCheck(t *testing.T) {
	cat, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "checks.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.ReplaceAll(string(b), "\r\n", "\n")
	for _, ch := range cat.Checks {
		if !strings.Contains(doc, "`"+ch.ID+"`") {
			t.Errorf("docs/checks.md is missing %s; add a row", ch.ID)
		}
	}
	if n := strings.Count(doc, "\n| `"); n != len(cat.Checks) {
		t.Errorf("docs/checks.md lists %d checks; catalog has %d", n, len(cat.Checks))
	}
}

// The README states how many checks there are; keep it honest.
func TestReadmeCheckCount(t *testing.T) {
	cat, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), strconv.Itoa(len(cat.Checks))+" read-only checks") {
		t.Errorf("README.md should say %d read-only checks", len(cat.Checks))
	}
}
