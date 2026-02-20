package catalog

import (
	"testing"
)

func TestLoad(t *testing.T) {
	cat, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cat == nil {
		t.Fatal("Load() returned nil catalog")
	}
	if len(cat.Checks) == 0 {
		t.Fatal("Load() returned catalog with no checks")
	}
}

func TestBySection(t *testing.T) {
	cat, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	triage := cat.BySection("triage")
	if len(triage) == 0 {
		t.Error("BySection(\"triage\") returned no checks; expected at least one")
	}
	for _, ch := range triage {
		if ch.Section != "triage" {
			t.Errorf("BySection(\"triage\") returned check with section %q", ch.Section)
		}
		if ch.Name == "" {
			t.Error("check has empty name")
		}
	}

	empty := cat.BySection("nonexistent-section-id")
	if len(empty) != 0 {
		t.Errorf("BySection(\"nonexistent-section-id\") returned %d checks; expected 0", len(empty))
	}
}

func TestSections(t *testing.T) {
	cat, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	sections := cat.Sections()
	if len(sections) == 0 {
		t.Fatal("Sections() returned empty slice")
	}

	seen := make(map[string]bool)
	for _, s := range sections {
		if seen[s] {
			t.Errorf("Sections() returned duplicate %q", s)
		}
		seen[s] = true
	}

	// First section in catalog is triage
	if sections[0] != "triage" {
		t.Errorf("Sections()[0] = %q; expected \"triage\"", sections[0])
	}

	// Known sections from checks.yaml
	wantSections := map[string]bool{
		"triage": true, "processes": true, "kernel": true, "persistence": true,
		"network": true, "security-tools": true, "advanced": true, "harden": true,
	}
	for _, s := range sections {
		if !wantSections[s] {
			t.Logf("Sections() includes %q (may be valid)", s)
		}
	}
}
