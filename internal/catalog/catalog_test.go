package catalog

import (
	"strings"
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

func TestParse_RejectsUnknownKeys(t *testing.T) {
	_, err := Parse([]byte("checks:\n  - section: triage\n    name: x\n    command: /bin/true\n    sudoo: true\n"))
	if err == nil {
		t.Fatal("typo'd key should be rejected")
	}
}

func TestValidate_Problems(t *testing.T) {
	cases := map[string]string{
		"no command":     "checks:\n  - {section: triage, name: a}\n",
		"both":           "checks:\n  - {section: triage, name: a, command: /bin/true, script: 'true'}\n",
		"bad section":    "checks:\n  - {section: nope, name: a, command: /bin/true}\n",
		"empty name":     "checks:\n  - {section: triage, command: /bin/true}\n",
		"duplicate":      "checks:\n  - {section: triage, name: a, command: /bin/true}\n  - {section: triage, name: a, command: /bin/true}\n",
		"args on script": "checks:\n  - {section: triage, name: a, script: 'true', args: [x]}\n",
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestEmbeddedCatalog_ReadOnlyAndAbsolute(t *testing.T) {
	cat, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range cat.Checks {
		if ch.Command != "" && !strings.HasPrefix(ch.Command, "/") {
			t.Errorf("%s/%s: command %q must be an absolute path", ch.Section, ch.Name, ch.Command)
		}
		if ch.Command == "/usr/sbin/kextcache" || ch.Command == "kextcache" {
			t.Errorf("%s/%s: kextcache rewrites caches; not a read-only check", ch.Section, ch.Name)
		}
	}
}

func TestExitOK(t *testing.T) {
	ch := Check{OKExit: []int{1}}
	if !ch.ExitOK(0) || !ch.ExitOK(1) || ch.ExitOK(2) {
		t.Error("ExitOK mismatch")
	}
}

func TestEmbeddedCatalog_NoDuplicateCommands(t *testing.T) {
	cat, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, ch := range cat.Checks {
		sig := ch.Command + " " + strings.Join(ch.Args, " ") + "|" + ch.Script
		if prev, dup := seen[sig]; dup {
			t.Errorf("%s/%s duplicates %s", ch.Section, ch.Name, prev)
		}
		seen[sig] = ch.Section + "/" + ch.Name
	}
}

func TestEmbeddedCatalog_NoDeprecatedTools(t *testing.T) {
	cat, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range cat.Checks {
		all := ch.Command + " " + ch.Script
		for _, bad := range []string{"kextstat", "kextcache", "repair_packages"} {
			if strings.Contains(all, bad) {
				t.Errorf("%s/%s uses deprecated/mutating %s", ch.Section, ch.Name, bad)
			}
		}
	}
}

func TestParse_BadArch(t *testing.T) {
	if _, err := Parse([]byte("checks:\n  - {section: triage, name: a, command: /bin/true, arch: ppc}\n")); err == nil {
		t.Fatal("bad arch should be rejected")
	}
}

func TestAppliesTo(t *testing.T) {
	ch := Check{MacOSMin: 12, MacOSMax: 26}
	for v, want := range map[int]bool{0: true, 11: false, 12: true, 26: true, 27: false} {
		if got := ch.AppliesTo(v); got != want {
			t.Errorf("AppliesTo(%d) = %v; want %v", v, got, want)
		}
	}
	if !(Check{}).AppliesTo(27) {
		t.Error("unbounded check must apply to every version")
	}
}

func TestParse_BadMacOSRange(t *testing.T) {
	if _, err := Parse([]byte("checks:\n  - {section: triage, name: a, command: /bin/true, macos_min: 15, macos_max: 12}\n")); err == nil {
		t.Fatal("min > max should be rejected")
	}
}
