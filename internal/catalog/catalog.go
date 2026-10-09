package catalog

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed checks.yaml
var catalogFS embed.FS

var idRe = regexp.MustCompile(`^[a-z0-9-]+\.[a-z0-9-]+$`)

// KnownSections lists the section ids a check may use.
var KnownSections = []string{
	"triage", "processes", "kernel", "persistence",
	"network", "security-tools", "advanced", "harden",
}

// Check represents a single runnable check.
type Check struct {
	ID               string   `yaml:"id"` // stable dotted id, e.g. "triage.sip"
	Section          string   `yaml:"section"`
	Name             string   `yaml:"name"`
	Description      string   `yaml:"description"`
	Command          string   `yaml:"command"`
	Args             []string `yaml:"args"`
	Script           string   `yaml:"script"` // If set, run with sh -c (for pipes etc.)
	Sudo             bool     `yaml:"sudo"`
	VMSafe           bool     `yaml:"vm_safe"`           // Safe to run in VM
	RequiresHardware bool     `yaml:"requires_hardware"` // T2/Secure Enclave etc.
	// Arch limits the check to one CPU architecture: "x86_64" or "arm64". Empty means any.
	Arch string `yaml:"arch"`
	// MacOSMin/MacOSMax bound the macOS major version (11, 12, ... 26, 27) the check
	// applies to; 0 means unbounded. Outside the range the check is skipped.
	MacOSMin int `yaml:"macos_min"`
	MacOSMax int `yaml:"macos_max"`
	// Optional marks a check whose binary may be absent on some macOS versions;
	// a missing binary is reported as skipped, not failed.
	Optional bool `yaml:"optional"`
	// OKExit lists exit codes (besides 0) that mean the check ran fine, e.g. 1 for
	// "grep found nothing" or "crontab: no crontab for user".
	OKExit []int `yaml:"ok_exit"`
}

// AppliesTo reports whether the check applies to macOS major version v.
// An unknown version (0) applies to everything, so detection failure never hides checks.
func (c Check) AppliesTo(v int) bool {
	if v == 0 {
		return true
	}
	return v >= c.MacOSMin && (c.MacOSMax == 0 || v <= c.MacOSMax)
}

// ExitOK reports whether code is an acceptable exit status for the check.
func (c Check) ExitOK(code int) bool {
	if code == 0 {
		return true
	}
	for _, ok := range c.OKExit {
		if ok == code {
			return true
		}
	}
	return false
}

// Catalog is the in-memory check catalog.
type Catalog struct {
	Checks []Check `yaml:"checks"`
}

// Load reads, parses and validates the embedded checks.yaml.
func Load() (*Catalog, error) {
	data, err := catalogFS.ReadFile("checks.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	return Parse(data)
}

// Parse decodes catalog YAML strictly (unknown keys are errors) and validates it.
func Parse(data []byte) (*Catalog, error) {
	var c Catalog
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid catalog: %w", err)
	}
	return &c, nil
}

// Validate checks every entry for structural problems.
func (c *Catalog) Validate() error {
	known := make(map[string]bool, len(KnownSections))
	for _, s := range KnownSections {
		known[s] = true
	}
	seen := make(map[string]bool)
	ids := make(map[string]bool)
	var errs []error
	for i, ch := range c.Checks {
		where := fmt.Sprintf("check #%d (%q)", i+1, ch.Name)
		switch {
		case strings.TrimSpace(ch.Name) == "":
			errs = append(errs, fmt.Errorf("check #%d: empty name", i+1))
			continue
		case !known[ch.Section]:
			errs = append(errs, fmt.Errorf("%s: unknown section %q", where, ch.Section))
		}
		if (ch.Command == "") == (ch.Script == "") {
			errs = append(errs, fmt.Errorf("%s: exactly one of command or script is required", where))
		}
		if ch.Arch != "" && ch.Arch != "x86_64" && ch.Arch != "arm64" {
			errs = append(errs, fmt.Errorf("%s: arch must be x86_64 or arm64, got %q", where, ch.Arch))
		}
		if ch.MacOSMin < 0 || ch.MacOSMax < 0 || (ch.MacOSMax != 0 && ch.MacOSMin > ch.MacOSMax) {
			errs = append(errs, fmt.Errorf("%s: invalid macos_min/macos_max (%d, %d)", where, ch.MacOSMin, ch.MacOSMax))
		}
		if ch.Script != "" && len(ch.Args) > 0 {
			errs = append(errs, fmt.Errorf("%s: args set together with script", where))
		}
		if !idRe.MatchString(ch.ID) {
			errs = append(errs, fmt.Errorf("%s: id %q must look like section.slug (lowercase, digits, dashes)", where, ch.ID))
		} else if ids[ch.ID] {
			errs = append(errs, fmt.Errorf("%s: duplicate id %q", where, ch.ID))
		}
		ids[ch.ID] = true
		key := ch.Section + "/" + ch.Name
		if seen[key] {
			errs = append(errs, fmt.Errorf("%s: duplicate name in section %q", where, ch.Section))
		}
		seen[key] = true
	}
	return errors.Join(errs...)
}

// BySection returns checks for the given section id (e.g. "triage", "processes").
func (c *Catalog) BySection(section string) []Check {
	var out []Check
	for _, ch := range c.Checks {
		if ch.Section == section {
			out = append(out, ch)
		}
	}
	return out
}

// Sections returns unique section IDs in order of first appearance.
func (c *Catalog) Sections() []string {
	seen := make(map[string]bool)
	var order []string
	for _, ch := range c.Checks {
		if !seen[ch.Section] {
			seen[ch.Section] = true
			order = append(order, ch.Section)
		}
	}
	return order
}
