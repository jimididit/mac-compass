package catalog

import (
	"embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed checks.yaml
var catalogFS embed.FS

// Check represents a single runnable check.
type Check struct {
	Section          string   `yaml:"section"`
	Name             string   `yaml:"name"`
	Description      string   `yaml:"description"`
	Command          string   `yaml:"command"`
	Args             []string `yaml:"args"`
	Script           string   `yaml:"script"` // If set, run with sh -c (for pipes etc.)
	Sudo             bool     `yaml:"sudo"`
	VMSafe           bool     `yaml:"vm_safe"`           // Safe to run in VM
	RequiresHardware bool     `yaml:"requires_hardware"` // T2/Secure Enclave etc.
}

// Catalog is the in-memory check catalog.
type Catalog struct {
	Checks []Check `yaml:"checks"`
}

// Load reads and parses the embedded checks.yaml.
func Load() (*Catalog, error) {
	data, err := catalogFS.ReadFile("checks.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	var c Catalog
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}
	return &c, nil
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
