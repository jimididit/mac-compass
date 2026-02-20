package output

import (
	"encoding/json"
	"io"
)

// CheckResult is the result of running a single check.
type CheckResult struct {
	Section string `json:"section"`
	Name    string `json:"name"`
	Ok      bool   `json:"ok"`
	Stdout  string `json:"stdout,omitempty"`
	Stderr  string `json:"stderr,omitempty"`
	Error   string `json:"error,omitempty"`
}

// SectionResult holds all check results for a section.
type SectionResult struct {
	Section string        `json:"section"`
	Checks  []CheckResult `json:"checks"`
}

// WriteJSON writes section results as JSON to w.
func WriteJSON(w io.Writer, sections []SectionResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sections)
}
