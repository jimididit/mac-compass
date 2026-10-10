package output

import (
	"encoding/json"
	"io"
	"time"
)

// SchemaVersion is bumped when the JSON report layout changes incompatibly.
const SchemaVersion = 1

// Severity ranks a failed finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Rank orders severities; unknown values rank below info.
func (s Severity) Rank() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	}
	return 0
}

// Status is the outcome of a finding.
type Status string

const (
	StatusPass  Status = "pass"  // check ran and the setting is as expected
	StatusFail  Status = "fail"  // check ran and found something worth attention (see Severity)
	StatusInfo  Status = "info"  // informational, no judgement
	StatusError Status = "error" // check could not run, so nothing can be concluded
)

// Finding is an interpreted result derived from one check's output.
type Finding struct {
	ID          string   `json:"id"`       // e.g. "triage.sip"
	CheckID     string   `json:"check_id"` // catalog check that produced it
	Status      Status   `json:"status"`
	Severity    Severity `json:"severity,omitempty"` // only for StatusFail
	Title       string   `json:"title"`
	Detail      string   `json:"detail,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Attack      []string `json:"attack,omitempty"` // MITRE ATT&CK technique ids
}

// CheckResult is the result of running a single check.
type CheckResult struct {
	ID         string   `json:"id"`
	Section    string   `json:"section"`
	Name       string   `json:"name"`
	Attack     []string `json:"attack,omitempty"`
	Ok         bool     `json:"ok"`
	Skipped    bool     `json:"skipped,omitempty"`
	SkipReason string   `json:"skip_reason,omitempty"`
	ExitCode   int      `json:"exit_code"`
	DurationMS int64    `json:"duration_ms"`
	Stdout     string   `json:"stdout,omitempty"`
	Stderr     string   `json:"stderr,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// SectionResult holds all check results for a section.
type SectionResult struct {
	Section string        `json:"section"`
	Checks  []CheckResult `json:"checks"`
}

// ToolInfo identifies the build that produced a report.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// HostInfo describes the machine that was examined.
type HostInfo struct {
	Hostname     string `json:"hostname,omitempty"`
	OS           string `json:"os"`
	MacOSVersion string `json:"macos_version,omitempty"`
	MacOSBuild   string `json:"macos_build,omitempty"`
	Arch         string `json:"arch"`
}

// Suppressed is a finding the user accepted in a suppressions file, with the reason they gave.
type Suppressed struct {
	Finding
	Reason string `json:"reason"`
}

// Summary counts findings by outcome.
type Summary struct {
	Pass            int              `json:"pass"`
	Info            int              `json:"info"`
	Error           int              `json:"error"`
	FailBySeverity  map[Severity]int `json:"fail_by_severity"`
	Fail            int              `json:"fail"`
	HighestSeverity Severity         `json:"highest_severity,omitempty"`
	ChecksOK        int              `json:"checks_ok"`
	ChecksSkipped   int              `json:"checks_skipped"`
	ChecksFailed    int              `json:"checks_failed"`
	Suppressed      int              `json:"suppressed"`
}

// Report is the complete JSON document for a run.
type Report struct {
	SchemaVersion int             `json:"schema_version"`
	Tool          ToolInfo        `json:"tool"`
	Host          HostInfo        `json:"host"`
	StartedAt     time.Time       `json:"started_at"`
	DurationMS    int64           `json:"duration_ms"`
	SudoEnabled   bool            `json:"sudo_enabled"`
	VMMode        bool            `json:"vm_mode"`
	Sections      []SectionResult `json:"sections"`
	Findings      []Finding       `json:"findings"`
	Suppressed    []Suppressed    `json:"suppressed,omitempty"`
	Posture       *Posture        `json:"posture,omitempty"`
	Summary       Summary         `json:"summary"`
}

// Posture scores the Mac against a set of hardening controls. Only controls that could be assessed count.
type Posture struct {
	Score       int              `json:"score"` // 0-100, weighted share of assessed controls that pass
	Passed      int              `json:"passed"`
	Failed      int              `json:"failed"`
	Accepted    int              `json:"accepted"`     // failing controls accepted in the suppressions file; not scored
	NotAssessed int              `json:"not_assessed"` // check skipped, errored, or output not recognised
	Controls    []PostureControl `json:"controls"`
}

// PostureControl is one hardening control and how this Mac fares against it.
type PostureControl struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Status      string `json:"status"` // pass, fail, accepted, not-assessed
	Weight      int    `json:"weight"`
	MSCP        string `json:"mscp,omitempty"` // macOS Security Compliance Project rule id
	Remediation string `json:"remediation,omitempty"`
}

// Summarize fills Summary from sections and findings.
func (r *Report) Summarize() {
	s := Summary{FailBySeverity: map[Severity]int{}}
	for _, sec := range r.Sections {
		for _, c := range sec.Checks {
			switch {
			case c.Skipped:
				s.ChecksSkipped++
			case c.Ok:
				s.ChecksOK++
			default:
				s.ChecksFailed++
			}
		}
	}
	for _, f := range r.Findings {
		switch f.Status {
		case StatusPass:
			s.Pass++
		case StatusInfo:
			s.Info++
		case StatusError:
			s.Error++
		case StatusFail:
			s.Fail++
			s.FailBySeverity[f.Severity]++
			if f.Severity.Rank() > s.HighestSeverity.Rank() {
				s.HighestSeverity = f.Severity
			}
		}
	}
	s.Suppressed = len(r.Suppressed)
	r.Summary = s
}

// WriteJSON writes the report as indented JSON to w.
func WriteJSON(w io.Writer, r Report) error {
	// Emit [] rather than null so consumers can iterate without a nil check.
	if r.Sections == nil {
		r.Sections = []SectionResult{}
	}
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
