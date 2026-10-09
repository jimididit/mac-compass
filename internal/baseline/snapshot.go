// Package baseline records a normalized snapshot of a Mac's security-relevant inventory
// (persistence items, listeners, extensions, settings) and diffs two snapshots.
package baseline

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/jimididit/mac-compass/internal/output"
)

// SchemaVersion is bumped when the snapshot layout changes incompatibly.
const SchemaVersion = 1

// Kind says how an entry's items are compared.
type Kind string

const (
	// KindSet entries are unordered collections; the diff reports added and removed items.
	KindSet Kind = "set"
	// KindState entries are settings; the diff reports a change from one value to another.
	KindState Kind = "state"
)

// Entry is the normalized inventory from one check.
type Entry struct {
	Kind  Kind     `json:"kind"`
	Items []string `json:"items"`
}

// Snapshot is a point-in-time inventory. Only checks that ran successfully appear in
// Checks, so a check missing from either side of a comparison is simply not comparable.
type Snapshot struct {
	SchemaVersion int              `json:"schema_version"`
	Tool          output.ToolInfo  `json:"tool"`
	Host          output.HostInfo  `json:"host"`
	TakenAt       time.Time        `json:"taken_at"`
	SudoEnabled   bool             `json:"sudo_enabled"`
	Redacted      bool             `json:"redacted,omitempty"` // host and user names are masked
	Checks        map[string]Entry `json:"checks"`
}

// FromSections builds a snapshot from check results. Failed and skipped checks, and
// checks without an extractor, are left out.
func FromSections(tool output.ToolInfo, host output.HostInfo, sudo bool, taken time.Time, sections []output.SectionResult) Snapshot {
	s := Snapshot{SchemaVersion: SchemaVersion, Tool: tool, Host: host, TakenAt: taken.UTC(), SudoEnabled: sudo, Checks: map[string]Entry{}}
	for _, sec := range sections {
		for _, r := range sec.Checks {
			ex, ok := extractors[r.ID]
			if !ok || !r.Ok || r.Skipped {
				continue
			}
			items := ex.fn(r)
			sort.Strings(items)
			s.Checks[r.ID] = Entry{Kind: ex.kind, Items: dedupe(items)}
		}
	}
	return s
}

// Write encodes the snapshot as indented JSON.
func (s Snapshot) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// Read decodes a snapshot and rejects unknown schema versions.
func Read(r io.Reader) (Snapshot, error) {
	var s Snapshot
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return s, fmt.Errorf("decode snapshot: %w", err)
	}
	if s.SchemaVersion != SchemaVersion {
		return s, fmt.Errorf("unsupported snapshot schema_version %d (this build reads %d)", s.SchemaVersion, SchemaVersion)
	}
	if s.Checks == nil {
		return s, fmt.Errorf("snapshot has no checks")
	}
	return s, nil
}

func dedupe(sorted []string) []string {
	out := sorted[:0:0]
	for i, v := range sorted {
		if i == 0 || v != sorted[i-1] {
			out = append(out, v)
		}
	}
	return out
}
