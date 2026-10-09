// Package monitor runs mac-compass on a schedule: each cycle takes a snapshot, compares it with the
// monitor's own baseline, and raises an alert only when the set of serious new findings changes.
package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jimididit/mac-compass/internal/baseline"
	"github.com/jimididit/mac-compass/internal/output"
)

const (
	baselineFile = "baseline.json"
	stateFile    = "state.json"
	latestFile   = "latest.json"
	historyDir   = "history"
	// MaxHistory is how many past comparison reports are kept.
	MaxHistory = 50
	// MaxLogBytes is the size at which the monitor's log file is emptied.
	MaxLogBytes = 1 << 20
)

// State is what the monitor remembers between cycles.
type State struct {
	LastRun       time.Time `json:"last_run"`
	LastResult    string    `json:"last_result"` // baselined, clean, changes, alerted (this run), alert-active (unchanged since the last alert), error
	LastError     string    `json:"last_error,omitempty"`
	Runs          int       `json:"runs"`
	BaselineTaken time.Time `json:"baseline_taken"`
	AlertedHash   string    `json:"alerted_hash,omitempty"` // hash of the set of findings last alerted on
	LastAlert     time.Time `json:"last_alert,omitempty"`
}

// Options configures one cycle. The funcs are injected so a cycle can be tested without a Mac.
type Options struct {
	StateDir  string
	Threshold output.Severity // alert on new findings at or above this severity
	Rebase    bool            // discard the baseline and take a new one

	Snapshot func(ctx context.Context) (baseline.Snapshot, error)
	// Filter optionally removes accepted findings (suppressions) before alerting.
	Filter func([]output.Finding) []output.Finding
	Notify func(title, body string) error
	Now    func() time.Time
}

// Result describes what a cycle did.
type Result struct {
	State    State
	Findings []output.Finding // findings from the comparison, after filtering
	Alerted  bool
	Title    string
	Body     string
}

// Run performs one monitoring cycle.
func Run(ctx context.Context, o Options) (Result, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := os.MkdirAll(filepath.Join(o.StateDir, historyDir), 0o700); err != nil {
		return Result{}, err
	}
	_ = os.Chmod(o.StateDir, 0o700)
	st, _ := LoadState(o.StateDir)
	now := o.Now().UTC()
	st.LastRun, st.Runs = now, st.Runs+1

	fail := func(err error) (Result, error) {
		st.LastResult, st.LastError = "error", err.Error()
		_ = saveJSON(filepath.Join(o.StateDir, stateFile), st)
		return Result{State: st}, err
	}

	cur, err := o.Snapshot(ctx)
	if err != nil {
		return fail(fmt.Errorf("snapshot: %w", err))
	}
	st.LastError = "" // a failure last time is stale once a snapshot succeeds

	basePath := filepath.Join(o.StateDir, baselineFile)
	var base baseline.Snapshot
	haveBase := false
	if !o.Rebase {
		if f, err := os.Open(basePath); err == nil {
			base, err = baseline.Read(f)
			f.Close()
			if err != nil {
				return fail(fmt.Errorf("read baseline (run with --rebaseline to replace it): %w", err))
			}
			haveBase = true
		}
	}
	if !haveBase {
		if err := writeSnapshot(basePath, cur); err != nil {
			return fail(err)
		}
		st.BaselineTaken, st.AlertedHash, st.LastResult, st.LastError = now, "", "baselined", ""
		if err := saveJSON(filepath.Join(o.StateDir, stateFile), st); err != nil {
			return Result{State: st}, err
		}
		return Result{State: st}, nil
	}

	cmp := baseline.Compare(base, cur)
	findings := cmp.Findings
	if o.Filter != nil {
		findings = o.Filter(findings)
	}
	rep := output.Report{
		SchemaVersion: output.SchemaVersion,
		Tool:          cur.Tool,
		Host:          cur.Host,
		StartedAt:     now,
		SudoEnabled:   cur.SudoEnabled,
		Findings:      findings,
	}
	rep.Summarize()
	if err := saveJSON(filepath.Join(o.StateDir, latestFile), rep); err != nil {
		return fail(err)
	}
	if hasChanges(findings) {
		name := now.Format("20060102T150405Z") + ".json"
		if err := saveJSON(filepath.Join(o.StateDir, historyDir, name), rep); err != nil {
			return fail(err)
		}
		pruneHistory(filepath.Join(o.StateDir, historyDir), MaxHistory)
	}

	res := Result{State: st, Findings: findings}
	serious := seriousFindings(findings, o.Threshold)
	hash := alertHash(serious)
	switch {
	case len(serious) == 0:
		st.LastResult, st.AlertedHash = "clean", ""
		if hasChanges(findings) {
			st.LastResult = "changes"
		}
	case hash == st.AlertedHash:
		st.LastResult = "alert-active" // same findings as the last alert: still open, but do not nag
	default:
		res.Title, res.Body = alertText(serious)
		if o.Notify != nil {
			if err := o.Notify(res.Title, res.Body); err != nil {
				st.LastError = "notify: " + err.Error()
			}
		}
		res.Alerted = true
		st.LastResult, st.AlertedHash, st.LastAlert = "alerted", hash, now
	}
	res.State = st
	return res, saveJSON(filepath.Join(o.StateDir, stateFile), st)
}

// hasChanges reports whether any finding is a failure or an informational diff (not host metadata).
func hasChanges(fs []output.Finding) bool {
	for _, f := range fs {
		if f.Status == output.StatusFail || (f.Status == output.StatusInfo && !strings.HasPrefix(f.ID, "baseline.")) {
			return true
		}
	}
	return false
}

func seriousFindings(fs []output.Finding, threshold output.Severity) []output.Finding {
	if threshold == "" {
		threshold = output.SeverityMedium
	}
	var out []output.Finding
	for _, f := range fs {
		if f.Status == output.StatusFail && f.Severity.Rank() >= threshold.Rank() {
			out = append(out, f)
		}
	}
	return out
}

// alertHash identifies a set of findings independent of order, so an unchanged situation is not
// re-announced every cycle.
func alertHash(fs []output.Finding) string {
	keys := make([]string, 0, len(fs))
	for _, f := range fs {
		keys = append(keys, f.ID+"|"+f.Title+"|"+f.Detail)
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return hex.EncodeToString(sum[:8])
}

func alertText(fs []output.Finding) (title, body string) {
	sorted := append([]output.Finding(nil), fs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Severity.Rank() > sorted[j].Severity.Rank() })
	title = fmt.Sprintf("mac-compass: %d new finding(s), highest %s", len(fs), sorted[0].Severity)
	var lines []string
	for i, f := range sorted {
		if i == 3 {
			lines = append(lines, fmt.Sprintf("and %d more", len(sorted)-3))
			break
		}
		lines = append(lines, f.Title)
	}
	return title, strings.Join(lines, "; ")
}

// LoadState reads the monitor's state; a missing file yields the zero state.
func LoadState(dir string) (State, error) {
	var st State
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

// LoadLatest reads the most recent comparison report, if there is one.
func LoadLatest(dir string) (output.Report, bool) {
	var rep output.Report
	b, err := os.ReadFile(filepath.Join(dir, latestFile))
	if err != nil || json.Unmarshal(b, &rep) != nil {
		return rep, false
	}
	return rep, true
}

func writeSnapshot(path string, s baseline.Snapshot) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return s.Write(f)
}

func saveJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// pruneHistory keeps the newest n files in dir (names sort by time).
func pruneHistory(dir string, n int) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for i := 0; i < len(names)-n; i++ {
		_ = os.Remove(filepath.Join(dir, names[i]))
	}
}

// TrimLog empties the log file once it grows past MaxLogBytes, so a scheduled job cannot fill the disk.
func TrimLog(path string) {
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Size() > MaxLogBytes {
		_ = os.Truncate(path, 0)
	}
}
