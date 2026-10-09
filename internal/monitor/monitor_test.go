package monitor

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jimididit/mac-compass/internal/baseline"
	"github.com/jimididit/mac-compass/internal/output"
)

// snap builds a snapshot with one launchd listing and the SIP state.
func snap(sip string, daemons ...string) baseline.Snapshot {
	listing := "total 8\n"
	for _, d := range daemons {
		listing += "-rw-r--r--  1 root  wheel  100 Jan  1 00:00 " + d + "\n"
	}
	return baseline.FromSections(output.ToolInfo{Name: "mac-compass"}, output.HostInfo{Hostname: "h", MacOSVersion: "26.0"}, false, time.Unix(0, 0),
		[]output.SectionResult{{Section: "triage", Checks: []output.CheckResult{
			{ID: "triage.sip", Ok: true, Stdout: sip},
			{ID: "triage.launchdaemons", Ok: true, Stdout: listing},
		}}})
}

type fixture struct {
	dir      string
	snapshot baseline.Snapshot
	notes    []string
	now      time.Time
}

func (f *fixture) opts() Options {
	return Options{
		StateDir:  f.dir,
		Threshold: output.SeverityMedium,
		Snapshot:  func(context.Context) (baseline.Snapshot, error) { return f.snapshot, nil },
		Notify:    func(title, body string) error { f.notes = append(f.notes, title+" | "+body); return nil },
		Now:       func() time.Time { f.now = f.now.Add(time.Hour); return f.now },
	}
}

func newFixture(t *testing.T) *fixture {
	return &fixture{dir: filepath.Join(t.TempDir(), "state"), snapshot: snap("System Integrity Protection status: enabled."), now: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)}
}

const sipOn = "System Integrity Protection status: enabled."
const sipOff = "System Integrity Protection status: disabled."

func TestFirstRunTakesBaselineAndDoesNotAlert(t *testing.T) {
	f := newFixture(t)
	res, err := Run(context.Background(), f.opts())
	if err != nil {
		t.Fatal(err)
	}
	if res.State.LastResult != "baselined" || res.Alerted || len(f.notes) != 0 {
		t.Errorf("first run: %+v notes=%v", res.State, f.notes)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "baseline.json")); err != nil {
		t.Errorf("baseline not written: %v", err)
	}
	if runtime := os.Getenv("OS"); runtime != "Windows_NT" {
		info, _ := os.Stat(f.dir)
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("state folder must be private: %v", info.Mode())
		}
	}
}

func TestUnchangedMachineStaysClean(t *testing.T) {
	f := newFixture(t)
	Run(context.Background(), f.opts())
	res, err := Run(context.Background(), f.opts())
	if err != nil || res.State.LastResult != "clean" || res.Alerted || len(f.notes) != 0 {
		t.Errorf("%+v %v notes=%v", res.State, err, f.notes)
	}
	if res.State.Runs != 2 {
		t.Errorf("runs = %d", res.State.Runs)
	}
}

func TestNewSeriousFindingAlertsOnceThenQuiets(t *testing.T) {
	f := newFixture(t)
	Run(context.Background(), f.opts())

	f.snapshot = snap(sipOff)
	res, _ := Run(context.Background(), f.opts())
	if !res.Alerted || len(f.notes) != 1 || !strings.Contains(f.notes[0], "highest high") || !strings.Contains(f.notes[0], "changed since baseline") {
		t.Fatalf("a changed SIP setting must alert: %+v notes=%v", res.State, f.notes)
	}
	// Same problem next cycle: no second notification.
	res, _ = Run(context.Background(), f.opts())
	if res.Alerted || len(f.notes) != 1 || res.State.LastResult != "alert-active" {
		t.Errorf("repeat alert for an unchanged situation: %+v notes=%v", res.State, f.notes)
	}
	// A different problem on top: alert again.
	f.snapshot = snap(sipOff, "com.evil.plist")
	res, _ = Run(context.Background(), f.opts())
	if !res.Alerted || len(f.notes) != 2 {
		t.Errorf("a new finding must re-alert: %+v notes=%v", res.State, f.notes)
	}
	// Back to the baseline: clean again, and the same problem later alerts afresh.
	f.snapshot = snap(sipOn)
	res, _ = Run(context.Background(), f.opts())
	if res.State.LastResult != "clean" || res.State.AlertedHash != "" {
		t.Errorf("recovery: %+v", res.State)
	}
	f.snapshot = snap(sipOff)
	if res, _ = Run(context.Background(), f.opts()); !res.Alerted {
		t.Error("the same problem returning after recovery must alert again")
	}
}

func TestThresholdAndFilter(t *testing.T) {
	f := newFixture(t)
	Run(context.Background(), f.opts())
	f.snapshot = snap(sipOn, "com.new.plist") // a new third-party launch item: medium
	o := f.opts()
	o.Threshold = output.SeverityHigh
	res, _ := Run(context.Background(), o)
	if res.Alerted || res.State.LastResult != "changes" {
		t.Errorf("below the threshold: recorded as a change, not an alert: %+v", res.State)
	}
	if _, ok := LoadLatest(f.dir); !ok {
		t.Error("latest.json must hold the comparison")
	}
	hist, _ := os.ReadDir(filepath.Join(f.dir, "history"))
	if len(hist) != 1 {
		t.Errorf("a change must be kept in history, got %d", len(hist))
	}

	o = f.opts()
	o.Filter = func(fs []output.Finding) []output.Finding { // everything accepted
		return nil
	}
	f.snapshot = snap(sipOff)
	if res, _ = Run(context.Background(), o); res.Alerted {
		t.Error("accepted findings must not alert")
	}
}

func TestNotifyFailureIsRecordedNotFatal(t *testing.T) {
	f := newFixture(t)
	Run(context.Background(), f.opts())
	f.snapshot = snap(sipOff)
	o := f.opts()
	o.Notify = func(string, string) error { return errors.New("no GUI session") }
	res, err := Run(context.Background(), o)
	if err != nil || !res.Alerted || !strings.Contains(res.State.LastError, "no GUI session") {
		t.Errorf("%+v %v", res.State, err)
	}
	st, _ := LoadState(f.dir)
	if st.LastResult != "alerted" || st.AlertedHash == "" {
		t.Errorf("the alert must still be recorded: %+v", st)
	}
}

func TestSnapshotFailureIsRecorded(t *testing.T) {
	f := newFixture(t)
	o := f.opts()
	o.Snapshot = func(context.Context) (baseline.Snapshot, error) { return baseline.Snapshot{}, errors.New("boom") }
	if _, err := Run(context.Background(), o); err == nil {
		t.Fatal("expected an error")
	}
	st, _ := LoadState(f.dir)
	if st.LastResult != "error" || !strings.Contains(st.LastError, "boom") {
		t.Errorf("%+v", st)
	}
	// The next good cycle clears the error.
	if _, err := Run(context.Background(), f.opts()); err != nil {
		t.Fatal(err)
	}
	if st, _ = LoadState(f.dir); st.LastError != "" {
		t.Errorf("stale error: %+v", st)
	}
}

func TestRebaseReplacesBaseline(t *testing.T) {
	f := newFixture(t)
	Run(context.Background(), f.opts())
	f.snapshot = snap(sipOff)
	o := f.opts()
	o.Rebase = true
	res, _ := Run(context.Background(), o)
	if res.State.LastResult != "baselined" || res.Alerted {
		t.Errorf("rebaseline must accept the current state: %+v", res.State)
	}
	if res, _ = Run(context.Background(), f.opts()); res.State.LastResult != "clean" {
		t.Errorf("after rebaselining, the same state is clean: %+v", res.State)
	}
}

func TestCorruptBaselineIsAnErrorNotASilentReset(t *testing.T) {
	f := newFixture(t)
	Run(context.Background(), f.opts())
	os.WriteFile(filepath.Join(f.dir, "baseline.json"), []byte("garbage"), 0o600)
	if _, err := Run(context.Background(), f.opts()); err == nil || !strings.Contains(err.Error(), "rebaseline") {
		t.Errorf("a damaged baseline must not be quietly replaced (that would hide changes): %v", err)
	}
}

func TestHistoryIsPruned(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < MaxHistory+7; i++ {
		os.WriteFile(filepath.Join(dir, strings.Repeat("0", 3)+string(rune('a'+i%26))+string(rune('a'+i/26))+".json"), []byte("{}"), 0o600)
	}
	pruneHistory(dir, MaxHistory)
	ents, _ := os.ReadDir(dir)
	if len(ents) != MaxHistory {
		t.Errorf("kept %d; want %d", len(ents), MaxHistory)
	}
}

func TestTrimLog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "monitor.log")
	os.WriteFile(p, []byte(strings.Repeat("x", MaxLogBytes+1)), 0o600)
	TrimLog(p)
	if info, _ := os.Stat(p); info.Size() != 0 {
		t.Errorf("oversized log must be emptied, size %d", info.Size())
	}
	os.WriteFile(p, []byte("small"), 0o600)
	TrimLog(p)
	if info, _ := os.Stat(p); info.Size() != 5 {
		t.Error("a small log must be left alone")
	}
	TrimLog(filepath.Join(t.TempDir(), "missing.log")) // must not panic
}

func TestPlist(t *testing.T) {
	b, err := Plist(JobSpec{Binary: "/usr/local/bin/mac-compass", StateDir: "/Users/me/Library/Application Support/mac-compass", Interval: time.Hour, Args: []string{"--no-sudo", "--suppress", "/Users/me/a&b<c>.yaml"}})
	if err != nil {
		t.Fatal(err)
	}
	p := string(b)
	for _, want := range []string{
		"<string>io.github.jimididit.mac-compass.monitor</string>", "<string>/usr/local/bin/mac-compass</string>",
		"<string>monitor</string>", "<string>run</string>", "<string>--state-dir</string>", "<string>--no-sudo</string>",
		"<integer>3600</integer>", "<key>RunAtLoad</key>", "<key>StandardOutPath</key>",
		"/Users/me/Library/Application Support/mac-compass/monitor.log",
		"/Users/me/a&amp;b&lt;c&gt;.yaml", // user-controlled text is escaped
	} {
		if !strings.Contains(p, want) {
			t.Errorf("plist missing %q:\n%s", want, p)
		}
	}
	if strings.Contains(p, "a&b<c>") {
		t.Error("unescaped XML in plist")
	}
	for name, spec := range map[string]JobSpec{
		"relative binary": {Binary: "mac-compass", StateDir: "/x", Interval: time.Hour},
		"relative state":  {Binary: "/b", StateDir: "x", Interval: time.Hour},
		"too frequent":    {Binary: "/b", StateDir: "/x", Interval: time.Minute},
	} {
		if _, err := Plist(spec); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

func TestLaunchPaths(t *testing.T) {
	if got := LaunchDir(ScopeSystem, "/Users/me"); got != "/Library/LaunchDaemons" {
		t.Error(got)
	}
	if got := filepath.ToSlash(LaunchDir(ScopeUser, "/Users/me")); got != "/Users/me/Library/LaunchAgents" {
		t.Error(got)
	}
	if got := filepath.Base(PlistPath("/x")); got != Label+".plist" {
		t.Error(got)
	}
}

func fakeStat(owners map[string]uint32, modes map[string]fs.FileMode) StatFn {
	return func(p string) (uint32, fs.FileMode, error) {
		p = filepath.ToSlash(p)
		m, ok := modes[p]
		if !ok {
			return 0, 0, errors.New("no such file")
		}
		return owners[p], m, nil
	}
}

func TestCheckRootTrusted(t *testing.T) {
	good := map[string]fs.FileMode{"/usr/local/bin/mac-compass": 0o755, "/usr/local/bin": 0o755, "/usr/local": 0o755, "/usr": 0o755, "/": 0o755}
	if err := CheckRootTrusted("/usr/local/bin/mac-compass", fakeStat(nil, good)); err != nil {
		t.Errorf("a root-owned, locked-down install must be accepted: %v", err)
	}

	owned := map[string]uint32{"/Users/me/mac-compass": 501}
	user := map[string]fs.FileMode{"/Users/me/mac-compass": 0o755, "/Users/me": 0o755, "/Users": 0o755, "/": 0o755}
	if err := CheckRootTrusted("/Users/me/mac-compass", fakeStat(owned, user)); err == nil || !strings.Contains(err.Error(), "not owned by root") {
		t.Errorf("a user-owned binary must be refused: %v", err)
	}

	writable := map[string]fs.FileMode{"/opt/tools/mac-compass": 0o755, "/opt/tools": 0o777, "/opt": 0o755, "/": 0o755}
	if err := CheckRootTrusted("/opt/tools/mac-compass", fakeStat(nil, writable)); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("a world-writable parent folder must be refused: %v", err)
	}

	groupW := map[string]fs.FileMode{"/opt/mac-compass": 0o775, "/opt": 0o755, "/": 0o755}
	if err := CheckRootTrusted("/opt/mac-compass", fakeStat(nil, groupW)); err == nil {
		t.Error("a group-writable binary must be refused")
	}

	if err := CheckRootTrusted("/nowhere/mac-compass", fakeStat(nil, good)); err == nil {
		t.Error("an uninspectable path must be refused, not assumed safe")
	}
}

func TestAppleScriptString(t *testing.T) {
	cases := map[string]string{
		`plain`:                 `"plain"`,
		`say "hi"`:              `"say \"hi\""`,
		`back\slash`:            `"back\\slash"`,
		"line\nbreak":           `"line break"`,
		`"; do shell script "x`: `"\"; do shell script \"x"`,
	}
	for in, want := range cases {
		if got := AppleScriptString(in); got != want {
			t.Errorf("AppleScriptString(%q) = %s; want %s", in, got, want)
		}
	}
	if got := AppleScriptString(strings.Repeat("a", 500)); len(got) > 230 {
		t.Errorf("notification text must be capped, got %d chars", len(got))
	}
}

func TestQuote(t *testing.T) {
	if got := Quote([]string{"a", "b c", "it's"}); got != `a 'b c' 'it'\''s'` {
		t.Errorf("Quote = %s", got)
	}
}
