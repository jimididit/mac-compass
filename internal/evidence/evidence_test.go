package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jimididit/mac-compass/internal/baseline"
	"github.com/jimididit/mac-compass/internal/output"
)

func sample() Input {
	rep := output.Report{
		SchemaVersion: output.SchemaVersion,
		Tool:          output.ToolInfo{Name: "mac-compass", Version: "test"},
		Host:          output.HostInfo{Hostname: "alices-mbp.local", OS: "darwin", Arch: "arm64", MacOSVersion: "26.6.2"},
		Sections: []output.SectionResult{{Section: "triage", Checks: []output.CheckResult{
			{ID: "triage.sip", Section: "triage", Name: "SIP status", Ok: true, Stdout: "System Integrity Protection status: enabled.\n"},
			{ID: "network.firewall", Section: "network", Name: "Firewall", Ok: false, ExitCode: 2, Error: "exit status 2", Stderr: "boom"},
			{ID: "triage.skipped", Section: "triage", Name: "Skipped", Skipped: true, SkipReason: "requires sudo"},
		}}},
	}
	snap := baseline.FromSections(rep.Tool, rep.Host, true, time.Unix(0, 0), rep.Sections)
	return Input{Report: rep, Snapshot: snap, FindingsText: "No findings.\n"}
}

func TestWriteThenVerify(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	m, hash, err := Write(dir, sample())
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range m.Files {
		paths = append(paths, f.Path)
	}
	want := []string{"findings.txt", "raw/network.firewall.txt", "raw/triage.sip.txt", "report.json", "snapshot.json"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Errorf("files = %v; want %v (skipped checks have no raw file)", paths, want)
	}
	data, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hash != hex.EncodeToString(sum[:]) {
		t.Error("bundle hash must be the SHA-256 of MANIFEST.json")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "MANIFEST.sha256")); !strings.HasPrefix(string(b), hash+"  MANIFEST.json") {
		t.Errorf("MANIFEST.sha256 = %q", b)
	}
	res, err := Verify(dir)
	if err != nil || !res.OK() || res.BundleHash != hash {
		t.Fatalf("a fresh bundle must verify: %+v %v", res, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "raw", "network.firewall.txt"))
	if !strings.Contains(string(raw), "# error: exit status 2") || !strings.Contains(string(raw), "--- stderr\nboom") {
		t.Errorf("raw file: %q", raw)
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{dir, filepath.Join(dir, "report.json"), filepath.Join(dir, "MANIFEST.json")} {
			info, _ := os.Stat(p)
			if info.Mode().Perm()&0o077 != 0 {
				t.Errorf("%s must not be readable by others: %v", p, info.Mode())
			}
		}
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	mk := func() string {
		dir := filepath.Join(t.TempDir(), "b")
		if _, _, err := Write(dir, sample()); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	dir := mk()
	os.WriteFile(filepath.Join(dir, "raw", "triage.sip.txt"), []byte("System Integrity Protection status: enabled.\n"+"edited"), 0o600)
	if r, _ := Verify(dir); r.OK() || len(r.Mismatched) != 1 || r.Mismatched[0] != "raw/triage.sip.txt" {
		t.Errorf("edited file: %+v", r)
	}

	dir = mk()
	os.Remove(filepath.Join(dir, "report.json"))
	if r, _ := Verify(dir); r.OK() || len(r.Missing) != 1 || r.Missing[0] != "report.json" {
		t.Errorf("deleted file: %+v", r)
	}

	dir = mk()
	os.WriteFile(filepath.Join(dir, "raw", "planted.txt"), []byte("x"), 0o600)
	if r, _ := Verify(dir); r.OK() || len(r.Extra) != 1 || r.Extra[0] != "raw/planted.txt" {
		t.Errorf("extra file: %+v", r)
	}

	// Rewriting the manifest to match edited content is caught by the recorded bundle hash.
	dir = mk()
	_, hash, _ := Write(filepath.Join(t.TempDir(), "other"), sample())
	mf := filepath.Join(dir, "MANIFEST.json")
	b, _ := os.ReadFile(mf)
	os.WriteFile(mf, append(b, ' '), 0o600)
	r, err := Verify(dir)
	if err != nil || !r.BadHash || r.OK() {
		t.Errorf("a changed manifest must not match MANIFEST.sha256: %+v %v", r, err)
	}
	if r.BundleHash == hash {
		t.Error("changed manifest must change the bundle hash")
	}
}

func TestVerifyRejectsUnsafeManifestPaths(t *testing.T) {
	for _, bad := range []string{"../outside.txt", "/etc/passwd", "raw/../../x", `raw\..\x`} {
		dir := t.TempDir()
		m := Manifest{SchemaVersion: SchemaVersion, Files: []File{{Path: bad, SHA256: "00", Size: 0}}}
		data, _ := json.Marshal(m)
		os.WriteFile(filepath.Join(dir, "MANIFEST.json"), data, 0o600)
		if _, err := Verify(dir); err == nil {
			t.Errorf("manifest path %q must be rejected", bad)
		}
	}
}

func TestVerifyErrors(t *testing.T) {
	if _, err := Verify(t.TempDir()); err == nil {
		t.Error("a folder without a manifest is not a bundle")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "MANIFEST.json"), []byte(`{"schema_version": 99}`), 0o600)
	if _, err := Verify(dir); err == nil {
		t.Error("unknown schema version must be rejected")
	}
}

func TestWriteRefusesNonEmptyFolder(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("x"), 0o600)
	if _, _, err := Write(dir, sample()); err == nil {
		t.Error("evidence must never be written into a folder that already has files")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "keep.txt")); string(b) != "x" {
		t.Error("existing files must be left alone")
	}
	empty := filepath.Join(t.TempDir(), "empty")
	os.MkdirAll(empty, 0o700)
	if _, _, err := Write(empty, sample()); err != nil {
		t.Errorf("an empty folder is fine: %v", err)
	}
}

func TestWriteRedacts(t *testing.T) {
	in := sample()
	in.FindingsText = "host alices-mbp.local\n"
	in.Redact = func(s string) string { return strings.ReplaceAll(s, "alices-mbp.local", "[host]") }
	in.Report.Sections[0].Checks[0].Stdout = "on alices-mbp.local\n"
	dir := filepath.Join(t.TempDir(), "b")
	if _, _, err := Write(dir, in); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"findings.txt", "raw/triage.sip.txt"} {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		if strings.Contains(string(b), "alices-mbp") || !strings.Contains(string(b), "[host]") {
			t.Errorf("%s not redacted: %q", f, b)
		}
	}
}

func TestDuplicateIDsDoNotOverwrite(t *testing.T) {
	in := sample()
	in.Report.Sections[0].Checks = append(in.Report.Sections[0].Checks,
		output.CheckResult{ID: "triage.sip", Name: "again", Ok: true, Stdout: "second\n"})
	dir := filepath.Join(t.TempDir(), "b")
	m, _, err := Write(dir, in)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range m.Files {
		if strings.HasPrefix(f.Path, "raw/triage.sip") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("want two distinct raw files for a repeated id, got %d", n)
	}
}

func TestWriteIncludesHTMLWhenGiven(t *testing.T) {
	in := sample()
	in.HTML = []byte("<!doctype html><title>x</title>")
	dir := filepath.Join(t.TempDir(), "b")
	m, _, err := Write(dir, in)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range m.Files {
		if f.Path == "report.html" {
			found = true
		}
	}
	if !found {
		t.Error("report.html must be hashed into the manifest")
	}
	if r, err := Verify(dir); err != nil || !r.OK() {
		t.Errorf("%+v %v", r, err)
	}
}
