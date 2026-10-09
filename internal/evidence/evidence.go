// Package evidence writes a run's results as a self-describing bundle (report, baseline snapshot,
// findings and the raw output of every check) with a SHA-256 manifest, and verifies a bundle later.
//
// The manifest makes tampering after the fact detectable only if its hash is recorded somewhere an
// attacker on the examined Mac cannot reach. A bundle written to the same machine proves nothing on
// its own, so Write returns the bundle hash for the operator to copy off the machine.
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jimididit/mac-compass/internal/baseline"
	"github.com/jimididit/mac-compass/internal/output"
)

// SchemaVersion is bumped when the manifest layout changes incompatibly.
const SchemaVersion = 1

const (
	manifestName = "MANIFEST.json"
	hashName     = "MANIFEST.sha256"
	maxManifest  = 16 << 20
)

// File is one hashed file in a bundle.
type File struct {
	Path   string `json:"path"` // slash-separated, relative to the bundle
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest lists every file in a bundle.
type Manifest struct {
	SchemaVersion int             `json:"schema_version"`
	Tool          output.ToolInfo `json:"tool"`
	Host          output.HostInfo `json:"host"`
	CreatedAt     time.Time       `json:"created_at"`
	Files         []File          `json:"files"`
}

// Input is what a bundle is built from. Redact, when set, is applied to every string written.
type Input struct {
	Report       output.Report
	Snapshot     baseline.Snapshot
	FindingsText string
	HTML         []byte // optional rendered report, stored as report.html
	Redact       func(string) string
}

var unsafeName = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// Write creates dir (which must not exist or be empty) and fills it with the bundle. It returns the
// manifest and the bundle hash, the SHA-256 of MANIFEST.json.
func Write(dir string, in Input) (Manifest, string, error) {
	if ents, err := os.ReadDir(dir); err == nil && len(ents) > 0 {
		return Manifest{}, "", fmt.Errorf("%s is not empty; evidence is never written into an existing folder", dir)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Manifest{}, "", err
	}
	if err := os.MkdirAll(filepath.Join(dir, "raw"), 0o700); err != nil {
		return Manifest{}, "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil && !isWindows() {
		return Manifest{}, "", err
	}
	redact := in.Redact
	if redact == nil {
		redact = func(s string) string { return s }
	}

	var files []File
	put := func(rel string, data []byte) error {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.WriteFile(full, data, 0o600); err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		files = append(files, File{Path: rel, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))})
		return nil
	}

	var buf bytes.Buffer
	if err := output.WriteJSON(&buf, in.Report); err != nil {
		return Manifest{}, "", err
	}
	if err := put("report.json", buf.Bytes()); err != nil {
		return Manifest{}, "", err
	}
	buf.Reset()
	if err := in.Snapshot.Write(&buf); err != nil {
		return Manifest{}, "", err
	}
	if err := put("snapshot.json", buf.Bytes()); err != nil {
		return Manifest{}, "", err
	}
	if err := put("findings.txt", []byte(redact(in.FindingsText))); err != nil {
		return Manifest{}, "", err
	}
	if len(in.HTML) > 0 {
		if err := put("report.html", in.HTML); err != nil {
			return Manifest{}, "", err
		}
	}
	seen := map[string]int{}
	for _, sec := range in.Report.Sections {
		for _, c := range sec.Checks {
			if c.Skipped {
				continue
			}
			name := unsafeName.ReplaceAllString(c.ID, "_")
			if name == "" {
				name = "check"
			}
			if n := seen[name]; n > 0 {
				name = fmt.Sprintf("%s-%d", name, n)
			}
			seen[unsafeName.ReplaceAllString(c.ID, "_")]++
			if err := put("raw/"+name+".txt", []byte(rawText(c, redact))); err != nil {
				return Manifest{}, "", err
			}
		}
	}

	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	m := Manifest{SchemaVersion: SchemaVersion, Tool: in.Report.Tool, Host: in.Report.Host, CreatedAt: time.Now().UTC(), Files: files}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Manifest{}, "", err
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(dir, manifestName), data, 0o600); err != nil {
		return Manifest{}, "", err
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, hashName), []byte(hash+"  "+manifestName+"\n"), 0o600); err != nil {
		return Manifest{}, "", err
	}
	return m, hash, nil
}

func rawText(c output.CheckResult, redact func(string) string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s (%s)\n# section: %s  exit: %d  duration: %dms\n", redact(c.Name), c.ID, c.Section, c.ExitCode, c.DurationMS)
	if c.Error != "" {
		fmt.Fprintf(&b, "# error: %s\n", redact(c.Error))
	}
	b.WriteString("--- stdout\n")
	b.WriteString(redact(c.Stdout))
	if !strings.HasSuffix(c.Stdout, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("--- stderr\n")
	b.WriteString(redact(c.Stderr))
	if !strings.HasSuffix(c.Stderr, "\n") {
		b.WriteString("\n")
	}
	return b.String()
}

// Result is the outcome of verifying a bundle.
type Result struct {
	Manifest   Manifest
	BundleHash string   // SHA-256 of MANIFEST.json as found on disk
	Mismatched []string // listed files whose content no longer matches
	Missing    []string // listed files that are gone or are not regular files
	Extra      []string // files present that the manifest does not list
	BadHash    bool     // MANIFEST.sha256 disagrees with MANIFEST.json
}

// OK reports whether the bundle is exactly what the manifest describes.
func (r Result) OK() bool {
	return len(r.Mismatched) == 0 && len(r.Missing) == 0 && len(r.Extra) == 0 && !r.BadHash
}

// Verify re-hashes every file a bundle's manifest lists and looks for extra files. It treats the
// bundle as untrusted input: manifest paths that escape the folder are rejected.
func Verify(dir string) (Result, error) {
	var res Result
	data, err := readLimited(filepath.Join(dir, manifestName), maxManifest)
	if err != nil {
		return res, fmt.Errorf("read %s: %w", manifestName, err)
	}
	sum := sha256.Sum256(data)
	res.BundleHash = hex.EncodeToString(sum[:])
	if err := json.Unmarshal(data, &res.Manifest); err != nil {
		return res, fmt.Errorf("parse %s: %w", manifestName, err)
	}
	if res.Manifest.SchemaVersion != SchemaVersion {
		return res, fmt.Errorf("unsupported manifest schema_version %d (this build reads %d)", res.Manifest.SchemaVersion, SchemaVersion)
	}
	if h, err := readLimited(filepath.Join(dir, hashName), 4096); err == nil {
		if fields := strings.Fields(string(h)); len(fields) == 0 || fields[0] != res.BundleHash {
			res.BadHash = true
		}
	} else {
		res.BadHash = true
	}

	listed := map[string]bool{manifestName: true, hashName: true}
	for _, f := range res.Manifest.Files {
		if !filepath.IsLocal(filepath.FromSlash(f.Path)) || strings.Contains(f.Path, "\\") {
			return res, fmt.Errorf("manifest lists an unsafe path %q", f.Path)
		}
		listed[f.Path] = true
		full := filepath.Join(dir, filepath.FromSlash(f.Path))
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() {
			res.Missing = append(res.Missing, f.Path)
			continue
		}
		got, err := hashFile(full)
		if err != nil || got != f.SHA256 || info.Size() != f.Size {
			res.Mismatched = append(res.Mismatched, f.Path)
		}
	}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		if rel = filepath.ToSlash(rel); !listed[rel] {
			res.Extra = append(res.Extra, rel)
		}
		return nil
	})
	sort.Strings(res.Extra)
	return res, err
}

func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("file larger than %d bytes", max)
	}
	return data, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isWindows() bool { return filepath.Separator == '\\' }
