package monitor

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Label is the launchd label of the monitor job.
const Label = "io.github.jimididit.mac-compass.monitor"

// MinInterval is the shortest schedule accepted; each cycle runs the full inventory.
const MinInterval = 5 * time.Minute

// Scope is where the job is installed.
type Scope string

const (
	// ScopeUser installs a LaunchAgent for the current user: no root needed, desktop notifications work,
	// but only unprivileged checks run.
	ScopeUser Scope = "user"
	// ScopeSystem installs a LaunchDaemon that runs as root, with full coverage. It cannot show desktop
	// notifications; alerts go to the log and the state folder.
	ScopeSystem Scope = "system"
)

// JobSpec describes the job to install.
type JobSpec struct {
	Binary   string // absolute path of mac-compass
	StateDir string // where state, baseline and logs live
	Interval time.Duration
	Args     []string // extra arguments after "monitor run"
}

// LogPath is where the job's output goes.
func (j JobSpec) LogPath() string { return path.Join(j.StateDir, "monitor.log") }

// Plist renders the launchd property list for the job.
func Plist(j JobSpec) ([]byte, error) {
	if !isAbs(j.Binary) || !isAbs(j.StateDir) {
		return nil, fmt.Errorf("binary and state folder must be absolute paths")
	}
	if j.Interval < MinInterval {
		return nil, fmt.Errorf("interval %v is shorter than the %v minimum", j.Interval, MinInterval)
	}
	args := append([]string{j.Binary, "monitor", "run", "--state-dir", j.StateDir}, j.Args...)

	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
`)
	key := func(k string) { fmt.Fprintf(&b, "\t<key>%s</key>\n", esc(k)) }
	str := func(k, v string) { key(k); fmt.Fprintf(&b, "\t<string>%s</string>\n", esc(v)) }
	boolean := func(k string, v bool) {
		key(k)
		if v {
			b.WriteString("\t<true/>\n")
		} else {
			b.WriteString("\t<false/>\n")
		}
	}
	str("Label", Label)
	key("ProgramArguments")
	b.WriteString("\t<array>\n")
	for _, a := range args {
		fmt.Fprintf(&b, "\t\t<string>%s</string>\n", esc(a))
	}
	b.WriteString("\t</array>\n")
	key("StartInterval")
	fmt.Fprintf(&b, "\t<integer>%d</integer>\n", int(j.Interval.Seconds()))
	boolean("RunAtLoad", true)
	str("ProcessType", "Background")
	boolean("LowPriorityIO", true)
	key("Nice")
	b.WriteString("\t<integer>10</integer>\n")
	str("StandardOutPath", j.LogPath())
	str("StandardErrorPath", j.LogPath())
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes(), nil
}

// isAbs accepts a macOS absolute path, and the native form on the platform the tests run on.
func isAbs(p string) bool { return path.IsAbs(p) || filepath.IsAbs(p) }

func esc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// LaunchDir is the folder the plist is written to for a scope.
func LaunchDir(scope Scope, home string) string {
	if scope == ScopeSystem {
		return "/Library/LaunchDaemons"
	}
	return path.Join(home, "Library", "LaunchAgents")
}

// PlistPath is the full path of the job's plist.
func PlistPath(dir string) string { return path.Join(dir, Label+".plist") }

// StatFn reports ownership and mode of a path. It is injected so the trust check is testable.
type StatFn func(path string) (uid uint32, mode fs.FileMode, err error)

// CheckRootTrusted refuses a binary that a non-root user could replace. A root LaunchDaemon runs the
// binary as root on a schedule; if the binary (or any folder above it) is writable by someone else,
// installing the daemon would hand that person root. Every path component from the binary up to "/"
// must be owned by root and writable by no one else.
func CheckRootTrusted(binary string, stat StatFn) error {
	for p := path.Clean(binary); ; p = path.Dir(p) {
		uid, mode, err := stat(p)
		if err != nil {
			return fmt.Errorf("cannot inspect %s: %w", p, err)
		}
		if uid != 0 {
			return fmt.Errorf("%s is not owned by root, so it could be replaced by its owner and then run as root; install mac-compass somewhere root-owned, for example sudo cp mac-compass /usr/local/bin/", p)
		}
		if mode.Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by group or others, so it could be replaced and then run as root; fix with sudo chmod go-w %s", p, p)
		}
		if p == "/" || p == "." || path.Dir(p) == p {
			return nil
		}
	}
}

// OSStat is the production StatFn.
func OSStat(path string) (uint32, fs.FileMode, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, 0, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		// Judge the target, which is what would actually run.
		if info, err = os.Stat(path); err != nil {
			return 0, 0, err
		}
	}
	return ownerUID(info), info.Mode(), nil
}

// Quote renders args as a shell-safe string for messages shown to the user.
func Quote(args []string) string {
	var out []string
	for _, a := range args {
		if strings.ContainsAny(a, " \t'\"$\\") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		out = append(out, a)
	}
	return strings.Join(out, " ")
}
