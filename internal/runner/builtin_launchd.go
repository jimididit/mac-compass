package runner

import (
	"context"
	"encoding/json"
	"path"
	"strings"
)

// LaunchdHeader is the first line of the launchd-targets output; evaluators and baselines rely on
// the column order below.
const LaunchdHeader = "kind\tlabel\tplist\ttarget\tstate\tteam\tsigner\tnotarization\tflags"

type launchdPlist struct {
	Label            string   `json:"Label"`
	Program          string   `json:"Program"`
	ProgramArguments []string `json:"ProgramArguments"`
	RunAtLoad        bool     `json:"RunAtLoad"`
	KeepAlive        any      `json:"KeepAlive"`
}

// interpreters run a script rather than being the thing worth verifying: the script is.
var interpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"python": true, "python3": true, "perl": true, "ruby": true, "osascript": true, "node": true,
}

// launchdTargets lists every launch item in the system and invoking-user launchd folders with the
// program it runs and that program's code-signing state. One tab-separated row per item.
func launchdTargets(ctx context.Context, d deps) (string, error) {
	dirs := []struct{ dir, kind string }{
		{"/Library/LaunchDaemons", "daemon"},
		{"/Library/LaunchAgents", "agent"},
	}
	if d.home != "" {
		dirs = append(dirs, struct{ dir, kind string }{d.home + "/Library/LaunchAgents", "user-agent"})
	}
	var rows []string
	cache := map[string]signInfo{}
	for _, dd := range dirs {
		names, err := d.listDir(dd.dir)
		if err != nil {
			continue // folder absent: nothing to list
		}
		for _, name := range names {
			if !strings.HasSuffix(name, ".plist") {
				continue
			}
			if err := ctx.Err(); err != nil {
				return strings.Join(append([]string{LaunchdHeader}, rows...), "\n") + "\n", err
			}
			rows = append(rows, launchdRow(ctx, d, cache, dd.kind, dd.dir+"/"+name))
		}
	}
	return strings.Join(append([]string{LaunchdHeader}, rows...), "\n") + "\n", nil
}

func launchdRow(ctx context.Context, d deps, cache map[string]signInfo, kind, plist string) string {
	out, _, code, err := d.exec(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", "--", plist)
	var p launchdPlist
	if err != nil || code != 0 || json.Unmarshal([]byte(out), &p) != nil {
		return row(kind, "-", plist, "-", "unreadable", "-", "-", "-", "")
	}
	label := p.Label
	if label == "" {
		label = strings.TrimSuffix(path.Base(plist), ".plist")
	}
	args := p.ProgramArguments
	target := p.Program
	if target == "" && len(args) > 0 {
		target = args[0]
	}
	if target == "" {
		return row(kind, label, plist, "-", "no-program", "-", "-", "-", strings.Join(flagList(p), ","))
	}

	var flags []string
	if interpreters[path.Base(target)] {
		flags = append(flags, "interpreter")
		if script := scriptArg(args); script != "" {
			target = script
			flags = append(flags, "script")
		} else {
			flags = append(flags, "inline-command")
		}
	}
	if location := riskyLocation(target); location != "" {
		flags = append(flags, location)
	}
	flags = append(flags, flagList(p)...)

	if !d.exists(target) {
		return row(kind, label, plist, target, "missing", "-", "-", "-", strings.Join(flags, ","))
	}
	if hasFlag(flags, "script") || hasFlag(flags, "inline-command") {
		// Scripts carry no signature; the finding is the location and that a script runs at all.
		return row(kind, label, plist, target, "script", "-", "-", "-", strings.Join(flags, ","))
	}
	si, ok := cache[target]
	if !ok {
		si = inspectSignature(ctx, d, target)
		cache[target] = si
	}
	return row(kind, label, plist, target, si.State, si.Team, si.Signer, si.Notarization, strings.Join(flags, ","))
}

func row(kind, label, plist, target, state, team, signer, notar, flags string) string {
	return strings.Join([]string{clean(kind), clean(label), clean(plist), clean(target), clean(state), clean(team), clean(signer), clean(notar), clean(flags)}, "\t")
}

func hasFlag(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}

func flagList(p launchdPlist) []string {
	var f []string
	if p.RunAtLoad {
		f = append(f, "runatload")
	}
	switch v := p.KeepAlive.(type) {
	case bool:
		if v {
			f = append(f, "keepalive")
		}
	case map[string]any:
		f = append(f, "keepalive")
	}
	return f
}

// scriptArg returns the first argument after the interpreter that names a file (not an option
// and not an inline -c command), or "" when the item runs an inline command.
func scriptArg(args []string) string {
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "-c" || a == "-e" {
			return ""
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if strings.HasPrefix(a, "/") || strings.HasPrefix(a, "~") {
			return a
		}
		return ""
	}
	return ""
}

// riskyLocation names why a path is suspicious for a persistent program, or "".
func riskyLocation(p string) string {
	for _, prefix := range []string{"/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/var/folders/", "/private/var/folders/", "/Users/Shared/", "/Volumes/"} {
		if strings.HasPrefix(p, prefix) {
			return "temp-location"
		}
	}
	for _, part := range strings.Split(p, "/") {
		if strings.HasPrefix(part, ".") && part != "." && part != ".." {
			return "hidden-location"
		}
	}
	return ""
}

// signInfo is the code-signing state of one program.
type signInfo struct {
	State        string // apple, developer-id, adhoc, unsigned, other-signed, unreadable
	Team         string
	Signer       string
	Notarization string // notarized, developer-id, apple, rejected, app-store, unknown
}

func inspectSignature(ctx context.Context, d deps, target string) signInfo {
	out, errOut, code, err := d.exec(ctx, "/usr/bin/codesign", "-dvv", "--", target)
	if err != nil {
		return signInfo{State: "unreadable", Notarization: "unknown"}
	}
	si := parseCodesign(out+"\n"+errOut, code)
	so, se, _, err := d.exec(ctx, "/usr/sbin/spctl", "--assess", "--type", "execute", "-vv", "--", target)
	if err == nil {
		si.Notarization = parseSpctl(so + "\n" + se)
	} else {
		si.Notarization = "unknown"
	}
	return si
}

// parseCodesign classifies `codesign -dvv` output (it prints to stderr).
func parseCodesign(out string, code int) signInfo {
	low := strings.ToLower(out)
	if strings.Contains(low, "not signed at all") {
		return signInfo{State: "unsigned", Team: "-", Signer: "-"}
	}
	if code != 0 && !strings.Contains(out, "Identifier=") {
		return signInfo{State: "unreadable", Team: "-", Signer: "-"}
	}
	si := signInfo{State: "other-signed", Team: "-", Signer: "-"}
	var authorities []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "Authority="):
			authorities = append(authorities, strings.TrimPrefix(l, "Authority="))
		case strings.HasPrefix(l, "TeamIdentifier="):
			if t := strings.TrimPrefix(l, "TeamIdentifier="); t != "not set" {
				si.Team = t
			}
		}
	}
	if len(authorities) > 0 {
		si.Signer = authorities[0]
	}
	switch {
	case strings.Contains(out, "Signature=adhoc") || strings.Contains(out, "(adhoc"):
		si.State = "adhoc"
		si.Signer = "-"
	case hasPrefixAny(authorities, "Developer ID Application"):
		si.State = "developer-id"
	case onlyApple(authorities):
		si.State = "apple"
	}
	return si
}

func hasPrefixAny(xs []string, prefix string) bool {
	for _, x := range xs {
		if strings.HasPrefix(x, prefix) {
			return true
		}
	}
	return false
}

// applePlatformChain is the certificate chain of Apple's own platform binaries. Developer, App Store
// and Mac App Store certificates chain through other Apple authorities and are deliberately excluded.
var applePlatformChain = map[string]bool{
	"Software Signing":                           true,
	"Apple Code Signing Certification Authority": true,
	"Apple Root CA":                              true,
	"Apple Mac OS Application Signing":           true,
}

// onlyApple reports whether every certificate in the chain belongs to Apple's platform signing.
func onlyApple(auth []string) bool {
	if len(auth) == 0 {
		return false
	}
	for _, a := range auth {
		if !applePlatformChain[a] {
			return false
		}
	}
	return true
}

// parseSpctl classifies `spctl --assess --type execute -vv` output.
func parseSpctl(out string) string {
	switch {
	case strings.Contains(out, "source=Notarized Developer ID"):
		return "notarized"
	case strings.Contains(out, "source=Developer ID"):
		return "developer-id"
	case strings.Contains(out, "source=Apple System"):
		return "apple"
	case strings.Contains(out, "source=Mac App Store"):
		return "app-store"
	case strings.Contains(out, "rejected"):
		return "rejected"
	}
	return "unknown"
}
