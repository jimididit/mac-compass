package monitor

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// AppleScriptString quotes s as an AppleScript string literal. Finding titles come from the examined
// machine, so quotes, backslashes and line breaks must not be able to break out of the literal.
func AppleScriptString(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 {
			return -1
		}
		return r
	}, s)
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	if len(s) > 220 {
		s = s[:220] + "..."
	}
	return `"` + s + `"`
}

// OSANotifier shows a macOS desktop notification. It only works from a user session (a LaunchAgent).
func OSANotifier(title, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	script := "display notification " + AppleScriptString(body) + " with title " + AppleScriptString(title)
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	return cmd.Run()
}
