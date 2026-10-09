package baseline

import "strings"

// goodState says whether a normalized setting value is the secure one. A change from a bad
// value to a good one is reported as an improvement (info) rather than as a failing finding.
// Settings without an entry are always treated as findings when they change.
var goodState = map[string]func(string) bool{
	"triage.sip":                    hasText("status: enabled"),
	"triage.sip-authenticated-root": hasText("status: enabled"),
	"triage.gatekeeper":             hasText("assessments enabled"),
	"network.firewall":              hasText("firewall is enabled"),
	"security-tools.filevault":      hasText("filevault is on"),
	"kernel.nvram-boot-args":        func(v string) bool { return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "boot-args")) == "" },
	"accounts.autologin":            func(v string) bool { return strings.TrimSpace(v) == "" },
	"accounts.guest":                func(v string) bool { v = strings.TrimSpace(v); return v == "" || v == "0" },
}

func hasText(sub string) func(string) bool {
	return func(v string) bool { return strings.Contains(strings.ToLower(v), sub) }
}
