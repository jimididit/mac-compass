// Package findings turns raw check output into judged findings (pass/fail with severity).
// Evaluators are pure functions of a CheckResult, so they are tested against captured
// real-world output without needing a Mac.
package findings

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
)

// evaluator interprets one check's result. It leaves Finding.CheckID unset.
type evaluator func(r output.CheckResult) []output.Finding

var evaluators = map[string]evaluator{
	"triage.sip":                    evalSIP,
	"triage.sip-authenticated-root": evalAuthRoot,
	"triage.gatekeeper":             evalGatekeeper,
	"triage.kext-non-apple":         evalNonAppleKexts,
	"triage.launchdaemons":          evalThirdPartyPlists("system LaunchDaemons (/Library/LaunchDaemons)", "Review each daemon: it runs as root at boot."),
	"triage.launchagents-system":    evalThirdPartyPlists("system LaunchAgents (/Library/LaunchAgents)", "Review each agent: it runs at user login."),
	"processes.launchctl-dyld":      evalDYLD,
	"kernel.system-extensions":      evalSystemExtensions,
	"kernel.nvram-boot-args":        evalBootArgs,
	"persistence.crontab":           evalCrontab,
	"network.listening-tcp":         evalListeningTCP,
	"network.firewall":              evalFirewall,
	"security-tools.filevault":      evalFileVault,
	"harden.softwareupdate-list":    evalSoftwareUpdate,
	"harden.auto-update-settings":   evalAutoUpdate,
}

// HasEvaluator reports whether a check id has a findings evaluator.
func HasEvaluator(id string) bool { _, ok := evaluators[id]; return ok }

// Evaluate converts check results into findings, sorted most severe first.
// A check that failed to run yields an error finding; skipped checks yield nothing.
func Evaluate(sections []output.SectionResult) []output.Finding {
	var out []output.Finding
	for _, sec := range sections {
		for _, r := range sec.Checks {
			if r.Skipped {
				continue
			}
			if !r.Ok {
				out = append(out, output.Finding{
					ID: r.ID, CheckID: r.ID, Status: output.StatusError, Attack: r.Attack,
					Title:       fmt.Sprintf("Check %q could not run", r.Name),
					Detail:      strings.TrimSpace(r.Error + " " + firstLine(r.Stderr)),
					Remediation: errorHint(r),
				})
				continue
			}
			ev, ok := evaluators[r.ID]
			if !ok {
				continue
			}
			for _, f := range ev(r) {
				f.CheckID = r.ID
				f.Attack = r.Attack
				out = append(out, f)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return order(out[i]) > order(out[j]) })
	return out
}

// errorHint explains the usual cause of a check failing to run, when we know it.
func errorHint(r output.CheckResult) string {
	text := strings.ToLower(r.Error + " " + r.Stderr)
	switch {
	case strings.HasPrefix(r.ID, "security-tools.tcc-") && (strings.Contains(text, "authorization denied") || strings.Contains(text, "unable to open database")):
		return "The privacy database is protected. Give your terminal app Full Disk Access (System Settings > Privacy & Security > Full Disk Access), quit and reopen it, and run again."
	case strings.Contains(text, "timeout after"):
		return "The check took too long and was stopped. Run again; if it keeps timing out, raise --timeout."
	case strings.Contains(text, "operation not permitted"):
		return "macOS blocked access. Grant your terminal app Full Disk Access in System Settings > Privacy & Security."
	}
	return ""
}

// order ranks findings: fails by severity, then errors, then info, then pass.
func order(f output.Finding) int {
	switch f.Status {
	case output.StatusFail:
		return 100 + f.Severity.Rank()
	case output.StatusError:
		return 50
	case output.StatusInfo:
		return 10
	}
	return 0
}

func pass(id, title string) output.Finding {
	return output.Finding{ID: id, Status: output.StatusPass, Title: title}
}

func fail(id string, sev output.Severity, title, detail, fix string) output.Finding {
	return output.Finding{ID: id, Status: output.StatusFail, Severity: sev, Title: title, Detail: detail, Remediation: fix}
}

func info(id, title, detail string) output.Finding {
	return output.Finding{ID: id, Status: output.StatusInfo, Title: title, Detail: detail}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
