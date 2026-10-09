package baseline

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
)

// what describes each snapshotted check for human-readable output, and how serious an
// addition (or a changed setting) is.
type meta struct {
	label    string
	addedSev output.Severity
	fix      string
}

var metas = map[string]meta{
	"triage.sip":                       {"System Integrity Protection", output.SeverityHigh, "Re-enable SIP from Recovery: csrutil enable"},
	"triage.sip-authenticated-root":    {"Signed system volume", output.SeverityHigh, "Re-enable from Recovery: csrutil authenticated-root enable"},
	"triage.gatekeeper":                {"Gatekeeper", output.SeverityHigh, "Run: sudo spctl --global-enable"},
	"network.firewall":                 {"Application firewall", output.SeverityMedium, "Check System Settings > Network > Firewall"},
	"security-tools.filevault":         {"FileVault", output.SeverityMedium, "Check System Settings > Privacy & Security > FileVault"},
	"kernel.nvram-boot-args":           {"NVRAM boot-args", output.SeverityHigh, "Inspect with nvram boot-args; clear with sudo nvram -d boot-args"},
	"harden.auto-update-settings":      {"Automatic update settings", output.SeverityLow, "Review System Settings > General > Software Update"},
	"triage.launchdaemons":             {"LaunchDaemon (/Library/LaunchDaemons)", output.SeverityMedium, "Inspect the plist and the program it runs; remove it if unexpected"},
	"triage.launchagents-system":       {"LaunchAgent (/Library/LaunchAgents)", output.SeverityMedium, "Inspect the plist and the program it runs; remove it if unexpected"},
	"persistence.system-launchdaemons": {"System LaunchDaemon (/System/Library)", output.SeverityHigh, "This directory is on the sealed system volume; changes outside an OS update are a red flag"},
	"persistence.launchagents-user":    {"User LaunchAgent", output.SeverityMedium, "Inspect ~/Library/LaunchAgents and the program it runs"},
	"persistence.login-items":          {"Login item", output.SeverityMedium, "Review System Settings > General > Login Items"},
	"persistence.crontab":              {"Crontab entry", output.SeverityMedium, "Run crontab -l and remove entries you did not add"},
	"processes.launchctl-dyld":         {"DYLD variable in launchd", output.SeverityHigh, "DYLD_* variables inject code into processes; find what set them"},
	"triage.kext-non-apple":            {"Non-Apple kernel extension", output.SeverityMedium, "Confirm the vendor and remove it if unexpected"},
	"kernel.kext-loaded":               {"Kernel extension", output.SeverityMedium, "Confirm the vendor and remove it if unexpected"},
	"kernel.system-extensions":         {"System extension", output.SeverityMedium, "Review with systemextensionsctl list"},
	"network.listening-tcp":            {"TCP listener", output.SeverityMedium, "Identify the process with lsof -iTCP -sTCP:LISTEN"},
	"network.listening-udp":            {"UDP listener", output.SeverityMedium, "Identify the process with lsof -iUDP"},
	"network.dns":                      {"DNS server", output.SeverityMedium, "Check network settings; unexpected resolvers can redirect traffic"},
}

// Result is the outcome of comparing two snapshots.
type Result struct {
	Findings      []output.Finding
	Compared      int      // checks present in both snapshots
	NotComparable []string // check ids present in only one, or with differing kinds
}

// Compare diffs old against cur. Items added since the baseline are findings whose
// severity depends on the kind of item; removals are informational; a changed setting is
// a finding. Differences in host or macOS version are reported as info so that Apple's own
// changes after an update are not mistaken for tampering.
func Compare(old, cur Snapshot) Result {
	var res Result
	if old.Host.MacOSVersion != cur.Host.MacOSVersion && old.Host.MacOSVersion != "" {
		res.Findings = append(res.Findings, output.Finding{
			ID: "baseline.macos-version", CheckID: "baseline", Status: output.StatusInfo,
			Title:  fmt.Sprintf("macOS version changed: %s -> %s", old.Host.MacOSVersion, cur.Host.MacOSVersion),
			Detail: "Changes to system-owned items (extensions, system daemons, settings) are expected after an update.",
		})
	}
	if old.Host.Hostname != cur.Host.Hostname && old.Host.Hostname != "" && cur.Host.Hostname != "" {
		res.Findings = append(res.Findings, output.Finding{
			ID: "baseline.hostname", CheckID: "baseline", Status: output.StatusInfo,
			Title: fmt.Sprintf("Host name differs: %q vs %q", old.Host.Hostname, cur.Host.Hostname),
		})
	}
	if old.SudoEnabled != cur.SudoEnabled {
		res.Findings = append(res.Findings, output.Finding{
			ID: "baseline.sudo", CheckID: "baseline", Status: output.StatusInfo,
			Title: "Snapshots were taken with different sudo settings; privileged checks are not comparable",
		})
	}

	ids := make([]string, 0, len(old.Checks)+len(cur.Checks))
	seen := map[string]bool{}
	for id := range old.Checks {
		ids, seen[id] = append(ids, id), true
	}
	for id := range cur.Checks {
		if !seen[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	for _, id := range ids {
		o, inOld := old.Checks[id]
		c, inCur := cur.Checks[id]
		if !inOld || !inCur || o.Kind != c.Kind {
			res.NotComparable = append(res.NotComparable, id)
			continue
		}
		res.Compared++
		m, ok := metas[id]
		if !ok {
			m = meta{label: id, addedSev: output.SeverityMedium}
		}
		if c.Kind == KindState {
			res.Findings = append(res.Findings, diffState(id, m, o, c)...)
		} else {
			res.Findings = append(res.Findings, diffSet(id, m, o, c)...)
		}
	}
	return res
}

func diffState(id string, m meta, o, c Entry) []output.Finding {
	ov, cv := strings.Join(o.Items, "; "), strings.Join(c.Items, "; ")
	if ov == cv {
		return nil
	}
	if good, ok := goodState[id]; ok && good(cv) && !good(ov) {
		return []output.Finding{{
			ID: id, CheckID: id, Status: output.StatusInfo,
			Title:  m.label + " improved since baseline",
			Detail: fmt.Sprintf("was: %s\nnow: %s", ov, cv),
		}}
	}
	return []output.Finding{{
		ID: id, CheckID: id, Status: output.StatusFail, Severity: m.addedSev,
		Title:       m.label + " changed since baseline",
		Detail:      fmt.Sprintf("was: %s\nnow: %s", ov, cv),
		Remediation: m.fix,
	}}
}

func diffSet(id string, m meta, o, c Entry) []output.Finding {
	added, removed := setDiff(o.Items, c.Items)
	var out []output.Finding
	if len(added) > 0 {
		out = append(out, output.Finding{
			ID: id, CheckID: id, Status: output.StatusFail, Severity: m.addedSev,
			Title:       fmt.Sprintf("%d new since baseline: %s", len(added), m.label),
			Detail:      "+ " + strings.Join(added, "\n+ "),
			Remediation: m.fix,
		})
	}
	if len(removed) > 0 {
		out = append(out, output.Finding{
			ID: id, CheckID: id, Status: output.StatusInfo,
			Title:  fmt.Sprintf("%d removed since baseline: %s", len(removed), m.label),
			Detail: "- " + strings.Join(removed, "\n- "),
		})
	}
	return out
}

// setDiff returns items only in cur (added) and only in old (removed). Inputs are sorted.
func setDiff(old, cur []string) (added, removed []string) {
	have := map[string]bool{}
	for _, v := range old {
		have[v] = true
	}
	now := map[string]bool{}
	for _, v := range cur {
		now[v] = true
		if !have[v] {
			added = append(added, v)
		}
	}
	for _, v := range old {
		if !now[v] {
			removed = append(removed, v)
		}
	}
	return added, removed
}
