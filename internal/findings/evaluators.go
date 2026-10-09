package findings

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
)

func evalSIP(r output.CheckResult) []output.Finding {
	out := strings.ToLower(r.Stdout)
	switch {
	case strings.Contains(out, "status: enabled") && !strings.Contains(out, "custom"):
		return []output.Finding{pass("triage.sip", "System Integrity Protection is enabled")}
	case strings.Contains(out, "status: disabled"):
		return []output.Finding{fail("triage.sip", output.SeverityHigh, "System Integrity Protection is disabled",
			"SIP protects system files and processes from modification, even by root. Malware commonly disables it.",
			"Boot to Recovery, open Terminal and run: csrutil enable")}
	case strings.Contains(out, "custom") || strings.Contains(out, "unknown"):
		return []output.Finding{fail("triage.sip", output.SeverityMedium, "System Integrity Protection is partially configured",
			firstLine(r.Stdout), "Boot to Recovery and run: csrutil enable")}
	}
	return []output.Finding{info("triage.sip", "SIP status not recognised", firstLine(r.Stdout))}
}

func evalAuthRoot(r output.CheckResult) []output.Finding {
	out := strings.ToLower(r.Stdout)
	switch {
	case strings.Contains(out, "status: enabled"):
		return []output.Finding{pass("triage.sip-authenticated-root", "Signed system volume is enabled")}
	case strings.Contains(out, "status: disabled"):
		return []output.Finding{fail("triage.sip-authenticated-root", output.SeverityMedium, "Signed system volume (authenticated root) is disabled",
			"The sealed system volume is not verified at boot, so system files can be altered unnoticed.",
			"Boot to Recovery and run: csrutil authenticated-root enable")}
	}
	return []output.Finding{info("triage.sip-authenticated-root", "Authenticated root status not recognised", firstLine(r.Stdout))}
}

func evalGatekeeper(r output.CheckResult) []output.Finding {
	out := strings.ToLower(r.Stdout)
	switch {
	case strings.Contains(out, "assessments enabled"):
		return []output.Finding{pass("triage.gatekeeper", "Gatekeeper is enabled")}
	case strings.Contains(out, "assessments disabled"):
		return []output.Finding{fail("triage.gatekeeper", output.SeverityHigh, "Gatekeeper is disabled",
			"Apps are not checked for notarization or developer signatures before they run.",
			"Run: sudo spctl --global-enable")}
	}
	return []output.Finding{info("triage.gatekeeper", "Gatekeeper status not recognised", firstLine(r.Stdout))}
}

// kmutil showloaded prints a header row; every other line is a loaded extension.
func evalNonAppleKexts(r output.CheckResult) []output.Finding {
	var kexts []string
	for _, l := range lines(r.Stdout) {
		if strings.HasPrefix(l, "Index") {
			continue
		}
		kexts = append(kexts, l)
	}
	if len(kexts) == 0 {
		return []output.Finding{pass("triage.kext-non-apple", "No non-Apple kernel extensions are loaded")}
	}
	return []output.Finding{fail("triage.kext-non-apple", output.SeverityMedium,
		fmt.Sprintf("%d non-Apple kernel extension(s) loaded", len(kexts)),
		strings.Join(kexts, "\n"),
		"Confirm each extension is expected and from a trusted vendor; remove any you do not recognise.")}
}

func evalDYLD(r output.CheckResult) []output.Finding {
	if strings.TrimSpace(r.Stdout) == "" {
		return []output.Finding{pass("processes.launchctl-dyld", "No DYLD_* variables set in the launchd system domain")}
	}
	return []output.Finding{fail("processes.launchctl-dyld", output.SeverityHigh,
		"DYLD_* variables are set in the launchd system domain",
		strings.TrimSpace(r.Stdout),
		"DYLD_INSERT_LIBRARIES and friends inject code into every process; find and remove whatever sets them.")}
}

var extCount = regexp.MustCompile(`(\d+) extension\(s\)`)

func evalSystemExtensions(r output.CheckResult) []output.Finding {
	m := extCount.FindStringSubmatch(r.Stdout)
	if m == nil {
		return []output.Finding{info("kernel.system-extensions", "System extension list not recognised", firstLine(r.Stdout))}
	}
	if m[1] == "0" {
		return []output.Finding{pass("kernel.system-extensions", "No system extensions installed")}
	}
	return []output.Finding{info("kernel.system-extensions", m[1]+" system extension(s) installed", strings.TrimSpace(r.Stdout))}
}

// Boot-args that weaken code-signing or kernel protections.
var dangerousBootArgs = []string{"amfi_get_out_of_my_way", "cs_enforcement_disable", "amfi=", "kext-dev-mode", "rootless=0", "-arm64e_preview_abi"}

func evalBootArgs(r output.CheckResult) []output.Finding {
	val := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r.Stdout), "boot-args"))
	if val == "" {
		return []output.Finding{pass("kernel.nvram-boot-args", "No NVRAM boot-args set")}
	}
	for _, bad := range dangerousBootArgs {
		if strings.Contains(val, bad) {
			return []output.Finding{fail("kernel.nvram-boot-args", output.SeverityHigh,
				"Boot-args weaken system security: "+val,
				"These flags disable code-signing enforcement or kernel protections.",
				"Run: sudo nvram -d boot-args  (then reboot)")}
		}
	}
	return []output.Finding{fail("kernel.nvram-boot-args", output.SeverityLow, "Custom NVRAM boot-args set: "+val,
		"Non-default boot arguments are unusual on a production Mac.", "Run: sudo nvram -d boot-args  (unless you set it deliberately)")}
}

func evalCrontab(r output.CheckResult) []output.Finding {
	var entries []string
	for _, l := range lines(r.Stdout) {
		if !strings.HasPrefix(l, "#") {
			entries = append(entries, l)
		}
	}
	if len(entries) == 0 {
		return []output.Finding{pass("persistence.crontab", "No crontab entries for this user")}
	}
	return []output.Finding{fail("persistence.crontab", output.SeverityLow,
		fmt.Sprintf("%d crontab entr(ies) for this user", len(entries)),
		strings.Join(entries, "\n"), "cron is an old persistence mechanism; confirm each entry is yours.")}
}

var tcpRow = regexp.MustCompile(`^(\S+)\s+(\d+)\s+(\S+)\s+.*TCP\s+(\S+):(\d+) \(LISTEN\)`)

// remoteAccessPorts are services that expose the Mac to remote control.
var remoteAccessPorts = map[string]string{"22": "Remote Login (SSH)", "5900": "Screen Sharing (VNC)", "3283": "Apple Remote Desktop", "445": "SMB file sharing", "548": "AFP file sharing"}

func evalListeningTCP(r output.CheckResult) []output.Finding {
	type listener struct{ proc, user, addr, port string }
	var external []listener
	seen := map[string]bool{}
	for _, l := range lines(r.Stdout) {
		m := tcpRow.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		addr, port := m[4], m[5]
		if addr == "127.0.0.1" || addr == "localhost" || addr == "[::1]" || addr == "::1" {
			continue
		}
		key := m[1] + addr + port
		if seen[key] {
			continue
		}
		seen[key] = true
		external = append(external, listener{m[1], m[3], addr, port})
	}
	if len(external) == 0 {
		return []output.Finding{pass("network.listening-tcp", "No TCP services listen on external interfaces")}
	}
	var out []output.Finding
	var rest []string
	reported := map[string]bool{}
	for _, l := range external {
		desc := fmt.Sprintf("%s (user %s) on %s:%s", l.proc, l.user, l.addr, l.port)
		if name, ok := remoteAccessPorts[l.port]; ok {
			if reported[l.port] {
				continue
			}
			reported[l.port] = true
			out = append(out, fail("network.listening-tcp", output.SeverityLow, name+" is reachable on the network", desc,
				"If you do not use this service, turn it off in System Settings > General > Sharing."))
			continue
		}
		rest = append(rest, desc)
	}
	if len(rest) > 0 {
		out = append(out, info("network.listening-tcp", fmt.Sprintf("%d other TCP listener(s) on external interfaces", len(rest)), strings.Join(rest, "\n")))
	}
	return out
}

func evalFirewall(r output.CheckResult) []output.Finding {
	out := strings.ToLower(r.Stdout)
	switch {
	case strings.Contains(out, "firewall is disabled"):
		return []output.Finding{fail("network.firewall", output.SeverityMedium, "Application firewall is off",
			"Incoming connections to apps are not filtered.",
			"Enable in System Settings > Network > Firewall, or: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on")}
	case strings.Contains(out, "firewall is enabled"), strings.Contains(out, "state = 1"), strings.Contains(out, "state = 2"):
		return []output.Finding{pass("network.firewall", "Application firewall is on")}
	}
	return []output.Finding{info("network.firewall", "Firewall state not recognised", firstLine(r.Stdout))}
}

func evalFileVault(r output.CheckResult) []output.Finding {
	out := strings.ToLower(r.Stdout)
	switch {
	case strings.Contains(out, "filevault is on"):
		return []output.Finding{pass("security-tools.filevault", "FileVault disk encryption is on")}
	case strings.Contains(out, "filevault is off"):
		return []output.Finding{fail("security-tools.filevault", output.SeverityMedium, "FileVault disk encryption is off",
			"Anyone with physical access can read the disk.", "Enable in System Settings > Privacy & Security > FileVault.")}
	}
	return []output.Finding{info("security-tools.filevault", "FileVault state not recognised", firstLine(r.Stdout))}
}

var updateLabel = regexp.MustCompile(`(?m)^\* Label: (.+)$`)
var updateRecommended = regexp.MustCompile(`Title: ([^,]+), Version: ([^,]+),.*Recommended: YES`)

func evalSoftwareUpdate(r output.CheckResult) []output.Finding {
	labels := updateLabel.FindAllStringSubmatch(r.Stdout, -1)
	if len(labels) == 0 {
		// softwareupdate prints "No new software available." to stderr on some macOS releases.
		if strings.Contains(r.Stdout+" "+r.Stderr, "No new software available") {
			return []output.Finding{pass("harden.softwareupdate-list", "macOS is up to date")}
		}
		return []output.Finding{info("harden.softwareupdate-list", "Update list not recognised", firstLine(r.Stdout))}
	}
	var names []string
	for _, m := range updateRecommended.FindAllStringSubmatch(r.Stdout, -1) {
		names = append(names, m[1]+" "+m[2])
	}
	if len(names) == 0 {
		for _, l := range labels {
			names = append(names, l[1])
		}
	}
	return []output.Finding{fail("harden.softwareupdate-list", output.SeverityLow,
		fmt.Sprintf("%d software update(s) available", len(labels)), strings.Join(names, "\n"),
		"Install in System Settings > General > Software Update.")}
}

func plistValue(s, key string) (string, bool) {
	m := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + ` = (\S+);`).FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func evalAutoUpdate(r output.CheckResult) []output.Finding {
	var off []string
	for _, key := range []string{"CriticalUpdateInstall", "ConfigDataInstall"} {
		if v, ok := plistValue(r.Stdout, key); ok && v == "0" {
			off = append(off, key)
		}
	}
	if len(off) == 0 {
		return []output.Finding{pass("harden.auto-update-settings", "Automatic security and system-data updates are on")}
	}
	return []output.Finding{fail("harden.auto-update-settings", output.SeverityLow,
		"Automatic security updates are off ("+strings.Join(off, ", ")+")",
		"Security responses and system data files (for example XProtect definitions) will not install automatically.",
		"Turn on 'Install Security Responses and system files' in System Settings > General > Software Update > Automatic Updates.")}
}

var plistName = regexp.MustCompile(`\s(\S+\.plist)\s*$`)

// evalThirdPartyPlists lists launchd plists in an `ls -la` listing that are not Apple's.
func evalThirdPartyPlists(label, fix string) evaluator {
	return func(r output.CheckResult) []output.Finding {
		var third []string
		for _, l := range lines(r.Stdout) {
			m := plistName.FindStringSubmatch(l)
			if m == nil || strings.HasPrefix(m[1], "com.apple.") {
				continue
			}
			third = append(third, m[1])
		}
		if len(third) == 0 {
			return []output.Finding{pass(r.ID, "No third-party items in "+label)}
		}
		f := info(r.ID, fmt.Sprintf("%d third-party item(s) in %s", len(third), label), strings.Join(third, "\n"))
		f.Remediation = fix
		return []output.Finding{f}
	}
}
