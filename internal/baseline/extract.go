package baseline

import (
	"regexp"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
)

type extractor struct {
	kind Kind
	fn   func(output.CheckResult) []string
}

// extractors maps check ids to the function that normalizes their output. Anything that
// changes on every run (pids, addresses, timestamps, sizes) must be stripped here.
var extractors = map[string]extractor{
	"triage.sip":                    {KindState, firstLine},
	"triage.sip-authenticated-root": {KindState, firstLine},
	"triage.gatekeeper":             {KindState, firstLine},
	"network.firewall":              {KindState, firstLine},
	"security-tools.filevault":      {KindState, firstLine},
	"kernel.nvram-boot-args":        {KindState, firstLine},
	"harden.auto-update-settings":   {KindState, autoUpdateKeys},

	"triage.launchdaemons":             {KindSet, plistNames(true)},
	"triage.launchagents-system":       {KindSet, plistNames(true)},
	"persistence.system-launchdaemons": {KindSet, plistNames(false)},
	"persistence.launchagents-user":    {KindSet, plistNames(false)},
	"persistence.login-items":          {KindSet, loginItems},
	"persistence.crontab":              {KindSet, crontabLines},
	"processes.launchctl-dyld":         {KindSet, allLines},
	"triage.kext-non-apple":            {KindSet, kexts},
	"kernel.kext-loaded":               {KindSet, kexts},
	"kernel.system-extensions":         {KindSet, systemExtensions},
	"network.listening-tcp":            {KindSet, listeners("TCP")},
	"network.listening-udp":            {KindSet, listeners("UDP")},
	"network.dns":                      {KindSet, dnsServers},
}

// HasExtractor reports whether a check contributes to snapshots.
func HasExtractor(id string) bool { _, ok := extractors[id]; return ok }

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func firstLine(r output.CheckResult) []string {
	if l := nonEmptyLines(r.Stdout); len(l) > 0 {
		return []string{strings.Join(strings.Fields(l[0]), " ")}
	}
	return []string{""}
}

func allLines(r output.CheckResult) []string { return nonEmptyLines(r.Stdout) }

var plistRe = regexp.MustCompile(`\s(\S+\.plist)\s*$`)

// plistNames extracts launchd plist file names from an `ls -l` listing, optionally
// dropping Apple's own (which change with every OS update).
func plistNames(skipApple bool) func(output.CheckResult) []string {
	return func(r output.CheckResult) []string {
		var out []string
		for _, l := range nonEmptyLines(r.Stdout) {
			m := plistRe.FindStringSubmatch(l)
			if m == nil || (skipApple && strings.HasPrefix(m[1], "com.apple.")) {
				continue
			}
			out = append(out, m[1])
		}
		return out
	}
}

func loginItems(r output.CheckResult) []string {
	var out []string
	for _, p := range strings.Split(r.Stdout, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func crontabLines(r output.CheckResult) []string {
	var out []string
	for _, l := range nonEmptyLines(r.Stdout) {
		if !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

var kextRe = regexp.MustCompile(`\s(\S+) \(([^)]*)\)`)

// kexts extracts "name (version)" from kmutil showloaded rows, skipping the header. Apple's own extensions
// are left out: macOS loads and unloads them on demand, so they come and go between two runs on an untouched
// Mac, and the same "com.apple" rule is what the non-Apple kernel extension check applies.
func kexts(r output.CheckResult) []string {
	var out []string
	for _, l := range nonEmptyLines(r.Stdout) {
		if strings.HasPrefix(l, "Index") {
			continue
		}
		if m := kextRe.FindStringSubmatch(l); m != nil && !strings.HasPrefix(m[1], "com.apple.") {
			out = append(out, m[1]+" ("+m[2]+")")
		}
	}
	return out
}

// systemExtensions keeps the rows of systemextensionsctl list that describe an extension
// (they contain a bracketed state), with whitespace normalized.
func systemExtensions(r output.CheckResult) []string {
	var out []string
	for _, l := range nonEmptyLines(r.Stdout) {
		if strings.Contains(l, "[") && strings.Contains(l, "]") && !strings.Contains(l, "teamID") {
			out = append(out, strings.Join(strings.Fields(l), " "))
		}
	}
	return out
}

var (
	tcpRe = regexp.MustCompile(`^(\S+)\s+\d+\s+(\S+)\s+.*TCP\s+(\S+):(\d+) \(LISTEN\)`)
	udpRe = regexp.MustCompile(`^(\S+)\s+\d+\s+(\S+)\s+.*UDP\s+(\S+?)(?::(\d+|\*))?(?:\s|$)`)
)

// listeners reduces lsof rows to "process user address:port", dropping pid and fd.
func listeners(proto string) func(output.CheckResult) []string {
	re := tcpRe
	if proto == "UDP" {
		re = udpRe
	}
	return func(r output.CheckResult) []string {
		var out []string
		for _, l := range nonEmptyLines(r.Stdout) {
			m := re.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			out = append(out, proto+" "+m[1]+" "+m[2]+" "+m[3]+":"+m[4])
		}
		return out
	}
}

var dnsRe = regexp.MustCompile(`nameserver\[\d+\] : (\S+)`)

func dnsServers(r output.CheckResult) []string {
	var out []string
	for _, m := range dnsRe.FindAllStringSubmatch(r.Stdout, -1) {
		out = append(out, "nameserver "+m[1])
	}
	return out
}

// autoUpdateKeys keeps only the stable on/off switches from the Software Update plist;
// the rest of it (dates, offered updates) changes constantly.
func autoUpdateKeys(r output.CheckResult) []string {
	var out []string
	for _, key := range []string{"AutomaticCheckEnabled", "AutomaticDownload", "AutomaticallyInstallMacOSUpdates", "CriticalUpdateInstall", "ConfigDataInstall"} {
		m := regexp.MustCompile(`(?m)^\s*` + key + ` = (\S+);`).FindStringSubmatch(r.Stdout)
		if m != nil {
			out = append(out, key+"="+m[1])
		}
	}
	return []string{strings.Join(out, " ")}
}
