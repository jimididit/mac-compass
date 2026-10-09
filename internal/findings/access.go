package findings

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
)

func init() {
	for id, ev := range map[string]evaluator{
		"accounts.local-users":            evalLocalUsers,
		"accounts.admin-group":            evalAdminGroup,
		"accounts.guest":                  evalGuest,
		"accounts.autologin":              evalAutoLogin,
		"accounts.ssh-authorized-keys":    evalAuthorizedKeys,
		"persistence.login-hooks":         evalLoginHooks,
		"persistence.hosts":               evalHosts,
		"persistence.sudoers-d":           evalSudoersD,
		"network.proxy":                   evalProxy,
		"security-tools.xprotect-version": evalXProtect,
		"security-tools.profiles":         evalProfiles,
		"security-tools.mdm-enrollment":   evalMDM,
		"security-tools.tcc-system":       evalTCC("system-wide"),
		"security-tools.tcc-user":         evalTCC("this user"),
	} {
		evaluators[id] = ev
	}
}

// evalLocalUsers reads `dscl . -list /Users UniqueID` rows ("name   uid").
func evalLocalUsers(r output.CheckResult) []output.Finding {
	var human, extraRoot []string
	for _, l := range lines(r.Stdout) {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		uid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		switch {
		case uid == 0 && f[0] != "root":
			extraRoot = append(extraRoot, f[0])
		case uid >= 500 && !strings.HasPrefix(f[0], "_"):
			human = append(human, f[0])
		}
	}
	var out []output.Finding
	if len(extraRoot) > 0 {
		out = append(out, fail("accounts.local-users", output.SeverityHigh,
			"Extra account with root privileges (uid 0): "+strings.Join(extraRoot, ", "),
			"Only 'root' should have uid 0. A second uid 0 account is a common backdoor.",
			"Investigate with: dscl . -read /Users/<name>; remove it if you did not create it."))
	}
	if len(human) > 0 {
		out = append(out, info("accounts.local-users", fmt.Sprintf("%d local user account(s)", len(human)), strings.Join(human, "\n")))
	} else if len(extraRoot) == 0 {
		out = append(out, pass("accounts.local-users", "No local user accounts found beyond system accounts"))
	}
	return out
}

func evalAdminGroup(r output.CheckResult) []output.Finding {
	_, rest, ok := strings.Cut(r.Stdout, "GroupMembership:")
	if !ok {
		return []output.Finding{info("accounts.admin-group", "Admin group membership not recognised", firstLine(r.Stdout))}
	}
	var admins []string
	for _, m := range strings.Fields(rest) {
		if m != "root" {
			admins = append(admins, m)
		}
	}
	return []output.Finding{info("accounts.admin-group", fmt.Sprintf("%d administrator account(s) besides root", len(admins)), strings.Join(admins, "\n"))}
}

func evalGuest(r output.CheckResult) []output.Finding {
	if strings.TrimSpace(r.Stdout) == "1" {
		return []output.Finding{fail("accounts.guest", output.SeverityMedium, "Guest account is enabled",
			"Anyone can log in without a password.", "Turn off in System Settings > Users & Groups > Guest User.")}
	}
	return []output.Finding{pass("accounts.guest", "Guest account is disabled")}
}

func evalAutoLogin(r output.CheckResult) []output.Finding {
	if u := strings.TrimSpace(r.Stdout); u != "" {
		return []output.Finding{fail("accounts.autologin", output.SeverityMedium, "Automatic login is on for "+u,
			"The Mac logs in without a password at boot, so physical access means full access.",
			"Turn off in System Settings > Users & Groups > Automatically log in as.")}
	}
	return []output.Finding{pass("accounts.autologin", "Automatic login is off")}
}

func evalAuthorizedKeys(r output.CheckResult) []output.Finding {
	keys := lines(r.Stdout)
	if len(keys) == 0 {
		return []output.Finding{pass("accounts.ssh-authorized-keys", "No SSH authorized keys for this user")}
	}
	return []output.Finding{info("accounts.ssh-authorized-keys",
		fmt.Sprintf("%d SSH authorized key(s) can log in as this user", len(keys)),
		strings.Join(keys, "\n")+"\nConfirm you recognise every key; an unknown key is a persistent remote-access backdoor.")}
}

func evalLoginHooks(r output.CheckResult) []output.Finding {
	hooks := lines(r.Stdout)
	if len(hooks) == 0 {
		return []output.Finding{pass("persistence.login-hooks", "No login or logout hooks")}
	}
	return []output.Finding{fail("persistence.login-hooks", output.SeverityHigh, "Login/logout hook is configured",
		strings.Join(hooks, "\n")+"\nThese run a script as root at every login or logout and are deprecated; legitimate use is rare.",
		"Remove with: sudo defaults delete com.apple.loginwindow LoginHook (or LogoutHook)")}
}

var defaultHosts = map[string]bool{"127.0.0.1 localhost": true, "255.255.255.255 broadcasthost": true, "::1 localhost": true}

func evalHosts(r output.CheckResult) []output.Finding {
	var extra []string
	for _, l := range lines(r.Stdout) {
		if !defaultHosts[strings.Join(strings.Fields(l), " ")] {
			extra = append(extra, l)
		}
	}
	if len(extra) == 0 {
		return []output.Finding{pass("persistence.hosts", "/etc/hosts has only default entries")}
	}
	return []output.Finding{fail("persistence.hosts", output.SeverityLow,
		fmt.Sprintf("%d custom /etc/hosts entr(ies)", len(extra)), strings.Join(extra, "\n"),
		"Entries can redirect domains (for example to block telemetry or to hijack a site); remove any you did not add.")}
}

func evalSudoersD(r output.CheckResult) []output.Finding {
	var files []string
	for _, l := range lines(r.Stdout) {
		if !strings.EqualFold(l, "README") {
			files = append(files, l)
		}
	}
	if len(files) == 0 {
		return []output.Finding{pass("persistence.sudoers-d", "No custom sudoers drop-ins")}
	}
	return []output.Finding{fail("persistence.sudoers-d", output.SeverityLow,
		fmt.Sprintf("%d custom sudoers drop-in file(s)", len(files)), strings.Join(files, "\n"),
		"Review with: sudo cat /etc/sudoers.d/<file>. A NOPASSWD rule grants root without a password.")}
}

var proxyEnabled = regexp.MustCompile(`(?m)^\s*(HTTP|HTTPS|SOCKS|FTP|RTSP|Gopher|ProxyAutoConfig|ProxyAutoDiscovery)Enable : 1\s*$`)
var proxyHost = regexp.MustCompile(`(?m)^\s*(HTTP|HTTPS|SOCKS|FTP|RTSP|Gopher)Proxy : (\S+)\s*$`)
var pacURL = regexp.MustCompile(`(?m)^\s*ProxyAutoConfigURLString : (\S+)\s*$`)

func evalProxy(r output.CheckResult) []output.Finding {
	enabled := proxyEnabled.FindAllStringSubmatch(r.Stdout, -1)
	if len(enabled) == 0 {
		return []output.Finding{pass("network.proxy", "No system proxy is configured")}
	}
	var detail []string
	for _, m := range enabled {
		detail = append(detail, m[1]+" enabled")
	}
	for _, m := range proxyHost.FindAllStringSubmatch(r.Stdout, -1) {
		detail = append(detail, m[1]+" proxy: "+m[2])
	}
	for _, m := range pacURL.FindAllStringSubmatch(r.Stdout, -1) {
		detail = append(detail, "PAC URL: "+m[1])
	}
	return []output.Finding{fail("network.proxy", output.SeverityLow, "A system proxy is configured",
		strings.Join(detail, "\n")+"\nA proxy sees (and can alter) traffic. Expected on managed networks; otherwise suspicious.",
		"Review System Settings > Network > (your connection) > Details > Proxies.")}
}

func evalXProtect(r output.CheckResult) []output.Finding {
	if v := strings.TrimSpace(r.Stdout); v != "" {
		return []output.Finding{info("security-tools.xprotect-version", "XProtect malware signatures version "+v, "")}
	}
	return []output.Finding{info("security-tools.xprotect-version", "XProtect version could not be read", firstLine(r.Stderr))}
}

func evalProfiles(r output.CheckResult) []output.Finding {
	out := strings.TrimSpace(r.Stdout + "\n" + r.Stderr)
	if out == "" || strings.Contains(strings.ToLower(out), "no configuration profiles") {
		return []output.Finding{pass("security-tools.profiles", "No configuration profiles are installed")}
	}
	return []output.Finding{info("security-tools.profiles", "Configuration profiles are installed", out+"\nProfiles can set proxies, certificates, VPNs and restrictions; confirm each is expected.")}
}

func evalMDM(r output.CheckResult) []output.Finding {
	out := strings.ToLower(r.Stdout)
	if strings.Contains(out, "mdm enrollment: yes") || strings.Contains(out, "enrolled via dep: yes") {
		return []output.Finding{info("security-tools.mdm-enrollment", "This Mac is enrolled in device management (MDM)", strings.TrimSpace(r.Stdout)+"\nAn MDM server can install software and change settings remotely.")}
	}
	return []output.Finding{pass("security-tools.mdm-enrollment", "This Mac is not enrolled in MDM")}
}

var tccService = map[string]string{
	"kTCCServiceSystemPolicyAllFiles":   "Full Disk Access",
	"kTCCServiceAccessibility":          "Accessibility (control the computer)",
	"kTCCServiceScreenCapture":          "Screen Recording",
	"kTCCServiceListenEvent":            "Input Monitoring (keylogging)",
	"kTCCServicePostEvent":              "Send keystrokes",
	"kTCCServiceEndpointSecurityClient": "Endpoint Security",
}

// evalTCC reads rows of "service|client|client_type"; client_type 1 means the grant is to
// a bare path rather than a signed bundle, which is how scripts and dropped binaries get access.
func evalTCC(scope string) evaluator {
	return func(r output.CheckResult) []output.Finding {
		id := r.ID
		var byPath, bundles []string
		for _, l := range lines(r.Stdout) {
			p := strings.Split(l, "|")
			if len(p) != 3 {
				continue
			}
			name := tccService[p[0]]
			if name == "" {
				name = p[0]
			}
			row := fmt.Sprintf("%s: %s", name, p[1])
			if p[2] == "1" {
				byPath = append(byPath, row)
			} else {
				bundles = append(bundles, row)
			}
		}
		var out []output.Finding
		if len(byPath) > 0 {
			out = append(out, fail(id, output.SeverityMedium,
				fmt.Sprintf("%d binary(ies) granted sensitive privacy access by path (%s)", len(byPath), scope),
				strings.Join(byPath, "\n"),
				"Grants to bare paths (not signed apps) are unusual. Review in System Settings > Privacy & Security and remove any you do not recognise."))
		}
		if len(bundles) > 0 {
			out = append(out, info(id, fmt.Sprintf("%d app(s) hold sensitive privacy permissions (%s)", len(bundles), scope), strings.Join(bundles, "\n")))
		}
		if len(out) == 0 {
			out = append(out, pass(id, "No apps hold the monitored privacy permissions ("+scope+")"))
		}
		return out
	}
}
