package baseline

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
)

func init() {
	for id, ex := range map[string]extractor{
		"accounts.local-users":            {KindSet, localUsers},
		"accounts.admin-group":            {KindSet, adminMembers},
		"accounts.guest":                  {KindState, firstLine},
		"accounts.autologin":              {KindState, firstLine},
		"accounts.ssh-authorized-keys":    {KindSet, allLines},
		"persistence.shell-rc":            {KindSet, allLines},
		"persistence.login-hooks":         {KindSet, allLines},
		"persistence.hosts":               {KindSet, normalizedLines},
		"persistence.sudoers-d":           {KindSet, allLines},
		"network.proxy":                   {KindSet, proxyLines},
		"security-tools.xprotect-version": {KindState, firstLine},
		"security-tools.profiles":         {KindSet, allLines},
		"security-tools.mdm-enrollment":   {KindState, joinedLines},
		"security-tools.tcc-system":       {KindSet, allLines},
		"security-tools.tcc-user":         {KindSet, allLines},
	} {
		extractors[id] = ex
	}
	for id, m := range map[string]meta{
		"accounts.local-users":            {"Local account", output.SeverityHigh, "Review with dscl . -list /Users; remove accounts you did not create"},
		"accounts.admin-group":            {"Administrator account", output.SeverityHigh, "Review with dscl . -read /Groups/admin GroupMembership"},
		"accounts.guest":                  {"Guest account setting", output.SeverityMedium, "System Settings > Users & Groups"},
		"accounts.autologin":              {"Automatic login setting", output.SeverityMedium, "System Settings > Users & Groups"},
		"accounts.ssh-authorized-keys":    {"SSH authorized key", output.SeverityHigh, "Remove unknown keys from ~/.ssh/authorized_keys"},
		"persistence.shell-rc":            {"Shell startup file (hash)", output.SeverityMedium, "Diff the file against a known-good copy; shell startup files run code in every terminal"},
		"persistence.login-hooks":         {"Login/logout hook", output.SeverityHigh, "sudo defaults delete com.apple.loginwindow LoginHook"},
		"persistence.hosts":               {"Hosts file entry", output.SeverityMedium, "Review /etc/hosts"},
		"persistence.sudoers-d":           {"Sudoers drop-in", output.SeverityHigh, "Review /etc/sudoers.d; a NOPASSWD rule grants root without a password"},
		"network.proxy":                   {"Proxy setting", output.SeverityMedium, "System Settings > Network > Details > Proxies"},
		"security-tools.xprotect-version": {"XProtect version", output.SeverityLow, "Update macOS; XProtect updates ship with system data updates"},
		"security-tools.profiles":         {"Configuration profile", output.SeverityHigh, "Review in System Settings > Privacy & Security > Profiles"},
		"security-tools.mdm-enrollment":   {"MDM enrollment", output.SeverityHigh, "Run profiles status -type enrollment"},
		"security-tools.tcc-system":       {"System privacy grant", output.SeverityHigh, "Review System Settings > Privacy & Security"},
		"security-tools.tcc-user":         {"User privacy grant", output.SeverityHigh, "Review System Settings > Privacy & Security"},
	} {
		metas[id] = m
	}
}

// localUsers keeps human accounts (uid >= 500, not _service) plus any uid 0 account.
func localUsers(r output.CheckResult) []string {
	var out []string
	for _, l := range nonEmptyLines(r.Stdout) {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		uid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		if uid == 0 || (uid >= 500 && !strings.HasPrefix(f[0], "_")) {
			out = append(out, f[0]+" "+f[1])
		}
	}
	return out
}

func adminMembers(r output.CheckResult) []string {
	_, rest, ok := strings.Cut(r.Stdout, "GroupMembership:")
	if !ok {
		return nil
	}
	return strings.Fields(rest)
}

func normalizedLines(r output.CheckResult) []string {
	var out []string
	for _, l := range nonEmptyLines(r.Stdout) {
		out = append(out, strings.Join(strings.Fields(l), " "))
	}
	return out
}

func joinedLines(r output.CheckResult) []string {
	return []string{strings.Join(normalizedLines(r), "; ")}
}

var proxyKey = regexp.MustCompile(`^(\w+(Enable|Proxy|Port)|ProxyAutoConfigURLString) : (.+)$`)

// proxyLines keeps proxy switches, hosts and ports; scutil also prints interface noise.
func proxyLines(r output.CheckResult) []string {
	var out []string
	for _, l := range nonEmptyLines(r.Stdout) {
		if proxyKey.MatchString(l) {
			out = append(out, l)
		}
	}
	return out
}
