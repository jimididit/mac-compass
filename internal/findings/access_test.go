package findings

import (
	"strings"
	"testing"

	"github.com/jimididit/mac-compass/internal/output"
)

func TestAccessEvaluators(t *testing.T) {
	cases := []struct {
		name   string
		r      output.CheckResult
		status output.Status
		sev    output.Severity
		want   string // substring of Title+Detail, optional
	}{
		{"extra uid 0", res("accounts.local-users", "_spotlight 89\nroot 0\nbackdoor 0\nalice 501\n"), output.StatusFail, output.SeverityHigh, "backdoor"},
		{"normal users", res("accounts.local-users", "_spotlight 89\nroot 0\nalice 501\nbob 502\n"), output.StatusInfo, "", "2 local user"},
		{"system only", res("accounts.local-users", "_spotlight 89\nroot 0\n"), output.StatusPass, "", ""},
		{"admins", res("accounts.admin-group", "GroupMembership: root alice\n"), output.StatusInfo, "", "alice"},
		{"admin unparsable", res("accounts.admin-group", "weird"), output.StatusInfo, "", "not recognised"},
		{"guest on", res("accounts.guest", "1\n"), output.StatusFail, output.SeverityMedium, ""},
		{"guest off", res("accounts.guest", "0\n"), output.StatusPass, "", ""},
		{"guest unset", res("accounts.guest", ""), output.StatusPass, "", ""},
		{"autologin", res("accounts.autologin", "alice\n"), output.StatusFail, output.SeverityMedium, "alice"},
		{"no autologin", res("accounts.autologin", ""), output.StatusPass, "", ""},
		{"ssh keys", res("accounts.ssh-authorized-keys", "256 SHA256:abc me@x (ED25519)\n"), output.StatusInfo, "", "1 SSH authorized"},
		{"no ssh keys", res("accounts.ssh-authorized-keys", ""), output.StatusPass, "", ""},
		{"login hook", res("persistence.login-hooks", "    LoginHook = \"/tmp/x.sh\";\n"), output.StatusFail, output.SeverityHigh, "x.sh"},
		{"no hooks", res("persistence.login-hooks", ""), output.StatusPass, "", ""},
		{"default hosts", res("persistence.hosts", "127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n::1             localhost\n"), output.StatusPass, "", ""},
		{"custom hosts", res("persistence.hosts", "127.0.0.1 localhost\n1.2.3.4 www.bank.com\n"), output.StatusFail, output.SeverityLow, "bank"},
		{"sudoers readme", res("persistence.sudoers-d", "README\n"), output.StatusPass, "", ""},
		{"sudoers nopasswd", res("persistence.sudoers-d", "README\nalice-nopasswd\n"), output.StatusFail, output.SeverityLow, "alice-nopasswd"},
		{"no proxy", res("network.proxy", "<dictionary> {\n  HTTPEnable : 0\n  SOCKSEnable : 0\n}\n"), output.StatusPass, "", ""},
		{"http proxy", res("network.proxy", "<dictionary> {\n  HTTPEnable : 1\n  HTTPPort : 8080\n  HTTPProxy : 10.0.0.9\n}\n"), output.StatusFail, output.SeverityLow, "10.0.0.9"},
		{"pac proxy", res("network.proxy", "<dictionary> {\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://x/p.pac\n}\n"), output.StatusFail, output.SeverityLow, "p.pac"},
		{"xprotect", res("security-tools.xprotect-version", "5322\n"), output.StatusInfo, "", "5322"},
		{"no profiles", res("security-tools.profiles", "There are no configuration profiles installed in the system domain\n"), output.StatusPass, "", ""},
		{"profiles present", res("security-tools.profiles", "_computerlevel[1] attribute: profileIdentifier: com.corp.mdm\n"), output.StatusInfo, "", "com.corp.mdm"},
		{"not enrolled", res("security-tools.mdm-enrollment", "Enrolled via DEP: No\nMDM enrollment: No\n"), output.StatusPass, "", ""},
		{"enrolled", res("security-tools.mdm-enrollment", "Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)\n"), output.StatusInfo, "", "MDM"},
		{"tcc none", res("security-tools.tcc-system", ""), output.StatusPass, "", ""},
		{"tcc bundle", res("security-tools.tcc-user", "kTCCServiceScreenCapture|us.zoom.xos|0\n"), output.StatusInfo, "", "Screen Recording"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := one(t, eval(t, c.r))
			if f.Status != c.status || f.Severity != c.sev {
				t.Errorf("got %s/%s %q; want %s/%s", f.Status, f.Severity, f.Title, c.status, c.sev)
			}
			if c.want != "" && !strings.Contains(f.Title+"\n"+f.Detail, c.want) {
				t.Errorf("finding lacks %q: %+v", c.want, f)
			}
			if f.Status == output.StatusFail && f.Remediation == "" {
				t.Error("failing finding needs a remediation")
			}
		})
	}
}

func TestTCC_PathGrantIsFlagged(t *testing.T) {
	r := res("security-tools.tcc-system", "kTCCServiceSystemPolicyAllFiles|/tmp/dropper|1\nkTCCServiceAccessibility|com.vendor.app|0\n")
	fs := eval(t, r)
	if len(fs) != 2 || fs[0].Status != output.StatusFail || !strings.Contains(fs[0].Detail, "/tmp/dropper") || !strings.Contains(fs[0].Detail, "Full Disk Access") {
		t.Fatalf("want path grant failing first, then bundle info: %+v", fs)
	}
	if fs[1].Status != output.StatusInfo || !strings.Contains(fs[1].Detail, "com.vendor.app") {
		t.Errorf("bundle grant: %+v", fs[1])
	}
}
