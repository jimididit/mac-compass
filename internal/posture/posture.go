// Package posture scores a Mac against a short list of hardening controls. Each control is judged from
// the finding that an existing check already produces, so the score never needs extra commands.
//
// The controls are the ones that mac-compass can read without changing anything. They follow the
// macOS Security Compliance Project (mSCP), the open baseline from which the CIS and NIST macOS
// benchmarks are generated; each control names its mSCP rule where one exists. The score is a guide to
// where to look first, not a compliance result: it covers a subset of any benchmark.
package posture

import (
	"github.com/jimididit/mac-compass/internal/output"
)

// Control is one hardening control, judged from the findings of one check.
type Control struct {
	ID        string // finding id the control reads, e.g. "triage.sip"
	Title     string
	Weight    int    // 1 (minor) to 3 (core protection)
	MSCP      string // mSCP rule id, when there is one
	Remediate string // used when the finding carries no remediation of its own
}

// Controls is the ordered control list.
var Controls = []Control{
	{"triage.sip", "System Integrity Protection is on", 3, "os_sip_enable", "Boot to Recovery and run: csrutil enable"},
	{"triage.sip-authenticated-root", "Signed system volume is on", 2, "os_authenticated_root_enable", "Boot to Recovery and run: csrutil authenticated-root enable"},
	{"triage.gatekeeper", "Gatekeeper is on", 3, "os_gatekeeper_enable", "Run: sudo spctl --global-enable"},
	{"security-tools.filevault", "FileVault disk encryption is on", 3, "system_settings_filevault_enforce", "System Settings > Privacy & Security > FileVault"},
	{"network.firewall", "Application firewall is on", 2, "system_settings_firewall_enable", "System Settings > Network > Firewall"},
	{"network.firewall-stealth", "Firewall stealth mode is on", 1, "system_settings_firewall_stealth_mode_enable", "System Settings > Network > Firewall > Options"},
	{"accounts.guest", "Guest account is off", 2, "system_settings_guest_account_disable", "System Settings > Users & Groups"},
	{"accounts.autologin", "Automatic login is off", 2, "system_settings_automatic_login_disable", "System Settings > Users & Groups"},
	{"harden.auto-update-settings", "Automatic software updates are on", 2, "system_settings_critical_update_install_enforce", "System Settings > General > Software Update > Automatic Updates"},
	{"harden.softwareupdate-list", "macOS is up to date", 1, "", "System Settings > General > Software Update"},
	{"kernel.nvram-boot-args", "No weakening NVRAM boot-args", 2, "", "Run: sudo nvram -d boot-args"},
	{"processes.launchctl-dyld", "No DYLD variables in the launchd domain", 2, "", ""},
	{"persistence.login-hooks", "No login or logout hooks", 2, "", ""},
	{"persistence.sudoers-d", "No custom sudoers drop-ins", 1, "", "Review /etc/sudoers.d; a NOPASSWD rule grants root without a password"},
	{"triage.kext-non-apple", "No non-Apple kernel extensions are loaded", 1, "", "Remove the software that installed the extension"},
	{"network.listening-tcp", "No remote-access services reachable", 1, "", "System Settings > General > Sharing"},
}

const (
	StatusPass        = "pass"
	StatusFail        = "fail"
	StatusAccepted    = "accepted"
	StatusNotAssessed = "not-assessed"
)

// Assess scores the findings. suppressed holds findings the user accepted; a control whose only failing
// findings were accepted is reported as accepted and leaves the score alone.
func Assess(findings []output.Finding, suppressed []output.Suppressed) output.Posture {
	var p output.Posture
	var got, total int
	for _, c := range Controls {
		pc := output.PostureControl{ID: c.ID, Title: c.Title, Weight: c.Weight, MSCP: c.MSCP, Status: StatusNotAssessed}
		var pass, fail bool
		for _, f := range findings {
			if f.CheckID != c.ID {
				continue
			}
			switch f.Status {
			case output.StatusPass:
				pass = true
			case output.StatusFail:
				fail = true
				pc.Remediation = f.Remediation
			}
		}
		accepted := false
		if !fail {
			for _, s := range suppressed {
				if s.CheckID == c.ID && s.Status == output.StatusFail {
					accepted = true
				}
			}
		}
		switch {
		case fail:
			pc.Status = StatusFail
			p.Failed++
			total += c.Weight
			if pc.Remediation == "" {
				pc.Remediation = c.Remediate
			}
		case accepted:
			pc.Status = StatusAccepted
			p.Accepted++
		case pass:
			pc.Status = StatusPass
			p.Passed++
			total += c.Weight
			got += c.Weight
		default:
			p.NotAssessed++
		}
		p.Controls = append(p.Controls, pc)
	}
	if total > 0 {
		p.Score = (got*100 + total/2) / total
	}
	return p
}
