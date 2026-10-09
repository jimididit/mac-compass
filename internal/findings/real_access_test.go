package findings

import (
	"strings"
	"testing"

	"github.com/jimididit/mac-compass/internal/btm"
	"github.com/jimididit/mac-compass/internal/output"
)

// Output captured from a GitHub-hosted macOS 26 runner (an intentionally loose machine).
func TestRealRunner_AccessChecks(t *testing.T) {
	want := map[string]struct {
		status output.Status
		sev    output.Severity
		in     string // substring expected in Title+Detail
	}{
		"accounts.autologin":              {output.StatusFail, output.SeverityMedium, "runner"},
		"accounts.guest":                  {output.StatusPass, "", ""},
		"accounts.admin-group":            {output.StatusInfo, "", "runner"},
		"persistence.login-hooks":         {output.StatusPass, "", ""},
		"persistence.hosts":               {output.StatusFail, output.SeverityLow, "192.168.64.15"},
		"persistence.sudoers-d":           {output.StatusFail, output.SeverityLow, "runner"},
		"network.proxy":                   {output.StatusPass, "", ""},
		"security-tools.xprotect-version": {output.StatusInfo, "", "5287"},
		"security-tools.profiles":         {output.StatusPass, "", ""},
		"security-tools.mdm-enrollment":   {output.StatusPass, "", ""},
	}
	for id, w := range want {
		t.Run(id, func(t *testing.T) {
			f := one(t, eval(t, fixture(t, "macos26-arm64", id)))
			if f.Status != w.status || f.Severity != w.sev {
				t.Errorf("got %s/%s %q; want %s/%s", f.Status, f.Severity, f.Title, w.status, w.sev)
			}
			if !strings.Contains(f.Title+"\n"+f.Detail, w.in) {
				t.Errorf("finding lacks %q: %+v", w.in, f)
			}
		})
	}
}

func TestRealRunner_TCC(t *testing.T) {
	for _, id := range []string{"security-tools.tcc-system", "security-tools.tcc-user"} {
		fs := eval(t, fixture(t, "macos26-arm64", id))
		if len(fs) != 2 || fs[0].Status != output.StatusFail || fs[0].Severity != output.SeverityMedium || fs[1].Status != output.StatusInfo {
			t.Fatalf("%s: want path-grant fail then bundle info; got %+v", id, fs)
		}
		if !strings.Contains(fs[0].Detail, "/bin/bash") || !strings.Contains(fs[0].Detail, "Accessibility") {
			t.Errorf("%s: path grants not listed: %q", id, fs[0].Detail)
		}
		if !strings.Contains(fs[1].Detail, "com.apple.Terminal") {
			t.Errorf("%s: bundle grants not listed: %q", id, fs[1].Detail)
		}
	}
}

func TestRealRunner_BTM(t *testing.T) {
	r := fixture(t, "macos26-arm64", "persistence.btm")
	items := btm.Parse(r.Stdout)
	if len(items) < 5 {
		t.Fatalf("parsed only %d items", len(items))
	}
	var legacy *btm.Item
	for i := range items {
		if items[i].Name == "ankaupd.sh" {
			legacy = &items[i]
		}
	}
	if legacy == nil {
		t.Fatal("ankaupd.sh not parsed")
	}
	if legacy.Type != "legacy daemon" || !legacy.Enabled() || !strings.HasSuffix(legacy.URL, "ankaupd.plist") || !strings.HasSuffix(legacy.ExecutablePath, "ankaupd.sh") {
		t.Errorf("fields wrong: %+v", *legacy)
	}
	f := one(t, eval(t, r))
	if f.Status != output.StatusInfo || !strings.Contains(f.Detail, "ankaupd.sh [legacy daemon]") {
		t.Errorf("btm finding: %+v", f)
	}
	for _, line := range strings.Split(f.Detail, "\n") {
		if strings.Contains(line, "[developer]") {
			t.Errorf("developer grouping records must not be listed: %q", line)
		}
	}
}

func TestBTMParse_Synthetic(t *testing.T) {
	out := ` Items:

 #1:
                 UUID: A
                 Name: Dropbox
       Developer Name: Dropbox, Inc.
                 Type: login item (0x4)
          Disposition: [disabled, allowed, notified] (0x4)
           Identifier: 2.com.dropbox
                  URL: Contents/Library/LoginItems/Dropbox.app
  Embedded Item Identifiers:
    #1: 2.com.dropbox.helper

 #2:
                 Name: (null)
                 Type: developer (0x20)
          Disposition: [enabled, allowed] (0x3)
           Identifier: Unknown Developer
`
	items := btm.Parse(out)
	if len(items) != 2 {
		t.Fatalf("want 2 items, got %d: %+v", len(items), items)
	}
	if items[0].Enabled() || items[0].Type != "login item" || items[0].DeveloperName != "Dropbox, Inc." {
		t.Errorf("item 0: %+v", items[0])
	}
	if !items[1].Grouping() || items[1].DisplayName() != "Unknown Developer" {
		t.Errorf("item 1: %+v", items[1])
	}
	f := one(t, eval(t, res("persistence.btm", out)))
	if !strings.Contains(f.Title, "0 enabled background item(s) of 1") {
		t.Errorf("counts: %q", f.Title)
	}
}
