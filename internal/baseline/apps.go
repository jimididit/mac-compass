package baseline

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/runner"
)

const appsID = "advanced.applications"

func init() {
	extractors[appsID] = extractor{KindKeyed, appItems}
	metas[appsID] = meta{"Application", output.SeverityLow, "Confirm you installed or updated it; remove it if you do not recognise it"}
	keyedSpecs[appsID] = keyedSpec{classify: classifyAppValues, added: output.SeverityLow, removed: true}
}

// appItems records, per application, its identity and signing state. The identity is the bundle path.
func appItems(r output.CheckResult) []string {
	var out []string
	for _, l := range nonEmptyLines(r.Stdout) {
		c := strings.Split(l, "\t")
		if l == runner.AppsHeader || len(c) != 7 {
			continue
		}
		// path bundle_id version state team signer cdhash
		out = append(out, fmt.Sprintf("%s%sid=%s version=%s state=%s team=%s cdhash=%s signer=%s", c[0], keySep, c[1], c[2], c[3], c[4], c[6], c[5]))
	}
	return out
}

type appState struct{ id, version, state, team, cdhash, signer string }

var appRe = regexp.MustCompile(`^id=(\S+) version=(.*) state=(\S+) team=(\S+) cdhash=(\S+) signer=(.*)$`)

func parseApp(v string) (appState, bool) {
	m := appRe.FindStringSubmatch(v)
	if m == nil {
		return appState{}, false
	}
	return appState{m[1], m[2], m[3], m[4], m[5], m[6]}, true
}

// classifyAppValues rates a change to one installed application. A new version from the same signer is
// routine; a different bundle id, signer or signing state is not; and changed contents under an unchanged
// version number is what a modified or re-signed copy looks like.
func classifyAppValues(was, now string) (output.Severity, []string) {
	o, ok1 := parseApp(was)
	n, ok2 := parseApp(now)
	if !ok1 || !ok2 {
		return output.SeverityMedium, []string{"changed"}
	}
	var sev output.Severity
	var reasons []string
	raise := func(s output.Severity, why string) {
		reasons = append(reasons, why)
		if s.Rank() > sev.Rank() {
			sev = s
		}
	}
	if o.id != n.id {
		raise(output.SeverityHigh, fmt.Sprintf("its bundle identifier changed (%s -> %s)", o.id, n.id))
	}
	if o.team != n.team || o.signer != n.signer {
		raise(output.SeverityHigh, "its signer changed")
	}
	if o.state != n.state {
		raise(output.SeverityHigh, fmt.Sprintf("its signing state changed (%s -> %s)", o.state, n.state))
	}
	switch {
	case o.version != n.version:
		raise(output.SeverityInfo, fmt.Sprintf("updated %s -> %s", o.version, n.version))
	case o.cdhash != n.cdhash:
		raise(output.SeverityMedium, "its contents changed without a version change")
	}
	return sev, reasons
}
