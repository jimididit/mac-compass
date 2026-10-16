package baseline

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/runner"
)

const integrityID = "persistence.launch-integrity"

func init() {
	extractors[integrityID] = extractor{KindKeyed, integrityItems}
	metas[integrityID] = meta{"Launch item", output.SeverityMedium, "Compare the plist and program with a known-good copy; reinstall the software that owns the item"}
	keyedSpecs[integrityID] = keyedSpec{classify: classifyIntegrityValues}
}

// keySep separates an item's identity from its recorded state in a keyed entry.
const keySep = " => "

// integrityItems records, per launch item, the hashes and signature state that decide whether it was tampered
// with. The identity is the plist path; everything after the separator is compared as the item's state.
func integrityItems(r output.CheckResult) []string {
	var out []string
	for _, l := range nonEmptyLines(r.Stdout) {
		c := strings.Split(l, "\t")
		if l == runner.IntegrityHeader || len(c) != 10 || c[1] == runner.MonitorLabel {
			continue
		}
		// kind label plist plist_sha256 target target_sha256 state signature team signer
		out = append(out, fmt.Sprintf("%s%splist=%s program=%s sha=%s state=%s sig=%s team=%s signer=%s",
			c[2], keySep, c[3], c[4], c[5], c[6], c[7], c[8], c[9]))
	}
	return out
}

// integrityState is one launch item's recorded state.
type integrityState struct{ plist, program, sha, state, sig, team, signer string }

var integrityRe = regexp.MustCompile(`^plist=(\S+) program=(.*) sha=(\S+) state=(\S+) sig=(\S+) team=(\S+) signer=(.*)$`)

func parseIntegrity(v string) (integrityState, bool) {
	m := integrityRe.FindStringSubmatch(v)
	if m == nil {
		return integrityState{}, false
	}
	return integrityState{m[1], m[2], m[3], m[4], m[5], m[6], m[7]}, true
}

// classifyIntegrity says how worrying a change to one launch item is. A new program hash alone is routine
// (software updates itself); it matters when the signature stops verifying, the signer or the program
// changes, or the program cannot be verified at all.
func classifyIntegrity(o, n integrityState) (sev output.Severity, reasons []string) {
	raise := func(s output.Severity, why string) {
		reasons = append(reasons, why)
		if s.Rank() > sev.Rank() {
			sev = s
		}
	}
	if n.sig == "invalid" && o.sig != "invalid" {
		raise(output.SeverityHigh, "its code signature no longer verifies")
	}
	if o.team != n.team || o.signer != n.signer {
		raise(output.SeverityHigh, "its signer changed")
	}
	if o.program != n.program {
		raise(output.SeverityHigh, "it now runs a different program")
	}
	if o.state != n.state {
		raise(output.SeverityHigh, fmt.Sprintf("its signing state changed (%s -> %s)", o.state, n.state))
	}
	if o.plist != n.plist {
		raise(output.SeverityMedium, "its launch definition (plist) changed")
	}
	if o.sha != n.sha {
		if n.sig == "valid" && (n.state == "apple" || n.state == "developer-id") {
			raise(output.SeverityInfo, "its program was updated and the developer signature still verifies")
		} else {
			raise(output.SeverityMedium, "its program changed and nothing signed vouches for it")
		}
	}
	return sev, reasons
}

// classifyIntegrityValues classifies one launch item whose recorded state changed. Items that appear or
// disappear are not reported here: the launch item program check already raises them.
func classifyIntegrityValues(was, now string) (output.Severity, []string) {
	prev, ok1 := parseIntegrity(was)
	cur, ok2 := parseIntegrity(now)
	if !ok1 || !ok2 {
		return output.SeverityMedium, []string{"changed"}
	}
	return classifyIntegrity(prev, cur)
}
