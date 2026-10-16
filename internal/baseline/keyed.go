package baseline

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
)

// keyedSpec says how a keyed check's differences are judged.
type keyedSpec struct {
	// classify rates one item present in both snapshots whose state differs, and says why.
	classify func(was, now string) (output.Severity, []string)
	// added, when set, is the severity of items present only in the new snapshot; zero ignores them.
	added output.Severity
	// removed reports items that disappeared (informational).
	removed bool
}

var keyedSpecs = map[string]keyedSpec{}

func splitKeyed(items []string) map[string]string {
	out := map[string]string{}
	for _, it := range items {
		if k, v, ok := strings.Cut(it, keySep); ok {
			out[k] = v
		}
	}
	return out
}

// diffKeyed compares keyed entries: an item present in both is classified by what changed; additions and
// removals are reported as the check's spec says.
func diffKeyed(id string, m meta, o, c Entry) []output.Finding {
	spec := keyedSpecs[id]
	was, now := splitKeyed(o.Items), splitKeyed(c.Items)

	byLevel := map[output.Severity][]string{}
	var added, removed []string
	for k, nv := range now {
		ov, ok := was[k]
		switch {
		case !ok:
			added = append(added, k+" ("+nv+")")
		case ov != nv && spec.classify != nil:
			sev, reasons := spec.classify(ov, nv)
			if len(reasons) == 0 {
				sev, reasons = output.SeverityMedium, []string{"changed"}
			}
			byLevel[sev] = append(byLevel[sev], k+": "+strings.Join(reasons, "; "))
		}
	}
	for k, ov := range was {
		if _, ok := now[k]; !ok {
			removed = append(removed, k+" ("+ov+")")
		}
	}

	var out []output.Finding
	for _, sev := range []output.Severity{output.SeverityCritical, output.SeverityHigh, output.SeverityMedium, output.SeverityLow} {
		if lines := byLevel[sev]; len(lines) > 0 {
			sort.Strings(lines)
			out = append(out, output.Finding{
				ID: id, CheckID: id, Status: output.StatusFail, Severity: sev,
				Title:       fmt.Sprintf("%d %s(s) changed since baseline (%s)", len(lines), m.label, sev),
				Detail:      strings.Join(lines, "\n"),
				Remediation: m.fix,
			})
		}
	}
	if lines := byLevel[output.SeverityInfo]; len(lines) > 0 {
		sort.Strings(lines)
		out = append(out, output.Finding{
			ID: id, CheckID: id, Status: output.StatusInfo,
			Title:  fmt.Sprintf("%d %s(s) updated since baseline", len(lines), m.label),
			Detail: strings.Join(lines, "\n"),
		})
	}
	if spec.added != "" && len(added) > 0 {
		sort.Strings(added)
		out = append(out, output.Finding{
			ID: id, CheckID: id, Status: output.StatusFail, Severity: spec.added,
			Title:       fmt.Sprintf("%d new since baseline: %s", len(added), m.label),
			Detail:      "+ " + strings.Join(added, "\n+ "),
			Remediation: m.fix,
		})
	}
	if spec.removed && len(removed) > 0 {
		sort.Strings(removed)
		out = append(out, output.Finding{
			ID: id, CheckID: id, Status: output.StatusInfo,
			Title:  fmt.Sprintf("%d removed since baseline: %s", len(removed), m.label),
			Detail: "- " + strings.Join(removed, "\n- "),
		})
	}
	return out
}
