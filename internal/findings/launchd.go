package findings

import (
	"fmt"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/runner"
)

// monitorLabel is the launchd label of mac-compass monitor's own job; a test keeps it equal to monitor.Label.
const monitorLabel = "io.github.jimididit.mac-compass.monitor"

func init() { evaluators["persistence.launchd-targets"] = evalLaunchdTargets }

// launchItem is one parsed row of the launchd-targets collector.
type launchItem struct {
	Kind, Label, Plist, Target, State, Team, Signer, Notarization string
	Flags                                                         map[string]bool
}

func (i launchItem) String() string {
	return fmt.Sprintf("%s (%s) -> %s", i.Label, i.Kind, i.Target)
}

func parseLaunchItems(stdout string) []launchItem {
	var items []launchItem
	for _, l := range strings.Split(stdout, "\n") {
		if l == "" || l == runner.LaunchdHeader {
			continue
		}
		c := strings.Split(l, "\t")
		if len(c) != 9 {
			continue
		}
		it := launchItem{Kind: c[0], Label: c[1], Plist: c[2], Target: c[3], State: c[4], Team: c[5], Signer: c[6], Notarization: c[7], Flags: map[string]bool{}}
		for _, f := range strings.Split(c[8], ",") {
			it.Flags[f] = true
		}
		items = append(items, it)
	}
	return items
}

// evalLaunchdTargets groups launch items by how worrying their program is. Apple-signed and
// notarized Developer ID programs are the normal case and only appear in the summary.
func evalLaunchdTargets(r output.CheckResult) []output.Finding {
	items := parseLaunchItems(r.Stdout)
	if len(items) == 0 {
		return []output.Finding{pass("persistence.launchd-targets", "No launch items to check")}
	}
	var temp, unsigned, adhoc, missing, scripts []string
	counts := map[string]int{}
	for _, it := range items {
		if it.Label == monitorLabel {
			counts["mac-compass monitor job"]++
			continue
		}
		switch {
		case it.Flags["temp-location"] || it.Flags["hidden-location"]:
			temp = append(temp, it.String()+" ["+locationFlag(it)+"]")
		case it.State == "unsigned":
			unsigned = append(unsigned, it.String())
		case it.State == "adhoc":
			adhoc = append(adhoc, it.String())
		case it.State == "missing":
			missing = append(missing, it.String())
		case it.State == "script":
			scripts = append(scripts, it.String())
		}
		counts[summaryBucket(it)]++
	}
	var out []output.Finding
	add := func(sev output.Severity, title string, lines []string, fix string) {
		if len(lines) > 0 {
			out = append(out, fail("persistence.launchd-targets", sev, fmt.Sprintf(title, len(lines)), strings.Join(lines, "\n"), fix))
		}
	}
	add(output.SeverityHigh, "%d launch item(s) run a program from a temporary or hidden location", temp,
		"Legitimate software installs to /Applications, /Library or /usr/local. Inspect the plist and program, and remove the item if you do not recognise it.")
	add(output.SeverityMedium, "%d launch item(s) run an unsigned program", unsigned,
		"Unsigned programs cannot be attributed to a developer. Confirm where each came from; remove it if unexpected.")
	add(output.SeverityLow, "%d launch item(s) run an ad-hoc signed program", adhoc,
		"Ad-hoc signatures carry no developer identity (common for locally built tools). Confirm you built or installed it.")
	add(output.SeverityLow, "%d launch item(s) point to a program that no longer exists", missing,
		"Leftovers from uninstalled software, or a program removed after infection. Delete the plist if the software is gone.")
	add(output.SeverityLow, "%d launch item(s) run a shell script or inline command", scripts,
		"Scripts are not code-signed; read each one to confirm what it does.")
	out = append(out, info("persistence.launchd-targets",
		fmt.Sprintf("%d launch item(s) checked", len(items)), summaryLine(counts)))
	return out
}

func locationFlag(it launchItem) string {
	if it.Flags["temp-location"] {
		return "temporary location"
	}
	return "hidden location"
}

func summaryBucket(it launchItem) string {
	switch {
	case it.State == "apple":
		return "Apple"
	case it.State == "developer-id" && it.Notarization == "notarized":
		return "Developer ID, notarized"
	case it.State == "developer-id" && it.Notarization == "unknown":
		return "Developer ID, notarization unknown"
	case it.State == "developer-id":
		return "Developer ID, not notarized"
	case it.State == "other-signed":
		return "other signature"
	}
	return it.State
}

func summaryLine(counts map[string]int) string {
	var parts []string
	for _, k := range []string{"Apple", "Developer ID, notarized", "Developer ID, not notarized", "Developer ID, notarization unknown", "other signature", "adhoc", "unsigned", "script", "missing", "unreadable", "no-program", "mac-compass monitor job"} {
		if n := counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	return strings.Join(parts, ", ")
}
