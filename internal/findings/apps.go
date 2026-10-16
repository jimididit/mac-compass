package findings

import (
	"fmt"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/runner"
)

func init() { evaluators["advanced.applications"] = evalApplications }

func appBucket(state, signer string) string {
	switch {
	case state == "apple":
		return "Apple"
	case state == "developer-id":
		return "Developer ID"
	case state == "other-signed" && signer == appStoreSigner:
		return "Mac App Store"
	case state == "other-signed":
		return "other signature"
	}
	return state
}

// evalApplications summarises installed applications and flags those with no signature at all.
func evalApplications(r output.CheckResult) []output.Finding {
	counts := map[string]int{}
	var unsigned []string
	total := 0
	for _, l := range strings.Split(r.Stdout, "\n") {
		c := strings.Split(l, "\t")
		if l == "" || l == runner.AppsHeader || len(c) != 7 {
			continue
		}
		total++
		counts[appBucket(c[3], c[5])]++
		if c[3] == "unsigned" {
			unsigned = append(unsigned, c[0])
		}
	}
	var out []output.Finding
	if len(unsigned) > 0 {
		out = append(out, fail("advanced.applications", output.SeverityLow,
			fmt.Sprintf("%d installed application(s) have no code signature", len(unsigned)), strings.Join(unsigned, "\n"),
			"Unsigned apps cannot be attributed to a developer, and macOS treats them as untrusted. Confirm where each came from; remove it if unexpected."))
	}
	var parts []string
	for _, k := range []string{"Apple", "Mac App Store", "Developer ID", "other signature", "adhoc", "unsigned", "unreadable"} {
		if n := counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	return append(out, info("advanced.applications", fmt.Sprintf("%d installed application(s)", total), strings.Join(parts, ", ")))
}
