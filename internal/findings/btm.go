package findings

import (
	"fmt"
	"strings"

	"github.com/jimididit/mac-compass/internal/btm"
	"github.com/jimididit/mac-compass/internal/output"
)

func init() { evaluators["persistence.btm"] = evalBTM }

// evalBTM lists enabled background items (login items, launch agents/daemons, apps).
// Existence alone is not a defect, so this is informational; `compare` flags new ones.
func evalBTM(r output.CheckResult) []output.Finding {
	var enabled []string
	total := 0
	for _, it := range btm.Parse(r.Stdout) {
		if it.Grouping() {
			continue
		}
		total++
		if it.Enabled() {
			enabled = append(enabled, fmt.Sprintf("%s [%s] %s", it.DisplayName(), it.Type, it.Where()))
		}
	}
	if total == 0 {
		return []output.Finding{pass("persistence.btm", "No background items are registered")}
	}
	return []output.Finding{info("persistence.btm",
		fmt.Sprintf("%d enabled background item(s) of %d registered", len(enabled), total),
		strings.Join(enabled, "\n"))}
}
