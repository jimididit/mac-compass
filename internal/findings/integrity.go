package findings

import (
	"fmt"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/runner"
)

func init() { evaluators["persistence.launch-integrity"] = evalLaunchIntegrity }

// evalLaunchIntegrity reports launch item programs whose code signature no longer verifies. The hashes in the
// output are for comparing against a baseline; one run on its own can only judge the signature.
func evalLaunchIntegrity(r output.CheckResult) []output.Finding {
	var bad []string
	checked := 0
	for _, l := range strings.Split(r.Stdout, "\n") {
		c := strings.Split(l, "\t")
		if l == "" || l == runner.IntegrityHeader || len(c) != 10 {
			continue
		}
		checked++
		if c[7] == "invalid" {
			bad = append(bad, fmt.Sprintf("%s (%s) -> %s", c[1], c[0], c[4]))
		}
	}
	if len(bad) > 0 {
		return []output.Finding{fail("persistence.launch-integrity", output.SeverityHigh,
			fmt.Sprintf("%d launch item program(s) fail code-signature verification", len(bad)), strings.Join(bad, "\n"),
			"The program was changed after it was signed, or its signature is damaged. Reinstall the software that owns it; if you do not recognise it, treat it as tampered with.")}
	}
	return []output.Finding{pass("persistence.launch-integrity", fmt.Sprintf("%d launch item program(s) verified", checked))}
}
