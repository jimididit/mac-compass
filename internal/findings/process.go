package findings

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
	"github.com/jimididit/mac-compass/internal/runner"
)

func init() { evaluators["processes.signatures"] = evalProcessSignatures }

type runningProgram struct {
	Users, Path          string
	Count                int
	State, Team          string
	Signer, Notarization string
	Flags                map[string]bool
}

func (p runningProgram) String() string {
	return fmt.Sprintf("%s (%d process(es), user %s)", p.Path, p.Count, p.Users)
}

func parseRunningPrograms(stdout string) []runningProgram {
	var progs []runningProgram
	for _, l := range strings.Split(stdout, "\n") {
		if l == "" || l == runner.ProcessHeader {
			continue
		}
		c := strings.Split(l, "\t")
		if len(c) != 8 {
			continue
		}
		n, _ := strconv.Atoi(c[2])
		p := runningProgram{Users: c[0], Path: c[1], Count: n, State: c[3], Team: c[4], Signer: c[5], Notarization: c[6], Flags: map[string]bool{}}
		for _, f := range strings.Split(c[7], ",") {
			p.Flags[f] = true
		}
		progs = append(progs, p)
	}
	return progs
}

// evalProcessSignatures flags running programs by how their location and signature look. Ad-hoc
// signatures are common for locally built tools (every Apple Silicon build is ad-hoc signed), so
// they only matter in a risky location and are otherwise just counted.
func evalProcessSignatures(r output.CheckResult) []output.Finding {
	progs := parseRunningPrograms(r.Stdout)
	if len(progs) == 0 {
		return []output.Finding{info("processes.signatures", "No running programs were listed", firstLine(r.Stderr))}
	}
	var risky, hiddenHome, rootUser, gone, unsigned []string
	counts := map[string]int{}
	for _, p := range progs {
		switch {
		case p.Flags["hidden-location"] && !p.Flags["temp-location"] && strings.HasPrefix(p.Path, "/Users/"):
			// Developer tools keep helpers in hidden folders under the home directory (~/.cache, ~/.cursor).
			hiddenHome = append(hiddenHome, p.String()+" ["+p.State+"]")
		case p.Flags["temp-location"] || p.Flags["hidden-location"]:
			risky = append(risky, p.String()+" ["+processLocation(p)+", "+p.State+"]")
		case p.Flags["root-from-user-dir"]:
			rootUser = append(rootUser, p.String()+" ["+p.State+"]")
		case p.State == "missing":
			gone = append(gone, p.String())
		case p.State == "unsigned":
			unsigned = append(unsigned, p.String())
		}
		counts[processBucket(p)]++
	}
	var out []output.Finding
	add := func(sev output.Severity, title string, lines []string, fix string) {
		if len(lines) > 0 {
			out = append(out, fail("processes.signatures", sev, fmt.Sprintf(title, len(lines)), strings.Join(lines, "\n"), fix))
		}
	}
	add(output.SeverityHigh, "%d running program(s) started from a temporary or hidden location", risky,
		"Legitimate software runs from /Applications, /Library, /usr or a user's own tools folder. Identify the process (ps, lsof -p) and stop it if unknown.")
	add(output.SeverityMedium, "%d running program(s) started from a hidden folder in a home directory", hiddenHome,
		"Common for developer tool caches such as ~/.cache and ~/.cursor, but malware also hides here. Confirm each program is something you installed; accept the ones you have reviewed with --suppress.")
	add(output.SeverityMedium, "%d program(s) run as root from a user's home folder", rootUser,
		"Root processes normally come from system locations. Confirm what launched it and why it has root.")
	add(output.SeverityMedium, "%d running program(s) no longer exist on disk", gone,
		"Malware sometimes deletes itself after starting. It is also normal for a few seconds while an app updates; run again to confirm.")
	add(output.SeverityMedium, "%d running program(s) are unsigned", unsigned,
		"Unsigned programs cannot be attributed to a developer. Confirm each is something you built or installed.")
	out = append(out, info("processes.signatures", fmt.Sprintf("%d distinct running program(s) checked", len(progs)), processSummary(counts)))
	return out
}

func processLocation(p runningProgram) string {
	if p.Flags["temp-location"] {
		return "temporary location"
	}
	return "hidden location"
}

func processBucket(p runningProgram) string {
	switch {
	case p.State == "apple":
		return "Apple"
	case p.State == "developer-id" && p.Notarization == "notarized":
		return "Developer ID, notarized"
	case p.State == "developer-id" && p.Notarization == "unknown":
		return "Developer ID, notarization unknown"
	case p.State == "developer-id":
		return "Developer ID, not notarized"
	case p.State == "other-signed":
		return "other signature"
	}
	return p.State
}

func processSummary(counts map[string]int) string {
	var parts []string
	for _, k := range []string{"Apple", "Developer ID, notarized", "Developer ID, not notarized", "Developer ID, notarization unknown", "other signature", "adhoc", "unsigned", "missing", "unreadable"} {
		if n := counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	return strings.Join(parts, ", ")
}
