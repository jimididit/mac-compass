// Package suppress lets a user accept findings they have reviewed. Accepted findings are removed from
// the active results (and from --fail-on) but stay visible in the report with the reason recorded,
// so nothing is silently hidden and every acceptance can expire.
package suppress

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jimididit/mac-compass/internal/output"
	"gopkg.in/yaml.v3"
)

// Rule accepts findings from one check.
//
// With only ID, every finding for that check is accepted. With Match as well, only the detail lines
// containing Match (case-insensitive) are accepted, so one reviewed item can be accepted while any
// other item in the same finding is still reported. A finding whose detail lines are all accepted is
// accepted entirely.
type Rule struct {
	ID      string `yaml:"id"`
	Match   string `yaml:"match"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires"` // YYYY-MM-DD, optional; the rule stops applying after this day
}

type file struct {
	Suppressions []Rule `yaml:"suppressions"`
}

var idRe = regexp.MustCompile(`^[a-z0-9-]+\.[a-z0-9-]+$`)

// Load reads and validates a suppressions file. Unknown keys are errors.
func Load(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes and validates suppressions YAML.
func Parse(data []byte) ([]Rule, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse suppressions: %w", err)
	}
	for i, r := range f.Suppressions {
		switch {
		case !idRe.MatchString(r.ID):
			return nil, fmt.Errorf("suppression #%d: id %q must look like section.slug", i+1, r.ID)
		case strings.TrimSpace(r.Reason) == "":
			return nil, fmt.Errorf("suppression #%d (%s): reason is required", i+1, r.ID)
		}
		if r.Expires != "" {
			if _, err := time.Parse("2006-01-02", r.Expires); err != nil {
				return nil, fmt.Errorf("suppression #%d (%s): expires must be YYYY-MM-DD", i+1, r.ID)
			}
		}
	}
	return f.Suppressions, nil
}

// Result is the outcome of applying rules.
type Result struct {
	Kept       []output.Finding
	Suppressed []output.Suppressed
	Notices    []output.Finding // info findings about the rules themselves (expired)
}

// Apply removes accepted findings. now decides which rules have expired.
func Apply(rules []Rule, findings []output.Finding, now time.Time) Result {
	var res Result
	var active []Rule
	today := now.UTC().Format("2006-01-02")
	for _, r := range rules {
		if r.Expires != "" && today > r.Expires {
			res.Notices = append(res.Notices, output.Finding{
				ID: "suppress.expired", CheckID: r.ID, Status: output.StatusInfo,
				Title:  fmt.Sprintf("Suppression for %s expired on %s", r.ID, r.Expires),
				Detail: "Reason it was accepted: " + r.Reason + "\nReview the finding again, then renew or remove the rule.",
			})
			continue
		}
		active = append(active, r)
	}

	for _, f := range findings {
		kept, gone := f, false
		for _, r := range active {
			if r.ID != kept.ID {
				continue
			}
			if r.Match == "" {
				res.Suppressed = append(res.Suppressed, output.Suppressed{Finding: kept, Reason: r.Reason})
				gone = true
				break
			}
			rest, removed := splitDetail(kept.Detail, r.Match)
			if kept.Detail == "" {
				if strings.Contains(strings.ToLower(kept.Title), strings.ToLower(r.Match)) {
					res.Suppressed = append(res.Suppressed, output.Suppressed{Finding: kept, Reason: r.Reason})
					gone = true
					break
				}
				continue
			}
			if len(removed) == 0 {
				continue
			}
			part := kept
			part.Detail = strings.Join(removed, "\n")
			res.Suppressed = append(res.Suppressed, output.Suppressed{Finding: part, Reason: r.Reason})
			if len(rest) == 0 {
				gone = true
				break
			}
			kept.Detail = strings.Join(rest, "\n")
			kept.Title = fmt.Sprintf("%s [%d accepted]", kept.Title, len(removed))
		}
		if !gone {
			res.Kept = append(res.Kept, kept)
		}
	}
	return res
}

// splitDetail separates detail lines containing match from the rest.
func splitDetail(detail, match string) (rest, removed []string) {
	m := strings.ToLower(match)
	for _, l := range strings.Split(detail, "\n") {
		switch {
		case strings.TrimSpace(l) == "":
		case strings.Contains(strings.ToLower(l), m):
			removed = append(removed, l)
		default:
			rest = append(rest, l)
		}
	}
	return rest, removed
}
