package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

// IntegrityHeader is the first line of the launch-integrity output; evaluators and baselines rely on
// the column order below.
const IntegrityHeader = "kind\tlabel\tplist\tplist_sha256\ttarget\ttarget_sha256\tstate\tsignature\tteam\tsigner"

// MonitorLabel is the launchd label of mac-compass monitor's own job. Its plist and program change when the
// monitor is reinstalled or updated, so integrity comparisons leave it out.
const MonitorLabel = "io.github.jimididit.mac-compass.monitor"

// maxHashSize is the largest file hashed; a bigger program is reported without a hash rather than
// stalling the run.
const maxHashSize = 512 << 20

// launchIntegrity extends the launch item list with a SHA-256 of each plist and program and a check that
// the program's code signature still verifies. A hash alone changes on every legitimate update; a signature
// that no longer verifies, or a changed hash on a program that cannot be verified, is what points at tampering.
func launchIntegrity(ctx context.Context, d deps) (string, error) {
	base, err := launchdTargets(ctx, d)
	rows := []string{IntegrityHeader}
	for _, l := range strings.Split(base, "\n") {
		c := strings.Split(l, "\t")
		if len(c) != 9 || l == LaunchdHeader {
			continue
		}
		kind, label, plist, target, state, team, signer := c[0], c[1], c[2], c[3], c[4], c[5], c[6]
		sig := "-"
		switch state {
		case "apple", "developer-id", "other-signed", "adhoc":
			sig = verifySignature(ctx, d, target)
		}
		targetSum := "-"
		if state != "missing" && state != "no-program" && state != "unreadable" {
			targetSum = hashOrDash(d, target)
		}
		rows = append(rows, strings.Join([]string{clean(kind), clean(label), clean(plist), hashOrDash(d, plist),
			clean(target), targetSum, clean(state), sig, clean(team), clean(signer)}, "\t"))
	}
	return strings.Join(rows, "\n") + "\n", err
}

// verifySignature reports "valid" when codesign accepts the program's signature, "invalid" when it does not.
func verifySignature(ctx context.Context, d deps, target string) string {
	_, _, code, err := d.exec(ctx, "/usr/bin/codesign", "--verify", "--", target)
	switch {
	case err != nil:
		return "-"
	case code == 0:
		return "valid"
	}
	return "invalid"
}

func hashOrDash(d deps, path string) string {
	if d.hashFile == nil {
		return "-"
	}
	sum, err := d.hashFile(path)
	if err != nil || sum == "" {
		return "-"
	}
	return sum
}

// sha256File returns the hex SHA-256 of a file, or "" when it is too large to hash.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > maxHashSize {
		return "", nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
