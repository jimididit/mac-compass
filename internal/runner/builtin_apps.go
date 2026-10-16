package runner

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
)

// AppsHeader is the first line of the app-inventory output; evaluators and baselines rely on the column order.
const AppsHeader = "path\tbundle_id\tversion\tstate\tteam\tsigner\tcdhash"

// appWorkers bounds how many applications are inspected at once; codesign is the slow part.
const appWorkers = 4

type appInfoPlist struct {
	BundleID string `json:"CFBundleIdentifier"`
	Short    string `json:"CFBundleShortVersionString"`
	Build    string `json:"CFBundleVersion"`
}

// appInventory lists the applications installed in /Applications and the invoking user's ~/Applications, one
// level of subfolders deep (for example /Applications/Utilities), with each bundle's identifier, version and
// code-signing identity. /System/Applications is left out: it is on the sealed system volume.
func appInventory(ctx context.Context, d deps) (string, error) {
	roots := []string{"/Applications"}
	if d.home != "" {
		roots = append(roots, d.home+"/Applications")
	}
	var apps []string
	for _, root := range roots {
		names, err := d.listDir(root)
		if err != nil {
			continue
		}
		for _, n := range names {
			p := root + "/" + n
			if strings.HasSuffix(n, ".app") {
				apps = append(apps, p)
				continue
			}
			if sub, err := d.listDir(p); err == nil { // a plain folder: look one level down
				for _, s := range sub {
					if strings.HasSuffix(s, ".app") {
						apps = append(apps, p+"/"+s)
					}
				}
			}
		}
	}

	rows := make([]string, len(apps))
	var wg sync.WaitGroup
	sem := make(chan struct{}, appWorkers)
	for i, app := range apps {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, app string) {
			defer wg.Done()
			defer func() { <-sem }()
			rows[i] = appRow(ctx, d, app)
		}(i, app)
	}
	wg.Wait()

	out := []string{AppsHeader}
	for _, r := range rows {
		if r != "" {
			out = append(out, r)
		}
	}
	return strings.Join(out, "\n") + "\n", ctx.Err()
}

func appRow(ctx context.Context, d deps, app string) string {
	if ctx.Err() != nil {
		return ""
	}
	var info appInfoPlist
	if out, _, code, err := d.exec(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", "--", app+"/Contents/Info.plist"); err == nil && code == 0 {
		_ = json.Unmarshal([]byte(out), &info)
	}
	version := info.Short
	if version == "" {
		version = info.Build
	}
	out, errOut, code, err := d.exec(ctx, "/usr/bin/codesign", "-dvvv", "--", app)
	si := signInfo{State: "unreadable", Team: "-", Signer: "-"}
	cdhash := "-"
	if err == nil {
		si = parseCodesign(out+"\n"+errOut, code)
		cdhash = parseCDHash(out + "\n" + errOut)
	}
	return strings.Join([]string{clean(app), clean(info.BundleID), clean(version), clean(si.State), clean(si.Team), clean(si.Signer), cdhash}, "\t")
}

// parseCDHash returns the code directory hash from `codesign -dvvv` output, or "-".
func parseCDHash(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if h, ok := strings.CutPrefix(strings.TrimSpace(l), "CDHash="); ok && h != "" {
			return h
		}
	}
	return "-"
}
