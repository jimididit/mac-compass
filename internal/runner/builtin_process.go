package runner

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ProcessHeader is the first line of the process-signatures output.
const ProcessHeader = "users\tpath\tcount\tstate\tteam\tsigner\tnotarization\tflags"

// signWorkers bounds concurrent codesign calls; a Mac has a few hundred distinct programs running.
const signWorkers = 8

// processSignatures lists the distinct programs currently running with their code-signing state.
// One tab-separated row per program, with the users running it and how many processes it has.
func processSignatures(ctx context.Context, d deps) (string, error) {
	stdout, _, code, err := d.exec(ctx, "/bin/ps", "-axww", "-o", "user=,comm=")
	if err != nil || code != 0 {
		return ProcessHeader + "\n", errOrExit("ps", err, code)
	}
	progs := parseProcessList(stdout)

	paths := make([]string, 0, len(progs))
	for p := range progs {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	infos := make([]signInfo, len(paths))
	missing := make([]bool, len(paths))
	var wg sync.WaitGroup
	sem := make(chan struct{}, signWorkers)
	for i, p := range paths {
		if !d.exists(p) {
			missing[i] = true
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p string) {
			defer wg.Done()
			defer func() { <-sem }()
			infos[i] = inspectSignature(ctx, d, p)
		}(i, p)
	}
	wg.Wait()

	rows := []string{ProcessHeader}
	for i, p := range paths {
		pr := progs[p]
		var flags []string
		if loc := riskyLocation(p); loc != "" {
			flags = append(flags, loc)
		}
		if pr.users["root"] && strings.HasPrefix(p, "/Users/") {
			flags = append(flags, "root-from-user-dir")
		}
		si := infos[i]
		if missing[i] {
			si = signInfo{State: "missing", Team: "-", Signer: "-", Notarization: "-"}
		}
		rows = append(rows, strings.Join([]string{
			clean(pr.userList()), clean(p), strconv.Itoa(pr.count), clean(si.State), clean(si.Team),
			clean(si.Signer), clean(si.Notarization), clean(strings.Join(flags, ",")),
		}, "\t"))
	}
	return strings.Join(rows, "\n") + "\n", ctx.Err()
}

type processGroup struct {
	count int
	users map[string]bool
}

func (g processGroup) userList() string {
	u := make([]string, 0, len(g.users))
	for k := range g.users {
		u = append(u, k)
	}
	sort.Strings(u)
	return strings.Join(u, ",")
}

// parseProcessList groups `ps -o user=,comm=` rows by executable path. Rows whose command is not an
// absolute path (login shells like "-zsh", kernel threads, "(sd-pam)") are ignored.
func parseProcessList(out string) map[string]processGroup {
	progs := map[string]processGroup{}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		user, rest, ok := strings.Cut(l, " ")
		rest = strings.TrimSpace(rest)
		if !ok || !strings.HasPrefix(rest, "/") {
			continue
		}
		g := progs[rest]
		if g.users == nil {
			g.users = map[string]bool{}
		}
		g.count++
		g.users[user] = true
		progs[rest] = g
	}
	return progs
}

func errOrExit(name string, err error, code int) error {
	if err != nil {
		return err
	}
	return &exitError{name: name, code: code}
}

type exitError struct {
	name string
	code int
}

func (e *exitError) Error() string { return e.name + " exited with status " + strconv.Itoa(e.code) }
