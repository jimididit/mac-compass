package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/jimididit/mac-compass/internal/catalog"
)

// execFn runs a command and returns its output and exit code. err is set only when the command
// could not be started at all. Production uses realExec; tests inject a fake.
type execFn func(ctx context.Context, argv ...string) (stdout, stderr string, code int, err error)

// deps are the system touchpoints a builtin collector uses, injectable for tests.
type deps struct {
	exec     execFn
	listDir  func(dir string) ([]string, error) // file names in dir
	exists   func(path string) bool
	readHead func(path string, n int) ([]byte, error) // first n bytes of a file
	home     string                                   // the invoking user's home directory
}

type builtinFn func(ctx context.Context, d deps) (string, error)

// builtins implements every name in catalog.KnownBuiltins.
var builtins = map[string]builtinFn{
	"launchd-targets":    launchdTargets,
	"process-signatures": processSignatures,
}

// runBuiltin runs an in-process collector with the same timeout and result shape as a command.
func runBuiltin(ctx context.Context, ch catalog.Check, opts Options, out io.Writer) Result {
	fn, ok := builtins[ch.Builtin]
	if !ok {
		return Result{Err: fmt.Errorf("unknown builtin %q", ch.Builtin)}
	}
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	home, _ := InvokingUserHome()
	start := time.Now()
	stdout, err := fn(runCtx, deps{exec: realExec, listDir: listDir, exists: pathExists, readHead: readHead, home: home})
	res := Result{Stdout: stdout, Duration: time.Since(start)}
	if out != nil {
		io.WriteString(out, stdout)
	}
	switch {
	case runCtx.Err() == context.DeadlineExceeded:
		res.ExitCode, res.Err = -1, fmt.Errorf("timeout after %v", opts.Timeout)
	case err != nil:
		res.Err = err
	}
	return res
}

func realExec(ctx context.Context, argv ...string) (string, string, int, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = safeEnv()
	cmd.WaitDelay = killGrace
	configureProcess(cmd)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if err == nil {
		return o.String(), e.String(), 0, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return o.String(), e.String(), ee.ExitCode(), nil
	}
	return o.String(), e.String(), -1, err
}

func listDir(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

func readHead(p string, n int) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	m, err := io.ReadFull(f, buf)
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		err = nil
	}
	return buf[:m], err
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// clean makes a value safe for one tab-separated output field.
func clean(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return "-"
	}
	return s
}
