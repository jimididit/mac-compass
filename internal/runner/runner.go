package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jimididit/mac-compass/internal/catalog"
)

// ErrSkipped marks a check that was not run (not a failure).
var ErrSkipped = errors.New("skipped")

// safePath is the PATH given to every child so a poisoned PATH cannot shadow system tools.
const safePath = "/usr/bin:/bin:/usr/sbin:/sbin"

// killGrace is how long a timed-out child gets to exit before it is force-killed.
const killGrace = 2 * time.Second

// Options configures how checks are run.
type Options struct {
	UseSudo         bool
	Timeout         time.Duration
	SkipSudo        bool // If true, skip checks that require sudo
	VMMode          bool // If true, skip checks that require hardware (e.g. T2)
	MacOSMajor      int  // Detected macOS major version; 0 = unknown (no version gating)
	SudoAllowPrompt bool // If true and running in a TTY, sudo will prompt for password when needed
	OutWriter       io.Writer
	ErrWriter       io.Writer
}

// DefaultOptions returns options with sensible defaults.
func DefaultOptions() Options {
	return Options{
		Timeout:   90 * time.Second,
		UseSudo:   true,
		SkipSudo:  false,
		VMMode:    false,
		OutWriter: os.Stdout,
		ErrWriter: os.Stderr,
	}
}

// Result is the outcome of one check.
type Result struct {
	Stdout     string
	Stderr     string
	ExitCode   int
	Skipped    bool
	SkipReason string
	Duration   time.Duration
	Err        error // nil when the check ran and its exit status was acceptable
}

// Run executes one check. Output is captured into the Result; when out/errw are
// non-nil it is also streamed to them as it is produced.
func Run(ctx context.Context, ch catalog.Check, opts Options, out, errw io.Writer) Result {
	if ch.Sudo && opts.SkipSudo {
		return Result{Skipped: true, SkipReason: "requires sudo", Err: fmt.Errorf("%w: check requires sudo (omit --no-sudo or run with sudo)", ErrSkipped)}
	}
	if ch.RequiresHardware && opts.VMMode {
		return Result{Skipped: true, SkipReason: "requires hardware (VM mode)"}
	}

	if !ch.AppliesTo(opts.MacOSMajor) {
		return Result{Skipped: true, SkipReason: fmt.Sprintf("not applicable to macOS %d", opts.MacOSMajor)}
	}
	if ch.Arch != "" && ch.Arch != HostArch() {
		return Result{Skipped: true, SkipReason: "only on " + ch.Arch}
	}
	if ch.Optional && ch.Command != "" {
		if _, err := os.Stat(ch.Command); errors.Is(err, os.ErrNotExist) {
			return Result{Skipped: true, SkipReason: "not present on this macOS"}
		}
	}

	if ch.Builtin != "" {
		return runBuiltin(ctx, ch, opts, out)
	}

	script := ch.Script
	if script != "" {
		var err error
		if script, err = ExpandUserHome(script); err != nil {
			return Result{Err: fmt.Errorf("expand home: %w", err)}
		}
	}

	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	var argv []string
	if ch.Sudo && opts.UseSudo {
		argv = append(argv, "sudo")
		argv = append(argv, sudoArgsForCheck(ch, opts)...)
	}
	if script != "" {
		argv = append(argv, "sh", "-c", script)
	} else {
		argv = append(argv, ch.Command)
		argv = append(argv, ch.Args...)
	}

	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...)
	cmd.Env = safeEnv()
	cmd.WaitDelay = killGrace
	configureProcess(cmd)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = tee(&outBuf, out)
	cmd.Stderr = tee(&errBuf, errw)

	start := time.Now()
	runErr := cmd.Run()
	res := Result{Stdout: outBuf.String(), Stderr: errBuf.String(), Duration: time.Since(start)}
	if runErr == nil {
		return res
	}
	if runCtx.Err() == context.DeadlineExceeded {
		res.ExitCode = -1
		res.Err = fmt.Errorf("timeout after %v", opts.Timeout)
		return res
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		if ch.ExitOK(res.ExitCode) {
			return res
		}
	}
	res.Err = runErr
	return res
}

// MacOSInfo describes the running macOS.
type MacOSInfo struct {
	Version string // e.g. "26.6.2"
	Build   string // e.g. "25G83"
	Major   int    // e.g. 26; 0 if unknown
}

// DetectMacOS returns the running macOS version, or the zero value when it cannot be
// determined (non-macOS host, sw_vers missing, unexpected output).
func DetectMacOS() MacOSInfo {
	if runtime.GOOS != "darwin" {
		return MacOSInfo{}
	}
	sw := func(flag string) string {
		out, err := exec.Command("/usr/bin/sw_vers", flag).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	v := sw("-productVersion")
	return MacOSInfo{Version: v, Build: sw("-buildVersion"), Major: ParseMajor(v)}
}

// ParseMajor extracts the major version from "26.6.2", "15.7", "10.15.7" style strings.
func ParseMajor(v string) int {
	v = strings.TrimSpace(v)
	major, _, _ := strings.Cut(v, ".")
	n, err := strconv.Atoi(major)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// HostArch returns the running CPU architecture in uname -m terms (x86_64, arm64).
func HostArch() string {
	if runtime.GOARCH == "amd64" {
		return "x86_64"
	}
	return runtime.GOARCH
}

func tee(buf *bytes.Buffer, w io.Writer) io.Writer {
	if w == nil {
		return buf
	}
	return io.MultiWriter(buf, w)
}

// RunCheck runs a single check and streams output to opts.OutWriter/ErrWriter.
// Skipped-for-VM returns nil; skipped-for-sudo returns an error wrapping ErrSkipped.
func RunCheck(ctx context.Context, ch catalog.Check, opts Options) error {
	res := Run(ctx, ch, opts, opts.OutWriter, opts.ErrWriter)
	if res.Skipped && res.Err == nil && opts.ErrWriter != nil {
		fmt.Fprintf(opts.ErrWriter, "  (skipped: %s)\n", res.SkipReason)
	}
	return res.Err
}

// RunCheckCapture runs a single check and returns captured stdout, stderr, and error.
func RunCheckCapture(ctx context.Context, ch catalog.Check, opts Options) (stdout, stderr string, err error) {
	res := Run(ctx, ch, opts, nil, nil)
	return res.Stdout, res.Stderr, res.Err
}

// RunChecks runs multiple checks in sequence.
func RunChecks(ctx context.Context, checks []catalog.Check, opts Options) []error {
	var errs []error
	for i := range checks {
		ch := checks[i]
		if err := RunCheck(ctx, ch, opts); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ch.Name, err))
		}
	}
	return errs
}

// sudoArgsForCheck returns the arguments to pass to sudo before the actual command.
// When SudoAllowPrompt is true, we omit -n so sudo can prompt for a password when needed.
func sudoArgsForCheck(ch catalog.Check, opts Options) []string {
	if !ch.Sudo || !opts.UseSudo {
		return nil
	}
	if opts.SudoAllowPrompt {
		return nil // allow sudo to prompt
	}
	return []string{"-n"} // non-interactive: fail if password required
}

// safeEnv returns a minimal environment: fixed PATH, no DYLD_*/LD_* injection vars.
func safeEnv() []string {
	env := []string{"PATH=" + safePath, "LC_ALL=C"}
	for _, k := range []string{"HOME", "USER", "LOGNAME", "TERM", "TMPDIR", "SUDO_USER"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

var tildeRe = regexp.MustCompile(`(^|[\s="':])~(/|$|\s)`)

// ExpandUserHome replaces a word-leading ~ with the invoking user's home directory.
// Under sudo it uses SUDO_USER's home so user-scoped checks look at the right account.
func ExpandUserHome(script string) (string, error) {
	if !strings.Contains(script, "~") {
		return script, nil
	}
	home, err := InvokingUserHome()
	if err != nil {
		return script, err
	}
	return tildeRe.ReplaceAllString(script, "${1}"+strings.ReplaceAll(home, "$", "$$")+"${2}"), nil
}

// InvokingUserHome is the home folder of the user who ran the tool, or of the sudo caller when run under sudo.
func InvokingUserHome() (string, error) {
	if os.Geteuid() == 0 {
		if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
			if u, err := user.Lookup(name); err == nil && u.HomeDir != "" {
				return u.HomeDir, nil
			}
		}
	}
	return os.UserHomeDir()
}
