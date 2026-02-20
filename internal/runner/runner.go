package runner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jimididit/mac-compass/internal/catalog"
)

// Options configures how checks are run.
type Options struct {
	UseSudo        bool
	Timeout        time.Duration
	SkipSudo       bool // If true, skip checks that require sudo
	VMMode         bool // If true, skip checks that require hardware (e.g. T2)
	SudoAllowPrompt bool // If true and running in a TTY, sudo will prompt for password when needed
	OutWriter      interface{ Write([]byte) (int, error) }
	ErrWriter      interface{ Write([]byte) (int, error) }
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

// RunCheck runs a single check and writes output to opts.OutWriter/ErrWriter.
func RunCheck(ctx context.Context, ch catalog.Check, opts Options) error {
	if ch.Sudo && opts.SkipSudo {
		return fmt.Errorf("check requires sudo (use --no-skip-sudo or run with sudo)")
	}
	if ch.RequiresHardware && opts.VMMode {
		fmt.Fprintf(opts.ErrWriter, "  (skipped in VM: requires hardware)\n")
		return nil
	}
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	script := ch.Script
	if script != "" {
		var err error
		script, err = ExpandUserHome(script)
		if err != nil {
			return fmt.Errorf("expand home: %w", err)
		}
	}

	sudoArgs := sudoArgsForCheck(ch, opts)
	var cmd *exec.Cmd
	if ch.Sudo && opts.UseSudo {
		if script != "" {
			cmd = exec.CommandContext(runCtx, "sudo", append(sudoArgs, "sh", "-c", script)...)
		} else {
			cmd = exec.CommandContext(runCtx, "sudo", append(sudoArgs, append([]string{ch.Command}, ch.Args...)...)...)
		}
	} else {
		if script != "" {
			cmd = exec.CommandContext(runCtx, "sh", "-c", script)
		} else {
			cmd = exec.CommandContext(runCtx, ch.Command, ch.Args...)
		}
	}
	cmd.Stdout = opts.OutWriter
	cmd.Stderr = opts.ErrWriter
	err := cmd.Run()
	if err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("timeout after %v", opts.Timeout)
		}
		return err
	}
	return nil
}

// RunCheckCapture runs a single check and returns captured stdout, stderr, and error.
func RunCheckCapture(ctx context.Context, ch catalog.Check, opts Options) (stdout, stderr string, err error) {
	if ch.Sudo && opts.SkipSudo {
		return "", "", fmt.Errorf("check requires sudo (use --no-skip-sudo or run with sudo)")
	}
	if ch.RequiresHardware && opts.VMMode {
		return "", "", nil // skipped
	}
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	script := ch.Script
	if script != "" {
		var expandErr error
		script, expandErr = ExpandUserHome(script)
		if expandErr != nil {
			return "", "", fmt.Errorf("expand home: %w", expandErr)
		}
	}

	sudoArgs := sudoArgsForCheck(ch, opts)
	var cmd *exec.Cmd
	if ch.Sudo && opts.UseSudo {
		if script != "" {
			cmd = exec.CommandContext(runCtx, "sudo", append(sudoArgs, "sh", "-c", script)...)
		} else {
			cmd = exec.CommandContext(runCtx, "sudo", append(sudoArgs, append([]string{ch.Command}, ch.Args...)...)...)
		}
	} else {
		if script != "" {
			cmd = exec.CommandContext(runCtx, "sh", "-c", script)
		} else {
			cmd = exec.CommandContext(runCtx, ch.Command, ch.Args...)
		}
	}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	runErr := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()
	if runErr != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return stdout, stderr, fmt.Errorf("timeout after %v", opts.Timeout)
		}
		return stdout, stderr, runErr
	}
	return stdout, stderr, nil
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

// ExpandUserHome replaces ~ with the user's home directory in script.
func ExpandUserHome(script string) (string, error) {
	if !strings.Contains(script, "~") {
		return script, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return script, err
	}
	return strings.ReplaceAll(script, "~", home), nil
}
