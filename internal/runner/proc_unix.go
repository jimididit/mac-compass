//go:build !windows

package runner

import (
	"os/exec"
	"syscall"
)

// configureProcess puts the child in its own process group and, on cancel,
// signals the whole group so pipeline members do not outlive the timeout.
func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
}
