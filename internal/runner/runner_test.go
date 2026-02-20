package runner

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jimididit/mac-compass/internal/catalog"
)

func TestExpandUserHome(t *testing.T) {
	// No tilde: unchanged
	got, err := ExpandUserHome("/etc/path")
	if err != nil {
		t.Fatalf("ExpandUserHome: %v", err)
	}
	if got != "/etc/path" {
		t.Errorf("ExpandUserHome(\"/etc/path\") = %q", got)
	}

	// With tilde: should expand to actual home
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("UserHomeDir: %v", err)
	}
	got, err = ExpandUserHome("~/Library/LaunchAgents")
	if err != nil {
		t.Fatalf("ExpandUserHome: %v", err)
	}
	want := home + "/Library/LaunchAgents"
	if got != want {
		t.Errorf("ExpandUserHome(\"~/Library/LaunchAgents\") = %q; want %q", got, want)
	}
}

func TestRunCheck_SkipSudo(t *testing.T) {
	ch := catalog.Check{Section: "test", Name: "needs sudo", Command: "true", Sudo: true}
	opts := DefaultOptions()
	opts.SkipSudo = true
	opts.OutWriter = bytes.NewBuffer(nil)
	opts.ErrWriter = bytes.NewBuffer(nil)

	err := RunCheck(context.Background(), ch, opts)
	if err == nil {
		t.Error("RunCheck with Sudo=true and SkipSudo=true should return error")
	}
	if !strings.Contains(err.Error(), "sudo") {
		t.Errorf("error should mention sudo: %v", err)
	}
}

func TestRunCheck_RequiresHardware_VMMode(t *testing.T) {
	ch := catalog.Check{Section: "test", Name: "efi", Command: "true", RequiresHardware: true}
	opts := DefaultOptions()
	opts.VMMode = true
	var errBuf bytes.Buffer
	opts.ErrWriter = &errBuf

	err := RunCheck(context.Background(), ch, opts)
	if err != nil {
		t.Errorf("RunCheck with RequiresHardware and VMMode should skip (no error): %v", err)
	}
	if !strings.Contains(errBuf.String(), "VM") {
		t.Logf("stderr should mention VM skip: %q", errBuf.String())
	}
}

func TestRunCheckCapture_SimpleCommand(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("skipping exec test on non-Unix OS")
	}
	ch := catalog.Check{Section: "test", Name: "echo", Command: "printf", Args: []string{"%s", "ok"}}
	opts := DefaultOptions()
	opts.Timeout = 5 * time.Second

	stdout, stderr, err := RunCheckCapture(context.Background(), ch, opts)
	if err != nil {
		t.Fatalf("RunCheckCapture: %v", err)
	}
	if stdout != "ok" {
		t.Errorf("stdout = %q; want \"ok\"", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr = %q; want empty", stderr)
	}
}

func TestRunCheckCapture_Script(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("skipping exec test on non-Unix OS")
	}
	ch := catalog.Check{Section: "test", Name: "script", Script: "echo -n script-ok"}
	opts := DefaultOptions()
	opts.Timeout = 5 * time.Second

	stdout, _, err := RunCheckCapture(context.Background(), ch, opts)
	if err != nil {
		t.Fatalf("RunCheckCapture (script): %v", err)
	}
	if !strings.Contains(stdout, "script-ok") {
		t.Errorf("stdout = %q; want to contain \"script-ok\"", stdout)
	}
}

func TestRunCheckCapture_NonexistentCommand(t *testing.T) {
	ch := catalog.Check{Section: "test", Name: "bad", Command: "/nonexistent/binary/xyz", Args: nil}
	opts := DefaultOptions()
	opts.Timeout = 2 * time.Second

	_, _, err := RunCheckCapture(context.Background(), ch, opts)
	if err == nil {
		t.Error("RunCheckCapture with nonexistent command should return error")
	}
}

func TestRunCheckCapture_SkipSudo(t *testing.T) {
	ch := catalog.Check{Section: "test", Name: "sudo", Command: "true", Sudo: true}
	opts := DefaultOptions()
	opts.SkipSudo = true

	stdout, stderr, err := RunCheckCapture(context.Background(), ch, opts)
	if err == nil {
		t.Error("RunCheckCapture with Sudo and SkipSudo should return error")
	}
	if stdout != "" || stderr != "" {
		t.Errorf("expected no output when error; got stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestRunCheckCapture_VMModeSkipsHardware(t *testing.T) {
	ch := catalog.Check{Section: "test", Name: "efi", Command: "true", RequiresHardware: true}
	opts := DefaultOptions()
	opts.VMMode = true

	stdout, stderr, err := RunCheckCapture(context.Background(), ch, opts)
	if err != nil {
		t.Errorf("VMMode + RequiresHardware should skip with nil error: %v", err)
	}
	if stdout != "" || stderr != "" {
		t.Errorf("skipped check should return empty output; got stdout=%q stderr=%q", stdout, stderr)
	}
}
