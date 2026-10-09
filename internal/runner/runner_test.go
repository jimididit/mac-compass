package runner

import (
	"bytes"
	"context"
	"errors"
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

func skipNonUnix(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("skipping exec test on non-Unix OS")
	}
}

func TestRun_OKExit(t *testing.T) {
	skipNonUnix(t)
	opts := DefaultOptions()
	opts.Timeout = 5 * time.Second

	ch := catalog.Check{Section: "test", Name: "nomatch", Script: "echo hi | grep -v hi"}
	if res := Run(context.Background(), ch, opts, nil, nil); res.Err == nil || res.ExitCode != 1 {
		t.Fatalf("exit 1 without ok_exit should fail; got err=%v code=%d", res.Err, res.ExitCode)
	}
	ch.OKExit = []int{1}
	if res := Run(context.Background(), ch, opts, nil, nil); res.Err != nil {
		t.Fatalf("exit 1 with ok_exit [1] should pass; got %v", res.Err)
	}
	ch.Script = "exit 2"
	if res := Run(context.Background(), ch, opts, nil, nil); res.Err == nil {
		t.Fatal("exit 2 not in ok_exit should fail")
	}
}

func TestRun_SkipSudoIsSkipped(t *testing.T) {
	ch := catalog.Check{Section: "test", Name: "sudo", Command: "true", Sudo: true}
	opts := DefaultOptions()
	opts.SkipSudo = true
	res := Run(context.Background(), ch, opts, nil, nil)
	if !res.Skipped || !errors.Is(res.Err, ErrSkipped) {
		t.Fatalf("want skipped with ErrSkipped; got %+v", res)
	}
}

func TestRun_TimeoutKillsPipeline(t *testing.T) {
	skipNonUnix(t)
	ch := catalog.Check{Section: "test", Name: "hang", Script: "sleep 30 | cat"}
	opts := DefaultOptions()
	opts.Timeout = 300 * time.Millisecond

	start := time.Now()
	res := Run(context.Background(), ch, opts, nil, nil)
	if res.Err == nil || !strings.Contains(res.Err.Error(), "timeout") {
		t.Fatalf("want timeout error; got %v", res.Err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("timeout took %v; pipeline children not reaped", elapsed)
	}
}

func TestRun_ScrubbedEnv(t *testing.T) {
	skipNonUnix(t)
	t.Setenv("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib")
	t.Setenv("PATH", "/tmp/evil:"+os.Getenv("PATH"))
	ch := catalog.Check{Section: "test", Name: "env", Script: "echo \"$PATH|$DYLD_INSERT_LIBRARIES\""}
	opts := DefaultOptions()
	opts.Timeout = 5 * time.Second

	res := Run(context.Background(), ch, opts, nil, nil)
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if got := strings.TrimSpace(res.Stdout); got != safePath+"|" {
		t.Errorf("env not scrubbed: %q", got)
	}
}

func TestRun_StreamsAndCaptures(t *testing.T) {
	skipNonUnix(t)
	var out bytes.Buffer
	ch := catalog.Check{Section: "test", Name: "echo", Script: "echo hi"}
	opts := DefaultOptions()
	opts.Timeout = 5 * time.Second
	res := Run(context.Background(), ch, opts, &out, nil)
	if res.Stdout != "hi\n" || out.String() != "hi\n" {
		t.Errorf("captured=%q streamed=%q", res.Stdout, out.String())
	}
}

func TestExpandUserHome_OnlyWordLeading(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	got, err := ExpandUserHome(`ls ~/x; grep 'a~b' f; echo "~/y"; ls ~`)
	if err != nil {
		t.Fatal(err)
	}
	want := `ls ` + home + `/x; grep 'a~b' f; echo "` + home + `/y"; ls ` + home
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}
