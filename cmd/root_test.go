package cmd

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestChoiceToSubcommand(t *testing.T) {
	tests := []struct {
		choice string
		want   string
	}{
		{"1", "triage"},
		{"triage", "triage"},
		{"2", "processes"},
		{"processes", "processes"},
		{"3", "kernel"},
		{"kernel", "kernel"},
		{"4", "persistence"},
		{"5", "network"},
		{"6", "security-tools"},
		{"security-tools", "security-tools"},
		{"7", "advanced"},
		{"8", "checklist"},
		{"9", "harden"},
		{"10", "refs"},
		{"refs", "refs"},
		{"11", "run-all"},
		{"12", "accounts"},
		{"accounts", "accounts"},
		{"run-all", "run-all"},
		{"", ""},
		{"unknown", ""},
		{"99", ""},
	}
	for _, tt := range tests {
		got := choiceToSubcommand(tt.choice)
		if got != tt.want {
			t.Errorf("choiceToSubcommand(%q) = %q; want %q", tt.choice, got, tt.want)
		}
	}
}

func TestRequireDarwin(t *testing.T) {
	t.Setenv("MAC_COMPASS_ALLOW_NON_DARWIN", "")
	err := requireDarwin()
	if runtime.GOOS == "darwin" {
		if err != nil {
			t.Fatalf("on darwin: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "macOS") {
		t.Fatalf("want macOS-only error; got %v", err)
	}
	t.Setenv("MAC_COMPASS_ALLOW_NON_DARWIN", "1")
	if err := requireDarwin(); err != nil {
		t.Fatalf("override ignored: %v", err)
	}
}

// The menu loops until quit, survives a failing section, and rejects unknown input.
func TestInteractiveMenu_Loops(t *testing.T) {
	t.Setenv("MAC_COMPASS_ALLOW_NON_DARWIN", "")
	out, errOut := bytes.NewBuffer(nil), bytes.NewBuffer(nil)
	rootCmd.SetOut(out)
	rootCmd.SetErr(errOut)
	rootCmd.SetIn(strings.NewReader("checklist\nbogus\n12\nq\n"))
	_ = rootCmd.Flags().Set("help", "false") // earlier tests leave --help set on the shared command
	rootCmd.SetArgs([]string{})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("menu: %v", err)
	}
	if strings.Count(out.String(), "Enter number or name") != 4 {
		t.Errorf("menu should prompt once per input line:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "When you suspect a compromise") {
		t.Error("checklist did not run")
	}
	if !strings.Contains(errOut.String(), `Unknown choice: "bogus"`) {
		t.Errorf("unknown choice not reported: %q", errOut.String())
	}
	if runtime.GOOS != "darwin" && !strings.Contains(errOut.String(), "only run on macOS") {
		t.Errorf("failing section should be reported, not fatal: %q", errOut.String())
	}
	rootCmd.SetIn(nil)
}
