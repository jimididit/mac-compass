package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestRootHelp ensures the root command runs with --help without error.
func TestRootHelp(t *testing.T) {
	out := bytes.NewBuffer(nil)
	errOut := bytes.NewBuffer(nil)
	rootCmd.SetOut(out)
	rootCmd.SetErr(errOut)
	rootCmd.SetArgs([]string{"--help"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("rootCmd.Execute() with --help: %v", err)
	}
	if out.Len() == 0 && errOut.Len() == 0 {
		t.Error("expected help output on stdout or stderr")
	}
}

// TestVersionCommand runs `mac-compass version` and checks output.
func TestVersionCommand(t *testing.T) {
	out := bytes.NewBuffer(nil)
	errOut := bytes.NewBuffer(nil)
	rootCmd.SetOut(out)
	rootCmd.SetErr(errOut)
	rootCmd.SetArgs([]string{"version"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("rootCmd.Execute() version: %v", err)
	}
	s := out.String()
	if s == "" {
		s = errOut.String()
	}
	if s == "" {
		t.Fatal("version command produced no output")
	}
	if !strings.Contains(s, "mac-compass") {
		t.Errorf("version output should contain \"mac-compass\": %q", s)
	}
}

// TestTriageHelp runs `mac-compass triage --help`.
func TestTriageHelp(t *testing.T) {
	out := bytes.NewBuffer(nil)
	errOut := bytes.NewBuffer(nil)
	rootCmd.SetOut(out)
	rootCmd.SetErr(errOut)
	rootCmd.SetArgs([]string{"triage", "--help"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("rootCmd.Execute() triage --help: %v", err)
	}
	combined := out.String() + errOut.String()
	if !strings.Contains(combined, "triage") {
		t.Errorf("triage help should mention triage: %q", combined)
	}
}

// TestChecklistCommand runs `mac-compass checklist` (no external commands).
func TestChecklistCommand(t *testing.T) {
	out := bytes.NewBuffer(nil)
	errOut := bytes.NewBuffer(nil)
	rootCmd.SetOut(out)
	rootCmd.SetErr(errOut)
	rootCmd.SetArgs([]string{"checklist"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("rootCmd.Execute() checklist: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "compromise") || !strings.Contains(s, "Document") {
		t.Errorf("checklist output should contain compromise and Document: %q", s)
	}
}

// TestRefsCommand runs `mac-compass refs`.
func TestRefsCommand(t *testing.T) {
	out := bytes.NewBuffer(nil)
	errOut := bytes.NewBuffer(nil)
	rootCmd.SetOut(out)
	rootCmd.SetErr(errOut)
	rootCmd.SetArgs([]string{"refs"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("rootCmd.Execute() refs: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "http") {
		t.Errorf("refs output should contain URLs: %q", s)
	}
}
