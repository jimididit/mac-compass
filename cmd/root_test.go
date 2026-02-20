package cmd

import (
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
