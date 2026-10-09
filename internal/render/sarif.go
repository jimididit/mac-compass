package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
)

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	projectURL   = "https://github.com/jimididit/mac-compass"
)

// SARIF renders the report as SARIF 2.1.0 for tools that ingest it. Findings describe a machine, not
// source files, so each result carries a logical location (the host) rather than a file location;
// viewers that require file locations, such as GitHub code scanning, will not display them.
// Passing findings are omitted.
func SARIF(rep output.Report) ([]byte, error) {
	rules := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range rep.Findings {
		if f.Status == output.StatusPass {
			continue
		}
		if _, ok := rules[f.ID]; !ok {
			rules[f.ID] = sarifRule{
				ID:               f.ID,
				Name:             ruleName(f.ID),
				ShortDescription: sarifText{Text: f.Title},
				HelpURI:          projectURL + "/blob/main/docs/checks.md",
				Properties:       map[string]any{"tags": attackTags(f.Attack)},
			}
		}
		results = append(results, sarifResult{
			RuleID:  f.ID,
			Level:   level(f),
			Kind:    kind(f),
			Message: sarifText{Text: message(f)},
			Locations: []sarifLocation{{LogicalLocations: []sarifLogical{
				{Name: hostName(rep), Kind: "module"},
			}}},
			PartialFingerprints: map[string]string{"macCompass/v1": fingerprint(f)},
			Properties:          map[string]any{"checkId": f.CheckID, "severity": string(f.Severity), "status": string(f.Status)},
		})
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	doc := sarifDoc{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "mac-compass",
				Version:        rep.Tool.Version,
				InformationURI: projectURL,
				Rules:          ruleList,
			}},
			Results: results,
			Properties: map[string]any{
				"macosVersion": rep.Host.MacOSVersion, "arch": rep.Host.Arch, "startedAt": rep.StartedAt,
			},
		}},
	}
	if doc.Runs[0].Results == nil {
		doc.Runs[0].Results = []sarifResult{}
	}
	return json.MarshalIndent(doc, "", "  ")
}

func level(f output.Finding) string {
	switch {
	case f.Status == output.StatusError:
		return "warning"
	case f.Status == output.StatusInfo:
		return "note"
	}
	switch f.Severity {
	case output.SeverityCritical, output.SeverityHigh:
		return "error"
	case output.SeverityMedium:
		return "warning"
	}
	return "note"
}

func kind(f output.Finding) string {
	if f.Status == output.StatusInfo {
		return "informational"
	}
	return "fail"
}

func message(f output.Finding) string {
	var b strings.Builder
	b.WriteString(f.Title)
	if f.Detail != "" {
		b.WriteString("\n\n" + f.Detail)
	}
	if f.Remediation != "" {
		b.WriteString("\n\nFix: " + f.Remediation)
	}
	return b.String()
}

func attackTags(ids []string) []string {
	tags := []string{"security", "macos"}
	for _, id := range ids {
		tags = append(tags, "external/mitre-attack/"+strings.ToLower(id))
	}
	return tags
}

func ruleName(id string) string {
	parts := strings.FieldsFunc(id, func(r rune) bool { return r == '.' || r == '-' })
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "")
}

func hostName(rep output.Report) string {
	if rep.Host.Hostname != "" {
		return rep.Host.Hostname
	}
	return "this-mac"
}

// fingerprint is stable across runs for the same finding, so viewers can track it over time. It
// uses the finding's identity (check and title), not its detail, which can change run to run.
func fingerprint(f output.Finding) string {
	sum := sha256.Sum256([]byte(f.CheckID + "\x00" + f.ID + "\x00" + f.Title))
	return hex.EncodeToString(sum[:16])
}

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	HelpURI          string         `json:"helpUri"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Kind                string            `json:"kind"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogical `json:"logicalLocations"`
}

type sarifLogical struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}
