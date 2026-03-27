// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
)

// Hex color constants for HTML rendering. Shared across grade, severity,
// protection, risk, scenario, and check-status color functions.
const (
	colorGreen  = "#22c55e"
	colorBlue   = "#3b82f6"
	colorYellow = "#eab308"
	colorOrange = "#f97316"
	colorRed    = "#ef4444"
	colorGray   = "#6b7280"
)

//go:embed template.html
var assessTemplateHTML string

//go:embed summary_template.html
var assessSummaryTemplateHTML string

// maxPriorityActions is the upper bound on items returned by priorityActions.
const maxPriorityActions = 5

// truncHashLen is the prefix length shown by the truncHash template function.
const truncHashLen = 12

// FindingCounts holds per-severity tallies for the findings summary bar.
type FindingCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// assessFuncMap returns the shared template function map for assessment rendering.
func assessFuncMap() template.FuncMap {
	return template.FuncMap{
		"gradeColor":      gradeColor,
		"gradeFromScore":  func(score int) string { return gradeFromPercentage(score) },
		"sevColor":        severityColor,
		"sevBadge":        severityBadge,
		"percent":         scorePercent,
		"formatEvidence":  formatEvidence,
		"protColor":       protectionColor,
		"protLabel":       protectionLabel,
		"riskColor":       riskColor,
		"scenarioResult":  scenarioResult,
		"scenarioColor":   scenarioColor,
		"checkColor":      checkStatusColor,
		"execSummary":     execSummary,
		"truncHash":       truncHash,
		"addInts":         addInts,
		"add1":            func(i int) int { return i + 1 },
		"priorityActions": priorityActions,
		"auditBarColor":   auditBarColor,
		"findingCounts":   findingCounts,
		"toplineStory":    toplineStory,
		"summaryTopline":  summaryTopline,
		"serverStatColor": serverStatColor,
		"discoverCausedCap": func(a *Assessment) bool {
			if a.GradeCap == "" {
				return false
			}
			for _, cr := range a.CapReasons {
				if cr.Cap == a.GradeCap && cr.Source == sourceDiscover {
					return true
				}
			}
			return false
		},
	}
}

// renderAssessmentHTML renders the full assessment as a self-contained HTML document.
func renderAssessmentHTML(w io.Writer, a *Assessment) error {
	tmpl, err := template.New("assessment").Funcs(assessFuncMap()).Parse(assessTemplateHTML)
	if err != nil {
		return fmt.Errorf("parse assessment template: %w", err)
	}
	return tmpl.Execute(w, a)
}

// renderSummaryHTML renders the free-tier summary as a self-contained HTML document.
func renderSummaryHTML(w io.Writer, s *Summary) error {
	tmpl, err := template.New("summary").Funcs(assessFuncMap()).Parse(assessSummaryTemplateHTML)
	if err != nil {
		return fmt.Errorf("parse summary template: %w", err)
	}
	return tmpl.Execute(w, s)
}

// gradeColor returns the hex color for a letter grade badge.
// A=green, B=blue, C=yellow, D=orange, F=red.
func gradeColor(grade string) string {
	switch grade {
	case assessGradeA:
		return colorGreen
	case assessGradeB:
		return colorBlue
	case assessGradeC:
		return colorYellow
	case assessGradeD:
		return colorOrange
	default: // F and unknown
		return colorRed
	}
}

// severityColor returns the hex color for a finding severity badge.
func severityColor(sev string) string {
	switch sev {
	case assessSevCritical:
		return colorRed
	case assessSevHigh:
		return colorOrange
	case assessSevMedium:
		return colorYellow
	case assessSevLow:
		return colorBlue
	default: // info and unknown
		return colorGray
	}
}

// severityBadge returns the display label for a severity value.
func severityBadge(sev string) string {
	return strings.ToUpper(sev)
}

// scorePercent computes a 0-100 integer percentage for use in score bar widths.
// Returns 0 when maxScore is zero (skipped primitive) to prevent division by zero.
func scorePercent(score, maxScore int) int {
	if maxScore == 0 {
		return 0
	}
	return (score * 100) / maxScore
}

// formatEvidence pretty-prints a json.RawMessage for HTML display.
// Returns empty string for nil or JSON null evidence, and falls back to raw bytes on indent error.
func formatEvidence(raw json.RawMessage) string {
	if raw == nil || string(raw) == "null" {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

// protectionColor returns the hex color for a discover protection status.
func protectionColor(status string) string {
	switch status {
	case "protected_pipelock":
		return colorGreen
	case "protected_other":
		return colorBlue
	case "unprotected":
		return colorRed
	default:
		return colorGray
	}
}

// protectionLabel returns the display label for a discover protection status.
func protectionLabel(status string) string {
	switch status {
	case "protected_pipelock":
		return "PIPELOCK"
	case "protected_other":
		return "OTHER"
	case "unprotected":
		return "UNPROTECTED"
	default:
		return "UNKNOWN"
	}
}

// riskColor returns the hex color for a discover risk level.
func riskColor(risk string) string {
	switch risk {
	case "high":
		return colorRed
	case "medium":
		return colorYellow
	default:
		return colorGray
	}
}

// scenarioResult returns the display label for a simulation scenario outcome.
func scenarioResult(detected, limitation bool) string {
	if limitation {
		return "KNOWN LIMITATION"
	}
	if detected {
		return "DETECTED"
	}
	return "MISSED"
}

// scenarioColor returns the hex color for a simulation scenario outcome.
func scenarioColor(detected, limitation bool) string {
	if limitation {
		return colorGray
	}
	if detected {
		return colorGreen
	}
	return colorRed
}

// checkStatusColor returns the hex color for a verification check status.
func checkStatusColor(status string) string {
	switch status {
	case "pass":
		return colorGreen
	case "fail":
		return colorRed
	default:
		return colorGray
	}
}

// execSummary builds a 3-4 sentence plain-English executive summary from assessment data.
func execSummary(a *Assessment) string {
	var parts []string

	parts = append(parts, fmt.Sprintf(
		"This assessment evaluated a pipelock deployment across %d security dimensions on %s.",
		len(a.Sections), a.Manifest.Platform))

	if a.Sources.Simulate != nil {
		applicable := a.Sources.Simulate.Total - a.Sources.Simulate.KnownLimits
		parts = append(parts, fmt.Sprintf(
			"The scanner detected %d of %d simulated attack scenarios (%d%% coverage).",
			a.Sources.Simulate.Passed, applicable, a.Sources.Simulate.Percentage))
	}

	if a.Sources.Discover != nil {
		s := a.Sources.Discover.Summary
		total := s.TotalServers
		protected := s.ProtectedPipelock + s.ProtectedOther
		if total > 0 {
			parts = append(parts, fmt.Sprintf(
				"%d of %d MCP servers are protected (%d unprotected).",
				protected, total, s.Unprotected))
		}
	}

	if a.GradeCap != "" {
		parts = append(parts, fmt.Sprintf(
			"The overall score of %d/100 was capped at grade %s due to critical exposure.",
			a.OverallScore, a.GradeCap))
	} else {
		parts = append(parts, fmt.Sprintf(
			"Overall security posture: grade %s (%d/100).",
			a.OverallGrade, a.OverallScore))
	}

	return strings.Join(parts, " ")
}

// truncHash returns the first truncHashLen characters of a hash string followed
// by "...", or the full string if it is shorter than the threshold.
func truncHash(h string) string {
	if len(h) > truncHashLen {
		return h[:truncHashLen] + "..."
	}
	return h
}

// addInts returns the sum of two integers. Used in templates for inline addition.
func addInts(a, b int) int { return a + b }

// priorityActions extracts up to maxPriorityActions deduplicated remediation actions.
// Discover findings are grouped into a single combined action instead of appearing
// individually, since they all share the same fix (wrap with pipelock).
func priorityActions(findings []Finding) []string {
	var actions []string
	seen := make(map[string]bool)

	// Count unprotected servers for a combined action.
	var unprotectedHigh, unprotectedOther int
	for _, f := range findings {
		if f.Source == sourceDiscover {
			if f.Severity == assessSevHigh {
				unprotectedHigh++
			} else {
				unprotectedOther++
			}
		}
	}

	// Add combined MCP wrapping action first if there are unprotected servers.
	if unprotectedHigh+unprotectedOther > 0 {
		total := unprotectedHigh + unprotectedOther
		action := fmt.Sprintf("Wrap %d unprotected MCP server(s) with pipelock: `pipelock mcp proxy --config pipelock.yaml -- <command>`.", total)
		if unprotectedHigh > 0 {
			action += fmt.Sprintf(" %d high-risk server(s) with database or shell access should be prioritized.", unprotectedHigh)
		}
		actions = append(actions, action)
		seen[sourceDiscover] = true
	}

	for _, f := range findings {
		if f.Remediation == "" || f.Source == sourceDiscover { // discover already handled
			continue
		}
		key := f.Source + ":" + f.Category
		if seen[key] {
			continue
		}
		seen[key] = true
		actions = append(actions, f.Remediation)
		if len(actions) >= maxPriorityActions {
			break
		}
	}
	return actions
}

// findingCounts tallies findings by severity for the findings summary bar.
func findingCounts(findings []Finding) FindingCounts {
	var c FindingCounts
	for _, f := range findings {
		switch f.Severity {
		case assessSevCritical:
			c.Critical++
		case assessSevHigh:
			c.High++
		case assessSevMedium:
			c.Medium++
		case assessSevLow:
			c.Low++
		case assessSevInfo:
			c.Info++
		}
	}
	return c
}

// auditBarColor returns a hex color for config audit score bars based on
// the percentage of points earned. 90%+=green, 70%+=yellow, 50%+=orange, <50%=red.
func auditBarColor(score, maxScore int) string {
	if maxScore == 0 {
		return colorGray
	}
	pct := (score * 100) / maxScore
	switch {
	case pct >= 90:
		return colorGreen
	case pct >= 70:
		return colorYellow
	case pct >= 50:
		return colorOrange
	default:
		return colorRed
	}
}

// toplineStory builds a single bold sentence summarising the assessment outcome.
// When the grade is capped the sentence explains the cap using the reason that
// produced the effective GradeCap (not necessarily CapReasons[0]).
func toplineStory(a *Assessment) string {
	if a.GradeCap != "" && len(a.CapReasons) > 0 {
		reason := effectiveCapReason(a.GradeCap, a.CapReasons)
		return fmt.Sprintf("Scored %d/100 but capped at %s — %s.",
			a.OverallScore, a.GradeCap, reason)
	}
	return fmt.Sprintf("Scored %d/100. Overall security posture: %s.",
		a.OverallScore, a.OverallGrade)
}

// effectiveCapReason returns the reason string from the cap reason that matches
// the effective grade cap. Falls back to the first reason if no exact match.
func effectiveCapReason(gradeCap string, reasons []CapReason) string {
	for _, cr := range reasons {
		if cr.Cap == gradeCap {
			return cr.Reason
		}
	}
	return reasons[0].Reason
}

// summaryTopline builds a short sentence for the free-tier summary header.
// Unlike toplineStory it works with the Summary type (no CapReasons slice).
func summaryTopline(s *Summary) string {
	if s.GradeCap != "" {
		return fmt.Sprintf("Scored %d/100 but capped at %s due to critical exposure.",
			s.OverallScore, s.GradeCap)
	}
	return fmt.Sprintf("Scored %d/100. Overall security posture: %s.",
		s.OverallScore, s.OverallGrade)
}

// serverStatColor returns green when all servers are protected and red when
// any are unprotected. Used by the SERVERS PROTECTED stat tile in the header.
func serverStatColor(protected, total int) string {
	if protected < total {
		return colorRed
	}
	return colorGreen
}
