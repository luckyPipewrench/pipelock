// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"
)

//go:embed assess_template.html
var assessTemplateHTML string

//go:embed assess_summary_template.html
var assessSummaryTemplateHTML string

// renderAssessmentHTML renders the full assessment as a self-contained HTML document.
func renderAssessmentHTML(w io.Writer, a *Assessment) error {
	funcMap := template.FuncMap{
		"gradeColor": gradeColor,
		"sevColor":   severityColor,
		"sevBadge":   severityBadge,
		"percent":    scorePercent,
	}
	tmpl, err := template.New("assessment").Funcs(funcMap).Parse(assessTemplateHTML)
	if err != nil {
		return fmt.Errorf("parse assessment template: %w", err)
	}
	return tmpl.Execute(w, a)
}

// renderSummaryHTML renders the free-tier summary as a self-contained HTML document.
func renderSummaryHTML(w io.Writer, s *Summary) error {
	funcMap := template.FuncMap{
		"gradeColor": gradeColor,
		"sevColor":   severityColor,
		"sevBadge":   severityBadge,
		"percent":    scorePercent,
	}
	tmpl, err := template.New("summary").Funcs(funcMap).Parse(assessSummaryTemplateHTML)
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
		return "#22c55e"
	case assessGradeB:
		return "#3b82f6"
	case assessGradeC:
		return "#eab308"
	case assessGradeD:
		return "#f97316"
	default: // F and unknown
		return "#ef4444"
	}
}

// severityColor returns the hex color for a finding severity badge.
func severityColor(sev string) string {
	switch sev {
	case assessSevCritical:
		return "#ef4444"
	case assessSevHigh:
		return "#f97316"
	case assessSevMedium:
		return "#eab308"
	case assessSevLow:
		return "#3b82f6"
	default: // info and unknown
		return "#6b7280"
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
