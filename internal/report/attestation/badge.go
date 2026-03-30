// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"fmt"
	"html"
	"strings"
)

// SVG renders a compact trust badge.
// Layout: [PIPELOCK | A | 91].
func SVG(a Attestation) string {
	gc := gradeColor(a.OverallScore)
	grade := html.EscapeString(strings.ToUpper(a.OverallGrade))
	score := a.OverallScore

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="138" height="24" viewBox="0 0 138 24" role="img" aria-label="Pipelock: Grade %s, Score %d">
  <rect width="78" height="24" rx="4" fill="#0f172a"/>
  <rect x="78" width="28" height="24" fill="%s"/>
  <rect x="106" width="32" height="24" rx="0" fill="#1e293b"/>
  <rect x="134" y="0" width="4" height="24" rx="4" fill="#1e293b"/>
  <text x="8" y="16" font-family="Verdana,Geneva,sans-serif" font-size="10" font-weight="700" fill="#94a3b8">PIPELOCK</text>
  <text x="92" y="16.5" text-anchor="middle" font-family="Verdana,Geneva,sans-serif" font-size="13" font-weight="700" fill="#fff">%s</text>
  <text x="122" y="16" text-anchor="middle" font-family="Verdana,Geneva,sans-serif" font-size="11" font-weight="600" fill="#e2e8f0">%d</text>
</svg>`, grade, score, gc, grade, score)
}

func gradeColor(score int) string {
	switch {
	case score >= 90:
		return "#15803d"
	case score >= 80:
		return "#1d4ed8"
	case score >= 70:
		return "#a16207"
	case score >= 60:
		return "#c2410c"
	default:
		return "#b91c1c"
	}
}
