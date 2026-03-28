// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"fmt"
	"html"
	"strings"
)

// SVG renders a compact SVG badge for the supplied attestation.
func SVG(a Attestation) string {
	scoreColor := badgeColor(a.OverallScore)
	grade := html.EscapeString(strings.ToUpper(a.OverallGrade))
	label := html.EscapeString(a.BadgeText)
	score := html.EscapeString(fmt.Sprintf("Score: %d/100", a.OverallScore))
	artifact := html.EscapeString(a.PrimaryArtifact)

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="360" height="72" viewBox="0 0 360 72" role="img" aria-label="%s">
  <defs>
    <linearGradient id="bg" x1="0" x2="1" y1="0" y2="0">
      <stop offset="0%%" stop-color="#0f172a"/>
      <stop offset="100%%" stop-color="%s"/>
    </linearGradient>
  </defs>
  <rect x="0.5" y="0.5" width="359" height="71" rx="12" fill="url(#bg)" stroke="#ffffff" stroke-opacity="0.14"/>
  <rect x="12" y="12" width="88" height="48" rx="9" fill="#ffffff" fill-opacity="0.08"/>
  <text x="56" y="33" text-anchor="middle" font-family="Inter, Arial, sans-serif" font-size="14" font-weight="700" fill="#fff">%s</text>
  <text x="56" y="49" text-anchor="middle" font-family="Inter, Arial, sans-serif" font-size="10" fill="#ffffff" fill-opacity="0.78">Verified</text>
  <text x="116" y="29" font-family="Inter, Arial, sans-serif" font-size="17" font-weight="700" fill="#fff">%s</text>
  <text x="116" y="48" font-family="Inter, Arial, sans-serif" font-size="12" fill="#ffffff" fill-opacity="0.82">%s</text>
  <text x="116" y="62" font-family="Inter, Arial, sans-serif" font-size="10" fill="#ffffff" fill-opacity="0.66">%s</text>
</svg>`, label, scoreColor, label, score, grade, artifact)
}

func badgeColor(score int) string {
	switch {
	case score >= 90:
		return "#16a34a"
	case score >= 80:
		return "#2563eb"
	case score >= 70:
		return "#ca8a04"
	case score >= 60:
		return "#ea580c"
	default:
		return "#dc2626"
	}
}
