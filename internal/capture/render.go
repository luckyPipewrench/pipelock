// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strconv"
)

//go:embed template.html
var diffTemplateHTML string

// diffColorRed is the badge suffix for new-block change type rows.
const diffColorRed = "red"

// diffColorYellow is the badge suffix for new-allow change type rows.
const diffColorYellow = "yellow"

// diffColorGreen is the badge suffix for unchanged rows.
const diffColorGreen = "green"

// diffColorGray is the badge suffix for all other change types.
const diffColorGray = "gray"

// diffFuncMap returns the template function map for diff report rendering.
func diffFuncMap() template.FuncMap {
	return template.FuncMap{
		// changeColor maps a change type to a CSS badge color suffix.
		// new_block→red, new_allow→yellow, unchanged→green, default→gray.
		"changeColor": func(changeType string) string {
			switch changeType {
			case changeTypeNewBlock:
				return diffColorRed
			case changeTypeNewAllow:
				return diffColorYellow
			case changeTypeUnchanged:
				return diffColorGreen
			default:
				return diffColorGray
			}
		},
		// pct computes an integer percentage: (n / total) * 100.
		// Returns "0" when total is zero to prevent division by zero.
		"pct": func(n, total int) string {
			if total == 0 {
				return "0"
			}
			return strconv.Itoa((n * 100) / total)
		},
	}
}

// RenderDiffHTML renders the DiffReport as a self-contained HTML document.
// The template is embedded at compile time from template.html.
func RenderDiffHTML(w io.Writer, d *DiffReport) error {
	tmpl, err := template.New("diff").Funcs(diffFuncMap()).Parse(diffTemplateHTML)
	if err != nil {
		return fmt.Errorf("parse diff template: %w", err)
	}
	return tmpl.Execute(w, d)
}

// RenderDiffJSON renders the DiffReport as indented JSON.
func RenderDiffJSON(w io.Writer, d *DiffReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}
