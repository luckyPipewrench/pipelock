// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidenceview

import (
	"embed"
	"html/template"
	"io"
	"time"
)

//go:embed single_agent.tmpl.html
var singleAgentFS embed.FS

var singleAgentTemplate = template.Must(template.ParseFS(singleAgentFS, "single_agent.tmpl.html"))

// RenderOptions controls the single-agent HTML renderer.
type RenderOptions struct {
	Title       string
	GeneratedAt time.Time // injected time; NO bare time.Now() inside the renderer
}

type singleAgentData struct {
	Title        string
	GeneratedAt  string
	Evidence     SessionEvidence
	Explanations []DecisionExplanation
}

// RenderSingleAgentHTML renders a self-contained, offline HTML report for one
// agent's evidence. The output contains inline CSS only (no external assets),
// matching the CSP-safe shape of the enterprise template. The renderer accepts
// an injected time via opts.GeneratedAt to keep tests stable.
func RenderSingleAgentHTML(w io.Writer, ev SessionEvidence, exp []DecisionExplanation, opts RenderOptions) error {
	title := opts.Title
	if title == "" {
		title = "Pipelock Evidence Report"
	}
	generatedAt := opts.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now()
	}

	data := singleAgentData{
		Title:        title,
		GeneratedAt:  generatedAt.UTC().Format(time.RFC3339),
		Evidence:     ev,
		Explanations: exp,
	}
	return singleAgentTemplate.Execute(w, data)
}
