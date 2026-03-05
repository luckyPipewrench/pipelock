package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"
)

//go:embed template.html
var templateHTML string

// RenderHTML renders the report as a self-contained HTML document.
func RenderHTML(w io.Writer, r *Report) error {
	funcMap := template.FuncMap{
		"riskColor": func(risk RiskRating) string {
			switch risk {
			case RiskRed:
				return "#ef4444"
			case RiskYellow:
				return "#eab308"
			default:
				return "#22c55e"
			}
		},
		"riskLabel": func(risk RiskRating) string {
			switch risk {
			case RiskRed:
				return "HIGH RISK"
			case RiskYellow:
				return "MODERATE"
			default:
				return "LOW RISK"
			}
		},
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05 UTC")
		},
		"join": func(items []string) string {
			return strings.Join(items, ", ")
		},
		"severityColor": func(sev string) string {
			switch sev {
			case severityCritical:
				return "#ef4444"
			case severityHigh:
				return "#f97316"
			case severityMedium:
				return "#eab308"
			default:
				return "#94a3b8"
			}
		},
		"eventSeverity": func(ev Event) string {
			return eventSeverity(&ev)
		},
		"eventJSON": func(ev Event) template.HTML {
			b, err := json.MarshalIndent(ev, "", "  ")
			if err != nil {
				return "{}"
			}
			// Safe to mark as HTML: json.Marshal escapes special chars,
			// and the data originates from parsed JSONL (no user HTML).
			return template.HTML(b) //nolint:gosec // G203: data from json.Marshal is safe
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(templateHTML)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}
	return tmpl.Execute(w, r)
}

// RenderJSON renders the report as indented JSON.
func RenderJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
