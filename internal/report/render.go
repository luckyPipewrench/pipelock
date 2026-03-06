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
				return "#f44336"
			case RiskYellow:
				return "#eab308"
			default:
				return "#00CC66"
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
			return t.UTC().Format("2006-01-02 15:04:05 UTC")
		},
		"join": func(items []string) string {
			return strings.Join(items, ", ")
		},
		"severityColor": func(sev string) string {
			switch sev {
			case severityCritical:
				return "#f44336"
			case severityHigh:
				return "#f97316"
			case severityMedium:
				return "#eab308"
			default:
				return "#999999"
			}
		},
		"eventSeverity": func(ev Event) string {
			return eventSeverity(&ev)
		},
		"execSummary": func(r Report) string {
			return generateExecSummary(&r)
		},
		"pct": func(part, total int) string {
			if total == 0 {
				return "0"
			}
			return fmt.Sprintf("%.0f", float64(part)/float64(total)*100)
		},
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"timelineBars": func(buckets []TimeBucket) []timelineBar {
			return buildTimelineBars(buckets)
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

// generateExecSummary creates a human-readable executive summary paragraph.
func generateExecSummary(r *Report) string {
	s := &r.Summary
	dur := r.TimeRange.End.Sub(r.TimeRange.Start)

	var period string
	switch {
	case dur <= 0:
		period = "single-point"
	case dur < time.Hour:
		m := int(dur.Minutes())
		if m <= 1 {
			period = "1-minute"
		} else {
			period = fmt.Sprintf("%d-minute", m)
		}
	case dur < 24*time.Hour:
		period = fmt.Sprintf("%.1f-hour", dur.Hours())
	default:
		period = fmt.Sprintf("%.1f-day", dur.Hours()/24)
	}

	// Traffic events only (excludes admin events like startup, config_reload).
	inspected := s.Allowed + s.Blocks + s.Warnings

	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "Over a %s observation window, pipelock processed %d %s across %d unique %s. ",
		period, inspected, plural(inspected, "request", "requests"),
		s.UniqueDomains, plural(s.UniqueDomains, "domain", "domains"))

	switch r.Risk {
	case RiskRed:
		_, _ = fmt.Fprintf(&b, "%d critical %s detected, requiring immediate attention. ",
			s.Criticals, plural(s.Criticals, "event was", "events were"))
	case RiskYellow:
		_, _ = fmt.Fprintf(&b, "%d %s and %d %s recorded. ",
			s.Blocks, plural(s.Blocks, "block", "blocks"),
			s.Warnings, plural(s.Warnings, "warning", "warnings"))
	default:
		b.WriteString("No security events were detected. All traffic was clean. ")
	}

	if s.Allowed > 0 && inspected > 0 {
		_, _ = fmt.Fprintf(&b, "%d of %d inspected requests (%.0f%%) were allowed without intervention.",
			s.Allowed, inspected, float64(s.Allowed)/float64(inspected)*100)
	}

	return b.String()
}

// plural returns singular when n == 1, otherwise returns the plural form.
func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}

// timelineBar holds pre-computed SVG coordinates for one stacked bar.
type timelineBar struct {
	Label   string  // time label (e.g. "10:03")
	X       float64 // x position in viewBox units
	CX      float64 // center x for labels
	W       float64 // bar width in viewBox units
	AY, AH  float64 // allowed: y and height
	WY, WH  float64 // warns: y and height
	BY, BH  float64 // blocks: y and height
	Total   int
	Blocks  int
	Warns   int
	Allowed int
}

// svgViewBoxWidth is the fixed width of the timeline SVG viewBox.
const svgViewBoxWidth = 1000

// svgBarAreaHeight is the height reserved for bars (top portion of viewBox).
const svgBarAreaHeight = 180

// svgCountLabelY is the top margin reserved for count labels above bars.
const svgCountLabelY = 15

// buildTimelineBars pre-computes SVG bar positions from timeline buckets.
// Includes ALL buckets (even empty ones) so time labels stay evenly spaced.
func buildTimelineBars(buckets []TimeBucket) []timelineBar {
	if len(buckets) == 0 {
		return nil
	}

	// Find peak bucket total.
	peak := 0
	for _, b := range buckets {
		total := b.Blocks + b.Warns + b.Allowed
		if total > peak {
			peak = total
		}
	}
	if peak == 0 {
		return nil
	}

	// Choose label format based on span. Multi-day spans use date labels
	// since time-of-day would collapse to "00:00" for daily buckets.
	span := buckets[len(buckets)-1].Start.Sub(buckets[0].Start)
	labelFmt := "15:04"
	if span >= 24*time.Hour {
		labelFmt = "Jan 2"
	}

	n := len(buckets)
	// 80% of width for bars, 20% for gaps.
	barW := float64(svgViewBoxWidth) * 0.8 / float64(n)
	gap := float64(svgViewBoxWidth) * 0.2 / float64(n)

	// Offset bars below the count label area.
	barTop := float64(svgCountLabelY) + 5
	barHeight := float64(svgBarAreaHeight) - barTop

	bars := make([]timelineBar, 0, n)
	for i, b := range buckets {
		total := b.Blocks + b.Warns + b.Allowed
		x := float64(i) * (barW + gap)
		cx := x + barW/2

		bar := timelineBar{
			Label:   b.Start.UTC().Format(labelFmt),
			X:       x,
			CX:      cx,
			W:       barW,
			Total:   total,
			Blocks:  b.Blocks,
			Warns:   b.Warns,
			Allowed: b.Allowed,
		}

		if total > 0 {
			// Heights proportional to peak, scaled to bar area.
			aH := float64(b.Allowed) / float64(peak) * barHeight
			wH := float64(b.Warns) / float64(peak) * barHeight
			bH := float64(b.Blocks) / float64(peak) * barHeight

			// Stack from bottom of bar area: blocks, warns, allowed on top.
			bottom := barTop + barHeight
			bY := bottom - bH
			wY := bY - wH
			aY := wY - aH

			bar.AY = aY
			bar.AH = aH
			bar.WY = wY
			bar.WH = wH
			bar.BY = bY
			bar.BH = bH
		}

		bars = append(bars, bar)
	}

	return bars
}

// RenderJSON renders the report as indented JSON.
func RenderJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
