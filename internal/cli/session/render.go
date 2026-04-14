// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

// Column header constants used by the table renderers. Extracted so
// goconst does not trip on repeated literals in the subcommand tests.
const (
	colKey        = "KEY"
	colAgent      = "AGENT"
	colIP         = "IP"
	colTier       = "TIER"
	colEscalation = "ESCALATION"
	colScore      = "SCORE"
	colInFlight   = "IN-FLIGHT"
	colLastActive = "LAST-ACTIVE"
)

// renderList writes a human-readable table of session snapshots to w.
func renderList(w io.Writer, snaps []proxy.SessionSnapshot) error {
	if len(snaps) == 0 {
		_, err := fmt.Fprintln(w, "No sessions match.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		colKey, colAgent, colIP, colTier, colEscalation, colScore, colLastActive)
	for _, s := range snaps {
		tier := s.AirlockTier
		if tier == "" {
			tier = "none"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%.2f\t%s\n",
			s.Key, defaultDash(s.Agent), defaultDash(s.ClientIP),
			tier, defaultDash(s.EscalationLevel), s.ThreatScore,
			relativeTime(s.LastActivity))
	}
	return tw.Flush()
}

// renderDetail writes a human-readable inspect view of a SessionDetail.
func renderDetail(w io.Writer, d proxy.SessionDetail) error {
	buf := &strings.Builder{}
	fmt.Fprintf(buf, "Session %s\n", d.Key)
	fmt.Fprintf(buf, "  kind:             %s\n", defaultDash(d.Kind))
	fmt.Fprintf(buf, "  agent:            %s\n", defaultDash(d.Agent))
	fmt.Fprintf(buf, "  client_ip:        %s\n", defaultDash(d.ClientIP))
	fmt.Fprintf(buf, "  airlock_tier:     %s\n", defaultIfEmpty(d.AirlockTier, "none"))
	if !d.AirlockEnteredAt.IsZero() {
		fmt.Fprintf(buf, "  airlock_entered:  %s (%s ago)\n",
			d.AirlockEnteredAt.UTC().Format(time.RFC3339),
			formatDuration(time.Since(d.AirlockEnteredAt)))
	} else {
		fmt.Fprintln(buf, "  airlock_entered:  -")
	}
	fmt.Fprintf(buf, "  in_flight:        %d\n", d.InFlight)
	fmt.Fprintf(buf, "  escalation:       %s (%d)\n", defaultDash(d.EscalationLevel), d.EscalationLevelInt)
	fmt.Fprintf(buf, "  threat_score:     %.2f\n", d.ThreatScore)
	fmt.Fprintf(buf, "  block_all:        %t\n", d.BlockAll)
	fmt.Fprintf(buf, "  taint_level:      %s\n", defaultDash(d.TaintLevel))
	fmt.Fprintf(buf, "  contaminated:     %t\n", d.Contaminated)
	if d.CurrentTaskID != "" {
		fmt.Fprintf(buf, "  current_task_id:  %s\n", d.CurrentTaskID)
	}
	if d.CurrentTaskLabel != "" {
		fmt.Fprintf(buf, "  current_task:     %s\n", d.CurrentTaskLabel)
	}
	fmt.Fprintf(buf, "  last_activity:    %s (%s ago)\n",
		d.LastActivity.UTC().Format(time.RFC3339), formatDuration(time.Since(d.LastActivity)))

	fmt.Fprintln(buf, "  recent_events:")
	if len(d.RecentEvents) == 0 {
		fmt.Fprintln(buf, "    (none)")
	} else {
		for _, e := range d.RecentEvents {
			fmt.Fprintf(buf, "    [%s] %s target=%s score=%.2f detail=%s\n",
				e.At.UTC().Format(time.RFC3339), e.Kind, defaultDash(e.Target), e.Score, e.Detail)
		}
	}

	_, err := io.WriteString(w, buf.String())
	return err
}

// renderExplanation writes a human-readable explain view of a
// SessionExplanation.
func renderExplanation(w io.Writer, e proxy.SessionExplanation) error {
	buf := &strings.Builder{}
	fmt.Fprintf(buf, "Session %s explanation\n", e.Key)
	fmt.Fprintf(buf, "  tier:                %s\n", defaultIfEmpty(e.Tier, "none"))
	fmt.Fprintf(buf, "  reason:              %s\n", defaultDash(e.Reason))
	if e.Trigger != "" {
		fmt.Fprintf(buf, "  trigger:             %s (source=%s)\n", e.Trigger, defaultDash(e.TriggerSource))
	}
	fmt.Fprintf(buf, "  escalation:          %s (%d)\n", defaultDash(e.EscalationLevel), e.EscalationLevelInt)
	fmt.Fprintf(buf, "  threat_score:        %.2f\n", e.ThreatScore)
	if !e.EnteredAt.IsZero() {
		fmt.Fprintf(buf, "  entered_at:          %s (%s ago)\n",
			e.EnteredAt.UTC().Format(time.RFC3339), formatDuration(time.Since(e.EnteredAt)))
	}
	if e.EvidenceKind != "" || e.EvidenceDetail != "" {
		fmt.Fprintln(buf, "  evidence:")
		if !e.EvidenceAt.IsZero() {
			fmt.Fprintf(buf, "    at:     %s\n", e.EvidenceAt.UTC().Format(time.RFC3339))
		}
		if e.EvidenceKind != "" {
			fmt.Fprintf(buf, "    kind:   %s\n", e.EvidenceKind)
		}
		if e.EvidenceTarget != "" {
			fmt.Fprintf(buf, "    target: %s\n", e.EvidenceTarget)
		}
		if e.EvidenceDetail != "" {
			fmt.Fprintf(buf, "    detail: %s\n", e.EvidenceDetail)
		}
	} else {
		fmt.Fprintln(buf, "  evidence:            (none recorded)")
	}
	if e.NextDeescalationTier != "" {
		fmt.Fprintf(buf, "  next_deescalation:   tier=%s", e.NextDeescalationTier)
		if !e.NextDeescalationAt.IsZero() {
			fmt.Fprintf(buf, " at=%s (in %s)",
				e.NextDeescalationAt.UTC().Format(time.RFC3339),
				formatDuration(time.Until(e.NextDeescalationAt)))
		} else {
			fmt.Fprint(buf, " (no timer — manual recovery only)")
		}
		fmt.Fprintln(buf)
	}
	_, err := io.WriteString(w, buf.String())
	return err
}

// defaultDash returns s when non-empty, or "-" to keep tables tidy.
func defaultDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// defaultIfEmpty returns s when non-empty, or the provided fallback.
func defaultIfEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// formatDuration prints a short fixed-width duration suitable for
// operator tables. Negative durations are treated as zero (the estimate
// may have already elapsed).
func formatDuration(d time.Duration) string {
	if d < 0 {
		return "0s"
	}
	if d < time.Second {
		return "0s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}

// relativeTime formats LastActivity as "ago" for list tables.
func relativeTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return formatDuration(time.Since(t)) + " ago"
}
