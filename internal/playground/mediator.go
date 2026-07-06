// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"fmt"
	"io"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// HONESTY RULE (enforced by the renderer):
// Every on-screen line carries exactly one EVIDENCE CLASS label, and no line
// may use a stronger class than the underlying evidence supports.
//
// Evidence classes (matching EvidenceClass constants in types.go):
//   - pipelock_decision  : signed receipt in the hash-linked chain (allow/block/warn/…).
//                          The ONLY cryptographically Pipelock-bound class.
//   - collector_witness  : the collector's own signed statement (separate key).
//                          "Target-side lab instrumentation."
//   - host_containment   : bypass failing at the kernel. No receipt. Operational result.
//   - narration          : the agent's printed intent. Unsigned, context only.

// MediatorEvent is one event in the terminal mediator timeline.
// Callers populate exactly the fields that apply to the class:
//   - ClassPipelockDecision → Verdict + Summary (safe, redacted destination class)
//   - ClassCollectorWitness → Summary
//   - ClassHostContainment  → Summary
//   - ClassNarration        → Text
type MediatorEvent struct {
	Class   EvidenceClass
	Verdict string // "allow", "block", "warn", etc. — only for ClassPipelockDecision
	Summary string // short, secret-free description
	Text    string // raw text — only for ClassNarration (agent stdout)
}

// mediatorLegend is a one-line legend printed at the top of every mediator view.
const mediatorLegend = "LEGEND: [pipelock_decision=signed receipt] " +
	"[collector_witness=signed collector stmt] " +
	"[host_containment=kernel-observed] " +
	"[narration=unsigned agent intent]"

// RenderMediator writes the mediator timeline to w. Each event occupies its
// own block with a clear EVIDENCE-CLASS label. A block verdict is rendered
// prominently with ">>> BLOCKED <<<". When color is true, blocks are rendered
// in a bracket that stands out; tests always pass color=false for
// deterministic output.
//
// The renderer never adds or enriches raw secret-shaped values — it only
// formats the class, verdict, and summary/text fields provided by the caller.
func RenderMediator(w io.Writer, events []MediatorEvent, color bool) {
	_, _ = fmt.Fprintln(w, mediatorLegend)
	_, _ = fmt.Fprintln(w, strings.Repeat("-", 72))

	for _, ev := range events {
		switch ev.Class {
		case ClassPipelockDecision:
			renderPipelockDecision(w, ev, color)
		case ClassCollectorWitness:
			renderCollectorWitness(w, ev)
		case ClassHostContainment:
			renderHostContainment(w, ev)
		case ClassNarration:
			renderNarration(w, ev)
		default:
			// Unknown class: render safely with label "unknown" — never
			// upgrade to a stronger class.
			_, _ = fmt.Fprintf(w, "[unknown] %s\n", ev.Summary)
		}
	}
}

// renderPipelockDecision formats a ClassPipelockDecision event.
// Block verdicts use the ">>> BLOCKED <<<" marker so they visually pop.
func renderPipelockDecision(w io.Writer, ev MediatorEvent, color bool) {
	_ = color
	verdict := strings.ToLower(ev.Verdict)
	if verdict == verdictBlock {
		_, _ = fmt.Fprintf(w, "[pipelock_decision] >>> BLOCKED <<< %s\n", ev.Summary)
	} else {
		_, _ = fmt.Fprintf(w, "[pipelock_decision] %s %s\n",
			strings.ToUpper(verdict), ev.Summary)
	}
}

// renderCollectorWitness formats a ClassCollectorWitness event.
// Deliberately distinct styling from pipelock_decision — no BLOCKED marker,
// no verdict label.
func renderCollectorWitness(w io.Writer, ev MediatorEvent) {
	_, _ = fmt.Fprintf(w, "[collector_witness] %s\n", ev.Summary)
}

// renderHostContainment formats a ClassHostContainment event.
// Must NOT use pipelock_decision styling or the BLOCKED marker — this is an
// operational observation, not a cryptographic receipt.
func renderHostContainment(w io.Writer, ev MediatorEvent) {
	_, _ = fmt.Fprintf(w, "[host_containment] %s\n", ev.Summary)
}

// renderNarration formats a ClassNarration event.
// Plaintext — unsigned agent output, no styling that implies enforcement.
func renderNarration(w io.Writer, ev MediatorEvent) {
	_, _ = fmt.Fprintf(w, "[narration] %s\n", ev.Text)
}

// verdictBlock is the normalized verdict string for a block decision.
const verdictBlock = "block"

// MediatorEventsFromEvidence reads a flight-recorder JSONL evidence file,
// extracts decision receipts, and maps each to a ClassPipelockDecision
// MediatorEvent. Session-control receipts prove coverage windows; they are not
// agent allow/deny decisions and must not be rendered as one.
//
// The summary for each event is built from the normalized verdict and the
// transport layer field — raw target values are NOT included because they may
// carry secret-shaped canary values. The caller must ensure the evidence file
// was produced with redaction enabled.
func MediatorEventsFromEvidence(evidenceFile string) ([]MediatorEvent, error) {
	receipts, err := receipt.ExtractReceipts(evidenceFile)
	if err != nil {
		return nil, fmt.Errorf("mediator: extract receipts: %w", err)
	}

	events := make([]MediatorEvent, 0, len(receipts))
	for _, r := range receipts {
		ar := r.ActionRecord
		if ar.SessionControl != nil {
			continue
		}
		verdict := receipt.NormalizeVerdict(ar.Verdict)

		// Build a secret-free summary. We include:
		//   - verdict  (allow/block/warn/…)
		//   - transport (http-forward, mcp, etc.)
		//   - layer    (dlp/ssrf/…) when present — never the raw target value
		//   - signature presence (true/false) — proves this is a signed receipt
		summary := buildSafeDecisionSummary(verdict, ar.Transport, ar.Layer, r.Signature != "")

		events = append(events, MediatorEvent{
			Class:   ClassPipelockDecision,
			Verdict: verdict,
			Summary: summary,
		})
	}
	return events, nil
}

// buildSafeDecisionSummary constructs a short, secret-free description for a
// pipelock decision event. It never includes the raw target URL or body values.
func buildSafeDecisionSummary(verdict, transport, layer string, signed bool) string {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "verdict=%s", verdict)
	if transport != "" {
		_, _ = fmt.Fprintf(&b, " transport=%s", transport)
	}
	if layer != "" {
		_, _ = fmt.Fprintf(&b, " layer=%s", layer)
	}
	if signed {
		b.WriteString(" sig=present")
	}
	return b.String()
}

// --- Helper constructors for T9 timeline assembly ---

// WitnessEvent constructs a ClassCollectorWitness MediatorEvent from a Witness.
// The summary reports the observed/total canary count. The Witness carries no
// secret-shaped values by design — it only holds counts and hashes.
func WitnessEvent(w Witness) MediatorEvent {
	summary := fmt.Sprintf("canary observed=%d total=%d run=%s",
		w.ObservedCount, w.TotalCount, safeNonce(w.RunNonce))
	return MediatorEvent{
		Class:   ClassCollectorWitness,
		Summary: summary,
	}
}

// ContainmentEvent constructs a ClassHostContainment MediatorEvent.
// blocked=true means the direct-egress attempt was denied at the kernel level.
// detail is a short, operator-supplied description (no secret values).
func ContainmentEvent(blocked bool, detail string) MediatorEvent {
	action := "allowed"
	if blocked {
		action = "blocked"
	}
	summary := fmt.Sprintf("kernel-containment=%s: %s", action, detail)
	return MediatorEvent{
		Class:   ClassHostContainment,
		Summary: summary,
	}
}

// NarrationEvent constructs a ClassNarration MediatorEvent from agent stdout text.
// The text is passed through verbatim; the caller is responsible for ensuring it
// does not contain raw secret values before passing to the renderer.
func NarrationEvent(text string) MediatorEvent {
	return MediatorEvent{
		Class: ClassNarration,
		Text:  text,
	}
}

// safeNonce truncates a run nonce to 8 chars for display — enough to identify
// the run without showing an unwieldy UUID or entropy blob.
func safeNonce(nonce string) string {
	if len(nonce) <= 8 {
		return nonce
	}
	return nonce[:8] + "…"
}
