// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidenceview

import (
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// ExplanationField is a single labeled fact about a decision. Present is false
// when the source field is empty/absent; Detail renders "not reported" so the
// UI never fabricates a value.
type ExplanationField struct {
	Present bool
	Label   string
	Detail  string
}

// DecisionExplanation surfaces, in bounded prose, WHY the boundary decided as
// it did for one receipt. Every field is independently populated; there is no
// aggregate verdict beyond the receipt's own Verdict.
type DecisionExplanation struct {
	// Core verdict
	Verdict       ExplanationField
	DecisionPhase ExplanationField
	Transport     ExplanationField
	Method        ExplanationField

	// Scanner detail
	Layer    ExplanationField
	Pattern  ExplanationField
	Severity ExplanationField

	// Policy context
	PolicyHash      ExplanationField
	ActionType      ExplanationField
	SideEffectClass ExplanationField
	Reversibility   ExplanationField

	// Taint context
	TaintLevel         ExplanationField
	TaintContaminated  ExplanationField
	TaintDecision      ExplanationField
	TaintReason        ExplanationField
	TaintSourceCount   ExplanationField
	TaintSourcesRawLen int // raw count; sources themselves are RAW-gated

	// Deferral context (populated when DecisionPhase indicates a defer)
	DeferID          ExplanationField
	ResolutionPolicy ExplanationField
	ResolutionSource ExplanationField

	// Redaction summary
	Redaction ExplanationField

	// Shield summary
	Shield ExplanationField

	// Semantics
	Intent         ExplanationField
	DataClassesIn  ExplanationField
	DataClassesOut ExplanationField

	// Identity
	Target    ExplanationField
	Actor     ExplanationField
	Principal ExplanationField
	ChainSeq  ExplanationField
}

const notReported = "not reported"

func field(label, value string) ExplanationField {
	if value == "" {
		return ExplanationField{Present: false, Label: label, Detail: notReported}
	}
	return ExplanationField{Present: true, Label: label, Detail: value}
}

func boolField(label string, value bool, present bool) ExplanationField {
	if !present {
		return ExplanationField{Present: false, Label: label, Detail: notReported}
	}
	detail := "no"
	if value {
		detail = "yes"
	}
	return ExplanationField{Present: true, Label: label, Detail: detail}
}

func intField(label string, value int, present bool) ExplanationField {
	if !present {
		return ExplanationField{Present: false, Label: label, Detail: notReported}
	}
	return ExplanationField{Present: true, Label: label, Detail: fmt.Sprintf("%d", value)}
}

// uintField renders a uint64 field (e.g. a chain sequence) without an
// int conversion, which would risk a gosec integer-overflow flag.
func uintField(label string, value uint64, present bool) ExplanationField {
	if !present {
		return ExplanationField{Present: false, Label: label, Detail: notReported}
	}
	return ExplanationField{Present: true, Label: label, Detail: fmt.Sprintf("%d", value)}
}

func sliceField(label string, values []string) ExplanationField {
	if len(values) == 0 {
		return ExplanationField{Present: false, Label: label, Detail: notReported}
	}
	detail := ""
	for i, v := range values {
		if i > 0 {
			detail += ", "
		}
		detail += v
	}
	return ExplanationField{Present: true, Label: label, Detail: detail}
}

// ExplainReceipt builds a DecisionExplanation from one receipt, surfacing WHY
// the boundary decided as it did. Uses bounded vocabulary; never fabricates a
// value for an absent field.
func ExplainReceipt(r receipt.Receipt) DecisionExplanation {
	ar := r.ActionRecord

	// Redaction summary
	redactionField := ExplanationField{Present: false, Label: "Redaction", Detail: notReported}
	if ar.Redaction != nil {
		redactionField = ExplanationField{
			Present: true,
			Label:   "Redaction",
			Detail:  fmt.Sprintf("%d redactions across %d classes", ar.Redaction.TotalRedactions, len(ar.Redaction.ByClass)),
		}
	}

	// Shield summary
	shieldField := ExplanationField{Present: false, Label: "Shield", Detail: notReported}
	if ar.Shield != nil {
		shieldField = ExplanationField{
			Present: true,
			Label:   "Shield",
			Detail:  fmt.Sprintf("%d rewrites via %s", ar.Shield.TotalRewrites, ar.Shield.Pipeline),
		}
	}

	// Taint source count (raw sources are RAW-gated; only the count is shown in metadata view)
	taintSourceCount := len(ar.RecentTaintSources)

	// Contaminated is meaningful only when SessionTaintLevel is present.
	taintPresent := ar.SessionTaintLevel != ""

	return DecisionExplanation{
		Verdict:       field("Verdict", ar.Verdict),
		DecisionPhase: field("Decision Phase", ar.DecisionPhase),
		Transport:     field("Transport", ar.Transport),
		Method:        field("Method", ar.Method),

		Layer:    field("Layer", ar.Layer),
		Pattern:  field("Pattern", ar.Pattern),
		Severity: field("Severity", ar.Severity),

		PolicyHash:      field("Policy Hash", shortHash(ar.PolicyHash)),
		ActionType:      field("Action Type", string(ar.ActionType)),
		SideEffectClass: field("Side Effect Class", string(ar.SideEffectClass)),
		Reversibility:   field("Reversibility", string(ar.Reversibility)),

		TaintLevel:         field("Session Taint Level", ar.SessionTaintLevel),
		TaintContaminated:  boolField("Session Contaminated", ar.SessionContaminated, taintPresent),
		TaintDecision:      field("Taint Decision", ar.TaintDecision),
		TaintReason:        field("Taint Decision Reason", ar.TaintDecisionReason),
		TaintSourceCount:   intField("Recent Taint Sources", taintSourceCount, taintSourceCount > 0),
		TaintSourcesRawLen: taintSourceCount,

		DeferID:          field("Defer ID", ar.DeferID),
		ResolutionPolicy: field("Resolution Policy", ar.ResolutionPolicy),
		ResolutionSource: field("Resolution Source", ar.ResolutionSource),

		Redaction: redactionField,
		Shield:    shieldField,

		Intent:         field("Intent", ar.Intent),
		DataClassesIn:  sliceField("Data Classes In", ar.DataClassesIn),
		DataClassesOut: sliceField("Data Classes Out", ar.DataClassesOut),

		Target:    field("Target", ar.Target),
		Actor:     field("Actor", ar.Actor),
		Principal: field("Principal", ar.Principal),
		ChainSeq:  uintField("Chain Seq", ar.ChainSeq, true),
	}
}

// Fields returns all explanation fields (excluding Verdict and ChainSeq which
// are used as the heading) in display order. Used by the HTML template.
func (e DecisionExplanation) Fields() []ExplanationField {
	return []ExplanationField{
		e.Transport,
		e.Method,
		e.Layer,
		e.Pattern,
		e.Severity,
		e.PolicyHash,
		e.ActionType,
		e.SideEffectClass,
		e.Reversibility,
		e.TaintLevel,
		e.TaintContaminated,
		e.TaintDecision,
		e.TaintReason,
		e.TaintSourceCount,
		e.DeferID,
		e.ResolutionPolicy,
		e.ResolutionSource,
		e.Redaction,
		e.Shield,
		e.Intent,
		e.DataClassesIn,
		e.DataClassesOut,
		e.Target,
		e.Actor,
		e.Principal,
	}
}

func redactField(f ExplanationField) ExplanationField {
	if !f.Present {
		return f
	}
	f.Detail = RedactedDestination
	return f
}

// RedactExplanation strips the raw, exfil-bearing receipt detail from an
// explanation for the metadata view, while keeping the decision SEMANTICS that
// the metadata investigator exists to show (Layer, Severity, ActionType, data
// classes, redaction/shield counts, etc.).
//
// Redacted (can carry a destination token or attacker/agent-controlled free
// text):
//   - Target: a destination URL can carry a capability token in its query.
//   - Intent: the agent's declared free-text intent — agent-controlled.
//   - TaintReason: the taint-decision reason may embed the tainting content.
//   - Pattern: usually a config pattern NAME, but a few decision paths set it to
//     a free-form reason string, so it is redacted fail-closed on that ambiguity.
//
// Kept visible (system/config values that are never attacker-controlled, so
// redacting them would gut the metadata view without adding safety):
//   - Redaction: the detail is integer counts only ("N redactions across M
//     classes") — the per-class names are never rendered.
//   - Shield: counts plus the configured shield pipeline name (a config label).
//   - DataClassesIn/Out: scanner-assigned data-class labels, not raw content.
//
// Raw taint SOURCES are already exposed only as a count; TaintSourcesRawLen is
// cleared so no per-source detail can be reconstructed downstream.
func RedactExplanation(e DecisionExplanation) DecisionExplanation {
	e.Target = redactField(e.Target)
	e.Intent = redactField(e.Intent)
	e.TaintReason = redactField(e.TaintReason)
	e.Pattern = redactField(e.Pattern)
	e.TaintSourcesRawLen = 0
	return e
}
