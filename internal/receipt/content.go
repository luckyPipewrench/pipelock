// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// ActionReceiptContentKind is the content-boundary kind of a signed v1 action
// receipt as written to the recorder.
const ActionReceiptContentKind = "pipelock.action_receipt.v1"

const (
	cContent    = receiptcontent.Content
	cIdentity   = receiptcontent.Identity
	cGenerated  = receiptcontent.Generated
	cEnum       = receiptcontent.Enum
	cProvenID   = receiptcontent.ProvenID
	cDynamic    = receiptcontent.Dynamic
	cRunSession = receiptcontent.RunSession
	// A policy hash this process computed from its configuration is a
	// generated digest; an override a caller chose stays content.
	cComputedDigest = receiptcontent.ComputedDigest
)

// actionReceiptProducer is the only capability that may exclude the
// emitter's own generated fields from a v1 receipt projection. It is
// unexported: other packages can project a v1 receipt only as unproven.
var actionReceiptProducer = receiptcontent.Register(receiptcontent.Schema{
	Kind:   ActionReceiptContentKind,
	Fields: actionReceiptFields(),
	Enums: map[string][]string{
		"action_record.action_type":       actionTypeNames(),
		"action_record.side_effect_class": {string(SideEffectNone), string(SideEffectExternalRead), string(SideEffectExternalWrite), string(SideEffectFinancial), string(SideEffectPhysical)},
		"action_record.reversibility":     {string(ReversibilityFull), string(ReversibilityCompensatable), string(ReversibilityIrreversible), string(ReversibilityUnknown)},
		"action_record.verdict":           {"block", "allow", "warn", "ask", "strip", "forward", "defer"},
		"action_record.decision_phase":    {DecisionPhaseIntent, DecisionPhaseOutcome, DecisionPhaseDefer, DecisionPhaseResolution},
		"action_record.session_control.kind": {
			string(SessionControlOpen), string(SessionControlHeartbeat), string(SessionControlClose),
		},
	},
	Outer: actionReceiptOuter,
})

// groupGateProducer is the group opener's capability for its gate entries.
var groupGateProducer = receiptcontent.Register(receiptcontent.Schema{
	Kind:   recorder.GroupGateContentKind,
	Fields: recorder.GroupGateFields(),
	Outer:  recorder.GroupGateOuter,
})

// transcriptRootProducer classifies a transcript root. Every value is the
// emitter's own chain state except the session handle, whose operator base is
// an identity.
var transcriptRootProducer = receiptcontent.Register(receiptcontent.Schema{
	Kind: "pipelock.transcript_root.v1",
	Fields: map[string]receiptcontent.Class{
		"session_id":    cRunSession,
		"final_seq":     cGenerated,
		"root_hash":     cGenerated,
		"receipt_count": cGenerated,
		"start_time":    cGenerated,
		"end_time":      cGenerated,
	},
	Outer: transcriptRootOuter,
})

// transcriptRootOuter derives a root's mirror. It no longer embeds the root
// hash prefix: generated values never enter mirror text.
func transcriptRootOuter(detail []byte) (receiptcontent.Outer, error) {
	var root TranscriptRoot
	if err := json.Unmarshal(detail, &root); err != nil {
		return receiptcontent.Outer{}, fmt.Errorf("decode transcript root mirror fields: %w", err)
	}
	return receiptcontent.Outer{
		Type:      recorder.TranscriptRootEntryType,
		EventKind: recorder.TranscriptRootEntryType,
		Summary:   fmt.Sprintf("transcript_root: %d receipts", root.ReceiptCount),
	}, nil
}

func actionTypeNames() []string {
	out := make([]string, 0, len(allActionTypes))
	for t := range allActionTypes {
		out = append(out, string(t))
	}
	return out
}

// actionReceiptFields classifies every JSON path of a v1 receipt. Generated
// fields are stamped by the emitter or derived from its own key and chain
// state and never come from EmitOpts. Identity fields are pairing handles:
// a hit rejects the receipt instead of collapsing identities into one marker.
// TestActionReceiptSchemaCoversEveryField fails when a field is unclassified.
func actionReceiptFields() map[string]receiptcontent.Class {
	f := map[string]receiptcontent.Class{
		"version":       cGenerated,
		"signature":     cGenerated,
		"signer_key":    cGenerated,
		"ext":           cDynamic,
		"ext.*":         cContent,
		"action_record": cContent,
	}
	ar := func(path string, c receiptcontent.Class) { f["action_record."+path] = c }
	for path, c := range map[string]receiptcontent.Class{
		"version":                             cGenerated,
		"action_id":                           cProvenID,
		"parent_action_id":                    cProvenID,
		"action_type":                         cEnum,
		"timestamp":                           cGenerated,
		"principal":                           cContent,
		"actor":                               cContent,
		"target":                              cContent,
		"intent":                              cContent,
		"side_effect_class":                   cEnum,
		"reversibility":                       cEnum,
		"policy_hash":                         cComputedDigest,
		"verdict":                             cEnum,
		"decision_phase":                      cEnum,
		"defer_id":                            cProvenID,
		"resolution_policy":                   cContent,
		"resolution_source":                   cContent,
		"session_id":                          cIdentity,
		"session_id_original":                 cIdentity,
		"session_taint_level":                 cContent,
		"session_contaminated":                cContent,
		"recent_taint_sources":                cContent,
		"recent_taint_sources[]":              cContent,
		"recent_taint_sources[].url":          cContent,
		"recent_taint_sources[].kind":         cContent,
		"recent_taint_sources[].level":        cContent,
		"recent_taint_sources[].timestamp":    cContent,
		"recent_taint_sources[].receipt_id":   cIdentity,
		"recent_taint_sources[].match_reason": cContent,
		"session_task_id":                     cIdentity,
		"session_task_label":                  cContent,
		"authority_kind":                      cContent,
		"taint_decision":                      cContent,
		"taint_decision_reason":               cContent,
		"task_override_applied":               cContent,
		"contract_winning_source":             cContent,
		"contract_live_verdict":               cContent,
		"contract_rule_id":                    cContent,
		"active_manifest_hash":                cComputedDigest,
		"contract_hash":                       cComputedDigest,
		"contract_selector_id":                cContent,
		"contract_generation":                 cContent,
		"transport":                           cContent,
		"method":                              cContent,
		"layer":                               cContent,
		"pattern":                             cContent,
		"severity":                            cContent,
		"request_id":                          receiptcontent.ProvenRequestID,
		"chain_prev_hash":                     cGenerated,
		"chain_seq":                           cGenerated,
		"run_nonce":                           cGenerated,
		"key_transition":                      cGenerated,
		"venue":                               cContent,
		"jurisdiction":                        cContent,
		"rulebook_id":                         cContent,
		"remedy_class":                        cContent,
		"contestation_window":                 cContent,
		"redaction":                           cContent,
		"redaction.profile":                   cContent,
		"redaction.provider":                  cContent,
		"redaction.parser":                    cContent,
		"redaction.total_redactions":          cContent,
		"redaction.by_class":                  cDynamic,
		"redaction.by_class.*":                cContent,
		"redaction.cache_boundary_kept":       cContent,
		"shield":                              cContent,
		"session_control":                     cContent,
		"session_control.kind":                cEnum,
		"session_control.open":                cContent,
		"session_control.heartbeat":           cContent,
		"session_control.close":               cContent,
		// The recorder session embeds the operator's session base; it is a
		// pairing identity, validated at acquisition and never redacted. Only
		// the base is projected; the proven run suffix is generated.
		"session_control.open.recorder_session":   cRunSession,
		"session_control.open.policy_hash":        cComputedDigest,
		"session_control.open.heartbeat_seconds":  cContent,
		"session_control.open.genesis_anchor_log": cContent,
		"session_control.open.contained_uid":      cContent,
		"session_control.close.close_reason":      cContent,
	} {
		ar(path, c)
	}
	for _, list := range []string{"delegation_chain", "data_classes_in", "data_classes_out", "contract_policy_sources", "precedent_refs"} {
		ar(list, cContent)
		ar(list+"[]", cContent)
	}
	for _, name := range []string{
		"pipeline", "total_rewrites", "extension_probes", "tracking_beacons", "agent_traps",
		"fingerprint_shim_injected", "svg_foreign_objects", "svg_event_handlers", "svg_external_references",
		"svg_hidden_text", "svg_animation_injections", "body_bytes", "scanned_bytes", "partial",
		"adaptive_signals_recorded", "adaptive_signal_max_per_body",
	} {
		ar("shield."+name, cContent)
	}
	// Session-control nonces, chain heads, counters and the posture binding
	// are generated by the emitter or by the verified posture capsule it was
	// configured with; none comes from EmitOpts.
	for _, name := range []string{
		"run_nonce", "open_nonce", "signer_key_epoch", "chain_open_seq", "prior_chain_head",
		"prior_chain_seq", "genesis_hash", "genesis_anchor_head", "posture_capsule_sha256", "posture_signer_key_id",
		"containment_nonce", "group_binding",
	} {
		ar("session_control.open."+name, cGenerated)
	}
	for _, name := range []string{
		"run_nonce", "open_nonce", "beat", "chain_head", "chain_seq_head", "heartbeat_time",
		"fsync_errors_gated", "durability_blocks",
	} {
		ar("session_control.heartbeat."+name, cGenerated)
	}
	for _, name := range []string{
		"run_nonce", "open_nonce", "final_seq", "root_hash", "receipt_count",
		"fsync_errors_gated", "durability_blocks",
	} {
		ar("session_control.close."+name, cGenerated)
	}
	return f
}

// actionReceiptOuter derives the recorder mirror fields of a v1 receipt from
// its exact detail. It reads only Enum and Content values, never a generated
// field, so the mirror cannot reintroduce generated detector input.
func actionReceiptOuter(detail []byte) (receiptcontent.Outer, error) {
	var d struct {
		ActionRecord struct {
			ActionType ActionType `json:"action_type"`
			Verdict    string     `json:"verdict"`
			Transport  string     `json:"transport"`
		} `json:"action_record"`
	}
	if err := json.Unmarshal(detail, &d); err != nil {
		return receiptcontent.Outer{}, fmt.Errorf("decode action receipt mirror fields: %w", err)
	}
	ar := d.ActionRecord
	return receiptcontent.Outer{
		Type:      recorderEntryType,
		EventKind: string(ar.ActionType),
		Transport: ar.Transport,
		Summary:   fmt.Sprintf("receipt: %s %s %s", ar.Verdict, ar.ActionType, ar.Transport),
	}, nil
}

// ErrRetainedContent means configuration content that every receipt of an
// emitter carries (principal, actor, policy hash, recorder session) trips the
// recorder's receipt detector. It is a configuration refusal raised at
// activation or reload, never a per-request refusal.
var ErrRetainedContent = errors.New("receipt content: configuration content trips the receipt detector")

// validateRetainedContent scans the content every receipt of this emitter
// carries as one joint projection, with the same union of views and the
// recorder's own receipt detector that emission uses. The template is a
// session_open receipt, which carries every retained field at once.
func validateRetainedContent(rec *recorder.Recorder, principal, actor, policyHash, session string) error {
	if rec.ReceiptDetector() == nil {
		return nil
	}
	tmpl := Receipt{Version: ReceiptVersion, ActionRecord: ActionRecord{
		Version: ActionRecordVersion, ActionType: ActionRead, Principal: principal, Actor: actor, PolicyHash: policyHash,
		SideEffectClass: SideEffectNone, Reversibility: ReversibilityFull, Verdict: "allow", Transport: sessionControlTransport,
		Target:         sessionOpenTarget,
		SessionControl: &SessionControl{Kind: SessionControlOpen, Open: &SessionOpen{RecorderSession: session, PolicyHash: policyHash}},
	}}
	raw, err := json.Marshal(tmpl)
	if err != nil {
		return fmt.Errorf("%w: marshal template: %w", ErrRetainedContent, err)
	}
	rep, cs, err := rec.ScanReceiptContent(context.Background(), actionReceiptProducer, raw)
	if err == nil && cs == nil {
		err = rep.Err()
	}
	if err != nil {
		// The rejection names the field path and pattern, never the value.
		return fmt.Errorf("%w: %w", ErrRetainedContent, err)
	}
	return nil
}

// ValidateConfigHash checks a reloaded policy hash together with this
// emitter's retained content before UpdateConfigHash publishes it.
func (e *Emitter) ValidateConfigHash(hash string) error {
	if e == nil {
		return nil
	}
	return validateRetainedContent(e.recorder, e.principal, e.actor, hash, e.session)
}

// contentRecord builds every field of an action record that does not depend
// on chain state. The emitter adds only generated stamps under its chain lock.
func (e *Emitter) contentRecord(opts EmitOpts, actionType ActionType, sideEffect SideEffectClass, reversibility Reversibility, policyHash string) ActionRecord {
	return ActionRecord{
		Version:               ActionRecordVersion,
		ActionID:              opts.ActionID,
		ParentActionID:        opts.ParentActionID,
		ActionType:            actionType,
		Principal:             e.principal,
		Actor:                 e.actorLabel(opts),
		DelegationChain:       nil, // Populated when delegation tracking ships
		Target:                opts.Target,
		SideEffectClass:       sideEffect,
		Reversibility:         reversibility,
		PolicyHash:            policyHash,
		Verdict:               NormalizeVerdict(opts.Verdict),
		DecisionPhase:         opts.DecisionPhase,
		DeferID:               opts.DeferID,
		ResolutionPolicy:      opts.ResolutionPolicy,
		ResolutionSource:      opts.ResolutionSource,
		SessionID:             opts.SessionID,
		SessionIDOriginal:     opts.SessionIDOriginal,
		SessionTaintLevel:     opts.SessionTaintLevel,
		SessionContaminated:   opts.SessionContaminated,
		RecentTaintSources:    append([]session.TaintSourceRef(nil), opts.RecentTaintSources...),
		SessionTaskID:         opts.SessionTaskID,
		SessionTaskLabel:      opts.SessionTaskLabel,
		AuthorityKind:         opts.AuthorityKind,
		TaintDecision:         opts.TaintDecision,
		TaintDecisionReason:   opts.TaintDecisionReason,
		TaskOverrideApplied:   opts.TaskOverrideApplied,
		ContractWinningSource: opts.ContractWinningSource,
		ContractLiveVerdict:   opts.ContractLiveVerdict,
		ContractPolicySources: append([]string(nil), opts.ContractPolicySources...),
		ContractRuleID:        opts.ContractRuleID,
		ActiveManifestHash:    opts.ActiveManifestHash,
		ContractHash:          opts.ContractHash,
		ContractSelectorID:    opts.ContractSelectorID,
		ContractGeneration:    opts.ContractGeneration,
		Transport:             opts.Transport,
		Method:                opts.Method,
		Layer:                 opts.Layer,
		Pattern:               opts.Pattern,
		Severity:              opts.Severity,
		Redaction:             redactionSummaryFromReport(opts.RedactionProfile, opts.RedactionReport),
		Shield:                cloneShieldSummary(opts.Shield),
		RequestID:             opts.RequestID,
	}
}

// scanActionContent scans the unsigned template with the recorder's receipt
// detector. Redactable content values (never identities or member names) are
// sanitized before signing and the template is scanned again; anything still
// flagged is a typed content rejection that leaves the chain untouched.
func (e *Emitter) scanActionContent(tmpl Receipt) (Receipt, *recorder.ContentScan, error) {
	ctx := context.Background()
	for attempt := 0; ; attempt++ {
		raw, err := json.Marshal(tmpl)
		if err != nil {
			return tmpl, nil, fmt.Errorf("marshal receipt content template: %w", err)
		}
		rep, cs, err := e.recorder.ScanReceiptContent(ctx, actionReceiptProducer, raw)
		if err != nil || cs != nil {
			return tmpl, cs, err
		}
		if attempt > 0 || !rep.Redactable() {
			return tmpl, nil, rep.Err()
		}
		det := e.recorder.ReceiptDetector()
		clean := func(text string) bool { return det(ctx, text).Clean }
		paths := make([]string, 0, len(rep.Findings))
		for _, f := range rep.Findings {
			paths = append(paths, f.Paths...)
		}
		redacted, err := actionReceiptProducer.RedactValues(raw, paths, func(path, value string) string {
			if path == "action_record.target" {
				return sanitizeTarget(value, clean)
			}
			return redactedTarget
		})
		if err != nil {
			return tmpl, nil, err
		}
		var next Receipt
		if err := json.Unmarshal(redacted, &next); err != nil {
			return tmpl, nil, fmt.Errorf("decode redacted receipt content template: %w", err)
		}
		tmpl = next
	}
}
