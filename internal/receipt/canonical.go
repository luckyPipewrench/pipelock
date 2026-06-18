// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

func canonicalActionRecord(version int, ar ActionRecord) ([]byte, error) {
	switch version {
	case ReceiptVersion:
		return canonicalActionRecordV1(ar)
	default:
		return nil, fmt.Errorf("unsupported receipt canonical version %d", version)
	}
}

// canonicalActionRecordV1 is the frozen signing projection for receipt version
// 1. Do not add future ActionRecord fields here. If the signed surface changes,
// create a new projection and select it from canonicalActionRecord.
func canonicalActionRecordV1(ar ActionRecord) ([]byte, error) {
	return json.Marshal(actionRecordCanonicalV1{
		Version:               ar.Version,
		ActionID:              ar.ActionID,
		ParentActionID:        ar.ParentActionID,
		ActionType:            ar.ActionType,
		Timestamp:             ar.Timestamp,
		Principal:             ar.Principal,
		Actor:                 ar.Actor,
		DelegationChain:       ar.DelegationChain,
		Target:                ar.Target,
		Intent:                ar.Intent,
		DataClassesIn:         ar.DataClassesIn,
		DataClassesOut:        ar.DataClassesOut,
		SideEffectClass:       ar.SideEffectClass,
		Reversibility:         ar.Reversibility,
		PolicyHash:            ar.PolicyHash,
		Verdict:               ar.Verdict,
		DecisionPhase:         ar.DecisionPhase,
		DeferID:               ar.DeferID,
		ResolutionPolicy:      ar.ResolutionPolicy,
		ResolutionSource:      ar.ResolutionSource,
		SessionID:             ar.SessionID,
		SessionIDOriginal:     ar.SessionIDOriginal,
		SessionTaintLevel:     ar.SessionTaintLevel,
		SessionContaminated:   ar.SessionContaminated,
		RecentTaintSources:    canonicalTaintSourceRefsV1(ar.RecentTaintSources),
		SessionTaskID:         ar.SessionTaskID,
		SessionTaskLabel:      ar.SessionTaskLabel,
		AuthorityKind:         ar.AuthorityKind,
		TaintDecision:         ar.TaintDecision,
		TaintDecisionReason:   ar.TaintDecisionReason,
		TaskOverrideApplied:   ar.TaskOverrideApplied,
		ContractWinningSource: ar.ContractWinningSource,
		ContractLiveVerdict:   ar.ContractLiveVerdict,
		ContractPolicySources: ar.ContractPolicySources,
		ContractRuleID:        ar.ContractRuleID,
		ActiveManifestHash:    ar.ActiveManifestHash,
		ContractHash:          ar.ContractHash,
		ContractSelectorID:    ar.ContractSelectorID,
		ContractGeneration:    ar.ContractGeneration,
		Transport:             ar.Transport,
		Method:                ar.Method,
		Layer:                 ar.Layer,
		Pattern:               ar.Pattern,
		Severity:              ar.Severity,
		Redaction:             canonicalRedactionSummaryV1(ar.Redaction),
		Shield:                canonicalShieldSummaryV1(ar.Shield),
		RequestID:             ar.RequestID,
		ChainPrevHash:         ar.ChainPrevHash,
		ChainSeq:              ar.ChainSeq,
		RunNonce:              ar.RunNonce,
		KeyTransition:         canonicalKeyTransitionV1(ar.KeyTransition),
		Venue:                 ar.Venue,
		Jurisdiction:          ar.Jurisdiction,
		RulebookID:            ar.RulebookID,
		RemedyClass:           ar.RemedyClass,
		ContestationWindow:    ar.ContestationWindow,
		PrecedentRefs:         ar.PrecedentRefs,
	})
}

type actionRecordCanonicalV1 struct {
	Version int `json:"version"`

	ActionID       string     `json:"action_id"`
	ParentActionID string     `json:"parent_action_id,omitempty"`
	ActionType     ActionType `json:"action_type"`
	Timestamp      time.Time  `json:"timestamp"`

	Principal       string   `json:"principal"`
	Actor           string   `json:"actor"`
	DelegationChain []string `json:"delegation_chain"`

	Target string `json:"target"`

	Intent         string   `json:"intent,omitempty"`
	DataClassesIn  []string `json:"data_classes_in,omitempty"`
	DataClassesOut []string `json:"data_classes_out,omitempty"`

	SideEffectClass SideEffectClass `json:"side_effect_class"`
	Reversibility   Reversibility   `json:"reversibility"`

	PolicyHash string `json:"policy_hash"`
	Verdict    string `json:"verdict"`

	DecisionPhase       string                      `json:"decision_phase,omitempty"`
	DeferID             string                      `json:"defer_id,omitempty"`
	ResolutionPolicy    string                      `json:"resolution_policy,omitempty"`
	ResolutionSource    string                      `json:"resolution_source,omitempty"`
	SessionID           string                      `json:"session_id,omitempty"`
	SessionIDOriginal   string                      `json:"session_id_original,omitempty"`
	SessionTaintLevel   string                      `json:"session_taint_level,omitempty"`
	SessionContaminated bool                        `json:"session_contaminated,omitempty"`
	RecentTaintSources  []taintSourceRefCanonicalV1 `json:"recent_taint_sources,omitempty"`
	SessionTaskID       string                      `json:"session_task_id,omitempty"`
	SessionTaskLabel    string                      `json:"session_task_label,omitempty"`
	AuthorityKind       string                      `json:"authority_kind,omitempty"`
	TaintDecision       string                      `json:"taint_decision,omitempty"`
	TaintDecisionReason string                      `json:"taint_decision_reason,omitempty"`
	TaskOverrideApplied bool                        `json:"task_override_applied,omitempty"`

	ContractWinningSource string   `json:"contract_winning_source,omitempty"`
	ContractLiveVerdict   string   `json:"contract_live_verdict,omitempty"`
	ContractPolicySources []string `json:"contract_policy_sources,omitempty"`
	ContractRuleID        string   `json:"contract_rule_id,omitempty"`
	ActiveManifestHash    string   `json:"active_manifest_hash,omitempty"`
	ContractHash          string   `json:"contract_hash,omitempty"`
	ContractSelectorID    string   `json:"contract_selector_id,omitempty"`
	ContractGeneration    uint64   `json:"contract_generation,omitempty"`

	Transport string                       `json:"transport"`
	Method    string                       `json:"method,omitempty"`
	Layer     string                       `json:"layer,omitempty"`
	Pattern   string                       `json:"pattern,omitempty"`
	Severity  string                       `json:"severity,omitempty"`
	Redaction *redactionSummaryCanonicalV1 `json:"redaction,omitempty"`
	Shield    *shieldSummaryCanonicalV1    `json:"shield,omitempty"`
	RequestID string                       `json:"request_id,omitempty"`

	ChainPrevHash string `json:"chain_prev_hash"`
	ChainSeq      uint64 `json:"chain_seq"`

	RunNonce      string                    `json:"run_nonce,omitempty"`
	KeyTransition *keyTransitionCanonicalV1 `json:"key_transition,omitempty"`

	Venue              string   `json:"venue,omitempty"`
	Jurisdiction       string   `json:"jurisdiction,omitempty"`
	RulebookID         string   `json:"rulebook_id,omitempty"`
	RemedyClass        string   `json:"remedy_class,omitempty"`
	ContestationWindow string   `json:"contestation_window,omitempty"`
	PrecedentRefs      []string `json:"precedent_refs,omitempty"`
}

type taintSourceRefCanonicalV1 struct {
	URL         string             `json:"url"`
	Kind        string             `json:"kind"`
	Level       session.TaintLevel `json:"level"`
	Timestamp   time.Time          `json:"timestamp"`
	ReceiptID   string             `json:"receipt_id,omitempty"`
	MatchReason string             `json:"match_reason,omitempty"`
}

func canonicalTaintSourceRefsV1(in []session.TaintSourceRef) []taintSourceRefCanonicalV1 {
	if len(in) == 0 {
		return nil
	}
	out := make([]taintSourceRefCanonicalV1, 0, len(in))
	for _, source := range in {
		out = append(out, taintSourceRefCanonicalV1{
			URL:         source.URL,
			Kind:        source.Kind,
			Level:       source.Level,
			Timestamp:   source.Timestamp,
			ReceiptID:   source.ReceiptID,
			MatchReason: source.MatchReason,
		})
	}
	return out
}

type keyTransitionCanonicalV1 struct {
	PriorSignerKey string `json:"prior_signer_key"`
	PriorChainSeq  uint64 `json:"prior_chain_seq"`
	PriorChainHash string `json:"prior_chain_hash"`
}

func canonicalKeyTransitionV1(in *KeyTransition) *keyTransitionCanonicalV1 {
	if in == nil {
		return nil
	}
	return &keyTransitionCanonicalV1{
		PriorSignerKey: in.PriorSignerKey,
		PriorChainSeq:  in.PriorChainSeq,
		PriorChainHash: in.PriorChainHash,
	}
}

type redactionSummaryCanonicalV1 struct {
	Profile           string         `json:"profile,omitempty"`
	Provider          string         `json:"provider,omitempty"`
	Parser            string         `json:"parser,omitempty"`
	TotalRedactions   int            `json:"total_redactions,omitempty"`
	ByClass           map[string]int `json:"by_class,omitempty"`
	CacheBoundaryKept bool           `json:"cache_boundary_kept,omitempty"`
}

func canonicalRedactionSummaryV1(in *RedactionSummary) *redactionSummaryCanonicalV1 {
	if in == nil {
		return nil
	}
	return &redactionSummaryCanonicalV1{
		Profile:           in.Profile,
		Provider:          in.Provider,
		Parser:            in.Parser,
		TotalRedactions:   in.TotalRedactions,
		ByClass:           in.ByClass,
		CacheBoundaryKept: in.CacheBoundaryKept,
	}
}

type shieldSummaryCanonicalV1 struct {
	Pipeline                 string `json:"pipeline,omitempty"`
	TotalRewrites            int    `json:"total_rewrites,omitempty"`
	ExtensionProbes          int    `json:"extension_probes,omitempty"`
	TrackingBeacons          int    `json:"tracking_beacons,omitempty"`
	AgentTraps               int    `json:"agent_traps,omitempty"`
	FingerprintShimInjected  bool   `json:"fingerprint_shim_injected,omitempty"`
	SVGForeignObjects        int    `json:"svg_foreign_objects,omitempty"`
	SVGEventHandlers         int    `json:"svg_event_handlers,omitempty"`
	SVGExternalReferences    int    `json:"svg_external_references,omitempty"`
	SVGHiddenText            int    `json:"svg_hidden_text,omitempty"`
	SVGAnimationInjections   int    `json:"svg_animation_injections,omitempty"`
	BodyBytes                int    `json:"body_bytes,omitempty"`
	ScannedBytes             int    `json:"scanned_bytes,omitempty"`
	Partial                  bool   `json:"partial,omitempty"`
	AdaptiveSignalsRecorded  int    `json:"adaptive_signals_recorded,omitempty"`
	AdaptiveSignalMaxPerBody int    `json:"adaptive_signal_max_per_body,omitempty"`
}

func canonicalShieldSummaryV1(in *ShieldSummary) *shieldSummaryCanonicalV1 {
	if in == nil {
		return nil
	}
	return &shieldSummaryCanonicalV1{
		Pipeline:                 in.Pipeline,
		TotalRewrites:            in.TotalRewrites,
		ExtensionProbes:          in.ExtensionProbes,
		TrackingBeacons:          in.TrackingBeacons,
		AgentTraps:               in.AgentTraps,
		FingerprintShimInjected:  in.FingerprintShimInjected,
		SVGForeignObjects:        in.SVGForeignObjects,
		SVGEventHandlers:         in.SVGEventHandlers,
		SVGExternalReferences:    in.SVGExternalReferences,
		SVGHiddenText:            in.SVGHiddenText,
		SVGAnimationInjections:   in.SVGAnimationInjections,
		BodyBytes:                in.BodyBytes,
		ScannedBytes:             in.ScannedBytes,
		Partial:                  in.Partial,
		AdaptiveSignalsRecorded:  in.AdaptiveSignalsRecorded,
		AdaptiveSignalMaxPerBody: in.AdaptiveSignalMaxPerBody,
	}
}
