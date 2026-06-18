// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

// fullyPopulatedActionRecordV1 sets every signed field, including the nested
// summaries, so the golden below exercises the entire v1 canonical surface.
func fullyPopulatedActionRecordV1() ActionRecord {
	return ActionRecord{
		Version:               ReceiptVersion,
		ActionID:              "act-1",
		ParentActionID:        "parent-1",
		ActionType:            ActionWrite,
		Timestamp:             time.Date(2026, 4, 4, 12, 0, 0, 123456789, time.UTC),
		Principal:             "user",
		Actor:                 "agent",
		DelegationChain:       []string{"user", "agent"},
		Target:                "https://example.com/api",
		Intent:                "exfil-test",
		DataClassesIn:         []string{"pii", "secret"},
		DataClassesOut:        []string{"public"},
		SideEffectClass:       SideEffectExternalWrite,
		Reversibility:         ReversibilityCompensatable,
		PolicyHash:            "policy-sha256",
		Verdict:               "block",
		DecisionPhase:         "phase",
		DeferID:               "defer-1",
		ResolutionPolicy:      "rp",
		ResolutionSource:      "rs",
		SessionID:             "sess",
		SessionIDOriginal:     "sess-orig",
		SessionTaintLevel:     "high",
		SessionContaminated:   true,
		RecentTaintSources:    []session.TaintSourceRef{{URL: "https://t", Kind: "k", Level: session.TaintExternalHostile, Timestamp: time.Date(2026, 4, 4, 11, 0, 0, 0, time.UTC), ReceiptID: "rid", MatchReason: "mr"}},
		SessionTaskID:         "task",
		SessionTaskLabel:      "label",
		AuthorityKind:         "ak",
		TaintDecision:         "td",
		TaintDecisionReason:   "tdr",
		TaskOverrideApplied:   true,
		ContractWinningSource: "cws",
		ContractLiveVerdict:   "clv",
		ContractPolicySources: []string{"cps1", "cps2"},
		ContractRuleID:        "crid",
		ActiveManifestHash:    "amh",
		ContractHash:          "ch",
		ContractSelectorID:    "csid",
		ContractGeneration:    9,
		Transport:             "mcp",
		Method:                "POST",
		Layer:                 "dlp",
		Pattern:               "pat",
		Severity:              "critical",
		Redaction:             &RedactionSummary{Profile: "p", Provider: "pr", Parser: "json", TotalRedactions: 3, ByClass: map[string]int{"secret": 3}, CacheBoundaryKept: true},
		Shield:                &ShieldSummary{Pipeline: "pl", TotalRewrites: 1, ExtensionProbes: 2, TrackingBeacons: 3, AgentTraps: 4, FingerprintShimInjected: true, SVGForeignObjects: 5, SVGEventHandlers: 6, SVGExternalReferences: 7, SVGHiddenText: 8, SVGAnimationInjections: 9, BodyBytes: 10, ScannedBytes: 11, Partial: true, AdaptiveSignalsRecorded: 12, AdaptiveSignalMaxPerBody: 13},
		RequestID:             "req-1",
		ChainPrevHash:         "genesis",
		ChainSeq:              7,
		RunNonce:              "nonce-abc",
		KeyTransition:         &KeyTransition{PriorSignerKey: "psk", PriorChainSeq: 6, PriorChainHash: "pch"},
		Venue:                 "venue",
		Jurisdiction:          "jur",
		RulebookID:            "rb",
		RemedyClass:           "rc",
		ContestationWindow:    "cw",
		PrecedentRefs:         []string{"pr1", "pr2"},
	}
}

// TestActionRecord_CanonicalV1GoldenBytes_FullSurface pins the frozen v1 signing
// projection for a fully-populated record, covering every field AND every nested
// summary mirror (redaction, shield, taint sources, key transition). These bytes
// are the signing preimage for receipt version 1 and MUST NOT change: any drift
// silently invalidates every already-emitted v1 receipt. If the signed surface
// must change, bump ReceiptVersion and add canonicalActionRecordV2 — do not edit
// canonicalActionRecordV1 or this golden.
func TestActionRecord_CanonicalV1GoldenBytes_FullSurface(t *testing.T) {
	t.Parallel()

	const want = `{"version":1,"action_id":"act-1","parent_action_id":"parent-1","action_type":"write","timestamp":"2026-04-04T12:00:00.123456789Z","principal":"user","actor":"agent","delegation_chain":["user","agent"],"target":"https://example.com/api","intent":"exfil-test","data_classes_in":["pii","secret"],"data_classes_out":["public"],"side_effect_class":"external_write","reversibility":"compensatable","policy_hash":"policy-sha256","verdict":"block","decision_phase":"phase","defer_id":"defer-1","resolution_policy":"rp","resolution_source":"rs","session_id":"sess","session_id_original":"sess-orig","session_taint_level":"high","session_contaminated":true,"recent_taint_sources":[{"url":"https://t","kind":"k","level":5,"timestamp":"2026-04-04T11:00:00Z","receipt_id":"rid","match_reason":"mr"}],"session_task_id":"task","session_task_label":"label","authority_kind":"ak","taint_decision":"td","taint_decision_reason":"tdr","task_override_applied":true,"contract_winning_source":"cws","contract_live_verdict":"clv","contract_policy_sources":["cps1","cps2"],"contract_rule_id":"crid","active_manifest_hash":"amh","contract_hash":"ch","contract_selector_id":"csid","contract_generation":9,"transport":"mcp","method":"POST","layer":"dlp","pattern":"pat","severity":"critical","redaction":{"profile":"p","provider":"pr","parser":"json","total_redactions":3,"by_class":{"secret":3},"cache_boundary_kept":true},"shield":{"pipeline":"pl","total_rewrites":1,"extension_probes":2,"tracking_beacons":3,"agent_traps":4,"fingerprint_shim_injected":true,"svg_foreign_objects":5,"svg_event_handlers":6,"svg_external_references":7,"svg_hidden_text":8,"svg_animation_injections":9,"body_bytes":10,"scanned_bytes":11,"partial":true,"adaptive_signals_recorded":12,"adaptive_signal_max_per_body":13},"request_id":"req-1","chain_prev_hash":"genesis","chain_seq":7,"run_nonce":"nonce-abc","key_transition":{"prior_signer_key":"psk","prior_chain_seq":6,"prior_chain_hash":"pch"},"venue":"venue","jurisdiction":"jur","rulebook_id":"rb","remedy_class":"rc","contestation_window":"cw","precedent_refs":["pr1","pr2"]}`

	got, err := canonicalActionRecordV1(fullyPopulatedActionRecordV1())
	if err != nil {
		t.Fatalf("canonicalActionRecordV1: %v", err)
	}
	if string(got) != want {
		t.Fatalf("v1 canonical bytes drifted (this invalidates existing receipts):\n got: %s\nwant: %s", got, want)
	}
}
