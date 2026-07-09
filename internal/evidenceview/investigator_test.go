// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidenceview

import (
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestExplainReceipt(t *testing.T) {
	tests := []struct {
		name        string
		ar          receipt.ActionRecord
		wantVerdict string
		wantPresent map[string]bool // field label -> expected Present value
	}{
		{
			name: "block with scanner detail",
			ar: receipt.ActionRecord{
				Version:         1,
				ActionID:        "act-block",
				ActionType:      receipt.ActionRead,
				Timestamp:       time.Now(),
				Target:          "https://api.vendor.example/exfil",
				Verdict:         "block",
				Transport:       "forward",
				Method:          "CONNECT",
				Layer:           "dlp",
				Pattern:         "provider-token",
				Severity:        "high",
				PolicyHash:      "abcdef1234567890abcdef1234567890",
				SideEffectClass: receipt.SideEffectNone,
				Reversibility:   receipt.ReversibilityFull,
				ChainSeq:        5,
				ChainPrevHash:   "prev",
			},
			wantVerdict: "block",
			wantPresent: map[string]bool{
				"Verdict":          true,
				"Transport":        true,
				"Method":           true,
				"Layer":            true,
				"Pattern":          true,
				"Severity":         true,
				"Policy Hash":      true,
				"Intent":           false,
				"Taint Decision":   false,
				"Defer ID":         false,
				"Redaction":        false,
				"Shield":           false,
				"Data Classes In":  false,
				"Data Classes Out": false,
			},
		},
		{
			name: "allow with minimal fields",
			ar: receipt.ActionRecord{
				Version:       1,
				ActionID:      "act-allow",
				ActionType:    receipt.ActionRead,
				Timestamp:     time.Now(),
				Target:        "https://api.vendor.example/safe",
				Verdict:       "allow",
				Transport:     "fetch",
				ChainSeq:      0,
				ChainPrevHash: "genesis",
			},
			wantVerdict: "allow",
			wantPresent: map[string]bool{
				"Verdict":             true,
				"Transport":           true,
				"Layer":               false,
				"Pattern":             false,
				"Severity":            false,
				"Policy Hash":         false,
				"Session Taint Level": false,
			},
		},
		{
			name: "defer with resolution",
			ar: receipt.ActionRecord{
				Version:          1,
				ActionID:         "act-defer",
				ActionType:       receipt.ActionRead,
				Timestamp:        time.Now(),
				Target:           "https://api.vendor.example/risky",
				Verdict:          "defer",
				Transport:        "mcp-stdio",
				DecisionPhase:    "deferred",
				DeferID:          "defer-123",
				ResolutionPolicy: "operator-approve",
				ResolutionSource: "hitl",
				ChainSeq:         3,
				ChainPrevHash:    "prev",
			},
			wantVerdict: "defer",
			wantPresent: map[string]bool{
				"Verdict":           true,
				"Decision Phase":    true,
				"Defer ID":          true,
				"Resolution Policy": true,
				"Resolution Source": true,
			},
		},
		{
			name: "taint escalation",
			ar: receipt.ActionRecord{
				Version:             1,
				ActionID:            "act-taint",
				ActionType:          receipt.ActionRead,
				Timestamp:           time.Now(),
				Target:              "https://api.vendor.example/post",
				Verdict:             "block",
				Transport:           "forward",
				SessionTaintLevel:   "elevated",
				SessionContaminated: true,
				TaintDecision:       "escalate",
				TaintDecisionReason: "external exposure followed by write",
				ChainSeq:            7,
				ChainPrevHash:       "prev",
			},
			wantVerdict: "block",
			wantPresent: map[string]bool{
				"Session Taint Level":   true,
				"Session Contaminated":  true,
				"Taint Decision":        true,
				"Taint Decision Reason": true,
			},
		},
		{
			name: "redaction present",
			ar: receipt.ActionRecord{
				Version:       1,
				ActionID:      "act-redact",
				ActionType:    receipt.ActionRead,
				Timestamp:     time.Now(),
				Target:        "https://api.vendor.example/model",
				Verdict:       "allow",
				Transport:     "forward",
				ChainSeq:      2,
				ChainPrevHash: "prev",
				Redaction: &receipt.RedactionSummary{
					TotalRedactions: 3,
					ByClass:         map[string]int{"provider-token": 2, "email": 1},
				},
			},
			wantVerdict: "allow",
			wantPresent: map[string]bool{
				"Redaction": true,
			},
		},
		{
			name: "shield present",
			ar: receipt.ActionRecord{
				Version:       1,
				ActionID:      "act-shield",
				ActionType:    receipt.ActionRead,
				Timestamp:     time.Now(),
				Target:        "https://api.vendor.example/page",
				Verdict:       "allow",
				Transport:     "fetch",
				ChainSeq:      1,
				ChainPrevHash: "prev",
				Shield: &receipt.ShieldSummary{
					Pipeline:      "browser-shield",
					TotalRewrites: 5,
				},
			},
			wantVerdict: "allow",
			wantPresent: map[string]bool{
				"Shield": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := receipt.Receipt{
				Version:      1,
				ActionRecord: tt.ar,
				SignerKey:    "testkey",
			}
			exp := ExplainReceipt(r)
			if exp.Verdict.Detail != tt.wantVerdict {
				t.Errorf("Verdict.Detail = %q, want %q", exp.Verdict.Detail, tt.wantVerdict)
			}

			fieldMap := make(map[string]ExplanationField)
			for _, f := range exp.Fields() {
				fieldMap[f.Label] = f
			}
			// Also add the heading fields.
			fieldMap[exp.Verdict.Label] = exp.Verdict
			fieldMap[exp.DecisionPhase.Label] = exp.DecisionPhase
			fieldMap[exp.ChainSeq.Label] = exp.ChainSeq

			for label, wantPresent := range tt.wantPresent {
				f, ok := fieldMap[label]
				if !ok {
					t.Errorf("field %q not found in explanation", label)
					continue
				}
				if f.Present != wantPresent {
					t.Errorf("field %q.Present = %v, want %v (Detail=%q)", label, f.Present, wantPresent, f.Detail)
				}
				// Absent fields must show "not reported", never an empty string.
				if !f.Present && f.Detail != notReported {
					t.Errorf("absent field %q.Detail = %q, want %q", label, f.Detail, notReported)
				}
			}
		})
	}
}

func TestRedactExplanation(t *testing.T) {
	r := receipt.Receipt{
		Version: 1,
		ActionRecord: receipt.ActionRecord{
			Version:       1,
			ActionID:      "act-1",
			ActionType:    receipt.ActionRead,
			Timestamp:     time.Now(),
			Target:        "https://api.vendor.example/with-capability-tok",
			Verdict:       "allow",
			Transport:     "fetch",
			ChainSeq:      0,
			ChainPrevHash: "genesis",
		},
		SignerKey: "testkey",
	}
	exp := ExplainReceipt(r)

	// Before redaction, Target should show the real URL.
	if exp.Target.Detail == RedactedDestination {
		t.Error("Target should not be redacted before RedactExplanation")
	}

	redacted := RedactExplanation(exp)
	if redacted.Target.Detail != RedactedDestination {
		t.Errorf("redacted Target.Detail = %q, want %q", redacted.Target.Detail, RedactedDestination)
	}
	if redacted.TaintSourcesRawLen != 0 {
		t.Errorf("redacted TaintSourcesRawLen = %d, want 0", redacted.TaintSourcesRawLen)
	}
}

func TestRedactExplanation_StripsRawMetadataFields(t *testing.T) {
	// Threat model: the metadata view must not leak fields an ATTACKER/agent can
	// influence (the destination, the agent's declared intent, the taint reason,
	// the pattern reason) — the secret is placed ONLY in those fields plus the
	// raw taint source. The scanner/config fields (Layer, Severity, data-class
	// labels, redaction/shield counts) carry benign, non-attacker values and MUST
	// stay visible so the metadata investigator remains useful.
	secret := "capability-token-secret"
	r := receipt.Receipt{
		Version: 1,
		ActionRecord: receipt.ActionRecord{
			Version:             1,
			ActionID:            "act-secret",
			ActionType:          receipt.ActionRead,
			Timestamp:           time.Now(),
			Target:              "https://api.vendor.example/" + secret,
			Verdict:             "block",
			Transport:           "fetch",
			Method:              "GET",
			Layer:               "dlp",
			Pattern:             "pattern-" + secret,
			Severity:            "high",
			SessionTaintLevel:   "elevated",
			SessionContaminated: true,
			TaintDecision:       "block",
			TaintDecisionReason: "taint-source-" + secret,
			RecentTaintSources: []session.TaintSourceRef{{
				URL:  "https://source.vendor.example/" + secret,
				Kind: "url",
			}},
			Intent:         "intent-" + secret,
			DataClassesIn:  []string{"pii"},
			DataClassesOut: []string{"credential"},
			Redaction: &receipt.RedactionSummary{
				TotalRedactions: 2,
				ByClass:         map[string]int{"aws": 2},
			},
			Shield: &receipt.ShieldSummary{
				Pipeline:      "html",
				TotalRewrites: 1,
			},
			ChainSeq:      0,
			ChainPrevHash: receipt.GenesisHash,
		},
		SignerKey: "testkey",
	}

	exp := ExplainReceipt(r)
	redacted := RedactExplanation(exp)

	// No field may leak the secret.
	for _, f := range redacted.Fields() {
		if strings.Contains(f.Detail, secret) {
			t.Fatalf("redacted field %q leaked secret in detail %q", f.Label, f.Detail)
		}
	}
	// The attacker/agent-controlled fields are redacted to the placeholder.
	for _, f := range []ExplanationField{
		redacted.Target,
		redacted.Intent,
		redacted.TaintReason,
		redacted.Pattern,
	} {
		if f.Detail != RedactedDestination {
			t.Fatalf("%s.Detail = %q, want redacted placeholder", f.Label, f.Detail)
		}
	}
	// The scanner/config semantic fields stay VISIBLE (never over-redacted), so
	// the metadata investigator still explains WHY the decision happened.
	kept := map[string]string{
		"Layer":            redacted.Layer.Detail,
		"Severity":         redacted.Severity.Detail,
		"Data Classes In":  redacted.DataClassesIn.Detail,
		"Data Classes Out": redacted.DataClassesOut.Detail,
		"Redaction":        redacted.Redaction.Detail,
		"Shield":           redacted.Shield.Detail,
	}
	wantKept := map[string]string{
		"Layer":            "dlp",
		"Severity":         "high",
		"Data Classes In":  "pii",
		"Data Classes Out": "credential",
		"Redaction":        "2 redactions across 1 classes",
		"Shield":           "1 rewrites via html",
	}
	for label, got := range kept {
		if got == RedactedDestination {
			t.Fatalf("%s was over-redacted; metadata view must keep decision semantics", label)
		}
		if got != wantKept[label] {
			t.Fatalf("%s.Detail = %q, want %q", label, got, wantKept[label])
		}
	}
	if redacted.TaintSourcesRawLen != 0 {
		t.Fatalf("TaintSourcesRawLen = %d, want 0", redacted.TaintSourcesRawLen)
	}
}

func TestExplainReceipt_AbsenceRendersNotReported(t *testing.T) {
	// A receipt with only the minimum fields should render every optional field
	// as "not reported", never as an empty string or a fabricated value.
	r := receipt.Receipt{
		Version: 1,
		ActionRecord: receipt.ActionRecord{
			Version:       1,
			ActionID:      "act-minimal",
			ActionType:    receipt.ActionRead,
			Timestamp:     time.Now(),
			Verdict:       "allow",
			Transport:     "fetch",
			ChainSeq:      0,
			ChainPrevHash: "genesis",
		},
		SignerKey: "testkey",
	}
	exp := ExplainReceipt(r)

	// Check all fields that should be absent.
	absentFields := []ExplanationField{
		exp.Layer, exp.Pattern, exp.Severity,
		exp.PolicyHash, exp.TaintLevel, exp.TaintDecision,
		exp.TaintReason, exp.TaintSourceCount,
		exp.DeferID, exp.ResolutionPolicy, exp.ResolutionSource,
		exp.Redaction, exp.Shield, exp.Intent,
		exp.DataClassesIn, exp.DataClassesOut,
		exp.Target, exp.Actor, exp.Principal,
		exp.DecisionPhase, exp.Method,
	}
	for _, f := range absentFields {
		if f.Present {
			t.Errorf("field %q should be absent for minimal receipt, got Present=true", f.Label)
		}
		if f.Detail != notReported {
			t.Errorf("absent field %q.Detail = %q, want %q", f.Label, f.Detail, notReported)
		}
	}
}
