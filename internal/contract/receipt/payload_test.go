// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

const testReceiptSignature = "ed25519:" + "" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000"

const testSHA256Digest = "sha256:" +
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const (
	testRedactedValue    = "[redacted-value]"
	testSpanMACKey       = "span-mac-key"
	testSpanEventID      = "01900000-0000-7000-8000-000000000001"
	testHMACSHA256       = "hmac-sha256"
	testAWSAccessKeyRule = "aws_access_key"
)

// marshalPayload marshals v to json.RawMessage for test use.
func marshalPayload(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return json.RawMessage(b)
}

// --- proxy_decision ---

func TestValidateProxyDecision_AcceptsValid(t *testing.T) {
	p := receipt.PayloadProxyDecisionStruct{
		ActionType:    "block",
		Target:        "https://example.com/",
		Verdict:       "blocked",
		Transport:     "forward",
		PolicySources: []string{"dlp"},
		WinningSource: "dlp",
	}
	if err := callValidator(t, receipt.PayloadProxyDecision, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateProxyDecision_RejectsMissingTarget(t *testing.T) {
	p := receipt.PayloadProxyDecisionStruct{
		ActionType:    "block",
		Target:        "",
		Verdict:       "blocked",
		Transport:     "forward",
		PolicySources: []string{"dlp"},
		WinningSource: "dlp",
	}
	err := callValidator(t, receipt.PayloadProxyDecision, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateProxyDecision_RejectsMissingPolicySources(t *testing.T) {
	p := receipt.PayloadProxyDecisionStruct{
		ActionType:    "block",
		Target:        "https://example.com/",
		Verdict:       "blocked",
		Transport:     "forward",
		PolicySources: nil,
		WinningSource: "dlp",
	}
	err := callValidator(t, receipt.PayloadProxyDecision, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- proxy_decision_with_spans ---

func TestValidateProxyDecisionWithSpans_AcceptsValid(t *testing.T) {
	t.Parallel()
	p := validProxyDecisionWithSpansPayload(t)
	if err := callValidator(t, receipt.PayloadProxyDecisionWithSpans, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateProxyDecisionWithSpans_RejectsMissingSpans(t *testing.T) {
	t.Parallel()
	p := validProxyDecisionWithSpansPayload(t)
	p.SourceSpans = nil
	err := callValidator(t, receipt.PayloadProxyDecisionWithSpans, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateProxyDecisionWithSpans_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{
		"action_type":"block",
		"target":"https://example.com/[redacted-value]",
		"verdict":"block",
		"transport":"forward",
		"policy_sources":["dlp"],
		"winning_source":"scanner",
		"source_spans":[{
			"source_id":"request-url",
			"source_kind":"http_request_url",
			"normalized_view":"sanitized_target",
			"pipelock_binary_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"rules_bundle_digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"transform_profile":"pipelock-transform-v1",
			"policy_hash":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"rule_id":"aws_access_key",
			"char_offset":20,
			"char_length":16,
			"match_hash":"hmac-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"match_hash_alg":"hmac-sha256",
			"match_class":"secret:aws_access_key",
			"raw_secret":"hidden"
		}]
	}`)
	err := callValidator(t, receipt.PayloadProxyDecisionWithSpans, raw)
	if err == nil {
		t.Fatal("unknown SourceSpan field accepted")
	}
}

func TestValidateProxyDecisionWithSpans_StrictDecodePreservesError(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{
		"action_type":"block",
		"target":"https://example.com/[redacted-value]",
		"verdict":"block",
		"transport":"forward",
		"policy_sources":["dlp"],
		"winning_source":"scanner",
		"source_spans":[],
		"unexpected":"field"
	}`)
	err := callValidator(t, receipt.PayloadProxyDecisionWithSpans, raw)
	if err == nil {
		t.Fatal("unknown top-level field accepted")
	}
	if errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("strict decode error was mislabeled as missing field: %v", err)
	}
	if !strings.Contains(err.Error(), `json: unknown field "unexpected"`) {
		t.Fatalf("strict decode detail not preserved: %v", err)
	}
}

// Structural validation can only reject a wrong algorithm label. Proving that
// a hmac-sha256:<hex> value was actually keyed belongs in the recheck path,
// where the verifier has the HMAC key and the signed event_id.
func TestValidateProxyDecisionWithSpans_RejectsWrongMatchHashAlgPrefix(t *testing.T) {
	t.Parallel()
	p := validProxyDecisionWithSpansPayload(t)
	p.SourceSpans[0].MatchHash = "sha256:" + strings.TrimPrefix(testSHA256Digest, "sha256:")
	err := callValidator(t, receipt.PayloadProxyDecisionWithSpans, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
	}
}

func TestValidateProxyDecisionWithSpans_RejectsOffsetsOnTransformedResponseView(t *testing.T) {
	t.Parallel()
	p := validProxyDecisionWithSpansPayload(t)
	p.SourceSpans[0].SourceKind = receipt.SourceKindHTTPResponse
	p.SourceSpans[0].NormalizedView = receipt.NormalizedViewBase64Decoded
	err := callValidator(t, receipt.PayloadProxyDecisionWithSpans, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
	}
}

func TestSourceSpanMatchHash_IsContextBoundAndKeyed(t *testing.T) {
	t.Parallel()
	span := validSourceSpan(t)
	first, err := receipt.SourceSpanMatchHash([]byte(testSpanMACKey+"-1"), testSpanEventID, 0, span, testRedactedValue)
	if err != nil {
		t.Fatalf("SourceSpanMatchHash first: %v", err)
	}
	second, err := receipt.SourceSpanMatchHash([]byte(testSpanMACKey+"-2"), testSpanEventID, 0, span, testRedactedValue)
	if err != nil {
		t.Fatalf("SourceSpanMatchHash second: %v", err)
	}
	if first == second {
		t.Fatal("match_hash did not change across HMAC keys")
	}
	span.RuleID = "other-rule"
	third, err := receipt.SourceSpanMatchHash([]byte(testSpanMACKey+"-1"), testSpanEventID, 0, span, testRedactedValue)
	if err != nil {
		t.Fatalf("SourceSpanMatchHash third: %v", err)
	}
	if first == third {
		t.Fatal("match_hash did not bind rule_id")
	}
	span = validSourceSpan(t)
	fourth, err := receipt.SourceSpanMatchHash([]byte(testSpanMACKey+"-1"), testSpanEventID+"-other", 0, span, testRedactedValue)
	if err != nil {
		t.Fatalf("SourceSpanMatchHash fourth: %v", err)
	}
	if first == fourth {
		t.Fatal("match_hash did not bind event_id")
	}
}

func TestSourceSpanMatchHash_RejectsEmptyMatchValue(t *testing.T) {
	t.Parallel()
	_, err := receipt.SourceSpanMatchHash([]byte(testSpanMACKey), testSpanEventID, 0, validSourceSpan(t), "")
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("err = %v, want ErrPayloadMissingField", err)
	}
}

func TestValidateSourceSpan_RejectsMalformedFields(t *testing.T) {
	t.Parallel()
	negativeOffset := -1
	zeroLength := 0
	offset := 20
	length := len(testRedactedValue)
	tests := map[string]struct {
		mutate func(*receipt.SourceSpan)
		want   error
	}{
		"missing source id": {
			mutate: func(span *receipt.SourceSpan) { span.SourceID = "" },
			want:   receipt.ErrPayloadMissingField,
		},
		"invalid normalized view": {
			mutate: func(span *receipt.SourceSpan) { span.NormalizedView = "unknown_view" },
			want:   receipt.ErrPayloadInvalidEnum,
		},
		"bad binary digest prefix": {
			mutate: func(span *receipt.SourceSpan) { span.PipelockBinaryDigest = "md5:0123" },
			want:   receipt.ErrPayloadInvalidEnum,
		},
		"bad rules digest length": {
			mutate: func(span *receipt.SourceSpan) { span.RulesBundleDigest = "sha256:0123" },
			want:   receipt.ErrPayloadInvalidEnum,
		},
		"bad policy digest hex": {
			mutate: func(span *receipt.SourceSpan) {
				span.PolicyHash = "sha256:" + strings.Repeat("z", 64)
			},
			want: receipt.ErrPayloadInvalidEnum,
		},
		"wrong hash alg": {
			mutate: func(span *receipt.SourceSpan) { span.MatchHashAlg = "sha256" },
			want:   receipt.ErrPayloadInvalidEnum,
		},
		"short match hash": {
			mutate: func(span *receipt.SourceSpan) { span.MatchHash = "hmac-sha256:0123" },
			want:   receipt.ErrPayloadInvalidEnum,
		},
		"bad match hash hex": {
			mutate: func(span *receipt.SourceSpan) {
				span.MatchHash = "hmac-sha256:" + strings.Repeat("z", 64)
			},
			want: receipt.ErrPayloadInvalidEnum,
		},
		"missing offset": {
			mutate: func(span *receipt.SourceSpan) {
				span.CharOffset = nil
				span.CharLength = &length
			},
			want: receipt.ErrPayloadMissingField,
		},
		"missing length": {
			mutate: func(span *receipt.SourceSpan) {
				span.CharOffset = &offset
				span.CharLength = nil
			},
			want: receipt.ErrPayloadMissingField,
		},
		"negative offset": {
			mutate: func(span *receipt.SourceSpan) { span.CharOffset = &negativeOffset },
			want:   receipt.ErrPayloadInvalidEnum,
		},
		"zero length": {
			mutate: func(span *receipt.SourceSpan) { span.CharLength = &zeroLength },
			want:   receipt.ErrPayloadInvalidEnum,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			span := validSourceSpan(t)
			tc.mutate(&span)
			if err := receipt.ValidateSourceSpan(span); !errors.Is(err, tc.want) {
				t.Fatalf("ValidateSourceSpan err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestValidateSourceSpan_AcceptsDLPNormalizedPrefixView(t *testing.T) {
	t.Parallel()
	span := validSourceSpan(t)
	span.NormalizedView = "dlp_normalized:aws_access_key"
	if err := receipt.ValidateSourceSpan(span); err != nil {
		t.Fatalf("ValidateSourceSpan rejected dlp-normalized prefix view: %v", err)
	}
}

func TestSourceSpanMatchHash_RejectsMissingContext(t *testing.T) {
	t.Parallel()
	_, err := receipt.SourceSpanMatchHash([]byte(testSpanMACKey), "", 0, validSourceSpan(t), testRedactedValue)
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("empty event_id err = %v, want ErrPayloadMissingField", err)
	}
	_, err = receipt.SourceSpanMatchHash([]byte(testSpanMACKey), testSpanEventID, -1, validSourceSpan(t), testRedactedValue)
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("negative span_index err = %v, want ErrPayloadInvalidEnum", err)
	}
}

func TestProxyDecisionWithSpansPayload_CarriesRedactedSampleOnlyInFixture(t *testing.T) {
	t.Parallel()
	// TODO(emitter): add the production no-leak regression when the live
	// SourceSpan emitter exists. The schema cannot prove a caller avoided raw
	// matched bytes; it can only carry the redacted value supplied here.
	p := validProxyDecisionWithSpansPayload(t)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	fakeAWSKey := "AKIA" + "IOSFODNN7EXAMPLE"
	if strings.Contains(string(data), fakeAWSKey) {
		t.Fatalf("payload leaked raw secret: %s", data)
	}
	if !strings.Contains(string(data), testRedactedValue) {
		t.Fatalf("payload missing redacted sample: %s", data)
	}
}

// --- contract_ratified ---

func TestValidateContractRatified_AcceptsValid(t *testing.T) {
	p := receipt.PayloadContractRatifiedStruct{
		ContractHash:                "sha256:abc",
		RatifierKeyID:               "key-1",
		RatifiedRuleIDs:             []string{"rule-1"},
		RatificationDecisionPerRule: map[string]string{"rule-1": "approved"},
	}
	if err := callValidator(t, receipt.PayloadContractRatified, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractRatified_RejectsMissingContractHash(t *testing.T) {
	p := receipt.PayloadContractRatifiedStruct{
		ContractHash:                "",
		RatifierKeyID:               "key-1",
		RatifiedRuleIDs:             []string{"rule-1"},
		RatificationDecisionPerRule: map[string]string{"rule-1": "approved"},
	}
	err := callValidator(t, receipt.PayloadContractRatified, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- contract_promote_intent ---

func TestValidateContractPromoteIntent_AcceptsValid(t *testing.T) {
	p := receipt.PayloadContractPromoteIntentStruct{
		TargetManifestHash: "sha256:target",
		TargetGeneration:   2,
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
	}
	if err := callValidator(t, receipt.PayloadContractPromoteIntent, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractPromoteIntent_RejectsMissingIntentID(t *testing.T) {
	p := receipt.PayloadContractPromoteIntentStruct{
		TargetManifestHash: "sha256:target",
		TargetGeneration:   2,
		PriorManifestHash:  "sha256:prior",
		IntentID:           "",
	}
	err := callValidator(t, receipt.PayloadContractPromoteIntent, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- contract_promote_committed ---

func TestValidateContractPromoteCommitted_AcceptsAccepted(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
		ValidationOutcome:  "accepted",
	}
	if err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractPromoteCommitted_AcceptsRejected(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
		ValidationOutcome:  "rejected",
		RejectReason:       "hash mismatch",
	}
	if err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractPromoteCommitted_RejectsRejectedWithoutReason(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
		ValidationOutcome:  "rejected",
	}
	err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractPromoteCommitted_RejectsBadValidationOutcome(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
		ValidationOutcome:  "maybe",
	}
	err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
	}
}

// --- contract_rollback_authorized ---

func TestValidateContractRollbackAuthorized_AcceptsValid(t *testing.T) {
	p := receipt.PayloadContractRollbackAuthorizedStruct{
		RollbackTargetHash:   "sha256:target",
		CurrentGeneration:    5,
		AuthorizerSignatures: []string{"ed25519:aabb"},
		AuthorizationID:      "auth-1",
	}
	if err := callValidator(t, receipt.PayloadContractRollbackAuthorized, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractRollbackAuthorized_RejectsMissingSignatures(t *testing.T) {
	p := receipt.PayloadContractRollbackAuthorizedStruct{
		RollbackTargetHash:   "sha256:target",
		CurrentGeneration:    5,
		AuthorizerSignatures: nil,
		AuthorizationID:      "auth-1",
	}
	err := callValidator(t, receipt.PayloadContractRollbackAuthorized, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- contract_rollback_committed ---

func TestValidateContractRollbackCommitted_AcceptsValid(t *testing.T) {
	p := receipt.PayloadContractRollbackCommittedStruct{
		RollbackTargetHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		AuthorizationID:    "auth-1",
		ValidationOutcome:  "accepted",
	}
	if err := callValidator(t, receipt.PayloadContractRollbackCommitted, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractRollbackCommitted_RejectsBadOutcome(t *testing.T) {
	p := receipt.PayloadContractRollbackCommittedStruct{
		RollbackTargetHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		AuthorizationID:    "auth-1",
		ValidationOutcome:  "pending",
	}
	err := callValidator(t, receipt.PayloadContractRollbackCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
	}
}

func TestValidateContractRollbackCommitted_RejectsRejectedWithoutReason(t *testing.T) {
	p := receipt.PayloadContractRollbackCommittedStruct{
		RollbackTargetHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		AuthorizationID:    "auth-1",
		ValidationOutcome:  "rejected",
	}
	err := callValidator(t, receipt.PayloadContractRollbackCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- contract_demoted ---

func TestValidateContractDemoted_AcceptsValid(t *testing.T) {
	p := receipt.PayloadContractDemotedStruct{
		ContractHash:      "sha256:abc",
		RuleID:            "rule-1",
		DemotionReason:    "missed windows",
		PriorState:        "active",
		NewState:          "shadow",
		AggregationWindow: "7d",
	}
	if err := callValidator(t, receipt.PayloadContractDemoted, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractDemoted_RejectsMissingNewState(t *testing.T) {
	p := receipt.PayloadContractDemotedStruct{
		ContractHash:      "sha256:abc",
		RuleID:            "rule-1",
		DemotionReason:    "missed windows",
		PriorState:        "active",
		NewState:          "",
		AggregationWindow: "7d",
	}
	err := callValidator(t, receipt.PayloadContractDemoted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- contract_expired ---

func TestValidateContractExpired_AcceptsValid(t *testing.T) {
	p := receipt.PayloadContractExpiredStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "rule-1",
		ExpirationReason: "ttl exceeded",
	}
	if err := callValidator(t, receipt.PayloadContractExpired, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractExpired_RejectsMissingRuleID(t *testing.T) {
	p := receipt.PayloadContractExpiredStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "",
		ExpirationReason: "ttl exceeded",
	}
	err := callValidator(t, receipt.PayloadContractExpired, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- contract_drift ---

func TestValidateContractDrift_AcceptsValid(t *testing.T) {
	p := receipt.PayloadContractDriftStruct{
		ContractHash: "sha256:abc",
		RuleID:       "rule-1",
		DriftKind:    "positive",
	}
	if err := callValidator(t, receipt.PayloadContractDrift, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractDrift_RejectsMissingDriftKind(t *testing.T) {
	p := receipt.PayloadContractDriftStruct{
		ContractHash: "sha256:abc",
		RuleID:       "rule-1",
		DriftKind:    "",
	}
	err := callValidator(t, receipt.PayloadContractDrift, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- shadow_delta ---

func TestValidateShadowDelta_AcceptsValid(t *testing.T) {
	p := receipt.PayloadShadowDeltaStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "rule-1",
		OriginalVerdict:  "blocked",
		CandidateVerdict: "allowed",
		Aggregation:      validShadowDeltaAggregation(),
	}
	if err := callValidator(t, receipt.PayloadShadowDelta, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateShadowDelta_RejectsMissingOriginalVerdict(t *testing.T) {
	p := receipt.PayloadShadowDeltaStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "rule-1",
		OriginalVerdict:  "",
		CandidateVerdict: "allowed",
		Aggregation:      validShadowDeltaAggregation(),
	}
	err := callValidator(t, receipt.PayloadShadowDelta, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- opportunity_missing ---

func TestValidateOpportunityMissing_AcceptsValid(t *testing.T) {
	p := receipt.PayloadOpportunityMissingStruct{
		ContractHash:              "sha256:abc",
		RuleID:                    "rule-1",
		ParentContext:             "agent-xyz",
		HistoricalOpportunityRate: "0.85",
		CurrentOpportunityRate:    "0.10",
		Window:                    "7d",
	}
	if err := callValidator(t, receipt.PayloadOpportunityMissing, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateOpportunityMissing_RejectsMissingWindow(t *testing.T) {
	p := receipt.PayloadOpportunityMissingStruct{
		ContractHash:              "sha256:abc",
		RuleID:                    "rule-1",
		ParentContext:             "agent-xyz",
		HistoricalOpportunityRate: "0.85",
		CurrentOpportunityRate:    "0.10",
		Window:                    "",
	}
	err := callValidator(t, receipt.PayloadOpportunityMissing, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- key_rotation ---

func TestValidateKeyRotation_AcceptsValid(t *testing.T) {
	p := receipt.PayloadKeyRotationStruct{
		KeyID:           "key-1",
		KeyPurpose:      "receipt-signing",
		OldStatus:       "active",
		NewStatus:       "revoked",
		RosterHash:      "sha256:roster",
		AuthorizationID: "auth-1",
	}
	if err := callValidator(t, receipt.PayloadKeyRotation, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateKeyRotation_RejectsMissingRosterHash(t *testing.T) {
	p := receipt.PayloadKeyRotationStruct{
		KeyID:           "key-1",
		KeyPurpose:      "receipt-signing",
		OldStatus:       "active",
		NewStatus:       "revoked",
		RosterHash:      "",
		AuthorizationID: "auth-1",
	}
	err := callValidator(t, receipt.PayloadKeyRotation, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- contract_redaction_request ---

func TestValidateContractRedactionRequest_AcceptsWithdrawPublicProof(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "sha256:abc",
		RequestKind:        "withdraw_public_proof",
		ReasonClass:        "privacy",
		AuthorizationID:    "auth-1",
		TombstoneHash:      "sha256:tomb",
	}
	if err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractRedactionRequest_AcceptsLocalErasure(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "sha256:abc",
		RequestKind:        "local_erasure_tombstone",
		ReasonClass:        "gdpr",
		AuthorizationID:    "auth-1",
		TombstoneHash:      "sha256:tomb",
	}
	if err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractRedactionRequest_RejectsBadRequestKind(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "sha256:abc",
		RequestKind:        "delete_everything",
		ReasonClass:        "privacy",
		AuthorizationID:    "auth-1",
		TombstoneHash:      "sha256:tomb",
	}
	err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
	}
}

// --- additional missing-field coverage ---

func TestValidateProxyDecision_RejectsMissingActionType(t *testing.T) {
	p := receipt.PayloadProxyDecisionStruct{
		ActionType:    "",
		Target:        "https://example.com/",
		Verdict:       "blocked",
		Transport:     "forward",
		PolicySources: []string{"dlp"},
		WinningSource: "dlp",
	}
	err := callValidator(t, receipt.PayloadProxyDecision, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateProxyDecision_RejectsMissingVerdict(t *testing.T) {
	p := receipt.PayloadProxyDecisionStruct{
		ActionType:    "block",
		Target:        "https://example.com/",
		Verdict:       "",
		Transport:     "forward",
		PolicySources: []string{"dlp"},
		WinningSource: "dlp",
	}
	err := callValidator(t, receipt.PayloadProxyDecision, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateProxyDecision_RejectsMissingTransport(t *testing.T) {
	p := receipt.PayloadProxyDecisionStruct{
		ActionType:    "block",
		Target:        "https://example.com/",
		Verdict:       "blocked",
		Transport:     "",
		PolicySources: []string{"dlp"},
		WinningSource: "dlp",
	}
	err := callValidator(t, receipt.PayloadProxyDecision, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateProxyDecision_RejectsMissingWinningSource(t *testing.T) {
	p := receipt.PayloadProxyDecisionStruct{
		ActionType:    "block",
		Target:        "https://example.com/",
		Verdict:       "blocked",
		Transport:     "forward",
		PolicySources: []string{"dlp"},
		WinningSource: "",
	}
	err := callValidator(t, receipt.PayloadProxyDecision, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateProxyDecision_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadProxyDecision, json.RawMessage(`not-json`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractRatified_RejectsMissingRatifierKeyID(t *testing.T) {
	p := receipt.PayloadContractRatifiedStruct{
		ContractHash:                "sha256:abc",
		RatifierKeyID:               "",
		RatifiedRuleIDs:             []string{"rule-1"},
		RatificationDecisionPerRule: map[string]string{"rule-1": "approved"},
	}
	err := callValidator(t, receipt.PayloadContractRatified, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRatified_RejectsMissingRatifiedRuleIDs(t *testing.T) {
	p := receipt.PayloadContractRatifiedStruct{
		ContractHash:                "sha256:abc",
		RatifierKeyID:               "key-1",
		RatifiedRuleIDs:             nil,
		RatificationDecisionPerRule: map[string]string{"rule-1": "approved"},
	}
	err := callValidator(t, receipt.PayloadContractRatified, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRatified_RejectsMissingDecisionPerRule(t *testing.T) {
	p := receipt.PayloadContractRatifiedStruct{
		ContractHash:                "sha256:abc",
		RatifierKeyID:               "key-1",
		RatifiedRuleIDs:             []string{"rule-1"},
		RatificationDecisionPerRule: nil,
	}
	err := callValidator(t, receipt.PayloadContractRatified, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRatified_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractRatified, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractPromoteIntent_RejectsMissingTargetManifestHash(t *testing.T) {
	p := receipt.PayloadContractPromoteIntentStruct{
		TargetManifestHash: "",
		TargetGeneration:   2,
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
	}
	err := callValidator(t, receipt.PayloadContractPromoteIntent, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractPromoteIntent_RejectsMissingPriorManifestHash(t *testing.T) {
	p := receipt.PayloadContractPromoteIntentStruct{
		TargetManifestHash: "sha256:target",
		TargetGeneration:   2,
		PriorManifestHash:  "",
		IntentID:           "intent-1",
	}
	err := callValidator(t, receipt.PayloadContractPromoteIntent, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractPromoteIntent_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractPromoteIntent, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractPromoteCommitted_RejectsMissingTargetManifestHash(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "",
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
		ValidationOutcome:  "accepted",
	}
	err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractPromoteCommitted_RejectsMissingPriorManifest(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "sha256:target",
		PriorManifestHash:  "",
		IntentID:           "intent-1",
		ValidationOutcome:  "accepted",
	}
	err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractPromoteCommitted_RejectsMissingIntentID(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		IntentID:           "",
		ValidationOutcome:  "accepted",
	}
	err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractPromoteCommitted_RejectsMissingValidationOutcome(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
		ValidationOutcome:  "",
	}
	err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractPromoteCommitted_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractPromoteCommitted, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractRollbackAuthorized_RejectsMissingRollbackTargetHash(t *testing.T) {
	p := receipt.PayloadContractRollbackAuthorizedStruct{
		RollbackTargetHash:   "",
		CurrentGeneration:    5,
		AuthorizerSignatures: []string{"ed25519:aabb"},
		AuthorizationID:      "auth-1",
	}
	err := callValidator(t, receipt.PayloadContractRollbackAuthorized, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRollbackAuthorized_RejectsMissingAuthorizationID(t *testing.T) {
	p := receipt.PayloadContractRollbackAuthorizedStruct{
		RollbackTargetHash:   "sha256:target",
		CurrentGeneration:    5,
		AuthorizerSignatures: []string{"ed25519:aabb"},
		AuthorizationID:      "",
	}
	err := callValidator(t, receipt.PayloadContractRollbackAuthorized, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRollbackAuthorized_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractRollbackAuthorized, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractRollbackCommitted_RejectsMissingRollbackTargetHash(t *testing.T) {
	p := receipt.PayloadContractRollbackCommittedStruct{
		RollbackTargetHash: "",
		PriorManifestHash:  "sha256:prior",
		AuthorizationID:    "auth-1",
		ValidationOutcome:  "accepted",
	}
	err := callValidator(t, receipt.PayloadContractRollbackCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRollbackCommitted_RejectsMissingPriorManifest(t *testing.T) {
	p := receipt.PayloadContractRollbackCommittedStruct{
		RollbackTargetHash: "sha256:target",
		PriorManifestHash:  "",
		AuthorizationID:    "auth-1",
		ValidationOutcome:  "accepted",
	}
	err := callValidator(t, receipt.PayloadContractRollbackCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRollbackCommitted_RejectsMissingAuthorizationID(t *testing.T) {
	p := receipt.PayloadContractRollbackCommittedStruct{
		RollbackTargetHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		AuthorizationID:    "",
		ValidationOutcome:  "accepted",
	}
	err := callValidator(t, receipt.PayloadContractRollbackCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRollbackCommitted_RejectsMissingValidationOutcome(t *testing.T) {
	p := receipt.PayloadContractRollbackCommittedStruct{
		RollbackTargetHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		AuthorizationID:    "auth-1",
		ValidationOutcome:  "",
	}
	err := callValidator(t, receipt.PayloadContractRollbackCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRollbackCommitted_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractRollbackCommitted, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractDemoted_RejectsMissingContractHash(t *testing.T) {
	p := receipt.PayloadContractDemotedStruct{
		ContractHash:      "",
		RuleID:            "rule-1",
		DemotionReason:    "missed windows",
		PriorState:        "active",
		NewState:          "shadow",
		AggregationWindow: "7d",
	}
	err := callValidator(t, receipt.PayloadContractDemoted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractDemoted_RejectsMissingRuleID(t *testing.T) {
	p := receipt.PayloadContractDemotedStruct{
		ContractHash:      "sha256:abc",
		RuleID:            "",
		DemotionReason:    "missed windows",
		PriorState:        "active",
		NewState:          "shadow",
		AggregationWindow: "7d",
	}
	err := callValidator(t, receipt.PayloadContractDemoted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractDemoted_RejectsMissingDemotionReason(t *testing.T) {
	p := receipt.PayloadContractDemotedStruct{
		ContractHash:      "sha256:abc",
		RuleID:            "rule-1",
		DemotionReason:    "",
		PriorState:        "active",
		NewState:          "shadow",
		AggregationWindow: "7d",
	}
	err := callValidator(t, receipt.PayloadContractDemoted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractDemoted_RejectsMissingPriorState(t *testing.T) {
	p := receipt.PayloadContractDemotedStruct{
		ContractHash:      "sha256:abc",
		RuleID:            "rule-1",
		DemotionReason:    "missed windows",
		PriorState:        "",
		NewState:          "shadow",
		AggregationWindow: "7d",
	}
	err := callValidator(t, receipt.PayloadContractDemoted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractDemoted_RejectsMissingAggregationWindow(t *testing.T) {
	p := receipt.PayloadContractDemotedStruct{
		ContractHash:      "sha256:abc",
		RuleID:            "rule-1",
		DemotionReason:    "missed windows",
		PriorState:        "active",
		NewState:          "shadow",
		AggregationWindow: "",
	}
	err := callValidator(t, receipt.PayloadContractDemoted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractDemoted_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractDemoted, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractExpired_RejectsMissingContractHash(t *testing.T) {
	p := receipt.PayloadContractExpiredStruct{
		ContractHash:     "",
		RuleID:           "rule-1",
		ExpirationReason: "ttl exceeded",
	}
	err := callValidator(t, receipt.PayloadContractExpired, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractExpired_RejectsMissingExpirationReason(t *testing.T) {
	p := receipt.PayloadContractExpiredStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "rule-1",
		ExpirationReason: "",
	}
	err := callValidator(t, receipt.PayloadContractExpired, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractExpired_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractExpired, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractDrift_RejectsMissingContractHash(t *testing.T) {
	p := receipt.PayloadContractDriftStruct{
		ContractHash: "",
		RuleID:       "rule-1",
		DriftKind:    "positive",
	}
	err := callValidator(t, receipt.PayloadContractDrift, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractDrift_RejectsMissingRuleID(t *testing.T) {
	p := receipt.PayloadContractDriftStruct{
		ContractHash: "sha256:abc",
		RuleID:       "",
		DriftKind:    "positive",
	}
	err := callValidator(t, receipt.PayloadContractDrift, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractDrift_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractDrift, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateShadowDelta_RejectsMissingContractHash(t *testing.T) {
	p := receipt.PayloadShadowDeltaStruct{
		ContractHash:     "",
		RuleID:           "rule-1",
		OriginalVerdict:  "blocked",
		CandidateVerdict: "allowed",
		Aggregation:      validShadowDeltaAggregation(),
	}
	err := callValidator(t, receipt.PayloadShadowDelta, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateShadowDelta_RejectsMissingRuleID(t *testing.T) {
	p := receipt.PayloadShadowDeltaStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "",
		OriginalVerdict:  "blocked",
		CandidateVerdict: "allowed",
		Aggregation:      validShadowDeltaAggregation(),
	}
	err := callValidator(t, receipt.PayloadShadowDelta, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateShadowDelta_RejectsMissingCandidateVerdict(t *testing.T) {
	p := receipt.PayloadShadowDeltaStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "rule-1",
		OriginalVerdict:  "blocked",
		CandidateVerdict: "",
		Aggregation:      validShadowDeltaAggregation(),
	}
	err := callValidator(t, receipt.PayloadShadowDelta, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateShadowDelta_RejectsMissingAggregation(t *testing.T) {
	p := receipt.PayloadShadowDeltaStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "rule-1",
		OriginalVerdict:  "blocked",
		CandidateVerdict: "allowed",
		Aggregation:      receipt.ShadowDeltaAggregation{},
	}
	err := callValidator(t, receipt.PayloadShadowDelta, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateShadowDelta_RejectsSampleCountMismatch(t *testing.T) {
	cases := []receipt.ShadowDeltaAggregation{
		{
			WindowStart:      "2026-04-30T12:00:00Z",
			WindowEnd:        "2026-04-30T12:01:00Z",
			LosslessCount:    1,
			DeltaSampleCount: 2,
			ExemplarIDs:      []string{"ex-1"},
		},
		{
			WindowStart:      "2026-04-30T12:00:00Z",
			WindowEnd:        "2026-04-30T12:01:00Z",
			LosslessCount:    1,
			DeltaSampleCount: 2,
			ExemplarIDs:      []string{"ex-1", "ex-2"},
		},
	}
	for _, aggregation := range cases {
		p := receipt.PayloadShadowDeltaStruct{
			ContractHash:     "sha256:abc",
			RuleID:           "rule-1",
			OriginalVerdict:  "blocked",
			CandidateVerdict: "allowed",
			Aggregation:      aggregation,
		}
		err := callValidator(t, receipt.PayloadShadowDelta, marshalPayload(t, p))
		if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
			t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
		}
	}
}

func TestValidateShadowDelta_RejectsInvalidWindow(t *testing.T) {
	cases := []receipt.ShadowDeltaAggregation{
		{
			WindowStart:      "not-time",
			WindowEnd:        "2026-04-30T12:01:00Z",
			LosslessCount:    1,
			DeltaSampleCount: 1,
			ExemplarIDs:      []string{"ex-1"},
		},
		{
			WindowStart:      "2026-04-30T12:00:00Z",
			WindowEnd:        "not-time",
			LosslessCount:    1,
			DeltaSampleCount: 1,
			ExemplarIDs:      []string{"ex-1"},
		},
		{
			WindowStart:      "2026-04-30T12:01:00Z",
			WindowEnd:        "2026-04-30T12:00:00Z",
			LosslessCount:    1,
			DeltaSampleCount: 1,
			ExemplarIDs:      []string{"ex-1"},
		},
		{
			WindowStart:      "2026-04-30T12:00:00Z",
			WindowEnd:        "2026-04-30T12:00:00Z",
			LosslessCount:    1,
			DeltaSampleCount: 1,
			ExemplarIDs:      []string{"ex-1"},
		},
	}
	for _, aggregation := range cases {
		p := receipt.PayloadShadowDeltaStruct{
			ContractHash:     "sha256:abc",
			RuleID:           "rule-1",
			OriginalVerdict:  "blocked",
			CandidateVerdict: "allowed",
			Aggregation:      aggregation,
		}
		err := callValidator(t, receipt.PayloadShadowDelta, marshalPayload(t, p))
		if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
			t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
		}
	}
}

func TestValidateShadowDelta_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadShadowDelta, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func validShadowDeltaAggregation() receipt.ShadowDeltaAggregation {
	return receipt.ShadowDeltaAggregation{
		WindowStart:      "2026-04-30T12:00:00Z",
		WindowEnd:        "2026-04-30T12:01:00Z",
		LosslessCount:    7,
		DeltaSampleCount: 2,
		ExemplarIDs:      []string{"ex-1", "ex-2"},
	}
}

func TestValidateOpportunityMissing_RejectsMissingContractHash(t *testing.T) {
	p := receipt.PayloadOpportunityMissingStruct{
		ContractHash:              "",
		RuleID:                    "rule-1",
		ParentContext:             "agent-xyz",
		HistoricalOpportunityRate: "0.85",
		CurrentOpportunityRate:    "0.10",
		Window:                    "7d",
	}
	err := callValidator(t, receipt.PayloadOpportunityMissing, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateOpportunityMissing_RejectsMissingRuleID(t *testing.T) {
	p := receipt.PayloadOpportunityMissingStruct{
		ContractHash:              "sha256:abc",
		RuleID:                    "",
		ParentContext:             "agent-xyz",
		HistoricalOpportunityRate: "0.85",
		CurrentOpportunityRate:    "0.10",
		Window:                    "7d",
	}
	err := callValidator(t, receipt.PayloadOpportunityMissing, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateOpportunityMissing_RejectsMissingParentContext(t *testing.T) {
	p := receipt.PayloadOpportunityMissingStruct{
		ContractHash:              "sha256:abc",
		RuleID:                    "rule-1",
		ParentContext:             "",
		HistoricalOpportunityRate: "0.85",
		CurrentOpportunityRate:    "0.10",
		Window:                    "7d",
	}
	err := callValidator(t, receipt.PayloadOpportunityMissing, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateOpportunityMissing_RejectsMissingHistoricalRate(t *testing.T) {
	p := receipt.PayloadOpportunityMissingStruct{
		ContractHash:              "sha256:abc",
		RuleID:                    "rule-1",
		ParentContext:             "agent-xyz",
		HistoricalOpportunityRate: "",
		CurrentOpportunityRate:    "0.10",
		Window:                    "7d",
	}
	err := callValidator(t, receipt.PayloadOpportunityMissing, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateOpportunityMissing_RejectsMissingCurrentRate(t *testing.T) {
	p := receipt.PayloadOpportunityMissingStruct{
		ContractHash:              "sha256:abc",
		RuleID:                    "rule-1",
		ParentContext:             "agent-xyz",
		HistoricalOpportunityRate: "0.85",
		CurrentOpportunityRate:    "",
		Window:                    "7d",
	}
	err := callValidator(t, receipt.PayloadOpportunityMissing, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateOpportunityMissing_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadOpportunityMissing, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateKeyRotation_RejectsMissingKeyID(t *testing.T) {
	p := receipt.PayloadKeyRotationStruct{
		KeyID:           "",
		KeyPurpose:      "receipt-signing",
		OldStatus:       "active",
		NewStatus:       "revoked",
		RosterHash:      "sha256:roster",
		AuthorizationID: "auth-1",
	}
	err := callValidator(t, receipt.PayloadKeyRotation, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateKeyRotation_RejectsMissingKeyPurpose(t *testing.T) {
	p := receipt.PayloadKeyRotationStruct{
		KeyID:           "key-1",
		KeyPurpose:      "",
		OldStatus:       "active",
		NewStatus:       "revoked",
		RosterHash:      "sha256:roster",
		AuthorizationID: "auth-1",
	}
	err := callValidator(t, receipt.PayloadKeyRotation, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateKeyRotation_RejectsMissingOldStatus(t *testing.T) {
	p := receipt.PayloadKeyRotationStruct{
		KeyID:           "key-1",
		KeyPurpose:      "receipt-signing",
		OldStatus:       "",
		NewStatus:       "revoked",
		RosterHash:      "sha256:roster",
		AuthorizationID: "auth-1",
	}
	err := callValidator(t, receipt.PayloadKeyRotation, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateKeyRotation_RejectsMissingNewStatus(t *testing.T) {
	p := receipt.PayloadKeyRotationStruct{
		KeyID:           "key-1",
		KeyPurpose:      "receipt-signing",
		OldStatus:       "active",
		NewStatus:       "",
		RosterHash:      "sha256:roster",
		AuthorizationID: "auth-1",
	}
	err := callValidator(t, receipt.PayloadKeyRotation, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateKeyRotation_RejectsMissingAuthorizationID(t *testing.T) {
	p := receipt.PayloadKeyRotationStruct{
		KeyID:           "key-1",
		KeyPurpose:      "receipt-signing",
		OldStatus:       "active",
		NewStatus:       "revoked",
		RosterHash:      "sha256:roster",
		AuthorizationID: "",
	}
	err := callValidator(t, receipt.PayloadKeyRotation, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateKeyRotation_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadKeyRotation, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractRedactionRequest_RejectsMissingTargetContractHash(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "",
		RequestKind:        "withdraw_public_proof",
		ReasonClass:        "privacy",
		AuthorizationID:    "auth-1",
		TombstoneHash:      "sha256:tomb",
	}
	err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRedactionRequest_RejectsMissingReasonClass(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "sha256:abc",
		RequestKind:        "withdraw_public_proof",
		ReasonClass:        "",
		AuthorizationID:    "auth-1",
		TombstoneHash:      "sha256:tomb",
	}
	err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRedactionRequest_RejectsMissingAuthorizationID(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "sha256:abc",
		RequestKind:        "withdraw_public_proof",
		ReasonClass:        "privacy",
		AuthorizationID:    "",
		TombstoneHash:      "sha256:tomb",
	}
	err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRedactionRequest_RejectsMissingTombstoneHash(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "sha256:abc",
		RequestKind:        "withdraw_public_proof",
		ReasonClass:        "privacy",
		AuthorizationID:    "auth-1",
		TombstoneHash:      "",
	}
	err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRedactionRequest_RejectsMissingRequestKind(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "sha256:abc",
		RequestKind:        "",
		ReasonClass:        "privacy",
		AuthorizationID:    "auth-1",
		TombstoneHash:      "sha256:tomb",
	}
	err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRedactionRequest_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractRedactionRequest, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

// --- strict decode: unknown-field and trailing-token rejection ---

func TestValidateProxyDecision_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{
		"action_type":"connect","target":"x.com","verdict":"allow",
		"transport":"forward","policy_sources":["a"],"winning_source":"a",
		"future_field":"sneaky"
	}`)
	err := callValidator(t, receipt.PayloadProxyDecision, raw)
	if err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestValidateContractRedactionRequest_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{
		"target_contract_hash":"sha256:abc",
		"request_kind":"withdraw_public_proof",
		"reason_class":"legal",
		"authorization_id":"sha256:auth",
		"tombstone_hash":"sha256:tomb",
		"advisory_extension":"hidden"
	}`)
	err := callValidator(t, receipt.PayloadContractRedactionRequest, raw)
	if err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestValidateProxyDecision_RejectsTrailingTokens(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"action_type":"connect","target":"x","verdict":"allow","transport":"forward","policy_sources":["a"],"winning_source":"a"} extra`)
	err := callValidator(t, receipt.PayloadProxyDecision, raw)
	if err == nil {
		t.Fatal("trailing tokens accepted")
	}
}

func TestValidateProxyDecision_RejectsTrailingDelimiter(t *testing.T) {
	t.Parallel()
	cases := []json.RawMessage{
		json.RawMessage(`{"action_type":"connect","target":"x","verdict":"allow","transport":"forward","policy_sources":["a"],"winning_source":"a"}]`),
		json.RawMessage(`{"action_type":"connect","target":"x","verdict":"allow","transport":"forward","policy_sources":["a"],"winning_source":"a"}}`),
	}
	for _, raw := range cases {
		err := callValidator(t, receipt.PayloadProxyDecision, raw)
		if err == nil {
			t.Fatalf("trailing delimiter accepted for %s", raw)
		}
	}
}

// callValidator dispatches to the validator for kind with raw payload.
// It is intentionally wired through the exported EvidenceReceipt.Validate()
// to exercise the full dispatch path.
func callValidator(t *testing.T, kind receipt.PayloadKind, raw json.RawMessage) error {
	t.Helper()
	r := receipt.EvidenceReceipt{
		RecordType:       receipt.RecordTypeEvidenceV2,
		ReceiptVersion:   2,
		PayloadKind:      kind,
		Canonicalization: receipt.DefaultCanonicalizationProfile(),
		Crit:             receipt.CritForPayloadKind(kind),
		EventID:          "01900000-0000-7000-8000-000000000001",
		Timestamp:        time.Now(),
		Payload:          raw,
		Signature: receipt.SignatureProof{
			SignerKeyID: "test-key",
			KeyPurpose:  testKeyPurposeForPayload(kind),
			Algorithm:   "ed25519",
			Signature:   testReceiptSignature,
		},
	}
	return r.Validate()
}

func testKeyPurposeForPayload(kind receipt.PayloadKind) string {
	switch kind {
	case receipt.PayloadContractPromoteIntent,
		receipt.PayloadContractRollbackAuthorized,
		receipt.PayloadKeyRotation,
		receipt.PayloadContractRedactionRequest:
		return "contract-activation-signing"
	default:
		return "receipt-signing"
	}
}

func validProxyDecisionWithSpansPayload(t *testing.T) receipt.PayloadProxyDecisionWithSpansStruct {
	t.Helper()
	return receipt.PayloadProxyDecisionWithSpansStruct{
		ActionType:    "block",
		Target:        "https://example.com/" + testRedactedValue,
		Verdict:       "block",
		Transport:     "forward",
		PolicySources: []string{"dlp"},
		WinningSource: "scanner",
		RuleID:        testAWSAccessKeyRule,
		SourceSpans:   []receipt.SourceSpan{validSourceSpan(t)},
	}
}

func validSourceSpan(t *testing.T) receipt.SourceSpan {
	t.Helper()
	offset := 20
	length := len(testRedactedValue)
	span := receipt.SourceSpan{
		SourceID:             "request-url",
		SourceKind:           receipt.SourceKindHTTPRequestURL,
		NormalizedView:       receipt.NormalizedViewSanitizedTarget,
		PipelockBinaryDigest: testSHA256Digest,
		RulesBundleDigest:    testSHA256Digest,
		TransformProfile:     "pipelock-transform-v1",
		PolicyHash:           testSHA256Digest,
		RuleID:               testAWSAccessKeyRule,
		CharOffset:           &offset,
		CharLength:           &length,
		MatchHashAlg:         testHMACSHA256,
		MatchClass:           "secret:aws_access_key",
		RedactedSample:       testRedactedValue,
	}
	matchHash, err := receipt.SourceSpanMatchHash([]byte(testSpanMACKey), testSpanEventID, 0, span, span.RedactedSample)
	if err != nil {
		t.Fatalf("SourceSpanMatchHash: %v", err)
	}
	span.MatchHash = matchHash
	return span
}

func TestTestReceiptSignatureShape(t *testing.T) {
	t.Parallel()
	if got := strings.TrimPrefix(testReceiptSignature, "ed25519:"); len(got) != 128 {
		t.Fatalf("test signature hex length=%d, want 128", len(got))
	}
}
