// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors for payload dispatch and envelope validation.
var (
	// ErrUnknownPayloadKind is returned when payload_kind is not in the v2 registry.
	ErrUnknownPayloadKind = errors.New("unknown payload_kind for v2 receipt")
	// ErrPayloadMissingField is returned when a required field is empty or zero.
	ErrPayloadMissingField = errors.New("payload missing required field")
	// ErrPayloadInvalidEnum is returned when an enum-like field holds a disallowed value.
	ErrPayloadInvalidEnum = errors.New("payload field has invalid enum value")
	// ErrSignatureVerification is returned when the receipt is structurally valid
	// but its detached Ed25519 signature does not verify.
	ErrSignatureVerification = errors.New("signature verification failed")
	// ErrUnsupportedRecordType is returned when record_type is not evidence_receipt_v2.
	ErrUnsupportedRecordType = errors.New("unsupported record_type for v2 verifier")
	// ErrWrongReceiptVersion is returned when receipt_version is not 2.
	ErrWrongReceiptVersion = errors.New("EvidenceReceipt requires receipt_version=2")
)

// decodeStrict unmarshals raw into target with strict semantics:
//   - DisallowUnknownFields: rejects any key not present in the typed struct
//   - UseNumber: preserves integer fidelity through round-trips
//   - trailing tokens after the value are rejected (no junk after the payload)
func decodeStrict(raw json.RawMessage, target any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return errors.New("empty or null payload")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("strict decode: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return fmt.Errorf("trailing tokens after payload: %w", err)
		}
		return fmt.Errorf("trailing tokens after payload")
	}
	return nil
}

// payloadValidators maps every known PayloadKind to its structural validator.
var payloadValidators = map[PayloadKind]func(json.RawMessage) error{
	PayloadProxyDecision:              validateProxyDecision,
	PayloadProxyDecisionWithSpans:     validateProxyDecisionWithSpans,
	PayloadContractRatified:           validateContractRatified,
	PayloadContractPromoteIntent:      validateContractPromoteIntent,
	PayloadContractPromoteCommitted:   validateContractPromoteCommitted,
	PayloadContractRollbackAuthorized: validateContractRollbackAuthorized,
	PayloadContractRollbackCommitted:  validateContractRollbackCommitted,
	PayloadContractDemoted:            validateContractDemoted,
	PayloadContractExpired:            validateContractExpired,
	PayloadContractDrift:              validateContractDrift,
	PayloadShadowDelta:                validateShadowDelta,
	PayloadOpportunityMissing:         validateOpportunityMissing,
	PayloadKeyRotation:                validateKeyRotation,
	PayloadContractRedactionRequest:   validateContractRedactionRequest,
}

// requireNonEmpty returns ErrPayloadMissingField if val is empty.
func requireNonEmpty(fieldName, val string) error {
	if val == "" {
		return fmt.Errorf("%w: %s", ErrPayloadMissingField, fieldName)
	}
	return nil
}

// requireNonEmptySlice returns ErrPayloadMissingField if s is empty or nil.
func requireNonEmptySlice[T any](fieldName string, s []T) error {
	if len(s) == 0 {
		return fmt.Errorf("%w: %s", ErrPayloadMissingField, fieldName)
	}
	return nil
}

// validationOutcomeValues are the allowed values for validation_outcome fields.
const (
	outcomeAccepted = "accepted"
	outcomeRejected = "rejected"
)

// allowedRequestKinds are the allowed values for request_kind in redaction requests.
const (
	requestKindWithdrawPublicProof   = "withdraw_public_proof"
	requestKindLocalErasureTombstone = "local_erasure_tombstone"
)

// SourceKind values identify the evidence surface a SourceSpan references.
const (
	SourceKindHTTPRequestURL = "http_request_url"
	SourceKindHTTPResponse   = "http_response"
	SourceKindMCPToolResult  = "mcp_tool_result"
	SourceKindMCPToolArgs    = "mcp_tool_args"
)

// Normalized view labels name the scanner view that SourceSpan offsets index.
const (
	NormalizedViewSanitizedTarget     = "sanitized_target"
	NormalizedViewForMatching         = "for_matching"
	NormalizedViewInvisibleSpaced     = "for_matching:invisible_spaced"
	NormalizedViewLeetspeak           = "leetspeak:for_matching"
	NormalizedViewVowelFold           = "vowel_fold:for_matching"
	NormalizedViewBase64Decoded       = "for_matching:base64_decoded"
	NormalizedViewHexDecoded          = "for_matching:hex_decoded"
	NormalizedViewDLPNormalized       = "dlp_normalized"
	normalizedViewDLPNormalizedPrefix = "dlp_normalized:"
)

const (
	// SourceSpanMatchHashAlgHMACSHA256 is the only match_hash algorithm
	// accepted for SourceSpan commitments in this schema version.
	SourceSpanMatchHashAlgHMACSHA256 = "hmac-sha256"

	sourceSpanMatchHashPrefix = SourceSpanMatchHashAlgHMACSHA256 + ":"
	sourceSpanHMACDomain      = "pipelock/source-span/v1"
)

func validateProxyDecision(raw json.RawMessage) error {
	var p PayloadProxyDecisionStruct
	if err := decodeStrict(raw, &p); err != nil {
		return fmt.Errorf("%w: action_type (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	return validateProxyDecisionBase(proxyDecisionBase{
		ActionType:    p.ActionType,
		Target:        p.Target,
		Verdict:       p.Verdict,
		Transport:     p.Transport,
		PolicySources: p.PolicySources,
		WinningSource: p.WinningSource,
	})
}

func validateProxyDecisionWithSpans(raw json.RawMessage) error {
	var p PayloadProxyDecisionWithSpansStruct
	if err := decodeStrict(raw, &p); err != nil {
		return fmt.Errorf("proxy_decision_with_spans strict decode: %w", err)
	}
	if err := validateProxyDecisionBase(proxyDecisionBase{
		ActionType:    p.ActionType,
		Target:        p.Target,
		Verdict:       p.Verdict,
		Transport:     p.Transport,
		PolicySources: p.PolicySources,
		WinningSource: p.WinningSource,
	}); err != nil {
		return err
	}
	if err := requireNonEmptySlice("source_spans", p.SourceSpans); err != nil {
		return err
	}
	for i, span := range p.SourceSpans {
		if err := ValidateSourceSpan(span); err != nil {
			return fmt.Errorf("source_spans[%d]: %w", i, err)
		}
	}
	return nil
}

type proxyDecisionBase struct {
	ActionType    string
	Target        string
	Verdict       string
	Transport     string
	PolicySources []string
	WinningSource string
}

func validateProxyDecisionBase(p proxyDecisionBase) error {
	if err := requireNonEmpty("action_type", p.ActionType); err != nil {
		return err
	}
	if err := requireNonEmpty("target", p.Target); err != nil {
		return err
	}
	if err := requireNonEmpty("verdict", p.Verdict); err != nil {
		return err
	}
	if err := requireNonEmpty("transport", p.Transport); err != nil {
		return err
	}
	if err := requireNonEmptySlice("policy_sources", p.PolicySources); err != nil {
		return err
	}
	return requireNonEmpty("winning_source", p.WinningSource)
}

// ValidateSourceSpan applies the full structural validation a SourceSpan must
// pass inside a proxy_decision_with_spans payload: required fields, source_kind
// and normalized_view enums, sha256 digest shapes, the hmac-sha256 match_hash
// algorithm and form, and the offset/view consistency rule. It is the single
// source of truth shared by the registry validator and the runtime builder, so
// the builder fails fast on a malformed span instead of emitting a signable
// receipt that only Validate() would later reject.
func ValidateSourceSpan(span SourceSpan) error {
	for field, val := range map[string]string{
		"source_id":              span.SourceID,
		"source_kind":            span.SourceKind,
		"normalized_view":        span.NormalizedView,
		"pipelock_binary_digest": span.PipelockBinaryDigest,
		"rules_bundle_digest":    span.RulesBundleDigest,
		"transform_profile":      span.TransformProfile,
		"policy_hash":            span.PolicyHash,
		"rule_id":                span.RuleID,
		"match_hash":             span.MatchHash,
		"match_hash_alg":         span.MatchHashAlg,
		"match_class":            span.MatchClass,
	} {
		if err := requireNonEmpty(field, val); err != nil {
			return err
		}
	}
	if !validSourceKind(span.SourceKind) {
		return fmt.Errorf("%w: source_kind=%q", ErrPayloadInvalidEnum, span.SourceKind)
	}
	if !validNormalizedView(span.NormalizedView) {
		return fmt.Errorf("%w: normalized_view=%q", ErrPayloadInvalidEnum, span.NormalizedView)
	}
	if err := validateSHA256Digest("pipelock_binary_digest", span.PipelockBinaryDigest); err != nil {
		return err
	}
	if err := validateSHA256Digest("rules_bundle_digest", span.RulesBundleDigest); err != nil {
		return err
	}
	if err := validateSHA256Digest("policy_hash", span.PolicyHash); err != nil {
		return err
	}
	if span.MatchHashAlg != SourceSpanMatchHashAlgHMACSHA256 {
		return fmt.Errorf("%w: match_hash_alg=%q", ErrPayloadInvalidEnum, span.MatchHashAlg)
	}
	if err := validateHMACMatchHash(span.MatchHash); err != nil {
		return err
	}
	if span.CharOffset == nil && span.CharLength != nil {
		return fmt.Errorf("%w: char_offset", ErrPayloadMissingField)
	}
	if span.CharOffset != nil && span.CharLength == nil {
		return fmt.Errorf("%w: char_length", ErrPayloadMissingField)
	}
	if span.CharOffset != nil {
		if *span.CharOffset < 0 {
			return fmt.Errorf("%w: char_offset=%d", ErrPayloadInvalidEnum, *span.CharOffset)
		}
		if *span.CharLength <= 0 {
			return fmt.Errorf("%w: char_length=%d", ErrPayloadInvalidEnum, *span.CharLength)
		}
		if !offsetsAllowedForView(span.NormalizedView) {
			return fmt.Errorf("%w: char_offset not allowed for normalized_view=%q", ErrPayloadInvalidEnum, span.NormalizedView)
		}
	}
	return nil
}

func validSourceKind(kind string) bool {
	switch kind {
	case SourceKindHTTPRequestURL, SourceKindHTTPResponse, SourceKindMCPToolResult, SourceKindMCPToolArgs:
		return true
	default:
		return false
	}
}

func validNormalizedView(view string) bool {
	switch view {
	case NormalizedViewSanitizedTarget,
		NormalizedViewForMatching,
		NormalizedViewInvisibleSpaced,
		NormalizedViewLeetspeak,
		NormalizedViewVowelFold,
		NormalizedViewBase64Decoded,
		NormalizedViewHexDecoded,
		NormalizedViewDLPNormalized:
		return true
	default:
		return strings.HasPrefix(view, normalizedViewDLPNormalizedPrefix) && len(view) > len(normalizedViewDLPNormalizedPrefix)
	}
}

func offsetsAllowedForView(view string) bool {
	return view == NormalizedViewSanitizedTarget ||
		view == NormalizedViewDLPNormalized ||
		strings.HasPrefix(view, normalizedViewDLPNormalizedPrefix)
}

func validateSHA256Digest(field, val string) error {
	const digestPrefix = "sha256:"
	if !strings.HasPrefix(val, digestPrefix) {
		return fmt.Errorf("%w: %s", ErrPayloadInvalidEnum, field)
	}
	digest := strings.TrimPrefix(val, digestPrefix)
	if len(digest) != sha256.Size*2 {
		return fmt.Errorf("%w: %s length", ErrPayloadInvalidEnum, field)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return fmt.Errorf("%w: %s hex: %w", ErrPayloadInvalidEnum, field, err)
	}
	return nil
}

func validateHMACMatchHash(val string) error {
	if !strings.HasPrefix(val, sourceSpanMatchHashPrefix) {
		return fmt.Errorf("%w: match_hash prefix", ErrPayloadInvalidEnum)
	}
	digest := strings.TrimPrefix(val, sourceSpanMatchHashPrefix)
	if len(digest) != sha256.Size*2 {
		return fmt.Errorf("%w: match_hash length", ErrPayloadInvalidEnum)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return fmt.Errorf("%w: match_hash hex: %w", ErrPayloadInvalidEnum, err)
	}
	return nil
}

// SourceSpanMatchHash computes the signer-keyed match_hash for a span. eventID
// MUST be the signed EvidenceReceipt.event_id for the receipt that will carry
// the span; verifiers reconstruct the same input from that envelope field.
// matchValue is the normalized/redacted evidence slice, or a class/placeholder
// value for secret-bearing matches. The key is not serialized into the receipt,
// which prevents offline confirmation of guessed low-entropy values.
func SourceSpanMatchHash(key []byte, eventID string, spanIndex int, span SourceSpan, matchValue string) (string, error) {
	if len(key) == 0 {
		return "", fmt.Errorf("%w: source_span_hmac_key", ErrPayloadMissingField)
	}
	if eventID == "" {
		return "", fmt.Errorf("%w: event_id", ErrPayloadMissingField)
	}
	if spanIndex < 0 {
		return "", fmt.Errorf("%w: span_index=%d", ErrPayloadInvalidEnum, spanIndex)
	}
	if matchValue == "" {
		return "", fmt.Errorf("%w: match_value", ErrPayloadMissingField)
	}
	mac := hmac.New(sha256.New, key)
	writeMACPart(mac, sourceSpanHMACDomain)
	writeMACPart(mac, eventID)
	writeMACPart(mac, strconv.Itoa(spanIndex))
	writeMACPart(mac, span.SourceKind)
	writeMACPart(mac, span.NormalizedView)
	writeMACPart(mac, span.RuleID)
	writeMACPart(mac, span.MatchClass)
	writeMACPart(mac, matchValue)
	return sourceSpanMatchHashPrefix + hex.EncodeToString(mac.Sum(nil)), nil
}

func writeMACPart(mac io.Writer, part string) {
	_, _ = mac.Write([]byte(strconv.Itoa(len(part))))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(part))
	_, _ = mac.Write([]byte{0})
}

func validateContractRatified(raw json.RawMessage) error {
	var p PayloadContractRatifiedStruct
	if err := decodeStrict(raw, &p); err != nil {
		return fmt.Errorf("%w: contract_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("contract_hash", p.ContractHash); err != nil {
		return err
	}
	if err := requireNonEmpty("ratifier_key_id", p.RatifierKeyID); err != nil {
		return err
	}
	if err := requireNonEmptySlice("ratified_rule_ids", p.RatifiedRuleIDs); err != nil {
		return err
	}
	if len(p.RatificationDecisionPerRule) == 0 {
		return fmt.Errorf("%w: ratification_decision_per_rule", ErrPayloadMissingField)
	}
	return nil
}

func validateContractPromoteIntent(raw json.RawMessage) error {
	var p PayloadContractPromoteIntentStruct
	if err := decodeStrict(raw, &p); err != nil {
		return fmt.Errorf("%w: target_manifest_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("target_manifest_hash", p.TargetManifestHash); err != nil {
		return err
	}
	if err := requireNonEmpty("prior_manifest_hash", p.PriorManifestHash); err != nil {
		return err
	}
	return requireNonEmpty("intent_id", p.IntentID)
}

func validateContractPromoteCommitted(raw json.RawMessage) error {
	var p PayloadContractPromoteCommittedStruct
	if err := decodeStrict(raw, &p); err != nil {
		return fmt.Errorf("%w: target_manifest_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("target_manifest_hash", p.TargetManifestHash); err != nil {
		return err
	}
	if err := requireNonEmpty("prior_manifest_hash", p.PriorManifestHash); err != nil {
		return err
	}
	if err := requireNonEmpty("intent_id", p.IntentID); err != nil {
		return err
	}
	if err := requireNonEmpty("validation_outcome", p.ValidationOutcome); err != nil {
		return err
	}
	if p.ValidationOutcome != outcomeAccepted && p.ValidationOutcome != outcomeRejected {
		return fmt.Errorf("%w: validation_outcome=%q (must be %q or %q)",
			ErrPayloadInvalidEnum, p.ValidationOutcome, outcomeAccepted, outcomeRejected)
	}
	if p.ValidationOutcome == outcomeRejected {
		return requireNonEmpty("reject_reason", p.RejectReason)
	}
	return nil
}

func validateContractRollbackAuthorized(raw json.RawMessage) error {
	var p PayloadContractRollbackAuthorizedStruct
	if err := decodeStrict(raw, &p); err != nil {
		return fmt.Errorf("%w: rollback_target_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("rollback_target_hash", p.RollbackTargetHash); err != nil {
		return err
	}
	if err := requireNonEmptySlice("authorizer_signatures", p.AuthorizerSignatures); err != nil {
		return err
	}
	return requireNonEmpty("authorization_id", p.AuthorizationID)
}

func validateContractRollbackCommitted(raw json.RawMessage) error {
	var p PayloadContractRollbackCommittedStruct
	if err := decodeStrict(raw, &p); err != nil {
		return fmt.Errorf("%w: rollback_target_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("rollback_target_hash", p.RollbackTargetHash); err != nil {
		return err
	}
	if err := requireNonEmpty("prior_manifest_hash", p.PriorManifestHash); err != nil {
		return err
	}
	if err := requireNonEmpty("authorization_id", p.AuthorizationID); err != nil {
		return err
	}
	if err := requireNonEmpty("validation_outcome", p.ValidationOutcome); err != nil {
		return err
	}
	if p.ValidationOutcome != outcomeAccepted && p.ValidationOutcome != outcomeRejected {
		return fmt.Errorf("%w: validation_outcome=%q (must be %q or %q)",
			ErrPayloadInvalidEnum, p.ValidationOutcome, outcomeAccepted, outcomeRejected)
	}
	if p.ValidationOutcome == outcomeRejected {
		return requireNonEmpty("reject_reason", p.RejectReason)
	}
	return nil
}

func validateContractDemoted(raw json.RawMessage) error {
	var p PayloadContractDemotedStruct
	if err := decodeStrict(raw, &p); err != nil {
		return fmt.Errorf("%w: contract_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("contract_hash", p.ContractHash); err != nil {
		return err
	}
	if err := requireNonEmpty("rule_id", p.RuleID); err != nil {
		return err
	}
	if err := requireNonEmpty("demotion_reason", p.DemotionReason); err != nil {
		return err
	}
	if err := requireNonEmpty("prior_state", p.PriorState); err != nil {
		return err
	}
	if err := requireNonEmpty("new_state", p.NewState); err != nil {
		return err
	}
	return requireNonEmpty("aggregation_window", p.AggregationWindow)
}

func validateContractExpired(raw json.RawMessage) error {
	var p PayloadContractExpiredStruct
	if err := decodeStrict(raw, &p); err != nil {
		return fmt.Errorf("%w: contract_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("contract_hash", p.ContractHash); err != nil {
		return err
	}
	if err := requireNonEmpty("rule_id", p.RuleID); err != nil {
		return err
	}
	return requireNonEmpty("expiration_reason", p.ExpirationReason)
}

func validateContractDrift(raw json.RawMessage) error {
	var p PayloadContractDriftStruct
	if err := decodeStrict(raw, &p); err != nil {
		return fmt.Errorf("%w: contract_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("contract_hash", p.ContractHash); err != nil {
		return err
	}
	if err := requireNonEmpty("rule_id", p.RuleID); err != nil {
		return err
	}
	return requireNonEmpty("drift_kind", p.DriftKind)
}

func validateShadowDelta(raw json.RawMessage) error {
	var p PayloadShadowDeltaStruct
	if err := decodeStrict(raw, &p); err != nil {
		return fmt.Errorf("%w: contract_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("contract_hash", p.ContractHash); err != nil {
		return err
	}
	if err := requireNonEmpty("rule_id", p.RuleID); err != nil {
		return err
	}
	if err := requireNonEmpty("original_verdict", p.OriginalVerdict); err != nil {
		return err
	}
	if err := requireNonEmpty("candidate_verdict", p.CandidateVerdict); err != nil {
		return err
	}
	return validateShadowDeltaAggregation(p.Aggregation)
}

func validateShadowDeltaAggregation(a ShadowDeltaAggregation) error {
	if err := requireNonEmpty("aggregation.window_start", a.WindowStart); err != nil {
		return err
	}
	if err := requireNonEmpty("aggregation.window_end", a.WindowEnd); err != nil {
		return err
	}
	start, err := time.Parse(time.RFC3339Nano, a.WindowStart)
	if err != nil {
		return fmt.Errorf("%w: aggregation.window_start", ErrPayloadInvalidEnum)
	}
	end, err := time.Parse(time.RFC3339Nano, a.WindowEnd)
	if err != nil {
		return fmt.Errorf("%w: aggregation.window_end", ErrPayloadInvalidEnum)
	}
	if !end.After(start) {
		return fmt.Errorf("%w: aggregation.window_end", ErrPayloadInvalidEnum)
	}
	if a.LosslessCount == 0 {
		return fmt.Errorf("%w: aggregation.lossless_count", ErrPayloadMissingField)
	}
	if a.DeltaSampleCount != uint64(len(a.ExemplarIDs)) {
		return fmt.Errorf("%w: aggregation.delta_sample_count", ErrPayloadInvalidEnum)
	}
	if a.DeltaSampleCount > a.LosslessCount {
		return fmt.Errorf("%w: aggregation.delta_sample_count", ErrPayloadInvalidEnum)
	}
	for i, id := range a.ExemplarIDs {
		if id == "" {
			return fmt.Errorf("%w: aggregation.exemplar_ids[%d]", ErrPayloadMissingField, i)
		}
	}
	return nil
}

func validateOpportunityMissing(raw json.RawMessage) error {
	var p PayloadOpportunityMissingStruct
	if err := decodeStrict(raw, &p); err != nil {
		return fmt.Errorf("%w: contract_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("contract_hash", p.ContractHash); err != nil {
		return err
	}
	if err := requireNonEmpty("rule_id", p.RuleID); err != nil {
		return err
	}
	if err := requireNonEmpty("parent_context", p.ParentContext); err != nil {
		return err
	}
	if err := requireNonEmpty("historical_opportunity_rate", p.HistoricalOpportunityRate); err != nil {
		return err
	}
	if err := requireNonEmpty("current_opportunity_rate", p.CurrentOpportunityRate); err != nil {
		return err
	}
	return requireNonEmpty("window", p.Window)
}

func validateKeyRotation(raw json.RawMessage) error {
	var p PayloadKeyRotationStruct
	if err := decodeStrict(raw, &p); err != nil {
		return fmt.Errorf("%w: key_id (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("key_id", p.KeyID); err != nil {
		return err
	}
	if err := requireNonEmpty("key_purpose", p.KeyPurpose); err != nil {
		return err
	}
	if err := requireNonEmpty("old_status", p.OldStatus); err != nil {
		return err
	}
	if err := requireNonEmpty("new_status", p.NewStatus); err != nil {
		return err
	}
	if err := requireNonEmpty("roster_hash", p.RosterHash); err != nil {
		return err
	}
	return requireNonEmpty("authorization_id", p.AuthorizationID)
}

func validateContractRedactionRequest(raw json.RawMessage) error {
	var p PayloadContractRedactionRequestStruct
	if err := decodeStrict(raw, &p); err != nil {
		return fmt.Errorf("%w: target_contract_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("target_contract_hash", p.TargetContractHash); err != nil {
		return err
	}
	if err := requireNonEmpty("request_kind", p.RequestKind); err != nil {
		return err
	}
	if p.RequestKind != requestKindWithdrawPublicProof && p.RequestKind != requestKindLocalErasureTombstone {
		return fmt.Errorf("%w: request_kind=%q (must be %q or %q)",
			ErrPayloadInvalidEnum, p.RequestKind,
			requestKindWithdrawPublicProof, requestKindLocalErasureTombstone)
	}
	if err := requireNonEmpty("reason_class", p.ReasonClass); err != nil {
		return err
	}
	if err := requireNonEmpty("authorization_id", p.AuthorizationID); err != nil {
		return err
	}
	return requireNonEmpty("tombstone_hash", p.TombstoneHash)
}
