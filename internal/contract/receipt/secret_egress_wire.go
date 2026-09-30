// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

// ParseEvidenceReceipt parses serialized v2 receipts at the authoritative raw
// ingress boundary. The new secret-egress kind gets its wire-profile check
// before the unchanged strict decoder binds fields. Other payload kinds retain
// existing strict decoding behavior. Signature verification remains separate.
//
// Generic json.Unmarshal/contract.DecodeStrictJSON are parsing operations, not
// substitutes for this profile boundary. Typed verification cannot reconstruct
// original field spelling, presence or numeric tokens discarded by a caller.
func ParseEvidenceReceipt(raw []byte) (EvidenceReceipt, error) {
	if isSecretEgressWire(raw) {
		if err := validateSecretEgressWire(raw); err != nil {
			return EvidenceReceipt{}, err
		}
	}
	var r EvidenceReceipt
	if err := contract.DecodeStrictJSON(raw, &r); err != nil {
		return EvidenceReceipt{}, err
	}
	return r, nil
}

// Inspect every root selector, including duplicate and case-alias selectors.
// A malformed value still goes through the normal decoder and fails there.
func isSecretEgressWire(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		name, ok := token.(string)
		if !ok {
			return false
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false
		}
		if strings.EqualFold(name, "crit") {
			var features []string
			if json.Unmarshal(value, &features) == nil && slices.Contains(features, CritSecretEgressDecisionV1) {
				return true
			}
		}
		if strings.EqualFold(name, "payload_kind") {
			var kind string
			if json.Unmarshal(value, &kind) == nil && kind == string(PayloadSecretEgressDecisionV1) {
				return true
			}
		}
	}
	return false
}

func validateSecretEgressWire(raw []byte) error {
	required := []string{
		"record_type", "receipt_version", "payload_kind", "canonicalization", "crit",
		"event_id", "timestamp", "signature", "chain_seq", "chain_prev_hash", "policy_hash", "payload",
	}
	optionalStrings := []string{"principal", "actor", "active_manifest_hash", "contract_hash", "selector_id"}
	optional := append(append([]string(nil), optionalStrings...), "delegation_chain", "contract_generation")
	fields, err := secretEgressWireObject(raw, required, optional)
	if err != nil {
		return err
	}
	if err := rejectSecretEgressWireNulls(raw); err != nil {
		return err
	}
	for _, key := range append([]string{"record_type", "payload_kind", "event_id", "timestamp", "chain_prev_hash", "policy_hash"}, optionalStrings...) {
		if value, ok := fields[key]; ok {
			if _, err := secretEgressWireString(value, key); err != nil {
				return err
			}
		}
	}
	if err := secretEgressWireTimestamp(fields["timestamp"]); err != nil {
		return err
	}
	if string(bytes.TrimSpace(fields["receipt_version"])) != "2" {
		return fmt.Errorf("secret egress receipt_version must be integer token 2")
	}
	if err := secretEgressWireInteger(fields["chain_seq"], "chain_seq", 0); err != nil {
		return err
	}
	if value, ok := fields["contract_generation"]; ok {
		if err := secretEgressWireInteger(value, "contract_generation", 1); err != nil {
			return err
		}
	}
	if value, ok := fields["delegation_chain"]; ok {
		if _, err := secretEgressWireStrings(value, "delegation_chain"); err != nil {
			return err
		}
	}
	crit, err := secretEgressWireStrings(fields["crit"], "crit")
	if err != nil {
		return err
	}
	if len(crit) != 2 || !slices.Contains(crit, CritCanonicalization) || !slices.Contains(crit, CritSecretEgressDecisionV1) {
		return fmt.Errorf("secret egress crit must name exactly its two critical features")
	}
	if err := secretEgressWireStringObject(fields["canonicalization"], []string{
		"jcs_profile", "jcs_version", "hash_alg", "sig_alg", "redaction_ruleset_id", "redaction_ruleset_version", "redaction_ruleset_hash",
	}); err != nil {
		return err
	}
	if err := secretEgressWireSignature(fields["signature"]); err != nil {
		return err
	}
	_, err = parseSecretEgressDecisionPayload(fields["payload"])
	return err
}

func secretEgressWireObject(raw []byte, required, optional []string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := contract.DecodeStrictJSON(raw, &fields); err != nil {
		return nil, fmt.Errorf("secret egress wire object: %w", err)
	}
	for key := range fields {
		if !slices.Contains(required, key) && !slices.Contains(optional, key) {
			return nil, fmt.Errorf("secret egress wire contains unknown field %q", key)
		}
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return nil, fmt.Errorf("secret egress wire missing field %q", key)
		}
	}
	return fields, nil
}

func secretEgressWireString(raw []byte, key string) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return "", fmt.Errorf("secret egress wire %s must be a nonempty string", key)
	}
	return value, nil
}

func secretEgressWireStrings(raw []byte, key string) ([]string, error) {
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || len(values) == 0 {
		return nil, fmt.Errorf("secret egress wire %s must be a nonempty string array", key)
	}
	strings := make([]string, 0, len(values))
	for _, value := range values {
		s, err := secretEgressWireString(value, key)
		if err != nil {
			return nil, err
		}
		strings = append(strings, s)
	}
	return strings, nil
}

func secretEgressWireStringObject(raw []byte, required []string) error {
	fields, err := secretEgressWireObject(raw, required, nil)
	if err != nil {
		return err
	}
	for key, value := range fields {
		if _, err := secretEgressWireString(value, key); err != nil {
			return err
		}
	}
	return nil
}

func secretEgressWireInteger(raw []byte, key string, minimum uint64) error {
	value := bytes.TrimSpace(raw)
	if len(value) == 0 || len(value) > 1 && value[0] == '0' {
		return fmt.Errorf("secret egress wire %s must use decimal integer spelling", key)
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return fmt.Errorf("secret egress wire %s must use decimal integer spelling", key)
		}
	}
	parsed, err := strconv.ParseUint(string(value), 10, 64)
	const maxSafeInteger = 9007199254740991
	if err != nil || parsed < minimum || parsed > maxSafeInteger {
		return fmt.Errorf("secret egress wire %s is outside the safe integer range", key)
	}
	return nil
}

func rejectSecretEgressWireNulls(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil || token == nil {
			return fmt.Errorf("secret egress wire contains null or malformed JSON")
		}
	}
}

// The candidate new-kind profile requires the unescaped ASCII UTC JSON token
// emitted by time.Time.MarshalJSON. This local profile restriction avoids
// cross-language time binding differences; it is not a general RFC3339 rule.
func secretEgressWireTimestamp(raw []byte) error {
	value, err := secretEgressWireString(raw, "timestamp")
	if err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || !strings.HasSuffix(value, "Z") {
		return fmt.Errorf("secret egress timestamp must be canonical nonzero UTC RFC3339Nano")
	}
	canonical, err := parsed.MarshalJSON()
	if err != nil {
		return fmt.Errorf("secret egress timestamp is not representable: %w", err)
	}
	if !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return fmt.Errorf("secret egress timestamp must use the unescaped ASCII canonical UTC token")
	}
	return nil
}

// ValidateSecretEgressContext checks typed scalar context shared by the new
// fixture builder and verifier. It does not verify a signature or payload.
func (r EvidenceReceipt) ValidateSecretEgressContext() error {
	const maxSafeInteger = 9007199254740991
	if r.ChainSeq > maxSafeInteger || r.ContractGeneration > maxSafeInteger {
		return fmt.Errorf("secret egress envelope integer exceeds the safe range")
	}
	_, offset := r.Timestamp.Zone()
	if offset != 0 || r.Timestamp.Year() < 0 || r.Timestamp.Year() > 9999 {
		return fmt.Errorf("secret egress timestamp must emit canonical UTC RFC3339Nano")
	}
	for _, delegate := range r.DelegationChain {
		if delegate == "" {
			return fmt.Errorf("secret egress delegation_chain entries must be nonempty strings")
		}
	}
	return nil
}

// validateSecretEgressSignature fixes the new kind's signature-value spelling.
// This is a candidate profile constraint, not a change to legacy receipt kinds
// or the Ed25519 signing recipe. No whitespace or case normalization occurs.
func validateSecretEgressSignature(value string) error {
	if len(value) != len(signaturePrefixEd25519)+ed25519.SignatureSize*2 || !strings.HasPrefix(value, signaturePrefixEd25519) {
		return fmt.Errorf("%w: signature.signature requires ed25519:<128 lowercase ASCII hex>", ErrPayloadInvalidEnum)
	}
	for _, c := range []byte(value[len(signaturePrefixEd25519):]) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("%w: signature.signature must use lowercase ASCII hex", ErrPayloadInvalidEnum)
		}
	}
	return nil
}

func secretEgressWireSignature(raw []byte) error {
	fields, err := secretEgressWireObject(raw, []string{"signer_key_id", "key_purpose", "algorithm", "signature"}, nil)
	if err != nil {
		return err
	}
	for key, rawValue := range fields {
		value, err := secretEgressWireString(rawValue, key)
		if err != nil {
			return err
		}
		if key == "signature" {
			if err := validateSecretEgressSignature(value); err != nil {
				return err
			}
		}
	}
	return nil
}
