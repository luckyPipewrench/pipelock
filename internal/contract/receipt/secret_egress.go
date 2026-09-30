// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/egressevidence"
)

// PayloadSecretEgressDecisionV1Struct carries a registry commitment and a
// strictly typed decision. It is fixture-only: signature and shape validation
// do not establish registry membership, policy-reference resolution, producer
// coverage, receipt durability, or permission to release bytes.
// Field order is part of the emitted-byte profile, independently of JCS signing.
type PayloadSecretEgressDecisionV1Struct struct {
	RegistryHash string                  `json:"registry_hash"`
	Decision     egressevidence.Decision `json:"decision"`
}

func validateSecretEgressDecision(raw json.RawMessage) error {
	_, err := parseSecretEgressDecisionPayload(raw)
	return err
}

func parseSecretEgressDecisionPayload(raw json.RawMessage) (PayloadSecretEgressDecisionV1Struct, error) {
	var fields map[string]json.RawMessage
	if err := decodeStrict(raw, &fields); err != nil {
		return PayloadSecretEgressDecisionV1Struct{}, fmt.Errorf("secret egress payload: %w", err)
	}
	// encoding/json accepts case-folded struct fields. Check exact wire names
	// before binding so this new kind cannot silently discard a spelling.
	if len(fields) != 2 || fields["registry_hash"] == nil || fields["decision"] == nil {
		return PayloadSecretEgressDecisionV1Struct{}, fmt.Errorf("secret egress payload requires exactly registry_hash and decision")
	}
	var registryHash string
	if err := json.Unmarshal(fields["registry_hash"], &registryHash); err != nil {
		return PayloadSecretEgressDecisionV1Struct{}, fmt.Errorf("secret egress registry_hash: %w", err)
	}
	if err := requirePolicyHash("registry_hash", registryHash); err != nil {
		return PayloadSecretEgressDecisionV1Struct{}, err
	}
	decision, err := egressevidence.ParseDecision(fields["decision"])
	if err != nil {
		return PayloadSecretEgressDecisionV1Struct{}, fmt.Errorf("secret egress decision: %w", err)
	}
	return PayloadSecretEgressDecisionV1Struct{RegistryHash: registryHash, Decision: decision}, nil
}
