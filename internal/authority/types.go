// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package authority defines the provider-neutral boundary for verifying an
// externally issued action authorization. It does not participate in the live
// allow path yet.
package authority

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Decision is the closed outcome set returned by every Verifier. Its zero
// value is deliberately Indeterminate so an omitted decision cannot allow an
// action.
type Decision uint8

const (
	DecisionIndeterminate Decision = iota
	DecisionAllow
	DecisionDeny
)

// String returns the stable wire name for d.
func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionDeny:
		return "deny"
	case DecisionIndeterminate:
		return "indeterminate"
	default:
		return "invalid"
	}
}

// Valid reports whether d is a member of the closed decision set.
func (d Decision) Valid() bool {
	return d <= DecisionDeny
}

// MarshalJSON encodes decisions by their stable wire names.
func (d Decision) MarshalJSON() ([]byte, error) {
	if !d.Valid() {
		return nil, fmt.Errorf("invalid authority decision %d", d)
	}
	return json.Marshal(d.String())
}

// UnmarshalJSON accepts only members of the closed decision set.
func (d *Decision) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode authority decision: %w", err)
	}
	switch value {
	case "allow":
		*d = DecisionAllow
	case "deny":
		*d = DecisionDeny
	case "indeterminate":
		*d = DecisionIndeterminate
	default:
		return fmt.Errorf("unknown authority decision %q", value)
	}
	return nil
}

// Reason is a stable, machine-readable explanation for a verification result.
// Providers may define additional reasons while preserving the closed Decision
// semantics.
type Reason string

const (
	ReasonMatched             Reason = "matched"
	ReasonActorMismatch       Reason = "actor_mismatch"
	ReasonActionMismatch      Reason = "action_mismatch"
	ReasonDestinationMismatch Reason = "destination_mismatch"
	ReasonExpired             Reason = "expired"
	ReasonRevoked             Reason = "revoked"
	ReasonMalformedReference  Reason = "malformed_reference"
	ReasonUntrustedIssuer     Reason = "untrusted_issuer"
	ReasonInvalidSignature    Reason = "invalid_signature"
	ReasonTimeout             Reason = "timeout"
	ReasonCanceled            Reason = "canceled"
)

// Request contains the already-normalized action description and the opaque
// reference to verify. Constructing or normalizing these fields is deliberately
// outside this first, unwired slice.
type Request struct {
	Actor        string `json:"actor"`
	Action       string `json:"action"`
	Destination  string `json:"destination"`
	AuthorityRef string `json:"authority_ref"`
}

// Result reports the provider-neutral verification outcome. Issuer, Reference,
// and ExpiresAt are populated only after the reference signature is verified.
type Result struct {
	Decision  Decision  `json:"decision"`
	Issuer    string    `json:"issuer,omitempty"`
	Reference string    `json:"reference,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Reason    Reason    `json:"reason"`
}

// Verifier checks whether an opaque external authority reference authorizes
// the exact normalized action in req.
//
// A verifier is one conjunctive gate. An allow result must never override any
// scanner, policy, contract, taint, kill-switch, or operator decision, and must
// not raise Pipelock's internal authority level.
type Verifier interface {
	Verify(context.Context, Request) Result
}
