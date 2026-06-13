// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

// KeyPurpose is the typed form of the wire-string key_purpose attribute on
// every signed-artifact key entry. The wire form is the lowercase hyphenated
// string representation; this typed wrapper centralises validation and helpers.
//
// Thirteen values are defined, drawn from the design doc Key Management section
// (lines 758-870) and the Conductor control-plane spec:
//
//   - PurposeReceiptSigning:            runtime receipt keys (hot-loadable)
//   - PurposeContractCompileSigning:    compile-time contract keys (warm, operator-only)
//   - PurposeContractActivationSigning: activation/promotion authority keys
//   - PurposeRulesOfficialSigning:      official rules package signing keys
//   - PurposeRosterRoot:                deployment-local trust root for key rosters
//   - PurposeRecoveryRoot:              deployment-local trust root for recovery operations
//   - PurposePolicyBundleSigning:       Conductor policy bundle signing keys
//   - PurposePolicyBundleRollback:      Conductor rollback authorization keys
//   - PurposeRemoteKillSigning:         Conductor remote kill-switch keys
//   - PurposeTrustRootRotation:         Conductor trust-root rotation keys
//   - PurposeAuditBatchSigning:         follower audit batch signing keys
//   - PurposeEnrollmentTokenSigning:    Conductor enrollment-token signing keys
//   - PurposeFleetReportSigning:        Fleet Receipt Report signing keys
//
// Wire stability: these strings are part of the signed-artifact wire format
// and will not change without a schema_version bump.
//
// Why this lives in signing, not contract: the contract package owns the
// payload-kind authority matrix; the signing package owns deployment-side key
// handling. Both reference the same wire strings.
type KeyPurpose string

const (
	// PurposeReceiptSigning identifies keys used to sign runtime receipts
	// (proxy_decision, contract lifecycle events, shadow deltas, etc.).
	PurposeReceiptSigning KeyPurpose = "receipt-signing"

	// PurposeContractCompileSigning identifies keys used to sign compiled
	// contract artifacts. These are warm/operator-only keys, not hot-loaded.
	PurposeContractCompileSigning KeyPurpose = "contract-compile-signing"

	// PurposeContractActivationSigning identifies keys used to authorise
	// contract promotion, rollback, key rotation, and redaction requests.
	PurposeContractActivationSigning KeyPurpose = "contract-activation-signing"

	// PurposeRulesOfficialSigning identifies keys used to sign official
	// rules packages distributed by the project.
	PurposeRulesOfficialSigning KeyPurpose = "rules-official-signing"

	// PurposeRosterRoot identifies the deployment-local trust root key
	// that signs the key roster itself.
	PurposeRosterRoot KeyPurpose = "roster-root"

	// PurposeRecoveryRoot identifies the deployment-local trust root key
	// used for recovery operations (root transition, emergency rotation).
	PurposeRecoveryRoot KeyPurpose = "recovery-root"

	// PurposePolicyBundleSigning identifies keys used to sign Conductor
	// policy bundles distributed to followers.
	PurposePolicyBundleSigning KeyPurpose = "policy-bundle-signing"

	// PurposePolicyBundleRollback identifies keys used to authorize a one-shot
	// rollback to a lower Conductor policy bundle version.
	PurposePolicyBundleRollback KeyPurpose = "policy-bundle-rollback"

	// PurposeRemoteKillSigning identifies keys used to sign Conductor
	// remote kill-switch state messages.
	PurposeRemoteKillSigning KeyPurpose = "remote-kill-signing"

	// PurposeTrustRootRotation identifies keys used to sign Conductor
	// trust-root rotation artifacts.
	PurposeTrustRootRotation KeyPurpose = "trust-root-rotation"

	// PurposeAuditBatchSigning identifies follower instance keys used to sign
	// Conductor-bound audit batch envelopes.
	PurposeAuditBatchSigning KeyPurpose = "audit-batch-signing"

	// PurposeEnrollmentTokenSigning identifies Conductor keys used to sign narrow,
	// one-shot enrollment tokens.
	PurposeEnrollmentTokenSigning KeyPurpose = "enrollment-token-signing"

	// PurposeFleetReportSigning identifies keys used to sign Fleet Receipt
	// Reports. Verification is Apache/free; minting is Enterprise-gated.
	PurposeFleetReportSigning KeyPurpose = "fleet-report-signing"
)

// ErrUnknownKeyPurpose indicates a key_purpose value is not one of the
// recognised purposes.
var ErrUnknownKeyPurpose = errors.New("unknown key_purpose")

// knownPurposes is the canonical ordered list. KnownPurposes returns a copy.
var knownPurposes = [...]KeyPurpose{
	PurposeReceiptSigning,
	PurposeContractCompileSigning,
	PurposeContractActivationSigning,
	PurposeRulesOfficialSigning,
	PurposeRosterRoot,
	PurposeRecoveryRoot,
	PurposePolicyBundleSigning,
	PurposePolicyBundleRollback,
	PurposeRemoteKillSigning,
	PurposeTrustRootRotation,
	PurposeAuditBatchSigning,
	PurposeEnrollmentTokenSigning,
	PurposeFleetReportSigning,
}

// knownSet provides O(1) validation lookup.
var knownSet = func() map[KeyPurpose]struct{} {
	m := make(map[KeyPurpose]struct{}, len(knownPurposes))
	for _, p := range knownPurposes {
		m[p] = struct{}{}
	}
	return m
}()

// String returns the wire-format string of the key purpose. Satisfies
// fmt.Stringer.
func (p KeyPurpose) String() string {
	return string(p)
}

// Validate returns nil if p is one of the known purposes. Otherwise it
// returns an error wrapping ErrUnknownKeyPurpose with the offending value.
func (p KeyPurpose) Validate() error {
	if _, ok := knownSet[p]; ok {
		return nil
	}
	return fmt.Errorf("%w: %q", ErrUnknownKeyPurpose, string(p))
}

// IsRoot returns true for the two deployment-local trust root purposes:
// PurposeRosterRoot and PurposeRecoveryRoot.
func (p KeyPurpose) IsRoot() bool {
	return p == PurposeRosterRoot || p == PurposeRecoveryRoot
}

// IsActivationAuthority returns true for PurposeContractActivationSigning.
// Used by future dual-control logic to identify keys that can authorise
// contract promotion, rollback, rotation, and redaction.
func (p KeyPurpose) IsActivationAuthority() bool {
	return p == PurposeContractActivationSigning
}

// IsRuntimeReceipt returns true for PurposeReceiptSigning. Used to gate
// hot-loaded keys that sign runtime proxy decisions and lifecycle events.
func (p KeyPurpose) IsRuntimeReceipt() bool {
	return p == PurposeReceiptSigning
}

// IsCompileTime returns true for PurposeContractCompileSigning. Used to gate
// warm/operator-only keys that sign compiled contract artifacts.
func (p KeyPurpose) IsCompileTime() bool {
	return p == PurposeContractCompileSigning
}

// IsConductorPurpose returns true for Conductor control-plane purposes.
func (p KeyPurpose) IsConductorPurpose() bool {
	switch p {
	case PurposePolicyBundleSigning,
		PurposePolicyBundleRollback,
		PurposeRemoteKillSigning,
		PurposeTrustRootRotation,
		PurposeAuditBatchSigning,
		PurposeEnrollmentTokenSigning,
		PurposeFleetReportSigning:
		return true
	default:
		return false
	}
}

// RequiresConductorThreshold returns true for Conductor actions that are
// catastrophic enough to require multi-approver signing policy.
func (p KeyPurpose) RequiresConductorThreshold() bool {
	switch p {
	case PurposePolicyBundleRollback, PurposeRemoteKillSigning, PurposeTrustRootRotation:
		return true
	default:
		return false
	}
}

// KnownPurposes returns a freshly-allocated slice of all recognised key
// purposes in stable order:
//
//  1. PurposeReceiptSigning
//  2. PurposeContractCompileSigning
//  3. PurposeContractActivationSigning
//  4. PurposeRulesOfficialSigning
//  5. PurposeRosterRoot
//  6. PurposeRecoveryRoot
//  7. PurposePolicyBundleSigning
//  8. PurposePolicyBundleRollback
//  9. PurposeRemoteKillSigning
//  10. PurposeTrustRootRotation
//  11. PurposeAuditBatchSigning
//  12. PurposeEnrollmentTokenSigning
//  13. PurposeFleetReportSigning
//
// Tests rely on this order; it will not change without a major version bump.
func KnownPurposes() []KeyPurpose {
	out := make([]KeyPurpose, len(knownPurposes))
	copy(out, knownPurposes[:])
	return out
}

// AuthorizePayload checks that signedWith is the required key purpose for the
// given payloadKind according to the EvidenceReceipt v2 authority matrix in
// contract.AuthorizeKeyPurpose. Returns nil on success. On failure, the
// returned error preserves errors.Is compatibility with
// contract.ErrWrongKeyPurpose and contract.ErrUnknownPayloadKind.
func AuthorizePayload(payloadKind string, signedWith KeyPurpose) error {
	return contract.AuthorizeKeyPurpose(payloadKind, signedWith.String())
}
