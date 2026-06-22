// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import "errors"

// ReloadClass classifies a license re-verification performed during a hot
// config reload, so the paid-surface gates (agent listeners, the Conductor
// follower) can distinguish PROVEN entitlement loss from an UNVERIFIABLE new
// input.
//
// License inputs are restart-only: a reload never activates a new license, it
// preserves the old verified entitlement and warns. So an unreadable or
// malformed NEW input (a fat-fingered crl_file path, a corrupt intermediate, a
// bad-signature token) does not change the effective entitlement and must NOT
// tear down a running paid surface — tearing down there is a denial-of-service
// on an operator typo, not fail-closed security. Only a NEW input that PROVES
// the entitlement is gone (revoked, expired, or a cleanly-verified token that
// no longer carries the feature) tears the surface down. Genuine runtime
// revocation/expiry of the ACTIVE license is still enforced independently by
// the CRL watcher and the expiry timer, against the effective license state.
type ReloadClass int

const (
	// ReloadUnverifiable: the new license inputs could not be verified at all
	// (no token, no verifier key, unreadable/malformed CRL or intermediate, or
	// an invalid signature). The effective (restart-only) entitlement is
	// unchanged — preserve the running surface and warn loudly.
	ReloadUnverifiable ReloadClass = iota
	// ReloadRevoked: the token verified but a loaded CRL revokes it. Proven
	// loss — tear the surface down fail-closed.
	ReloadRevoked
	// ReloadExpired: the token verified but is past its expiry. Proven loss.
	ReloadExpired
	// ReloadVerified: the token verified cleanly. The caller must still check
	// HasFeature on the returned License: a verified token that no longer
	// carries the surface's feature is a genuine downgrade (proven loss); a
	// verified token that still carries it means no loss at all.
	ReloadVerified
)

// ClassifyReload verifies the supplied license inputs the same way the fleet
// gate does (shared verifyLicenseInputs core: identical key resolution, env
// fallback, and CRL/intermediate loading) but classifies the outcome for a
// hot-reload teardown decision instead of checking a specific feature. On
// ReloadVerified it returns the decoded License so the caller can apply its own
// HasFeature test; otherwise the returned License is zero. Require-intermediate
// mode is OFF on this legacy entry point; use ClassifyReloadWithOptions to
// honour it.
func ClassifyReload(licenseKey, publicKeyHex, crlFile, intermediateFile string) (License, ReloadClass) {
	return ClassifyReloadWithOptions(FleetVerifyInputs{
		LicenseKey:       licenseKey,
		PublicKeyHex:     publicKeyHex,
		CRLFile:          crlFile,
		IntermediateFile: intermediateFile,
	})
}

// ClassifyReloadWithOptions classifies a reload re-verification honouring
// require-intermediate mode. A revoked intermediate or an unsatisfied
// require-intermediate (ErrIntermediateRevoked / ErrIntermediateRequired) is
// PROVEN loss on reload — the running surface must tear down — because the new
// inputs prove the active entitlement can no longer be validated through the
// required trust tier. (A configured-but-malformed intermediate stays
// ReloadUnverifiable: an operator typo must not DoS a running paid surface.)
func ClassifyReloadWithOptions(in FleetVerifyInputs) (License, ReloadClass) {
	lic, err := verifyLicenseInputsOpts(in)
	switch {
	case err == nil:
		return lic, ReloadVerified
	case errors.Is(err, ErrLicenseRevoked), errors.Is(err, ErrIntermediateRevoked):
		return License{}, ReloadRevoked
	case errors.Is(err, ErrLicenseExpired):
		return License{}, ReloadExpired
	case errors.Is(err, ErrIntermediateRequired), errors.Is(err, ErrCRLRequired):
		// require-intermediate is on but the active inputs no longer satisfy it
		// (no/empty intermediate under require, or no CRL floor). This is proven
		// loss of the verifiable entitlement, not an unreadable typo, so tear
		// down fail-closed. Classified as Revoked (the strongest proven-loss
		// class) since ProvesLoss treats Revoked/Expired identically.
		return License{}, ReloadRevoked
	default:
		return License{}, ReloadUnverifiable
	}
}

// ProvesLoss reports whether a reload classification (paired with the verified
// license, when ReloadVerified) proves the named feature entitlement was lost
// and the surface must be torn down. ReloadUnverifiable always returns false:
// an input that cannot be verified cannot prove loss. This is the single
// decision both gates (agents + Conductor) consult, so they stay in lockstep.
func (c ReloadClass) ProvesLoss(lic License, feature string) bool {
	switch c {
	case ReloadRevoked, ReloadExpired:
		return true
	case ReloadVerified:
		return !lic.HasFeature(feature)
	default: // ReloadUnverifiable
		return false
	}
}
