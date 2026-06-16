// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// EnvLicenseKey is the env variable carrying the signed license token. The
// conductor / fleet-sink server commands resolve their license from this
// because they do not take a config file flag; the follower runtime resolves
// the token from `cfg.LicenseKey` first and falls back to this env variable.
const EnvLicenseKey = "PIPELOCK_LICENSE_KEY"

// EnvLicensePublicKey is the optional env override for the verifier public key.
// It accepts either a raw 64-character hex Ed25519 key or the versioned
// "pipelock-ed25519-public-v1\n<base64>" format written to license.pub, so a
// self-hosted issuer can point it straight at the generated file. Official
// builds embed the production key at build time; this env variable is for
// development and self-hosted issuance.
const EnvLicensePublicKey = "PIPELOCK_LICENSE_PUBLIC_KEY"

// EnvLicenseCRLFile is the optional env variable pointing to a signed license
// revocation list. Server commands that do not take a full config file can use
// this to fail closed on revoked licenses.
const EnvLicenseCRLFile = "PIPELOCK_LICENSE_CRL_FILE"

// EnvLicenseIntermediateFile points to a root-signed intermediate
// license-signing certificate. When set, fleet verification uses the
// token->intermediate->root chain and fails closed if the certificate is bad.
const EnvLicenseIntermediateFile = "PIPELOCK_LICENSE_INTERMEDIATE_FILE"

// ErrFleetLicenseRequired is returned by RequireFleet when the supplied
// license does not carry the fleet feature (or no license is present).
// Callers should refuse to start fleet work and surface this error verbatim
// so the operator sees the missing-entitlement message.
var ErrFleetLicenseRequired = errors.New(
	"fleet control plane (Conductor) requires an Enterprise license " +
		"that grants the \"fleet\" feature; set PIPELOCK_LICENSE_KEY (and " +
		"PIPELOCK_LICENSE_PUBLIC_KEY on unofficial builds) or contact your " +
		"administrator",
)

// RequireFleet verifies the supplied license and returns nil only when it
// carries the FeatureFleet entitlement. Pass licenseKey="" and publicKeyHex=""
// to use the environment variables + the build-embedded public key.
//
// The function is intentionally narrow and fail-closed: any failure mode -
// missing token, missing verifier key, expired/invalid signature, missing
// feature - returns a wrapped ErrFleetLicenseRequired so call sites can keep
// the error path uniform without branching on individual failure reasons.
//
// Callers (`pipelock conductor serve`, `pipelock fleet-sink`, and the
// `pipelock run` follower runtime when `conductor.enabled: true`) invoke this
// before doing any fleet work and abort fail-closed on a non-nil error.
func RequireFleet(licenseKey, publicKeyHex string) error {
	_, err := VerifyFleet(licenseKey, publicKeyHex, "")
	return err
}

// VerifyFleet verifies the supplied license token and returns the decoded
// license only when it carries the FeatureFleet entitlement. The optional
// crlFile argument, or PIPELOCK_LICENSE_CRL_FILE when empty, enables fail-closed
// revocation checks with a signed CRL.
func VerifyFleet(licenseKey, publicKeyHex, crlFile string) (License, error) {
	return VerifyFleetWithIntermediate(licenseKey, publicKeyHex, crlFile, "")
}

// errNoLicenseToken and errNoVerifierKey are the unverifiable-input causes that
// verifyLicenseInputsOpts returns before any token verification can run. They are
// unexported because callers classify by behavior (any non-revoked/non-expired
// failure is "unverifiable"), not by these specific identities; VerifyFleet*
// wraps them in ErrFleetLicenseRequired for the operator-facing message.
var (
	errNoLicenseToken = errors.New("no license token provided")
	errNoVerifierKey  = errors.New("no verifier public key available " +
		"(build-embedded key missing and PIPELOCK_LICENSE_PUBLIC_KEY unset, " +
		"empty, or unparseable; accepts 64-char raw hex or the versioned " +
		"\"pipelock-ed25519-public-v1\\n<base64>\" license.pub format)")
)

// FleetVerifyInputs groups the license-resolution inputs shared by the fleet
// gate, the reload classifier, and the env-only conductor/fleet CLI commands.
// It is an options struct (per the options-struct rule) so require-intermediate
// — and any future verify knob — threads through without growing the positional
// signatures of VerifyFleet / ClassifyReload.
//
// All string fields are "" = fall back to the matching env var. RequireSet
// distinguishes "config did not specify" (consult env) from "config explicitly
// set Require to false/true".
type FleetVerifyInputs struct {
	LicenseKey       string
	PublicKeyHex     string
	CRLFile          string
	IntermediateFile string
	IntermediateCert []byte // already-loaded cert bytes (config path); wins over IntermediateFile
	RequireSet       bool
	Require          bool
	// MaxAge is the configured CRL freshness window (license_crl_max_age). Zero
	// falls back to DefaultCRLMaxAge.
	MaxAge time.Duration
}

// verifyLicenseInputsOpts resolves the verifier public key, builds the
// fail-closed VerifyOptions (CRL + intermediate + require-mode) via the single
// resolver, and verifies the token. It performs NO feature check. The fleet
// gate and the reload classifier share this so they never drift on key
// resolution, env fallback, CRL freshness, or require semantics. The returned
// error preserves ErrLicenseRevoked / ErrLicenseExpired / ErrIntermediateRevoked
// / ErrIntermediateRequired in its chain so callers can classify the outcome.
func verifyLicenseInputsOpts(in FleetVerifyInputs) (License, error) {
	licenseKey := in.LicenseKey
	if licenseKey == "" {
		licenseKey = os.Getenv(EnvLicenseKey)
	}
	if licenseKey == "" {
		return License{}, errNoLicenseToken
	}
	pubKey := EmbeddedPublicKey()
	if pubKey == nil {
		publicKey := in.PublicKeyHex
		if publicKey == "" {
			publicKey = os.Getenv(EnvLicensePublicKey)
		}
		if publicKey != "" {
			// signing.ParsePublicKey accepts BOTH the durable versioned
			// "pipelock-ed25519-public-v1\n<base64>" form written by the signing
			// CLI to license.pub AND a raw 64-hex Ed25519 key. It rejects
			// malformed, short, or otherwise garbage keys, so the verifier still
			// fails closed below when the override is unparseable.
			parsed, parseErr := signing.ParsePublicKey(publicKey)
			if parseErr == nil && len(parsed) == ed25519.PublicKeySize {
				pubKey = parsed
			}
		}
	}
	if pubKey == nil {
		return License{}, errNoVerifierKey
	}
	opts, err := ResolveVerifyOptions(ResolveInputs{
		RootPub:          pubKey,
		CRLFile:          in.CRLFile,
		IntermediateCert: in.IntermediateCert,
		IntermediateFile: in.IntermediateFile,
		RequireSet:       in.RequireSet,
		Require:          in.Require,
		MaxAge:           in.MaxAge,
	})
	if err != nil {
		return License{}, err
	}
	return VerifyTokenWithOptions(licenseKey, opts)
}

// VerifyFleetWithIntermediate verifies the supplied fleet license, optionally
// using a configured intermediate certificate file. Empty intermediateFile
// falls back to PIPELOCK_LICENSE_INTERMEDIATE_FILE, then legacy direct-root
// verification if neither is set. Require-intermediate mode is OFF on this
// legacy entry point; use VerifyFleetWithOptions to honour it.
func VerifyFleetWithIntermediate(licenseKey, publicKeyHex, crlFile, intermediateFile string) (License, error) {
	return VerifyFleetWithOptions(FleetVerifyInputs{
		LicenseKey:       licenseKey,
		PublicKeyHex:     publicKeyHex,
		CRLFile:          crlFile,
		IntermediateFile: intermediateFile,
	})
}

// VerifyFleetWithOptions verifies a fleet license honouring require-intermediate
// mode (and any other VerifyOptions knob) resolved from in. It returns the
// decoded license only when it carries FeatureFleet, failing closed (wrapped in
// ErrFleetLicenseRequired) on any verification failure including
// ErrIntermediateRequired. This is the entry point the env-only conductor / fleet
// CLI commands use so require mode is honoured there, not just in the runtime.
func VerifyFleetWithOptions(in FleetVerifyInputs) (License, error) {
	lic, err := verifyLicenseInputsOpts(in)
	if err != nil {
		return License{}, fmt.Errorf("%w: %w", ErrFleetLicenseRequired, err)
	}
	if !lic.HasFeature(FeatureFleet) {
		return License{}, fmt.Errorf("%w: license %s does not include the fleet feature "+
			"(present features: %v)",
			ErrFleetLicenseRequired, lic.ID, lic.Features)
	}
	return lic, nil
}
