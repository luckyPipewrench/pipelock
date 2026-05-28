// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"
)

// EnvLicenseKey is the env variable carrying the signed license token. The
// conductor / fleet-sink server commands resolve their license from this
// because they do not take a config file flag; the follower runtime resolves
// the token from `cfg.LicenseKey` first and falls back to this env variable.
const EnvLicenseKey = "PIPELOCK_LICENSE_KEY"

// EnvLicensePublicKey is the optional env override for the verifier public key
// in hex. Official builds embed the production key at build time; this env
// variable is for development and self-hosted issuance.
const EnvLicensePublicKey = "PIPELOCK_LICENSE_PUBLIC_KEY"

// EnvLicenseCRLFile is the optional env variable pointing to a signed license
// revocation list. Server commands that do not take a full config file can use
// this to fail closed on revoked licenses.
const EnvLicenseCRLFile = "PIPELOCK_LICENSE_CRL_FILE"

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
// The function is intentionally narrow and fail-closed: any failure mode —
// missing token, missing verifier key, expired/invalid signature, missing
// feature — returns a wrapped ErrFleetLicenseRequired so call sites can keep
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
	if licenseKey == "" {
		licenseKey = os.Getenv(EnvLicenseKey)
	}
	if licenseKey == "" {
		return License{}, ErrFleetLicenseRequired
	}
	pubKey := EmbeddedPublicKey()
	if pubKey == nil {
		if publicKeyHex == "" {
			publicKeyHex = os.Getenv(EnvLicensePublicKey)
		}
		if publicKeyHex != "" {
			keyBytes, decErr := hex.DecodeString(publicKeyHex)
			if decErr == nil && len(keyBytes) == ed25519.PublicKeySize {
				pubKey = keyBytes
			}
		}
	}
	if pubKey == nil {
		return License{}, fmt.Errorf("%w: no verifier public key available "+
			"(build-embedded key missing and PIPELOCK_LICENSE_PUBLIC_KEY unset)",
			ErrFleetLicenseRequired)
	}
	if crlFile == "" {
		crlFile = os.Getenv(EnvLicenseCRLFile)
	}
	var (
		lic License
		err error
	)
	if crlFile != "" {
		crl, crlErr := LoadAndVerifyCRL(crlFile, pubKey, time.Now())
		if crlErr != nil {
			return License{}, fmt.Errorf("%w: loading license CRL: %w", ErrFleetLicenseRequired, crlErr)
		}
		lic, err = VerifyWithCRL(licenseKey, pubKey, &crl)
	} else {
		lic, err = Verify(licenseKey, pubKey)
	}
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
