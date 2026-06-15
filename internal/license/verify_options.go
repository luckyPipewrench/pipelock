// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// EnvLicenseRequireIntermediate is the env override for require-intermediate
// mode. When set, the consumer refuses any license that is not signed by a
// root-certified intermediate (the offline-root PKI tier). It is a fail-closed
// security knob: an invalid boolean value is rejected, never silently defaulted
// to false. The build-spec invariant is that the DEFAULT (unset / false)
// preserves today's behaviour exactly so existing root-signed licenses keep
// verifying — turning it on is an explicit operator decision after migration.
const EnvLicenseRequireIntermediate = "PIPELOCK_LICENSE_REQUIRE_INTERMEDIATE"

// ErrIntermediateRequired is returned when require-intermediate mode is on but
// no intermediate certificate is configured (im == nil). It is distinct from
// ErrIntermediateMalformed (a cert was supplied but is bad) so the operator
// sees "you must configure an intermediate" rather than "your cert is broken".
var ErrIntermediateRequired = errors.New("intermediate certificate required but none configured")

// ErrInvalidRequireIntermediateEnv is returned when
// PIPELOCK_LICENSE_REQUIRE_INTERMEDIATE holds a value that is not a recognized
// boolean. Resolving fails closed on this rather than defaulting to false: a
// fat-fingered "treu" must never silently disable the require-intermediate
// trust tier.
var ErrInvalidRequireIntermediateEnv = errors.New("invalid PIPELOCK_LICENSE_REQUIRE_INTERMEDIATE value (want a boolean)")

// VerifyOptions carries every input the license verification chain needs. It is
// the single options struct that the config + env resolver builds, so each
// verify entry point takes ONE value instead of growing a positional argument
// per knob (per the options-struct rule in CLAUDE.md).
type VerifyOptions struct {
	// Intermediate is the raw configured intermediate-cert bytes. Empty/nil
	// means no intermediate is configured.
	Intermediate []byte
	// RequireIntermediate, when true, refuses any token that is not validated
	// through a root-certified intermediate. When false (the default), behaviour
	// is unchanged: root-signed tokens still verify directly.
	RequireIntermediate bool
	// CRL is the loaded, already-verified revocation list (nil = none).
	CRL *CRL
	// RootPub is the trust-anchor public key.
	RootPub ed25519.PublicKey
	// Now is the verification clock. Zero falls back to time.Now() so callers
	// that do not inject a clock keep working.
	Now time.Time
	// MaxAge is the CRL freshness window (IssuedAt-age). Zero (or negative) falls
	// back to DefaultCRLMaxAge so callers that do not set it keep today's
	// behaviour. It is consulted ONLY under require mode (freshness is
	// require-only), matching ResolveVerifyOptions.
	MaxAge time.Duration
}

func (o VerifyOptions) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

// maxAge resolves the freshness window, clamping a zero/negative value to
// DefaultCRLMaxAge. A configured value must never be able to DISABLE the
// freshness check (which CheckFreshness treats maxAge<=0 as), so the floor here
// is fail-safe: a misconfigured 0 becomes the 25h default, never "no check".
func (o VerifyOptions) maxAge() time.Duration {
	if o.MaxAge <= 0 {
		return DefaultCRLMaxAge
	}
	return o.MaxAge
}

// VerifyTokenWithOptions is the options-based verification entry point. It
// enforces the fail-closed contract for a configured intermediate cert AND the
// require-intermediate semantics, and is the function every higher-level gate
// (fleet, reload, status, doctor, assess, runtime watcher) routes through.
//
// Semantics:
//
//   - RequireIntermediate == false (default): identical to
//     VerifyTokenWithOptionalIntermediate — a configured cert is used and fails
//     closed if bad; with no cert, legacy direct-root verification applies.
//   - RequireIntermediate == true, no cert (Intermediate empty): the token CANNOT
//     have come through an intermediate, so verification fails closed with
//     ErrIntermediateRequired. (The caller decides whether that is fatal; for the
//     free proxy it is a warning, see the resolver doc.)
//   - RequireIntermediate == true, cert present: the cert MUST parse, root-verify,
//     be within its window, and not be revoked; the token is then verified
//     against the intermediate key with NO fallback to direct-root. A signature
//     mismatch against the intermediate fails closed (a root-signed legacy token
//     is rejected under require mode by design). Expiry/revocation fail closed.
func VerifyTokenWithOptions(token string, opts VerifyOptions) (License, error) {
	if len(opts.RootPub) != ed25519.PublicKeySize {
		return License{}, errors.New("invalid root public key")
	}
	now := opts.now()

	if !opts.RequireIntermediate {
		// Back-compat path: configured-cert-or-legacy-root, exactly as before.
		return VerifyTokenWithOptionalIntermediate(token, opts.Intermediate, opts.RootPub, opts.CRL, now)
	}

	// require == true.
	if len(opts.Intermediate) == 0 {
		return License{}, ErrIntermediateRequired
	}
	im, err := ParseAndVerifyIntermediate(opts.Intermediate, opts.RootPub, now)
	if err != nil {
		return License{}, fmt.Errorf("configured intermediate certificate rejected: %w", err)
	}
	if opts.CRL != nil {
		if err := opts.CRL.CheckIntermediate(im.Serial()); err != nil {
			return License{}, err
		}
	}
	// Strict path: token MUST be signed by the active intermediate. No
	// fall-back to direct-root verification — that is the whole point of require
	// mode (a popped root cannot mint a token that bypasses the intermediate).
	return verifyChainStrict(token, im, opts.CRL, now)
}

// verifyChainStrict verifies a token against the intermediate public key ONLY.
// Unlike VerifyChain it never falls back to direct-root verification on a
// signature mismatch, so under require-intermediate mode a legacy root-signed
// token (or a token forged with a compromised root key) is rejected. The
// intermediate must already be root-verified by the caller. now is the
// verification clock, threaded so token expiry shares the instant already used
// for the intermediate window and CRL freshness.
func verifyChainStrict(token string, im Intermediate, crl *CRL, now time.Time) (License, error) {
	return verifyWithCRLAt(token, im.PublicKey(), crl, now)
}

// ResolveInputs are the config/env-resolved inputs ResolveVerifyOptions turns
// into a fail-closed VerifyOptions. It is an options struct (per the
// options-struct rule) so new verify knobs — like MaxAge — thread through
// without growing a positional signature.
type ResolveInputs struct {
	// RootPub is the trust anchor (already resolved by the caller; required).
	RootPub ed25519.PublicKey
	// CRLFile is the signed CRL path; "" falls back to EnvLicenseCRLFile.
	CRLFile string
	// IntermediateCert is raw cert bytes the caller already loaded (config path);
	// non-empty wins over IntermediateFile.
	IntermediateCert []byte
	// IntermediateFile is a cert path; "" falls back to EnvLicenseIntermediateFile.
	IntermediateFile string
	// RequireSet distinguishes "config did not specify" (consult env) from an
	// explicit config require value.
	RequireSet bool
	// Require is the explicit config require value (used only when RequireSet).
	Require bool
	// MaxAge is the configured CRL freshness window. Zero/negative falls back to
	// DefaultCRLMaxAge (a configured value can never DISABLE the check).
	MaxAge time.Duration
}

// ResolveVerifyOptions builds VerifyOptions from configured values and the
// environment, failing CLOSED on every malformed input. It is the ONE resolver
// the build-spec mandates so every entry point derives require-mode, the CRL,
// the freshness window, and the intermediate identically.
//
// Fail-closed conditions (all return an error, never a silently-relaxed opts):
//
//   - invalid boolean env (ErrInvalidRequireIntermediateEnv)
//   - require==true but no CRL configured (a stale/forged CRL is the rollback
//     vector require mode is meant to close; missing CRL = no rollback floor)
//   - CRL load/verify/freshness failure (freshness uses in.MaxAge, clamped to
//     DefaultCRLMaxAge when zero/negative)
//   - malformed intermediate cert
//
// Note: require==true with NO intermediate is NOT a resolver error — the
// resolver returns opts with RequireIntermediate=true and empty Intermediate;
// VerifyTokenWithOptions then returns ErrIntermediateRequired, which the free
// proxy treats as a warning (never crashing detection) while paid surfaces fail
// closed. This split keeps the "never gate detection behind a license" rule.
func ResolveVerifyOptions(in ResolveInputs) (VerifyOptions, error) {
	opts := VerifyOptions{RootPub: in.RootPub, Now: time.Now(), MaxAge: in.MaxAge}

	resolvedRequire, err := resolveRequireIntermediate(in.RequireSet, in.Require)
	if err != nil {
		return VerifyOptions{}, err
	}
	opts.RequireIntermediate = resolvedRequire

	// CRL. Freshness (IssuedAt-age) is enforced ONLY under require mode: a
	// stale-but-unexpired CRL is a compromise-response gap that require mode must
	// close, but enforcing freshness on the legacy path would be a behaviour
	// change (and could brick an unattended deployment whose publisher paused).
	crlFile := in.CRLFile
	if crlFile == "" {
		crlFile = strings.TrimSpace(os.Getenv(EnvLicenseCRLFile))
	}
	if crlFile != "" {
		var loaded CRL
		var crlErr error
		if resolvedRequire {
			loaded, crlErr = LoadAndVerifyCRLMonotonicFresh(crlFile, in.RootPub, opts.Now, opts.maxAge())
		} else {
			loaded, crlErr = LoadAndVerifyCRLMonotonic(crlFile, in.RootPub, opts.Now)
		}
		if crlErr != nil {
			return VerifyOptions{}, fmt.Errorf("loading license CRL: %w", crlErr)
		}
		opts.CRL = &loaded
	} else if resolvedRequire {
		// require mode without a CRL has no revocation floor: an attacker who can
		// strip the CRL re-enables a revoked intermediate. Fail closed.
		return VerifyOptions{}, fmt.Errorf("%w: require-intermediate mode requires a signed CRL", ErrIntermediateRequired)
	}

	// Intermediate.
	if len(in.IntermediateCert) > 0 {
		opts.Intermediate = in.IntermediateCert
	} else {
		intermediateFile := in.IntermediateFile
		if intermediateFile == "" {
			intermediateFile = strings.TrimSpace(os.Getenv(EnvLicenseIntermediateFile))
		}
		if intermediateFile != "" {
			data, loadErr := LoadIntermediateCertFile(intermediateFile)
			if loadErr != nil {
				return VerifyOptions{}, fmt.Errorf("loading intermediate certificate: %w", loadErr)
			}
			opts.Intermediate = data
		}
	}

	return opts, nil
}

// resolveRequireIntermediate picks the effective require value. An explicit
// config value (requireSet) wins; otherwise the env is consulted and a malformed
// boolean fails closed.
func resolveRequireIntermediate(requireSet, require bool) (bool, error) {
	if requireSet {
		return require, nil
	}
	raw, ok := os.LookupEnv(EnvLicenseRequireIntermediate)
	if !ok {
		return false, nil
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		// Present-but-empty is treated as unset (matches the trim-then-fallback
		// pattern the other license env knobs use).
		return false, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%w: %q", ErrInvalidRequireIntermediateEnv, raw)
	}
	return v, nil
}
