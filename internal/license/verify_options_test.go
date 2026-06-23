// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// vroKeys returns a fresh root + intermediate keypair for require-intermediate
// tests.
func vroKeys(t *testing.T) (rootPub ed25519.PublicKey, rootPriv ed25519.PrivateKey, intPub ed25519.PublicKey, intPriv ed25519.PrivateKey) {
	t.Helper()
	var err error
	rootPub, rootPriv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("root keygen: %v", err)
	}
	intPub, intPriv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("intermediate keygen: %v", err)
	}
	return rootPub, rootPriv, intPub, intPriv
}

// vroToken issues a license token signed by signer, carrying the given features.
func vroToken(t *testing.T, signer ed25519.PrivateKey, id string, features []string, expiresAt time.Time) string {
	t.Helper()
	lic := License{
		ID:        id,
		Email:     "ops@example.test",
		Org:       "Example Org",
		IssuedAt:  time.Now().Add(-time.Hour).Unix(),
		Features:  features,
		ExpiresAt: 0,
	}
	if !expiresAt.IsZero() {
		lic.ExpiresAt = expiresAt.Unix()
	}
	tok, err := Issue(lic, signer)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return tok
}

// vroCRL signs a CRL with optional revoked license IDs and intermediate serials,
// issued `age` before now.
func vroCRL(t *testing.T, signer ed25519.PrivateKey, now time.Time, age time.Duration, revokedLic []RevokedLicense, revokedInt []RevokedIntermediate) CRL {
	t.Helper()
	crl, err := SignCRL(CRLPayload{
		Version:              CRLVersion,
		Generation:           1,
		IssuedAt:             now.Add(-age).Unix(),
		ExpiresAt:            now.Add(7 * 24 * time.Hour).Unix(),
		Revoked:              revokedLic,
		RevokedIntermediates: revokedInt,
	}, signer)
	if err != nil {
		t.Fatalf("sign CRL: %v", err)
	}
	return crl
}

func TestVerifyTokenWithOptions_RequireSemantics(t *testing.T) {
	rootPub, rootPriv, intPub, intPriv := vroKeys(t)
	now := time.Now()
	_, intCertBytes := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(30*24*time.Hour))

	intToken := vroToken(t, intPriv, "lic_int", []string{FeatureFleet}, time.Time{})
	rootToken := vroToken(t, rootPriv, "lic_root", []string{FeatureFleet}, time.Time{})

	t.Run("require_off_root_token_accepted (brick-guard)", func(t *testing.T) {
		lic, err := VerifyTokenWithOptions(rootToken, VerifyOptions{RootPub: rootPub, Now: now})
		if err != nil {
			t.Fatalf("root token must verify with require off: %v", err)
		}
		if lic.ID != "lic_root" {
			t.Fatalf("license ID = %q", lic.ID)
		}
	})

	t.Run("require_off_default_no_intermediate (brick-guard)", func(t *testing.T) {
		// Zero-value RequireIntermediate must preserve today's behaviour exactly.
		if _, err := VerifyTokenWithOptions(rootToken, VerifyOptions{RootPub: rootPub, Now: now}); err != nil {
			t.Fatalf("default-false must accept root-signed token: %v", err)
		}
	})

	t.Run("require_on_valid_intermediate_token_accepted", func(t *testing.T) {
		crl := vroCRL(t, rootPriv, now, time.Hour, nil, nil)
		lic, err := VerifyTokenWithOptions(intToken, VerifyOptions{
			RootPub: rootPub, Now: now, RequireIntermediate: true, Intermediate: intCertBytes, CRL: &crl,
		})
		if err != nil {
			t.Fatalf("intermediate token must verify under require: %v", err)
		}
		if lic.ID != "lic_int" {
			t.Fatalf("license ID = %q", lic.ID)
		}
	})

	t.Run("require_on_root_token_rejected (no root fallthrough)", func(t *testing.T) {
		// A forged/legacy root-signed token must NOT verify under require mode,
		// even with a valid intermediate configured. A valid CRL is supplied so
		// the rejection is the root-fallthrough guard, not the CRL-required gate.
		crl := vroCRL(t, rootPriv, now, time.Hour, nil, nil)
		if _, err := VerifyTokenWithOptions(rootToken, VerifyOptions{
			RootPub: rootPub, Now: now, RequireIntermediate: true, Intermediate: intCertBytes, CRL: &crl,
		}); err == nil {
			t.Fatal("root-signed token must be rejected under require mode")
		}
	})

	t.Run("require_on_no_intermediate_returns_ErrIntermediateRequired", func(t *testing.T) {
		_, err := VerifyTokenWithOptions(intToken, VerifyOptions{
			RootPub: rootPub, Now: now, RequireIntermediate: true,
		})
		if !errors.Is(err, ErrIntermediateRequired) {
			t.Fatalf("want ErrIntermediateRequired, got %v", err)
		}
	})

	t.Run("require_on_intermediate_but_no_crl_returns_ErrCRLRequired", func(t *testing.T) {
		// Require mode with a valid intermediate but no CRL must fail closed:
		// a revoked intermediate would otherwise be undetectable.
		_, err := VerifyTokenWithOptions(intToken, VerifyOptions{
			RootPub: rootPub, Now: now, RequireIntermediate: true, Intermediate: intCertBytes,
		})
		if !errors.Is(err, ErrCRLRequired) {
			t.Fatalf("want ErrCRLRequired, got %v", err)
		}
	})

	t.Run("require_on_malformed_intermediate_fails_closed", func(t *testing.T) {
		_, err := VerifyTokenWithOptions(intToken, VerifyOptions{
			RootPub: rootPub, Now: now, RequireIntermediate: true, Intermediate: []byte("{not a cert"),
		})
		if err == nil || errors.Is(err, ErrIntermediateRequired) {
			t.Fatalf("malformed cert must fail closed (not Required), got %v", err)
		}
	})

	t.Run("require_on_expired_token_ErrLicenseExpired_no_fallthrough", func(t *testing.T) {
		expiredTok := vroToken(t, intPriv, "lic_exp", []string{FeatureFleet}, now.Add(-time.Hour))
		crl := vroCRL(t, rootPriv, now, time.Hour, nil, nil)
		_, err := VerifyTokenWithOptions(expiredTok, VerifyOptions{
			RootPub: rootPub, Now: now, RequireIntermediate: true, Intermediate: intCertBytes, CRL: &crl,
		})
		if !errors.Is(err, ErrLicenseExpired) {
			t.Fatalf("want ErrLicenseExpired, got %v", err)
		}
	})

	t.Run("require_on_license_revoked", func(t *testing.T) {
		crl := vroCRL(t, rootPriv, now, time.Hour,
			[]RevokedLicense{{ID: "lic_int", Reason: "test", RevokedAt: now.Add(-time.Hour).Unix()}}, nil)
		_, err := VerifyTokenWithOptions(intToken, VerifyOptions{
			RootPub: rootPub, Now: now, RequireIntermediate: true, Intermediate: intCertBytes, CRL: &crl,
		})
		if !errors.Is(err, ErrLicenseRevoked) {
			t.Fatalf("want ErrLicenseRevoked, got %v", err)
		}
	})

	t.Run("require_on_intermediate_serial_revoked", func(t *testing.T) {
		crl := vroCRL(t, rootPriv, now, time.Hour, nil,
			[]RevokedIntermediate{{Serial: testSerial, Reason: "rotated", RevokedAt: now.Add(-time.Hour).Unix()}})
		_, err := VerifyTokenWithOptions(intToken, VerifyOptions{
			RootPub: rootPub, Now: now, RequireIntermediate: true, Intermediate: intCertBytes, CRL: &crl,
		})
		if !errors.Is(err, ErrIntermediateRevoked) {
			t.Fatalf("want ErrIntermediateRevoked, got %v", err)
		}
	})

	t.Run("invalid_root_pub", func(t *testing.T) {
		if _, err := VerifyTokenWithOptions(intToken, VerifyOptions{RootPub: nil, Now: now}); err == nil {
			t.Fatal("nil root pub must error")
		}
	})
}

func TestResolveVerifyOptions_FailClosed(t *testing.T) {
	rootPub, rootPriv, intPub, _ := vroKeys(t)
	now := time.Now()
	_, intCertBytes := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(30*24*time.Hour))

	writeCRL := func(t *testing.T, age time.Duration) string {
		t.Helper()
		crl := vroCRL(t, rootPriv, now, age, nil, nil)
		data, err := json.Marshal(crl)
		if err != nil {
			t.Fatalf("marshal CRL: %v", err)
		}
		p := filepath.Join(t.TempDir(), "crl.json")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatalf("write CRL: %v", err)
		}
		return p
	}

	t.Run("invalid_bool_env_rejected_not_defaulted_false", func(t *testing.T) {
		t.Setenv(EnvLicenseRequireIntermediate, "treu")
		_, err := ResolveVerifyOptions(ResolveInputs{RootPub: rootPub, IntermediateCert: intCertBytes})
		if !errors.Is(err, ErrInvalidRequireIntermediateEnv) {
			t.Fatalf("invalid bool env must be rejected, got %v", err)
		}
	})

	t.Run("env_true_sets_require", func(t *testing.T) {
		t.Setenv(EnvLicenseRequireIntermediate, "true")
		crlPath := writeCRL(t, time.Hour)
		opts, err := ResolveVerifyOptions(ResolveInputs{RootPub: rootPub, CRLFile: crlPath, IntermediateCert: intCertBytes})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !opts.RequireIntermediate {
			t.Fatal("env=true must set RequireIntermediate")
		}
	})

	t.Run("config_explicit_wins_over_env", func(t *testing.T) {
		t.Setenv(EnvLicenseRequireIntermediate, "true")
		// requireSet=true, require=false: config explicitly disables.
		opts, err := ResolveVerifyOptions(ResolveInputs{RootPub: rootPub, IntermediateCert: intCertBytes, RequireSet: true, Require: false})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if opts.RequireIntermediate {
			t.Fatal("explicit config false must win over env true")
		}
	})

	t.Run("require_true_missing_crl_fails_closed", func(t *testing.T) {
		_, err := ResolveVerifyOptions(ResolveInputs{RootPub: rootPub, IntermediateCert: intCertBytes, RequireSet: true, Require: true})
		if err == nil {
			t.Fatal("require=true with no CRL must fail closed")
		}
	})

	t.Run("require_true_stale_crl_fails_closed", func(t *testing.T) {
		crlPath := writeCRL(t, DefaultCRLMaxAge+time.Hour)
		_, err := ResolveVerifyOptions(ResolveInputs{RootPub: rootPub, CRLFile: crlPath, IntermediateCert: intCertBytes, RequireSet: true, Require: true})
		if !errors.Is(err, ErrCRLStale) {
			t.Fatalf("stale CRL under require must fail closed with ErrCRLStale, got %v", err)
		}
	})

	t.Run("require_true_fresh_crl_ok", func(t *testing.T) {
		crlPath := writeCRL(t, time.Hour)
		opts, err := ResolveVerifyOptions(ResolveInputs{RootPub: rootPub, CRLFile: crlPath, IntermediateCert: intCertBytes, RequireSet: true, Require: true})
		if err != nil {
			t.Fatalf("fresh CRL under require must resolve: %v", err)
		}
		if opts.CRL == nil {
			t.Fatal("CRL must be loaded")
		}
	})

	t.Run("malformed_intermediate_file_fails_closed", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(p, []byte("{garbage"), 0o600); err != nil {
			t.Fatalf("write bad cert: %v", err)
		}
		crlPath := writeCRL(t, time.Hour)
		// intermediateFile path that loads but the cert won't parse at verify time;
		// LoadIntermediateCertFile only rejects oversize/non-regular, so a junk file
		// loads as bytes here. The malformed-bytes rejection lands at verify time;
		// confirm load succeeds but parse fails downstream.
		opts, err := ResolveVerifyOptions(ResolveInputs{RootPub: rootPub, CRLFile: crlPath, IntermediateFile: p, RequireSet: true, Require: true})
		if err != nil {
			t.Fatalf("resolve should load junk bytes: %v", err)
		}
		if _, verr := VerifyTokenWithOptions(vroToken(t, rootPriv, "x", []string{FeatureFleet}, time.Time{}), opts); verr == nil {
			t.Fatal("junk intermediate must fail closed at verify")
		}
	})

	t.Run("default_off_no_crl_no_intermediate_ok (brick-guard)", func(t *testing.T) {
		opts, err := ResolveVerifyOptions(ResolveInputs{RootPub: rootPub})
		if err != nil {
			t.Fatalf("default-off resolver must not fail with no inputs: %v", err)
		}
		if opts.RequireIntermediate || opts.CRL != nil || opts.Intermediate != nil {
			t.Fatal("default-off resolver must produce empty opts")
		}
	})
}

// TestResolveVerifyOptions_ConfiguredMaxAgeDrivesGate proves the configured
// freshness window — not the hardcoded const — drives the resolver's staleness
// gate: a CRL issued 2h ago is rejected under a custom 1h window but accepted
// under the default 25h window. It also confirms a zero MaxAge clamps to the
// default (never disables the check), the fail-safe behaviour.
func TestResolveVerifyOptions_ConfiguredMaxAgeDrivesGate(t *testing.T) {
	rootPub, rootPriv, intPub, _ := vroKeys(t)
	now := time.Now()
	_, intCertBytes := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(30*24*time.Hour))

	// CRL issued 2h ago: stale under a 1h window, fresh under 25h.
	crl := vroCRL(t, rootPriv, now, 2*time.Hour, nil, nil)
	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatalf("marshal CRL: %v", err)
	}
	crlPath := filepath.Join(t.TempDir(), "crl.json")
	if err := os.WriteFile(crlPath, data, 0o600); err != nil {
		t.Fatalf("write CRL: %v", err)
	}

	base := ResolveInputs{
		RootPub: rootPub, CRLFile: crlPath, IntermediateCert: intCertBytes,
		RequireSet: true, Require: true,
	}

	t.Run("custom_1h_rejects_2h_old_crl", func(t *testing.T) {
		in := base
		in.MaxAge = time.Hour
		if _, err := ResolveVerifyOptions(in); !errors.Is(err, ErrCRLStale) {
			t.Fatalf("custom 1h window must reject a 2h-old CRL with ErrCRLStale, got %v", err)
		}
	})

	t.Run("default_25h_accepts_2h_old_crl", func(t *testing.T) {
		in := base // MaxAge unset -> clamps to DefaultCRLMaxAge (25h)
		opts, err := ResolveVerifyOptions(in)
		if err != nil {
			t.Fatalf("default 25h window must accept a 2h-old CRL, got %v", err)
		}
		if opts.CRL == nil {
			t.Fatal("CRL must be loaded under the default window")
		}
	})

	t.Run("zero_maxage_clamps_to_default_not_disabled", func(t *testing.T) {
		// A configured 0 must NOT disable the freshness check; it clamps to the
		// default. A 2h CRL is fresh under the default, so it resolves — proving
		// the check is still ON (the gate ran, it just passed), not skipped.
		in := base
		in.MaxAge = 0
		if _, err := ResolveVerifyOptions(in); err != nil {
			t.Fatalf("zero MaxAge must clamp to default and accept a 2h CRL, got %v", err)
		}
		// And a CRL older than the default IS rejected even with MaxAge=0, proving
		// the check was never disabled.
		staleCRL := vroCRL(t, rootPriv, now, DefaultCRLMaxAge+time.Hour, nil, nil)
		staleData, mErr := json.Marshal(staleCRL)
		if mErr != nil {
			t.Fatalf("marshal stale CRL: %v", mErr)
		}
		stalePath := filepath.Join(t.TempDir(), "stale.json")
		if wErr := os.WriteFile(stalePath, staleData, 0o600); wErr != nil {
			t.Fatalf("write stale CRL: %v", wErr)
		}
		in.CRLFile = stalePath
		if _, err := ResolveVerifyOptions(in); !errors.Is(err, ErrCRLStale) {
			t.Fatalf("zero MaxAge must still reject a CRL older than the default, got %v", err)
		}
	})
}

// TestResolveVerifyOptions_MaxAgeEnvParity confirms VerifyOptions.maxAge() and
// the resolver honour an explicit window passed through ResolveInputs (the env
// fold itself lives in config.Load and is covered there).
func TestVerifyOptions_MaxAgeClamp(t *testing.T) {
	cases := []struct {
		name string
		set  time.Duration
		want time.Duration
	}{
		{"zero_clamps_to_default", 0, DefaultCRLMaxAge},
		{"negative_clamps_to_default", -time.Hour, DefaultCRLMaxAge},
		{"positive_used", 90 * time.Minute, 90 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := VerifyOptions{MaxAge: tc.set}.maxAge()
			if got != tc.want {
				t.Fatalf("maxAge() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestVerifyFleetWithOptions_RequireHonored(t *testing.T) {
	rootPub, rootPriv, intPub, intPriv := vroKeys(t)
	now := time.Now()
	_, intCertBytes := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(30*24*time.Hour))
	pubHex := hex.EncodeToString(rootPub)

	intFleetToken := vroToken(t, intPriv, "lic_fleet", []string{FeatureFleet}, time.Time{})
	rootFleetToken := vroToken(t, rootPriv, "lic_rootfleet", []string{FeatureFleet}, time.Time{})

	crl := vroCRL(t, rootPriv, now, time.Hour, nil, nil)
	crlData, err := json.Marshal(crl)
	if err != nil {
		t.Fatalf("marshal CRL: %v", err)
	}
	crlPath := filepath.Join(t.TempDir(), "crl.json")
	if err := os.WriteFile(crlPath, crlData, 0o600); err != nil {
		t.Fatalf("write CRL: %v", err)
	}

	t.Run("require_on_root_token_rejected", func(t *testing.T) {
		_, err := VerifyFleetWithOptions(FleetVerifyInputs{
			LicenseKey: rootFleetToken, PublicKeyHex: pubHex, CRLFile: crlPath,
			IntermediateCert: intCertBytes, RequireSet: true, Require: true,
		})
		if !errors.Is(err, ErrFleetLicenseRequired) {
			t.Fatalf("root token under require must be rejected as fleet-required, got %v", err)
		}
	})

	t.Run("require_on_intermediate_token_accepted", func(t *testing.T) {
		lic, err := VerifyFleetWithOptions(FleetVerifyInputs{
			LicenseKey: intFleetToken, PublicKeyHex: pubHex, CRLFile: crlPath,
			IntermediateCert: intCertBytes, RequireSet: true, Require: true,
		})
		if err != nil {
			t.Fatalf("intermediate fleet token under require must verify: %v", err)
		}
		if lic.ID != "lic_fleet" {
			t.Fatalf("license ID = %q", lic.ID)
		}
	})

	t.Run("env_only_command_path_honors_require", func(t *testing.T) {
		// The ~18 conductor/fleet CLI commands resolve everything from env.
		t.Setenv(EnvLicenseKey, rootFleetToken)
		t.Setenv(EnvLicensePublicKey, pubHex)
		t.Setenv(EnvLicenseCRLFile, crlPath)
		t.Setenv(EnvLicenseIntermediateFile, writeIntermediate(t, intCertBytes))
		t.Setenv(EnvLicenseRequireIntermediate, "true")
		// VerifyFleetWithOptions with all-empty inputs == the env-only call path.
		_, err := VerifyFleetWithOptions(FleetVerifyInputs{})
		if !errors.Is(err, ErrFleetLicenseRequired) {
			t.Fatalf("env-only require must reject root-signed token, got %v", err)
		}
	})

	t.Run("legacy_VerifyFleet_unaffected (brick-guard)", func(t *testing.T) {
		t.Setenv(EnvLicenseKey, rootFleetToken)
		t.Setenv(EnvLicensePublicKey, pubHex)
		// No require env. Legacy VerifyFleet must still accept the root token.
		_ = os.Unsetenv(EnvLicenseRequireIntermediate)
		lic, err := VerifyFleet(rootFleetToken, pubHex, "")
		if err != nil {
			t.Fatalf("legacy VerifyFleet must accept root token: %v", err)
		}
		if lic.ID != "lic_rootfleet" {
			t.Fatalf("license ID = %q", lic.ID)
		}
	})
}

func writeIntermediate(t *testing.T, certBytes []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "intermediate.json")
	if err := os.WriteFile(p, certBytes, 0o600); err != nil {
		t.Fatalf("write intermediate: %v", err)
	}
	return p
}

func TestClassifyReloadWithOptions_RequireProvesLoss(t *testing.T) {
	rootPub, rootPriv, intPub, intPriv := vroKeys(t)
	now := time.Now()
	_, intCertBytes := testIntermediate(t, rootPriv, intPub, now.Add(-time.Hour), now.Add(30*24*time.Hour))
	pubHex := hex.EncodeToString(rootPub)
	intToken := vroToken(t, intPriv, "lic_int", []string{FeatureFleet}, time.Time{})

	freshCRL := func(t *testing.T, revokedInt []RevokedIntermediate) string {
		t.Helper()
		crl := vroCRL(t, rootPriv, now, time.Hour, nil, revokedInt)
		data, _ := json.Marshal(crl)
		p := filepath.Join(t.TempDir(), "crl.json")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatalf("write CRL: %v", err)
		}
		return p
	}

	t.Run("verified_when_valid", func(t *testing.T) {
		lic, class := ClassifyReloadWithOptions(FleetVerifyInputs{
			LicenseKey: intToken, PublicKeyHex: pubHex, CRLFile: freshCRL(t, nil),
			IntermediateCert: intCertBytes, RequireSet: true, Require: true,
		})
		if class != ReloadVerified {
			t.Fatalf("class = %v, want ReloadVerified", class)
		}
		if class.ProvesLoss(lic, FeatureFleet) {
			t.Fatal("a valid fleet token must not prove loss")
		}
	})

	t.Run("intermediate_required_proves_loss", func(t *testing.T) {
		// require on, but no intermediate configured -> proven loss (tear down).
		_, class := ClassifyReloadWithOptions(FleetVerifyInputs{
			LicenseKey: intToken, PublicKeyHex: pubHex, CRLFile: freshCRL(t, nil),
			RequireSet: true, Require: true,
		})
		if !class.ProvesLoss(License{}, FeatureFleet) {
			t.Fatalf("missing intermediate under require must prove loss, class=%v", class)
		}
	})

	t.Run("crl_required_proves_loss", func(t *testing.T) {
		// require on, valid intermediate, but no CRL configured -> proven loss
		// (a revoked intermediate would be undetectable, so tear down).
		_, class := ClassifyReloadWithOptions(FleetVerifyInputs{
			LicenseKey: intToken, PublicKeyHex: pubHex,
			IntermediateCert: intCertBytes, RequireSet: true, Require: true,
		})
		if class != ReloadRevoked || !class.ProvesLoss(License{}, FeatureFleet) {
			t.Fatalf("missing CRL under require must prove loss, class=%v", class)
		}
	})

	t.Run("intermediate_revoked_proves_loss", func(t *testing.T) {
		crlPath := freshCRL(t, []RevokedIntermediate{{Serial: testSerial, Reason: "rotated", RevokedAt: now.Add(-time.Hour).Unix()}})
		_, class := ClassifyReloadWithOptions(FleetVerifyInputs{
			LicenseKey: intToken, PublicKeyHex: pubHex, CRLFile: crlPath,
			IntermediateCert: intCertBytes, RequireSet: true, Require: true,
		})
		if class != ReloadRevoked || !class.ProvesLoss(License{}, FeatureFleet) {
			t.Fatalf("revoked intermediate must prove loss, class=%v", class)
		}
	})

	t.Run("malformed_intermediate_stays_unverifiable (no DoS on typo)", func(t *testing.T) {
		p := writeIntermediate(t, []byte("{garbage"))
		_, class := ClassifyReloadWithOptions(FleetVerifyInputs{
			LicenseKey: intToken, PublicKeyHex: pubHex, CRLFile: freshCRL(t, nil),
			IntermediateFile: p, RequireSet: true, Require: true,
		})
		if class != ReloadUnverifiable {
			t.Fatalf("malformed cert must stay ReloadUnverifiable, got %v", class)
		}
	})
}

func TestCRL_CheckFreshness(t *testing.T) {
	_, rootPriv, _, _ := vroKeys(t)
	now := time.Now()

	t.Run("fresh_ok", func(t *testing.T) {
		crl := vroCRL(t, rootPriv, now, time.Hour, nil, nil)
		if err := crl.CheckFreshness(now, DefaultCRLMaxAge); err != nil {
			t.Fatalf("fresh CRL must pass: %v", err)
		}
	})
	t.Run("stale_fails", func(t *testing.T) {
		crl := vroCRL(t, rootPriv, now, DefaultCRLMaxAge+time.Hour, nil, nil)
		if err := crl.CheckFreshness(now, DefaultCRLMaxAge); !errors.Is(err, ErrCRLStale) {
			t.Fatalf("stale CRL must fail with ErrCRLStale: %v", err)
		}
	})
	t.Run("future_dated_fails", func(t *testing.T) {
		crl := vroCRL(t, rootPriv, now, -2*time.Hour, nil, nil) // issued 2h in the future
		if err := crl.CheckFreshness(now, DefaultCRLMaxAge); !errors.Is(err, ErrCRLStale) {
			t.Fatalf("future-dated CRL must fail: %v", err)
		}
	})
	t.Run("disabled_when_maxage_zero", func(t *testing.T) {
		crl := vroCRL(t, rootPriv, now, 365*24*time.Hour, nil, nil)
		if err := crl.CheckFreshness(now, 0); err != nil {
			t.Fatalf("maxAge=0 disables check: %v", err)
		}
	})
}
