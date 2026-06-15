// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// issueTokenExpiring mints an intermediate-signed token with an explicit expiry
// so the clock-injection tests can place the expiry boundary on either side of
// the wall clock.
func issueTokenExpiring(t *testing.T, signer ed25519.PrivateKey, id string, issuedAt, expiresAt time.Time) string {
	t.Helper()
	token, err := Issue(License{
		ID:        id,
		Email:     "customer@example.com",
		IssuedAt:  issuedAt.Unix(),
		ExpiresAt: expiresAt.Unix(),
		Features:  []string{FeatureFleet},
	}, signer)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return token
}

// TestVerifyChain_TokenExpiryHonorsInjectedClock proves the license token's own
// expiry is evaluated against the injected verification time, the SAME instant
// that drives the intermediate validity window and CRL checks — not the wall
// clock. Before the clock was threaded into the token-expiry check, Verify used
// time.Now() directly, so both subtests below would have produced the wrong
// verdict whenever the injected clock disagreed with the wall clock.
func TestVerifyChain_TokenExpiryHonorsInjectedClock(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, intPriv := testKeyPair(t)
	wall := time.Now().UTC()

	// A deliberately wide intermediate window so the ONLY field crossing its
	// boundary in each subtest is the token expiry, isolating the behavior under
	// test from the intermediate-window check.
	cert, _ := testIntermediate(t, rootPriv, intPub, wall.Add(-200*24*time.Hour), wall.Add(200*24*time.Hour))

	t.Run("as-of future past expiry, wall clock not yet there", func(t *testing.T) {
		// Token still valid by the wall clock (expires wall+1h) but we verify
		// as-of wall+2h. The old time.Now()-based check would have ACCEPTED it.
		token := issueTokenExpiring(t, intPriv, "lic_future_exp", wall, wall.Add(time.Hour))

		if _, err := VerifyChain(token, &cert, rootPub, nil, wall); err != nil {
			t.Fatalf("as-of wall (before expiry) should verify: %v", err)
		}
		_, err := VerifyChain(token, &cert, rootPub, nil, wall.Add(2*time.Hour))
		if !errors.Is(err, ErrLicenseExpired) {
			t.Fatalf("as-of wall+2h (after expiry) want ErrLicenseExpired, got %v", err)
		}
	})

	t.Run("as-of past before expiry, wall clock already past it", func(t *testing.T) {
		// Token already expired by the wall clock (expired wall-1h) but we verify
		// as-of wall-2h, before its expiry. The old time.Now()-based check would
		// have REJECTED a token that was valid at the injected instant.
		token := issueTokenExpiring(t, intPriv, "lic_past_exp", wall.Add(-3*time.Hour), wall.Add(-time.Hour))

		lic, err := VerifyChain(token, &cert, rootPub, nil, wall.Add(-2*time.Hour))
		if err != nil {
			t.Fatalf("as-of wall-2h (before expiry) should verify, got %v", err)
		}
		if lic.ID != "lic_past_exp" {
			t.Fatalf("lic.ID = %q, want lic_past_exp", lic.ID)
		}
		if _, err := VerifyChain(token, &cert, rootPub, nil, wall); !errors.Is(err, ErrLicenseExpired) {
			t.Fatalf("as-of wall (after expiry) want ErrLicenseExpired, got %v", err)
		}
	})
}

// TestVerifyChain_OneClockDrivesWindowAndExpiry confirms a single injected
// instant drives BOTH the intermediate validity window and the token expiry: as
// the clock advances we get the intermediate's verdict first (window), then the
// token's (expiry), proving they share one clock rather than two.
func TestVerifyChain_OneClockDrivesWindowAndExpiry(t *testing.T) {
	rootPub, rootPriv := testKeyPair(t)
	intPub, intPriv := testKeyPair(t)
	base := time.Now().UTC()

	// Intermediate valid [base-1h, base+10h]; token expires at base+5h.
	cert, _ := testIntermediate(t, rootPriv, intPub, base.Add(-time.Hour), base.Add(10*time.Hour))
	token := issueTokenExpiring(t, intPriv, "lic_pivot", base, base.Add(5*time.Hour))

	// Within both windows: clean verify.
	if _, err := VerifyChain(token, &cert, rootPub, nil, base.Add(time.Hour)); err != nil {
		t.Fatalf("as-of base+1h should verify: %v", err)
	}
	// Past the token expiry but still inside the intermediate window: the token
	// expiry must be the verdict, driven by the same injected clock.
	if _, err := VerifyChain(token, &cert, rootPub, nil, base.Add(6*time.Hour)); !errors.Is(err, ErrLicenseExpired) {
		t.Fatalf("as-of base+6h want ErrLicenseExpired, got %v", err)
	}
	// Past the intermediate NotAfter: now the intermediate window is the verdict,
	// proving the same clock also drives the window check (fails closed before the
	// token is even considered).
	if _, err := VerifyChain(token, &cert, rootPub, nil, base.Add(11*time.Hour)); !errors.Is(err, ErrIntermediateExpired) {
		t.Fatalf("as-of base+11h want ErrIntermediateExpired, got %v", err)
	}
}
