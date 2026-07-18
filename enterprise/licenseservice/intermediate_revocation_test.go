//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

// TestIssuerSideIntermediateRevocationRoundTrip proves the full path: an admin
// revokes an intermediate serial, the service-published SignedCRL carries it as
// a RevokedIntermediate, and a consumer verifying a token signed by that
// intermediate fails closed with ErrIntermediateRevoked.
func TestIssuerSideIntermediateRevocationRoundTrip(t *testing.T) {
	ts := newTestSetup(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// The handler's CRL signing key is the root trust anchor for this test: it
	// signs both the CRL and the intermediate cert, and verifies the token chain.
	rootPriv := ts.cfg.CRLPrivateKey
	rootPub, ok := rootPriv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("CRL key has no public half")
	}

	// Build an intermediate + a token signed by it.
	intPub, intPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("int keygen: %v", err)
	}
	const serial = "im_revoke_target"
	cert, err := license.SignIntermediate(license.IntermediatePayload{
		Serial:    serial,
		Purpose:   license.PurposeLicenseSigning,
		Algorithm: license.AlgorithmEd25519,
		PublicKey: hex.EncodeToString(intPub),
		NotBefore: now.Add(-time.Hour).Unix(),
		NotAfter:  now.Add(30 * 24 * time.Hour).Unix(),
		IssuedAt:  now.Add(-time.Hour).Unix(),
	}, rootPriv)
	if err != nil {
		t.Fatalf("SignIntermediate: %v", err)
	}
	certBytes, err := cert.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal cert: %v", err)
	}
	token, err := license.Issue(license.License{
		ID:       "lic_chain",
		Email:    "ops@example.test",
		IssuedAt: now.Add(-time.Hour).Unix(),
		Features: []string{license.FeatureFleet},
	}, intPriv)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	verifyConsumer := func(t *testing.T) error {
		crl, err := ts.handler.SignedCRL(ctx, time.Now())
		if err != nil {
			t.Fatalf("SignedCRL: %v", err)
		}
		// Re-marshal and parse to exercise the published wire form a consumer sees.
		data, err := json.Marshal(crl)
		if err != nil {
			t.Fatalf("marshal CRL: %v", err)
		}
		parsed, err := license.ParseAndVerifyCRL(data, rootPub, time.Now())
		if err != nil {
			t.Fatalf("consumer parse CRL: %v", err)
		}
		_, verr := license.VerifyTokenWithOptions(token, license.VerifyOptions{
			Intermediate:        certBytes,
			RequireIntermediate: true,
			CRL:                 &parsed,
			RootPub:             rootPub,
			Now:                 time.Now(),
		})
		return verr
	}

	// Before revocation: the token verifies.
	if err := verifyConsumer(t); err != nil {
		t.Fatalf("pre-revocation token must verify: %v", err)
	}

	// Admin revokes the intermediate.
	if err := ts.handler.RevokeIntermediate(ctx, serial, "rotated", now); err != nil {
		t.Fatalf("RevokeIntermediate: %v", err)
	}

	// After revocation: the published CRL carries the serial AND the consumer
	// rejects the token.
	crl, err := ts.handler.SignedCRL(ctx, time.Now())
	if err != nil {
		t.Fatalf("SignedCRL after revoke: %v", err)
	}
	found := false
	for _, ri := range crl.Payload.RevokedIntermediates {
		if ri.Serial == serial {
			found = true
		}
	}
	if !found {
		t.Fatalf("published CRL must carry revoked intermediate %q, got %+v", serial, crl.Payload.RevokedIntermediates)
	}
	if err := verifyConsumer(t); !errors.Is(err, license.ErrIntermediateRevoked) {
		t.Fatalf("post-revocation consumer must reject with ErrIntermediateRevoked, got %v", err)
	}
}

// TestRevokeIntermediate_ReplayIdempotent confirms a duplicate revoke does not
// fault and does not duplicate the serial in the published CRL.
func TestRevokeIntermediate_ReplayIdempotent(t *testing.T) {
	ts := newTestSetup(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const serial = "im_dup"

	if err := ts.handler.RevokeIntermediate(ctx, serial, "rotated", now); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if err := ts.handler.RevokeIntermediate(ctx, serial, "rotated-again", now.Add(time.Minute)); err != nil {
		t.Fatalf("replay revoke must be idempotent: %v", err)
	}
	crl, err := ts.handler.SignedCRL(ctx, time.Now())
	if err != nil {
		t.Fatalf("SignedCRL: %v", err)
	}
	count := 0
	for _, ri := range crl.Payload.RevokedIntermediates {
		if ri.Serial == serial {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate revoke must yield exactly one CRL entry, got %d", count)
	}
}

func TestRevokeIntermediate_EmptySerialRejected(t *testing.T) {
	ts := newTestSetup(t)
	if err := ts.handler.RevokeIntermediate(context.Background(), "", "x", time.Now()); err == nil {
		t.Fatal("empty serial must be rejected")
	}
}

// TestRecoverCRLGenerationFromSignedCRL proves the high-water recovery path:
// after the DB counter is reset (simulating a restore), feeding the last
// published signed CRL re-raises the counter so the next emission cannot regress
// below a generation a consumer already accepted.
func TestRecoverCRLGenerationFromSignedCRL(t *testing.T) {
	ts := newTestSetup(t)
	ctx := context.Background()

	// Emit a few CRLs to advance the generation.
	var lastBytes []byte
	for range 3 {
		crl, err := ts.handler.SignedCRL(ctx, time.Now())
		if err != nil {
			t.Fatalf("SignedCRL: %v", err)
		}
		lastBytes, err = json.Marshal(crl)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	var published license.CRL
	if err := json.Unmarshal(lastBytes, &published); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	publishedGen := published.Payload.Generation
	if publishedGen < 3 {
		t.Fatalf("expected generation >= 3, got %d", publishedGen)
	}

	// Simulate a DB restore that rewound the counter to 0.
	if _, err := ts.db.db.ExecContext(ctx, `UPDATE crl_generation SET generation = 0 WHERE id = 0`); err != nil {
		t.Fatalf("reset counter: %v", err)
	}

	recovered, err := ts.handler.RecoverCRLGenerationFromSignedCRL(ctx, lastBytes)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if recovered < publishedGen {
		t.Fatalf("recovered generation %d must be >= published %d", recovered, publishedGen)
	}

	// The next emission must be STRICTLY above the published generation, so a
	// consumer that accepted publishedGen will accept the new one but reject the
	// rolled-back DB state.
	next, err := ts.handler.SignedCRL(ctx, time.Now())
	if err != nil {
		t.Fatalf("SignedCRL after recovery: %v", err)
	}
	if next.Payload.Generation <= publishedGen {
		t.Fatalf("post-recovery generation %d must exceed published %d (no rollback)", next.Payload.Generation, publishedGen)
	}
}

// TestRecoverCRLGeneration_RejectsForgedCRL confirms a CRL signed by the wrong
// key cannot poison the high-water.
func TestRecoverCRLGeneration_RejectsForgedCRL(t *testing.T) {
	ts := newTestSetup(t)
	ctx := context.Background()

	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	forged, err := license.SignCRL(license.CRLPayload{
		Version:    license.CRLVersion,
		Generation: 9_999_999,
		IssuedAt:   time.Now().Add(-time.Hour).Unix(),
		ExpiresAt:  time.Now().Add(time.Hour).Unix(),
	}, attackerPriv)
	if err != nil {
		t.Fatalf("sign forged CRL: %v", err)
	}
	data, err := json.Marshal(forged)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := ts.handler.RecoverCRLGenerationFromSignedCRL(ctx, data); err == nil {
		t.Fatal("forged CRL must be rejected for recovery (wrong signing key)")
	}
}

// TestEntitlementDB_RevokedIntermediates covers the durable storage layer:
// upsert is idempotent, list is sorted, and an empty serial is rejected.
func TestEntitlementDB_RevokedIntermediates(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	now := time.Now().UTC()

	if err := db.UpsertRevokedIntermediate(ctx, RevokedIntermediateRecord{Serial: "b", Reason: "x", RevokedAt: now}); err != nil {
		t.Fatalf("upsert b: %v", err)
	}
	if err := db.UpsertRevokedIntermediate(ctx, RevokedIntermediateRecord{Serial: "a", Reason: "y", RevokedAt: now}); err != nil {
		t.Fatalf("upsert a: %v", err)
	}
	// Idempotent re-revoke.
	if err := db.UpsertRevokedIntermediate(ctx, RevokedIntermediateRecord{Serial: "a", Reason: "y2", RevokedAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("re-upsert a: %v", err)
	}
	if err := db.UpsertRevokedIntermediate(ctx, RevokedIntermediateRecord{Serial: ""}); err == nil {
		t.Fatal("empty serial must be rejected")
	}

	list, err := db.ListRevokedIntermediates(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 unique serials, got %d", len(list))
	}
	if list[0].Serial != "a" || list[1].Serial != "b" {
		t.Fatalf("must be sorted by serial, got %q,%q", list[0].Serial, list[1].Serial)
	}
	if list[0].Reason != "y2" {
		t.Fatalf("re-revoke must update reason, got %q", list[0].Reason)
	}
}

// TestEntitlementDB_RecoverCRLGenerationMonotonic confirms recovery only ever
// raises the counter and never lowers it.
func TestEntitlementDB_RecoverCRLGenerationMonotonic(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()

	// Advance to 3 via NextCRLGeneration.
	for range 3 {
		if _, err := db.NextCRLGeneration(ctx); err != nil {
			t.Fatalf("next: %v", err)
		}
	}
	// Recover to a higher floor raises it.
	got, err := db.RecoverCRLGeneration(ctx, 10)
	if err != nil {
		t.Fatalf("recover up: %v", err)
	}
	if got != 10 {
		t.Fatalf("recover to floor 10 = %d", got)
	}
	// Recover to a LOWER floor must NOT lower it.
	got, err = db.RecoverCRLGeneration(ctx, 5)
	if err != nil {
		t.Fatalf("recover down: %v", err)
	}
	if got != 10 {
		t.Fatalf("recover must never lower; got %d, want 10", got)
	}
	// Next generation is strictly above the recovered floor.
	next, err := db.NextCRLGeneration(ctx)
	if err != nil {
		t.Fatalf("next after recover: %v", err)
	}
	if next != 11 {
		t.Fatalf("next after recover = %d, want 11", next)
	}
}
