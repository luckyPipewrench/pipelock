//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// quarantineRecorder is a quarantineCounter that records every quarantine for
// assertions. It is concurrency-safe so a test can read it after read-path calls
// without racing the (synchronous) recorder.
type quarantineRecorder struct {
	mu     sync.Mutex
	events []quarantineEvent
}

type quarantineEvent struct {
	control string
	reason  string
}

type erroringVerifiedEnumerators struct {
	failingEmergencyStore
}

func (erroringVerifiedEnumerators) enumerateRollbacks(context.Context) ([]StoredRollbackAuthorization, error) {
	return nil, errors.New("enumerate rollbacks failed")
}

func (erroringVerifiedEnumerators) enumerateRemoteKills(context.Context) ([]StoredRemoteKill, error) {
	return nil, errors.New("enumerate remote kills failed")
}

func (q *quarantineRecorder) RecordConductorEmergencyQuarantine(control, reason string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.events = append(q.events, quarantineEvent{control: control, reason: reason})
}

func (q *quarantineRecorder) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.events)
}

func (q *quarantineRecorder) hasReason(reason string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, e := range q.events {
		if e.reason == reason {
			return true
		}
	}
	return false
}

// trustedRollbackRecord builds a rollback authorization signed by the returned
// resolver's keys and packs it into a StoredRollbackAuthorization with a correct
// hash so it passes structural load validation.
func trustedRollbackRecord(t *testing.T, id string, counter uint64, created time.Time) (StoredRollbackAuthorization, conductor.SignatureKeyResolver) {
	t.Helper()
	auth, resolver := signedRollbackAuthorizationWithResolver(t, id, counter, created)
	return storedRollback(t, auth, created), resolver
}

func storedRollback(t *testing.T, auth conductor.RollbackAuthorization, published time.Time) StoredRollbackAuthorization {
	t.Helper()
	hash, err := auth.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(rollback): %v", err)
	}
	return StoredRollbackAuthorization{Authorization: auth, AuthorizationHash: hash, PublishedAt: published}
}

func storedRemoteKill(t *testing.T, msg conductor.RemoteKillMessage, published time.Time) StoredRemoteKill {
	t.Helper()
	hash, err := msg.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(remote kill): %v", err)
	}
	return StoredRemoteKill{Message: msg, MessageHash: hash, PublishedAt: published}
}

// forgedRollbackRecord builds a rollback authorization that is STRUCTURALLY
// valid (correct schema, ids, validity, threshold count, and a matching
// canonical hash) but whose Ed25519 signatures were made by keys that the given
// trusted resolver does NOT know. It passes validateStoredRollback (load) and
// fails VerifySignaturesAt against the trusted keys. The signer key IDs reuse
// the trusted IDs so the failure is a bad-signature, not a resolver miss
// (forgery), unless useRotatedIDs is set, which makes the IDs unknown to the
// resolver (rotation/untrusted-signer case).
func forgedRollbackRecord(t *testing.T, id string, counter uint64, created time.Time, useRotatedIDs bool) StoredRollbackAuthorization {
	t.Helper()
	auth := conductor.RollbackAuthorization{
		SchemaVersion:   conductor.SchemaVersion,
		AuthorizationID: id,
		OrgID:           "org-main",
		FleetID:         "prod",
		CurrentBundleID: "bundle-current",
		CurrentVersion:  42,
		TargetBundleID:  "bundle-target",
		TargetVersion:   41,
		Counter:         counter,
		Reason:          "forged rollback",
		CreatedAt:       created,
		ExpiresAt:       created.Add(time.Hour),
	}
	keyIDs := []string{"rollback-signer-1", "rollback-signer-2"}
	if useRotatedIDs {
		keyIDs = []string{"rotated-signer-1", "rotated-signer-2"}
	}
	auth.Signatures = forgeSignatures(t, auth.SignablePreimage, signing.PurposePolicyBundleRollback, keyIDs...)
	if err := auth.Validate(); err != nil {
		t.Fatalf("forged rollback Validate() = %v, want nil (must pass structural validation)", err)
	}
	return storedRollback(t, auth, created)
}

// forgedRemoteKillRecord mirrors forgedRollbackRecord for remote-kill messages.
func forgedRemoteKillRecord(t *testing.T, id string, counter uint64, created time.Time) StoredRemoteKill {
	t.Helper()
	msg := conductor.RemoteKillMessage{
		SchemaVersion: conductor.SchemaVersion,
		MessageID:     id,
		OrgID:         "org-main",
		FleetID:       "prod",
		Audience:      conductor.Audience{InstanceIDs: []string{"pl-prod-1"}},
		State:         conductor.KillSwitchActive,
		Counter:       counter,
		Reason:        "forged kill",
		CreatedAt:     created,
		NotBefore:     created.Add(-time.Minute),
		ExpiresAt:     created.Add(time.Hour),
	}
	msg.Signatures = forgeSignatures(t, msg.SignablePreimage, signing.PurposeRemoteKillSigning, "kill-signer-1", "kill-signer-2")
	if err := msg.Validate(); err != nil {
		t.Fatalf("forged remote kill Validate() = %v, want nil (must pass structural validation)", err)
	}
	return storedRemoteKill(t, msg, created)
}

// forgeSignatures signs the preimage with FRESH (untrusted) keys but labels the
// proofs with the supplied key IDs, producing structurally-valid proofs that no
// trusted resolver will verify.
func forgeSignatures(t *testing.T, preimage func() ([]byte, error), purpose signing.KeyPurpose, keyIDs ...string) []conductor.SignatureProof {
	t.Helper()
	data, err := preimage()
	if err != nil {
		t.Fatalf("SignablePreimage() error = %v", err)
	}
	proofs := make([]conductor.SignatureProof, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}
		proofs = append(proofs, conductor.SignatureProof{
			SignerKeyID: keyID,
			KeyPurpose:  purpose,
			Algorithm:   conductor.SignatureAlgorithmEd25519,
			Signature:   conductor.SignaturePrefixEd25519 + hex.EncodeToString(ed25519.Sign(priv, data)),
		})
	}
	return proofs
}

// seedEmergencyStateOnDisk writes an emergency-controls.json into dir holding
// the given records, then opens a FileEmergencyStore over it. It proves the
// records pass STRUCTURAL load validation (load() is fatal-on-corruption but
// must NOT verify signatures), exactly the #745 landmine.
func seedEmergencyStateOnDisk(t *testing.T, dir string, kills []StoredRemoteKill, rollbacks []StoredRollbackAuthorization) *FileEmergencyStore {
	t.Helper()
	if err := writeEmergencyState(filepath.Join(dir, emergencyStateFileName), emergencyStateRecord{
		RemoteKills: kills,
		Rollbacks:   rollbacks,
	}); err != nil {
		t.Fatalf("writeEmergencyState: %v", err)
	}
	store, err := OpenFileEmergencyStore(dir)
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore(seeded): %v (load must tolerate a bad SIGNATURE; only raw corruption is fatal)", err)
	}
	return store
}

func defaultFollower() FollowerIdentity { return defaultFollowerIdentity() }

func defaultRollbackLookup() RollbackLookup {
	return RollbackLookup{CurrentBundleID: "bundle-current", CurrentVersion: 42, TargetBundleID: "bundle-target", TargetVersion: 41}
}

// 1 + 7. Forged-signature record at EVERY read path is dropped, and a flipped
// signature byte flips applied->quarantined. Asserts the forged record fails
// VerifySignaturesAt directly too.
func TestVerifiedEmergencyStore_ForgedRecordDroppedAtEveryReadPath(t *testing.T) {
	now := testNow
	legit, resolver := trustedRollbackRecord(t, "rollback-legit", 5, now)
	forged := forgedRollbackRecord(t, "rollback-forged", 9, now, false) // higher counter
	forgedKill := forgedRemoteKillRecord(t, "kill-forged", 9, now)
	legitKill, killResolver := func() (StoredRemoteKill, conductor.SignatureKeyResolver) {
		msg, r := signedRemoteKillMessageWithResolver(t, "kill-legit", 4, conductor.KillSwitchActive, now)
		return storedRemoteKill(t, msg, now), r
	}()

	// Sanity: the forged records genuinely fail signature verification.
	if err := forged.Authorization.VerifySignaturesAt(now, resolver); err == nil {
		t.Fatal("forged rollback VerifySignaturesAt() = nil, want failure")
	}
	if err := forgedKill.Message.VerifySignaturesAt(now, killResolver); err == nil {
		t.Fatal("forged kill VerifySignaturesAt() = nil, want failure")
	}

	dir := t.TempDir()
	store := seedEmergencyStateOnDisk(t, dir,
		[]StoredRemoteKill{legitKill, forgedKill},
		[]StoredRollbackAuthorization{legit, forged},
	)
	rec := &quarantineRecorder{}
	combined := composeResolvers(resolver, killResolver)
	v := newVerifiedEmergencyStore(store, combined, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), rec)

	ctx := context.Background()
	// LatestRemoteKill: only the legit kill survives.
	gotKill, err := v.LatestRemoteKill(ctx, defaultFollower(), now)
	if err != nil {
		t.Fatalf("LatestRemoteKill() error = %v", err)
	}
	if gotKill.Message.MessageID != "kill-legit" {
		t.Fatalf("LatestRemoteKill = %q, want kill-legit (forged higher-counter kill must not win)", gotKill.Message.MessageID)
	}
	// LatestRollbackAuthorization: only the legit rollback matches the lookup.
	gotRoll, err := v.LatestRollbackAuthorization(ctx, defaultFollower(), defaultRollbackLookup(), now)
	if err != nil {
		t.Fatalf("LatestRollbackAuthorization() error = %v", err)
	}
	if gotRoll.Authorization.AuthorizationID != "rollback-legit" {
		t.Fatalf("LatestRollbackAuthorization = %q, want rollback-legit", gotRoll.Authorization.AuthorizationID)
	}
	// ActiveRollbackForFollower: forged higher-counter rollback must not win.
	active, ok, err := v.ActiveRollbackForFollower(ctx, defaultFollower(), now)
	if err != nil || !ok {
		t.Fatalf("ActiveRollbackForFollower() ok=%v err=%v, want ok", ok, err)
	}
	if active.Authorization.AuthorizationID != "rollback-legit" {
		t.Fatalf("ActiveRollbackForFollower = %q, want rollback-legit (forged higher-counter rollback must not move the head)", active.Authorization.AuthorizationID)
	}
	// Enumeration paths (reconcile + stream-status) only see verified records.
	rolls, err := v.(*verifiedEmergencyStore).RollbackAuthorizations(ctx)
	if err != nil {
		t.Fatalf("RollbackAuthorizations() error = %v", err)
	}
	if len(rolls) != 1 || rolls[0].Authorization.AuthorizationID != "rollback-legit" {
		t.Fatalf("RollbackAuthorizations enumerated %d, want only rollback-legit", len(rolls))
	}
	kills, err := v.(*verifiedEmergencyStore).RemoteKills(ctx)
	if err != nil {
		t.Fatalf("RemoteKills() error = %v", err)
	}
	if len(kills) != 1 || kills[0].Message.MessageID != "kill-legit" {
		t.Fatalf("RemoteKills enumerated %d, want only kill-legit", len(kills))
	}
	if !rec.hasReason("signature_verification_failed") {
		t.Fatal("quarantine recorder missing signature_verification_failed event")
	}

	// Boundary (test 7): flip one signature byte of the LEGIT record -> it now
	// quarantines and no longer applies.
	tampered := legit
	tampered.Authorization.Signatures = flipLastSignatureByte(t, tampered.Authorization.Signatures)
	dir2 := t.TempDir()
	store2 := seedEmergencyStateOnDisk(t, dir2, nil, []StoredRollbackAuthorization{tampered})
	v2 := newVerifiedEmergencyStore(store2, resolver, nil, &quarantineRecorder{})
	if _, ok, err := v2.ActiveRollbackForFollower(ctx, defaultFollower(), now); err != nil || ok {
		t.Fatalf("ActiveRollbackForFollower(tampered) ok=%v err=%v, want no active rollback (flipped byte must quarantine)", ok, err)
	}
}

func flipLastSignatureByte(t *testing.T, sigs []conductor.SignatureProof) []conductor.SignatureProof {
	t.Helper()
	out := make([]conductor.SignatureProof, len(sigs))
	copy(out, sigs)
	// Decode the hex body after the ed25519: prefix, flip one byte, re-encode.
	raw := strings.TrimPrefix(out[0].Signature, conductor.SignaturePrefixEd25519)
	b, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode signature hex: %v", err)
	}
	b[len(b)-1] ^= 0x01
	out[0].Signature = conductor.SignaturePrefixEd25519 + hex.EncodeToString(b)
	return out
}

// 2. Legit signed record still applies/serves (no over-quarantine), proven via
// the full handler path: NewHandler wraps the store, reconcile applies the head.
func TestVerifiedEmergencyStore_LegitRecordStillApplies(t *testing.T) {
	store := mustStore(t)
	signer := newTestSigner(t)
	audience := conductor.Audience{InstanceIDs: []string{"*"}}
	v1 := signedControlBundle(t, signer, bundleSpec{id: "vstore-v1", version: 1, audience: audience})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1): %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id: "vstore-v2", version: 2, previousHash: r1.BundleHash, audience: audience,
		configYAML: "mode: strict\napi_allowlist:\n  - v2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2): %v", err)
	}
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "vstore-rollback", v2, v1, testNow)
	handler := newTestHandlerWithOptions(t, store, nil, resolver)
	if _, created, err := handler.emergencyControls.PublishRollbackAuthorization(t.Context(), auth, testNow); err != nil || !created {
		t.Fatalf("PublishRollbackAuthorization created=%v err=%v", created, err)
	}
	w := latestPolicyBundle(t, handler, nil)
	assertLatestBundleID(t, w, "vstore-v1")
}

// 3. A forged HIGH-counter record does not suppress a legit LOWER-counter
// control via newest-wins. (Covered for kills + rollbacks in test 1's
// selection asserts; this isolates the suppression attack explicitly.)
func TestVerifiedEmergencyStore_ForgedHighCounterDoesNotSuppressLegit(t *testing.T) {
	now := testNow
	legit, resolver := trustedRollbackRecord(t, "low-counter-legit", 2, now)
	forgedHigh := forgedRollbackRecord(t, "high-counter-forged", 1000, now, false)

	dir := t.TempDir()
	store := seedEmergencyStateOnDisk(t, dir, nil, []StoredRollbackAuthorization{forgedHigh, legit})
	v := newVerifiedEmergencyStore(store, resolver, nil, &quarantineRecorder{})

	active, ok, err := v.ActiveRollbackForFollower(context.Background(), defaultFollower(), now)
	if err != nil || !ok {
		t.Fatalf("ActiveRollbackForFollower ok=%v err=%v, want ok", ok, err)
	}
	if active.Authorization.AuthorizationID != "low-counter-legit" {
		t.Fatalf("active = %q, want low-counter-legit (forged counter=1000 must not suppress legit counter=2)", active.Authorization.AuthorizationID)
	}
}

// 4. Key-rotation quarantine: a record signed by K1 with a resolver that only
// knows K2 quarantines LOUDLY (distinct rotation reason) and does not crash.
func TestVerifiedEmergencyStore_KeyRotationQuarantineIsLoud(t *testing.T) {
	now := testNow
	// Record signed with IDs the resolver below does NOT know (rotated out).
	rotated := forgedRollbackRecord(t, "rotated-rollback", 3, now, true)
	// A resolver that knows only the canonical (now-rotated-out) IDs is absent;
	// build one that resolves a DIFFERENT key id set so every rotated id misses.
	_, k2Resolver := signedRollbackAuthorizationWithResolver(t, "k2-rollback", 1, now)

	dir := t.TempDir()
	store := seedEmergencyStateOnDisk(t, dir, nil, []StoredRollbackAuthorization{rotated})
	rec := &quarantineRecorder{}
	var logBuf bytes.Buffer
	v := newVerifiedEmergencyStore(store, k2Resolver, slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo})), rec)

	if _, ok, err := v.ActiveRollbackForFollower(context.Background(), defaultFollower(), now); err != nil || ok {
		t.Fatalf("ActiveRollbackForFollower ok=%v err=%v, want quarantined (no active)", ok, err)
	}
	if !rec.hasReason("untrusted_or_rotated_signer") {
		t.Fatal("rotation quarantine missing untrusted_or_rotated_signer reason")
	}
	if !strings.Contains(logBuf.String(), auditRollbackQuarantineRotation) {
		t.Fatalf("rotation quarantine not logged loudly: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "level=ERROR") {
		t.Fatalf("rotation quarantine not logged at ERROR (high severity): %s", logBuf.String())
	}
}

// 5. Restart-survival: a legit rollback applies and the durable head persists
// across a reopen + new Handler; injecting a forged record on disk then
// restarting quarantines it and leaves the head unchanged, no crash.
func TestVerifiedEmergencyStore_RestartSurvival(t *testing.T) {
	bundleDir := t.TempDir()
	emergencyDir := t.TempDir()
	store, err := OpenFileBundleStore(bundleDir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore: %v", err)
	}
	signer := newTestSigner(t)
	audience := conductor.Audience{InstanceIDs: []string{"*"}}
	v1 := signedControlBundle(t, signer, bundleSpec{id: "restart-v1", version: 1, audience: audience})
	r1, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1): %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id: "restart-v2", version: 2, previousHash: r1.BundleHash, audience: audience,
		configYAML: "mode: strict\napi_allowlist:\n  - restart2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(v2): %v", err)
	}
	emergency, err := OpenFileEmergencyStore(emergencyDir)
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore: %v", err)
	}
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "restart-rollback", v2, v1, testNow)
	verified := newVerifiedEmergencyStore(emergency, resolver, nil, &quarantineRecorder{})
	if _, created, err := verified.PublishRollbackAuthorization(t.Context(), auth, testNow); err != nil || !created {
		t.Fatalf("PublishRollbackAuthorization created=%v err=%v", created, err)
	}
	if err := reconcileRollbackHeads(store, verified, testNow, nil); err != nil {
		t.Fatalf("reconcile(first): %v", err)
	}
	latest, err := store.Latest(t.Context(), defaultFollower(), testNow)
	if err != nil {
		t.Fatalf("Latest(after apply): %v", err)
	}
	if latest.Bundle.BundleID != "restart-v1" {
		t.Fatalf("Latest after apply = %q, want restart-v1", latest.Bundle.BundleID)
	}

	// Inject a forged record straight onto disk, then restart (reopen store +
	// emergency + reconcile via a fresh verified view).
	forged := forgedRollbackRecord(t, "restart-forged", 999, testNow, false)
	existing, err := emergency.enumerateRollbacks(t.Context())
	if err != nil {
		t.Fatalf("enumerateRollbacks: %v", err)
	}
	if err := writeEmergencyState(filepath.Join(emergencyDir, emergencyStateFileName), emergencyStateRecord{
		Rollbacks: append(existing, forged),
	}); err != nil {
		t.Fatalf("inject forged onto disk: %v", err)
	}
	reopenStore, err := OpenFileBundleStore(bundleDir)
	if err != nil {
		t.Fatalf("reopen bundle store: %v", err)
	}
	reopenEmergency, err := OpenFileEmergencyStore(emergencyDir)
	if err != nil {
		t.Fatalf("reopen emergency (must tolerate forged signature at load): %v", err)
	}
	rec := &quarantineRecorder{}
	reopenVerified := newVerifiedEmergencyStore(reopenEmergency, resolver, nil, rec)
	if err := reconcileRollbackHeads(reopenStore, reopenVerified, testNow.Add(time.Hour), nil); err != nil {
		t.Fatalf("reconcile(after forged inject) error = %v (must not crash)", err)
	}
	latest2, err := reopenStore.Latest(t.Context(), defaultFollower(), testNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("Latest(after restart): %v", err)
	}
	if latest2.Bundle.BundleID != "restart-v1" {
		t.Fatalf("Latest after restart = %q, want restart-v1 (forged record must not move the head)", latest2.Bundle.BundleID)
	}
	if rec.count() == 0 {
		t.Fatal("forged record on restart did not quarantine")
	}
}

// 6. nil/empty resolver quarantines ALL records and does NOT crash startup.
func TestVerifiedEmergencyStore_NilResolverQuarantinesAll(t *testing.T) {
	now := testNow
	legit, _ := trustedRollbackRecord(t, "nilres-rollback", 1, now)
	kill, _ := signedRemoteKillMessageWithResolver(t, "nilres-kill", 1, conductor.KillSwitchActive, now)
	dir := t.TempDir()
	store := seedEmergencyStateOnDisk(t, dir,
		[]StoredRemoteKill{storedRemoteKill(t, kill, now)},
		[]StoredRollbackAuthorization{legit},
	)
	rec := &quarantineRecorder{}
	// nil resolver -> fail closed.
	v := newVerifiedEmergencyStore(store, nil, nil, rec)

	if _, _, err := v.ActiveRollbackForFollower(context.Background(), defaultFollower(), now); err != nil {
		t.Fatalf("ActiveRollbackForFollower(nil resolver) error = %v, want nil (no active, no crash)", err)
	}
	rolls, err := v.(*verifiedEmergencyStore).RollbackAuthorizations(context.Background())
	if err != nil {
		t.Fatalf("RollbackAuthorizations(nil resolver) error = %v", err)
	}
	if len(rolls) != 0 {
		t.Fatalf("RollbackAuthorizations(nil resolver) = %d, want 0 (all quarantined)", len(rolls))
	}
	kills, err := v.(*verifiedEmergencyStore).RemoteKills(context.Background())
	if err != nil {
		t.Fatalf("RemoteKills(nil resolver) error = %v", err)
	}
	if len(kills) != 0 {
		t.Fatalf("RemoteKills(nil resolver) = %d, want 0 (all quarantined)", len(kills))
	}
	if !rec.hasReason("nil_resolver") {
		t.Fatal("nil resolver quarantine missing nil_resolver reason")
	}

	// NewHandler with a nil EmergencyKeys must not crash (the #745 landmine).
	bundleStore := mustStore(t)
	handler, err := NewHandler(HandlerOptions{
		Store:              bundleStore,
		Capabilities:       DefaultCapabilities("conductor-test"),
		Now:                func() time.Time { return testNow },
		FollowerIdentity:   func(*http.Request) (FollowerIdentity, error) { return defaultFollowerIdentity(), nil },
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
		EmergencyControls:  store,
		EmergencyKeys:      nil,
	})
	if err != nil {
		t.Fatalf("NewHandler(nil EmergencyKeys) error = %v, want nil (must not crash)", err)
	}
	if handler == nil {
		t.Fatal("NewHandler returned nil handler")
	}
}

// 8. Idempotency: a second Handler/verified-view open over the same dir
// re-quarantines deterministically (same drop, same head).
func TestVerifiedEmergencyStore_IdempotentReQuarantine(t *testing.T) {
	now := testNow
	legit, resolver := trustedRollbackRecord(t, "idem-legit", 5, now)
	forged := forgedRollbackRecord(t, "idem-forged", 9, now, false)
	dir := t.TempDir()
	// Seed the disk state once; both opens below read the same bytes.
	seedEmergencyStateOnDisk(t, dir, nil, []StoredRollbackAuthorization{legit, forged})

	for i := range 2 {
		store, err := OpenFileEmergencyStore(dir)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		rec := &quarantineRecorder{}
		v := newVerifiedEmergencyStore(store, resolver, nil, rec)
		rolls, err := v.(*verifiedEmergencyStore).RollbackAuthorizations(context.Background())
		if err != nil {
			t.Fatalf("iter %d RollbackAuthorizations: %v", i, err)
		}
		if len(rolls) != 1 || rolls[0].Authorization.AuthorizationID != "idem-legit" {
			t.Fatalf("iter %d enumerated %d, want only idem-legit", i, len(rolls))
		}
		if rec.count() != 1 {
			t.Fatalf("iter %d quarantine count = %d, want exactly 1 (deterministic)", i, rec.count())
		}
	}
}

func TestVerifiedEmergencyStore_ReadPathValidationAndEnumerationFailures(t *testing.T) {
	now := testNow
	ctx := context.Background()

	errStore := newVerifiedEmergencyStore(erroringVerifiedEnumerators{}, nil, nil, nil)
	if _, err := errStore.LatestRemoteKill(ctx, defaultFollower(), now); err == nil || !strings.Contains(err.Error(), "enumerate remote kills failed") {
		t.Fatalf("LatestRemoteKill(enum error) err = %v, want enumerate remote kills failed", err)
	}
	if _, err := errStore.LatestRollbackAuthorization(ctx, defaultFollower(), defaultRollbackLookup(), now); err == nil || !strings.Contains(err.Error(), "enumerate rollbacks failed") {
		t.Fatalf("LatestRollbackAuthorization(enum error) err = %v, want enumerate rollbacks failed", err)
	}
	if _, _, err := errStore.ActiveRollbackForFollower(ctx, defaultFollower(), now); err == nil || !strings.Contains(err.Error(), "enumerate rollbacks failed") {
		t.Fatalf("ActiveRollbackForFollower(enum error) err = %v, want enumerate rollbacks failed", err)
	}

	empty := newVerifiedEmergencyStore(mustEmergencyStore(t), nil, nil, nil)
	if _, err := empty.LatestRemoteKill(ctx, FollowerIdentity{}, now); err == nil {
		t.Fatal("LatestRemoteKill(invalid follower) error = nil, want validation error")
	}
	if _, err := empty.LatestRemoteKill(ctx, defaultFollower(), time.Time{}); !errors.Is(err, ErrEmergencyNotFound) {
		t.Fatalf("LatestRemoteKill(zero time, no records) err = %v, want ErrEmergencyNotFound", err)
	}
	if _, err := empty.LatestRollbackAuthorization(ctx, FollowerIdentity{}, defaultRollbackLookup(), now); err == nil {
		t.Fatal("LatestRollbackAuthorization(invalid follower) error = nil, want validation error")
	}
	if _, err := empty.LatestRollbackAuthorization(ctx, defaultFollower(), RollbackLookup{}, now); err == nil {
		t.Fatal("LatestRollbackAuthorization(invalid lookup) error = nil, want validation error")
	}
	if _, err := empty.LatestRollbackAuthorization(ctx, defaultFollower(), defaultRollbackLookup(), time.Time{}); !errors.Is(err, ErrEmergencyNotFound) {
		t.Fatalf("LatestRollbackAuthorization(zero time, no records) err = %v, want ErrEmergencyNotFound", err)
	}
	if _, _, err := empty.ActiveRollbackForFollower(ctx, FollowerIdentity{}, now); err == nil {
		t.Fatal("ActiveRollbackForFollower(invalid follower) error = nil, want validation error")
	}
	if _, ok, err := empty.ActiveRollbackForFollower(ctx, defaultFollower(), time.Time{}); err != nil || ok {
		t.Fatalf("ActiveRollbackForFollower(zero time, no records) ok=%v err=%v, want no active and nil error", ok, err)
	}
}

func TestVerifiedEmergencyStore_SkipsInvalidVerifiedCandidates(t *testing.T) {
	now := testNow
	ctx := context.Background()

	expiredKill, expiredKillResolver := signedRemoteKillMessageWithResolver(t, "skip-expired-kill", 1, conductor.KillSwitchActive, now.Add(-48*time.Hour))
	scopedKill, scopedKillResolver := signedRemoteKillMessageWithResolver(t, "skip-scoped-kill", 2, conductor.KillSwitchActive, now)
	store := seedEmergencyStateOnDisk(t, t.TempDir(),
		[]StoredRemoteKill{storedRemoteKill(t, expiredKill, now), storedRemoteKill(t, scopedKill, now)},
		nil,
	)
	verified := newVerifiedEmergencyStore(store, composeResolvers(expiredKillResolver, scopedKillResolver), nil, nil)
	otherFollower := defaultFollower()
	otherFollower.InstanceID = "pl-prod-2"
	if _, err := verified.LatestRemoteKill(ctx, otherFollower, now); !errors.Is(err, ErrEmergencyNotFound) {
		t.Fatalf("LatestRemoteKill(skip expired/out-of-scope) err = %v, want ErrEmergencyNotFound", err)
	}
	scopedOnlyKill, scopedOnlyResolver := signedRemoteKillMessageWithResolver(t, "skip-scoped-only-kill", 1, conductor.KillSwitchActive, now)
	scopedOnlyStore := seedEmergencyStateOnDisk(t, t.TempDir(), []StoredRemoteKill{storedRemoteKill(t, scopedOnlyKill, now)}, nil)
	scopedOnlyVerified := newVerifiedEmergencyStore(scopedOnlyStore, scopedOnlyResolver, nil, nil)
	if _, err := scopedOnlyVerified.LatestRemoteKill(ctx, otherFollower, now); !errors.Is(err, ErrEmergencyNotFound) {
		t.Fatalf("LatestRemoteKill(single out-of-scope) err = %v, want ErrEmergencyNotFound", err)
	}

	mismatchLookup, resolver := trustedRollbackRecord(t, "skip-mismatch-lookup", 1, now)
	expiredAuth, expiredResolver := signedRollbackAuthorizationWithResolver(t, "skip-expired-auth", 2, now.Add(-48*time.Hour))
	scopedAuth, scopedResolver := signedRollbackAuthorizationWithResolver(t, "skip-scoped-auth", 3, now)
	rollbackStore := seedEmergencyStateOnDisk(t, t.TempDir(), nil, []StoredRollbackAuthorization{
		mismatchLookup,
		storedRollback(t, expiredAuth, now),
		storedRollback(t, scopedAuth, now),
	})
	rollbackVerified := newVerifiedEmergencyStore(rollbackStore, composeResolvers(resolver, expiredResolver, scopedResolver), nil, nil)
	lookup := RollbackLookup{CurrentBundleID: "other-current", CurrentVersion: 42, TargetBundleID: "bundle-target", TargetVersion: 41}
	if _, err := rollbackVerified.LatestRollbackAuthorization(ctx, defaultFollower(), lookup, now); !errors.Is(err, ErrEmergencyNotFound) {
		t.Fatalf("LatestRollbackAuthorization(skip mismatched lookup) err = %v, want ErrEmergencyNotFound", err)
	}
	otherOrg := defaultFollower()
	otherOrg.OrgID = "org-other"
	if _, err := rollbackVerified.LatestRollbackAuthorization(ctx, otherOrg, defaultRollbackLookup(), now); !errors.Is(err, ErrEmergencyNotFound) {
		t.Fatalf("LatestRollbackAuthorization(skip expired/out-of-org) err = %v, want ErrEmergencyNotFound", err)
	}
	if _, ok, err := rollbackVerified.ActiveRollbackForFollower(ctx, otherOrg, now); err != nil || ok {
		t.Fatalf("ActiveRollbackForFollower(skip expired/out-of-org) ok=%v err=%v, want no active", ok, err)
	}
	expiredOnlyAuth, expiredOnlyResolver := signedRollbackAuthorizationWithResolver(t, "skip-expired-only-auth", 1, now.Add(-48*time.Hour))
	expiredOnlyStore := seedEmergencyStateOnDisk(t, t.TempDir(), nil, []StoredRollbackAuthorization{storedRollback(t, expiredOnlyAuth, now)})
	expiredOnlyVerified := newVerifiedEmergencyStore(expiredOnlyStore, expiredOnlyResolver, nil, nil)
	if _, err := expiredOnlyVerified.LatestRollbackAuthorization(ctx, defaultFollower(), defaultRollbackLookup(), now); !errors.Is(err, ErrEmergencyNotFound) {
		t.Fatalf("LatestRollbackAuthorization(single expired) err = %v, want ErrEmergencyNotFound", err)
	}
	if _, ok, err := expiredOnlyVerified.ActiveRollbackForFollower(ctx, defaultFollower(), now); err != nil || ok {
		t.Fatalf("ActiveRollbackForFollower(single expired) ok=%v err=%v, want no active", ok, err)
	}

	noRemoteEnumerator := newVerifiedEmergencyStore(failingEmergencyStore{}, nil, nil, nil).(*verifiedEmergencyStore)
	kills, err := noRemoteEnumerator.verifiedRemoteKills(ctx, now)
	if err != nil || len(kills) != 0 {
		t.Fatalf("verifiedRemoteKills(no enumerator) len=%d err=%v, want empty nil", len(kills), err)
	}
}
