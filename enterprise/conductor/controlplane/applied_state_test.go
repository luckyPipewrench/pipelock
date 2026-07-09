//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func validTestAppliedState(observedAt time.Time) conductor.FollowerAppliedState {
	return conductor.FollowerAppliedState{
		ActiveBundleID:                 "bundle-active-1",
		ActiveBundleVersion:            7,
		ActiveBundleHash:               strings.Repeat("ab", 32),
		ActiveBundleMinPipelockVersion: "3.0.0",
		PipelockVersion:                "3.1.0",
		LastPolicyPollAt:               observedAt,
		LastSuccessfulApplyAt:          observedAt,
		ObservedAt:                     observedAt,
	}
}

// appliedStateBatch builds an AcceptedAuditBatch carrying the given applied-state
// (nil for a v1 batch). When manualSign is true the envelope is signed WITHOUT
// SignEnvelope's Validate gate, so a malformed applied-state can be injected to
// exercise the ingest fail-closed path.
func appliedStateBatch(t *testing.T, identity FollowerIdentity, batchID string, seqStart, seqEnd uint64, applied *conductor.FollowerAppliedState, manualSign bool) AcceptedAuditBatch {
	t.Helper()
	auditPub, auditPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(audit): %v", err)
	}
	_ = auditPub
	recorderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(recorder): %v", err)
	}
	payload := []byte(`{"event":"ok"}`)
	sum := sha256.Sum256(payload)
	envelope := conductor.AuditBatchEnvelope{
		SchemaVersion:      conductor.SchemaVersion,
		BatchID:            batchID,
		OrgID:              identity.OrgID,
		FleetID:            identity.FleetID,
		InstanceID:         identity.InstanceID,
		AuditSchemaVersion: conductor.SchemaVersion,
		EmittedAt:          testNow,
		SeqStart:           seqStart,
		SeqEnd:             seqEnd,
		EventCount:         seqEnd - seqStart + 1,
		PayloadSHA256:      hex.EncodeToString(sum[:]),
		PayloadBytes:       uint64(len(payload)),
		Chain: conductor.EvidenceChain{
			EntryVersion:           2,
			SegmentID:              "segment-1",
			SeqStart:               seqStart,
			SeqEnd:                 seqEnd,
			SegmentHeadHash:        auditStoreHash("head", batchID),
			SegmentTailHash:        auditStoreHash("tail", batchID),
			CheckpointSeq:          seqEnd,
			CheckpointHash:         auditStoreHash("checkpoint", batchID),
			CheckpointSignature:    conductor.SignaturePrefixEd25519 + strings.Repeat("a", 128),
			CheckpointSignerKeyID:  "receipt-key-1",
			FollowerRecorderKeyID:  "recorder-key-1",
			FollowerRecorderPubHex: hex.EncodeToString(recorderPub),
		},
		AppliedState: applied,
	}
	if manualSign {
		preimage, err := envelope.SignablePreimage()
		if err != nil {
			t.Fatalf("SignablePreimage: %v", err)
		}
		sig := ed25519.Sign(auditPriv, preimage)
		envelope.Signatures = []conductor.SignatureProof{{
			SignerKeyID: testAuditKeyID,
			KeyPurpose:  signing.PurposeAuditBatchSigning,
			Algorithm:   conductor.SignatureAlgorithmEd25519,
			Signature:   conductor.SignaturePrefixEd25519 + hex.EncodeToString(sig),
		}}
	} else {
		signed, err := auditbatcher.SignEnvelope(envelope, testAuditKeyID, auditPriv)
		if err != nil {
			t.Fatalf("SignEnvelope: %v", err)
		}
		envelope = signed
	}
	envelopeHash, err := envelope.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	return AcceptedAuditBatch{
		Identity:     identity,
		Envelope:     envelope,
		EnvelopeHash: envelopeHash,
		Payload:      append([]byte(nil), payload...),
		ReceivedAt:   testNow.Add(time.Second),
	}
}

func TestSQLiteAuditStore_VerifiedAppliedStateUpsertGetList(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()
	id := defaultFollowerIdentity()
	applied := validTestAppliedState(testNow)
	batch := appliedStateBatch(t, id, "audit-batch-applied-1", 10, 10, &applied, false)

	if _, err := store.put(context.Background(), batch); err != nil {
		t.Fatalf("put() error = %v", err)
	}

	got, ok, err := store.GetVerifiedAppliedState(context.Background(), id.OrgID, id.FleetID, id.InstanceID)
	if err != nil || !ok {
		t.Fatalf("GetVerifiedAppliedState() ok=%v err=%v", ok, err)
	}
	if !got.Verified {
		t.Fatal("Verified = false, want true")
	}
	if got.AppliedState.ActiveBundleID != applied.ActiveBundleID || got.AppliedState.ActiveBundleVersion != applied.ActiveBundleVersion {
		t.Fatalf("applied-state = %+v", got.AppliedState)
	}
	if got.BatchID != batch.Envelope.BatchID || got.EnvelopeHash != batch.EnvelopeHash {
		t.Fatalf("provenance mismatch: batch=%q hash=%q", got.BatchID, got.EnvelopeHash)
	}
	if got.SignerKeyID != testAuditKeyID {
		t.Fatalf("SignerKeyID = %q, want %q", got.SignerKeyID, testAuditKeyID)
	}
	if !got.VerifiedAt.Equal(batch.ReceivedAt) {
		t.Fatalf("VerifiedAt = %v, want %v", got.VerifiedAt, batch.ReceivedAt)
	}

	list, err := store.ListVerifiedAppliedState(context.Background(), VerifiedAppliedStateQuery{OrgID: id.OrgID, FleetID: id.FleetID})
	if err != nil {
		t.Fatalf("ListVerifiedAppliedState() error = %v", err)
	}
	if len(list) != 1 || list[0].InstanceID != id.InstanceID {
		t.Fatalf("list = %+v", list)
	}
}

// TestSQLiteAuditStore_NilAppliedStateStoresNoRow pins invariant #3: a v1 batch
// (no applied_state) is accepted but records no verified applied-state, so the
// fleet view falls back to the unsigned path for that follower.
func TestSQLiteAuditStore_NilAppliedStateStoresNoRow(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()
	id := defaultFollowerIdentity()
	batch := appliedStateBatch(t, id, "audit-batch-v1", 10, 10, nil, false)
	if _, err := store.put(context.Background(), batch); err != nil {
		t.Fatalf("put() error = %v", err)
	}
	if _, ok, err := store.GetVerifiedAppliedState(context.Background(), id.OrgID, id.FleetID, id.InstanceID); err != nil || ok {
		t.Fatalf("GetVerifiedAppliedState() ok=%v err=%v, want ok=false", ok, err)
	}
}

// TestSQLiteAuditStore_MalformedAppliedStateFailsClosed proves a batch whose
// applied-state fails validation is rejected whole (fail-closed) and stores
// nothing, even when its signature is otherwise well-formed.
func TestSQLiteAuditStore_MalformedAppliedStateFailsClosed(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()
	id := defaultFollowerIdentity()
	malformed := validTestAppliedState(testNow)
	malformed.ObservedAt = time.Time{} // present but missing required field
	batch := appliedStateBatch(t, id, "audit-batch-bad", 10, 10, &malformed, true)

	_, err := store.put(context.Background(), batch)
	if !errors.Is(err, conductor.ErrMissingField) {
		t.Fatalf("put() = %v, want ErrMissingField (fail-closed)", err)
	}
	if _, ok, _ := store.GetVerifiedAppliedState(context.Background(), id.OrgID, id.FleetID, id.InstanceID); ok {
		t.Fatal("malformed applied-state must not be stored")
	}
	// The batch itself must also not have been recorded.
	if _, ok, _ := store.GetAuditBatch(context.Background(), id.OrgID, id.FleetID, id.InstanceID, "audit-batch-bad"); ok {
		t.Fatal("rejected batch must not be stored")
	}
}

// TestSQLiteAuditStore_AppliedStateMonotonicAndIdempotent proves an older
// out-of-order batch never rolls the stored applied-state backward, and a
// byte-identical retry is a no-op.
func TestSQLiteAuditStore_AppliedStateMonotonicAndIdempotent(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()
	id := defaultFollowerIdentity()

	newer := validTestAppliedState(testNow.Add(time.Second))
	newer.ActiveBundleVersion = 9
	newerBatch := appliedStateBatch(t, id, "audit-batch-newer", 20, 20, &newer, false)
	if _, err := store.put(context.Background(), newerBatch); err != nil {
		t.Fatalf("put(newer) error = %v", err)
	}

	older := validTestAppliedState(testNow)
	older.ActiveBundleVersion = 3
	olderBatch := appliedStateBatch(t, id, "audit-batch-older", 10, 10, &older, false)
	if _, err := store.put(context.Background(), olderBatch); err != nil {
		t.Fatalf("put(older) error = %v", err)
	}

	got, ok, err := store.GetVerifiedAppliedState(context.Background(), id.OrgID, id.FleetID, id.InstanceID)
	if err != nil || !ok {
		t.Fatalf("GetVerifiedAppliedState() ok=%v err=%v", ok, err)
	}
	if got.AppliedState.ActiveBundleVersion != 9 || got.BatchID != "audit-batch-newer" {
		t.Fatalf("older batch rolled applied-state backward: %+v (batch %q)", got.AppliedState, got.BatchID)
	}

	// Idempotent retry of the newer batch: still one row, unchanged.
	if _, err := store.put(context.Background(), newerBatch); err != nil {
		t.Fatalf("put(newer retry) error = %v", err)
	}
	list, err := store.ListVerifiedAppliedState(context.Background(), VerifiedAppliedStateQuery{OrgID: id.OrgID})
	if err != nil {
		t.Fatalf("ListVerifiedAppliedState() error = %v", err)
	}
	if len(list) != 1 || list[0].AppliedState.ActiveBundleVersion != 9 {
		t.Fatalf("idempotent retry changed store: %+v", list)
	}

	sameObserved := validTestAppliedState(newer.ObservedAt)
	sameObserved.ActiveBundleVersion = 4
	sameObservedBatch := appliedStateBatch(t, id, "audit-batch-same-observed", 30, 30, &sameObserved, false)
	if _, err := store.put(context.Background(), sameObservedBatch); err != nil {
		t.Fatalf("put(same observed_at) error = %v", err)
	}
	got, ok, err = store.GetVerifiedAppliedState(context.Background(), id.OrgID, id.FleetID, id.InstanceID)
	if err != nil || !ok {
		t.Fatalf("GetVerifiedAppliedState() after same observed_at ok=%v err=%v", ok, err)
	}
	if got.AppliedState.ActiveBundleVersion != 9 || got.BatchID != "audit-batch-newer" {
		t.Fatalf("same observed_at batch replaced applied-state: %+v (batch %q)", got.AppliedState, got.BatchID)
	}
}

func TestSQLiteAuditStore_FutureAppliedStateObservedAtFailsClosed(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()
	id := defaultFollowerIdentity()

	applied := validTestAppliedState(testNow.Add(conductor.DefaultAuditMaxSkew + 2*time.Second))
	batch := appliedStateBatch(t, id, "audit-batch-future-applied-state", 10, 10, &applied, false)
	_, err := store.IngestAuditBatch(context.Background(), batch)
	if !errors.Is(err, conductor.ErrSkewExceeded) {
		t.Fatalf("IngestAuditBatch() error = %v, want ErrSkewExceeded", err)
	}
	if _, ok, _ := store.GetVerifiedAppliedState(context.Background(), id.OrgID, id.FleetID, id.InstanceID); ok {
		t.Fatal("future-dated applied-state must not be stored")
	}
}

// TestEnrichFollowerStatusPrefersSignedAppliedState drives the fleet-overview
// read path end to end: a follower with a verified applied-state row surfaces
// signed_applied_state; a follower without one does not.
func TestEnrichFollowerStatusPrefersSignedAppliedState(t *testing.T) {
	store := openTestSQLiteAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer func() { _ = store.Close() }()
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	signedFollower := FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1", Environment: "prod"}
	unsignedFollower := FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-2", Environment: "prod"}
	mustEnrollFollower(t, enrollments, "tok-main-1", signedFollower, "audit-key-main-1")
	mustEnrollFollower(t, enrollments, "tok-main-2", unsignedFollower, "audit-key-main-2")

	applied := validTestAppliedState(testNow)
	batch := appliedStateBatch(t, signedFollower, "audit-batch-applied-1", 10, 10, &applied, false)
	if _, err := store.put(context.Background(), batch); err != nil {
		t.Fatalf("put() error = %v", err)
	}

	handler := newAppliedStateFleetHandler(t, enrollments, store)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, FollowersPath+"?org_id=org-main", nil)
	req.Header.Set("Authorization", "Bearer "+followerAdminToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp listFollowersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var sawSigned, sawUnsigned bool
	for _, f := range resp.Followers {
		switch f.InstanceID {
		case "pl-prod-1":
			sawSigned = true
			if f.SignedAppliedState == nil {
				t.Fatal("pl-prod-1 should have signed_applied_state")
			}
			if !f.SignedAppliedState.Verified || f.SignedAppliedState.AppliedState.ActiveBundleID != applied.ActiveBundleID {
				t.Fatalf("signed applied-state = %+v", f.SignedAppliedState)
			}
		case "pl-prod-2":
			sawUnsigned = true
			if f.SignedAppliedState != nil {
				t.Fatalf("pl-prod-2 should have no signed_applied_state, got %+v", f.SignedAppliedState)
			}
		}
	}
	if !sawSigned || !sawUnsigned {
		t.Fatalf("missing followers in response: %+v", resp.Followers)
	}
}

func newAppliedStateFleetHandler(t *testing.T, enrollments EnrollmentStore, sink AuditBatchSink) *Handler {
	t.Helper()
	followerAuth, err := ScopedBearerFollowerListAuthorizer([]ScopedBearerCredential{
		{Token: followerAdminToken, Role: RoleAdmin, OrgID: "org-main"},
	})
	if err != nil {
		t.Fatalf("ScopedBearerFollowerListAuthorizer() error = %v", err)
	}
	adminAuth, err := ScopedBearerAdminAuthorizer([]ScopedBearerCredential{
		{Token: followerAdminToken, Role: RoleAdmin, OrgID: "org-main"},
	})
	if err != nil {
		t.Fatalf("ScopedBearerAdminAuthorizer() error = %v", err)
	}
	handler, err := NewHandler(HandlerOptions{
		Store:              mustStore(t),
		Capabilities:       DefaultCapabilities("conductor-test"),
		Now:                func() time.Time { return testNow },
		FollowerIdentity:   func(*http.Request) (FollowerIdentity, error) { return defaultFollowerIdentity(), nil },
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuthorizeFollowers: followerAuth,
		AuthorizeAdmin:     adminAuth,
		AuditSink:          sink,
		AuditKeys:          rejectingAuditKeyResolver,
		Enrollments:        enrollments,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}
