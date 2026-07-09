//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func newAppliedStateProducer(t *testing.T, cfg ProducerConfig) (*Producer, *Queue, ed25519.PublicKey) {
	t.Helper()
	auditPub, auditPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey audit: %v", err)
	}
	recorderPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey recorder: %v", err)
	}
	q, err := Open(Config{Dir: filepath.Join(t.TempDir(), "queue")})
	if err != nil {
		t.Fatalf("Open queue: %v", err)
	}
	cfg.Queue = q
	cfg.OrgID = "org-main"
	cfg.FleetID = "prod"
	cfg.InstanceID = "pl-prod-1"
	cfg.AuditSignerKeyID = "audit-key-1"
	cfg.RecorderKeyID = "recorder-key-1"
	cfg.AuditSigner = auditPriv
	cfg.RecorderPublicKey = recorderPub
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC) }
	}
	producer, err := NewProducer(cfg)
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	t.Cleanup(func() { _ = producer.Close() })
	return producer, q, auditPub
}

func claimOneBatch(t *testing.T, q *Queue, producer *Producer, auditPub ed25519.PublicKey) Batch {
	t.Helper()
	for _, entry := range checkpointSegment(0) {
		producer.ObserveRecorderEntry(entry)
	}
	waitForPending(t, q, producer, 1)
	lease, err := q.Claim()
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	batch := lease.Batch
	if err := batch.Envelope.VerifySignatures(func(id string) (conductor.SignatureKey, error) {
		if id != "audit-key-1" {
			return conductor.SignatureKey{}, errors.New("unknown key")
		}
		return conductor.SignatureKey{PublicKey: auditPub, KeyPurpose: signing.PurposeAuditBatchSigning}, nil
	}); err != nil {
		t.Fatalf("VerifySignatures: %v", err)
	}
	return batch
}

func TestProducer_EmitsSignedAppliedStateWhenEnabled(t *testing.T) {
	want := conductor.FollowerAppliedState{
		ActiveBundleID:      "bundle-active-9",
		ActiveBundleVersion: 9,
		PipelockVersion:     "3.1.0",
		ObservedAt:          time.Date(2026, 5, 24, 11, 59, 0, 0, time.UTC),
	}
	producer, q, auditPub := newAppliedStateProducer(t, ProducerConfig{
		EmitAppliedState:     true,
		AppliedStateProvider: func() (conductor.FollowerAppliedState, bool) { return want, true },
	})
	batch := claimOneBatch(t, q, producer, auditPub)
	if batch.Envelope.AppliedState == nil {
		t.Fatal("AppliedState = nil, want present")
	}
	if batch.Envelope.AppliedState.ActiveBundleID != want.ActiveBundleID ||
		batch.Envelope.AppliedState.ActiveBundleVersion != want.ActiveBundleVersion {
		t.Fatalf("AppliedState = %+v, want %+v", *batch.Envelope.AppliedState, want)
	}
	// Signature already verified in claimOneBatch, which proves it covers the
	// applied-state (it is inside SignablePreimage).
}

func TestProducer_StampsObservedAtWhenProviderLeavesZero(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	producer, q, auditPub := newAppliedStateProducer(t, ProducerConfig{
		Now:              func() time.Time { return now },
		EmitAppliedState: true,
		AppliedStateProvider: func() (conductor.FollowerAppliedState, bool) {
			return conductor.FollowerAppliedState{PipelockVersion: "3.1.0"}, true
		},
	})
	batch := claimOneBatch(t, q, producer, auditPub)
	if batch.Envelope.AppliedState == nil {
		t.Fatal("AppliedState = nil, want present")
	}
	if !batch.Envelope.AppliedState.ObservedAt.Equal(now) {
		t.Fatalf("ObservedAt = %v, want stamped %v", batch.Envelope.AppliedState.ObservedAt, now)
	}
}

func TestProducer_OmitsAppliedStateWhenDisabled(t *testing.T) {
	producer, q, auditPub := newAppliedStateProducer(t, ProducerConfig{
		EmitAppliedState: false, // v1 conductor / negotiation off
		AppliedStateProvider: func() (conductor.FollowerAppliedState, bool) {
			return conductor.FollowerAppliedState{ObservedAt: time.Now().UTC()}, true
		},
	})
	batch := claimOneBatch(t, q, producer, auditPub)
	if batch.Envelope.AppliedState != nil {
		t.Fatalf("AppliedState = %+v, want nil (emit disabled)", *batch.Envelope.AppliedState)
	}
}

func TestProducer_OmitsAppliedStateWhenProviderNotOK(t *testing.T) {
	producer, q, auditPub := newAppliedStateProducer(t, ProducerConfig{
		EmitAppliedState: true,
		AppliedStateProvider: func() (conductor.FollowerAppliedState, bool) {
			return conductor.FollowerAppliedState{}, false
		},
	})
	batch := claimOneBatch(t, q, producer, auditPub)
	if batch.Envelope.AppliedState != nil {
		t.Fatalf("AppliedState = %+v, want nil (provider not ok)", *batch.Envelope.AppliedState)
	}
}

func TestProducer_OmitsAppliedStateWhenProviderNil(t *testing.T) {
	producer, q, auditPub := newAppliedStateProducer(t, ProducerConfig{
		EmitAppliedState:     true,
		AppliedStateProvider: nil,
	})
	batch := claimOneBatch(t, q, producer, auditPub)
	if batch.Envelope.AppliedState != nil {
		t.Fatalf("AppliedState = %+v, want nil (nil provider)", *batch.Envelope.AppliedState)
	}
}
