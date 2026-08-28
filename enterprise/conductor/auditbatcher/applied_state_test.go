//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sync/atomic"
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
	q, err := testOpen(t, Config{Dir: filepath.Join(t.TempDir(), "queue")})
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

func TestSignAppliedStateHeartbeat(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	heartbeat := conductor.AppliedStateHeartbeat{
		SchemaVersion: conductor.SchemaVersion,
		HeartbeatID:   "state-1",
		OrgID:         "org-main",
		FleetID:       "prod",
		InstanceID:    "pl-prod-1",
		EmittedAt:     now,
		AppliedState: conductor.FollowerAppliedState{
			PipelockVersion:       "3.1.0",
			LastPolicyPollAt:      now,
			LastSuccessfulApplyAt: now,
			ObservedAt:            now,
			ProvenanceAt:          now,
		},
	}
	signed, err := SignAppliedStateHeartbeat(heartbeat, "audit-key-1", priv)
	if err != nil {
		t.Fatalf("SignAppliedStateHeartbeat: %v", err)
	}
	if err := signed.VerifySignaturesAt(now, func(id string) (conductor.SignatureKey, error) {
		if id != "audit-key-1" {
			return conductor.SignatureKey{}, errors.New("unknown key")
		}
		return conductor.SignatureKey{PublicKey: pub, KeyPurpose: signing.PurposeAuditBatchSigning}, nil
	}); err != nil {
		t.Fatalf("VerifySignaturesAt: %v", err)
	}
	if _, err := SignAppliedStateHeartbeat(heartbeat, "audit-key-1", ed25519.PrivateKey("short")); err == nil {
		t.Fatal("SignAppliedStateHeartbeat(short key) = nil error")
	}
	if _, err := SignAppliedStateHeartbeat(heartbeat, "bad key id", priv); err == nil {
		t.Fatal("SignAppliedStateHeartbeat(bad signer id) = nil error")
	}
	heartbeat.AppliedState.ProvenanceAt = time.Time{}
	if _, err := SignAppliedStateHeartbeat(heartbeat, "audit-key-1", priv); err == nil {
		t.Fatal("SignAppliedStateHeartbeat(missing provenance) = nil error")
	}
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

func TestProducer_AppliedStateHeartbeatRunsIdleAndStopsOnClose(t *testing.T) {
	fired := make(chan struct{}, 1)
	var count atomic.Int64
	producer, _, _ := newAppliedStateProducer(t, ProducerConfig{
		EmitAppliedState:          true,
		EmitAppliedStateHeartbeat: true,
		HeartbeatInterval:         10 * time.Millisecond,
		AppliedStateHeartbeat: func(context.Context) error {
			count.Add(1)
			select {
			case fired <- struct{}{}:
			default:
			}
			return nil
		},
	})
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("idle applied-state heartbeat did not fire")
	}
	if err := producer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	closedCount := count.Load()
	select {
	case <-producer.heartbeatDone:
	default:
		t.Fatal("heartbeat goroutine still running after Close")
	}
	if count.Load() != closedCount {
		t.Fatalf("applied-state heartbeat count advanced after close: %d -> %d", closedCount, count.Load())
	}
}

func TestProducer_AppliedStateHeartbeatDisabledWithoutNegotiation(t *testing.T) {
	fired := make(chan struct{}, 1)
	producer, _, _ := newAppliedStateProducer(t, ProducerConfig{
		// Audit schema v2 enables batch applied-state, but only v3 enables the
		// recorder-independent heartbeat.
		EmitAppliedState:  true,
		HeartbeatInterval: time.Millisecond,
		AppliedStateHeartbeat: func(context.Context) error {
			fired <- struct{}{}
			return nil
		},
	})
	<-producer.heartbeatDone
	select {
	case <-fired:
		t.Fatal("unnegotiated applied-state heartbeat fired")
	default:
	}
	if err := producer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestProducer_CloseCancelsActiveAppliedStateHeartbeat(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	producer, _, _ := newAppliedStateProducer(t, ProducerConfig{
		EmitAppliedStateHeartbeat: true,
		HeartbeatInterval:         time.Millisecond,
		AppliedStateHeartbeat: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(canceled)
			return ctx.Err()
		},
	})
	<-started
	if err := producer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-canceled:
	default:
		t.Fatal("active heartbeat context was not canceled by Close")
	}
}
