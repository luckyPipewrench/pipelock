// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
)

func TestFileAuditSpoolPersistsAcceptedBatch(t *testing.T) {
	spool, err := OpenFileAuditSpool(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileAuditSpool() error = %v", err)
	}
	payload := []byte(`{"entry":"ok"}`)
	batch := acceptedSpoolBatch(t, "batch-1", payload)
	if err := spool.IngestAuditBatch(context.Background(), batch); err != nil {
		t.Fatalf("IngestAuditBatch() error = %v", err)
	}
	payload[0] = '['

	data, err := os.ReadFile(filepath.Clean(filepath.Join(spool.dir, batch.EnvelopeHash+".json"))) //nolint:gosec // Test reads from a temp dir plus fixed hash filename.
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var got spooledAuditBatch
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Identity.InstanceID != "pl-prod-1" || string(got.Payload) != `{"entry":"ok"}` {
		t.Fatalf("spooled batch = %+v payload=%q", got.Identity, string(got.Payload))
	}
}

func TestFileAuditSpoolRejectsInvalidInput(t *testing.T) {
	spool, err := OpenFileAuditSpool(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileAuditSpool() error = %v", err)
	}
	if err := spool.IngestAuditBatch(context.Background(), AcceptedAuditBatch{EnvelopeHash: "bad"}); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("IngestAuditBatch(bad hash) error = %v, want ErrInvalidStoreRecord", err)
	}
	var nilCtx context.Context
	if err := spool.IngestAuditBatch(nilCtx, AcceptedAuditBatch{}); !errors.Is(err, ErrAuditSinkRequired) {
		t.Fatalf("IngestAuditBatch(nil context) error = %v, want ErrAuditSinkRequired", err)
	}
	if err := (*FileAuditSpool)(nil).IngestAuditBatch(context.Background(), AcceptedAuditBatch{}); !errors.Is(err, ErrAuditSinkRequired) {
		t.Fatalf("nil IngestAuditBatch error = %v, want ErrAuditSinkRequired", err)
	}
}

func TestFileAuditSpoolRejectsEnvelopeHashMismatch(t *testing.T) {
	spool, err := OpenFileAuditSpool(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileAuditSpool() error = %v", err)
	}
	batch := acceptedSpoolBatch(t, "batch-1", []byte(`{"entry":"ok"}`))
	batch.EnvelopeHash = strings.Repeat("f", 64)
	if err := spool.IngestAuditBatch(context.Background(), batch); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("IngestAuditBatch(hash mismatch) error = %v, want ErrInvalidStoreRecord", err)
	}
}

// TestFileAuditSpoolRejectsCorruptedIdentity asserts the defensive identity
// re-validation in IngestAuditBatch fires when an authenticated-then-validated
// identity later carries forbidden bytes (defense-in-depth against a future
// resolver that bypasses canonical identifier checks).
func TestFileAuditSpoolRejectsCorruptedIdentity(t *testing.T) {
	spool, err := OpenFileAuditSpool(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileAuditSpool() error = %v", err)
	}
	hash := strings.Repeat("a", 64)
	for _, c := range []struct {
		name     string
		identity FollowerIdentity
	}{
		{"null byte in org", FollowerIdentity{OrgID: "org\x00main", FleetID: "prod", InstanceID: "pl-prod-1", Environment: "prod"}},
		{"slash in instance", FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl/prod-1", Environment: "prod"}},
		{"empty environment", FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1"}},
		{"leading dash on fleet", FollowerIdentity{OrgID: "org-main", FleetID: "-prod", InstanceID: "pl-prod-1", Environment: "prod"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := spool.IngestAuditBatch(context.Background(), AcceptedAuditBatch{
				Identity:     c.identity,
				EnvelopeHash: hash,
				Payload:      []byte("{}"),
				ReceivedAt:   testNow,
			})
			if !errors.Is(err, ErrFollowerRequired) {
				t.Fatalf("IngestAuditBatch(%s) error = %v, want ErrFollowerRequired", c.name, err)
			}
		})
	}
}

// TestFileAuditSpoolFileMode asserts spool files land at 0o600 since they
// contain audit payloads that may include sensitive follower telemetry.
func TestFileAuditSpoolFileMode(t *testing.T) {
	spool, err := OpenFileAuditSpool(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileAuditSpool() error = %v", err)
	}
	batch := acceptedSpoolBatch(t, "batch-1", []byte(`{"ok":true}`))
	if err := spool.IngestAuditBatch(context.Background(), batch); err != nil {
		t.Fatalf("IngestAuditBatch() error = %v", err)
	}
	info, err := os.Stat(filepath.Clean(filepath.Join(spool.dir, batch.EnvelopeHash+".json"))) //nolint:gosec // Test reads from a temp dir plus fixed hash filename.
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("spool file mode = %v, want 0o600", info.Mode().Perm())
	}
}

func acceptedSpoolBatch(t *testing.T, batchID string, payload []byte) AcceptedAuditBatch {
	t.Helper()
	identity := FollowerIdentity{
		OrgID:       "org-main",
		FleetID:     "prod",
		InstanceID:  "pl-prod-1",
		Environment: "prod",
	}
	envelope := conductor.AuditBatchEnvelope{
		BatchID:    batchID,
		OrgID:      identity.OrgID,
		FleetID:    identity.FleetID,
		InstanceID: identity.InstanceID,
	}
	hash, err := envelope.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash() error = %v", err)
	}
	return AcceptedAuditBatch{
		Identity:     identity,
		Envelope:     envelope,
		EnvelopeHash: hash,
		Payload:      payload,
		ReceivedAt:   testNow,
	}
}
