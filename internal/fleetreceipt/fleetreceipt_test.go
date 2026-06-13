// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package fleetreceipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	testReportID  = "01934e1c-cd60-7abc-823a-d6f5e6f7a8b9"
	testTimestamp = "2026-06-13T12:00:00Z"
)

func TestSignAndVerifyFleetReceipt(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyID := hex.EncodeToString(pub)
	env, err := SignStatement(testStatement(), keyID, priv)
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	raw, err := MarshalEnvelope(env)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	got, err := Verify(raw, map[string]ed25519.PublicKey{keyID: pub})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !got.Trusted || got.Unpinned {
		t.Fatalf("trusted/unpinned = %v/%v, want true/false", got.Trusted, got.Unpinned)
	}
	if got.SignerKeyID != keyID {
		t.Fatalf("SignerKeyID = %q, want %q", got.SignerKeyID, keyID)
	}
	if got.SourceBatches != 2 || got.TotalActions != 3 || got.MediatedFraction != "1" {
		t.Fatalf("summary = batches %d actions %d fraction %q", got.SourceBatches, got.TotalActions, got.MediatedFraction)
	}
}

func TestVerifyFleetReceipt_UnpinnedUsesKeyIDButReportsIt(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	env, err := SignStatement(testStatement(), hex.EncodeToString(pub), priv)
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	raw, err := MarshalEnvelope(env)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	got, err := Verify(raw, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Trusted || !got.Unpinned {
		t.Fatalf("trusted/unpinned = %v/%v, want false/true", got.Trusted, got.Unpinned)
	}
}

func TestVerifyFleetReceiptRejectsWrongTrustedKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey other: %v", err)
	}
	keyID := hex.EncodeToString(pub)
	env, err := SignStatement(testStatement(), keyID, priv)
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	raw, err := MarshalEnvelope(env)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	_, err = Verify(raw, map[string]ed25519.PublicKey{keyID: otherPub})
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("Verify error = %v, want signature failure", err)
	}
}

func TestVerifyFleetReceiptRejectsWrongKeyPurpose(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyID := hex.EncodeToString(pub)
	env, err := SignStatement(testStatement(), keyID, priv)
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	env.Signatures[0].KeyPurpose = signing.PurposeAuditBatchSigning.String()
	raw, err := MarshalEnvelope(env)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	_, err = Verify(raw, map[string]ed25519.PublicKey{keyID: pub})
	if err == nil || !strings.Contains(err.Error(), "key_purpose") {
		t.Fatalf("Verify error = %v, want key_purpose failure", err)
	}
}

func TestVerifyFleetReceiptRejectsTamperedPayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyID := hex.EncodeToString(pub)
	env, err := SignStatement(testStatement(), keyID, priv)
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	payload = []byte(strings.Replace(string(payload), `"totalActions":3`, `"totalActions":4`, 1))
	env.Payload = base64.StdEncoding.EncodeToString(payload)
	raw, err := MarshalEnvelope(env)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	_, err = Verify(raw, map[string]ed25519.PublicKey{keyID: pub})
	if err == nil || !strings.Contains(err.Error(), "summary.") {
		t.Fatalf("Verify error = %v, want predicate arithmetic failure", err)
	}
}

func TestStatementValidateRejectsDuplicateAndReorderedBatches(t *testing.T) {
	base := testStatement()
	tests := []struct {
		name string
		edit func(*Statement)
		want string
	}{
		{
			name: "duplicate",
			edit: func(s *Statement) {
				s.Predicate.SourceBatches = append(s.Predicate.SourceBatches, s.Predicate.SourceBatches[0])
			},
			want: "duplicate source batch",
		},
		{
			name: "reordered",
			edit: func(s *Statement) {
				s.Predicate.SourceBatches[1].SeqStart = 1
			},
			want: "overlap or are reordered",
		},
		{
			name: "fraction_not_decimal",
			edit: func(s *Statement) {
				s.Predicate.Completeness.MediatedFraction = "1/2"
			},
			want: "decimal string",
		},
		{
			name: "fraction_above_one",
			edit: func(s *Statement) {
				s.Predicate.Completeness.MediatedFraction = "1.2"
			},
			want: "between 0 and 1",
		},
		{
			name: "fraction_arithmetic_mismatch",
			edit: func(s *Statement) {
				s.Predicate.Completeness.MediatedActions = 1
				s.Predicate.Completeness.MediatedFraction = "1"
			},
			want: "completeness.mediatedFraction",
		},
		{
			name: "summary_dimension_total_mismatch",
			edit: func(s *Statement) {
				s.Predicate.Summary.ByTransport = map[string]uint64{"fetch": 2}
			},
			want: "summary.byTransport totals",
		},
		{
			name: "source_batch_wrong_fleet",
			edit: func(s *Statement) {
				s.Predicate.SourceBatches[0].FleetID = "other-fleet"
			},
			want: "belongs to",
		},
		{
			name: "l2_reserved_until_replay_verifier",
			edit: func(s *Statement) {
				s.Predicate.VerificationLevel = "L2"
			},
			want: "verificationLevel",
		},
		{
			name: "subject_digest_mismatch",
			edit: func(s *Statement) {
				s.Subject[0].Digest.SHA256 = hex64("not-the-envelope")
			},
			want: "digest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt := base
			stmt.Predicate.SourceBatches = append([]SourceBatch(nil), base.Predicate.SourceBatches...)
			stmt.Subject = append([]Subject(nil), base.Subject...)
			tt.edit(&stmt)
			err := stmt.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestUnmarshalEnvelopeRejectsDuplicateKeys(t *testing.T) {
	raw := []byte(`{"payloadType":"a","payloadType":"b","payload":"","signatures":[]}`)
	_, err := UnmarshalEnvelope(raw)
	if err == nil || !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("UnmarshalEnvelope error = %v, want ErrInvalidEnvelope", err)
	}
}

func testStatement() Statement {
	start := time.Date(2026, 6, 13, 11, 0, 0, 0, time.UTC).Format(time.RFC3339)
	end := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	return Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "conductor-audit-batch:pipelab/dogfood/pl-1/audit-1", Digest: Digest{SHA256: hex64("envelope-audit-1")}},
			{Name: "conductor-audit-batch:pipelab/dogfood/pl-1/audit-2", Digest: Digest{SHA256: hex64("envelope-audit-2")}},
		},
		PredicateType: PredicateType,
		Predicate: Predicate{
			SchemaVersion:     1,
			ReportID:          testReportID,
			GeneratedAt:       testTimestamp,
			OrgID:             "pipelab",
			FleetID:           "dogfood",
			ReportWindow:      TimeWindow{Start: start, End: end},
			VerificationLevel: VerificationLevelL1,
			Conductor:         Conductor{ID: "conductor", Version: "v2.8.0-test"},
			SourceBatches: []SourceBatch{
				testBatch("audit-1", 1, 2, 2),
				testBatch("audit-2", 3, 3, 1),
			},
			Summary: Summary{
				TotalActions: 3,
				ByFollower:   map[string]uint64{"pl-1": 3},
				ByTransport:  map[string]uint64{"mcp": 1, "fetch": 2},
				ByActionType: map[string]uint64{"read": 2, "write": 1},
				ByVerdict:    map[string]uint64{"allow": 2, "block": 1},
				ByLayer:      map[string]uint64{"dlp": 1, "scheme": 2},
			},
			Completeness: Completeness{
				ObservedActions:        3,
				DroppedObservedActions: 0,
				MediatedActions:        3,
				MediatedFraction:       "1",
				Basis:                  "included_signed_audit_batches",
				Claim:                  "fraction of observed fleet action records in included signed audit batches that were mediated by Pipelock",
				NonClaim:               "does not prove no bypass occurred outside Pipelock, outside enrolled followers, or outside the report window",
			},
			Limits: []string{"mediated traffic only"},
		},
	}
}

func testBatch(id string, start, end, events uint64) SourceBatch {
	return SourceBatch{
		OrgID:           "pipelab",
		FleetID:         "dogfood",
		InstanceID:      "pl-1",
		BatchID:         id,
		SeqStart:        start,
		SeqEnd:          end,
		EventCount:      events,
		PayloadSHA256:   hex64("payload-" + id),
		PayloadBytes:    1024,
		EnvelopeHash:    hex64("envelope-" + id),
		SegmentTailHash: hex64("tail-" + id),
		EmittedAt:       testTimestamp,
		ReceivedAt:      testTimestamp,
		SignatureKeyIDs: []string{"audit-key-1"},
	}
}

func hex64(seed string) string {
	sum := sha256String(seed)
	return hex.EncodeToString(sum[:])
}

func sha256String(seed string) [32]byte {
	return sha256.Sum256([]byte(seed))
}
