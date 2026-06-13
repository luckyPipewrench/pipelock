// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package fleetreceipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

func TestVerifyEnvelopeRejectsMalformedEnvelope(t *testing.T) {
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
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, payload, "", "  "); err != nil {
		t.Fatalf("Indent: %v", err)
	}

	tests := []struct {
		name        string
		edit        func(*Envelope)
		trustedKeys map[string]ed25519.PublicKey
		want        string
	}{
		{
			name: "wrong_payload_type",
			edit: func(e *Envelope) {
				e.PayloadType = "application/json"
			},
			trustedKeys: map[string]ed25519.PublicKey{keyID: pub},
			want:        "payloadType",
		},
		{
			name: "signature_count",
			edit: func(e *Envelope) {
				e.Signatures = append(e.Signatures, e.Signatures[0])
			},
			trustedKeys: map[string]ed25519.PublicKey{keyID: pub},
			want:        "signatures=2",
		},
		{
			name: "bad_payload_base64",
			edit: func(e *Envelope) {
				e.Payload = "not base64"
			},
			trustedKeys: map[string]ed25519.PublicKey{keyID: pub},
			want:        "decode payload",
		},
		{
			name: "noncanonical_payload",
			edit: func(e *Envelope) {
				e.Payload = base64.StdEncoding.EncodeToString(pretty.Bytes())
			},
			trustedKeys: map[string]ed25519.PublicKey{keyID: pub},
			want:        "not canonical",
		},
		{
			name: "wrong_key_purpose",
			edit: func(e *Envelope) {
				e.Signatures[0].KeyPurpose = signing.PurposeAuditBatchSigning.String()
			},
			trustedKeys: map[string]ed25519.PublicKey{keyID: pub},
			want:        "key_purpose",
		},
		{
			name: "wrong_algorithm",
			edit: func(e *Envelope) {
				e.Signatures[0].Algorithm = "rsa"
			},
			trustedKeys: map[string]ed25519.PublicKey{keyID: pub},
			want:        "algorithm",
		},
		{
			name: "missing_signature_prefix",
			edit: func(e *Envelope) {
				e.Signatures[0].Sig = strings.TrimPrefix(e.Signatures[0].Sig, signaturePrefix)
			},
			trustedKeys: map[string]ed25519.PublicKey{keyID: pub},
			want:        "signature missing",
		},
		{
			name: "bad_signature_base64",
			edit: func(e *Envelope) {
				e.Signatures[0].Sig = signaturePrefix + "not base64"
			},
			trustedKeys: map[string]ed25519.PublicKey{keyID: pub},
			want:        "decode signature",
		},
		{
			name: "bad_signature_length",
			edit: func(e *Envelope) {
				e.Signatures[0].Sig = signaturePrefix + base64.StdEncoding.EncodeToString([]byte("short"))
			},
			trustedKeys: map[string]ed25519.PublicKey{keyID: pub},
			want:        "signature length",
		},
		{
			name: "missing_keyid",
			edit: func(e *Envelope) {
				e.Signatures[0].KeyID = ""
			},
			trustedKeys: nil,
			want:        "keyid required",
		},
		{
			name: "untrusted_key",
			edit: func(*Envelope) {
			},
			trustedKeys: map[string]ed25519.PublicKey{"other": pub},
			want:        ErrUntrustedKey.Error(),
		},
		{
			name: "bad_trusted_key_length",
			edit: func(*Envelope) {
			},
			trustedKeys: map[string]ed25519.PublicKey{keyID: ed25519.PublicKey("short")},
			want:        "trusted key",
		},
		{
			name: "bad_unpinned_keyid",
			edit: func(e *Envelope) {
				e.Signatures[0].KeyID = "not-hex"
			},
			trustedKeys: nil,
			want:        "unpinned keyid",
		},
		{
			name: "signature_mismatch",
			edit: func(e *Envelope) {
				e.Signatures[0].KeyID = hex.EncodeToString(mustOtherPublicKey(t))
			},
			trustedKeys: nil,
			want:        "signature verification failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := env
			candidate.Signatures = append([]Signature(nil), env.Signatures...)
			tt.edit(&candidate)
			_, err := VerifyEnvelope(candidate, tt.trustedKeys)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("VerifyEnvelope error = %v, want %q", err, tt.want)
			}
			if !errors.Is(err, ErrInvalidEnvelope) && !errors.Is(err, ErrUntrustedKey) {
				t.Fatalf("VerifyEnvelope error = %v, want envelope or trust error", err)
			}
		})
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
		{
			name: "generated_at_must_be_utc",
			edit: func(s *Statement) {
				s.Predicate.GeneratedAt = "2026-06-13T07:00:00-05:00"
			},
			want: "ending in Z",
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

func TestStatementValidateErrorClasses(t *testing.T) {
	t.Parallel()

	t.Run("subject digest is statement error", func(t *testing.T) {
		stmt := testStatement()
		stmt.Subject[0].Digest.SHA256 = strings.ToUpper(stmt.Subject[0].Digest.SHA256)
		err := stmt.Validate()
		if err == nil {
			t.Fatal("expected uppercase subject digest to fail")
		}
		if !errors.Is(err, ErrInvalidStatement) {
			t.Fatalf("Validate error = %v, want ErrInvalidStatement", err)
		}
		if errors.Is(err, ErrInvalidPredicate) {
			t.Fatalf("Validate error = %v, must not wrap ErrInvalidPredicate", err)
		}
	})

	t.Run("source batch digest is predicate error", func(t *testing.T) {
		stmt := testStatement()
		stmt.Predicate.SourceBatches[0].PayloadSHA256 = strings.ToUpper(stmt.Predicate.SourceBatches[0].PayloadSHA256)
		err := stmt.Validate()
		if err == nil {
			t.Fatal("expected uppercase source batch digest to fail")
		}
		if !errors.Is(err, ErrInvalidPredicate) {
			t.Fatalf("Validate error = %v, want ErrInvalidPredicate", err)
		}
	})
}

func TestStatementValidateRejectsInvalidStatementHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		edit func(*Statement)
		want string
	}{
		{
			name: "wrong_type",
			edit: func(s *Statement) {
				s.Type = "https://example.com/wrong"
			},
			want: "_type",
		},
		{
			name: "wrong_predicate_type",
			edit: func(s *Statement) {
				s.PredicateType = "https://example.com/wrong"
			},
			want: "predicateType",
		},
		{
			name: "missing_subjects",
			edit: func(s *Statement) {
				s.Subject = nil
			},
			want: "subject required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt := testStatement()
			tt.edit(&stmt)
			err := stmt.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate error = %v, want %q", err, tt.want)
			}
			if !errors.Is(err, ErrInvalidStatement) {
				t.Fatalf("Validate error = %v, want ErrInvalidStatement", err)
			}
		})
	}
}

func TestPredicateValidateRejectsEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		edit func(*Predicate)
		want string
	}{
		{
			name: "schema_version",
			edit: func(p *Predicate) {
				p.SchemaVersion = 2
			},
			want: "schemaVersion",
		},
		{
			name: "required_string",
			edit: func(p *Predicate) {
				p.ReportID = " "
			},
			want: "reportId required",
		},
		{
			name: "bad_rfc3339",
			edit: func(p *Predicate) {
				p.GeneratedAt = "2026-13-99T99:99:99Z"
			},
			want: "generatedAt",
		},
		{
			name: "window_end_not_after_start",
			edit: func(p *Predicate) {
				p.ReportWindow.End = p.ReportWindow.Start
			},
			want: "reportWindow.end",
		},
		{
			name: "source_batches_required",
			edit: func(p *Predicate) {
				p.SourceBatches = nil
			},
			want: "sourceBatches required",
		},
		{
			name: "source_batch_identity_required",
			edit: func(p *Predicate) {
				p.SourceBatches[0].BatchID = ""
			},
			want: "source batch identity required",
		},
		{
			name: "source_batch_invalid_range",
			edit: func(p *Predicate) {
				p.SourceBatches[0].SeqEnd = p.SourceBatches[0].SeqStart - 1
			},
			want: "invalid source batch sequence range",
		},
		{
			name: "source_batch_empty_size",
			edit: func(p *Predicate) {
				p.SourceBatches[0].PayloadBytes = 0
			},
			want: "eventCount and payloadBytes",
		},
		{
			name: "source_batch_bad_hex_length",
			edit: func(p *Predicate) {
				p.SourceBatches[0].PayloadSHA256 = "abc"
			},
			want: "64 hex chars",
		},
		{
			name: "source_batch_bad_hex_char",
			edit: func(p *Predicate) {
				p.SourceBatches[0].PayloadSHA256 = strings.Repeat("g", 64)
			},
			want: "must be hex",
		},
		{
			name: "source_batch_bad_timestamp",
			edit: func(p *Predicate) {
				p.SourceBatches[0].EmittedAt = "2026-06-13T12:00:00"
			},
			want: "ending in Z",
		},
		{
			name: "source_batch_signature_keys_required",
			edit: func(p *Predicate) {
				p.SourceBatches[0].SignatureKeyIDs = nil
			},
			want: "signatureKeyIds required",
		},
		{
			name: "source_batch_signature_blank",
			edit: func(p *Predicate) {
				p.SourceBatches[0].SignatureKeyIDs = []string{" "}
			},
			want: "blank key",
		},
		{
			name: "summary_total_required",
			edit: func(p *Predicate) {
				p.Summary.TotalActions = 0
			},
			want: "summary.totalActions",
		},
		{
			name: "summary_empty_key",
			edit: func(p *Predicate) {
				p.Summary.ByFollower = map[string]uint64{"": 3}
			},
			want: "empty key",
		},
		{
			name: "summary_zero_count",
			edit: func(p *Predicate) {
				p.Summary.ByFollower = map[string]uint64{"pl-1": 0}
			},
			want: "is zero",
		},
		{
			name: "summary_overflow",
			edit: func(p *Predicate) {
				p.Summary.TotalActions = ^uint64(0)
				p.Summary.ByFollower = map[string]uint64{"a": ^uint64(0), "b": 1}
			},
			want: "overflow",
		},
		{
			name: "mediated_exceeds_observed",
			edit: func(p *Predicate) {
				p.Completeness.MediatedActions = p.Completeness.ObservedActions + 1
			},
			want: "mediatedActions exceeds",
		},
		{
			name: "bad_decimal_text",
			edit: func(p *Predicate) {
				p.Completeness.MediatedFraction = "0.x"
			},
			want: "decimal string",
		},
		{
			name: "bad_decimal_shape",
			edit: func(p *Predicate) {
				p.Completeness.MediatedFraction = "1.1"
			},
			want: "between 0 and 1",
		},
		{
			name: "bad_decimal_trailing_nonzero",
			edit: func(p *Predicate) {
				p.Completeness.MediatedFraction = "1.01"
			},
			want: "between 0 and 1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predicate := testStatement().Predicate
			tt.edit(&predicate)
			err := predicate.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate error = %v, want %q", err, tt.want)
			}
			if !errors.Is(err, ErrInvalidPredicate) {
				t.Fatalf("Validate error = %v, want ErrInvalidPredicate", err)
			}
		})
	}
}

func TestTrustedKeyMap(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyID := "fleet"
	got, err := TrustedKeyMap(map[string]string{keyID: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatalf("TrustedKeyMap: %v", err)
	}
	if !bytes.Equal(got[keyID], pub) {
		t.Fatalf("TrustedKeyMap[%q] = %x, want %x", keyID, got[keyID], pub)
	}

	if _, err := TrustedKeyMap(map[string]string{"bad": "not-hex"}); err == nil {
		t.Fatal("expected bad hex trusted key to fail")
	}
	if _, err := TrustedKeyMap(map[string]string{"short": hex.EncodeToString([]byte("short"))}); err == nil {
		t.Fatal("expected short trusted key to fail")
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

func mustOtherPublicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey other: %v", err)
	}
	return pub
}

func sha256String(seed string) [32]byte {
	return sha256.Sum256([]byte(seed))
}
