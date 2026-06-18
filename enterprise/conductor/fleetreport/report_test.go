//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package fleetreport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	testOrgID       = "org-main"
	testFleetID     = "prod"
	testInstanceID  = "pl-1"
	testAuditKeyID  = "audit-key-1"
	testReportKeyID = "fleet-report-key-1"
)

var testWindowStart = time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)

type staticEvidenceSource struct {
	evidence []controlplane.AuditBatchEvidence
	err      error
}

func (s staticEvidenceSource) ListAuditBatchEvidence(context.Context, controlplane.AuditEvidenceQuery) ([]controlplane.AuditBatchEvidence, error) {
	return s.evidence, s.err
}

func TestBuildFleetReceiptReport(t *testing.T) {
	reportPub, reportPriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(report): %v", err)
	}
	_, auditPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(audit): %v", err)
	}
	first := testEvidence(t, auditPriv, "audit-1", 1, []receipt.Receipt{
		testActionReceipt(t, "a1", receipt.ActionRead, "allow", "fetch", "url", "low"),
	}, 0)
	const droppedActionReceipts = 1
	second := testEvidence(t, auditPriv, "audit-2", 3, []receipt.Receipt{
		testActionReceipt(t, "a2", receipt.ActionWrite, "block", "mcp", "dlp", "high"),
	}, droppedActionReceipts)

	result, err := Build(context.Background(), staticEvidenceSource{evidence: []controlplane.AuditBatchEvidence{first, second}}, Options{
		OrgID:            testOrgID,
		FleetID:          testFleetID,
		WindowStart:      testWindowStart,
		WindowEnd:        testWindowStart.Add(time.Hour),
		ConductorID:      "conductor",
		ConductorVersion: "v2.8.0-test",
		SignerKeyID:      testReportKeyID,
		Signer:           reportPriv,
		GeneratedAt:      testWindowStart.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	verified, err := fleetreceipt.VerifyEnvelope(result.Envelope, map[string]ed25519.PublicKey{testReportKeyID: reportPub})
	if err != nil {
		t.Fatalf("VerifyEnvelope() error = %v", err)
	}
	p := verified.Statement.Predicate
	if p.Summary.TotalActions != 2 || p.Completeness.DroppedObservedActions != droppedActionReceipts || p.Completeness.MediatedFraction != "1" {
		t.Fatalf("predicate totals = actions %d dropped %d fraction %q", p.Summary.TotalActions, p.Completeness.DroppedObservedActions, p.Completeness.MediatedFraction)
	}
	if p.Summary.ByFollower[testInstanceID] != 2 || p.Summary.ByVerdict["allow"] != 1 || p.Summary.ByVerdict["block"] != 1 {
		t.Fatalf("summary maps = %+v", p.Summary)
	}
	if len(verified.Statement.Subject) != 2 || len(p.SourceBatches) != 2 {
		t.Fatalf("source set = subjects %d batches %d", len(verified.Statement.Subject), len(p.SourceBatches))
	}
	if p.SourceBatches[1].EventCount <= droppedActionReceipts || p.SourceBatches[1].DroppedCount != droppedActionReceipts {
		t.Fatalf("source batch event/dropped counts = %d/%d, want event count greater than dropped action count %d",
			p.SourceBatches[1].EventCount, p.SourceBatches[1].DroppedCount, droppedActionReceipts)
	}
}

func TestBuildFleetReceiptReportNegativeCases(t *testing.T) {
	_, reportPriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(report): %v", err)
	}
	auditPub, auditPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(audit): %v", err)
	}
	base := testEvidence(t, auditPriv, "audit-1", 1, []receipt.Receipt{
		testActionReceipt(t, "a1", receipt.ActionRead, "allow", "fetch", "url", "low"),
	}, 0)
	baseOpts := Options{
		OrgID:       testOrgID,
		FleetID:     testFleetID,
		WindowStart: testWindowStart,
		WindowEnd:   testWindowStart.Add(time.Hour),
		ConductorID: "conductor",
		SignerKeyID: testReportKeyID,
		Signer:      reportPriv,
		GeneratedAt: testWindowStart.Add(time.Minute),
	}
	cases := []struct {
		name     string
		evidence []controlplane.AuditBatchEvidence
		opts     Options
		want     string
	}{
		{
			name: "malformed_payload",
			evidence: []controlplane.AuditBatchEvidence{func() controlplane.AuditBatchEvidence {
				ev := base
				ev.Payload = []byte(`{"v":2`)
				return ev
			}()},
			opts: baseOpts,
			want: "payload",
		},
		{
			name: "payload_hash_mismatch",
			evidence: []controlplane.AuditBatchEvidence{func() controlplane.AuditBatchEvidence {
				ev := base
				ev.Envelope.PayloadSHA256 = strings.Repeat("0", 64)
				return ev
			}()},
			opts: baseOpts,
			want: "payload",
		},
		{
			name: "overlapping_batches_fail_statement_validation",
			evidence: []controlplane.AuditBatchEvidence{
				base,
				testEvidence(t, auditPriv, "audit-2", 2, []receipt.Receipt{
					testActionReceipt(t, "a2", receipt.ActionRead, "allow", "fetch", "url", "low"),
				}, 0),
			},
			opts: baseOpts,
			want: "overlap",
		},
		{
			name: "bad_audit_signature_with_resolver",
			evidence: []controlplane.AuditBatchEvidence{
				base,
			},
			opts: func() Options {
				opts := baseOpts
				opts.AuditKeys = func(controlplane.FollowerIdentity, string) (conductorcore.SignatureKey, error) {
					otherPub, _, genErr := ed25519.GenerateKey(rand.Reader)
					if genErr != nil {
						t.Fatalf("GenerateKey(other): %v", genErr)
					}
					return conductorcore.SignatureKey{PublicKey: otherPub, KeyPurpose: signing.PurposeAuditBatchSigning}, nil
				}
				return opts
			}(),
			want: "verify audit batch",
		},
		{
			name: "no_action_receipts",
			evidence: []controlplane.AuditBatchEvidence{
				testEvidenceEntries(t, auditPriv, "audit-empty", 1, []recorder.Entry{testCheckpointEntry(1, recorder.GenesisHash)}, 0),
			},
			opts: baseOpts,
			want: ErrNoActionReceipts.Error(),
		},
		{
			name: "report_id_generation_failure",
			evidence: []controlplane.AuditBatchEvidence{
				base,
			},
			opts: func() Options {
				opts := baseOpts
				opts.ReportID = ""
				return opts
			}(),
			want: "generate report id",
		},
	}
	_ = auditPub
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "report_id_generation_failure" {
				orig := newReportUUID
				newReportUUID = func() (uuid.UUID, error) {
					return uuid.Nil, errors.New("uuid unavailable")
				}
				t.Cleanup(func() {
					newReportUUID = orig
				})
			}
			_, err := Build(context.Background(), staticEvidenceSource{evidence: tc.evidence}, tc.opts)
			if err == nil {
				t.Fatal("Build() error = nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Build() error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestExactDecimalRatio(t *testing.T) {
	cases := []struct {
		num     uint64
		den     uint64
		want    string
		wantErr error
	}{
		{1, 1, "1", nil},
		{0, 7, "0", nil},
		{1, 2, "0.5", nil},
		{1, 8, "0.125", nil},
		{1, 3, "", ErrNonTerminatingRatio},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("%d/%d", tc.num, tc.den), func(t *testing.T) {
			got, err := exactDecimalRatio(tc.num, tc.den)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("exactDecimalRatio(%d,%d) error = %v, want %v", tc.num, tc.den, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("exactDecimalRatio(%d,%d) = %q, want %q", tc.num, tc.den, got, tc.want)
			}
		})
	}
}

func TestValidateOptionsRejectsInvalidInputs(t *testing.T) {
	_, reportPriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(report): %v", err)
	}
	base := Options{
		OrgID:       testOrgID,
		FleetID:     testFleetID,
		WindowStart: testWindowStart,
		WindowEnd:   testWindowStart.Add(time.Hour),
		ConductorID: "conductor",
		Signer:      reportPriv,
	}
	cases := []struct {
		name string
		edit func(*Options)
		want string
	}{
		{"missing_org", func(o *Options) { o.OrgID = "" }, "org id"},
		{"missing_fleet", func(o *Options) { o.FleetID = "" }, "fleet id"},
		{"missing_conductor", func(o *Options) { o.ConductorID = "" }, "conductor id"},
		{"bad_window", func(o *Options) { o.WindowEnd = o.WindowStart }, "invalid report window"},
		{"bad_signer", func(o *Options) { o.Signer = ed25519.PrivateKey("short") }, "signer private key length"},
		{"negative_limit", func(o *Options) { o.Limit = -1 }, "limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := base
			tc.edit(&opts)
			err := validateOptions(opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateOptions() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifySegmentRejectsMalformedSegments(t *testing.T) {
	first := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  10,
		Timestamp: testWindowStart,
		SessionID: "proxy",
		Type:      "checkpoint",
		Transport: "recorder",
		Summary:   "first",
		PrevHash:  recorder.GenesisHash,
	}
	first.Hash = recorder.ComputeHash(first)
	second := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  11,
		Timestamp: testWindowStart.Add(time.Second),
		SessionID: "proxy",
		Type:      "checkpoint",
		Transport: "recorder",
		Summary:   "second",
		PrevHash:  first.Hash,
	}
	second.Hash = recorder.ComputeHash(second)
	valid := []recorder.Entry{first, second}
	cases := []struct {
		name    string
		start   uint64
		end     uint64
		head    string
		tail    string
		entries []recorder.Entry
		want    string
	}{
		{"empty", 10, 11, first.Hash, second.Hash, nil, "empty payload"},
		{"range", 9, 11, first.Hash, second.Hash, valid, "sequence range mismatch"},
		{"head_tail", 10, 11, strings.Repeat("0", 64), second.Hash, valid, "chain head/tail mismatch"},
		{"unsupported_version", 10, 11, first.Hash, second.Hash, func() []recorder.Entry {
			entries := append([]recorder.Entry(nil), valid...)
			entries[1].Version = 99
			return entries
		}(), "unsupported recorder entry version"},
		{"gap", 10, 12, first.Hash, second.Hash, func() []recorder.Entry {
			entries := append([]recorder.Entry(nil), valid...)
			entries[1].Sequence = 12
			return entries
		}(), "seq gap"},
		{"link", 10, 11, first.Hash, second.Hash, func() []recorder.Entry {
			entries := append([]recorder.Entry(nil), valid...)
			entries[1].PrevHash = recorder.GenesisHash
			return entries
		}(), "chain link mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifySegment("audit-1", tc.start, tc.end, tc.head, tc.tail, tc.entries)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("verifySegment() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValueOrUnspecified(t *testing.T) {
	if got := valueOrUnspecified(" fetch "); got != "fetch" {
		t.Fatalf("valueOrUnspecified(non-empty) = %q", got)
	}
	if got := valueOrUnspecified(" "); got != "unspecified" {
		t.Fatalf("valueOrUnspecified(empty) = %q", got)
	}
}

func testActionReceipt(t *testing.T, id string, actionType receipt.ActionType, verdict, transport, layer, severity string) receipt.Receipt {
	t.Helper()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(receipt): %v", err)
	}
	rcpt, err := receipt.Sign(receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        id,
		ActionType:      actionType,
		Timestamp:       testWindowStart.Add(time.Minute),
		Principal:       "agent",
		Actor:           "agent",
		Target:          "https://example.com",
		SideEffectClass: receipt.SideEffectExternalRead,
		Reversibility:   receipt.ReversibilityFull,
		PolicyHash:      strings.Repeat("a", 64),
		Verdict:         verdict,
		Transport:       transport,
		Layer:           layer,
		Severity:        severity,
		ChainPrevHash:   receipt.GenesisHash,
		ChainSeq:        1,
	}, priv)
	if err != nil {
		t.Fatalf("receipt.Sign(): %v", err)
	}
	return rcpt
}

func testEvidence(t *testing.T, auditPriv ed25519.PrivateKey, batchID string, seqStart uint64, receipts []receipt.Receipt, dropped uint64) controlplane.AuditBatchEvidence {
	t.Helper()
	entries := make([]recorder.Entry, 0, len(receipts)+1)
	prev := recorder.GenesisHash
	for i, rcpt := range receipts {
		seq := seqStart + uint64(i)
		entry := recorder.Entry{
			Version:   recorder.EntryVersion,
			Sequence:  seq,
			Timestamp: testWindowStart.Add(time.Second),
			SessionID: "proxy",
			Type:      "action_receipt",
			EventKind: string(rcpt.ActionRecord.ActionType),
			Transport: rcpt.ActionRecord.Transport,
			Summary:   "receipt",
			Detail:    rcpt,
			PrevHash:  prev,
		}
		entry.Hash = recorder.ComputeHash(entry)
		prev = entry.Hash
		entries = append(entries, entry)
	}
	entries = append(entries, testCheckpointEntry(seqStart+uint64(len(receipts)), prev))
	return testEvidenceEntries(t, auditPriv, batchID, seqStart, entries, dropped)
}

func testCheckpointEntry(seq uint64, prev string) recorder.Entry {
	entry := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  seq,
		Timestamp: testWindowStart.Add(time.Second),
		SessionID: "proxy",
		Type:      "checkpoint",
		EventKind: "checkpoint",
		Transport: "recorder",
		Summary:   "checkpoint",
		Detail: recorder.CheckpointDetail{
			EntryCount: 1,
			FirstSeq:   seq,
			LastSeq:    seq,
			Signature:  strings.Repeat("1", ed25519.SignatureSize*2),
		},
		PrevHash: prev,
	}
	entry.Hash = recorder.ComputeHash(entry)
	return entry
}

func testEvidenceEntries(t *testing.T, auditPriv ed25519.PrivateKey, batchID string, seqStart uint64, entries []recorder.Entry, dropped uint64) controlplane.AuditBatchEvidence {
	t.Helper()
	payload := marshalTestEntries(t, entries)
	sum := sha256.Sum256(payload)
	droppedAccounting := conductorcore.DroppedAccounting{}
	if dropped > 0 {
		droppedAccounting = conductorcore.DroppedAccounting{
			Count:   dropped,
			Reasons: []conductorcore.DroppedReason{{Reason: "queue_full", Count: dropped}},
		}
	}
	envelope := conductorcore.AuditBatchEnvelope{
		SchemaVersion:      conductorcore.SchemaVersion,
		BatchID:            batchID,
		OrgID:              testOrgID,
		FleetID:            testFleetID,
		InstanceID:         testInstanceID,
		AuditSchemaVersion: recorder.EntryVersion,
		EmittedAt:          testWindowStart.Add(time.Minute),
		SeqStart:           seqStart,
		SeqEnd:             entries[len(entries)-1].Sequence,
		EventCount:         uint64(len(entries)),
		PayloadSHA256:      hex.EncodeToString(sum[:]),
		PayloadBytes:       uint64(len(payload)),
		Dropped:            droppedAccounting,
		Chain: conductorcore.EvidenceChain{
			EntryVersion:           recorder.EntryVersion,
			SegmentID:              "segment-" + batchID,
			SeqStart:               seqStart,
			SeqEnd:                 entries[len(entries)-1].Sequence,
			SegmentHeadHash:        entries[0].Hash,
			SegmentTailHash:        entries[len(entries)-1].Hash,
			CheckpointSeq:          entries[len(entries)-1].Sequence,
			CheckpointHash:         entries[len(entries)-1].Hash,
			CheckpointSignature:    conductorcore.SignaturePrefixEd25519 + strings.Repeat("1", ed25519.SignatureSize*2),
			CheckpointSignerKeyID:  "recorder-key-1",
			FollowerRecorderKeyID:  "recorder-key-1",
			FollowerRecorderPubHex: strings.Repeat("2", ed25519.PublicKeySize*2),
		},
	}
	signed, err := auditbatcher.SignEnvelope(envelope, testAuditKeyID, auditPriv)
	if err != nil {
		t.Fatalf("SignEnvelope(): %v", err)
	}
	envelopeHash, err := signed.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(): %v", err)
	}
	return controlplane.AuditBatchEvidence{
		Summary: controlplane.AuditBatchSummary{
			BatchID:         signed.BatchID,
			OrgID:           signed.OrgID,
			FleetID:         signed.FleetID,
			InstanceID:      signed.InstanceID,
			AuditSchema:     signed.AuditSchemaVersion,
			SeqStart:        signed.SeqStart,
			SeqEnd:          signed.SeqEnd,
			EventCount:      signed.EventCount,
			PayloadSHA256:   signed.PayloadSHA256,
			PayloadBytes:    signed.PayloadBytes,
			EnvelopeHash:    envelopeHash,
			SegmentTailHash: signed.Chain.SegmentTailHash,
			DroppedCount:    signed.Dropped.Count,
			EmittedAt:       signed.EmittedAt,
			ReceivedAt:      testWindowStart.Add(2 * time.Minute),
			SignatureKeyIDs: []string{testAuditKeyID},
		},
		Envelope: signed,
		Payload:  payload,
	}
}

func marshalTestEntries(t *testing.T, entries []recorder.Entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, entry := range entries {
		if err := enc.Encode(entry); err != nil {
			t.Fatalf("Encode(entry): %v", err)
		}
	}
	return buf.Bytes()
}
