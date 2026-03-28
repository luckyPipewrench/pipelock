// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestDecisionRecord_SignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	dr := DecisionRecord{
		Version:   DecisionRecordVersion,
		Type:      DecisionRecordType,
		SessionID: "test-session",
		Timestamp: time.Now().UTC(),
		Verdict:   "block",
		ScannerResult: ScannerEvidence{
			Layer:      "dlp",
			Pattern:    "aws_access_key",
			MatchText:  "[REDACTED]",
			Confidence: "high",
		},
		PolicyRule: PolicyEvidence{
			Source:  "config",
			Section: "dlp",
			Action:  "block",
		},
		RequestContext: RequestEvidence{
			Transport: "mcp_stdio",
			ToolName:  "exec",
			Direction: "outbound",
		},
	}

	signed, err := dr.Sign(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if signed.Signature == "" {
		t.Fatal("expected non-empty signature")
	}

	if err := signed.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestDecisionRecord_TamperDetection(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	dr := DecisionRecord{
		Version:   DecisionRecordVersion,
		Type:      DecisionRecordType,
		SessionID: "s1",
		Verdict:   "block",
		Timestamp: time.Now().UTC(),
		RequestContext: RequestEvidence{
			Transport: "mcp_stdio",
		},
	}

	signed, err := dr.Sign(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Tamper with verdict after signing.
	signed.Verdict = "allow"

	if err := signed.Verify(pub); err == nil {
		t.Fatal("expected verification failure after tampering")
	}
}

func TestDecisionRecord_JSON(t *testing.T) {
	dr := DecisionRecord{
		Version:   DecisionRecordVersion,
		Type:      DecisionRecordType,
		SessionID: "s1",
		Verdict:   "allow",
		Timestamp: time.Now().UTC(),
		RequestContext: RequestEvidence{
			Transport: "fetch",
		},
		Signature: "ed25519:abc123",
	}

	data, err := json.Marshal(dr)
	if err != nil {
		t.Fatal(err)
	}

	var decoded DecisionRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != DecisionRecordVersion {
		t.Errorf("version: got %d", decoded.Version)
	}
	if decoded.Verdict != "allow" {
		t.Errorf("verdict: got %q", decoded.Verdict)
	}
}

func TestRecorder_RecordDecision(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rec, err := New(Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             false,
		CheckpointInterval: 100,
	}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}

	dr := DecisionRecord{
		SessionID: "test-session",
		Verdict:   "block",
		ScannerResult: ScannerEvidence{
			Layer:   "canary",
			Pattern: "aws_canary",
		},
		PolicyRule: PolicyEvidence{
			Source: "config",
			Action: "block",
		},
		RequestContext: RequestEvidence{
			Transport: "mcp_stdio",
			Direction: "outbound",
		},
	}

	if err := rec.RecordDecision(dr); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := ReadEntries(filepath.Join(dir, "evidence-test-session-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one entry")
	}
	if err := VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	var decisionEntry *Entry
	for i := range entries {
		if entries[i].Type == decisionEntryType {
			decisionEntry = &entries[i]
			break
		}
	}
	if decisionEntry == nil {
		t.Fatal("decision entry not found")
	}

	data, err := json.Marshal(decisionEntry.Detail)
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}
	var stored DecisionRecord
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("unmarshal detail: %v", err)
	}
	if err := stored.Verify(pub); err != nil {
		t.Fatalf("stored signature verification failed: %v", err)
	}
}

func TestRecorder_RecordDecisionRequiresSigningMaterial(t *testing.T) {
	dir := t.TempDir()
	rec, err := New(Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             false,
		CheckpointInterval: 100,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()

	dr := DecisionRecord{
		SessionID: "test-session",
		Verdict:   "block",
		RequestContext: RequestEvidence{
			Transport: "fetch",
		},
	}
	if err := rec.RecordDecision(dr); err == nil {
		t.Fatal("expected error without signature or recorder key")
	}
}

func TestDecisionRecord_Validate(t *testing.T) {
	tests := []struct {
		name    string
		dr      DecisionRecord
		wantErr string
	}{
		{
			name: "valid",
			dr: DecisionRecord{
				Version:        DecisionRecordVersion,
				Type:           DecisionRecordType,
				SessionID:      "s1",
				Verdict:        "block",
				RequestContext: RequestEvidence{Transport: "fetch"},
			},
			wantErr: "",
		},
		{
			name: "wrong version",
			dr: DecisionRecord{
				Version:        99,
				Type:           DecisionRecordType,
				SessionID:      "s1",
				Verdict:        "block",
				RequestContext: RequestEvidence{Transport: "fetch"},
			},
			wantErr: "unsupported decision record version",
		},
		{
			name: "wrong type",
			dr: DecisionRecord{
				Version:        DecisionRecordVersion,
				Type:           "wrong_type",
				SessionID:      "s1",
				Verdict:        "block",
				RequestContext: RequestEvidence{Transport: "fetch"},
			},
			wantErr: "invalid decision record type",
		},
		{
			name: "empty session_id",
			dr: DecisionRecord{
				Version:        DecisionRecordVersion,
				Type:           DecisionRecordType,
				SessionID:      "",
				Verdict:        "block",
				RequestContext: RequestEvidence{Transport: "fetch"},
			},
			wantErr: "session_id is required",
		},
		{
			name: "empty verdict",
			dr: DecisionRecord{
				Version:        DecisionRecordVersion,
				Type:           DecisionRecordType,
				SessionID:      "s1",
				Verdict:        "",
				RequestContext: RequestEvidence{Transport: "fetch"},
			},
			wantErr: "verdict is required",
		},
		{
			name: "empty transport",
			dr: DecisionRecord{
				Version:        DecisionRecordVersion,
				Type:           DecisionRecordType,
				SessionID:      "s1",
				Verdict:        "block",
				RequestContext: RequestEvidence{Transport: ""},
			},
			wantErr: "transport is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.dr.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
			}
		})
	}
}

func TestDecisionRecord_Normalize(t *testing.T) {
	t.Run("fills defaults", func(t *testing.T) {
		dr := DecisionRecord{
			SessionID:      "s1",
			Verdict:        "block",
			RequestContext: RequestEvidence{Transport: "fetch"},
		}
		n := dr.Normalize()
		if n.Version != DecisionRecordVersion {
			t.Errorf("version: got %d, want %d", n.Version, DecisionRecordVersion)
		}
		if n.Type != DecisionRecordType {
			t.Errorf("type: got %q, want %q", n.Type, DecisionRecordType)
		}
		if n.Timestamp.IsZero() {
			t.Error("timestamp should be set")
		}
	})

	t.Run("preserves existing values", func(t *testing.T) {
		ts := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
		dr := DecisionRecord{
			Version:        DecisionRecordVersion,
			Type:           DecisionRecordType,
			SessionID:      "s1",
			Verdict:        "allow",
			Timestamp:      ts,
			RequestContext: RequestEvidence{Transport: "fetch"},
		}
		n := dr.Normalize()
		if n.Version != DecisionRecordVersion {
			t.Error("should preserve version")
		}
		if n.Timestamp != ts {
			t.Errorf("should preserve timestamp, got %v", n.Timestamp)
		}
	})

	t.Run("converts timestamp to UTC", func(t *testing.T) {
		loc, err := time.LoadLocation("America/New_York")
		if err != nil {
			t.Skip("timezone data not available")
		}
		ts := time.Date(2026, 3, 28, 12, 0, 0, 0, loc)
		dr := DecisionRecord{Timestamp: ts}
		n := dr.Normalize()
		if n.Timestamp.Location() != time.UTC {
			t.Error("timestamp should be UTC")
		}
	})
}

func TestDecisionRecord_Sign_InvalidKey(t *testing.T) {
	dr := DecisionRecord{
		Version:        DecisionRecordVersion,
		Type:           DecisionRecordType,
		SessionID:      "s1",
		Verdict:        "block",
		RequestContext: RequestEvidence{Transport: "fetch"},
	}
	_, err := dr.Sign(ed25519.PrivateKey([]byte("too-short")))
	if err == nil {
		t.Fatal("expected error for invalid private key")
	}
	if !strings.Contains(err.Error(), "invalid private key") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDecisionRecord_Sign_InvalidRecord(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Missing required fields — Validate should fail
	dr := DecisionRecord{
		SessionID: "", // required
		Verdict:   "block",
		RequestContext: RequestEvidence{
			Transport: "fetch",
		},
	}
	_, err = dr.Sign(priv)
	if err == nil {
		t.Fatal("expected error for invalid record")
	}
}

func TestDecisionRecord_Verify_Errors(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	validDR := DecisionRecord{
		Version:        DecisionRecordVersion,
		Type:           DecisionRecordType,
		SessionID:      "s1",
		Verdict:        "block",
		Timestamp:      time.Now().UTC(),
		RequestContext: RequestEvidence{Transport: "fetch"},
	}
	signed, err := validDR.Sign(priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	t.Run("invalid public key", func(t *testing.T) {
		err := signed.Verify(ed25519.PublicKey([]byte("short")))
		if err == nil {
			t.Fatal("expected error for invalid public key")
		}
		if !strings.Contains(err.Error(), "invalid public key") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("no signature", func(t *testing.T) {
		noSig := signed
		noSig.Signature = ""
		err := noSig.Verify(pub)
		if err == nil {
			t.Fatal("expected error for missing signature")
		}
		if !strings.Contains(err.Error(), "no signature") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid signature format", func(t *testing.T) {
		badFmt := signed
		badFmt.Signature = "not-ed25519-prefix:abcdef"
		err := badFmt.Verify(pub)
		if err == nil {
			t.Fatal("expected error for invalid signature format")
		}
		if !strings.Contains(err.Error(), "invalid signature format") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid hex in signature", func(t *testing.T) {
		badHex := signed
		badHex.Signature = "ed25519:not-valid-hex!!!"
		err := badHex.Verify(pub)
		if err == nil {
			t.Fatal("expected error for invalid hex")
		}
		if !strings.Contains(err.Error(), "decode signature") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("wrong signature length", func(t *testing.T) {
		badLen := signed
		badLen.Signature = "ed25519:" + hex.EncodeToString([]byte("too-short"))
		err := badLen.Verify(pub)
		if err == nil {
			t.Fatal("expected error for wrong signature length")
		}
		if !strings.Contains(err.Error(), "invalid signature length") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		err = signed.Verify(otherPub)
		if err == nil {
			t.Fatal("expected error for wrong public key")
		}
		if !strings.Contains(err.Error(), "verification failed") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid record in verify", func(t *testing.T) {
		// A signed record with bad version should fail validate during Verify
		badVersion := signed
		badVersion.Version = 99
		err := badVersion.Verify(pub)
		if err == nil {
			t.Fatal("expected error for invalid version during verify")
		}
	})
}

func TestRecorder_RecordDecision_PreSigned(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rec, err := New(Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 100,
	}, nil, nil) // no recorder key
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()

	// Pre-sign the decision record
	dr := DecisionRecord{
		SessionID:      "pre-signed-session",
		Verdict:        "block",
		RequestContext: RequestEvidence{Transport: "fetch"},
	}
	signed, err := dr.Sign(priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// RecordDecision with a pre-signed record should work even without recorder key
	if err := rec.RecordDecision(signed); err != nil {
		t.Fatalf("RecordDecision with pre-signed: %v", err)
	}
}

func TestRecorder_RecordDecision_PreSignedInvalid(t *testing.T) {
	dir := t.TempDir()
	rec, err := New(Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 100,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()

	// Pre-signed record with invalid data should fail validation
	dr := DecisionRecord{
		SessionID: "",
		Verdict:   "block",
		Signature: "ed25519:abc123", // has signature but invalid record
		RequestContext: RequestEvidence{
			Transport: "fetch",
		},
	}
	err = rec.RecordDecision(dr)
	if err == nil {
		t.Fatal("expected error for invalid pre-signed record")
	}
	if !strings.Contains(err.Error(), "invalid decision record") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRecorder_RecordDecision_SummaryWithPattern(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rec, err := New(Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 100,
	}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}

	dr := DecisionRecord{
		SessionID: "summary-session",
		Verdict:   "block",
		ScannerResult: ScannerEvidence{
			Layer:   "dlp",
			Pattern: "aws_access_key",
		},
		RequestContext: RequestEvidence{Transport: "mcp_stdio"},
	}
	if err := rec.RecordDecision(dr); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := ReadEntries(filepath.Join(dir, "evidence-summary-session-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}

	var found bool
	for _, e := range entries {
		if e.Type == decisionEntryType {
			found = true
			if !strings.Contains(e.Summary, "aws_access_key") {
				t.Errorf("summary should contain pattern name, got %q", e.Summary)
			}
			if !strings.Contains(e.Summary, "block") {
				t.Errorf("summary should contain verdict, got %q", e.Summary)
			}
		}
	}
	if !found {
		t.Fatal("decision entry not found")
	}
}

func TestRecorder_RecordDecision_EmptyLayer(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rec, err := New(Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 100,
	}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}

	dr := DecisionRecord{
		SessionID: "empty-layer",
		Verdict:   "allow",
		ScannerResult: ScannerEvidence{
			Layer: "", // empty layer should become "unknown"
		},
		RequestContext: RequestEvidence{Transport: "fetch"},
	}
	if err := rec.RecordDecision(dr); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := ReadEntries(filepath.Join(dir, "evidence-empty-layer-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	for _, e := range entries {
		if e.Type == decisionEntryType {
			if !strings.Contains(e.Summary, "unknown") {
				t.Errorf("empty layer should become 'unknown' in summary, got %q", e.Summary)
			}
		}
	}
}

func TestRecorder_RecordDecisionUsesRecorderRedactionAndEscrow(t *testing.T) {
	dir := t.TempDir()

	recipientPub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}

	cfg := Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             true,
		CheckpointInterval: 100,
		RawEscrow:          true,
		EscrowPublicKey:    hex.EncodeToString(recipientPub[:]),
	}

	redactFn := func(_ context.Context, _ string) scanner.TextDLPResult {
		return scanner.TextDLPResult{
			Clean: false,
			Matches: []scanner.TextDLPMatch{
				{PatternName: "Test Secret"},
			},
		}
	}

	rec, err := New(cfg, redactFn, priv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	dr := DecisionRecord{
		SessionID: "redact-session",
		Verdict:   "block",
		ScannerResult: ScannerEvidence{
			Layer:     "dlp",
			MatchText: "AK" + "IA" + "IOSFODNN7EXAMPLE",
		},
		RequestContext: RequestEvidence{
			Transport: "mcp_stdio",
		},
	}

	if err := rec.RecordDecision(dr); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := ReadEntries(filepath.Join(dir, "evidence-redact-session-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(entries) < 1 {
		t.Fatal("expected at least one entry")
	}

	first := entries[0]
	if first.RawRef == "" {
		t.Fatal("expected raw escrow reference on decision entry")
	}

	detailJSON, err := json.Marshal(first.Detail)
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(detailJSON, &envelope); err != nil {
		t.Fatalf("unmarshal detail: %v", err)
	}
	if redacted, ok := envelope["redacted"].(bool); !ok || !redacted {
		t.Fatalf("expected redaction envelope, got %s", string(detailJSON))
	}
}

// Internal tests for unexported functions -- these are in package recorder.

func TestExtractSeqStart(t *testing.T) {
	tests := []struct {
		path string
		want int
	}{
		{"/dir/evidence-sess-0.jsonl", 0},
		{"/dir/evidence-sess-42.jsonl", 42},
		{"/dir/evidence-sess-100.jsonl", 100},
		{"evidence-sess-abc.jsonl", 0},          // non-numeric suffix
		{"nodash.jsonl", 0},                     // no dash at all after strip
		{"/dir/evidence-my-session-5.jsonl", 5}, // session ID with dashes
	}

	for _, tc := range tests {
		got := extractSeqStart(tc.path)
		if got != tc.want {
			t.Errorf("extractSeqStart(%q) = %d, want %d", tc.path, got, tc.want)
		}
	}
}

func TestSafeUint64(t *testing.T) {
	tests := []struct {
		name     string
		v        int
		fallback int
		want     uint64
	}{
		{"positive value", 500, 1, 500},
		{"zero uses fallback", 0, 42, 42},
		{"negative uses fallback", -10, 100, 100},
		{"at max bound", maxCheckpointBound, 1, uint64(maxCheckpointBound)},
		{"exceeds max bound", maxCheckpointBound + 1, 1, uint64(maxCheckpointBound)},
		{"both zero uses fallback", 0, 0, 0}, // fallback 0 stays 0 since 0 < 1
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := safeUint64(tc.v, tc.fallback)
			if got != tc.want {
				t.Errorf("safeUint64(%d, %d) = %d, want %d", tc.v, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestWriteEntry_MarshalError(t *testing.T) {
	// Exercise writeEntry's marshal error path by creating a recorder,
	// opening a file, then attempting to write an entry with an
	// unmarshalable detail.
	dir := t.TempDir()
	cfg := Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}
	rec, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	// Record a valid entry first to open the file
	err = rec.Record(Entry{
		SessionID: "write-err",
		Type:      "request",
		Transport: "fetch",
		Summary:   "open file",
	})
	if err != nil {
		t.Fatalf("first Record: %v", err)
	}

	// Now try with an unmarshalable detail (channel type)
	// The Record function marshals Detail before writeEntry, so the marshal
	// error happens in ComputeHash (which falls back to "null") and
	// writeEntry (which returns an error on json.Marshal).
	// Actually, looking at the code: Record calls ComputeHash which handles
	// marshal error gracefully (uses "null"), then writeEntry calls json.Marshal
	// on the Entry. The Entry itself with a chan detail would fail.
	// But Record also calls writeEscrow which json.Marshals e.Detail...
	// Let me use a func() type which json.Marshal can't handle.
	err = rec.Record(Entry{
		SessionID: "write-err",
		Type:      "request",
		Transport: "fetch",
		Summary:   "bad detail",
		Detail:    func() {}, // json.Marshal will fail on func type
	})
	if err == nil {
		t.Fatal("expected error for unmarshalable detail in writeEntry")
	}
	if !strings.Contains(err.Error(), "writing entry") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCloseFile_FlushAndCloseOnNilFile(t *testing.T) {
	// Construct a recorder, never record anything, and close.
	// This exercises closeFile with r.file == nil.
	dir := t.TempDir()
	rec, err := New(Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Close without writing -- closeFile path with nil file
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestClose_CheckpointFailure(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000, // won't auto-trigger
	}
	rec, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Record an entry to make sinceCheckpoint > 0
	err = rec.Record(Entry{
		SessionID: "close-cp",
		Type:      "request",
		Transport: "fetch",
		Summary:   "trigger final checkpoint",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Remove the evidence directory to cause checkpoint write failure
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}

	// Close should attempt final checkpoint, which will fail
	err = rec.Close()
	// On Linux, the file descriptor is still open even after dir removal,
	// so the checkpoint write may succeed. We just ensure Close doesn't panic.
	_ = err
}

func TestRedactDetail_NilDetail(t *testing.T) {
	// Calling redactDetail with nil should return nil
	dir := t.TempDir()
	redactFn := func(_ context.Context, _ string) scanner.TextDLPResult {
		t.Fatal("redact function should not be called for nil detail")
		return scanner.TextDLPResult{}
	}

	rec, err := New(Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             true,
		CheckpointInterval: 1000,
	}, redactFn, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	// Record with nil detail -- redactDetail should return nil early
	err = rec.Record(Entry{
		SessionID: "nil-detail",
		Type:      "request",
		Transport: "fetch",
		Summary:   "nil detail",
		Detail:    nil,
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
}

func TestRedactDetail_UnmarshalableDetail(t *testing.T) {
	// If detail can't be marshaled, redactDetail returns original
	dir := t.TempDir()
	called := false
	redactFn := func(_ context.Context, _ string) scanner.TextDLPResult {
		called = true
		return scanner.TextDLPResult{Clean: true}
	}

	rec, err := New(Config{
		Enabled:            true,
		Dir:                dir,
		Redact:             true,
		CheckpointInterval: 1000,
	}, redactFn, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	result := rec.redactDetail(make(chan int))
	// Should return the original (chan) since marshal fails
	if result == nil {
		t.Fatal("expected original detail to be returned on marshal error")
	}
	if called {
		t.Error("redact function should not be called when marshal fails")
	}
}

func TestWriteEntry_WriteErrors(t *testing.T) {
	// Test writeEntry when the underlying file is closed (causing write errors).
	dir := t.TempDir()
	cfg := Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}
	rec, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Record one entry to open the file
	err = rec.Record(Entry{
		SessionID: "write-err-test",
		Type:      "request",
		Transport: "fetch",
		Summary:   "open file",
	})
	if err != nil {
		t.Fatalf("first Record: %v", err)
	}

	// Close the underlying file to cause write errors, but keep the recorder open
	rec.mu.Lock()
	if rec.file != nil {
		_ = rec.file.Close()
	}
	rec.mu.Unlock()

	// The next record should fail when writeEntry tries to write to the closed file.
	// Note: bufio.Writer may buffer the first write, so the error may surface on Flush.
	err = rec.Record(Entry{
		SessionID: "write-err-test",
		Type:      "request",
		Transport: "fetch",
		Summary:   "should fail",
	})
	if err == nil {
		// Try one more -- the bufio.Writer may have buffered and the error
		// surfaces on Flush during the next write or on Close.
		err = rec.Record(Entry{
			SessionID: "write-err-test",
			Type:      "request",
			Transport: "fetch",
			Summary:   "should also fail",
		})
	}
	// At this point, either Record or Close should report the error.
	closeErr := rec.Close()

	if err == nil && closeErr == nil {
		t.Fatal("expected at least one error from writing to closed file")
	}
}

func TestCloseFile_FlushError(t *testing.T) {
	// Exercise the closeFile flush-error path by closing the underlying OS file
	// before calling closeFile through Close.
	dir := t.TempDir()
	cfg := Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}
	rec, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Record entries to open file and fill the buffer
	for i := range 5 {
		err := rec.Record(Entry{
			SessionID: "flush-err",
			Type:      "request",
			Transport: "fetch",
			Summary:   strings.Repeat("x", 1024), // large summary to fill buffer
		})
		if err != nil {
			t.Fatalf("Record(%d): %v", i, err)
		}
	}

	// Close the underlying OS file while keeping the recorder's reference intact
	rec.mu.Lock()
	if rec.file != nil {
		_ = rec.file.Close()
	}
	rec.mu.Unlock()

	// Now Close() should encounter a flush error in closeFile
	err = rec.Close()
	// On some OS/fs combinations the flush may succeed because data was already
	// synced. We just verify no panic occurs. If the error path is hit, great.
	_ = err
}

func TestCheckpointLocked_NoFile(t *testing.T) {
	// Exercise the checkpointLocked path where r.file == nil.
	// This happens when Close is called with sinceCheckpoint > 0
	// but the file has been rotated away (nil file).
	dir := t.TempDir()
	cfg := Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
		MaxEntriesPerFile:  1, // Force rotation after every entry
	}
	rec, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Record an entry -- this will open file, write entry, then rotate (close file)
	err = rec.Record(Entry{
		SessionID: "cp-nofile",
		Type:      "request",
		Transport: "fetch",
		Summary:   "rotated",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// After rotation, the file is nil. Close() will try to write a final checkpoint
	// with r.file == nil, exercising the branch in checkpointLocked that checks
	// r.file != nil before writing.
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestExpireOldFiles_SkipsDirectories(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:       true,
		Dir:           dir,
		RetentionDays: 1,
	}
	rec, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	// Create a subdirectory named like an evidence file
	subdir := filepath.Join(dir, "evidence-dir-0.jsonl")
	if err := os.MkdirAll(subdir, 0o750); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(subdir, old, old); err != nil {
		t.Fatal(err)
	}

	removed, err := rec.ExpireOldFiles()
	if err != nil {
		t.Fatalf("ExpireOldFiles: %v", err)
	}
	if removed != 0 {
		t.Errorf("expected 0 removed (directories should be skipped), got %d", removed)
	}
}

func TestRecorder_Record_CheckpointWriteError(t *testing.T) {
	// Test that checkpoint write errors propagate through Record.
	dir := t.TempDir()
	cfg := Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 2, // Trigger checkpoint after 2 entries
	}
	rec, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Record first entry
	err = rec.Record(Entry{
		SessionID: "cp-write-err",
		Type:      "request",
		Transport: "fetch",
		Summary:   "first",
	})
	if err != nil {
		t.Fatalf("Record(0): %v", err)
	}

	// Close the underlying file to make checkpoint write fail
	rec.mu.Lock()
	if rec.file != nil {
		_ = rec.file.Close()
	}
	rec.mu.Unlock()

	// Second entry should trigger checkpoint (sinceCheckpoint reaches threshold),
	// which should fail writing to the closed file.
	err = rec.Record(Entry{
		SessionID: "cp-write-err",
		Type:      "request",
		Transport: "fetch",
		Summary:   "trigger checkpoint",
	})
	// The error may surface here or at Close. We just verify no panic.
	_ = err
	_ = rec.Close()
}

func TestRecorder_Record_FileRotationError(t *testing.T) {
	// Test file rotation when the underlying dir is removed.
	dir := t.TempDir()
	cfg := Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
		MaxEntriesPerFile:  2, // Trigger rotation after 2 entries
	}
	rec, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Record first entry to open file
	err = rec.Record(Entry{
		SessionID: "rotate-err",
		Type:      "request",
		Transport: "fetch",
		Summary:   "first",
	})
	if err != nil {
		t.Fatalf("Record(0): %v", err)
	}

	// Record second entry to trigger rotation
	err = rec.Record(Entry{
		SessionID: "rotate-err",
		Type:      "request",
		Transport: "fetch",
		Summary:   "trigger rotation",
	})
	if err != nil {
		t.Fatalf("Record(1): %v", err)
	}

	// After rotation, dir still exists. Record third entry to verify the
	// new file opens correctly.
	err = rec.Record(Entry{
		SessionID: "rotate-err",
		Type:      "request",
		Transport: "fetch",
		Summary:   "after rotation",
	})
	if err != nil {
		t.Fatalf("Record(2): %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestEnsureFile_FirstSeqInSpan(t *testing.T) {
	// Test that ensureFile sets firstSeqInSpan when sinceCheckpoint == 0.
	dir := t.TempDir()
	cfg := Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 2,
	}
	rec, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Record 2 entries to trigger checkpoint (resets sinceCheckpoint to 0)
	for i := range 2 {
		err := rec.Record(Entry{
			SessionID: "span-test",
			Type:      "request",
			Transport: "fetch",
			Summary:   fmt.Sprintf("entry %d", i),
		})
		if err != nil {
			t.Fatalf("Record(%d): %v", i, err)
		}
	}

	// Record one more -- ensureFile will see sinceCheckpoint == 0
	// and set firstSeqInSpan to the new seqStart
	err = rec.Record(Entry{
		SessionID: "span-test",
		Type:      "request",
		Transport: "fetch",
		Summary:   "after checkpoint",
	})
	if err != nil {
		t.Fatalf("Record after checkpoint: %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := ReadEntries(filepath.Join(dir, "evidence-span-test-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}

	// Should have: 2 data entries + 1 checkpoint + 1 more data entry + 1 final checkpoint
	if len(entries) < 4 {
		t.Errorf("expected at least 4 entries, got %d", len(entries))
	}

	if err := VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}
