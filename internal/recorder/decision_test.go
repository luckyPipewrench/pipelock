// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
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
