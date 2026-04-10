// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	testPrincipal  = "test-principal"
	testActor      = "test-actor"
	testConfigHash = "abc123"
)

func newTestRecorder(t *testing.T, dir string, priv ed25519.PrivateKey) *recorder.Recorder {
	t.Helper()
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	return rec
}

func TestNewEmitter_NilRecorder(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	e := NewEmitter(EmitterConfig{
		Recorder: nil,
		PrivKey:  priv,
	})
	if e != nil {
		t.Error("NewEmitter() with nil recorder should return nil")
	}
}

func TestNewEmitter_NilPrivateKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	defer func() { _ = rec.Close() }()

	e := NewEmitter(EmitterConfig{
		Recorder: rec,
		PrivKey:  nil,
	})
	if e != nil {
		t.Error("NewEmitter() with nil private key should return nil")
	}
}

func TestNewEmitter_ShortPrivateKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	defer func() { _ = rec.Close() }()

	e := NewEmitter(EmitterConfig{
		Recorder: rec,
		PrivKey:  make([]byte, 16), // wrong size
	})
	if e != nil {
		t.Error("NewEmitter() with short private key should return nil")
	}
}

func TestNewEmitter_ValidInputs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	defer func() { _ = rec.Close() }()

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})
	if e == nil {
		t.Fatal("NewEmitter() with valid inputs returned nil")
	}
}

func TestEmitter_Emit_NilEmitter(t *testing.T) {
	t.Parallel()

	var e *Emitter
	err := e.Emit(EmitOpts{
		Target:    testTarget,
		Verdict:   config.ActionBlock,
		Transport: testTransport,
		Method:    http.MethodGet,
	})
	if err != nil {
		t.Errorf("Emit() on nil emitter should be no-op, got error: %v", err)
	}
}

func TestEmitter_Emit_HappyPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})
	if e == nil {
		t.Fatal("NewEmitter() returned nil")
	}

	err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionBlock,
		Transport: testTransport,
		Method:    http.MethodGet,
	})
	if err != nil {
		t.Fatalf("Emit() error: %v", err)
	}

	// Close the recorder to flush.
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close() error: %v", err)
	}

	// Read the JSONL file back and find our receipt entry.
	receipt := readReceiptFromDir(t, dir, pub)
	if receipt.ActionRecord.Target != testTarget {
		t.Errorf("target = %q, want %q", receipt.ActionRecord.Target, testTarget)
	}
	if receipt.ActionRecord.Verdict != "block" {
		t.Errorf("verdict = %q, want %q", receipt.ActionRecord.Verdict, "block")
	}
	if receipt.ActionRecord.PolicyHash != testConfigHash {
		t.Errorf("policy_hash = %q, want %q", receipt.ActionRecord.PolicyHash, testConfigHash)
	}
	if receipt.ActionRecord.Principal != testPrincipal {
		t.Errorf("principal = %q, want %q", receipt.ActionRecord.Principal, testPrincipal)
	}
}

func TestEmitter_Emit_TaintFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})

	source := session.TaintSourceRef{
		URL:   "https://evil.example/issue/123",
		Kind:  "http_response",
		Level: session.TaintExternalUntrusted,
	}
	err := e.Emit(EmitOpts{
		ActionID:            NewActionID(),
		Target:              testTarget,
		Verdict:             config.ActionAllow,
		Transport:           testTransport,
		Method:              http.MethodPost,
		SessionTaintLevel:   session.TaintExternalUntrusted.String(),
		SessionContaminated: true,
		RecentTaintSources:  []session.TaintSourceRef{source},
		SessionTaskID:       "task-123",
		SessionTaskLabel:    "review auth fix",
		AuthorityKind:       session.AuthorityOperatorOverride.String(),
		TaintDecision:       "ask",
		TaintDecisionReason: "protected_write_after_untrusted_external_exposure",
		TaskOverrideApplied: true,
	})
	if err != nil {
		t.Fatalf("Emit() error: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close() error: %v", err)
	}

	got := readReceiptFromDir(t, dir, pub)
	if got.ActionRecord.SessionTaintLevel != session.TaintExternalUntrusted.String() {
		t.Fatalf("session_taint_level = %q", got.ActionRecord.SessionTaintLevel)
	}
	if !got.ActionRecord.SessionContaminated {
		t.Fatal("expected session_contaminated to be true")
	}
	if len(got.ActionRecord.RecentTaintSources) != 1 {
		t.Fatalf("recent_taint_sources length = %d, want 1", len(got.ActionRecord.RecentTaintSources))
	}
	if got.ActionRecord.SessionTaskID != "task-123" {
		t.Fatalf("session_task_id = %q", got.ActionRecord.SessionTaskID)
	}
	if got.ActionRecord.SessionTaskLabel != "review auth fix" {
		t.Fatalf("session_task_label = %q", got.ActionRecord.SessionTaskLabel)
	}
	if got.ActionRecord.AuthorityKind != session.AuthorityOperatorOverride.String() {
		t.Fatalf("authority_kind = %q", got.ActionRecord.AuthorityKind)
	}
	if got.ActionRecord.TaintDecision != "ask" {
		t.Fatalf("taint_decision = %q", got.ActionRecord.TaintDecision)
	}
	if got.ActionRecord.TaintDecisionReason != "protected_write_after_untrusted_external_exposure" {
		t.Fatalf("taint_decision_reason = %q", got.ActionRecord.TaintDecisionReason)
	}
	if !got.ActionRecord.TaskOverrideApplied {
		t.Fatal("expected task_override_applied to be true")
	}
}

func TestEmitter_Emit_HTTPClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		wantAction ActionType
	}{
		{name: "GET_is_read", method: http.MethodGet, wantAction: ActionRead},
		{name: "POST_is_write", method: http.MethodPost, wantAction: ActionWrite},
		{name: "DELETE_is_write", method: http.MethodDelete, wantAction: ActionWrite},
		{name: "HEAD_is_read", method: http.MethodHead, wantAction: ActionRead},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			pub, priv := generateTestKey(t)
			rec := newTestRecorder(t, dir, priv)

			e := NewEmitter(EmitterConfig{
				Recorder:   rec,
				PrivKey:    priv,
				ConfigHash: testConfigHash,
				Principal:  testPrincipal,
				Actor:      testActor,
			})

			err := e.Emit(EmitOpts{
				ActionID:  NewActionID(),
				Target:    testTarget,
				Verdict:   config.ActionAllow,
				Transport: testTransport,
				Method:    tc.method,
			})
			if err != nil {
				t.Fatalf("Emit() error: %v", err)
			}

			if err := rec.Close(); err != nil {
				t.Fatalf("Close() error: %v", err)
			}

			receipt := readReceiptFromDir(t, dir, pub)
			if receipt.ActionRecord.ActionType != tc.wantAction {
				t.Errorf("action_type = %q, want %q",
					receipt.ActionRecord.ActionType, tc.wantAction)
			}
		})
	}
}

func TestEmitter_Emit_MCPClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		mcpMethod  string
		toolName   string
		wantAction ActionType
	}{
		{name: "tools_call_read", mcpMethod: "tools/call", toolName: "getUser", wantAction: ActionRead},
		{name: "tools_call_write", mcpMethod: "tools/call", toolName: "createFile", wantAction: ActionWrite},
		{name: "tools_call_delegate", mcpMethod: "tools/call", toolName: "runCommand", wantAction: ActionDelegate},
		{name: "tools_list", mcpMethod: "tools/list", toolName: "", wantAction: ActionRead},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			pub, priv := generateTestKey(t)
			rec := newTestRecorder(t, dir, priv)

			e := NewEmitter(EmitterConfig{
				Recorder:   rec,
				PrivKey:    priv,
				ConfigHash: testConfigHash,
				Principal:  testPrincipal,
				Actor:      testActor,
			})

			err := e.Emit(EmitOpts{
				ActionID:  NewActionID(),
				Target:    testTarget,
				Verdict:   config.ActionAllow,
				Transport: "mcp",
				MCPMethod: tc.mcpMethod,
				ToolName:  tc.toolName,
			})
			if err != nil {
				t.Fatalf("Emit() error: %v", err)
			}

			if err := rec.Close(); err != nil {
				t.Fatalf("Close() error: %v", err)
			}

			receipt := readReceiptFromDir(t, dir, pub)
			if receipt.ActionRecord.ActionType != tc.wantAction {
				t.Errorf("action_type = %q, want %q",
					receipt.ActionRecord.ActionType, tc.wantAction)
			}
			// MCP calls should have reversibility set to unknown.
			if receipt.ActionRecord.Reversibility != ReversibilityUnknown {
				t.Errorf("reversibility = %q, want %q",
					receipt.ActionRecord.Reversibility, ReversibilityUnknown)
			}
		})
	}
}

func TestEmitter_Emit_ActorLabel(t *testing.T) {
	t.Parallel()

	t.Run("default_actor", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		pub, priv := generateTestKey(t)
		rec := newTestRecorder(t, dir, priv)

		e := NewEmitter(EmitterConfig{
			Recorder:   rec,
			PrivKey:    priv,
			ConfigHash: testConfigHash,
			Principal:  testPrincipal,
			Actor:      testActor,
		})

		err := e.Emit(EmitOpts{
			ActionID:  NewActionID(),
			Target:    testTarget,
			Verdict:   config.ActionAllow,
			Transport: testTransport,
			Method:    http.MethodGet,
		})
		if err != nil {
			t.Fatalf("Emit() error: %v", err)
		}
		if err := rec.Close(); err != nil {
			t.Fatalf("Close() error: %v", err)
		}

		receipt := readReceiptFromDir(t, dir, pub)
		if receipt.ActionRecord.Actor != testActor {
			t.Errorf("actor = %q, want %q", receipt.ActionRecord.Actor, testActor)
		}
	})

	t.Run("agent_override", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		pub, priv := generateTestKey(t)
		rec := newTestRecorder(t, dir, priv)

		e := NewEmitter(EmitterConfig{
			Recorder:   rec,
			PrivKey:    priv,
			ConfigHash: testConfigHash,
			Principal:  testPrincipal,
			Actor:      testActor,
		})

		const agentLabel = "custom-agent"
		err := e.Emit(EmitOpts{
			ActionID:  NewActionID(),
			Target:    testTarget,
			Verdict:   config.ActionAllow,
			Transport: testTransport,
			Method:    http.MethodGet,
			Agent:     agentLabel,
		})
		if err != nil {
			t.Fatalf("Emit() error: %v", err)
		}
		if err := rec.Close(); err != nil {
			t.Fatalf("Close() error: %v", err)
		}

		receipt := readReceiptFromDir(t, dir, pub)
		if receipt.ActionRecord.Actor != agentLabel {
			t.Errorf("actor = %q, want %q", receipt.ActionRecord.Actor, agentLabel)
		}
	})
}

func TestEmitter_UpdateConfigHash(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "hash-before",
		Principal:  testPrincipal,
		Actor:      testActor,
	})

	// Emit first receipt with original hash.
	err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionAllow,
		Transport: testTransport,
		Method:    http.MethodGet,
	})
	if err != nil {
		t.Fatalf("Emit() error: %v", err)
	}

	// Update config hash (simulates hot reload).
	e.UpdateConfigHash("hash-after")

	// Emit second receipt with updated hash.
	err = e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    "https://other.example.com",
		Verdict:   config.ActionBlock,
		Transport: testTransport,
		Method:    http.MethodPost,
	})
	if err != nil {
		t.Fatalf("Emit() error: %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	// Read all receipts and verify policy_hash values differ.
	receipts := readAllReceiptsFromDir(t, dir, pub)
	if len(receipts) < 2 {
		t.Fatalf("expected at least 2 receipts, got %d", len(receipts))
	}

	if receipts[0].ActionRecord.PolicyHash != "hash-before" {
		t.Errorf("first receipt policy_hash = %q, want %q",
			receipts[0].ActionRecord.PolicyHash, "hash-before")
	}
	if receipts[1].ActionRecord.PolicyHash != "hash-after" {
		t.Errorf("second receipt policy_hash = %q, want %q",
			receipts[1].ActionRecord.PolicyHash, "hash-after")
	}
}

func TestEmitter_UpdateConfigHash_NilEmitter(t *testing.T) {
	t.Parallel()

	var e *Emitter
	// Should not panic.
	e.UpdateConfigHash("anything")
}

func TestEmitter_Emit_NoMethodOrMCP(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)

	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})

	// Emit with no Method and no MCPMethod => unclassified.
	err := e.Emit(EmitOpts{
		ActionID:  NewActionID(),
		Target:    testTarget,
		Verdict:   config.ActionBlock,
		Transport: testTransport,
	})
	if err != nil {
		t.Fatalf("Emit() error: %v", err)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	receipt := readReceiptFromDir(t, dir, pub)
	if receipt.ActionRecord.ActionType != ActionUnclassified {
		t.Errorf("action_type = %q, want %q",
			receipt.ActionRecord.ActionType, ActionUnclassified)
	}
}

func TestEmitter_Emit_MCPSideEffects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		toolName       string
		wantSideEffect SideEffectClass
	}{
		{name: "read_tool", toolName: "getUser", wantSideEffect: SideEffectExternalRead},
		{name: "write_tool", toolName: "createFile", wantSideEffect: SideEffectExternalWrite},
		{name: "delegate_tool", toolName: "runCommand", wantSideEffect: SideEffectExternalWrite},
		{name: "unclassified_tool", toolName: "mystery", wantSideEffect: SideEffectNone},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			pub, priv := generateTestKey(t)
			rec := newTestRecorder(t, dir, priv)

			e := NewEmitter(EmitterConfig{
				Recorder:   rec,
				PrivKey:    priv,
				ConfigHash: testConfigHash,
				Principal:  testPrincipal,
				Actor:      testActor,
			})

			err := e.Emit(EmitOpts{
				ActionID:  NewActionID(),
				Target:    testTarget,
				Verdict:   config.ActionAllow,
				Transport: "mcp",
				MCPMethod: "tools/call",
				ToolName:  tc.toolName,
			})
			if err != nil {
				t.Fatalf("Emit() error: %v", err)
			}
			if err := rec.Close(); err != nil {
				t.Fatalf("Close() error: %v", err)
			}

			receipt := readReceiptFromDir(t, dir, pub)
			if receipt.ActionRecord.SideEffectClass != tc.wantSideEffect {
				t.Errorf("side_effect_class = %q, want %q",
					receipt.ActionRecord.SideEffectClass, tc.wantSideEffect)
			}
		})
	}
}

func TestSideEffectFromMCPAction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		actionType ActionType
		want       SideEffectClass
	}{
		{name: "read", actionType: ActionRead, want: SideEffectExternalRead},
		{name: "write", actionType: ActionWrite, want: SideEffectExternalWrite},
		{name: "commit", actionType: ActionCommit, want: SideEffectExternalWrite},
		{name: "delegate", actionType: ActionDelegate, want: SideEffectExternalWrite},
		{name: "spend", actionType: ActionSpend, want: SideEffectFinancial},
		{name: "actuate", actionType: ActionActuate, want: SideEffectPhysical},
		{name: "unclassified", actionType: ActionUnclassified, want: SideEffectNone},
		{name: "derive", actionType: ActionDerive, want: SideEffectNone},
		{name: "authorize", actionType: ActionAuthorize, want: SideEffectNone},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sideEffectFromMCPAction(tc.actionType)
			if got != tc.want {
				t.Errorf("sideEffectFromMCPAction(%q) = %q, want %q",
					tc.actionType, got, tc.want)
			}
		})
	}
}

// readReceiptFromDir reads the first action_receipt entry from JSONL files
// in dir, parses the receipt, and verifies its signature.
func readReceiptFromDir(t *testing.T, dir string, pub ed25519.PublicKey) Receipt {
	t.Helper()
	receipts := readAllReceiptsFromDir(t, dir, pub)
	if len(receipts) == 0 {
		t.Fatal("no action_receipt entries found in evidence files")
	}
	return receipts[0]
}

// readAllReceiptsFromDir reads all action_receipt entries from JSONL files in dir.
// It verifies each receipt's signature against the provided public key.
func readAllReceiptsFromDir(t *testing.T, dir string, pub ed25519.PublicKey) []Receipt {
	t.Helper()

	expectedKeyHex := hex.EncodeToString(pub)

	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}

	var receipts []Receipt
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".jsonl") {
			continue
		}

		path := filepath.Join(dir, de.Name())
		fileEntries, err := recorder.ReadEntries(path)
		if err != nil {
			t.Fatalf("ReadEntries(%q): %v", path, err)
		}

		for _, entry := range fileEntries {
			if entry.Type != "action_receipt" {
				continue
			}

			// entry.Detail is map[string]any after JSON unmarshal.
			// Marshal it back to JSON, then unmarshal as Receipt.
			detailJSON, err := json.Marshal(entry.Detail)
			if err != nil {
				t.Fatalf("json.Marshal(entry.Detail): %v", err)
			}

			r, err := Unmarshal(detailJSON)
			if err != nil {
				t.Fatalf("Unmarshal(receipt): %v", err)
			}

			if err := VerifyWithKey(r, expectedKeyHex); err != nil {
				t.Fatalf("VerifyWithKey(receipt): %v", err)
			}

			receipts = append(receipts, r)
		}
	}
	return receipts
}

// Ensure crypto/rand is used (lint satisfaction for the import).
var _ = rand.Reader
