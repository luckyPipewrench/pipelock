// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const mcpTestPolicyHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// decisionReceiptLogFor reads the evidence-proxy chain log from the dir
// produced by newReceiptTestHarness (proxy_test.go). Using the harness
// directly keeps these tests aligned with the rest of the receipt-emit
// suite and avoids duplicating the signing-key + recorder plumbing.
func decisionReceiptLogFor(t *testing.T, dir string) []receipt.Receipt {
	t.Helper()
	return readActionReceipts(t, dir)
}

type mcpV2Entry struct {
	Type      string          `json:"type"`
	EventKind string          `json:"event_kind"`
	Detail    json.RawMessage `json:"detail"`
}

type mcpDecisionReceiptHarness struct {
	v1  *receipt.Emitter
	v2  *proxydecision.Emitter
	rec *recorder.Recorder
	dir string
	pub ed25519.PublicKey
	kid string
}

func newMCPDecisionReceiptHarness(t *testing.T) *mcpDecisionReceiptHarness {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rec, err := recorder.New(recorder.Config{
		Enabled: true, Dir: dir, CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })

	signer := proxydecision.NewKeyedSigner(priv)
	return &mcpDecisionReceiptHarness{
		v1: receipt.NewEmitter(receipt.EmitterConfig{
			Recorder: rec, PrivKey: priv, ConfigHash: "test-config-hash",
			Principal: "local", Actor: "pipelock",
		}),
		v2: proxydecision.NewEmitter(proxydecision.EmitterConfig{
			Recorder: rec, Signer: signer, Principal: "local", Actor: "pipelock",
		}),
		rec: rec,
		dir: dir,
		pub: pub,
		kid: signer.KeyID(),
	}
}

func mcpV2Receipts(t *testing.T, h *mcpDecisionReceiptHarness) []contractreceipt.EvidenceReceipt {
	t.Helper()
	if err := h.rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	entries, err := os.ReadDir(filepath.Clean(h.dir))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var out []contractreceipt.EvidenceReceipt
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(filepath.Join(h.dir, entry.Name())))
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var e mcpV2Entry
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				t.Fatalf("unmarshal recorder entry: %v", err)
			}
			if e.Type != "evidence_receipt" || e.EventKind != string(contractreceipt.PayloadProxyDecision) {
				continue
			}
			var r contractreceipt.EvidenceReceipt
			if err := json.Unmarshal(e.Detail, &r); err != nil {
				t.Fatalf("unmarshal v2 receipt: %v", err)
			}
			out = append(out, r)
		}
	}
	return out
}

type failingMCPV2Recorder struct{}

func (failingMCPV2Recorder) Record(recorder.Entry) error {
	return errors.New("v2 record failed")
}

func TestEmitMCPDecision_NilEmittersNoOp(t *testing.T) {
	// With nil emitters, the helper must not panic and must return
	// the InboundMsg verbatim.
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`)
	out, err := EmitMCPDecision(nil, nil, nil, MCPDecision{
		Receipt:    receipt.EmitOpts{ActionID: "abc", Verdict: config.ActionAllow},
		Envelope:   &envelope.BuildOpts{ActionID: "abc", Verdict: config.ActionAllow},
		InboundMsg: msg,
	})
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if !bytes.Equal(out, msg) {
		t.Errorf("outbound = %q, want inbound verbatim %q", string(out), string(msg))
	}
}

func TestEmitMCPDecision_EmptyActionIDSkipsReceipt(t *testing.T) {
	emitter, _, dir, _ := newReceiptTestHarness(t)

	_, err := EmitMCPDecision(emitter, nil, nil, MCPDecision{
		Receipt: receipt.EmitOpts{
			Verdict: config.ActionAllow,
			// ActionID intentionally empty: the helper must not emit.
		},
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	// The harness-created recorder only writes the evidence file on the
	// first emission. A skipped emit means no file exists. Checking for
	// file absence proves the skip happened without needing to read
	// chain entries (readActionReceipts fatal-errs on missing file).
	if _, statErr := os.Stat(filepath.Join(dir, "evidence-proxy-0.jsonl")); !os.IsNotExist(statErr) {
		t.Errorf("evidence file created despite empty ActionID; stat err = %v", statErr)
	}
}

func TestEmitMCPDecision_RequiredEmptyActionIDFailsClosed(t *testing.T) {
	emitter, _, dir, _ := newReceiptTestHarness(t)

	_, err := EmitMCPDecision(emitter, nil, nil, MCPDecision{
		Receipt: receipt.EmitOpts{
			Verdict: config.ActionAllow,
			// ActionID intentionally empty: RequireReceipt must fail closed
			// instead of treating the missing receipt as a silent skip.
		},
		RequireReceipt: true,
	})
	if !errors.Is(err, ErrReceiptRequired) {
		t.Fatalf("err = %v, want ErrReceiptRequired", err)
	}
	var log bytes.Buffer
	logReceiptEmitFailure(&log, err, true, config.ActionAllow)
	if !strings.Contains(log.String(), "event=block_receipt_emit_failed") || !strings.Contains(log.String(), "audit_gap=true") {
		t.Fatalf("missing audit-gap warning for required empty ActionID: %q", log.String())
	}
	if _, statErr := os.Stat(filepath.Join(dir, "evidence-proxy-0.jsonl")); !os.IsNotExist(statErr) {
		t.Errorf("evidence file created despite empty ActionID; stat err = %v", statErr)
	}
}

func TestEmitMCPDecision_RequiredEmptyActionIDDoesNotInjectEnvelope(t *testing.T) {
	emitter, _, _, _ := newReceiptTestHarness(t)
	envEmitter := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: "policy-h"})
	inbound := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{}}}`)

	out, err := EmitMCPDecision(emitter, nil, envEmitter, MCPDecision{
		Receipt: receipt.EmitOpts{
			Verdict: config.ActionAllow,
		},
		Envelope: &envelope.BuildOpts{
			ActionID: "must-not-leak",
			Action:   "tool_call",
			Verdict:  config.ActionAllow,
		},
		InboundMsg:     inbound,
		RequireReceipt: true,
	})
	if !errors.Is(err, ErrReceiptRequired) {
		t.Fatalf("err = %v, want ErrReceiptRequired", err)
	}
	if !bytes.Equal(out, inbound) {
		t.Fatalf("outbound was rewritten despite required receipt failure: %s", out)
	}
	if strings.Contains(string(out), "must-not-leak") || strings.Contains(string(out), "com.pipelock/mediation") {
		t.Fatalf("outbound leaked mediation envelope after required receipt failure: %s", out)
	}
}

func TestEmitMCPDecision_ReceiptOnly(t *testing.T) {
	emitter, _, dir, _ := newReceiptTestHarness(t)

	_, err := EmitMCPDecision(emitter, nil, nil, MCPDecision{
		Receipt: receipt.EmitOpts{
			ActionID:  "receipt-only-1",
			Verdict:   config.ActionBlock,
			Transport: "mcp_stdio",
			Target:    "fetch_url",
			MCPMethod: methodToolsCall,
			ToolName:  "fetch_url",
			Layer:     "mcp_input_scan",
			Pattern:   "dlp.match",
		},
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	receipts := decisionReceiptLogFor(t, dir)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0].ActionRecord.ActionID != "receipt-only-1" {
		t.Errorf("action_id = %q, want receipt-only-1", receipts[0].ActionRecord.ActionID)
	}
	if receipts[0].ActionRecord.Verdict != config.ActionBlock {
		t.Errorf("verdict = %q, want block", receipts[0].ActionRecord.Verdict)
	}
}

func TestEmitMCPDecision_EnvelopeInjection(t *testing.T) {
	envEmitter := envelope.NewEmitter(envelope.EmitterConfig{
		ConfigHash: "test-policy-hash",
	})

	inbound := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}`)
	out, err := EmitMCPDecision(nil, nil, envEmitter, MCPDecision{
		InboundMsg: inbound,
		Envelope: &envelope.BuildOpts{
			ActionID: "env-test-1",
			Action:   "tool_call",
			Verdict:  config.ActionAllow,
		},
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	// The envelope-injected message must differ from the input and
	// must contain the com.pipelock/mediation key.
	if bytes.Equal(out, inbound) {
		t.Fatal("envelope injection did not rewrite the message")
	}
	if !strings.Contains(string(out), `com.pipelock/mediation`) {
		t.Errorf("outbound missing mediation key: %s", string(out))
	}
	// Verify the rewritten message is still valid JSON.
	var rewritten map[string]any
	if err := json.Unmarshal(out, &rewritten); err != nil {
		t.Fatalf("envelope-rewritten output is invalid JSON: %v", err)
	}
}

func TestEmitMCPDecision_NilInboundSkipsEnvelope(t *testing.T) {
	// Block / strip / redirect decisions don't have an InboundMsg to
	// decorate. Passing nil InboundMsg must not crash and must return
	// nil outbound.
	envEmitter := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: "h"})

	out, err := EmitMCPDecision(nil, nil, envEmitter, MCPDecision{
		Envelope: &envelope.BuildOpts{ActionID: "x", Verdict: config.ActionAllow},
		// InboundMsg intentionally nil
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out != nil {
		t.Errorf("outbound = %q, want nil when InboundMsg is nil", string(out))
	}
}

func TestEmitMCPDecision_ReceiptAndEnvelope(t *testing.T) {
	recEmitter, _, dir, _ := newReceiptTestHarness(t)
	envEmitter := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: "policy-h"})

	inbound := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch","arguments":{}}}`)
	out, err := EmitMCPDecision(recEmitter, nil, envEmitter, MCPDecision{
		Receipt: receipt.EmitOpts{
			ActionID:  "dual-1",
			Verdict:   config.ActionAllow,
			Transport: "mcp_http_listener",
			Target:    "fetch",
			MCPMethod: methodToolsCall,
			ToolName:  "fetch",
		},
		Envelope: &envelope.BuildOpts{
			ActionID: "dual-1",
			Action:   "tool_call",
			Verdict:  config.ActionAllow,
		},
		InboundMsg: inbound,
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if bytes.Equal(out, inbound) {
		t.Error("envelope injection did not rewrite the message")
	}
	receipts := decisionReceiptLogFor(t, dir)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0].ActionRecord.ActionID != "dual-1" {
		t.Errorf("action_id = %q, want dual-1", receipts[0].ActionRecord.ActionID)
	}
	if !strings.Contains(string(out), "com.pipelock/mediation") {
		t.Errorf("envelope missing from outbound: %s", string(out))
	}
}

func TestEmitMCPDecision_RequiredAllowEmitsDurableIntentBeforeEnvelope(t *testing.T) {
	recEmitter, _, dir, _ := newReceiptTestHarness(t)
	envEmitter := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: "policy-h"})

	inbound := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch","arguments":{}}}`)
	out, err := EmitMCPDecision(recEmitter, nil, envEmitter, MCPDecision{
		Receipt: receipt.EmitOpts{
			ActionID:  "required-allow-1",
			Verdict:   config.ActionAllow,
			Transport: transportMCPStdio,
			Target:    "fetch",
			MCPMethod: methodToolsCall,
			ToolName:  "fetch",
		},
		Envelope: &envelope.BuildOpts{
			ActionID: "required-allow-1",
			Action:   "tool_call",
			Verdict:  config.ActionAllow,
		},
		InboundMsg:     inbound,
		RequireReceipt: true,
	})
	if err != nil {
		t.Fatalf("EmitMCPDecision: %v", err)
	}
	if bytes.Equal(out, inbound) {
		t.Fatal("envelope injection did not rewrite the message")
	}

	receipts := decisionReceiptLogFor(t, dir)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	record := receipts[0].ActionRecord
	if record.ActionID != "required-allow-1" {
		t.Fatalf("action_id = %q, want required-allow-1", record.ActionID)
	}
	if record.DecisionPhase != receipt.DecisionPhaseIntent {
		t.Fatalf("decision_phase = %q, want %q", record.DecisionPhase, receipt.DecisionPhaseIntent)
	}
}

func TestEmitMCPDecision_RequiredAllowSyncFailureBlocksBeforeEnvelope(t *testing.T) {
	recEmitter, rec, _, _ := newReceiptTestHarness(t)
	envEmitter := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: "policy-h"})
	syncErr := errors.New("injected durable sync failure")
	rec.SetSyncForTest(func(*os.File) error {
		return syncErr
	})

	inbound := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch","arguments":{}}}`)
	out, err := EmitMCPDecision(recEmitter, nil, envEmitter, MCPDecision{
		Receipt: receipt.EmitOpts{
			ActionID:  "required-allow-sync-fail",
			Verdict:   config.ActionAllow,
			Transport: transportMCPStdio,
			Target:    "fetch",
			MCPMethod: methodToolsCall,
			ToolName:  "fetch",
		},
		Envelope: &envelope.BuildOpts{
			ActionID: "required-allow-sync-fail",
			Action:   "tool_call",
			Verdict:  config.ActionAllow,
		},
		InboundMsg:     inbound,
		RequireReceipt: true,
	})
	if !errors.Is(err, ErrReceiptRequired) {
		t.Fatalf("err = %v, want ErrReceiptRequired", err)
	}
	if !errors.Is(err, recorder.ErrDurability) {
		t.Fatalf("err = %v, want recorder.ErrDurability", err)
	}
	if !bytes.Equal(out, inbound) {
		t.Fatalf("outbound was rewritten despite durable intent failure: %s", out)
	}
	if strings.Contains(string(out), "com.pipelock/mediation") {
		t.Fatalf("outbound leaked mediation envelope after durable intent failure: %s", out)
	}
}

func TestEmitMCPDecision_ReceiptErrorDoesNotBlockEnvelope(t *testing.T) {
	// A nil receipt emitter is the closest to a "fails/skips" signal
	// we can induce without a bespoke error-injecting fake. The helper
	// must still inject the envelope. Covers the documented contract
	// that the two stages are independent.
	envEmitter := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: "h"})
	inbound := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`)

	out, err := EmitMCPDecision(nil, nil, envEmitter, MCPDecision{
		Receipt:    receipt.EmitOpts{ActionID: "would-emit-but-no-emitter", Verdict: config.ActionAllow},
		Envelope:   &envelope.BuildOpts{ActionID: "would-emit-but-no-emitter", Verdict: config.ActionAllow},
		InboundMsg: inbound,
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if bytes.Equal(out, inbound) {
		t.Error("envelope injection should run even when receipt is skipped")
	}
}

func TestEmitMCPDecision_DualEmitsV2WithPolicyHash(t *testing.T) {
	h := newMCPDecisionReceiptHarness(t)

	_, err := EmitMCPDecision(h.v1, h.v2, nil, MCPDecision{
		Receipt: receipt.EmitOpts{
			ActionID:   "mcp-v2-1",
			Verdict:    config.ActionBlock,
			Transport:  transportMCPStdio,
			Target:     "response:1",
			RequestID:  "1",
			Layer:      "mcp_response_scan",
			Pattern:    "Prompt Injection",
			PolicyHash: mcpTestPolicyHash,
		},
	})
	if err != nil {
		t.Fatalf("EmitMCPDecision: %v", err)
	}

	v2s := mcpV2Receipts(t, h)
	if len(v2s) != 1 {
		t.Fatalf("got %d v2 receipts, want 1", len(v2s))
	}
	if err := contractreceipt.VerifyWithKey(v2s[0], h.pub, h.kid); err != nil {
		t.Fatalf("v2 receipt verify: %v", err)
	}
	if v2s[0].PolicyHash != mcpTestPolicyHash {
		t.Fatalf("policy_hash = %q, want %q", v2s[0].PolicyHash, mcpTestPolicyHash)
	}
	var payload struct {
		ActionType string `json:"action_type"`
		Transport  string `json:"transport"`
	}
	if err := json.Unmarshal(v2s[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal v2 payload: %v", err)
	}
	if payload.ActionType != "mcp_tool_call" {
		t.Fatalf("action_type = %q, want mcp_tool_call", payload.ActionType)
	}
	if payload.Transport != transportMCPStdio {
		t.Fatalf("transport = %q, want %q", payload.Transport, transportMCPStdio)
	}
}

func TestEmitMCPDecision_V2EmitErrorSurfacesAfterV1(t *testing.T) {
	h := newMCPDecisionReceiptHarness(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{
		Recorder: failingMCPV2Recorder{},
		Signer:   proxydecision.NewKeyedSigner(priv),
	})
	if v2 == nil {
		t.Fatal("expected v2 emitter")
	}

	_, err = EmitMCPDecision(h.v1, v2, nil, MCPDecision{
		Receipt: receipt.EmitOpts{
			ActionID:   "mcp-v2-error",
			Verdict:    config.ActionBlock,
			Transport:  transportMCPStdio,
			Target:     "response:2",
			PolicyHash: mcpTestPolicyHash,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "v2 record failed") {
		t.Fatalf("EmitMCPDecision error = %v, want v2 record failure", err)
	}
	receipts := decisionReceiptLogFor(t, h.dir)
	if len(receipts) != 1 {
		t.Fatalf("got %d v1 receipts, want 1", len(receipts))
	}
	if receipts[0].ActionRecord.ActionID != "mcp-v2-error" {
		t.Fatalf("v1 action_id = %q, want mcp-v2-error", receipts[0].ActionRecord.ActionID)
	}
}

func TestEmitMCPDecision_RequiredV2EmitErrorFailsClosed(t *testing.T) {
	h := newMCPDecisionReceiptHarness(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{
		Recorder: failingMCPV2Recorder{},
		Signer:   proxydecision.NewKeyedSigner(priv),
	})
	if v2 == nil {
		t.Fatal("expected v2 emitter")
	}

	_, err = EmitMCPDecision(h.v1, v2, nil, MCPDecision{
		Receipt: receipt.EmitOpts{
			ActionID:   "mcp-v2-required-error",
			Verdict:    config.ActionAllow,
			Transport:  transportMCPStdio,
			Target:     "fetch",
			MCPMethod:  methodToolsCall,
			ToolName:   "fetch",
			PolicyHash: mcpTestPolicyHash,
		},
		RequireReceipt: true,
	})
	if !errors.Is(err, ErrReceiptRequired) {
		t.Fatalf("EmitMCPDecision error = %v, want ErrReceiptRequired", err)
	}
	if !strings.Contains(err.Error(), "v2 record failed") {
		t.Fatalf("EmitMCPDecision error = %v, want v2 record failure", err)
	}
	receipts := decisionReceiptLogFor(t, h.dir)
	if len(receipts) != 1 {
		t.Fatalf("got %d v1 receipts, want 1", len(receipts))
	}
	if receipts[0].ActionRecord.DecisionPhase != receipt.DecisionPhaseIntent {
		t.Fatalf("decision_phase = %q, want %q", receipts[0].ActionRecord.DecisionPhase, receipt.DecisionPhaseIntent)
	}
}

func TestEmitMCPV2Decision_RequiredDerivationFailureFailsClosed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{
		Recorder: failingMCPV2Recorder{},
		Signer:   proxydecision.NewKeyedSigner(priv),
	})
	if v2 == nil {
		t.Fatal("expected v2 emitter")
	}

	err = emitMCPV2Decision(v2, receipt.EmitOpts{
		ActionID:  "mcp-required-missing-target",
		Verdict:   config.ActionAllow,
		Transport: transportMCPStdio,
		// Target intentionally empty: v1 currently rejects this too, but the
		// required v2 helper must not silently skip configured v2 emission.
	}, true)
	if !errors.Is(err, errMCPV2ReceiptEmit) {
		t.Fatalf("emitMCPV2Decision error = %v, want errMCPV2ReceiptEmit", err)
	}
	if !strings.Contains(err.Error(), "could not derive v2 decision") {
		t.Fatalf("emitMCPV2Decision error = %v, want derivation failure detail", err)
	}
}

func TestEmitMCPDecision_OptionalV2EmitErrorStillInjectsEnvelope(t *testing.T) {
	h := newMCPDecisionReceiptHarness(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{
		Recorder: failingMCPV2Recorder{},
		Signer:   proxydecision.NewKeyedSigner(priv),
	})
	envEmitter := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: "policy-h"})
	inbound := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{}}}`)

	out, err := EmitMCPDecision(h.v1, v2, envEmitter, MCPDecision{
		Receipt: receipt.EmitOpts{
			ActionID:   "mcp-v2-optional-error",
			Verdict:    config.ActionAllow,
			Transport:  transportMCPStdio,
			Target:     "fetch",
			MCPMethod:  methodToolsCall,
			ToolName:   "fetch",
			PolicyHash: mcpTestPolicyHash,
		},
		Envelope: &envelope.BuildOpts{
			ActionID: "mcp-v2-optional-error",
			Action:   "tool_call",
			Verdict:  config.ActionAllow,
		},
		InboundMsg: inbound,
	})
	if err == nil || !strings.Contains(err.Error(), "v2 record failed") {
		t.Fatalf("EmitMCPDecision error = %v, want surfaced v2 record failure", err)
	}
	if errors.Is(err, ErrReceiptRequired) {
		t.Fatalf("optional v2 error = %v, must not be ErrReceiptRequired", err)
	}
	if bytes.Equal(out, inbound) || !strings.Contains(string(out), "com.pipelock/mediation") {
		t.Fatalf("optional v2 failure did not preserve envelope injection: %s", out)
	}
}

// TestMCPV2DecisionFromReceipt_SkipsEmptyTarget proves the helper refuses to
// build a v2 payload without a target, mirroring the forward proxy's
// v2DecisionFromOpts. The v2 emitter's validator requires a non-empty target,
// so a Decision built from a target-less EmitOpts could only ever be rejected.
// Today the v1 emitter also rejects an empty target and gates v2 off before
// this helper runs, but the guard keeps the v2 path self-defending if that
// coupling ever changes.
func TestMCPV2DecisionFromReceipt_SkipsEmptyTarget(t *testing.T) {
	if _, ok := mcpV2DecisionFromReceipt(receipt.EmitOpts{
		Verdict: config.ActionBlock,
		// Target intentionally empty.
	}); ok {
		t.Fatal("expected ok=false for empty target")
	}
	d, ok := mcpV2DecisionFromReceipt(receipt.EmitOpts{
		Target:  "fetch_url",
		Verdict: config.ActionBlock,
	})
	if !ok {
		t.Fatal("expected ok=true for non-empty target")
	}
	if d.Target != "fetch_url" {
		t.Fatalf("target = %q, want fetch_url", d.Target)
	}
}

func TestMCPV2DecisionFromReceipt_ProvenanceBranches(t *testing.T) {
	kill, ok := mcpV2DecisionFromReceipt(receipt.EmitOpts{
		Target:  "tool",
		Verdict: config.ActionBlock,
		Layer:   "kill_switch",
		Pattern: "kill",
	})
	if !ok {
		t.Fatal("expected kill-switch decision")
	}
	if kill.WinningSource != proxydecision.SourceKillSwitch {
		t.Fatalf("kill winning_source = %q, want kill_switch", kill.WinningSource)
	}
	if strings.Join(kill.PolicySources, ",") != proxydecision.SourceKillSwitch {
		t.Fatalf("kill policy_sources = %v, want kill_switch", kill.PolicySources)
	}
	if kill.RuleID != "kill" {
		t.Fatalf("kill RuleID = %q, want kill", kill.RuleID)
	}

	contractDecision, ok := mcpV2DecisionFromReceipt(receipt.EmitOpts{
		Target:                "tool",
		Verdict:               config.ActionBlock,
		ContractLiveVerdict:   config.ActionAllow,
		ContractPolicySources: []string{"manifest"},
		ContractRuleID:        "rule-1",
		ActiveManifestHash:    "manifest-hash",
		ContractHash:          "contract-hash",
		ContractSelectorID:    "selector",
		ContractGeneration:    7,
	})
	if !ok {
		t.Fatal("expected contract decision")
	}
	if contractDecision.WinningSource != proxydecision.SourceContract {
		t.Fatalf("contract winning_source = %q, want contract", contractDecision.WinningSource)
	}
	if !stringSliceContains(contractDecision.PolicySources, "manifest") ||
		!stringSliceContains(contractDecision.PolicySources, proxydecision.SourceContract) {
		t.Fatalf("contract policy_sources = %v, want manifest and contract", contractDecision.PolicySources)
	}
	if contractDecision.RuleID != "rule-1" || contractDecision.LiveVerdict != config.ActionAllow {
		t.Fatalf("contract rule/live = %q/%q, want rule-1/allow", contractDecision.RuleID, contractDecision.LiveVerdict)
	}
	if contractDecision.ActiveManifestHash != "manifest-hash" ||
		contractDecision.ContractHash != "contract-hash" ||
		contractDecision.SelectorID != "selector" ||
		contractDecision.ContractGeneration != 7 {
		t.Fatalf("contract envelope not preserved: %+v", contractDecision)
	}

	withContractSource, ok := mcpV2DecisionFromReceipt(receipt.EmitOpts{
		Target:                "tool",
		Verdict:               config.ActionBlock,
		ContractWinningSource: proxydecision.SourceContract,
		ContractPolicySources: []string{proxydecision.SourceContract},
	})
	if !ok {
		t.Fatal("expected contract-source decision")
	}
	if len(withContractSource.PolicySources) != 1 {
		t.Fatalf("contract source duplicated: %v", withContractSource.PolicySources)
	}
}

// The durable pre-egress guarantee must cover every forwardable verdict, not
// just allow: warn, forward, and strip all egress upstream, so their required
// decision receipt must be fsync-confirmed before the bytes leave. Only the
// durable (RecordDurable) path calls File.Sync, so an injected Sync failure
// makes a required forwardable verdict fail closed with recorder.ErrDurability
// while a non-forwardable verdict (no Sync call) is unaffected.
func TestEmitMCPDecision_ForwardableVerdictsEmitDurable(t *testing.T) {
	for _, verdict := range []string{config.ActionWarn, config.ActionForward, config.ActionStrip} {
		t.Run(verdict, func(t *testing.T) {
			recEmitter, rec, _, _ := newReceiptTestHarness(t)
			syncErr := errors.New("injected durable sync failure")
			rec.SetSyncForTest(func(*os.File) error { return syncErr })

			_, err := EmitMCPDecision(recEmitter, nil, nil, MCPDecision{
				Receipt: receipt.EmitOpts{
					ActionID:  "required-" + verdict,
					Verdict:   verdict,
					Transport: transportMCPStdio,
					Target:    "fetch",
					MCPMethod: methodToolsCall,
					ToolName:  "fetch",
				},
				RequireReceipt: true,
			})
			if !errors.Is(err, ErrReceiptRequired) {
				t.Fatalf("err = %v, want ErrReceiptRequired (forwardable %q must be durable)", err, verdict)
			}
			if !errors.Is(err, recorder.ErrDurability) {
				t.Fatalf("err = %v, want recorder.ErrDurability (forwardable %q took the non-durable path)", err, verdict)
			}
		})
	}
}

// A required block receipt does not egress upstream, so it stays on the
// non-durable Emit path: an injected Sync failure must NOT block it (no
// RecordDurable call means no Sync call). This proves broadening durability to
// the forwardable set did not accidentally make every verdict durable.
func TestEmitMCPDecision_NonForwardableVerdictStaysNonDurable(t *testing.T) {
	recEmitter, rec, _, _ := newReceiptTestHarness(t)
	rec.SetSyncForTest(func(*os.File) error {
		return errors.New("Sync must not be called for a non-durable verdict")
	})

	_, err := EmitMCPDecision(recEmitter, nil, nil, MCPDecision{
		Receipt: receipt.EmitOpts{
			ActionID:  "required-block",
			Verdict:   config.ActionBlock,
			Transport: transportMCPStdio,
			Target:    "fetch",
			MCPMethod: methodToolsCall,
			ToolName:  "fetch",
		},
		RequireReceipt: true,
	})
	if err != nil {
		t.Fatalf("err = %v, want nil (non-forwardable block must not take the durable/Sync path)", err)
	}
}

// Only allow carries DecisionPhaseIntent (paired with a downstream outcome);
// warn/forward/strip must stay single-phase so the completeness verifier counts
// them as neither an intent nor an outcome (no unmatched-intent).
func TestEmitMCPDecision_ForwardableVerdictsStaySinglePhase(t *testing.T) {
	for _, verdict := range []string{config.ActionWarn, config.ActionForward, config.ActionStrip} {
		t.Run(verdict, func(t *testing.T) {
			recEmitter, _, dir, _ := newReceiptTestHarness(t)
			_, err := EmitMCPDecision(recEmitter, nil, nil, MCPDecision{
				Receipt: receipt.EmitOpts{
					ActionID:  "single-phase-" + verdict,
					Verdict:   verdict,
					Transport: transportMCPStdio,
					Target:    "fetch",
					MCPMethod: methodToolsCall,
					ToolName:  "fetch",
				},
				RequireReceipt: true,
			})
			if err != nil {
				t.Fatalf("EmitMCPDecision(%s): %v", verdict, err)
			}
			receipts := decisionReceiptLogFor(t, dir)
			if len(receipts) != 1 {
				t.Fatalf("expected 1 receipt, got %d", len(receipts))
			}
			if phase := receipts[0].ActionRecord.DecisionPhase; phase == receipt.DecisionPhaseIntent {
				t.Fatalf("forwardable %q was marked DecisionPhaseIntent; want single-phase", verdict)
			}
		})
	}
}

// A deferred-resolution receipt carries DecisionPhaseResolution with a final
// allow verdict and a fresh ActionID (no paired outcome). It must keep its
// resolution phase, not be overwritten to intent — otherwise the completeness
// verifier would miscount it as an unmatched intent. Guards the phase-overwrite.
func TestEmitMCPDecision_RequiredResolutionAllowKeepsResolutionPhase(t *testing.T) {
	recEmitter, _, dir, _ := newReceiptTestHarness(t)
	_, err := EmitMCPDecision(recEmitter, nil, nil, MCPDecision{
		Receipt: receipt.EmitOpts{
			ActionID:      "resolution-allow-1",
			Verdict:       config.ActionAllow,
			Transport:     transportMCPStdio,
			Target:        "fetch",
			MCPMethod:     methodToolsCall,
			ToolName:      "fetch",
			DecisionPhase: receipt.DecisionPhaseResolution,
		},
		RequireReceipt: true,
	})
	if err != nil {
		t.Fatalf("EmitMCPDecision: %v", err)
	}
	receipts := decisionReceiptLogFor(t, dir)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if phase := receipts[0].ActionRecord.DecisionPhase; phase != receipt.DecisionPhaseResolution {
		t.Fatalf("decision_phase = %q, want %q (resolution phase overwritten to intent)", phase, receipt.DecisionPhaseResolution)
	}
}
