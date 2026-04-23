// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// decisionReceiptLogFor reads the evidence-proxy chain log from the dir
// produced by newReceiptTestHarness (proxy_test.go). Using the harness
// directly keeps these tests aligned with the rest of the receipt-emit
// suite and avoids duplicating the signing-key + recorder plumbing.
func decisionReceiptLogFor(t *testing.T, dir string) []receipt.Receipt {
	t.Helper()
	return readActionReceipts(t, dir)
}

func TestEmitMCPDecision_NilEmittersNoOp(t *testing.T) {
	// With nil emitters, the helper must not panic and must return
	// the InboundMsg verbatim.
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`)
	out, err := EmitMCPDecision(nil, nil, MCPDecision{
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

	_, err := EmitMCPDecision(emitter, nil, MCPDecision{
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

func TestEmitMCPDecision_ReceiptOnly(t *testing.T) {
	emitter, _, dir, _ := newReceiptTestHarness(t)

	_, err := EmitMCPDecision(emitter, nil, MCPDecision{
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
	out, err := EmitMCPDecision(nil, envEmitter, MCPDecision{
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

	out, err := EmitMCPDecision(nil, envEmitter, MCPDecision{
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
	out, err := EmitMCPDecision(recEmitter, envEmitter, MCPDecision{
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

func TestEmitMCPDecision_ReceiptErrorDoesNotBlockEnvelope(t *testing.T) {
	// A nil receipt emitter is the closest to a "fails/skips" signal
	// we can induce without a bespoke error-injecting fake. The helper
	// must still inject the envelope. Covers the documented contract
	// that the two stages are independent.
	envEmitter := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: "h"})
	inbound := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`)

	out, err := EmitMCPDecision(nil, envEmitter, MCPDecision{
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
