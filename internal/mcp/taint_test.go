// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

type taintRecorder struct {
	level int
	risk  session.SessionRisk
}

func (r *taintRecorder) RecordSignal(_ session.SignalType, _ float64) (bool, string, string) {
	return false, "", ""
}

func (r *taintRecorder) RecordClean(_ float64) {}

func (r *taintRecorder) EscalationLevel() int {
	return r.level
}

func (r *taintRecorder) ThreatScore() float64 {
	return 0
}

func (r *taintRecorder) RiskSnapshot() session.SessionRisk {
	return r.risk.Snapshot()
}

func (r *taintRecorder) ObserveRisk(observation session.RiskObservation) {
	r.risk.Observe(observation)
}

func TestForwardScanned_ExternalResponseContaminatesSession(t *testing.T) {
	t.Parallel()

	sc := testScannerWithAction(t, config.ActionWarn)
	rec := &taintRecorder{}
	cfg := config.Defaults()

	var out bytes.Buffer
	found, err := ForwardScanned(
		transport.NewStdioReader(bytes.NewBufferString(cleanResponse+"\n")),
		transport.NewStdioWriter(&out),
		&bytes.Buffer{},
		nil,
		MCPProxyOpts{
			Scanner:             sc,
			Rec:                 rec,
			TaintCfg:            &cfg.Taint,
			TaintExternalSource: true,
		},
	)
	if err != nil {
		t.Fatalf("ForwardScanned() error = %v", err)
	}
	if found {
		t.Fatal("expected clean response to remain clean")
	}
	if !rec.RiskSnapshot().Contaminated {
		t.Fatal("expected clean external MCP response to contaminate the session")
	}
	if rec.RiskSnapshot().Level != session.TaintExternalUntrusted {
		t.Fatalf("taint level = %v, want external_untrusted", rec.RiskSnapshot().Level)
	}
}

func TestForwardScanned_PromptHitMarksSessionHostile(t *testing.T) {
	t.Parallel()

	sc := testScannerWithAction(t, config.ActionWarn)
	rec := &taintRecorder{}
	cfg := config.Defaults()

	var out bytes.Buffer
	found, err := ForwardScanned(
		transport.NewStdioReader(bytes.NewBufferString(injectionResponse+"\n")),
		transport.NewStdioWriter(&out),
		&bytes.Buffer{},
		nil,
		MCPProxyOpts{
			Scanner:             sc,
			Rec:                 rec,
			TaintCfg:            &cfg.Taint,
			TaintExternalSource: true,
		},
	)
	if err != nil {
		t.Fatalf("ForwardScanned() error = %v", err)
	}
	if !found {
		t.Fatal("expected injection response to be detected")
	}
	if rec.RiskSnapshot().Level != session.TaintExternalHostile {
		t.Fatalf("taint level = %v, want external_hostile", rec.RiskSnapshot().Level)
	}
	if !rec.RiskSnapshot().PromptHit {
		t.Fatal("expected prompt_hit to be sticky")
	}
}

func TestScanHTTPInput_TaintProtectedWriteRequiresApproval(t *testing.T) {
	t.Parallel()

	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	rec.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://evil.example/issue/123",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
	})
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/repo/auth/middleware.go","content":"x"}}}`)

	blocked := scanHTTPInput(msg, &bytes.Buffer{}, "sess", "sess", MCPProxyOpts{
		Scanner:  sc,
		Rec:      rec,
		TaintCfg: &cfg.Taint,
	})
	if blocked == nil {
		t.Fatal("expected taint policy to block without approval")
	}
	if blocked.ErrorMessage != "pipelock: protected_write_after_untrusted_external_exposure" {
		t.Fatalf("error = %q", blocked.ErrorMessage)
	}
}

func TestScanHTTPInput_TaintApprovalIsOneShot(t *testing.T) {
	t.Parallel()

	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	rec.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://evil.example/issue/123",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
	})
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/repo/auth/middleware.go","content":"x"}}}`)

	allowed := scanHTTPInput(msg, &bytes.Buffer{}, "sess", "sess", MCPProxyOpts{
		Scanner:   sc,
		Approver:  testApproverForMCP(t, "y\n"),
		Rec:       rec,
		TaintCfg:  &cfg.Taint,
		Transport: "mcp_http",
	})
	if allowed != nil {
		t.Fatalf("expected approved request to pass, got block: %+v", allowed)
	}
	if !rec.RiskSnapshot().Contaminated {
		t.Fatal("approval should not clear session contamination")
	}

	blocked := scanHTTPInput(msg, &bytes.Buffer{}, "sess", "sess", MCPProxyOpts{
		Scanner:  sc,
		Rec:      rec,
		TaintCfg: &cfg.Taint,
	})
	if blocked == nil {
		t.Fatal("expected second action to require approval again")
	}
}

func TestScanHTTPInputDecision_ApprovedToolCarriesEnvelope(t *testing.T) {
	t.Parallel()

	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	rec.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://evil.example/issue/123",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
	})
	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/repo/auth/middleware.go","content":"x"}}}`)

	decision := scanHTTPInputDecision(msg, &bytes.Buffer{}, "sess", "sess", MCPProxyOpts{
		Scanner:         sc,
		Approver:        testApproverForMCP(t, "y\n"),
		Rec:             rec,
		TaintCfg:        &cfg.Taint,
		Transport:       "mcp_http",
		EnvelopeEmitter: envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: "test"}),
	})
	if decision.Blocked != nil {
		t.Fatalf("expected approved request to pass, got block: %+v", decision.Blocked)
	}

	var rpc struct {
		Params struct {
			Meta map[string]json.RawMessage `json:"_meta"`
		} `json:"params"`
	}
	if err := json.Unmarshal(decision.ForwardMessage, &rpc); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	envData, ok := rpc.Params.Meta[envelope.MCPMetaKey]
	if !ok {
		t.Fatal("expected mediation envelope in forwarded message")
	}
	var meta map[string]any
	if err := json.Unmarshal(envData, &meta); err != nil {
		t.Fatalf("json.Unmarshal envelope error = %v", err)
	}
	if meta["auth"] != session.AuthorityOperatorOverride.String() {
		t.Fatalf("auth = %v, want %q", meta["auth"], session.AuthorityOperatorOverride.String())
	}
	if meta["reauth"] != true {
		t.Fatalf("reauth = %v, want true", meta["reauth"])
	}
}

func TestEvaluateMCPTaint_TrustOverrideHonorsScope(t *testing.T) {
	t.Parallel()

	sc := testScannerWithAction(t, config.ActionWarn)
	cfg := config.Defaults()
	rec := &taintRecorder{}
	rec.ObserveRisk(session.RiskObservation{
		Source: session.TaintSourceRef{
			URL:   "https://evil.example/issue/123",
			Kind:  "http_response",
			Level: session.TaintExternalUntrusted,
		},
	})
	cfg.Taint.TrustOverrides = []config.TaintTrustOverride{{
		Scope:       "source",
		SourceMatch: "https://evil.example/*",
		ExpiresAt:   nowPlusHour(t),
	}}

	decision := evaluateMCPTaint(MCPProxyOpts{
		Scanner:  sc,
		Rec:      rec,
		TaintCfg: &cfg.Taint,
	}, "write_file", `{"path":"/repo/auth/middleware.go","content":"x"}`)
	if decision.Result.Decision != session.PolicyAllow {
		t.Fatalf("decision = %v, want allow", decision.Result.Decision)
	}

	cfg.Taint.TrustOverrides = []config.TaintTrustOverride{{
		Scope:       "action",
		ActionMatch: "mcp:write_file:/repo/auth/*",
		ExpiresAt:   nowPlusHour(t),
	}}
	decision = evaluateMCPTaint(MCPProxyOpts{
		Scanner:  sc,
		Rec:      rec,
		TaintCfg: &cfg.Taint,
	}, "write_file", `{"path":"/repo/auth/middleware.go","content":"x"}`)
	if decision.Result.Decision != session.PolicyAllow {
		t.Fatalf("decision = %v, want allow", decision.Result.Decision)
	}

	cfg.Taint.TrustOverrides = []config.TaintTrustOverride{{
		Scope:       "source",
		ActionMatch: "mcp:write_file:/repo/auth/*",
		ExpiresAt:   nowPlusHour(t),
	}}
	decision = evaluateMCPTaint(MCPProxyOpts{
		Scanner:  sc,
		Rec:      rec,
		TaintCfg: &cfg.Taint,
	}, "write_file", `{"path":"/repo/auth/middleware.go","content":"x"}`)
	if decision.Result.Decision != session.PolicyAsk {
		t.Fatalf("decision = %v, want ask when scope=source has no source_match", decision.Result.Decision)
	}
}

func nowPlusHour(t *testing.T) time.Time {
	t.Helper()
	return time.Now().UTC().Add(time.Hour)
}
