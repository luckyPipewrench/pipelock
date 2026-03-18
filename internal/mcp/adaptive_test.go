// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// mockRecorder is a test-only implementation of session.Recorder that captures
// signal calls so tests can assert on adaptive side-effects without needing a
// real SessionManager.
type mockRecorder struct {
	signals []session.SignalType
	cleans  int
	score   float64
	level   int
}

func (m *mockRecorder) RecordSignal(sig session.SignalType, _ float64) (bool, string, string) {
	m.signals = append(m.signals, sig)
	m.score += session.SignalPoints[sig]
	return false, "", ""
}

func (m *mockRecorder) RecordClean(_ float64) { m.cleans++ }
func (m *mockRecorder) EscalationLevel() int  { return m.level }
func (m *mockRecorder) ThreatScore() float64  { return m.score }

// adaptiveCfgEnabled returns a minimal enabled AdaptiveEnforcement config.
// EscalationThreshold is set high (100) so unit tests never accidentally
// trigger escalation and alter the effective action under test.
func adaptiveCfgEnabled() *config.AdaptiveEnforcement {
	return &config.AdaptiveEnforcement{
		Enabled:              true,
		EscalationThreshold:  100.0,
		DecayPerCleanRequest: 0.5,
	}
}

// buildBlockChainMatcher creates a chains.Matcher with a single custom pattern
// that blocks the sequence ["read", "exec"]. The built-in "read-then-exec"
// pattern is warn-only, so we need a custom block-action pattern to exercise
// the block-signal recording path.
func buildBlockChainMatcher() *chains.Matcher {
	cfg := &config.ToolChainDetection{
		Enabled:       true,
		WindowSize:    50,
		WindowSeconds: 300,
		CustomPatterns: []config.ChainPattern{
			{
				Name:     "test-block-chain",
				Sequence: []string{"read", "exec"},
				Severity: "critical",
				Action:   config.ActionBlock,
			},
		},
	}
	return chains.New(cfg)
}

// newAdaptiveTestScanner creates an isolated scanner for adaptive tests with
// SSRF disabled (no DNS lookups in unit tests).
func newAdaptiveTestScanner() *scanner.Scanner {
	cfg := config.Defaults()
	cfg.Internal = nil
	return scanner.New(cfg)
}

// runAdaptiveInput calls ForwardScannedInput with the given recorder and adaptive
// config, using nil for all other optional parameters. The function blocks until
// the reader is exhausted.
func runAdaptiveInput(
	input string,
	rec session.Recorder,
	adaptiveCfg *config.AdaptiveEnforcement,
	chainMatcher *chains.Matcher,
	action string,
) string {
	sc := newAdaptiveTestScanner()
	defer sc.Close()

	var serverBuf bytes.Buffer
	var logBuf bytes.Buffer
	blockedCh := make(chan BlockedRequest, 20)

	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(input)),
		transport.NewStdioWriter(&serverBuf),
		&logBuf,
		sc,
		action,
		config.ActionBlock, // onParseError
		blockedCh,
		nil, // policyCfg
		nil, // bindingCfg
		nil, // ks
		chainMatcher,
		nil, // tracker (nil-safe via RequestTracker.Track guard)
		nil, // auditLogger
		nil, // cee
		rec,
		adaptiveCfg,
		nil, // metrics
	)

	return serverBuf.String()
}

// TestMCP_Adaptive_ChainBlockRecordsSignalBlock verifies that when chain
// detection fires a block action, SignalBlock (+3 points) is recorded on the
// session recorder before the request is rejected.
func TestMCP_Adaptive_ChainBlockRecordsSignalBlock(t *testing.T) {
	chainMatcher := buildBlockChainMatcher()
	rec := &mockRecorder{}
	adaptiveCfg := adaptiveCfgEnabled()

	// Send read_file (classified as "read") then bash_exec (classified as
	// "exec") to trigger the custom test-block-chain pattern.
	readMsg := makeRequest(1, methodToolsCall, map[string]interface{}{
		"name":      "read_file",
		"arguments": map[string]string{"path": "/tmp/safe.txt"},
	}) + "\n"
	execMsg := makeRequest(2, methodToolsCall, map[string]interface{}{
		"name":      "bash_exec",
		"arguments": map[string]string{"command": "ls"},
	}) + "\n"

	runAdaptiveInput(readMsg+execMsg, rec, adaptiveCfg, chainMatcher, config.ActionBlock)

	// The chain block must have recorded SignalBlock.
	wantPoints := session.SignalPoints[session.SignalBlock]
	if rec.ThreatScore() < wantPoints {
		t.Errorf("ThreatScore = %.1f, want >= %.1f (at least one SignalBlock)", rec.ThreatScore(), wantPoints)
	}

	hasBlock := false
	for _, sig := range rec.signals {
		if sig == session.SignalBlock {
			hasBlock = true
			break
		}
	}
	if !hasBlock {
		t.Errorf("expected SignalBlock in recorded signals after chain block, got: %v", rec.signals)
	}
}

// TestMCP_Adaptive_CleanInputDecaysScore verifies that clean MCP input
// messages cause RecordClean to be called, which is how score decays over time.
func TestMCP_Adaptive_CleanInputDecaysScore(t *testing.T) {
	rec := &mockRecorder{}
	adaptiveCfg := adaptiveCfgEnabled()

	// Pre-load a positive threat score directly.
	_, _, _ = rec.RecordSignal(session.SignalNearMiss, adaptiveCfg.EscalationThreshold)
	_, _, _ = rec.RecordSignal(session.SignalNearMiss, adaptiveCfg.EscalationThreshold)
	if rec.ThreatScore() <= 0 {
		t.Fatalf("pre-condition: expected positive score before clean input, got %.1f", rec.ThreatScore())
	}

	// Send a clean message through the proxy.
	cleanMsg := makeRequest(3, "tools/list", nil) + "\n"
	runAdaptiveInput(cleanMsg, rec, adaptiveCfg, nil, config.ActionBlock)

	// RecordClean must have been called at least once.
	if rec.cleans == 0 {
		t.Error("expected RecordClean to be called at least once for clean input message")
	}
}

// TestMCP_Adaptive_DLPBlockRecordsSignalBlock verifies that a DLP-blocked MCP
// input with block action records SignalBlock (+3 points) on the recorder.
func TestMCP_Adaptive_DLPBlockRecordsSignalBlock(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{
			name:   "anthropic_key_pattern",
			secret: testSecretPrefix + strings.Repeat("m", 25),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &mockRecorder{}
			adaptiveCfg := adaptiveCfgEnabled()

			dirtyMsg := makeRequest(4, methodToolsCall, map[string]string{"api_key": tt.secret}) + "\n"
			runAdaptiveInput(dirtyMsg, rec, adaptiveCfg, nil, config.ActionBlock)

			wantPoints := session.SignalPoints[session.SignalBlock]
			if rec.ThreatScore() < wantPoints {
				t.Errorf("ThreatScore = %.1f, want >= %.1f after DLP block", rec.ThreatScore(), wantPoints)
			}

			hasBlock := false
			for _, sig := range rec.signals {
				if sig == session.SignalBlock {
					hasBlock = true
					break
				}
			}
			if !hasBlock {
				t.Errorf("expected SignalBlock in signals after DLP block, got: %v", rec.signals)
			}
		})
	}
}

// TestMCP_Adaptive_WarnRecordsNearMiss verifies that a DLP hit with warn action
// records SignalNearMiss (+1 point) and never SignalBlock.
func TestMCP_Adaptive_WarnRecordsNearMiss(t *testing.T) {
	rec := &mockRecorder{}
	adaptiveCfg := adaptiveCfgEnabled()

	secret := testSecretPrefix + strings.Repeat("n", 25)
	dirtyMsg := makeRequest(5, methodToolsCall, map[string]string{"api_key": secret}) + "\n"
	runAdaptiveInput(dirtyMsg, rec, adaptiveCfg, nil, config.ActionWarn)

	hasNearMiss := false
	for _, sig := range rec.signals {
		if sig == session.SignalNearMiss {
			hasNearMiss = true
		}
		if sig == session.SignalBlock {
			t.Errorf("unexpected SignalBlock for warn-action request, signals: %v", rec.signals)
		}
	}
	if !hasNearMiss {
		t.Errorf("expected SignalNearMiss in signals for warn-action hit, got: %v", rec.signals)
	}
}

// TestMCP_Adaptive_NilRecorderNoOp verifies that a nil recorder causes no panic
// and that clean requests are still forwarded correctly.
func TestMCP_Adaptive_NilRecorderNoOp(t *testing.T) {
	cleanMsg := makeRequest(6, "tools/list", nil) + "\n"
	serverOut := runAdaptiveInput(cleanMsg, nil, nil, nil, config.ActionBlock)

	if !strings.Contains(serverOut, "tools/list") {
		t.Error("expected clean request to be forwarded when recorder is nil")
	}
}

// TestMCP_Adaptive_DisabledAdaptiveSkipsSignals verifies that when
// AdaptiveEnforcement.Enabled is false, no signals or RecordClean calls are
// made even for blocked or clean requests.
func TestMCP_Adaptive_DisabledAdaptiveSkipsSignals(t *testing.T) {
	tests := []struct {
		name  string
		input func() string
	}{
		{
			name: "blocked_dlp_request",
			input: func() string {
				secret := testSecretPrefix + strings.Repeat("p", 25)
				return makeRequest(7, methodToolsCall, map[string]string{"key": secret}) + "\n"
			},
		},
		{
			name: "clean_request",
			input: func() string {
				return makeRequest(8, "tools/list", nil) + "\n"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &mockRecorder{}
			disabledCfg := &config.AdaptiveEnforcement{
				Enabled:              false,
				EscalationThreshold:  5.0,
				DecayPerCleanRequest: 0.5,
			}

			runAdaptiveInput(tt.input(), rec, disabledCfg, nil, config.ActionBlock)

			if len(rec.signals) != 0 {
				t.Errorf("expected no signals when adaptive is disabled, got: %v", rec.signals)
			}
			if rec.cleans != 0 {
				t.Errorf("expected no RecordClean calls when adaptive is disabled, got %d", rec.cleans)
			}
		})
	}
}

// TestMCP_Adaptive_MultipleBlocksAccumulate verifies that multiple blocked
// requests in sequence accumulate SignalBlock points additively.
func TestMCP_Adaptive_MultipleBlocksAccumulate(t *testing.T) {
	const blockCount = 3

	rec := &mockRecorder{}
	adaptiveCfg := adaptiveCfgEnabled()

	secret := testSecretPrefix + strings.Repeat("q", 25)
	var input strings.Builder
	for i := range blockCount {
		input.WriteString(makeRequest(i+10, methodToolsCall, map[string]string{"k": secret}) + "\n")
	}

	runAdaptiveInput(input.String(), rec, adaptiveCfg, nil, config.ActionBlock)

	wantMinScore := float64(blockCount) * session.SignalPoints[session.SignalBlock]
	if rec.ThreatScore() < wantMinScore {
		t.Errorf("ThreatScore = %.1f, want >= %.1f (%d blocks × %.1f pts each)",
			rec.ThreatScore(), wantMinScore, blockCount, session.SignalPoints[session.SignalBlock])
	}

	var blockSignals int
	for _, sig := range rec.signals {
		if sig == session.SignalBlock {
			blockSignals++
		}
	}
	if blockSignals < blockCount {
		t.Errorf("expected >= %d SignalBlock entries, got %d (signals: %v)", blockCount, blockSignals, rec.signals)
	}
}
