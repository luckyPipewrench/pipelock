// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	testMCPSessionKey = "session-001"
	testMCPAgent      = "myagent"
	testMCPSessionIP  = "10.0.0.1"

	// Fake AWS key suffix, built as constant to avoid repetition.
	// Combined with prefix at runtime to avoid gosec G101.
	testMCPAWSKeySuffix = "IOSF" + "ODNN7EXAMPLE"

	// 300 second window (5 minutes), matching entropy budget default.
	testMCPWindowSecs = 300
)

// testMCPScanner creates a Scanner with default DLP patterns and SSRF disabled.
func testMCPScanner() *scanner.Scanner {
	cfg := config.Defaults()
	cfg.Internal = nil // disable SSRF (no DNS in unit tests)
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	return scanner.New(cfg)
}

func TestCeeSessionKeyMCP_EmptyAgent(t *testing.T) {
	got := ceeSessionKeyMCP("", testMCPSessionIP)
	if got != testMCPSessionIP {
		t.Errorf("ceeSessionKeyMCP(%q, %q) = %q, want %q", "", testMCPSessionIP, got, testMCPSessionIP)
	}
}

func TestCeeSessionKeyMCP_WithAgent(t *testing.T) {
	got := ceeSessionKeyMCP(testMCPAgent, testMCPSessionIP)
	want := testMCPAgent + "|" + testMCPSessionIP
	if got != want {
		t.Errorf("ceeSessionKeyMCP(%q, %q) = %q, want %q", testMCPAgent, testMCPSessionIP, got, want)
	}
}

func TestCeeRecordMCP_NilCEE(t *testing.T) {
	reason := ceeRecordMCP(testMCPSessionKey, []byte("payload"), nil, nil, &bytes.Buffer{}, nil)
	if reason != "" {
		t.Errorf("expected empty reason for nil CEE, got %q", reason)
	}
}

func TestCeeRecordMCP_EmptyPayload(t *testing.T) {
	cee := &CEEDeps{}
	reason := ceeRecordMCP(testMCPSessionKey, []byte{}, cee, nil, &bytes.Buffer{}, nil)
	if reason != "" {
		t.Errorf("expected empty reason for empty payload, got %q", reason)
	}

	// Also test nil payload.
	reason = ceeRecordMCP(testMCPSessionKey, nil, cee, nil, &bytes.Buffer{}, nil)
	if reason != "" {
		t.Errorf("expected empty reason for nil payload, got %q", reason)
	}
}

func TestCeeRecordMCP_EntropyBudgetBlock(t *testing.T) {
	// Use a tiny budget so we exceed it immediately.
	et := scanner.NewEntropyTracker(1.0, testMCPWindowSecs)
	defer et.Close()

	m := metrics.New()
	logger, err := audit.New("json", "stdout", "", false, false)
	if err != nil {
		t.Fatal(err)
	}

	ceeCfg := &config.CrossRequestDetection{
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 1.0,
			WindowMinutes: testMCPWindowSecs / 60,
			Action:        config.ActionBlock,
		},
	}
	cee := &CEEDeps{
		Tracker: et,
		Metrics: m,
		Config:  ceeCfg,
	}

	sc := testMCPScanner()
	defer sc.Close()

	var logBuf bytes.Buffer
	payload := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz")
	reason := ceeRecordMCP(testMCPSessionKey, payload, cee, sc, &logBuf, logger)

	if reason == "" {
		t.Fatal("expected non-empty reason for entropy budget block")
	}

	// Log output should mention CEE.
	if !bytes.Contains(logBuf.Bytes(), []byte("CEE")) {
		t.Error("expected log output to contain CEE")
	}
}

func TestCeeRecordMCP_EntropyBudgetWarn(t *testing.T) {
	// Use a tiny budget so we exceed it immediately.
	et := scanner.NewEntropyTracker(1.0, testMCPWindowSecs)
	defer et.Close()

	m := metrics.New()

	ceeCfg := &config.CrossRequestDetection{
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 1.0,
			WindowMinutes: testMCPWindowSecs / 60,
			Action:        config.ActionWarn,
		},
	}
	cee := &CEEDeps{
		Tracker: et,
		Metrics: m,
		Config:  ceeCfg,
	}

	var logBuf bytes.Buffer
	payload := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz")
	reason := ceeRecordMCP(testMCPSessionKey, payload, cee, nil, &logBuf, nil)

	// Warn mode: should NOT block (empty reason).
	if reason != "" {
		t.Errorf("expected empty reason for warn mode, got %q", reason)
	}

	// Log output should still mention CEE (warning was emitted).
	if !bytes.Contains(logBuf.Bytes(), []byte("CEE")) {
		t.Error("expected log output to contain CEE for warn mode")
	}
}

func TestCeeRecordMCP_FragmentDLPBlock(t *testing.T) {
	fb := scanner.NewFragmentBuffer(65536, 1000, testMCPWindowSecs)
	defer fb.Close()

	sc := testMCPScanner()
	defer sc.Close()

	m := metrics.New()
	logger, err := audit.New("json", "stdout", "", false, false)
	if err != nil {
		t.Fatal(err)
	}

	ceeCfg := &config.CrossRequestDetection{
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  testMCPWindowSecs / 60,
		},
		Action: config.ActionBlock,
	}
	cee := &CEEDeps{
		Buffer:  fb,
		Metrics: m,
		Config:  ceeCfg,
	}

	// Build fake AWS key at runtime to avoid gosec G101.
	part1 := "AKI" + "A"
	part2 := testMCPAWSKeySuffix

	var logBuf bytes.Buffer

	// First fragment: not enough to trigger.
	reason := ceeRecordMCP(testMCPSessionKey, []byte(part1), cee, sc, &logBuf, logger)
	if reason != "" {
		t.Fatalf("expected no block on first fragment, got %q", reason)
	}

	// Second fragment: completes the key, should block.
	reason = ceeRecordMCP(testMCPSessionKey, []byte(part2), cee, sc, &logBuf, logger)
	if reason == "" {
		t.Fatal("expected non-empty reason for fragment DLP block")
	}
}

func TestCeeRecordMCP_FragmentDLPWarn(t *testing.T) {
	fb := scanner.NewFragmentBuffer(65536, 1000, testMCPWindowSecs)
	defer fb.Close()

	sc := testMCPScanner()
	defer sc.Close()

	m := metrics.New()
	logger, err := audit.New("json", "stdout", "", false, false)
	if err != nil {
		t.Fatal(err)
	}

	ceeCfg := &config.CrossRequestDetection{
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  testMCPWindowSecs / 60,
		},
		Action: config.ActionWarn, // warn, not block
	}
	cee := &CEEDeps{
		Buffer:  fb,
		Metrics: m,
		Config:  ceeCfg,
	}

	// Build fake AWS key at runtime to avoid gosec G101.
	part1 := "AKI" + "A"
	part2 := testMCPAWSKeySuffix

	var logBuf bytes.Buffer

	// First fragment.
	reason := ceeRecordMCP("warn-session", []byte(part1), cee, sc, &logBuf, logger)
	if reason != "" {
		t.Fatalf("expected no block on first fragment, got %q", reason)
	}

	// Second fragment: completes the key. Warn mode should NOT block.
	reason = ceeRecordMCP("warn-session", []byte(part2), cee, sc, &logBuf, logger)
	if reason != "" {
		t.Errorf("expected empty reason for warn mode, got %q", reason)
	}

	// Log output should still mention CEE (warning emitted).
	if !bytes.Contains(logBuf.Bytes(), []byte("CEE")) {
		t.Error("expected log output to contain CEE for warn mode")
	}
}

func TestCeeRecordMCP_EntropyBudgetWarnWithLogger(t *testing.T) {
	et := scanner.NewEntropyTracker(1.0, testMCPWindowSecs)
	defer et.Close()

	m := metrics.New()
	logger, err := audit.New("json", "stdout", "", false, false)
	if err != nil {
		t.Fatal(err)
	}

	ceeCfg := &config.CrossRequestDetection{
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 1.0,
			WindowMinutes: testMCPWindowSecs / 60,
			Action:        config.ActionWarn,
		},
	}
	cee := &CEEDeps{
		Tracker: et,
		Metrics: m,
		Config:  ceeCfg,
	}

	var logBuf bytes.Buffer
	payload := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz")
	reason := ceeRecordMCP(testMCPSessionKey, payload, cee, nil, &logBuf, logger)

	// Warn mode: should NOT block.
	if reason != "" {
		t.Errorf("expected empty reason for warn mode, got %q", reason)
	}
}
