// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestCardJSONNumberOnlyAuditAndBodyAction(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	for _, body := range []string{`[4111,1111,1111,1111]`, `[4111.0,1111.0,1111.0,1111.0]`} {
		for _, redaction := range []bool{false, true} {
			req := BodyScanRequest{Body: strings.NewReader(body), ContentType: "application/json", MaxBytes: 1 << 20, Scanner: s, Action: config.ActionBlock}
			if redaction {
				req.RedactMatcher = redact.NewDefaultMatcher()
			}
			out, result := scanRequestBody(t.Context(), req)
			if result.Clean || result.Action != config.ActionWarn || len(result.DLPMatches) == 0 || string(out) != body {
				t.Fatal("number-only body did not retain warning and original values")
			}
			if !result.IsInformationalCardRuns() || !isBodyAdaptiveExempt(scannerLabelBodyDLP, result, "api.vendor.example", cfg) {
				t.Fatal("number-only warning eligible for adaptive block")
			}
			mixed := result
			mixed.InjectionMatches = []scanner.ResponseMatch{{PatternName: "synthetic injection"}}
			if mixed.IsInformationalCardRuns() {
				t.Fatal("warning masked another finding")
			}
			var records bytes.Buffer
			log, err := audit.NewWithStream("json", "stdout", "", true, true, &records)
			if err != nil {
				t.Fatal(err)
			}
			r, _ := newWebSocketFrameSuppressionRelay(t, cfg, "wss://api.vendor.example/socket")
			cfg.AdaptiveEnforcement.Enabled = true
			sm := NewSessionManager(testSessionConfig(), nil, nil)
			t.Cleanup(sm.Close)
			sess := sm.GetOrCreate(testClientIP)
			r.rec = sess
			sess.RecordSignal(session.SignalBlock, 1)
			score := sess.ThreatScore()
			if r.handleClientTextFindings(log, result.DLPMatches, nil) {
				t.Fatal("enforcing WebSocket closed on number-only finding")
			}
			if sess.ThreatScore() != score {
				t.Fatal("number-only WebSocket warning changed the adaptive score")
			}
			log.Close()
			if !strings.Contains(records.String(), `"action":"audit"`) || !strings.Contains(records.String(), "Credit Card Number") {
				t.Fatalf("WebSocket warning not visible: %s", records.String())
			}
		}
	}
}

func TestCardJSONHTTPAndWSInspectionLimits(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	for _, body := range []string{`[1e10001]`, `[` + strings.Repeat("9", 4097) + `]`, strings.Repeat("[", 65) + "1" + strings.Repeat("]", 65)} {
		_, result := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(body), ContentType: "application/json", MaxBytes: 1 << 20, Scanner: s, Action: config.ActionBlock})
		if result.Clean || result.Action != config.ActionBlock {
			t.Fatal("body inspection limit did not refuse")
		}
		r, _ := newWebSocketFrameSuppressionRelay(t, cfg, "wss://api.vendor.example/socket")
		if !r.scanClientText(t.Context(), audit.NewNop(), []byte(body)) {
			t.Fatal("WebSocket inspection limit did not refuse")
		}
	}
}

func TestCardJSONBodyMixedMatchOrder(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	warnings := s.ScanJSONCardRuns(t.Context(), `[4111,1111,1111,1111]`)
	card := "4111" + "1111" + "1111" + "1111"
	enforcing := s.ScanTextForDLP(t.Context(), card).Matches
	if len(warnings) == 0 || len(enforcing) == 0 {
		t.Fatal("mixed-match controls did not detect cards")
	}
	for _, matches := range [][]scanner.TextDLPMatch{
		append(append([]scanner.TextDLPMatch{}, warnings...), enforcing...),
		append(append([]scanner.TextDLPMatch{}, enforcing...), warnings...),
	} {
		if requestBodyDLPAction(matches, config.ActionBlock, nil) != config.ActionBlock {
			t.Fatal("number-only warning downgraded an enforcing match")
		}
	}
}

func TestCardJSONA2AStreamDispatchRecordsWarning(t *testing.T) {
	s := ssetestScanner(t)
	t.Cleanup(s.Close)
	stream := "data: [4111.0,1111.0,1111.0,1111.0]\n\n"
	var out bytes.Buffer
	warnings, receipts := 0, 0
	err := DispatchSSEScan(t.Context(), strings.NewReader(stream), &out, nil, s, SSEDispatchOptions{
		IsA2A: true,
		A2A:   &config.A2AScanning{Enabled: true, Action: config.ActionBlock},
		Generic: mcp.GenericSSEScanOptions{
			OnFinding:      func(error) { warnings++ },
			ConfirmFinding: func(error) error { receipts++; return nil },
		},
	})
	if err != nil || out.String() != stream || warnings != 1 || receipts != 1 {
		t.Fatalf("dispatch warning/receipt missing: warnings=%d receipts=%d err=%v", warnings, receipts, err)
	}
}

func TestCardJSONNumberSeamRetainsRedactionRefusal(t *testing.T) {
	for _, knownMatch := range []bool{false, true} {
		cfg := testScannerConfig()
		cfg.DLP.ScanEnv = false
		applyRedactionTestProfile(cfg)
		enforce := false
		cfg.Enforce = &enforce
		card := "4111" + "1111" + "1111" + "1111"
		if knownMatch {
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Numeric seam credential", Regex: card, Severity: config.SeverityHigh})
		}
		s := scanner.MustNew(cfg)
		t.Cleanup(s.Close)
		r, _ := newWebSocketFrameSuppressionRelay(t, cfg, "wss://api.vendor.example/socket")
		r.scanner = s
		runtime, err := r.proxy.buildRedactionRuntimeWithScanner(cfg, s)
		if err != nil || runtime == nil || !runtime.required {
			t.Fatalf("redaction runtime: %v", err)
		}
		r.redaction = runtime
		cards := "41111111" + jsonnumber.NumberBoundary + "11111111"
		if blocked := r.scanClientNumberText(t.Context(), audit.NewNop(), []byte(card), []byte(cards)); blocked != knownMatch {
			t.Fatalf("numeric seam blocked=%v want=%v", blocked, knownMatch)
		}
	}
}
