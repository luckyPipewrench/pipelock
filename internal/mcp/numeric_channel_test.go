// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func numericCodes(value string) string {
	parts := make([]string, 0, len(value))
	for _, r := range value {
		parts = append(parts, strconv.Itoa(int(r)))
	}
	return strings.Join(parts, ",")
}

func numericChannelScanner(t *testing.T, canary string) *scanner.Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.CanaryTokens.Enabled = true
	cfg.CanaryTokens.Tokens = []config.CanaryToken{{Name: "planted", Value: canary}}
	// A digits-only DLP pattern that WOULD fire if numeric leaves were ever
	// joined into the general text view.
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Sixteen Digits", Regex: `\b\d{16}\b`, Severity: "high"})
	return scanner.MustNew(cfg)
}

func hasCanaryMatch(matches []scanner.TextDLPMatch) bool {
	for _, m := range matches {
		if strings.HasPrefix(m.PatternName, "Canary Token (") {
			return true
		}
	}
	return false
}

// TestScanResponse_NumericLeavesReachKnownValueMatching is the live probe from
// the row that motivated this change: a canary spelled out as decimal character
// codes under structuredContent extracted to empty text and was reported clean.
func TestScanResponse_NumericLeavesReachKnownValueMatching(t *testing.T) {
	canary := "canary-" + "7f3a9c2e4b1d"
	sc := numericChannelScanner(t, canary)
	codes := numericCodes(canary)

	for _, tt := range []struct {
		name string
		line string
	}{
		{name: "structuredContent array", line: `{"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{"payload":[` + codes + `]}}}`},
		{name: "structuredContent beside visible text", line: `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"done"}],"structuredContent":{"payload":[` + codes + `]}}}`},
		{name: "non-standard result shape", line: `{"jsonrpc":"2.0","id":1,"result":{"rows":[{"v":[` + codes + `]}]}}`},
		{name: "error data", line: `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"failed","data":{"debug":[` + codes + `]}}}`},
		{name: "notification params", line: `{"jsonrpc":"2.0","method":"notifications/message","params":{"data":[` + codes + `]}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := ScanResponse([]byte(tt.line), sc)
			if v.Clean || v.Error != "" {
				t.Fatalf("expected a canary finding, got clean=%v error=%q", v.Clean, v.Error)
			}
			if !hasCanaryMatch(v.DLPMatches) {
				t.Fatalf("expected a canary DLP match, got %+v", v.DLPMatches)
			}
		})
	}
}

func TestScanResponse_NumericCanaryScalar(t *testing.T) {
	sc := numericChannelScanner(t, "8675309123456789")
	line := `{"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{"value":8675309123456789}}}`
	v := ScanResponse([]byte(line), sc)
	if v.Clean || !hasCanaryMatch(v.DLPMatches) {
		t.Fatalf("a numeric canary returned as a number must be found, got clean=%v matches=%+v", v.Clean, v.DLPMatches)
	}
}

// TestScanResponse_NumericLeavesNeverJoinPatternDLP proves the channel is
// separate: a sixteen-digit number matches the digits-only pattern only if
// numbers were joined into the text view, and they must not be.
func TestScanResponse_NumericLeavesNeverJoinPatternDLP(t *testing.T) {
	sc := numericChannelScanner(t, "canary-"+"7f3a9c2e4b1d")
	// Control: the pattern is live on text.
	textLine := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"card 4111111111111112"}]}}`
	if v := ScanResponse([]byte(textLine), sc); v.Clean {
		t.Fatal("control failed: the digits pattern must fire on visible text")
	}
	numericLine := `{"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{"samples":[4111111111111112,255,255,255,0,0,0,128]}}}`
	v := ScanResponse([]byte(numericLine), sc)
	if !v.Clean || v.Error != "" {
		t.Fatalf("numeric telemetry must not reach pattern DLP or injection scanning, got clean=%v error=%q matches=%+v dlp=%+v", v.Clean, v.Error, v.Matches, v.DLPMatches)
	}
}

func TestScanResponseInjection_SkipsNumericChannel(t *testing.T) {
	// The injection-only entry point carries no DLP, so the known-value channel
	// (a DLP concern) does not run there either.
	canary := "canary-" + "7f3a9c2e4b1d"
	sc := numericChannelScanner(t, canary)
	line := `{"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{"payload":[` + numericCodes(canary) + `]}}}`
	if v := ScanResponseInjection([]byte(line), sc); !v.Clean {
		t.Fatalf("injection-only scan must not report DLP findings, got %+v", v)
	}
}

func TestScanResponse_NumericChannelInBatchAndToolsList(t *testing.T) {
	canary := "canary-" + "7f3a9c2e4b1d"
	sc := numericChannelScanner(t, canary)
	codes := numericCodes(canary)

	batch := `[{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"fine"}]}},{"jsonrpc":"2.0","id":2,"result":{"content":[],"structuredContent":{"payload":[` + codes + `]}}}]`
	if v := ScanResponse([]byte(batch), sc); v.Clean || !hasCanaryMatch(v.DLPMatches) {
		t.Fatalf("batch element numeric channel must be scanned, got clean=%v matches=%+v", v.Clean, v.DLPMatches)
	}

	toolsList := `{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"echo","description":"echoes"}],"_meta":{"trace":[` + codes + `]}}}`
	v := ScanResponseDispatch([]byte(toolsList), sc, true, ResponseScanOptions{})
	if v.Clean || !hasCanaryMatch(v.DLPMatches) {
		t.Fatalf("tools/list sibling numeric channel must be scanned, got clean=%v matches=%+v", v.Clean, v.DLPMatches)
	}
}
