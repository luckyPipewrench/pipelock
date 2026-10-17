// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCardOverflowEvidence(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	card := cardtest.Number()
	for _, tt := range []struct {
		body           string
		block, finding bool
	}{
		{`[` + card[:8] + `,` + card[8:] + `]`, false, true},
		{`[1e10001]`, true, true},
		{`[]`, false, false},
	} {
		var result A2AScanResult
		block := a2aOverflowPass(t.Context(), []byte(tt.body), sc, &result)
		if block != tt.block || (len(result.DLPFindings) > 0) != tt.finding {
			t.Fatalf("block=%v findings=%d", block, len(result.DLPFindings))
		}
	}
}

func TestCardRemainderInspectionRefusal(t *testing.T) {
	for _, body := range []string{`[]`, `{`, strings.Repeat("[", extract.MaxExtractDepth+1) + `"x"` + strings.Repeat("]", extract.MaxExtractDepth+1)} {
		if _, ok := responseEnvelopeRemainder([]byte(body), jsonrpc.RPCResponse{}, &jsonrpc.MediaTextBudget{}); ok {
			t.Fatal("uninspectable envelope admitted")
		}
	}
	if _, ok := responseEnvelopeRemainder([]byte(`{"result":null}`), jsonrpc.RPCResponse{}, &jsonrpc.MediaTextBudget{}); !ok {
		t.Fatal("inspectable control rejected")
	}
}

func TestCardSplitEvidenceKeepsOtherCredentials(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Joined fixture", Regex: `^fixturecredential$`, Severity: config.SeverityHigh})
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	card := cardtest.Number()
	prior := sc.ScanTextForDLP(t.Context(), `[`+card[:8]+`,`+card[8:]+`]`)
	for _, raw := range []string{`["fixture","credential"]`, `["fixture","other","credential"]`, `["credential","other","fixture"]`} {
		result := scanSplitSecret(t.Context(), json.RawMessage(raw), "ordinary separated view", sc, prior)
		if result.Clean || !scanner.HasEnforcingMatch(result.Matches) || len(result.Matches) < 2 {
			t.Fatal("warning hid cross-field credential")
		}
	}
}

func TestCardSSECrossEventWarningsAndKnownValues(t *testing.T) {
	card := cardtest.Number()
	for _, known := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.ScanEnv = false
		if known {
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Known fixture", Regex: card, Severity: config.SeverityHigh})
		}
		sc := scanner.MustNew(cfg)
		stream := "data: {\"kind\":\"status\",\"n\":" + card[:8] + "}\n\ndata: {\"kind\":\"status\",\"n\":" + card[8:] + "}\n\ndata: ordinary report\n\n"
		var out bytes.Buffer
		warnings := 0
		err := ScanGenericSSEStreamWithOptions(t.Context(), strings.NewReader(stream), &out, nil, sc, &config.GenericSSEScanning{Enabled: true, Action: config.ActionBlock}, GenericSSEScanOptions{OnFinding: func(error) { warnings++ }})
		sc.Close()
		if known {
			if !errors.Is(err, ErrSSEStreamFinding) || out.String() == stream {
				t.Fatal("known numeric credential forwarded")
			}
		} else if err != nil || out.String() != stream || warnings == 0 {
			t.Fatal("numeric evidence lost warning or forwarding")
		}
	}
}

func TestCardSSEWarningCancellation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sc.SetDLPWarnHook(func(context.Context, string, string) { cancel() })
	card := cardtest.Number()
	stream := "data: {\"kind\":\"status\",\"n\":" + card[:8] + "}\n\ndata: {\"kind\":\"status\",\"n\":" + card[8:] + "}\n\ndata: ordinary report\n\n"
	var out bytes.Buffer
	err := ScanGenericSSEStreamWithOptions(ctx, strings.NewReader(stream), &out, nil, sc, &config.GenericSSEScanning{Enabled: true, Action: config.ActionBlock}, GenericSSEScanOptions{})
	if !errors.Is(err, context.Canceled) || out.String() == stream {
		t.Fatal("canceled number scan forwarded unchecked event")
	}
}

func TestCardResponseFieldCombinations(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.ResponseScanning.Action = config.ActionBlock
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, toolsList := range []bool{false, true} {
		for _, typedError := range []bool{false, true} {
			for _, cardValue := range []bool{false, true} {
				value := "ordinary error data"
				if cardValue {
					value = cardtest.Number()
				}
				result := map[string]any{"content": []any{map[string]string{"type": "text", "text": "ordinary result"}}}
				if toolsList {
					result = map[string]any{"tools": []any{}, "note": "ordinary result"}
				}
				var rpcError any = []string{value}
				if typedError {
					rpcError = map[string]any{"code": -1, "message": "ordinary error", "data": map[string]any{"content": []any{map[string]string{"type": "text", "text": value}}}}
				}
				body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result, "error": rpcError, "params": map[string]any{"content": []any{map[string]string{"type": "text", "text": "ordinary notification"}}}})
				if err != nil {
					t.Fatal(err)
				}
				verdict := ScanResponse(body, sc)
				if toolsList {
					verdict = scanToolsListNonToolFields(body, sc, ResponseScanOptions{})
				}
				if verdict.Error != "" || verdict.Clean == cardValue || (cardValue && len(verdict.DLPMatches) == 0) {
					t.Fatalf("tools=%v typed error=%v card=%v: clean=%v error=%s", toolsList, typedError, cardValue, verdict.Clean, verdict.Error)
				}
			}
		}
	}
}

func TestCardFallbackShapeKeepsWordBoundaries(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.ResponseScanning.Action = config.ActionBlock
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, cardValue := range []bool{false, true} {
		value := "ordinary"
		if cardValue {
			value = cardtest.Number()
		}
		values := map[string]any{"a": "order", "b": value, "c": "tail"}
		for name, message := range map[string]map[string]any{
			"result": {"jsonrpc": "2.0", "id": 1, "result": values},
			"error":  {"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -1, "message": "failed", "data": values}},
			"params": {"jsonrpc": "2.0", "method": "notifications/message", "params": values},
		} {
			body, err := json.Marshal(message)
			if err != nil {
				t.Fatal(err)
			}
			verdict := ScanResponse(body, sc)
			if verdict.Error != "" || verdict.Clean == cardValue || (cardValue && len(verdict.DLPMatches) == 0) {
				t.Fatalf("%s card=%v: clean=%v error=%s", name, cardValue, verdict.Clean, verdict.Error)
			}
		}
	}
}

func TestCardA2ANumberStreamKeepsKnownValues(t *testing.T) {
	card := cardtest.Number()
	for _, known := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.ScanEnv = false
		if known {
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Known stream fixture", Regex: card, Severity: config.SeverityHigh})
		}
		sc := scanner.MustNew(cfg)
		stream := "data: {\"kind\":\"status\",\"n\":" + card[:8] + "}\n\ndata: {\"kind\":\"status\",\"n\":" + card[8:] + "}\n\n"
		var out bytes.Buffer
		warnings := 0
		err := ScanA2AStreamWithOptions(t.Context(), strings.NewReader(stream), &out, nil, sc, A2AStreamOptions{Config: &config.A2AScanning{Enabled: true, Action: config.ActionBlock}, Warning: GenericSSEScanOptions{OnFinding: func(error) { warnings++ }}})
		sc.Close()
		if known {
			if !errors.Is(err, ErrA2AStreamFinding) || out.String() == stream {
				t.Fatal("known numeric A2A credential forwarded")
			}
		} else if err != nil || out.String() != stream || warnings == 0 {
			t.Fatal("numeric A2A evidence lost warning or forwarding")
		}
	}
}
