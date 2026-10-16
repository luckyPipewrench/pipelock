// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCardJSONResponseSegments(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.ResponseScanning.Action = config.ActionBlock
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	metric := `{"ctr":0.41111111` + `11111111}`
	card := "41111111" + "11111111"
	for _, tt := range []struct {
		name  string
		parts []string
		clean bool
	}{
		{"single metric", []string{metric}, true},
		{"metric with prose", []string{metric, "ordinary report"}, true},
		{"metric before card", []string{metric, card}, false},
		{"card before metric", []string{card, metric}, false},
		{"split card with metric", []string{card[:8], card[8:], metric}, false},
		{"two documents", []string{metric, metric}, true},
		{"card string", []string{`{"n":"0.` + card + `"}`}, false},
		{"scalar decimal text", []string{"0." + card}, false},
		{"dotted text", []string{"x." + card}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var blocks []map[string]string
			for _, part := range tt.parts {
				blocks = append(blocks, map[string]string{"type": "text", "text": part})
			}
			line, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": blocks}})
			if err != nil {
				t.Fatal(err)
			}
			v := ScanResponse(line, s)
			if v.Clean != tt.clean || v.Error != "" {
				t.Fatalf("clean=%v want=%v error=%s matches=%+v", v.Clean, tt.clean, v.Error, v.DLPMatches)
			}
		})
	}
	// Single numeric cards enforce alongside the separate known-value channel.
	line := []byte(`{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"n":` + card + `}}}`)
	if v := ScanResponse(line, s); v.Clean || v.Error != "" || v.Action != config.ActionBlock {
		t.Fatalf("numeric channel changed: %+v", v)
	}
	groups := "4111,1111" + ",1111,1111"
	line = []byte(`{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"ids":[` + groups + `]}}}`)
	if v := ScanResponse(line, s); v.Clean || v.Action != config.ActionWarn || v.Error != "" || len(v.DLPMatches) == 0 {
		t.Fatalf("split numeric response lacked warning evidence: %+v", v)
	}
}

func TestCardJSONSharedTransportCorpus(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.ResponseScanning.Action = config.ActionBlock
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	for _, tt := range cardtest.JSONCases() {
		t.Run(tt.Name, func(t *testing.T) {
			request := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":` + tt.Body + `}`)
			if v := ScanRequest(t.Context(), request, s, config.ActionBlock, config.ActionBlock); v.Clean != tt.Clean || v.Error != "" {
				t.Fatalf("MCP request clean=%v error=%q want=%v", v.Clean, v.Error, tt.Clean)
			} else if tt.Warn && (v.Action != config.ActionWarn || len(v.Matches) == 0) {
				t.Fatal("MCP request warning missing")
			}
			response, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []map[string]string{{"type": "text", "text": tt.Body}}}})
			if err != nil {
				t.Fatal(err)
			}
			if v := ScanResponse(response, s); v.Clean != tt.Clean || v.Error != "" {
				t.Fatalf("MCP response clean=%v error=%q want=%v", v.Clean, v.Error, tt.Clean)
			} else if tt.Warn && (v.Action != config.ActionWarn || len(v.DLPMatches) == 0) {
				t.Fatalf("MCP response warning missing: %+v", v)
			}
			a2aCfg := enabledA2ACfg()
			a2aCfg.Action = config.ActionBlock
			if v := ScanA2ARequestBody(t.Context(), []byte(tt.Body), s, a2aCfg); v.Clean != tt.Clean {
				t.Fatalf("A2A clean=%v want=%v", v.Clean, tt.Clean)
			} else if tt.Warn && (v.Action != config.ActionWarn || len(v.DLPFindings) == 0) {
				t.Fatal("A2A warn evidence missing")
			}
			stream := "data: " + tt.Body + "\n\n"
			var forwarded bytes.Buffer
			err = ScanGenericSSEStream(t.Context(), strings.NewReader(stream), &forwarded, nil, s, enabledSSECfg())
			if (err == nil) != (tt.Clean || tt.Warn) {
				t.Fatalf("SSE error=%v want clean=%v", err, tt.Clean)
			}
			if (tt.Clean || tt.Warn) && forwarded.String() != stream {
				t.Fatal("clean SSE event changed")
			}
		})
	}
}

func TestCardJSONResponseNumberBudgetFailsClosed(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	line := []byte(`{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"n":` + strings.Repeat("9", 4097) + `}}}`)
	v := ScanResponse(line, s)
	if v.Clean || v.Error != "" || len(v.DLPMatches) == 0 || v.DLPMatches[0].PatternName != "Uninspectable JSON number" {
		t.Fatalf("over-budget response was treated as clean: %+v", v)
	}
}

// A string argument is not a JSON document, even when its contents are a
// valid JSON scalar. Only the request's own over-budget numbers are refused.
func TestCardJSONInputStringScalarNotRefused(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	request := func(arg string) []byte {
		return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bignum","arguments":{"result":` + arg + `}}}`)
	}
	for _, arg := range []string{`"` + strings.Repeat("7", 4097) + `"`, `"1e10001"`} {
		if v := ScanRequest(t.Context(), request(arg), s, config.ActionBlock, config.ActionBlock); !v.Clean {
			t.Fatalf("string argument %.12s was refused: %+v", arg, v.Matches)
		}
	}
	for _, arg := range []string{strings.Repeat("7", 4097), `1e10001`} {
		v := ScanRequest(t.Context(), request(arg), s, config.ActionBlock, config.ActionBlock)
		if v.Clean || v.Action != config.ActionBlock {
			t.Fatalf("over-budget number %.12s was not refused: %+v", arg, v)
		}
	}
}

func TestCardJSONInputTypes(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	card := "41111111" + "11111111"
	groups := "4111,1111" + ",1111,1111"
	for _, tt := range []struct {
		name, params string
		clean        bool
	}{
		{"numeric metric", `{"n":0.` + card + `}`, true},
		{"ids", `{"ids":[` + groups + `]}`, false},
		{"bbox", `{"bbox":[` + groups + `]}`, false},
		{"root groups", `[` + groups + `]`, false},
		{"empty key", `{"": [` + groups + `]}`, false},
		{"dash key", `{"-": [` + groups + `]}`, false},
		{"prefix key", `{"x-": [` + groups + `]}`, false},
		{"card string", `{"n":"` + card + `"}`, false},
		{"card integer", `{"n":` + card + `}`, false},
		{"string groups", `["4111","1111","1111","1111"]`, false},
		{"string halves", `["41111111","11111111"]`, false},
		{"written integer", `{"n":` + card + `.1}`, false},
		{"integer exponent", `{"n":` + card + `e-2}`, false},
		{"fraction split", `{"n":41111111.11111111}`, true},
		{"unrelated decimals", `[1200.21,3400.22,5600.23,7800.24]`, true},
		{"separate decimals carrying a card", `[4111.21,1111.22,1111.23,1111.24]`, false},
		{"string", `{"n":"0.` + card + `"}`, false},
		{"JSON string", `{"n":"{\"n\":0.` + card + `}"}`, false},
		{"encoded string", `{"n":"` + base64.StdEncoding.EncodeToString([]byte(card)) + `"}`, false},
		{"metric and string", `{"n":0.` + card + `,"s":"` + card + `"}`, false},
		{"split string", `{"a":"` + card[:8] + `","b":"` + card[8:] + `","n":0.` + card + `}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":` + tt.params + `}`)
			v := ScanRequest(t.Context(), line, s, config.ActionBlock, config.ActionBlock)
			if v.Clean != tt.clean || v.Error != "" {
				t.Fatalf("clean=%v want=%v verdict=%+v", v.Clean, tt.clean, v)
			}
			if !tt.clean && v.Action != scanner.CardRunAction(v.Matches, config.ActionBlock) {
				t.Fatalf("card action did not match its class: %+v", v)
			}
		})
	}
}

func TestCardJSONResponseLiteralFields(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	metric := `{"n":0.41111111` + `11111111}`
	for _, result := range []any{
		metric,
		map[string]any{"structuredContent": map[string]string{"n": metric}},
		map[string]any{"content": []map[string]string{{"type": "resource_link", "name": metric}}},
	} {
		line, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
		if err != nil {
			t.Fatal(err)
		}
		v := ScanResponse(line, s)
		if v.Clean || v.Error != "" || len(v.DLPMatches) == 0 {
			t.Fatalf("string lost its type: %+v", v)
		}
	}
}

func TestCardJSONA2ANumericTypes(t *testing.T) {
	s := testA2AScanner(t)
	t.Cleanup(s.Close)
	card := "41111111" + "11111111"
	groups := "4111,1111" + ",1111,1111"
	for _, tt := range []struct {
		body  string
		clean bool
	}{
		{`{"metric":0.` + card + `}`, true},
		{`{"ids":[` + groups + `]}`, false},
		{`{"bbox":[` + groups + `]}`, false},
		{`[` + groups + `]`, false},
		{`{"":[` + groups + `]}`, false},
		{`{"-":[` + groups + `]}`, false},
		{`{"x-":[` + groups + `]}`, false},
		{`{"metric":"` + card + `"}`, false},
		{`{"metric":` + card + `}`, false},
		{`{"metric":` + card + `.1}`, false},
		{`["4111","1111","1111","1111"]`, false},
		{`["41111111","11111111"]`, false},
		{`{"metric":"0.` + card + `"}`, false},
	} {
		result := ScanA2ARequestBody(t.Context(), []byte(tt.body), s, enabledA2ACfg())
		if result.Clean != tt.clean {
			t.Fatalf("body=%s result=%+v want clean=%v", tt.body, result, tt.clean)
		}
	}
}

func TestCardJSONA2AStreamTypes(t *testing.T) {
	s := testA2AScanner(t)
	t.Cleanup(s.Close)
	card := "41111111" + "11111111"
	groups := "4111,1111" + ",1111,1111"
	for _, tt := range []struct {
		event string
		clean bool
	}{
		{`{"metric":0.` + card + `}`, true},
		{`{"ids":[` + groups + `]}`, false},
		{`{"bbox":[` + groups + `]}`, false},
		{`[` + groups + `]`, false},
		{`{"":[` + groups + `]}`, false},
		{`{"-":[` + groups + `]}`, false},
		{`{"x-":[` + groups + `]}`, false},
		{`{"metric":"` + card + `"}`, false},
		{`{"metric":` + card + `}`, false},
		{`{"metric":` + card + `.1}`, false},
		{`{"metric":"0.` + card + `"}`, false},
	} {
		stream := "data: " + tt.event + "\n\ndata: " + tt.event + "\n\n"
		var forwarded bytes.Buffer
		err := ScanA2AStream(t.Context(), strings.NewReader(stream), &forwarded, nil, s, enabledA2ACfg())
		warn := scanner.OnlyNumberOnlyCardRuns(ScanA2ARequestBody(t.Context(), []byte(tt.event), s, enabledA2ACfg()).DLPFindings)
		if (err == nil) != (tt.clean || warn) {
			t.Fatalf("event=%s error=%v want clean=%v", tt.event, err, tt.clean)
		}
		if (tt.clean || warn) && forwarded.String() != stream {
			t.Fatalf("numeric event bytes changed: %q", forwarded.String())
		}
	}
	for _, field := range []string{"id", "event"} {
		stream := field + ": 0." + card + "\ndata: {}\n\n"
		var forwarded bytes.Buffer
		if err := ScanA2AStream(t.Context(), strings.NewReader(stream), &forwarded, nil, s, enabledA2ACfg()); err == nil || forwarded.Len() != 0 {
			t.Fatalf("string metadata received numeric relief: field=%s error=%v bytes=%d", field, err, forwarded.Len())
		}
	}
}

func TestCardJSONA2ACrossEventBoundaries(t *testing.T) {
	first := "4111" + "1111"
	last := "1111" + "1111"
	for _, tt := range []struct {
		name, firstEvent, lastEvent string
		wantFinding                 bool
	}{
		{"root strings", `"` + first + `"`, `"` + last + `"`, true},
		{"object then array", `{"part":"` + first + `"}`, `["` + last + `"]`, true},
		{"root integer arrays", `[` + first + `]`, `[` + last + `]`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := testA2AScanner(t)
			t.Cleanup(s.Close)
			stream := "data: " + tt.firstEvent + "\n\ndata: " + tt.lastEvent + "\n\n"
			var forwarded bytes.Buffer
			err := ScanA2AStream(t.Context(), strings.NewReader(stream), &forwarded, nil, s, enabledA2ACfg())
			if tt.wantFinding {
				if !errors.Is(err, ErrA2AStreamFinding) {
					t.Fatalf("cross-event card was not denied: %v", err)
				}
			} else if err != nil || forwarded.String() != stream {
				t.Fatalf("numeric events changed: error=%v forwarded=%q", err, forwarded.String())
			}
		})
	}
}

func TestCardJSONA2ATaskUpdateNumbersAcrossEvents(t *testing.T) {
	s := testA2AScanner(t)
	t.Cleanup(s.Close)
	first := "4111" + "1111"
	last := "1111" + "1111"
	wrap := func(piece string) string {
		return `{"status":{"message":{"parts":[{"kind":"data","data":{"value":` + piece + `}}]}}}`
	}
	stream := "event: task-update\ndata: " + wrap(first) + "\n\nevent: task-update\ndata: " + wrap(last) + "\n\n"
	var forwarded bytes.Buffer
	err := ScanA2AStream(t.Context(), strings.NewReader(stream), &forwarded, nil, s, enabledA2ACfg())
	if err != nil || forwarded.String() != stream {
		t.Fatalf("number-only task update was not forwarded: %v", err)
	}
}
