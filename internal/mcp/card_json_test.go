// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

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
	// Existing structured numeric-channel behavior is intentionally preserved.
	line := []byte(`{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"n":` + card + `}}}`)
	if v := ScanResponse(line, s); !v.Clean || v.Error != "" {
		t.Fatalf("numeric channel changed: %+v", v)
	}
}

func TestCardJSONInputTypes(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	card := "41111111" + "11111111"
	groups := `4111,1111,1111,1111`
	for _, tt := range []struct {
		name, params string
		clean        bool
	}{
		{"numeric metric", `{"n":0.` + card + `}`, true},
		{"ids", `{"ids":[` + groups + `]}`, true},
		{"bbox", `{"bbox":[` + groups + `]}`, true},
		{"root groups", `[` + groups + `]`, true},
		{"empty key", `{"": [` + groups + `]}`, true},
		{"dash key", `{"-": [` + groups + `]}`, true},
		{"prefix key", `{"x-": [` + groups + `]}`, true},
		{"card string", `{"n":"` + card + `"}`, false},
		{"card integer", `{"n":` + card + `}`, false},
		{"string groups", `["4111","1111","1111","1111"]`, false},
		{"string halves", `["41111111","11111111"]`, false},
		{"written integer", `{"n":` + card + `.1}`, false},
		{"integer exponent", `{"n":` + card + `e-2}`, false},
		{"fraction split", `{"n":41111111.11111111}`, true},
		{"unrelated decimals", `[4111.21,1111.22,1111.23,1111.24]`, true},
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
			if !tt.clean && v.Action != config.ActionBlock {
				t.Fatalf("card did not block: %+v", v)
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
	groups := `4111,1111,1111,1111`
	for _, tt := range []struct {
		body  string
		clean bool
	}{
		{`{"metric":0.` + card + `}`, true},
		{`{"ids":[` + groups + `]}`, true},
		{`{"bbox":[` + groups + `]}`, true},
		{`[` + groups + `]`, true},
		{`{"":[` + groups + `]}`, true},
		{`{"-":[` + groups + `]}`, true},
		{`{"x-":[` + groups + `]}`, true},
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
	groups := `4111,1111,1111,1111`
	for _, tt := range []struct {
		event string
		clean bool
	}{
		{`{"metric":0.` + card + `}`, true},
		{`{"ids":[` + groups + `]}`, true},
		{`{"bbox":[` + groups + `]}`, true},
		{`[` + groups + `]`, true},
		{`{"":[` + groups + `]}`, true},
		{`{"-":[` + groups + `]}`, true},
		{`{"x-":[` + groups + `]}`, true},
		{`{"metric":"` + card + `"}`, false},
		{`{"metric":` + card + `}`, false},
		{`{"metric":` + card + `.1}`, false},
		{`{"metric":"0.` + card + `"}`, false},
	} {
		stream := "data: " + tt.event + "\n\ndata: " + tt.event + "\n\n"
		var forwarded bytes.Buffer
		err := ScanA2AStream(t.Context(), strings.NewReader(stream), &forwarded, nil, s, enabledA2ACfg())
		if (err == nil) != tt.clean {
			t.Fatalf("event=%s error=%v want clean=%v", tt.event, err, tt.clean)
		}
		if tt.clean && forwarded.String() != stream {
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
