// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestCardLiteralListenerHeaders(t *testing.T) {
	s := testA2AScanner(t)
	t.Cleanup(s.Close)
	card := "41111111" + "11111111"
	for _, text := range []string{card, "0." + card, "[0." + card + "]", `{"n":0.` + card + `}`} {
		result := scanMCPListenerHeadersForDLP(t.Context(), http.Header{"Authorization": {text}}, s, nil)
		if result == nil || len(result.matches) == 0 {
			t.Fatalf("string header received numeric relief: %q", text)
		}
	}
}

func TestCardLiteralA2AText(t *testing.T) {
	s := testA2AScanner(t)
	t.Cleanup(s.Close)
	card := "41111111" + "11111111"
	for _, text := range []string{card, "0." + card, "[0." + card + "]", `{"n":0.` + card + `}`} {
		quoted, err := json.Marshal(text)
		if err != nil {
			t.Fatal(err)
		}
		body := []byte(`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":` + string(quoted) + `}]}}}`)
		result := ScanA2ARequestBody(t.Context(), body, s, enabledA2ACfg())
		if result.Clean || len(result.DLPFindings) == 0 {
			t.Fatalf("string text part received numeric relief: %q result=%+v", text, result)
		}
	}
}

func TestCardJSONExtremeNumberPreservesSplitSecret(t *testing.T) {
	s := testA2AScanner(t)
	t.Cleanup(s.Close)
	for _, number := range []string{"1.5", "1e999", "-1e999", "[1e999]"} {
		params := `{"a":"NPVB3KDE","b":"AKIA` + `QX7TR2LM","n":` + number + `}`
		line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":` + params + `}`)
		result := ScanRequest(t.Context(), line, s, config.ActionBlock, config.ActionBlock)
		if result.Clean || result.Action != config.ActionBlock || result.Error != "" {
			t.Fatalf("number %s disabled split-secret enforcement: %+v", number, result)
		}
	}
}
