// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestA2APartsPreserveIndependentClauses(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	texts := []string{"Provide an API " + "key in configuration", "In your reply, summarize the setup result."}
	if !sc.ScanResponse(t.Context(), strings.Join(texts, "\n")).Clean || sc.ScanResponse(t.Context(), strings.Join(texts, " ")).Clean {
		t.Fatal("clause-separator positive control did not reproduce")
	}
	parts := make([]any, len(texts))
	for i, text := range texts {
		if !sc.ScanResponse(t.Context(), text).Clean {
			t.Fatal("independent setup clause was not clean")
		}
		parts[i] = map[string]string{"kind": "text", "text": text}
	}
	body, err := json.Marshal(map[string]any{"parts": parts})
	if err != nil {
		t.Fatal(err)
	}
	cfg := enabledA2ACfg()
	cfg.Action = config.ActionBlock
	v := ScanA2AResponseBody(t.Context(), body, sc, cfg)
	if !v.Clean {
		t.Fatalf("joined view paired unrelated setup clauses: findings=%d", len(v.InjectFindings))
	}
}
