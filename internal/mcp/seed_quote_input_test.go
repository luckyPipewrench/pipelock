// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const mcpTestSeedPhrase12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// TestScanRequest_SeedPhraseQuotedInArgument covers MCP input scanning when a
// tool argument carries JSON or quoted text, so the extracted string value has
// a quote glued to the first and last word of the phrase.
func TestScanRequest_SeedPhraseQuotedInArgument(t *testing.T) {
	sc := testInputScanner(t)
	nested, err := json.Marshal(map[string]string{"mnemonic": mcpTestSeedPhrase12})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	cases := []struct {
		name  string
		value string
	}{
		{"nested JSON payload", string(nested)},
		{"double-quoted value", `"` + mcpTestSeedPhrase12 + `"`},
		{"single-quoted value", "'" + mcpTestSeedPhrase12 + "'"},
		{"backtick value", "`" + mcpTestSeedPhrase12 + "`"},
		{"JSON with prose", "save this: " + string(nested) + " ok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := makeRequest(1, "tools/call", map[string]any{
				"name":      "write_file",
				"arguments": map[string]string{"content": tc.value},
			})
			verdict := ScanRequest(context.Background(), []byte(line), sc, config.ActionBlock, config.ActionBlock)
			if verdict.Clean {
				t.Fatalf("quoted seed phrase in MCP argument not detected: %s", line)
			}
			if !strings.Contains(joinInputVerdictReasons(verdict), "Seed Phrase") {
				t.Fatalf("blocked but not as a seed phrase: %+v", verdict)
			}
		})
	}
}

func TestScanRequest_QuotedWordlistProseClean(t *testing.T) {
	sc := testInputScanner(t)
	invalid12 := strings.TrimSpace(strings.Repeat("abandon ", 12))
	for _, value := range []string{
		`"` + invalid12 + `"`,
		`{"note":"the actor will travel to the island to find a hidden treasure and return before dawn"}`,
	} {
		line := makeRequest(1, "tools/call", map[string]any{
			"name":      "write_file",
			"arguments": map[string]string{"content": value},
		})
		verdict := ScanRequest(context.Background(), []byte(line), sc, config.ActionBlock, config.ActionBlock)
		if !verdict.Clean {
			t.Fatalf("false positive on %q: %+v", value, verdict)
		}
	}
}
