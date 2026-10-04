// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package seedprotect

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustJSONString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// TestDetect_QuoteAndMarkupSeparators pins that punctuation glued to the first
// or last word does not hide a phrase. Every JSON string value starts and ends
// with a quote, so a phrase serialized as JSON used to fail the wordlist lookup
// on its first and last word.
func TestDetect_QuoteAndMarkupSeparators(t *testing.T) {
	obj, err := json.Marshal(map[string]string{"mnemonic": valid12})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	arr, err := json.Marshal([]string{valid12})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	cases := []struct {
		name      string
		text      string
		wantWords int
	}{
		{"whole JSON string", mustJSONString(t, valid12), 12},
		{"JSON object field", string(obj), 12},
		{"JSON array element", string(arr), 12},
		{"JSON with prose", "please store this " + string(obj) + " for later", 12},
		{"leading quote only", `"` + valid12, 12},
		{"trailing quote only", valid12 + `"`, 12},
		{"single quotes", "'" + valid12 + "'", 12},
		{"backticks", "`" + valid12 + "`", 12},
		{"parentheses", "(" + valid12 + ")", 12},
		{"square brackets", "[" + valid12 + "]", 12},
		{"curly braces", "{" + valid12 + "}", 12},
		{"markup tag", "<code>" + valid12 + "</code>", 12},
		{"key=value", "seed=" + valid12 + "&x=1", 12},
		{"question mark", "is this right?" + valid12 + "?", 12},
		{"escaped JSON inside JSON", mustJSONString(t, string(obj)), 12},
		{"curly double quotes", "“" + valid12 + "”", 12},
		{"curly single quotes", "‘" + valid12 + "’", 12},
		{"guillemets", "«" + valid12 + "»", 12},
		{"fullwidth quotes", "＂" + valid12 + "＂", 12},
		{"fullwidth apostrophes", "＇" + valid12 + "＇", 12},
		{"fullwidth grave accents", "｀" + valid12 + "｀", 12},
		{"CJK corner brackets", "「" + valid12 + "」", 12},
		{"fullwidth parentheses", "（" + valid12 + "）", 12},
		{"24-word JSON string", mustJSONString(t, valid24), 24},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := Detect(tc.text, 12, true)
			if len(matches) == 0 {
				t.Fatalf("seed phrase not detected in %q", tc.text)
			}
			if matches[0].WordCount != tc.wantWords || !matches[0].ChecksumValid {
				t.Fatalf("got %+v, want %d checksum-valid words", matches[0], tc.wantWords)
			}
		})
	}
}

// TestDetectSpans_QuotedPhraseOffsetsExcludeQuotes proves the span covers the
// words only, so redaction removes the phrase and leaves the JSON quotes.
func TestDetectSpans_QuotedPhraseOffsetsExcludeQuotes(t *testing.T) {
	text := mustJSONString(t, valid12)
	spans := DetectSpans(text, 12, true)
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if got := text[spans[0].Start:spans[0].End]; got != valid12 {
		t.Fatalf("span = %q, want %q", got, valid12)
	}
}

// TestDetect_QuotedBenignTextStaysClean holds the false-positive line: quoted
// wordlist words that are not a checksum-valid mnemonic, and ordinary quoted
// prose, must not match.
func TestDetect_QuotedBenignTextStaysClean(t *testing.T) {
	invalid12 := strings.TrimSpace(strings.Repeat("abandon ", 12))
	prose := `"we should never abandon the plan," she said, "because the river is about to rise and the village needs a bridge before the winter storm."`
	jsonProse, err := json.Marshal(map[string]string{"note": "the actor will travel to the island to find a hidden treasure and return before dawn"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	cases := []struct {
		name string
		text string
	}{
		{"quoted invalid checksum", mustJSONString(t, invalid12)},
		{"single-quoted invalid checksum", "'" + invalid12 + "'"},
		{"quoted English prose", prose},
		{"JSON English prose", string(jsonProse)},
		{"contractions", "don't won't can't it's they're we've you'll I'd"},
		// Ten wordlist words plus the structural "name" key and "write_file"
		// value form a checksum-valid 12-word mnemonic if a window may span
		// JSON quotes. Quotes are phrase boundaries, so this stays clean.
		{"no window across JSON fields", `{"params":{"arguments":{"content":"` +
			strings.TrimSpace(strings.Repeat("abandon ", 10)) + `"},"name":"write_file"}}`},
		{"no window across quoted words", `"` + strings.Join(strings.Fields(valid12), `" "`) + `"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if matches := Detect(tc.text, 12, true); len(matches) != 0 {
				t.Fatalf("false positive on %q: %+v", tc.text, matches)
			}
		})
	}
}
