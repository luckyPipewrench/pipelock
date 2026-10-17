// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

func TestRewriteJSONCardDepthRefusal(t *testing.T) {
	for _, body := range []string{`[[1]]`, `[[[1]]]`} {
		_, _, err := RewriteJSON([]byte(body), NewDefaultMatcher(), NewRedactor(), Limits{MaxDepth: 1})
		be, ok := asBlockError(err)
		if !ok || be.Reason != ReasonDepthExceeded {
			t.Fatalf("typed inspection did not refuse depth: %v", err)
		}
	}
}

func TestRewriteJSONNumberOnlyRunsUnchanged(t *testing.T) {
	for _, body := range []string{`[4111,1111,1111,1111]`, `[4111.0,1111.0,1111.0,1111.0]`, `[4111e0,1111e-2,1111E2,1111e+1]`} {
		out, report, err := RewriteJSON([]byte(body), NewDefaultMatcher(), NewRedactor(), Limits{})
		if err != nil || !bytes.Equal(out, []byte(body)) || report.TotalRedactions != 0 {
			t.Fatalf("number-only values changed: err=%v", err)
		}
	}
	for _, body := range []string{`[1e10001]`, `[` + strings.Repeat("9", 4097) + `]`} {
		_, _, err := RewriteJSON([]byte(body), NewDefaultMatcher(), NewRedactor(), Limits{})
		be, ok := asBlockError(err)
		if !ok || be.Reason != ReasonSecretInNumericScalar {
			t.Fatalf("uninspectable number allowed: %v", err)
		}
	}
}

func TestRewriteJSONDepthOrigin(t *testing.T) {
	for _, body := range []string{`{"a":{}}`, `{"a":[]}`, `[{}]`} {
		if _, _, err := RewriteJSON([]byte(body), NewDefaultMatcher(), NewRedactor(), Limits{MaxDepth: 1}); err != nil {
			t.Fatalf("empty nested container refused: %v", err)
		}
	}
	for _, body := range []string{`{"a":{"b":1}}`, `{"a":{"b":{}}}`} {
		_, _, err := RewriteJSON([]byte(body), NewDefaultMatcher(), NewRedactor(), Limits{MaxDepth: 1})
		if be, ok := asBlockError(err); !ok || be.Reason != ReasonDepthExceeded {
			t.Fatalf("depth not refused: %v", err)
		}
	}
}

func TestRewriteJSONCardProfileAndKnownValues(t *testing.T) {
	card := cardtest.Number()
	body := []byte(`["` + card[:2] + `","` + card[2:9] + `","` + card[9:] + `"]`)
	for _, m := range []*Matcher{nil, {}, NewDefaultMatcher()} {
		if _, report, err := RewriteJSON(body, m, NewRedactor(), Limits{}); err != nil || report.TotalRedactions != 0 {
			t.Fatalf("informational join changed: %v", err)
		}
	}
	for _, whole := range [][]byte{[]byte(`{"card":"` + card + `"}`), []byte(`{"card":` + card + `}`)} {
		for _, m := range []*Matcher{nil, {}} {
			if _, report, err := RewriteJSON(whole, m, NewRedactor(), Limits{}); err != nil || report.TotalRedactions != 0 {
				t.Fatalf("disabled class unexpectedly enforced: %v", err)
			}
		}
	}
	m := NewDefaultMatcher()
	if err := m.AddDictionary(Dictionary{Class: ClassCreditCard, Entries: []string{card}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RewriteJSON(body, m, NewRedactor(), Limits{}); err == nil {
		t.Fatal("known dictionary value lost enforcement")
	}
}
