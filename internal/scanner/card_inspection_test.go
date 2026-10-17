// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestJSONInspectionActions(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	informational := sc.ScanJSONCardRuns(t.Context(), `[`+cardtest.Number()[:8]+`,`+cardtest.Number()[8:]+`]`)
	if !OnlyInformational(informational) {
		t.Fatal("warning positive control missing")
	}
	limit := sc.ScanJSONCardRuns(t.Context(), `[1e10001]`)
	if len(limit) != 1 || !limit[0].IsInspectionLimit() {
		t.Fatal("inspection-limit positive control missing")
	}
	for _, action := range []string{config.ActionWarn, config.ActionBlock, config.ActionStrip, config.ActionAsk} {
		for _, matches := range [][]TextDLPMatch{limit, append(append([]TextDLPMatch{}, informational...), limit...), append(append([]TextDLPMatch{}, limit...), informational...)} {
			if !HasInspectionLimit(matches) || CardRunAction(matches, action) != config.ActionBlock {
				t.Fatal("inspection refusal downgraded")
			}
		}
		if CardRunAction(informational, action) != config.ActionWarn {
			t.Fatal("informational evidence escalated")
		}
		ordinary := []TextDLPMatch{{PatternName: "ordinary"}}
		if HasInspectionLimit(ordinary) || CardRunAction(ordinary, action) != action {
			t.Fatal("ordinary action changed")
		}
	}
	if HasInspectionLimit(nil) || CardRunAction(nil, config.ActionWarn) != config.ActionWarn {
		t.Fatal("empty control changed")
	}
}

func TestJSONInspectionLimitViews(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, tt := range []struct {
		body  string
		limit bool
	}{
		{`[1e10001]`, true},
		{`[` + strings.Repeat("9", 4097) + `]`, true},
		{strings.Repeat("[", 65) + `1` + strings.Repeat("]", 65), true},
		{`[]`, false},
		{`{"n":1}`, false},
		{``, false},
		{`[`, false},
		{`1e10001`, false},
		{`"[1e10001]"`, false},
	} {
		if sc.JSONInspectionLimitExceeded(tt.body) != tt.limit {
			t.Fatalf("limit=%v want=%v", !tt.limit, tt.limit)
		}
	}
	cfg.DLP.Patterns = nil
	disabled := MustNew(cfg)
	t.Cleanup(disabled.Close)
	if disabled.JSONInspectionLimitExceeded(`[1e10001]`) {
		t.Fatal("disabled card scanner inspected input")
	}
}

func TestJSONInspectionScalarRuns(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, body := range []string{`1e10001`, strings.Repeat("7", 4097), cardtest.Number() + `e10001`} {
		matches := sc.ScanJSONCardRuns(t.Context(), body)
		if HasInspectionLimit(matches) {
			t.Fatal("scalar received structured-document refusal")
		}
		if strings.HasPrefix(body, cardtest.Number()) && !HasEnforcingMatch(matches) {
			t.Fatal("scalar integer card lost ordinary enforcement")
		}
	}
}

func TestJSONInspectionFragmentEvidence(t *testing.T) {
	sc := testFragmentScanner()
	t.Cleanup(sc.Close)
	buffer := NewFragmentBuffer(65536, 10, testWindowSecs)
	t.Cleanup(buffer.Close)
	buffer.Append(testCEEIdentity("inspection"), []byte(`[1e`))
	buffer.Append(testCEEIdentity("inspection"), []byte(`10001]`))
	matches := buffer.ScanForSecrets(t.Context(), testCEEStream("inspection"), sc)
	for _, match := range matches {
		if match.PatternName == UninspectableJSONNumberPattern {
			return
		}
	}
	t.Fatalf("no inspection-limit evidence: %+v", matches)
}

func TestJSONInspectionFragmentClass(t *testing.T) {
	if HasFragmentInspectionLimit(nil) || HasFragmentInspectionLimit([]DLPMatch{{PatternName: "ordinary"}}) {
		t.Fatal("ordinary fragment classified as incomplete")
	}
	if !HasFragmentInspectionLimit([]DLPMatch{{PatternName: "ordinary"}, {PatternName: UninspectableJSONNumberPattern}}) {
		t.Fatal("later fragment refusal missed")
	}
}
