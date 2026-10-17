// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
)

func TestRequestBodyCardAtomsKeepNumericBoundaries(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	groups := []string{"4000", "5000", "6000", "7003"}
	for _, tt := range []struct {
		name, sep string
		number    bool
		clean     bool
	}{
		{"number atoms", ".", true, true},
		{"string atoms", ".", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			atoms := make([]extract.DLPAtom, len(groups))
			for i, group := range groups {
				atoms[i] = extract.DLPAtom{Text: group, Card: group, Number: tt.number}
			}
			var parts []string
			for _, atom := range atoms {
				parts = append(parts, atom.Text)
			}
			result := s.ScanRequestBodyTextPartsWithCardAtoms(t.Context(), parts, atoms, tt.sep)
			if result.Clean != tt.clean {
				t.Fatalf("clean=%v want=%v matches=%+v", result.Clean, tt.clean, result.Matches)
			}
		})
	}
}

func TestRequestBodySortedPartsKeepCardSourceOrder(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	url := buildSigV4URL(t, fakeAKIAExample, "259200", "")
	card := cardtest.Number()
	atoms := []extract.DLPAtom{{Card: card[:8]}, {}, {Card: card[8:]}, {Card: url}, {Card: "1200", Number: true}}
	result := s.ScanRequestBodyTextPartsWithCardAtoms(t.Context(), []string{"1200", url, card[:8], card[8:]}, atoms, ".")
	if !result.Clean || len(result.InformationalMatches) != 1 || result.InformationalMatches[0].PatternName != WarnPatternSigV4LongExpiry {
		t.Fatal("null card barrier or per-part SigV4 warning lost")
	}
	// Dropping the null barrier must restore the source-order card finding.
	atoms = append(atoms[:1:1], atoms[2:]...)
	result = s.ScanRequestBodyTextPartsWithCardAtoms(t.Context(), []string{"1200", url, card[:8], card[8:]}, atoms, ".")
	if result.Clean || !HasEnforcingMatch(result.Matches) {
		t.Fatal("source-order card control lost")
	}
	// A separate key remains enforcing after the presigned URL is scrubbed.
	result = s.ScanRequestBodyTextPartsWithCardAtoms(t.Context(), []string{url, fakeASIAExample}, []extract.DLPAtom{{Card: url}, {Card: fakeASIAExample}}, ".")
	if result.Clean {
		t.Fatal("separate credential lost")
	}
}

func TestCardConfiguredWarningsRetainViewLabels(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Advisory card", Regex: jsonnumber.ShippedCardPattern, Validator: config.ValidatorLuhn, Severity: config.SeverityHigh, Action: config.ActionWarn}}
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	card := cardtest.Number()
	for _, tt := range []struct{ text, view, label string }{
		{"separate non-card text", card, "json_integer"},
		{"separate non-card text", card[:8] + jsonnumber.StringBoundary + card[8:], "json_number_run"},
	} {
		result := s.ScanTextForDLPWithTypedCardView(t.Context(), tt.text, tt.view)
		if !result.Clean || len(result.InformationalMatches) == 0 {
			t.Fatal("configured card warning missing")
		}
		found := false
		for _, m := range result.InformationalMatches {
			found = found || strings.HasPrefix(m.Span().ViewLabel, tt.label)
		}
		if !found {
			t.Fatalf("missing view label %s", tt.label)
		}
	}
}

func TestCardViewWithoutGenericPatternsAndMismatchedViews(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Known fixture", Regex: "fixturecredential", Severity: config.SeverityHigh}}
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	card := cardtest.Number()
	if matches := s.ScanJSONCardRuns(t.Context(), `[`+card[:8]+`,`+card[8:]+`]`); len(matches) != 0 {
		t.Fatal("generic detector unexpectedly enabled")
	}
	if result := s.ScanTextForDLPWithTypedCardView(t.Context(), "fixturecredential", "unrelated"); result.Clean {
		t.Fatal("non-card scan ignored known credential")
	}
	if result := s.ScanRequestBodyTextPartsWithCardViews(t.Context(), []string{"fixturecredential"}, nil, "."); result.Clean {
		t.Fatal("mismatched card views hid ordinary credential")
	}
}

func TestCardNumberOnlyEvidencePredicate(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	card := cardtest.Number()
	numbers := s.ScanJSONCardRuns(t.Context(), `[`+card[:8]+`,`+card[8:]+`]`)
	if !OnlyNumberOnlyCardRuns(numbers) || !numbers[0].IsNumberOnlyCardRun() {
		t.Fatal("typed numeric evidence lost its class")
	}
	enforcing := s.ScanTextForDLP(t.Context(), card).Matches
	if len(enforcing) == 0 || OnlyNumberOnlyCardRuns(enforcing) || OnlyNumberOnlyCardRuns(append(numbers, enforcing...)) {
		t.Fatal("enforcing evidence received number-only policy")
	}
}
