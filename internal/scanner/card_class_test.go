// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
)

func TestCardRunClassification(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	if OnlyNumberOnlyCardRuns(nil) {
		t.Fatal("empty evidence must not downgrade an action")
	}
	for _, tt := range cardtest.JSONCases() {
		t.Run(tt.Name, func(t *testing.T) {
			extracted := extract.AllStringsFromJSONResult(json.RawMessage(tt.Body))
			text := strings.Join(extracted.Strings, "\n")
			view := extract.JoinCardAtoms(extracted.Atoms, " ")
			results := []TextDLPResult{s.ScanTextForDLPWithCardView(t.Context(), tt.Body, jsonnumber.CardView(tt.Body, extract.MaxExtractDepth))}
			// Object keys interrupt the flattened atom view. Its callers also
			// inspect the original document and individual leaves.
			if strings.HasPrefix(tt.Body, "[") {
				results = append(results,
					s.ScanTextForDLPWithTypedCardView(t.Context(), text, view),
					s.ScanTextForDLPInboundWithTypedCardView(t.Context(), text, view),
					s.ScanTextForDLPQuietWithTypedCardView(t.Context(), text, view),
					s.ScanRequestBodyTextPartsWithCardAtoms(t.Context(), extracted.Atoms, "\n"))
			}
			for _, result := range results {
				if result.Clean != tt.Clean || OnlyNumberOnlyCardRuns(result.Matches) != tt.Warn {
					t.Fatalf("clean=%v number-only=%v; want clean=%v warn=%v", result.Clean, OnlyNumberOnlyCardRuns(result.Matches), tt.Clean, tt.Warn)
				}
				wantAction := config.ActionBlock
				if tt.Warn {
					wantAction = config.ActionWarn
				}
				if CardRunAction(result.Matches, config.ActionBlock) != wantAction {
					t.Fatal("card class changed an unrelated action")
				}
				for _, m := range result.Matches {
					if tt.Warn && !m.IsNumberOnlyCardRun() {
						t.Fatal("card match lost scalar provenance")
					}
				}
				if tt.Warn {
					for _, m := range result.Matches {
						if !m.Warn || !strings.HasPrefix(m.Span().ViewLabel, "json_number_run") {
							t.Fatal("warning metadata missing")
						}
					}
				}
			}
		})
	}
}

func TestCardJSONDirectRunPolicy(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	for _, tt := range cardtest.JSONCases() {
		matches := s.ScanJSONCardRuns(t.Context(), tt.Body)
		// Complete string cards use the ordinary string scan.
		if tt.Name == "number run and string card" {
			// The standalone string card is enforced by the ordinary scan;
			// this direct pass reports only the numeric join.
			if !OnlyNumberOnlyCardRuns(matches) {
				t.Fatal("numeric run missing beside a standalone string card")
			}
			continue
		}
		if tt.Clean || tt.Name == "string card" {
			if len(matches) != 0 {
				t.Fatal("non-run input produced a typed card run")
			}
			continue
		}
		if len(matches) == 0 || OnlyNumberOnlyCardRuns(matches) != tt.Warn {
			t.Fatalf("direct run class missing for %s", tt.Name)
		}
	}
	for _, body := range []string{`[1e10001]`, strings.Repeat("[", 65) + "1" + strings.Repeat("]", 65)} {
		matches := s.ScanJSONCardRuns(t.Context(), body)
		if len(matches) != 1 || matches[0].PatternName != UninspectableJSONNumberPattern || matches[0].Warn {
			t.Fatal("direct inspection limit did not refuse")
		}
	}
}

func TestCardRunBoundaryTextCannotClaimNumberType(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	for _, separator := range []string{jsonnumber.NumberBoundary, jsonnumber.StringNumberBoundary, jsonnumber.NumberStringBoundary} {
		text := strings.Join([]string{"4111", "1111", "1111", "1111"}, separator)
		for _, result := range []TextDLPResult{s.ScanTextForDLP(t.Context(), text), s.ScanTextForDLPWithCardView(t.Context(), text, text)} {
			if result.Clean || OnlyNumberOnlyCardRuns(result.Matches) {
				t.Fatal("input marker received numeric warning policy")
			}
		}
		atoms := []extract.DLPAtom{{Text: text, Card: text}}
		result := s.ScanTextForDLPWithTypedCardView(t.Context(), text, extract.JoinCardAtoms(atoms, " "))
		if result.Clean || OnlyNumberOnlyCardRuns(result.Matches) {
			t.Fatal("string atom manufactured typed numeric evidence")
		}
	}
}

func TestCardRunBudgetRefusesOnlyStructuredText(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	// Scalar text is valid JSON but is a string value or plain text, never a
	// document; its digits keep the ordinary text scan.
	for _, text := range []string{strings.Repeat("7", 4097), " 1e10001 ", "-" + strings.Repeat("7", 4097)} {
		for _, result := range []TextDLPResult{
			s.ScanTextForDLP(t.Context(), text),
			s.ScanTextForDLPWithCardView(t.Context(), text, text),
			s.ScanTextForDLPInboundWithCardView(t.Context(), text, text),
		} {
			if !result.Clean {
				t.Fatalf("scalar text %.12q was refused: %+v", text, result.Matches)
			}
		}
	}
	for _, text := range []string{`[1e10001]`, ` {"n":` + strings.Repeat("7", 4097) + `}`, strings.Repeat("[", 65) + "1" + strings.Repeat("]", 65)} {
		result := s.ScanTextForDLP(t.Context(), text)
		if result.Clean || result.Matches[0].PatternName != UninspectableJSONNumberPattern {
			t.Fatalf("structured over-budget text %.12q was not refused", text)
		}
	}
	// An in-budget scalar still contributes its integer component.
	card := "4111" + "1111" + "1111" + "1111"
	if result := s.ScanTextForDLP(t.Context(), card+"e-2"); result.Clean || OnlyNumberOnlyCardRuns(result.Matches) {
		t.Fatal("scalar exponent card lost enforcement")
	}
}
