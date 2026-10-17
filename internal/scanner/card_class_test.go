// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/json"
	"slices"
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
			results = append(results,
				s.ScanTextForDLPWithTypedCardView(t.Context(), text, view),
				s.ScanTextForDLPInboundWithTypedCardView(t.Context(), text, view),
				s.ScanTextForDLPQuietWithTypedCardView(t.Context(), text, view),
				s.ScanRequestBodyTextPartsWithCardAtoms(t.Context(), extracted.Atoms, "\n"))
			for _, result := range results {
				if result.Clean != (tt.Clean || tt.Warn) || OnlyInformational(result.Matches) != tt.Warn {
					t.Fatalf("clean=%v number-only=%v; want clean=%v warn=%v", result.Clean, OnlyInformational(result.Matches), tt.Clean, tt.Warn)
				}
				wantAction := config.ActionBlock
				if tt.Warn {
					wantAction = config.ActionWarn
				}
				if CardRunAction(result.Matches, config.ActionBlock) != wantAction {
					t.Fatal("card class changed an unrelated action")
				}
				for _, m := range result.Matches {
					if tt.Warn && !m.IsInformational() {
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
		if tt.Name == "number run and string card" || tt.Name == "uneven then whole card" {
			// The standalone string card is enforced by the ordinary scan;
			// this direct pass reports only the numeric join.
			if !OnlyInformational(matches) {
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
		if len(matches) == 0 || OnlyInformational(matches) != tt.Warn {
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
			if result.Clean || OnlyInformational(result.Matches) {
				t.Fatal("input marker received numeric warning policy")
			}
		}
		atoms := []extract.DLPAtom{{Text: text, Card: text}}
		result := s.ScanTextForDLPWithTypedCardView(t.Context(), text, extract.JoinCardAtoms(atoms, " "))
		if result.Clean || OnlyInformational(result.Matches) {
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
	// A scalar still contributes its integer component, in or over budget.
	card := "4111" + "1111" + "1111" + "1111"
	for _, text := range []string{card + "e-2", card + "e10001", " -" + card + ".5E-10001", card + "." + strings.Repeat("7", 4097)} {
		if result := s.ScanTextForDLP(t.Context(), text); result.Clean || OnlyInformational(result.Matches) || result.Matches[0].PatternName == UninspectableJSONNumberPattern {
			t.Fatalf("scalar card %.24q lost enforcement: %+v", text, result.Matches)
		}
	}
}

func TestCardRunInformationalDoesNotHideProtectedValues(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	card := cardtest.Number()
	pieces := []string{card[:2], card[2:9], card[9:]}
	var atoms []extract.DLPAtom
	for _, p := range pieces {
		atoms = append(atoms, extract.DLPAtom{Text: p, Card: p})
	}
	view := extract.JoinCardAtoms(atoms, "")
	s.envSecrets = []string{card}
	if result := s.ScanTextForDLPWithTypedCardView(t.Context(), card, view); result.Clean {
		t.Fatal("known secret lost to informational card")
	}
	s.envSecrets = nil
	value := "whsec_" + strings.Repeat("a", 24)
	body := `["` + strings.Join(pieces, `","`) + `","` + value + `"]`
	if result := s.ScanTextForDLP(t.Context(), body); result.Clean || OnlyInformational(result.Matches) {
		t.Fatal("other credential lost to informational card")
	}
}

func TestCardRunUntrustedStringMarkersKeepOrdinaryPolicy(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	card := cardtest.Number()
	for _, separator := range []string{jsonnumber.NumberBoundary, jsonnumber.NumberStringBoundary, jsonnumber.StringNumberBoundary, jsonnumber.StringBoundary} {
		text := strings.Join([]string{card[:2], card[2:9], card[9:]}, separator)
		result := s.ScanTextForDLPWithTypedCardView(t.Context(), text, extract.JoinCardAtoms([]extract.DLPAtom{{Text: text, Card: text}}, " "))
		if result.Clean || OnlyInformational(result.Matches) {
			t.Fatal("untrusted marker manufactured informational scalar pieces")
		}
	}
}

func TestCardRunLaterEnforcementWins(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	card := cardtest.Number()
	informational := s.ScanJSONCardRuns(t.Context(), `["`+card[:2]+`","`+card[2:9]+`","`+card[9:]+`"]`)
	enforcing := s.ScanTextForDLP(t.Context(), card).Matches
	for _, matches := range [][]TextDLPMatch{append(informational, enforcing...), append(enforcing, informational...)} {
		if OnlyInformational(matches) || !HasEnforcingMatch(matches) || CardRunAction(matches, config.ActionBlock) != config.ActionBlock {
			t.Fatal("informational evidence hid enforcement")
		}
	}
}

func TestCardRunFragmentWarningsRemainInformational(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "fixture warn", Regex: `fixturewarn-[a-z]+`, Action: config.ActionWarn, Severity: config.SeverityHigh})
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	card := cardtest.Number()
	text := `["` + card[:2] + `","` + card[2:9] + `","` + card[9:] + `","fixturewarn-alpha"]`
	if result := s.ScanTextForDLP(t.Context(), text); !result.Clean || !OnlyInformational(result.Matches) || len(result.InformationalMatches) == 0 {
		t.Fatal("fixture lost its two warning classes")
	}
	if matches := scanFragmentsForSecrets(t.Context(), s, []fragment{{data: []byte(text[:7])}, {data: []byte(text[7:])}}); len(matches) != 0 {
		t.Fatal("fragment reconstruction promoted informational evidence")
	}
}

func TestCardRunSingleScalarNotRepeated(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	card := cardtest.Number()
	atoms := []extract.DLPAtom{{Text: card, Card: card, Number: true}, {Text: "stop", Card: "stop"}}
	result := s.ScanTextForDLPWithTypedCardView(t.Context(), card+" stop", extract.JoinCardAtoms(atoms, " "))
	if result.Clean || len(result.Matches) != 1 {
		t.Fatalf("standalone card count=%d clean=%v", len(result.Matches), result.Clean)
	}
}

func TestCardRunFragmentMemoKeepsWarnings(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	warnings := 0
	s.SetDLPWarnHook(func(_ context.Context, _, _ string) { warnings++ })
	card := cardtest.Number()
	text := `["` + card[:2] + `","` + card[2:9] + `","` + card[9:] + `"]`
	fragments := []fragment{{data: []byte(text[:7])}, {data: []byte(text[7:])}}
	memo := &fragmentCleanMemo{limit: 4096}
	for range 2 {
		warnings = 0
		if matches := scanOneFragmentContinuityMemo(t.Context(), s, fragments, memo, "card"); len(matches) != 0 {
			t.Fatal("informational card enforced")
		}
		if warnings == 0 {
			t.Fatal("clean memo suppressed informational warning")
		}
	}
	clean := []fragment{{data: []byte("ordinary ")}, {data: []byte("report")}}
	_ = scanOneFragmentContinuityMemo(t.Context(), s, clean, memo, "clean")
	_ = scanOneFragmentContinuityMemo(t.Context(), s, clean, memo, "clean")
	if memo.hits == 0 {
		t.Fatal("warning-free positive control did not use memo")
	}
}

func TestCardRunFragmentMaskedWarningsRemainInformational(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	card := cardtest.Number()
	for _, tt := range []struct {
		name, tail string
		enforce    bool
	}{
		{name: "glue-only strings", tail: `["` + card[:2] + `","` + card[2:9] + `","` + card[9:] + `"]`},
		{name: "number-only", tail: `[` + card[:4] + `,` + card[4:8] + `,` + card[8:12] + `,` + card[12:] + `]`},
		{name: "grouped strings", tail: `["` + card[:4] + `","` + card[4:8] + `","` + card[8:12] + `","` + card[12:] + `"]`, enforce: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// A complete occurrence belongs to one request. The remaining occurrence
			// spans requests and must keep its own evidence class after masking.
			prefix := `["` + card + `",`
			tail := tt.tail[1:]
			text := prefix + tail
			before := s.ScanTextForDLP(t.Context(), text)
			if before.Clean {
				t.Fatal("complete occurrence did not enforce")
			}
			masked := s.ScanTextForDLP(t.Context(), `["",`+tail)
			if len(masked.Matches) == 0 || OnlyInformational(masked.Matches) == tt.enforce {
				t.Fatal("tail lost its expected evidence class")
			}
			for _, image := range []string{"", dataURLForPNGBytes(t, randomPNG(t, 21))} {
				first := prefix + tail[:3]
				if image != "" {
					first = `["` + image + `",` + first[1:]
				}
				fragments := []fragment{{data: []byte(first)}, {data: []byte(tail[3:])}}
				for range 2 {
					matches := scanFragmentsForSecrets(t.Context(), s, fragments)
					if (len(matches) > 0) != tt.enforce {
						t.Fatalf("image=%v cross-request enforcement=%v; want %v", image != "", len(matches) > 0, tt.enforce)
					}
				}
			}
		})
	}
}

func TestCardUnionUsesShippedReconstructionRule(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	// This configured rule finds the same digit values but excludes separators.
	// Typed reconstruction still follows the shared shipped-rule UNION.
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Card fixture", Regex: strings.ReplaceAll(jsonnumber.ShippedCardPattern, "[- ]?", ""), Validator: "luhn", Severity: config.SeverityHigh}}
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	for _, tt := range cardtest.UnionCases() {
		t.Run(tt.Name, func(t *testing.T) {
			matches := s.ScanJSONCardRuns(t.Context(), tt.Body)
			if HasEnforcingMatch(matches) != (!tt.Clean && !tt.Warn) {
				t.Fatal("configured matching changed the shared reconstruction policy")
			}
		})
	}
}

func TestCardTypedViewOwnsReconstruction(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Other credential fixture", Regex: `credential-marker`, Severity: config.SeverityHigh})
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	found := false
	for _, tt := range cardtest.UnionCases() {
		if tt.Name != "context prefixed split" {
			continue
		}
		found = true
		if result := s.ScanTextForDLPWithTypedCardView(t.Context(), tt.Body, tt.Body); result.Clean {
			t.Fatal("positive typed source missed")
		}
		if result := s.ScanTextForDLPWithTypedCardView(t.Context(), tt.Body, ""); !result.Clean {
			t.Fatal("text join fabricated typed card evidence")
		}
		if result := s.ScanTextForDLPWithTypedCardView(t.Context(), tt.Body+" credential-marker", ""); result.Clean || !slices.ContainsFunc(result.Matches, func(m TextDLPMatch) bool { return m.PatternName == "Other credential fixture" }) {
			t.Fatal("non-card credentials lost reconstruction")
		}
	}
	if !found {
		t.Fatal("positive corpus row missing")
	}
}
