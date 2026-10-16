// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
)

func TestCardJSONNumbers(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	for _, tt := range []struct {
		name, text string
		card       bool
	}{
		{"ratio", `{"ctr":0.41111111` + `11111111}`, false},
		{"position", `{"position":4.41111111` + `11111111}`, false},
		{"fraction split", `{"n":41111111.11111111}`, false},
		{"mantissa card", `{"n":41111111` + `11111111.1}`, true},
		{"signed mantissa", `{"n":-41111111` + `11111111.1}`, true},
		{"integer", `{"n":41111111` + `11111111}`, true},
		{"integer decimal", `{"n":41111111` + `11111111.0}`, true},
		{"integer exponent", `{"n":41111111` + `11111111e0}`, true},
		{"shifted exponent", `{"n":4.11111111` + `1111111e15}`, false},
		{"signed exponent", `{"n":-4.11111111` + `1111111e15}`, false},
		{"fractional exponent mantissa", `{"n":41111111` + `11111111e-4}`, true},
		{"nineteen digits", `{"n":41111111` + `11111111110.0}`, true},
		{"string", `{"n":"0.41111111` + `11111111"}`, true},
		{"key", `{"41111111` + `11111111":0.1}`, true},
		{"encoded string", `{"n":"` + base64.StdEncoding.EncodeToString([]byte("41111111"+"11111111")) + `"}`, true},
		{"nested string retains its type", `{"n":"{\"ctr\":0.41111111` + `11111111}"}`, true},
		{"prose", "position 4.41111111" + "11111111", true},
		{"malformed", `{ctr:0.41111111` + `11111111}`, true},
		{"trailing", `{"ctr":0.41111111` + `11111111} junk`, true},
		{"decoy", `{"ctr":0.41111111` + `11111111,"n":"41111111` + `11111111"}`, true},
		{"duplicate key", `{"n":"41111111` + `11111111","n":0.41111111` + `11111111}`, true},
		{"encoded attack after metric", `{"n":0.41111111` + `11111111,"s":"` + base64.StdEncoding.EncodeToString([]byte("41111111"+"11111111")) + `"}`, true},
		{"depth fallback", strings.Repeat("[", 65) + `0.41111111` + `11111111` + strings.Repeat("]", 65), true},
		{"exponent budget fallback", `{"n":0.41111111` + `11111111,"other":1e10001}`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, inbound := range []bool{false, true} {
				result := s.ScanTextForDLPWithCardView(t.Context(), tt.text, jsonnumber.CardView(tt.text, extract.MaxExtractDepth))
				if inbound {
					result = s.ScanTextForDLPInboundWithCardView(t.Context(), tt.text, jsonnumber.CardView(tt.text, extract.MaxExtractDepth))
				}
				card := false
				for _, m := range result.Matches {
					card = card || m.PatternName == "Credit Card Number"
				}
				if card != tt.card {
					t.Fatalf("inbound=%v card=%v want=%v matches=%+v", inbound, card, tt.card, result.Matches)
				}
			}
		})
	}
}

func TestCardJSONKnownValues(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.CanaryTokens.Enabled = true
	cfg.CanaryTokens.Tokens = []config.CanaryToken{{Name: "numeric", Value: "4111" + "1111" + "1111" + "1111"}}
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	for _, text := range []string{`{"ctr":0.41111111` + `11111111}`, `{"n":"0.41111111` + `11111111"}`} {
		for _, result := range []TextDLPResult{s.ScanTextForDLPWithCardView(t.Context(), text, jsonnumber.CardView(text, extract.MaxExtractDepth)), s.ScanTextForDLPInboundWithCardView(t.Context(), text, jsonnumber.CardView(text, extract.MaxExtractDepth))} {
			found := false
			for _, m := range result.Matches {
				found = found || strings.HasPrefix(m.PatternName, "Canary Token (")
			}
			if !found || result.Clean {
				t.Fatalf("known-value detection lost: %+v", result)
			}
		}
	}
}

func TestCardJSONNumberBudgetFailsClosed(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	text := `{"n":` + strings.Repeat("9", 4097) + `}`
	result := s.ScanTextForDLPWithCardView(t.Context(), text, jsonnumber.CardView(text, extract.MaxExtractDepth))
	if result.Clean || len(result.Matches) == 0 || result.Matches[0].PatternName != "Uninspectable JSON number" {
		t.Fatalf("over-budget number was treated as clean: %+v", result)
	}
}

func TestCardJSONKnownSecretAndValidatorIdentity(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	for i := range cfg.DLP.Patterns {
		if cfg.DLP.Patterns[i].Validator == config.ValidatorLuhn {
			cfg.DLP.Patterns[i].Name = "Renamed card rule"
		}
	}
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	card := "41111111" + "11111111"
	metric := `{"n":0.` + card + `}`
	if r := s.ScanTextForDLPWithCardView(t.Context(), metric, jsonnumber.CardView(metric, extract.MaxExtractDepth)); !r.Clean {
		t.Fatalf("rule name selected policy: %+v", r)
	}
	s.envSecrets = []string{card}
	if r := s.ScanTextForDLPWithCardView(t.Context(), metric, jsonnumber.CardView(metric, extract.MaxExtractDepth)); r.Clean {
		t.Fatal("original known secret was lost")
	}
	if r := s.ScanTextForDLPInboundWithCardView(t.Context(), metric, jsonnumber.CardView(metric, extract.MaxExtractDepth)); !r.Clean {
		t.Fatal("inbound env semantics changed")
	}
	r := s.ScanTextForDLPQuietWithCardView(t.Context(), `{"n":`+card+`.1}`, jsonnumber.CardView(`{"n":`+card+`.1}`, extract.MaxExtractDepth))
	located := false
	for _, m := range r.Matches {
		located = located || m.PatternName == "Renamed card rule" && strings.Contains(m.Span().ViewLabel, "json_integer")
	}
	if r.Clean || !located {
		t.Fatalf("integer match lacks its scan view: %+v", r)
	}
}

func TestCardJSONMetricDoesNotMaskEncodedSecret(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	// A non-core credential must survive too: the immutable core has its own
	// decoding path and can conceal a configured-pattern early-exit defect.
	value := "whsec_" + strings.Repeat("a", 24)
	for i := range 4 {
		text := `{"n":0.41111111` + `11111111,"s` + strings.Repeat("x", i) + `":"https://api.vendor.example/` + base64.StdEncoding.EncodeToString([]byte(value)) + `/end"}`
		r := s.ScanTextForDLPWithCardView(t.Context(), text, jsonnumber.CardView(text, extract.MaxExtractDepth))
		found := false
		for _, m := range r.Matches {
			found = found || m.PatternName == "Stripe Webhook Secret"
		}
		if r.Clean || !found {
			t.Fatalf("prefix=%d metric masked encoded credential: %+v", i, r)
		}
	}
}
