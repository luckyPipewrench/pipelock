// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
)

func TestCardLiteralTextRetainsType(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	card := "41111111" + "11111111"
	for _, text := range []string{card, "0." + card, "[0." + card + "]", `{"n":0.` + card + `}`} {
		for _, result := range []TextDLPResult{
			s.ScanTextForDLP(t.Context(), text),
			s.ScanTextForDLPInbound(t.Context(), text),
			s.ScanTextForDLPQuiet(t.Context(), text),
			s.ScanRequestBodyTextPartsForDLP(t.Context(), []string{text}, "\n"),
		} {
			if result.Clean {
				t.Fatalf("literal text received numeric relief: %q", text)
			}
		}
	}
}

func TestCardJSONNumericJoinsMaintainBarriers(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	parts := []string{"4111.21", "1111.22", "1111.23", "1111.24"}
	cards := make([]string, len(parts))
	for i, part := range parts {
		cards[i] = jsonnumber.IntegralView(json.Number(part))
	}
	for _, inbound := range []bool{false, true} {
		original, cardView := strings.Join(parts, "\n"), strings.Join(cards, "\n")
		result := s.ScanTextForDLPWithCardView(t.Context(), original, cardView)
		if inbound {
			result = s.ScanTextForDLPInboundWithCardView(t.Context(), original, cardView)
		}
		if !result.Clean {
			t.Fatalf("unrelated integer components fabricated a card: %+v", result)
		}
	}
}

func TestCardJSONScalarViews(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	card := "41111111" + "11111111"
	for _, number := range []string{card + ".1", "-" + card + ".1", card + "e-2"} {
		view := jsonnumber.IntegralView(json.Number(number))
		if result := s.ScanTextForDLPWithCardView(t.Context(), number, view); result.Clean {
			t.Fatalf("written integer escaped scalar scan: %q view=%q result=%+v", number, view, result)
		}
	}
}
