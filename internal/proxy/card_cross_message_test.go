// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCardJSONCrossMessageViews(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	relay, _ := newWebSocketFrameSuppressionRelay(t, cfg, "wss://api.vendor.example/socket")
	card := "4111" + "111111111111"
	view := func(s string) []byte { return []byte(jsonnumber.CardView(s, extract.MaxExtractDepth)) }
	for _, tt := range []struct {
		name, tail, message string
		blocked             bool
	}{
		{"metrics", `{"n":0.` + card + `}`, `{"n":0.` + card + `}`, false},
		{"split card", card[:8], card[8:], true},
		{"split string", `{"s":"` + card[:8], card[8:] + `"}`, true},
		{"metric then split string", `{"n":0.` + card + `,"s":"` + card[:8], card[8:] + `"}`, true},
	} {
		for _, redaction := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/redaction=%v", tt.name, redaction), func(t *testing.T) {
				relay.redaction = nil
				if redaction {
					relay.redaction = &redactionRuntime{required: true}
				}
				if got := relay.scanClientCrossMessageTextViews(t.Context(), audit.NewNop(), []byte(tt.tail), []byte(tt.message), view(tt.tail), view(tt.message)); got != tt.blocked {
					t.Fatalf("redaction=%v blocked=%v, want=%v", redaction, got, tt.blocked)
				}
			})
		}
	}
}

func TestCardJSONCrossMessageEvidenceClass(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	relay, _ := newWebSocketFrameSuppressionRelay(t, cfg, "wss://api.vendor.example/socket")
	card := cardtest.Number()
	raw := `["` + card[:2] + `","` + card[2:9] + `","` + card[9:] + `"]`
	previous := relay.scanner.ScanTextForDLP(t.Context(), raw)
	combined := relay.scanner.ScanTextForDLP(t.Context(), `{"ids":`+raw+`,"card":"`+card+`"}`)
	current := relay.scanner.ScanTextForDLP(t.Context(), "ordinary report")
	matches, _ := wsCrossMessageDLPMatches(combined, previous, current)
	if !scanner.HasEnforcingMatch(matches) {
		t.Fatal("prior informational card suppressed enforcing evidence")
	}
	matches, warns := wsCrossMessageDLPMatches(previous, previous, current)
	if len(matches) != 0 || len(warns) != 0 {
		t.Fatal("same-class warning repeated across messages")
	}
}
