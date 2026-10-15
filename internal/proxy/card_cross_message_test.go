// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
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
			t.Run(tt.name, func(t *testing.T) {
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
