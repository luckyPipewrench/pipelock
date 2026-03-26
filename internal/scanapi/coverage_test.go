// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestFieldLimit(t *testing.T) {
	t.Parallel()

	h := &Handler{cfg: config.Defaults()}

	tests := []struct {
		name       string
		configured int
		defaultVal int
		want       int
	}{
		{"zero uses default", 0, 8192, 8192},
		{"negative uses default", -1, 8192, 8192},
		{"configured positive", 1024, 8192, 1024},
		{"configured matches default", 8192, 8192, 8192},
		{"configured larger than default", 16384, 8192, 16384},
		{"one uses configured", 1, 8192, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := h.fieldLimit(tt.configured, tt.defaultVal)
			if got != tt.want {
				t.Errorf("fieldLimit(%d, %d) = %d, want %d", tt.configured, tt.defaultVal, got, tt.want)
			}
		})
	}
}

func TestKindEnabled(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.ScanAPI.Kinds.URL = true
	cfg.ScanAPI.Kinds.DLP = false
	cfg.ScanAPI.Kinds.PromptInjection = true
	cfg.ScanAPI.Kinds.ToolCall = false

	h := &Handler{cfg: cfg}

	tests := []struct {
		name string
		kind string
		want bool
	}{
		{"URL enabled", KindURL, true},
		{"DLP disabled", KindDLP, false},
		{"prompt_injection enabled", KindPromptInjection, true},
		{"tool_call disabled", KindToolCall, false},
		{"unknown kind", "unknown", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := h.kindEnabled(tt.kind)
			if got != tt.want {
				t.Errorf("kindEnabled(%q) = %v, want %v", tt.kind, got, tt.want)
			}
		})
	}
}
