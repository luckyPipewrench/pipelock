// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestSandboxBridgeIdleTimeout(t *testing.T) {
	tests := []struct {
		name        string
		forward, ws int
		want        time.Duration
	}{
		{"defaults take the larger websocket value", 120, 300, 300 * time.Second},
		{"forward larger", 900, 300, 900 * time.Second},
		{"websocket larger", 60, 600, 600 * time.Second},
		{"unset falls through to sandbox default", 0, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.ForwardProxy.IdleTimeoutSeconds = tt.forward
			cfg.WebSocketProxy.IdleTimeoutSeconds = tt.ws
			if got := sandboxBridgeIdleTimeout(cfg); got != tt.want {
				t.Fatalf("sandboxBridgeIdleTimeout = %v, want %v", got, tt.want)
			}
		})
	}
	d := config.Defaults()
	if got := sandboxBridgeIdleTimeout(d); got != 300*time.Second {
		t.Fatalf("shipped defaults map to %v, want the sandbox default 300s", got)
	}
}
