// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestDefaultMCPListenerSensitiveHeadersParity fails when the MCP listener's
// fallback header list drifts from the config default sensitive-header list.
// The listener list must be exactly the config default plus Last-Event-ID.
func TestDefaultMCPListenerSensitiveHeadersParity(t *testing.T) {
	canon := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, h := range in {
			out = append(out, http.CanonicalHeaderKey(h))
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	want := canon(append(append([]string(nil), config.Defaults().RequestBodyScanning.SensitiveHeaders...), listenerLastEventID))
	got := canon(defaultMCPListenerSensitiveHeaders)
	if !slices.Equal(got, want) {
		t.Fatalf("MCP listener sensitive headers = %v, want config default plus %s = %v", got, listenerLastEventID, want)
	}
}
