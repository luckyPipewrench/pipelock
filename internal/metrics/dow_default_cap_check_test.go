// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDoWDefaultSurvivesAFullProfileCap records maxTopEntries distinct configured
// agents and then records an unconfigured event, which the MCP path reports as
// the literal "_default" rather than as an empty string.
//
// The default bucket must never collapse into "_other". An operator reading
// "_other" cannot tell whether the spend came from an unconfigured agent or from
// one of the many named agents that overflowed the cap, which defeats the point
// of attributing the event at all.
func TestDoWDefaultSurvivesAFullProfileCap(t *testing.T) {
	m := New()

	for i := range maxTopEntries {
		m.RecordDenialOfWalletEvent("block", fmt.Sprintf("agent-%03d", i), "agent")
	}

	// The MCP attribution path passes the literal "_default", not "".
	m.RecordDenialOfWalletEvent("warn", "_default", "default")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)
	text := w.Body.String()

	want := `pipelock_denial_of_wallet_events_total{action="warn",agent="_default",subject_trust="default"} 1`
	if !strings.Contains(text, want) {
		t.Fatalf("default bucket collapsed after the cap filled; missing %q", want)
	}
}
