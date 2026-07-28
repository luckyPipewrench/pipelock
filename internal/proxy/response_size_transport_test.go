// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// The helper-level test proves responseSizeBlockReason renders correctly for a
// given flag, but it passes just as happily if a CALLER hands it the wrong
// flag. This drives the real fetch path so the flag the fetch caller actually
// passes is what gets asserted. Fetch has no per-host size-exempt branch, so
// its reason must say so and must not send an operator to a knob that cannot
// lift their block.
func TestFetchOversizedResponseReasonNamesNoHostExemption(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(strings.Repeat("x", 4096)))
	}))
	defer upstream.Close()

	cfg := testScannerConfig()
	// Any real response exceeds this, so the size gate is what blocks.
	cfg.FetchProxy.MaxResponseMB = 0
	logger := audit.NewNop()
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+upstream.URL, nil)
	rec := httptest.NewRecorder()
	p.handleFetch(rec, req)

	body := rec.Body.String()
	if rec.Code == http.StatusOK {
		t.Fatalf("oversized response was not blocked: status %d, body %q", rec.Code, body)
	}
	if !strings.Contains(body, "no per-host size exemption") {
		t.Errorf("fetch block reason does not state the exemption is unavailable: %q", body)
	}
	if strings.Contains(body, "size_exempt_domains") {
		t.Errorf("fetch block reason recommends a knob the fetch path never consults: %q", body)
	}
}
