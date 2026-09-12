// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const ceeWindowBodyBytes = 65536

func TestCEEAdmit_ScansCompletingHTTPBodyBeforeRetention(t *testing.T) {
	secret := "CTOK" + strings.Repeat("B", 12)
	first := strings.Repeat("x", ceeWindowBodyBytes-8) + secret[:8]
	second := secret[8:] + strings.Repeat("x", ceeWindowBodyBytes-8)

	for _, tc := range []struct {
		name   string
		cap    int
		action string
		block  bool
	}{
		{name: "default cap blocks", action: config.ActionBlock, block: true},
		{name: "lower cap warns", cap: ceeWindowBodyBytes / 2, action: config.ActionWarn},
		{name: "raised cap blocks", cap: ceeWindowBodyBytes * 2, action: config.ActionBlock, block: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ceeWindowProxyConfig(t, tc.action, tc.cap)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			bufferLimit := cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes
			fb := scanner.NewFragmentBuffer(bufferLimit, cfg.CrossRequestDetection.FragmentReassembly.ResolvedMaxSessions(), 300)
			t.Cleanup(fb.Close)
			m := metrics.New()

			firstResult := ceeWindowHTTPAdmit(t, cfg, sc, fb, m, first)
			if firstResult.Blocked || firstResult.FragmentHit {
				t.Fatalf("first individually clean body result = %+v", firstResult)
			}
			result := ceeWindowHTTPAdmit(t, cfg, sc, fb, m, second)
			if !result.FragmentHit || result.Blocked != tc.block {
				t.Fatalf("completing body result = %+v, want fragment hit with blocked=%t", result, tc.block)
			}
			if retained := fb.TotalBufferBytes(); retained > bufferLimit {
				t.Fatalf("retained body bytes = %d, exceeds configured cap %d", retained, bufferLimit)
			}
		})
	}
}

func TestCEEAdmit_DoesNotMatchNearMissAcrossHTTPBodies(t *testing.T) {
	cfg := ceeWindowProxyConfig(t, config.ActionBlock, 0)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	fb := scanner.NewFragmentBuffer(cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes, cfg.CrossRequestDetection.FragmentReassembly.ResolvedMaxSessions(), 300)
	t.Cleanup(fb.Close)
	m := metrics.New()

	first := strings.Repeat("x", ceeWindowBodyBytes-8) + "CTOKBBBB"
	second := "BBBBBBB7" + strings.Repeat("x", ceeWindowBodyBytes-8)
	if result := ceeWindowHTTPAdmit(t, cfg, sc, fb, m, first); result.FragmentHit || result.Blocked {
		t.Fatalf("first near-miss body result = %+v", result)
	}
	if result := ceeWindowHTTPAdmit(t, cfg, sc, fb, m, second); result.FragmentHit || result.Blocked {
		t.Fatalf("near-miss body result = %+v, want clean", result)
	}
}

func ceeWindowProxyConfig(t *testing.T, action string, bufferLimit int) *config.Config {
	t.Helper()
	var maxBuffer string
	if bufferLimit > 0 {
		maxBuffer = "    max_buffer_bytes: " + strconv.Itoa(bufferLimit) + "\n"
	}
	cfg, err := config.LoadBytes([]byte("dlp:\n  patterns:\n    - name: Boundary token\n      regex: 'CTOK[A-Z]{12}'\n      severity: high\ncross_request_detection:\n  enabled: true\n  action: " + action + "\n  entropy_budget:\n    enabled: false\n  fragment_reassembly:\n    enabled: true\n" + maxBuffer))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if bufferLimit == 0 && cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes != ceeWindowBodyBytes {
		t.Fatalf("default max_buffer_bytes = %d, want %d", cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes, ceeWindowBodyBytes)
	}
	cfg.Internal = nil
	return cfg
}

func ceeWindowHTTPAdmit(t *testing.T, cfg *config.Config, sc *scanner.Scanner, fb *scanner.FragmentBuffer, m *metrics.Metrics, body string) ceeResult {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.vendor.example/collect", bytes.NewBufferString(body))
	payloads := extractOutboundPayloads(req, false, "window-session", nil)
	if got := len(payloads.outbound); got != ceeWindowBodyBytes {
		t.Fatalf("extractOutboundPayloads body bytes = %d, want %d", got, ceeWindowBodyBytes)
	}
	return ceeAdmit(context.Background(), ceeAdmitOptions{
		ClientIP: "203.0.113.10", Outbound: payloads.outbound, TargetURL: req.URL.String(),
		Config: cfg.CrossRequestDetection, Fragments: fb, Scanner: sc, Logger: audit.NewNop(), Metrics: m,
	})
}
