// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestResponseScanExemptOverCapUnscannedObservability_Forward(t *testing.T) {
	const scanCapBytes = 1024 * 1024
	tests := []struct {
		name       string
		body       string
		configure  func(*config.Config, string)
		wantStatus int
		wantMetric bool
	}{
		{
			name: "exempt over cap records",
			body: strings.Repeat("E", scanCapBytes+128),
			configure: func(cfg *config.Config, host string) {
				cfg.ResponseScanning.ExemptDomains = []string{host}
			},
			wantStatus: http.StatusOK,
			wantMetric: true,
		},
		{
			name:       "non exempt over cap does not record",
			body:       strings.Repeat("N", scanCapBytes+128),
			wantStatus: http.StatusForbidden,
		},
		{
			name: "size exempt over cap passthrough does not record",
			body: strings.Repeat("S", scanCapBytes+128),
			configure: func(cfg *config.Config, host string) {
				cfg.ResponseScanning.SizeExemptDomains = []string{host}
				cfg.ResponseScanning.UnscannablePassthrough = []config.UnscannablePassthroughEntry{{
					Host:         host,
					Paths:        []string{"/payload"},
					ContentTypes: []string{"application/octet-stream"},
					Reason:       "opaque test artifact",
					Expires:      "2099-01-01",
				}}
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "exempt under cap does not record",
			body: strings.Repeat("U", 512),
			configure: func(cfg *config.Config, host string) {
				cfg.ResponseScanning.ExemptDomains = []string{host}
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Disposition", `attachment; filename="payload.bin"`)
				w.Header().Set("Content-Length", strconv.Itoa(len(tt.body)))
				_, _ = io.WriteString(w, tt.body)
			}))
			defer backend.Close()

			backendHost := mustURLHostname(t, backend.URL)
			proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
				cfg.FetchProxy.MaxResponseMB = 1
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.Action = config.ActionBlock
				if tt.configure != nil {
					tt.configure(cfg, backendHost)
				}
			})
			defer cleanup()

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, backend.URL+"/payload", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := proxyClient(proxyAddr).Do(req)
			if err != nil {
				t.Fatalf("proxy request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			assertResponseScanExemptOverCapMetric(t, p.metrics, TransportForward, tt.wantMetric)
		})
	}
}

func TestResponseScanExemptOverCapUnscannedObservability_Intercept(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		configure  func(*config.Config, string)
		wantStatus int
		wantMetric bool
	}{
		{
			name: "exempt over cap records",
			body: strings.Repeat("E", 1152),
			configure: func(cfg *config.Config, host string) {
				cfg.ResponseScanning.ExemptDomains = []string{host}
			},
			wantStatus: http.StatusOK,
			wantMetric: true,
		},
		{
			name:       "non exempt over cap does not record",
			body:       strings.Repeat("N", 1152),
			wantStatus: http.StatusForbidden,
		},
		{
			name: "size exempt over cap bounded scan does not record",
			body: strings.Repeat("S", 1152),
			configure: func(cfg *config.Config, host string) {
				cfg.ResponseScanning.SizeExemptDomains = []string{host}
				cfg.ResponseScanning.SizeExemptScanMaxBytes = 2048
				cfg.ResponseScanning.SizeExemptScanMaxInflightBytes = 4096
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "exempt under cap does not record",
			body: strings.Repeat("U", 512),
			configure: func(cfg *config.Config, host string) {
				cfg.ResponseScanning.ExemptDomains = []string{host}
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Length", strconv.Itoa(len(tt.body)))
				_, _ = io.WriteString(w, tt.body)
			}))
			defer upstream.Close()

			cache, pool, cfg, _, logger, m := testInterceptSetup(t)
			cfg.ResponseScanning.Enabled = true
			cfg.ResponseScanning.Action = config.ActionBlock
			cfg.TLSInterception.MaxResponseBytes = 1024
			host := upstream.Listener.Addr().(*net.TCPAddr).IP.String()
			if tt.configure != nil {
				tt.configure(cfg, host)
			}
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL+"/payload", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp := interceptAndRequest(t, upstream, cache, pool, cfg, sc, logger, m, req)
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			assertResponseScanExemptOverCapMetric(t, m, TransportConnect, tt.wantMetric)
		})
	}
}

func assertResponseScanExemptOverCapMetric(t *testing.T, m *metrics.Metrics, transport string, wantPresent bool) {
	t.Helper()
	wantPrefix := fmt.Sprintf(`pipelock_response_scan_exempt_overcap_unscanned_total{transport="%s"} `, transport)
	rec := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	gotPresent := strings.Contains(body, wantPrefix)
	if gotPresent != wantPresent {
		t.Fatalf("metric presence for %q = %v, want %v; metrics:\n%s", wantPrefix, gotPresent, wantPresent, body)
	}
}

// TestRecordResponseScanExemptOverCapUnscanned_HelperBranches covers the
// recorder helper's branches directly: the empty-host "_unknown" fallback, the
// nil-logger path (metric still records, log skipped), and the under-cap
// short-circuit (no record).
func TestRecordResponseScanExemptOverCapUnscanned_HelperBranches(t *testing.T) {
	m := metrics.New()
	logger, err := audit.New("json", "file", t.TempDir()+"/exempt.log", true, true)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer logger.Close()

	// Empty host, over cap: metric records and the audit log uses the
	// "_unknown" host fallback.
	recordResponseScanExemptOverCapUnscanned(m, logger, audit.LogContext{}, "", TransportForward, 2048, 1024)
	// Nil logger, over cap: metric still records, the logger block is skipped.
	recordResponseScanExemptOverCapUnscanned(m, nil, audit.LogContext{}, "host", TransportConnect, 2048, 1024)
	// Under cap: short-circuits before recording anything. Use a fresh metrics
	// instance so the short-circuit is actually verified (absence), rather than
	// aliasing the over-cap TransportForward record above.
	mUnder := metrics.New()
	recordResponseScanExemptOverCapUnscanned(mUnder, logger, audit.LogContext{}, "host", TransportForward, 512, 1024)

	assertResponseScanExemptOverCapMetric(t, m, TransportForward, true)
	assertResponseScanExemptOverCapMetric(t, m, TransportConnect, true)
	assertResponseScanExemptOverCapMetric(t, mUnder, TransportForward, false)
}

func mustURLHostname(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}
	return u.Hostname()
}
