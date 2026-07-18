// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type hardeningResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *hardeningResponseWriter) Header() http.Header {
	return w.header
}

func (w *hardeningResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *hardeningResponseWriter) Write(p []byte) (int, error) {
	return w.body.Write(p)
}

func hardeningLivechatServer(t *testing.T, cfg ServerConfig) *Server {
	t.Helper()
	gate, err := NewGate(GateConfig{
		Secret:   bytes.Repeat([]byte{0x5a}, 32),
		Codes:    []CodeSpec{{Code: "valid-code"}},
		TokenTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	cfg.Gate = gate
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = 2
	}
	if cfg.IPRate.Burst == 0 {
		cfg.IPRate = RateConfig{RefillPerSec: 100, Burst: 100}
	}
	if cfg.CodeRate.Burst == 0 {
		cfg.CodeRate = RateConfig{RefillPerSec: 100, Burst: 100}
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func TestHardeningLivechatRoutesRejectUnsupportedAndMalformedRequests(t *testing.T) {
	srv := hardeningLivechatServer(t, ServerConfig{})
	handler := srv.Handler()

	tests := []struct {
		name   string
		method string
		target string
		body   string
		status int
	}{
		{"health method", http.MethodPost, RouteHealth, "", http.StatusMethodNotAllowed},
		{"session preflight", http.MethodOptions, RouteSession, "", http.StatusNoContent},
		{"stream preflight", http.MethodOptions, RouteStream, "", http.StatusNoContent},
		{"message preflight", http.MethodOptions, RouteMessage, "", http.StatusNoContent},
		{"message malformed", http.MethodPost, RouteMessage, `{"token":`, http.StatusBadRequest},
		{"message unauthenticated", http.MethodPost, RouteMessage, `{"token":"bad","message":"hello"}`, http.StatusUnauthorized},
		{"bundle preflight", http.MethodOptions, RouteBundle, "", http.StatusNoContent},
		{"bundle unauthenticated", http.MethodGet, RouteBundle, "", http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.target, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}

func TestHardeningLivechatStreamRequiresFlushingSupport(t *testing.T) {
	t.Parallel()

	srv := hardeningLivechatServer(t, ServerConfig{})
	writer := &hardeningResponseWriter{header: make(http.Header)}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, RouteStream, nil)
	srv.handleStream(writer, req)
	if writer.status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusInternalServerError)
	}
	if !strings.Contains(writer.body.String(), "streaming unsupported") {
		t.Fatalf("body = %q", writer.body.String())
	}
}

func TestHardeningLivechatCleanupAndRefundAreIdempotent(t *testing.T) {
	t.Parallel()

	entry := &liveEntry{msgCount: 2}
	entry.refundMessage(0)
	if entry.msgCount != 2 {
		t.Fatalf("unlimited refund changed count to %d", entry.msgCount)
	}
	entry.refundMessage(1)
	entry.refundMessage(1)
	entry.refundMessage(1)
	if entry.msgCount != 0 {
		t.Fatalf("bounded refunds left count %d", entry.msgCount)
	}

	srv := hardeningLivechatServer(t, ServerConfig{})
	srv.teardown("missing")
	srv.finalize("missing")
	if got := srv.lookup("missing"); got != nil {
		t.Fatalf("missing session appeared after cleanup: %+v", got)
	}
}
