// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestWebSocketAdmissionReceiptReachesHandshake(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(io.Discard, conn)
	}))
	t.Cleanup(upstream.Close)
	backendAddr := strings.TrimPrefix(upstream.URL, "http://")
	for _, tc := range []struct {
		name     string
		required bool
		fail     bool
	}{
		{name: "required", required: true},
		{name: "best effort"},
		{name: "required write refused", required: true, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rph := newReceiptProxyHelper(t)
			proxyAddr, cleanup := setupWSProxyWithReceipts(t, rph, func(cfg *config.Config) {
				cfg.FlightRecorder.RequireReceipts = tc.required
			})
			t.Cleanup(cleanup)
			if tc.fail {
				if err := rph.rec.Close(); err != nil {
					t.Fatalf("close receipt writer: %v", err)
				}
			}
			spoofed := "0190a3c4-1234-7abc-89ab-0123456789ab"
			response := requestWSHandshake(t, proxyAddr, backendAddr, http.Header{
				blockreason.HeaderRecordedReceipt: []string{spoofed},
			})
			t.Cleanup(func() { _ = response.Body.Close() })
			id := response.Header.Get(blockreason.HeaderRecordedReceipt)
			if tc.fail {
				if response.StatusCode == http.StatusSwitchingProtocols || id != "" {
					t.Fatalf("failed receipt write returned status=%d receipt=%q", response.StatusCode, id)
				}
				return
			}
			if response.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("handshake status=%d, want 101", response.StatusCode)
			}
			if !tc.required {
				if id != "" {
					t.Fatalf("best-effort upgrade returned unconfirmed receipt %q", id)
				}
				return
			}
			if id == "" || id == spoofed {
				t.Fatalf("101 response receipt=%q, want the recorded proxy admission id", id)
			}
			requireSignedRecordedReceipt(t, rph, rph.findReceipts(t), id)
		})
	}
}
