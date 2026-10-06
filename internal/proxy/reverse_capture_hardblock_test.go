// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestReverseCaptureReflectsCriticalHardBlock pins that the policy-replay
// record for a reverse URL or body finding carries the verdict the live proxy
// enforced. A critical credential is a hard block in enforce mode whatever
// request_body_scanning.action says; the record used to keep the configured
// warn action, so a replay saw a warning where the client got a 403.
//
// Audit mode (enforce: false) still blocks the core credential floor, so the
// audit rows assert the same blocked verdict as the enforce rows.
func TestReverseCaptureReflectsCriticalHardBlock(t *testing.T) {
	tests := []struct {
		name        string
		subsurface  string
		method      string
		target      string
		body        string
		enforce     bool
		wantStatus  int
		wantAction  string
		wantOutcome string
	}{
		{"url enforce", "dlp_reverse_url", http.MethodGet, "/x?token=" + reverseCriticalFloorKey(), "", true, http.StatusForbidden, config.ActionBlock, capture.OutcomeBlocked},
		{"url audit still blocks core floor", "dlp_reverse_url", http.MethodGet, "/x?token=" + reverseCriticalFloorKey(), "", false, http.StatusForbidden, config.ActionBlock, capture.OutcomeBlocked},
		{"body enforce", "dlp_reverse_request", http.MethodPost, "/x", `{"k":"` + reverseCriticalFloorKey() + `"}`, true, http.StatusForbidden, config.ActionBlock, capture.OutcomeBlocked},
		{"body audit still blocks core floor", "dlp_reverse_request", http.MethodPost, "/x", `{"k":"` + reverseCriticalFloorKey() + `"}`, false, http.StatusForbidden, config.ActionBlock, capture.OutcomeBlocked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := captureMetadataConfig()
			cfg.CrossRequestDetection.Enabled = false
			cfg.Taint.Enabled = false
			cfg.RequestBodyScanning.Action = config.ActionWarn
			enforce := tt.enforce
			cfg.Enforce = &enforce

			obs := newReverseDLPRecordObserver()
			rp := newCaptureMetadataReverseProxy(t, cfg, audit.NewNop(), obs, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("ok"))
			})

			var req *http.Request
			if tt.body == "" {
				req = newReverseCaptureRequest(t, tt.method, tt.target, nil)
			} else {
				req = newReverseCaptureRequest(t, tt.method, tt.target, strings.NewReader(tt.body))
				req.Header.Set("Content-Type", "application/json")
			}
			rec := serveReverseCaptureRequest(rp, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}

			got := waitReverseDLPRecord(t, obs, tt.subsurface)
			if got.EffectiveAction != tt.wantAction || got.Outcome != tt.wantOutcome {
				t.Fatalf("capture effective=%s outcome=%s, want effective=%s outcome=%s",
					got.EffectiveAction, got.Outcome, tt.wantAction, tt.wantOutcome)
			}
		})
	}
}

func newReverseCaptureRequest(t *testing.T, method, target string, body *strings.Reader) *http.Request {
	t.Helper()
	if body == nil {
		return httptest.NewRequestWithContext(t.Context(), method, target, http.NoBody)
	}
	return httptest.NewRequestWithContext(t.Context(), method, target, body)
}

func serveReverseCaptureRequest(rp *ReverseProxyHandler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)
	return rec
}
