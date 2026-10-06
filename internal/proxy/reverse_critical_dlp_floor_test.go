// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// reverseCriticalFloorKey builds an AWS access key shape at runtime so this
// file's own source does not trip DLP.
func reverseCriticalFloorKey() string { return "AKIA" + "IOSFODNN7EXAMPLE" }

// TestReverseCriticalDLPHardBlocksEverySurface pins the critical-credential
// floor on the reverse proxy. The balanced preset runs request_body_scanning in
// warn mode, and the floor is what keeps a critical credential from leaving
// anyway: /fetch, the forward proxy, CONNECT interception, WebSocket and the
// reverse proxy's own body and header scans all hard-block it in enforce mode.
// The reverse proxy's URL path and query scan did not, so the same key a
// /fetch refused was forwarded upstream.
//
// The audit rows pin the contract that audit mode (enforce: false) still
// blocks the core credential floor on every one of these surfaces, whatever
// request_body_scanning.action says. Only ordinary findings are observed and
// forwarded in audit mode.
func TestReverseCriticalDLPHardBlocksEverySurface(t *testing.T) {
	type surface struct {
		name  string
		build func(key string) (target string, header http.Header)
	}
	surfaces := []surface{
		{"query", func(k string) (string, http.Header) { return "http://reverse.example/x?token=" + k, nil }},
		{"path", func(k string) (string, http.Header) { return "http://reverse.example/p/" + k, nil }},
		{"header", func(k string) (string, http.Header) {
			return "http://reverse.example/x", http.Header{"Authorization": []string{"Bearer " + k}}
		}},
	}
	tests := []struct {
		name        string
		action      string
		enforce     bool
		wantBlocked bool
	}{
		{"warn action, enforce", config.ActionWarn, true, true},
		{"block action, enforce", config.ActionBlock, true, true},
		{"warn action, audit still blocks core floor", config.ActionWarn, false, true},
		{"block action, audit still blocks core floor", config.ActionBlock, false, true},
	}
	for _, tt := range tests {
		for _, sf := range surfaces {
			t.Run(tt.name+"/"+sf.name, func(t *testing.T) {
				cfg := reverseParityBaseConfig(t)
				cfg.CrossRequestDetection.Enabled = false
				cfg.Taint.Enabled = false
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.Action = tt.action
				enforce := tt.enforce
				cfg.Enforce = &enforce

				var upstreamCalls atomic.Int32
				rp, _, _ := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
					upstreamCalls.Add(1)
					_, _ = w.Write([]byte("ok"))
				})

				target, hdr := sf.build(reverseCriticalFloorKey())
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
				req.RemoteAddr = "10.0.0.41:9000"
				for k, v := range hdr {
					req.Header[k] = v
				}
				rec := httptest.NewRecorder()
				rp.ServeHTTP(rec, req)

				if tt.wantBlocked {
					if rec.Code != http.StatusForbidden {
						t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
					}
					if got := upstreamCalls.Load(); got != 0 {
						t.Fatalf("blocked request reached upstream %d times, want 0", got)
					}
					if got := rec.Header().Get(blockreason.HeaderReason); got != string(blockreason.DLPMatch) {
						t.Fatalf("%s = %q, want %q", blockreason.HeaderReason, got, blockreason.DLPMatch)
					}
					return
				}
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
				}
				if got := upstreamCalls.Load(); got != 1 {
					t.Fatalf("request reached upstream %d times, want 1", got)
				}
			})
		}
	}
}

// TestReverseHardBlocksScoreAdaptiveOnce pins that every enforced reverse
// request hard block lands in the adaptive score, on the body path as well as
// the URL path. A body DLP block used to return before any session signal was
// recorded, so a caller refused on every request never escalated.
//
// Each case uses a fresh client so the one-score-per-identical-denial dedup
// cannot hide a missing signal behind an earlier block.
func TestReverseHardBlocksScoreAdaptiveOnce(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		target  string
		body    string
		enforce bool
		want    float64
	}{
		{"url floor under warn action", http.MethodGet, "http://reverse.example/x?k=", "", true, session.SignalPoints[session.SignalBlock]},
		{"body floor under warn action", http.MethodPost, "http://reverse.example/x", "k=", true, session.SignalPoints[session.SignalBlock]},
		{"body floor, audit mode still blocks the core floor and scores a block", http.MethodPost, "http://reverse.example/x", "k=", false, session.SignalPoints[session.SignalBlock]},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := reverseParityBaseConfig(t)
			cfg.CrossRequestDetection.Enabled = false
			cfg.Taint.Enabled = false
			cfg.SessionProfiling.Enabled = true
			cfg.SessionProfiling.MaxSessions = 1000
			cfg.SessionProfiling.DomainBurst = 100
			cfg.SessionProfiling.WindowMinutes = 5
			cfg.SessionProfiling.SessionTTLMinutes = 30
			cfg.SessionProfiling.CleanupIntervalSeconds = 600
			cfg.AdaptiveEnforcement.Enabled = true
			cfg.AdaptiveEnforcement.EscalationThreshold = 50
			cfg.RequestBodyScanning.Enabled = true
			cfg.RequestBodyScanning.Action = config.ActionWarn
			enforce := tt.enforce
			cfg.Enforce = &enforce

			rp, p, upstreamURL := newReverseParityHarness(t, cfg, nil)
			clientHost := fmt.Sprintf("10.0.1.%d", i+1)
			key := reverseCriticalFloorKey()
			var body []byte
			if tt.body != "" {
				body = []byte(tt.body + key)
			}
			target := tt.target
			if tt.body == "" {
				target += key
			}
			rec := reverseParityRequest(t, rp, tt.method, target, clientHost+":9000", body)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
			}

			sm := p.SessionMgrPtr().Load()
			if sm == nil {
				t.Fatal("session manager not initialized")
			}
			sess := sm.GetOrCreate(sessionKeyFor("", clientHost, envelope.ActorAuthUnknown))
			got := sess.ScopedThreatScore(adaptiveScopeForHost(upstreamURL.Hostname()))
			if got != tt.want {
				t.Fatalf("scoped threat score = %.2f, want %.2f", got, tt.want)
			}
		})
	}
}
