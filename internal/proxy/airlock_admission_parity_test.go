// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	airlockAdmissionClient = "192.0.2.77"
	airlockHeaderMarker    = "AIRLOCKHEADERFINDING"
	airlockResponseMarker  = "RESPONSE_SCOPE_MARKER"
)

func airlockAdmissionConfig(t *testing.T, tier string) *config.Config {
	t.Helper()
	cfg := reverseParityBaseConfig(t)
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "airlock header marker", Regex: airlockHeaderMarker})
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.MaxSessions = 100
	cfg.SessionProfiling.DomainBurst = 100
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.SessionProfiling.SessionTTLMinutes = 30
	cfg.SessionProfiling.CleanupIntervalSeconds = 300
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = 1
	cfg.AdaptiveEnforcement.DecayPerCleanRequest = 0
	cfg.AdaptiveEnforcement.Levels.Elevated = config.EscalationActions{}
	cfg.AdaptiveEnforcement.Levels.High = config.EscalationActions{}
	cfg.AdaptiveEnforcement.Levels.Critical = config.EscalationActions{}
	cfg.Airlock.Enabled = true
	cfg.Airlock.Triggers.OnElevated = tier
	cfg.Airlock.Triggers.OnHigh = tier
	cfg.Airlock.Triggers.OnCritical = tier
	cfg.Taint.Enabled = false
	cfg.CrossRequestDetection.Enabled = false
	return cfg
}

func TestAirlockAdmissionAfterHeaderFinding(t *testing.T) {
	for _, tc := range []struct {
		name, transport, method, trigger, initial string
		finding                                   bool
		want                                      int
	}{
		{"forward drain", TransportForward, http.MethodPost, config.AirlockTierDrain, "", true, http.StatusForbidden},
		{"fetch drain", TransportFetch, http.MethodGet, config.AirlockTierDrain, "", true, http.StatusForbidden},
		{"reverse drain", TransportReverse, http.MethodPost, config.AirlockTierDrain, "", true, http.StatusForbidden},
		{"forward control", TransportForward, http.MethodPost, config.AirlockTierNone, "", true, http.StatusOK},
		{"fetch control", TransportFetch, http.MethodGet, config.AirlockTierNone, "", true, http.StatusOK},
		{"reverse control", TransportReverse, http.MethodPost, config.AirlockTierNone, "", true, http.StatusOK},
		{"reverse hard read", TransportReverse, http.MethodGet, config.AirlockTierNone, config.AirlockTierHard, false, http.StatusOK},
		{"reverse hard write", TransportReverse, http.MethodPost, config.AirlockTierNone, config.AirlockTierHard, false, http.StatusForbidden},
		{"reverse existing drain", TransportReverse, http.MethodGet, config.AirlockTierNone, config.AirlockTierDrain, false, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			rp, p, upstream := newReverseParityHarness(t, airlockAdmissionConfig(t, tc.trigger), func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = fmt.Fprint(w, "upstream-control")
			})
			if tc.initial != "" {
				sess := p.sessionMgrPtr.Load().GetOrCreate(airlockAdmissionClient)
				_, _, _ = sess.AirlockForScope(adaptiveScopeForHost(upstream.Hostname())).SetTier(tc.initial)
			}
			target := upstream.String() + "/control"
			if tc.transport == TransportFetch {
				target = "http://proxy.example/fetch?url=" + url.QueryEscape(target)
			}
			req := httptest.NewRequestWithContext(t.Context(), tc.method, target, nil)
			req.RemoteAddr = airlockAdmissionClient + ":12345"
			if tc.finding {
				req.Header.Set("Authorization", "Bearer "+airlockHeaderMarker)
			}
			w := httptest.NewRecorder()
			switch tc.transport {
			case TransportForward:
				p.handleForwardHTTP(w, req)
			case TransportFetch:
				p.handleFetch(w, req)
			case TransportReverse:
				rp.ServeHTTP(w, req)
			}
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d upstream_calls=%d body=%s", w.Code, tc.want, calls.Load(), w.Body.String())
			}
			if tc.want == http.StatusForbidden {
				if calls.Load() != 0 || w.Header().Get(blockreason.HeaderReason) != string(blockreason.AirlockActive) {
					t.Fatalf("denial must be airlock before upstream: calls=%d reason=%q", calls.Load(), w.Header().Get(blockreason.HeaderReason))
				}
			} else if calls.Load() != 1 || !strings.Contains(w.Body.String(), "upstream-control") {
				t.Fatalf("positive control did not reach upstream: calls=%d body=%s", calls.Load(), w.Body.String())
			}
		})
	}
}

func TestAirlockResponseSignalUsesFinalOrigin(t *testing.T) {
	for _, transport := range []string{TransportForward, TransportFetch} {
		t.Run(transport, func(t *testing.T) {
			var calls atomic.Int32
			final := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "text/plain")
				_, _ = fmt.Fprint(w, "ordinary text "+airlockResponseMarker+" ordinary text")
			}))
			if err := final.Listener.Close(); err != nil {
				t.Fatalf("close default fixture listener: %v", err)
			}
			listenConfig := net.ListenConfig{}
			listener, err := listenConfig.Listen(t.Context(), "tcp4", "127.0.0.2:0")
			if err != nil {
				t.Fatalf("listen on second loopback origin: %v", err)
			}
			final.Listener = listener
			final.Start()
			defer final.Close()
			finalURL := final.URL
			cfg := airlockAdmissionConfig(t, config.AirlockTierDrain)
			cfg.ResponseScanning.Enabled = true
			cfg.ResponseScanning.Action = config.ActionStrip
			cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "airlock response marker", Regex: airlockResponseMarker}}
			_, p, redirect := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, finalURL+"/result", http.StatusFound)
			})
			target := redirect.String() + "/start"
			if transport == TransportFetch {
				target = "http://proxy.example/fetch?url=" + url.QueryEscape(target)
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			req.RemoteAddr = airlockAdmissionClient + ":12345"
			w := httptest.NewRecorder()
			if transport == TransportFetch {
				p.handleFetch(w, req)
			} else {
				p.handleForwardHTTP(w, req)
			}
			if w.Code != http.StatusOK || calls.Load() != 1 || strings.Contains(w.Body.String(), airlockResponseMarker) || !strings.Contains(w.Body.String(), "ordinary text") {
				t.Fatalf("response control failed: status=%d calls=%d body=%s", w.Code, calls.Load(), w.Body.String())
			}
			sess := p.sessionMgrPtr.Load().GetOrCreate(airlockAdmissionClient)
			if got := airlockTierForScope(sess, adaptiveScopeForHost("127.0.0.2")); got != config.AirlockTierDrain {
				t.Fatalf("final response origin tier=%q, want drain", got)
			}
			if got := airlockTierForScope(sess, adaptiveScopeForHost(redirect.Hostname())); got != config.AirlockTierNone {
				t.Fatalf("redirecting origin tier=%q, want none", got)
			}
		})
	}
}

func TestAirlockCleanRecoveryUsesFinalOrigin(t *testing.T) {
	for _, transport := range []string{TransportForward, TransportFetch} {
		for _, redirected := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/redirect=%t", transport, redirected), func(t *testing.T) {
				var calls atomic.Int32
				final := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					w.Header().Set("Content-Type", "text/plain")
					_, _ = fmt.Fprint(w, "ordinary clean response")
				}))
				if err := final.Listener.Close(); err != nil {
					t.Fatal(err)
				}
				listenConfig := net.ListenConfig{}
				listener, err := listenConfig.Listen(t.Context(), "tcp4", "127.0.0.2:0")
				if err != nil {
					t.Fatal(err)
				}
				final.Listener = listener
				final.Start()
				defer final.Close()
				cfg := airlockAdmissionConfig(t, config.AirlockTierSoft)
				cfg.AdaptiveEnforcement.EscalationThreshold = 3
				cfg.AdaptiveEnforcement.CleanRequestsToDeescalate = 1
				cfg.AdaptiveEnforcement.DecayPerCleanRequest = 1
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "airlock response marker", Regex: airlockResponseMarker}}
				_, p, redirect := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, final.URL+"/result", http.StatusFound)
				})
				sess := p.sessionMgrPtr.Load().GetOrCreate(airlockAdmissionClient)
				finalScope := adaptiveScopeForHost("127.0.0.2")
				originalScope := adaptiveScopeForHost(redirect.Hostname())
				for _, scope := range []string{originalScope, finalScope} {
					recordAdaptiveSignalForScope(sess, scope, session.SignalBlock, &cfg.AdaptiveEnforcement, &cfg.Airlock, decide.EscalationParams{Threshold: 3})
					if sess.EffectiveEscalationLevel(scope) != 1 {
						t.Fatal("fixture did not establish elevated state")
					}
				}
				target := final.URL + "/result"
				if redirected {
					target = redirect.String() + "/start"
				}
				if transport == TransportFetch {
					target = "http://proxy.example/fetch?url=" + url.QueryEscape(target)
				}
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
				req.RemoteAddr = airlockAdmissionClient + ":12345"
				w := httptest.NewRecorder()
				if transport == TransportFetch {
					p.handleFetch(w, req)
				} else {
					p.handleForwardHTTP(w, req)
				}
				if w.Code != http.StatusOK || calls.Load() != 1 || !strings.Contains(w.Body.String(), "ordinary clean response") {
					t.Fatalf("clean response control failed: status=%d calls=%d body=%s", w.Code, calls.Load(), w.Body.String())
				}
				if got := sess.EffectiveEscalationLevel(finalScope); got != 0 {
					t.Errorf("final response scope level=%d, want normal", got)
				}
				if got := sess.EffectiveEscalationLevel(originalScope); got != 1 {
					t.Errorf("unrelated redirecting scope level=%d, want unchanged elevated", got)
				}
			})
		}
	}
}
