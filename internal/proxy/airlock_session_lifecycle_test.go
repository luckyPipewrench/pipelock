// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

type airlockLogCallback func([]byte)

func (f airlockLogCallback) Write(p []byte) (int, error) {
	f(p)
	return len(p), nil
}

func TestAirlockAdmissionSessionReplacement(t *testing.T) {
	for _, transport := range []string{TransportForward, TransportFetch} {
		for _, replaceManager := range []bool{false, true} {
			for _, tc := range []struct {
				name, requestTier, currentTier string
				want                           int
			}{
				{"current quarantine", config.AirlockTierNone, config.AirlockTierDrain, http.StatusForbidden},
				{"request quarantine", config.AirlockTierDrain, config.AirlockTierNone, http.StatusForbidden},
				{"no quarantine", config.AirlockTierNone, config.AirlockTierNone, http.StatusOK},
			} {
				t.Run(fmt.Sprintf("%s/manager=%t/%s", transport, replaceManager, tc.name), func(t *testing.T) {
					cfg := airlockAdmissionConfig(t, tc.requestTier)
					cfg.SessionProfiling.MaxSessions = 1
					cfg.Airlock.Triggers.OnHigh = config.AirlockTierDrain
					var calls atomic.Int32
					_, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
						calls.Add(1)
						_, _ = fmt.Fprint(w, "upstream-control")
					})
					oldManager := p.sessionMgrPtr.Load()
					t.Cleanup(oldManager.Close)
					original := oldManager.GetOrCreate(airlockAdmissionClient)
					scope := adaptiveScopeForHost(upstream.Hostname())
					var replaced atomic.Bool
					logger, err := audit.NewWithStream("json", "stdout", "", true, true, airlockLogCallback(func(record []byte) {
						if !bytes.Contains(record, []byte(`"event":"`+string(audit.EventHeaderDLP)+`"`)) || !replaced.CompareAndSwap(false, true) {
							return
						}
						// The audit callback schedules competing activity after the
						// first admission but before the header signal is committed.
						currentManager := oldManager
						if replaceManager {
							currentManager = NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, p.metrics)
							currentManager.UpdateConfig(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, &cfg.Airlock)
							p.sessionMgrPtr.Store(currentManager)
						} else {
							currentManager.GetOrCreate("192.0.2.78")
						}
						current := currentManager.GetOrCreate(airlockAdmissionClient)
						if current == original {
							t.Error("replacement control retained the original session")
						}
						if tc.currentTier != config.AirlockTierNone {
							for range 2 {
								recordAdaptiveSignalForScope(current, scope, session.SignalNearMiss, &cfg.AdaptiveEnforcement, &cfg.Airlock, decide.EscalationParams{Threshold: 1})
							}
						}
						if got := airlockTierForScope(current, scope); got != tc.currentTier {
							t.Errorf("current session tier = %q, want %q", got, tc.currentTier)
						}
					}))
					if err != nil {
						t.Fatal(err)
					}
					p.logger = logger
					target := upstream.String() + "/control"
					if transport == TransportFetch {
						target = "http://proxy.example/fetch?url=" + url.QueryEscape(target)
					}
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
					req.RemoteAddr = airlockAdmissionClient + ":12345"
					req.Header.Set("Authorization", "Bearer "+airlockHeaderMarker)
					w := httptest.NewRecorder()
					if transport == TransportFetch {
						p.handleFetch(w, req)
					} else {
						p.handleForwardHTTP(w, req)
					}
					if !replaced.Load() {
						t.Fatal("header callback did not run")
					}
					if w.Code != tc.want {
						t.Fatalf("status=%d want=%d upstream_calls=%d body=%s", w.Code, tc.want, calls.Load(), w.Body.String())
					}
					if tc.want == http.StatusForbidden && calls.Load() != 0 {
						t.Fatalf("quarantined request reached upstream %d times", calls.Load())
					}
					if tc.want == http.StatusOK && (calls.Load() != 1 || !strings.Contains(w.Body.String(), "upstream-control")) {
						t.Fatalf("positive control failed: calls=%d body=%s", calls.Load(), w.Body.String())
					}
				})
			}
		}
	}
}

func TestScopedAirlockDelayedEdgePreservesStrongerTier(t *testing.T) {
	for _, scope := range []string{"", adaptiveScopeForHost(adaptiveScopePollHost)} {
		t.Run(scope, func(t *testing.T) {
			cfg := adaptiveScopedAirlockConfig()
			cfg.Airlock.Triggers.OnElevated = config.AirlockTierSoft
			cfg.Airlock.Triggers.OnHigh = config.AirlockTierDrain
			p, _ := newAdaptiveScopeProxy(t, cfg)
			sess := scopedSession(t, p)
			writer := airlockEdgeWriter(func() {
				recordAdaptiveSignalForScope(sess, scope, session.SignalBlock, &cfg.AdaptiveEnforcement, &cfg.Airlock, decide.EscalationParams{Threshold: 3})
				if got := sess.AirlockForScope(scope).Tier(); got != config.AirlockTierDrain {
					t.Fatalf("competing edge tier = %q, want drain", got)
				}
			})
			recordAdaptiveSignalForScope(sess, scope, session.SignalBlock, &cfg.AdaptiveEnforcement, &cfg.Airlock, decide.EscalationParams{Threshold: 3, ConsoleWriter: writer})
			if got := sess.AirlockForScope(scope).Tier(); got != config.AirlockTierDrain {
				t.Fatalf("delayed earlier edge weakened tier to %q", got)
			}
			trigger, source := sess.AirlockForScope(scope).EntryProvenance()
			if trigger != airlockTriggerOnHigh || source != airlockSourceTriggers {
				t.Fatalf("delayed edge changed provenance to %q/%q", trigger, source)
			}
		})
	}
}

func TestScopedAirlockSurvivesSessionEviction(t *testing.T) {
	for _, capacity := range []bool{false, true} {
		t.Run(fmt.Sprintf("capacity=%t", capacity), func(t *testing.T) {
			cfg := airlockAdmissionConfig(t, config.AirlockTierDrain)
			cfg.SessionProfiling.MaxSessions = 1
			sm := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, nil)
			t.Cleanup(sm.Close)
			sess := sm.GetOrCreate(airlockAdmissionClient)
			scope := adaptiveScopeForHost(adaptiveScopePollHost)
			_, _, _ = sess.AirlockForScope(scope).SetTier(config.AirlockTierDrain)
			sess.mu.Lock()
			sess.lastActivity = time.Now().Add(-time.Hour)
			sess.mu.Unlock()
			if capacity {
				sm.GetOrCreate("192.0.2.78")
			} else {
				sm.cleanup()
			}
			if sm.SessionByKey(airlockAdmissionClient) != sess {
				t.Fatal("session eviction removed destination quarantine")
			}
			_, _, _ = sess.ForceSetAirlockTierAllScopes(config.AirlockTierNone, airlockTriggerManual, airlockSourceAdminAPI)
			if capacity {
				sm.GetOrCreate("192.0.2.79")
			} else {
				sm.cleanup()
			}
			if sm.SessionByKey(airlockAdmissionClient) != nil {
				t.Fatal("released session did not become evictable")
			}
		})
	}
}
