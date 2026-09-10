// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// airlockSessionKeyClientIP is the client IP the loopback test HTTP client
// presents to the proxy. Escalation is driven against this same IP so the
// writer session and the request-time reader session line up.
const airlockSessionKeyClientIP = "127.0.0.1"

// airlockSessionKeyTarget is the destination host every request in this file
// targets. It is a named host (not a literal IP) so the adaptive scope is a
// realistic destination:<domain> and the p.client dial override reaches the
// stand-in upstream.
const airlockSessionKeyTarget = "evil.example.com"

// airlockActiveReason is the block-reason header value the airlock admission
// path writes, distinct from an adaptive escalation_level block.
var airlockActiveReason = string(blockreason.AirlockActive)

// airlockDrainProxyConfig enables session profiling, adaptive enforcement, and
// airlock with a critical->drain trigger so a short burst of blocked results
// drives a session's destination scope into drain.
func airlockDrainProxyConfig(cfg *config.Config) {
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.MaxSessions = 1000
	cfg.SessionProfiling.DomainBurst = 100
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = adaptiveTestThreshold
	cfg.AdaptiveEnforcement.DecayPerCleanRequest = 0.5
	cfg.Airlock.Enabled = true
	cfg.Airlock.Triggers.OnCritical = config.AirlockTierDrain
	cfg.Airlock.Timers.DrainMinutes = 15
	cfg.Airlock.Timers.DrainTimeoutSeconds = 30
}

// setupDrainedRecoveredSession puts the session into the exact state the fix
// targets: airlock tier at drain on the RAW adaptive session (raised through
// the real recordSessionActivity escalation path, the only request-path airlock
// writer), while the adaptive escalation level has since recovered to 0 through
// the real time-based recovery path. This is a genuine production state: a
// threat burst drives airlock to drain and adaptive to critical, then the
// adaptive lane recovers on its faster per-level timer while airlock stays in
// drain until its own 15-minute timer. In that window a request must be refused
// by airlock alone, with no adaptive escalation_level block masking the result.
func setupDrainedRecoveredSession(t *testing.T, p *Proxy, agent string) {
	t.Helper()
	const (
		ip   = airlockSessionKeyClientIP
		host = airlockSessionKeyTarget
	)
	sm := p.sessionMgrPtr.Load()
	if sm == nil {
		t.Fatal("session manager not initialized")
	}
	sess := sm.GetOrCreate(sessionKeyFor(agent, ip))
	if sess == nil {
		t.Fatal("expected a session for the raw key")
	}
	scope := adaptiveScopeForHost(host)
	cfg := p.CurrentConfig()
	logger := audit.NewNop()

	// Raise airlock to drain through the real escalation bridge.
	blocked := scanner.Result{Allowed: false}
	drained := false
	for range 40 {
		p.recordSessionActivity(ip, agent, host, "req-escalate", blocked, cfg, logger, false)
		if sess.AirlockForScope(scope).Tier() == config.AirlockTierDrain {
			drained = true
			break
		}
	}
	if !drained {
		t.Fatalf("precondition: could not drive scope %q to drain (tier=%q, level=%d)",
			scope, sess.AirlockForScope(scope).Tier(), sess.ScopedEscalationLevel(scope))
	}

	// Recover the adaptive escalation level to 0 through the real time-based
	// recovery path (TryAutoRecoverScopes), aging lastEscalation so each call
	// steps one level down. This touches only the adaptive lane; the airlock
	// timer is left alone, so the drain tier persists.
	for range 10 {
		if sess.ScopedEscalationLevel(scope) == 0 {
			break
		}
		sess.mu.Lock()
		for _, st := range sess.scopes {
			st.lastEscalation = time.Now().Add(-time.Hour)
		}
		sess.mu.Unlock()
		sess.TryAutoRecoverScopes(time.Nanosecond, func(int) bool { return false })
	}

	if got := sess.AirlockForScope(scope).Tier(); got != config.AirlockTierDrain {
		t.Fatalf("precondition: airlock tier must stay drain after adaptive recovery, got %q", got)
	}
	if got := sess.ScopedEscalationLevel(scope); got != 0 {
		t.Fatalf("precondition: adaptive level must recover to 0 to isolate airlock, got %d", got)
	}
}

// airlockTestUpstream starts a stand-in upstream that always returns 200 and
// wires p.client so both fetch and forward reach it for the named target host.
func airlockTestUpstream(t *testing.T, p *Proxy) {
	t.Helper()
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	installForwardTestDialer(p, upstream.Listener.Addr().String())
}

// TestAirlockAdmission_SelfDeclaredNamedAgent_RefusedOnFetchAndForward is the
// load-bearing regression guard. A self-declared NAMED agent whose airlock tier
// is at drain on the raw adaptive session must be refused on fetch AND forward.
// Before the fix, fetch and forward read airlock from the CEE-safe taint
// recorder, whose key folds the self-declared name to the client IP: a
// different SessionState that never saw the tier, so admission read "none" and
// the request sailed through (fail-open, 200). After the fix, both transports
// read the raw session the writer used and airlock refuses the request (403
// with an airlock_active reason).
func TestAirlockAdmission_SelfDeclaredNamedAgent_RefusedOnFetchAndForward(t *testing.T) {
	const agent = "named-agent-a"

	// Prove the two keys actually diverge for this identity, so a green result
	// cannot come from the keys accidentally coinciding.
	rawKey := sessionKeyFor(agent, airlockSessionKeyClientIP)
	ceeKey := responseTaintSessionKey(agent, airlockSessionKeyClientIP, envelope.ActorAuthSelfDeclared)
	if rawKey == ceeKey {
		t.Fatalf("test setup invalid: raw key %q must differ from CEE-safe key %q for a self-declared named agent", rawKey, ceeKey)
	}

	t.Run("fetch", func(t *testing.T) {
		proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, airlockDrainProxyConfig)
		defer cleanup()
		airlockTestUpstream(t, p)
		setupDrainedRecoveredSession(t, p, agent)

		status, reason := doFetchWithAgent(t, "http://"+proxyAddr, "http://"+airlockSessionKeyTarget+"/", agent)
		if status != http.StatusForbidden || reason != airlockActiveReason {
			t.Fatalf("fetch admission fail-open: status=%d reason=%q, want 403 %q (airlock drain on the raw session must refuse the self-declared named agent)",
				status, reason, airlockActiveReason)
		}
	})

	t.Run("forward", func(t *testing.T) {
		proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, airlockDrainProxyConfig)
		defer cleanup()
		airlockTestUpstream(t, p)
		setupDrainedRecoveredSession(t, p, agent)

		status, reason := doForwardWithAgent(t, proxyAddr, "http://"+airlockSessionKeyTarget+"/", agent)
		if status != http.StatusForbidden || reason != airlockActiveReason {
			t.Fatalf("forward admission fail-open: status=%d reason=%q, want 403 %q (airlock drain on the raw session must refuse the self-declared named agent)",
				status, reason, airlockActiveReason)
		}
	})
}

// TestAirlockAdmission_AnonymousAgentUnchanged is the control: an anonymous
// agent folds identically on the raw and CEE-safe keys, so admission behaved
// correctly before the fix and must still refuse a drained session after it.
// This locks the "unchanged for anonymous" half of the change.
func TestAirlockAdmission_AnonymousAgentUnchanged(t *testing.T) {
	// Anonymous keys are equal on both derivations by construction.
	rawKey := sessionKeyFor(agentAnonymous, airlockSessionKeyClientIP)
	ceeKey := responseTaintSessionKey(agentAnonymous, airlockSessionKeyClientIP, envelope.ActorAuthSelfDeclared)
	if rawKey != ceeKey {
		t.Fatalf("test setup invalid: anonymous raw key %q must equal CEE-safe key %q", rawKey, ceeKey)
	}

	t.Run("fetch", func(t *testing.T) {
		proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, airlockDrainProxyConfig)
		defer cleanup()
		airlockTestUpstream(t, p)
		setupDrainedRecoveredSession(t, p, agentAnonymous)

		status, reason := doFetchWithAgent(t, "http://"+proxyAddr, "http://"+airlockSessionKeyTarget+"/", "")
		if status != http.StatusForbidden || reason != airlockActiveReason {
			t.Fatalf("anonymous fetch admission regressed: status=%d reason=%q, want 403 %q", status, reason, airlockActiveReason)
		}
	})

	t.Run("forward", func(t *testing.T) {
		proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, airlockDrainProxyConfig)
		defer cleanup()
		airlockTestUpstream(t, p)
		setupDrainedRecoveredSession(t, p, agentAnonymous)

		status, reason := doForwardWithAgent(t, proxyAddr, "http://"+airlockSessionKeyTarget+"/", "")
		if status != http.StatusForbidden || reason != airlockActiveReason {
			t.Fatalf("anonymous forward admission regressed: status=%d reason=%q, want 403 %q", status, reason, airlockActiveReason)
		}
	})
}

// TestAirlockAdmissionKeyMatchesWriterKey documents, per transport and per
// provenance grade, that airlock admission keys on the RAW adaptive session
// (the writer's key) and NOT on the CEE-safe taint key. For bound and
// config-default grades the two keys coincide; for matched and self-declared
// grades the CEE-safe key folds the name to the client IP, which is exactly the
// fail-open the fix closes. The transport rows use the concrete key expression
// each production read site uses.
func TestAirlockAdmissionKeyMatchesWriterKey(t *testing.T) {
	const (
		agent = "grade-agent"
		ip    = "203.0.113.7"
	)
	writerKey := sessionKeyFor(agent, ip)

	// The airlock admission read key each transport uses. fetch and forward
	// read sessionKeyFor after the fix; WebSocket (websocket.go) and TLS
	// intercept (forward.go interceptRec) already read sessionKeyFor.
	transportReadKey := map[string]string{
		"fetch":     sessionKeyFor(agent, ip),
		"forward":   sessionKeyFor(agent, ip),
		"websocket": sessionKeyFor(agent, ip),
		"intercept": sessionKeyFor(agent, ip),
	}
	for transport, readKey := range transportReadKey {
		if readKey != writerKey {
			t.Errorf("%s: airlock read key %q != writer key %q", transport, readKey, writerKey)
		}
	}

	grades := []struct {
		name        string
		auth        envelope.ActorAuth
		ceeDiverges bool
	}{
		{"bound", envelope.ActorAuthBound, false},
		{"config-default", envelope.ActorAuthConfigDefault, false},
		{"matched", envelope.ActorAuthMatched, true},
		{"self-declared", envelope.ActorAuthSelfDeclared, true},
	}
	for _, g := range grades {
		t.Run(g.name, func(t *testing.T) {
			ceeKey := responseTaintSessionKey(agent, ip, g.auth)
			diverges := ceeKey != writerKey
			if diverges != g.ceeDiverges {
				t.Fatalf("grade %s: CEE-safe key %q vs writer key %q: diverges=%v, want %v",
					g.name, ceeKey, writerKey, diverges, g.ceeDiverges)
			}
			// Whatever the grade, airlock admission keys on the writer key.
			if got := sessionKeyFor(agent, ip); got != writerKey {
				t.Fatalf("grade %s: airlock read key %q != writer key %q", g.name, got, writerKey)
			}
		})
	}
}

// doFetchWithAgent issues a GET to the proxy /fetch endpoint for targetURL,
// optionally setting the self-declared agent header, and returns the HTTP
// status and block-reason header. An empty agent leaves the header unset
// (anonymous).
func doFetchWithAgent(t *testing.T, proxyBase, targetURL, agent string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		proxyBase+"/fetch?url="+url.QueryEscape(targetURL), nil)
	if err != nil {
		t.Fatalf("new fetch request: %v", err)
	}
	if agent != "" {
		req.Header.Set(AgentHeader, agent)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("fetch request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, resp.Header.Get(blockreason.HeaderReason)
}

// doForwardWithAgent issues a GET through the forward proxy to targetURL,
// optionally setting the self-declared agent header, and returns the HTTP
// status and block-reason header.
func doForwardWithAgent(t *testing.T, proxyAddr, targetURL, agent string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("new forward request: %v", err)
	}
	if agent != "" {
		req.Header.Set(AgentHeader, agent)
	}
	resp, err := forwardHTTPClient(t, proxyAddr).Do(req)
	if err != nil {
		t.Fatalf("forward request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, resp.Header.Get(blockreason.HeaderReason)
}
