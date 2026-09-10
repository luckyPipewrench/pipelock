// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/certgen"
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
	sess := sm.GetOrCreate(responseTaintSessionKey(agent, ip, envelope.ActorAuthSelfDeclared))
	profileSess := sm.GetOrCreate(sessionKeyFor(agent, ip))
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
		if profileSess.ScopedEscalationLevel(scope) == 0 {
			break
		}
		profileSess.mu.Lock()
		for _, st := range profileSess.scopes {
			st.lastEscalation = time.Now().Add(-time.Hour)
		}
		profileSess.mu.Unlock()
		profileSess.TryAutoRecoverScopes(time.Nanosecond, func(int) bool { return false })
	}

	if got := sess.AirlockForScope(scope).Tier(); got != config.AirlockTierDrain {
		t.Fatalf("precondition: airlock tier must stay drain after adaptive recovery, got %q", got)
	}
	if got := profileSess.ScopedEscalationLevel(scope); got != 0 {
		t.Fatalf("precondition: adaptive level must recover to 0 to isolate airlock, got %d", got)
	}
}

func setupForcedScopedDrain(t *testing.T, p *Proxy, agent, clientIP, host string) *SessionState {
	t.Helper()
	sm := p.sessionMgrPtr.Load()
	if sm == nil {
		t.Fatal("session manager not initialized")
	}
	sess := sm.GetOrCreate(responseTaintSessionKey(agent, clientIP, envelope.ActorAuthSelfDeclared))
	changed, _, to := sess.AirlockForScope(adaptiveScopeForHost(host)).ForceSetTierWithProvenance(
		config.AirlockTierDrain, airlockTriggerManual, airlockSourceAdminAPI,
	)
	if !changed || to != config.AirlockTierDrain {
		t.Fatalf("force scoped drain = changed:%v to:%q, want changed:true to:drain", changed, to)
	}
	return sess
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
// load-bearing regression guard. A self-declared caller cannot escape an
// airlock drain by rotating its request-supplied agent name: both names fold to
// the same source-bound enforcement session on fetch and forward.
func TestAirlockAdmission_SelfDeclaredNamedAgent_RefusedOnFetchAndForward(t *testing.T) {
	const (
		agent        = "named-agent-a"
		rotatedAgent = "named-agent-b"
	)

	t.Run("fetch", func(t *testing.T) {
		proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, airlockDrainProxyConfig)
		defer cleanup()
		airlockTestUpstream(t, p)
		setupDrainedRecoveredSession(t, p, agent)

		status, reason := doFetchWithAgent(t, "http://"+proxyAddr, "http://"+airlockSessionKeyTarget+"/", rotatedAgent)
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

		status, reason := doForwardWithAgent(t, proxyAddr, "http://"+airlockSessionKeyTarget+"/", rotatedAgent)
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

// TestAirlockAdmission_SelfDeclaredNamedAgent_RefusedOnConnect is the
// load-bearing regression guard for opaque (non-intercepted) CONNECT. A
// self-declared agent whose source-bound enforcement session is drained must be
// refused before the tunnel is dialed or hijacked.
func TestAirlockAdmission_SelfDeclaredNamedAgent_RefusedOnConnect(t *testing.T) {
	const agent = "named-agent-a"

	// airlockDrainProxyConfig leaves TLS interception off, so the target host
	// takes the opaque (non-intercepted) CONNECT path where the early airlock
	// admission runs. The airlock check answers before any dial, so no upstream
	// is needed.
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, airlockDrainProxyConfig)
	defer cleanup()
	setupForcedScopedDrain(t, p, agent, airlockSessionKeyClientIP, airlockSessionKeyTarget)

	status, reason := doConnectWithAgent(t, proxyAddr, airlockSessionKeyTarget+":443", agent)
	if status != http.StatusForbidden || reason != airlockActiveReason {
		t.Fatalf("CONNECT admission fail-open: status=%d reason=%q, want 403 %q (airlock drain on the raw session must refuse the self-declared named agent's opaque CONNECT)",
			status, reason, airlockActiveReason)
	}
}

// TestAirlockAdmission_SelfDeclaredNamedAgent_RefusedOnRedirect is the
// load-bearing regression guard for a redirect hop on both fetch and forward. A
// self-declared NAMED agent's initial request to a non-drained host is admitted;
// the upstream 302s to the drained target, and the redirect hop must refuse it.
// Before the fix, CheckRedirect read airlock from redirectRec - the CEE-safe
// taint recorder the originating handler stages - whose key folds the
// self-declared name to the client IP: a different SessionState that never saw
// the tier, so the redirect sailed through (fail-open, redirected egress
// occurs). After the fix, the originating handler also stages the raw airlock
// session in ctxKeyRedirectAirlockSession and the hop refuses it (403, no
// redirected egress).
func TestAirlockAdmission_SelfDeclaredNamedAgent_RefusedOnRedirect(t *testing.T) {
	const (
		agent = "named-agent-a"
		// initialHost is a non-drained scope the originating handler admits.
		// installForwardTestDialer already routes it to the test upstream.
		initialHost = "api.example.com"
	)

	// Prove the two keys diverge for this identity.
	rawKey := sessionKeyFor(agent, airlockSessionKeyClientIP)
	ceeKey := responseTaintSessionKey(agent, airlockSessionKeyClientIP, envelope.ActorAuthSelfDeclared)
	if rawKey == ceeKey {
		t.Fatalf("test setup invalid: raw key %q must differ from CEE-safe key %q for a self-declared named agent", rawKey, ceeKey)
	}

	// redirectBackend answers the initial host with a 302 to the drained target
	// and records any redirected egress to that target, which must never occur.
	redirectBackend := func(t *testing.T, initialHits, redirectedHits *atomic.Int32) string {
		t.Helper()
		backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host == airlockSessionKeyTarget {
				redirectedHits.Add(1)
				w.WriteHeader(http.StatusOK)
				return
			}
			initialHits.Add(1)
			http.Redirect(w, r, "http://"+airlockSessionKeyTarget+"/final", http.StatusFound)
		}))
		t.Cleanup(backend.Close)
		return backend.Listener.Addr().String()
	}

	t.Run("fetch", func(t *testing.T) {
		proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, airlockDrainProxyConfig)
		defer cleanup()
		var initialHits, redirectedHits atomic.Int32
		installForwardTestDialer(p, redirectBackend(t, &initialHits, &redirectedHits))
		setupDrainedRecoveredSession(t, p, agent)

		status, _ := doFetchWithAgent(t, "http://"+proxyAddr, "http://"+initialHost+"/", agent)
		if status != http.StatusForbidden {
			t.Fatalf("fetch redirect admission fail-open: status=%d, want 403 (airlock drain on the raw session must refuse the redirect hop to the drained target)", status)
		}
		if initialHits.Load() != 1 {
			t.Fatalf("initial upstream hits = %d, want 1", initialHits.Load())
		}
		if redirectedHits.Load() != 0 {
			t.Fatalf("redirected egress to the drained target = %d, want 0 (redirect hop failed open)", redirectedHits.Load())
		}
	})

	t.Run("forward", func(t *testing.T) {
		proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, airlockDrainProxyConfig)
		defer cleanup()
		var initialHits, redirectedHits atomic.Int32
		installForwardTestDialer(p, redirectBackend(t, &initialHits, &redirectedHits))
		setupDrainedRecoveredSession(t, p, agent)

		status, _ := doForwardWithAgent(t, proxyAddr, "http://"+initialHost+"/", agent)
		if status != http.StatusForbidden {
			t.Fatalf("forward redirect admission fail-open: status=%d, want 403 (airlock drain on the raw session must refuse the redirect hop to the drained target)", status)
		}
		if initialHits.Load() != 1 {
			t.Fatalf("initial upstream hits = %d, want 1", initialHits.Load())
		}
		if redirectedHits.Load() != 0 {
			t.Fatalf("redirected egress to the drained target = %d, want 0 (redirect hop failed open)", redirectedHits.Load())
		}
	})
}

// TestAirlockAdmissionKeyMatchesWriterKey verifies the shared production
// helper's trust-graded lookup contract. Transport behavior is covered by the
// functional fetch, forward, CONNECT, redirect, intercept, and WebSocket tests;
// this test does not duplicate their key expressions.
func TestAirlockAdmissionKeyMatchesWriterKey(t *testing.T) {
	const (
		agent = "grade-agent"
		ip    = "203.0.113.7"
	)
	p, _, _ := redirectPolicyTestProxy(t)
	sm := p.sessionMgrPtr.Load()
	if sess := p.airlockSessionForIdentity(agent, ip, envelope.ActorAuthSelfDeclared); sess != nil {
		t.Fatalf("lookup-only admission created a session: %+v", sess)
	}

	grades := []struct {
		name    string
		auth    envelope.ActorAuth
		wantKey string
	}{
		{"bound", envelope.ActorAuthBound, sessionKeyFor(agent, ip)},
		{"config-default", envelope.ActorAuthConfigDefault, sessionKeyFor(agent, ip)},
		{"matched", envelope.ActorAuthMatched, ip},
		{"self-declared", envelope.ActorAuthSelfDeclared, ip},
	}
	for _, g := range grades {
		t.Run(g.name, func(t *testing.T) {
			sm.GetOrCreate(g.wantKey)
			if got := p.airlockSessionForIdentity(agent, ip, g.auth); got == nil || got.key != g.wantKey {
				t.Fatalf("grade %s: admission session = %+v, want key %q", g.name, got, g.wantKey)
			}
		})
	}
}

// TestAirlockAdmission_TLSIntercept_RefusedOnScopedDrain is the load-bearing
// regression guard for the TLS-interception inner-request admission. When
// adaptive enforcement drives a session's DESTINATION scope to drain, the
// session-wide airlock tier stays none (AirlockForScope holds a distinct
// per-destination state). Before the fix, the intercept handler read the
// session-wide Airlock().Tier() and saw none, so every intercepted inner
// request to the drained destination was admitted (fail-open). After the fix
// it reads the scoped tier via airlockTierForScope, the same scoped read fetch,
// forward, opaque CONNECT, and WebSocket use, and refuses with 403.
func TestAirlockAdmission_TLSIntercept_RefusedOnScopedDrain(t *testing.T) {
	const (
		agent    = "named-agent-a"
		clientIP = airlockSessionKeyClientIP
		host     = airlockSessionKeyTarget
	)

	_, p, cleanup := setupForwardProxyWithInstance(t, airlockDrainProxyConfig)
	defer cleanup()

	sm := p.sessionMgrPtr.Load()
	if sm == nil {
		t.Fatal("session manager not initialized")
	}
	scope := adaptiveScopeForHost(host)

	// Put the session into airlock=drain on the destination scope with the
	// adaptive escalation level recovered to 0, so airlock is the ONLY blocker
	// and a fail-open is a genuine admission, not an adaptive block masking it.
	// This drives drain through the real escalation bridge (recordSessionActivity).
	setupDrainedRecoveredSession(t, p, agent)
	sess := sm.GetOrCreate(responseTaintSessionKey(agent, clientIP, envelope.ActorAuthSelfDeclared))
	if got := sess.AirlockForScope(scope).Tier(); got != config.AirlockTierDrain {
		t.Fatalf("precondition: scope %q tier = %q, want drain", scope, got)
	}

	// The crux of the fail-open: a scoped drain leaves the SESSION-WIDE tier at
	// none, so a global read admits the intercepted inner request.
	if got := sess.Airlock().Tier(); got != config.AirlockTierNone {
		t.Fatalf("precondition: session-wide airlock tier = %q, want none (a scoped drain must not raise the global tier)", got)
	}

	cfg := p.CurrentConfig()
	logger := audit.NewNop()
	icfg := cfg.Clone()
	icfg.TLSInterception.Enabled = true
	if icfg.TLSInterception.MaxResponseBytes == 0 {
		icfg.TLSInterception.MaxResponseBytes = 1 << 20
	}
	sc := scanner.MustNew(icfg)
	t.Cleanup(sc.Close)

	var upstreamCalls atomic.Int32
	rt := roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
		upstreamCalls.Add(1)
		rr := httptest.NewRecorder()
		rr.WriteHeader(http.StatusOK)
		return rr.Result(), nil
	})

	handler := newInterceptHandler(&InterceptContext{
		TargetHost: host,
		TargetPort: "443",
		Config:     icfg,
		Scanner:    sc,
		Logger:     logger,
		Metrics:    p.metrics,
		ClientIP:   clientIP,
		RequestID:  "req-intercept-airlock",
		Agent:      agent,
		SessionMgr: sm,
		Recorder:   sess,
		Redaction:  p.currentRedactionRuntimeFor(icfg),
		Proxy:      p,
		KillSwitch: p.ks,
	}, rt)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+host+":443/inner", nil)
	req.Host = host + ":443"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden || w.Header().Get(blockreason.HeaderReason) != airlockActiveReason {
		t.Fatalf("intercept admission fail-open: status=%d reason=%q, want 403 %q (a scoped drain on the raw session must refuse the intercepted inner request)",
			w.Code, w.Header().Get(blockreason.HeaderReason), airlockActiveReason)
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("intercepted egress to a drained destination = %d, want 0 (admission failed open)", upstreamCalls.Load())
	}
}

// airlockProbeHoldListener accepts one connection, reads a single relayed probe
// byte (signalling that the CONNECT relay - and therefore the airlock cancel
// registration that runs just before it - is live), then blocks holding the
// connection open until it is torn down. It never sends, so the client side of
// the tunnel only unblocks when the connection is closed.
func airlockProbeHoldListener(t *testing.T) (net.Listener, <-chan struct{}) {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	relayLive := make(chan struct{})
	var once sync.Once
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 1)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		once.Do(func() { close(relayLive) })
		// Hold the connection open until it is closed by the airlock cancel
		// (targetConn.Close) or test teardown; a blocking read returns then.
		_, _ = conn.Read(make([]byte, 1))
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln, relayLive
}

// TestAirlockCancel_ConnectTunnel_TornDownOnScopedEscalation is the load-bearing
// regression guard for opaque CONNECT tunnel teardown (ITEM 2, fail-open
// containment). A self-declared NAMED agent opens a tunnel while the destination
// scope is below the trigger, so the tunnel is admitted and its airlock cancel
// is registered. Adaptive enforcement then escalates the RAW session's scoped
// tier to drain. Before the fix, the cancel was registered on connectRec
// (ceeSessionKey), which folds the self-declared name to the client IP: a
// different SessionState than the one the writer transitions, so escalation
// never fired the cancel and the tunnel stayed open. After the fix the cancel is
// registered on the raw session (airlockSessionForIdentity) and escalation tears
// the tunnel down.
func TestAirlockCancel_ConnectTunnel_TornDownOnScopedEscalation(t *testing.T) {
	const (
		agent    = "named-agent-a"
		clientIP = airlockSessionKeyClientIP
	)

	// Prove the two keys diverge for this identity, so a green result cannot
	// come from the keys accidentally coinciding.
	rawKey := sessionKeyFor(agent, clientIP)
	ceeKey := responseTaintSessionKey(agent, clientIP, envelope.ActorAuthSelfDeclared)
	if rawKey == ceeKey {
		t.Fatalf("test setup invalid: raw key %q must differ from CEE-safe key %q for a self-declared named agent", rawKey, ceeKey)
	}

	target, relayLive := airlockProbeHoldListener(t)
	// The CONNECT target host is a loopback literal so the SSRF-safe tunnel
	// dialer reaches the stand-in target; the airlock scope is keyed on it.
	targetHost, _, err := net.SplitHostPort(target.Addr().String())
	if err != nil {
		t.Fatalf("split target addr: %v", err)
	}

	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(c *config.Config) {
		airlockDrainProxyConfig(c)
		// Keep idle/tunnel timers well above the test deadline so a torn-down
		// tunnel can only be attributed to the airlock cancel, not a timeout.
		c.ForwardProxy.IdleTimeoutSeconds = 60
		c.ForwardProxy.MaxTunnelSeconds = 120
	})
	defer cleanup()

	sm := p.sessionMgrPtr.Load()
	if sm == nil {
		t.Fatal("session manager not initialized")
	}
	sess := sm.GetOrCreate(responseTaintSessionKey(agent, clientIP, envelope.ActorAuthSelfDeclared))
	scope := adaptiveScopeForHost(targetHost)

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s: %s\r\n\r\n",
		target.Addr().String(), target.Addr().String(), AgentHeader, agent); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT setup status = %d, want 200 (tunnel must open before escalation)", resp.StatusCode)
	}

	// Send a probe byte and wait for the target to receive it. This proves the
	// relay is running, which means the airlock cancel is already registered
	// (registration runs immediately before the relay loop).
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("write tunnel probe: %v", err)
	}
	select {
	case <-relayLive:
	case <-time.After(5 * time.Second):
		t.Fatal("precondition: tunnel relay never delivered the probe byte")
	}

	// Escalate the RAW session's destination scope to drain through the real
	// bridge. This is the writer that transitions the tier and fires the
	// registered cancels on that scope's airlock.
	cfg := p.CurrentConfig()
	logger := audit.NewNop()
	drained := false
	for range 40 {
		p.recordSessionActivity(clientIP, agent, targetHost, "req-escalate", scanner.Result{Allowed: false}, cfg, logger, false)
		if sess.AirlockForScope(scope).Tier() == config.AirlockTierDrain {
			drained = true
			break
		}
	}
	if !drained {
		t.Fatalf("precondition: could not drive scope %q to drain (tier=%q)", scope, sess.AirlockForScope(scope).Tier())
	}

	// After the fix the cancel fires on escalation and closes both tunnel ends,
	// so the client read returns promptly. Before the fix the cancel sits on the
	// folded session, nothing fires, and the read blocks until the deadline.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, readErr := conn.Read(make([]byte, 1))
	elapsed := time.Since(start)
	if readErr == nil {
		t.Fatal("tunnel returned unexpected data; expected teardown on airlock drain")
	}
	var nerr net.Error
	if errors.As(readErr, &nerr) && nerr.Timeout() {
		t.Fatalf("airlock drain did not tear down the CONNECT tunnel within 5s (read err=%v after %s): the cancel is registered on the folded session, not the raw session the writer transitions", readErr, elapsed)
	}
}

// TestAirlockCancel_TLSInterceptTunnel_TornDownOnScopedDrain is the load-bearing
// regression guard for the TLS-interception tunnel teardown hook, the second
// cancel-registration site in handleConnect. It uses the immediate-fire property
// of RegisterCancel: with the destination scope already at drain, registering the
// intercept cancel on the RIGHT session fires it at once, cancelling the intercept
// context before the inner-request TLS handshake and tearing the tunnel down
// immediately. Interception bypasses the early opaque-CONNECT admission, so the
// tunnel still reaches the registration. Before the fix the cancel was registered
// on connectRec (the folded, undrained session), so nothing fired and the tunnel
// blocked on the 30s client handshake instead. After the fix it registers on the
// raw drained session and the tunnel is torn down at once.
func TestAirlockCancel_TLSInterceptTunnel_TornDownOnScopedDrain(t *testing.T) {
	const (
		agent    = "named-agent-a"
		clientIP = airlockSessionKeyClientIP
		host     = "127.0.0.1"
	)

	// Prove the two keys diverge for this identity.
	rawKey := sessionKeyFor(agent, clientIP)
	ceeKey := responseTaintSessionKey(agent, clientIP, envelope.ActorAuthSelfDeclared)
	if rawKey == ceeKey {
		t.Fatalf("test setup invalid: raw key %q must differ from CEE-safe key %q for a self-declared named agent", rawKey, ceeKey)
	}

	// A hold-open TCP target so the CONNECT's initial dial succeeds and the
	// handler reaches the interception branch.
	target := listenHold(t)
	t.Cleanup(func() { _ = target.Close() })
	_, targetPort, err := net.SplitHostPort(target.Addr().String())
	if err != nil {
		t.Fatalf("split target addr: %v", err)
	}

	sniOff := false
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(c *config.Config) {
		airlockDrainProxyConfig(c)
		c.TLSInterception.Enabled = true
		c.TLSInterception.MaxResponseBytes = 1 << 20
		c.ForwardProxy.IdleTimeoutSeconds = 60
		c.ForwardProxy.MaxTunnelSeconds = 120
		// Disable SNI verification so the handler reaches the interception
		// branch (and its cancel registration) without a ClientHello; otherwise
		// SNI's own read timeout tears the tunnel down before the branch runs.
		c.ForwardProxy.SNIVerification = &sniOff
	})
	defer cleanup()

	// Install a cert cache so the interception branch proceeds past the
	// fail-closed cert-cache check to the cancel registration.
	ca, caKey, _, err := certgen.GenerateCA("Test", time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	cache, err := certgen.NewCertCache(ca, caKey, time.Hour, 100)
	if err != nil {
		t.Fatalf("NewCertCache: %v", err)
	}
	p.certCachePtr.Store(cache)

	scope := adaptiveScopeForHost(host)
	sess := setupForcedScopedDrain(t, p, agent, clientIP, host)
	if got := sess.AirlockForScope(scope).Tier(); got != config.AirlockTierDrain {
		t.Fatalf("precondition: airlock tier must stay drain after adaptive recovery, got %q", got)
	}

	conn := dialProxy(t, proxyAddr)
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n%s: %s\r\n\r\n",
		host, targetPort, host, targetPort, AgentHeader, agent); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT setup status = %d, want 200 (interception must reach the intercept branch)", resp.StatusCode)
	}

	// After the fix the pre-registered cancel fires immediately and the tunnel is
	// torn down before any inner-request handshake; the client read returns
	// promptly with a non-timeout error. Before the fix the cancel sits on the
	// folded session, interceptTunnel blocks on the 30s client handshake, and the
	// read hits the test deadline.
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	start := time.Now()
	_, readErr := br.Read(make([]byte, 1))
	elapsed := time.Since(start)
	if readErr == nil {
		t.Fatal("tunnel returned unexpected data; expected teardown on airlock drain")
	}
	var nerr net.Error
	if errors.As(readErr, &nerr) && nerr.Timeout() {
		t.Fatalf("TLS-intercept tunnel not torn down within 4s (read err=%v after %s): the intercept-branch cancel is registered on the folded session, not the raw drained session", readErr, elapsed)
	}
}

// TestForceSetAirlockTier_AppliesToEveryScope is the load-bearing regression
// guard for the operator override (ITEM 3, operability). Adaptive enforcement
// writes the airlock tier per DESTINATION scope, but ForceSetAirlockTier used to
// mutate only the session-wide airlock. So after a scoped drain an operator
// releasing the tier to none found the destination still denied, and an operator
// forcing drain never quarantined a scoped destination. After the fix the
// override applies to the session-wide airlock AND every destination scope, in
// both directions.
func TestForceSetAirlockTier_AppliesToEveryScope(t *testing.T) {
	const (
		agent    = "named-agent-a"
		clientIP = airlockSessionKeyClientIP
		host     = airlockSessionKeyTarget
	)
	key := responseTaintSessionKey(agent, clientIP, envelope.ActorAuthSelfDeclared)
	scope := adaptiveScopeForHost(host)

	t.Run("release_to_none_clears_scoped_drain", func(t *testing.T) {
		proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, airlockDrainProxyConfig)
		defer cleanup()
		airlockTestUpstream(t, p)
		setupDrainedRecoveredSession(t, p, agent)

		sm := p.sessionMgrPtr.Load()
		sess := sm.GetOrCreate(key)
		if got := sess.AirlockForScope(scope).Tier(); got != config.AirlockTierDrain {
			t.Fatalf("precondition: scope tier = %q, want drain", got)
		}

		found, changed, from, to := sm.ForceSetAirlockTier(key, config.AirlockTierNone)
		if !found || !changed || from != config.AirlockTierDrain || to != config.AirlockTierNone {
			t.Fatalf("ForceSetAirlockTier(none) = found:%v changed:%v from:%q to:%q, want found:true changed:true from:drain to:none", found, changed, from, to)
		}
		if got := sess.Airlock().Tier(); got != config.AirlockTierNone {
			t.Fatalf("session-wide tier after release = %q, want none", got)
		}
		if got := sess.AirlockForScope(scope).Tier(); got != config.AirlockTierNone {
			t.Fatalf("scoped tier after release = %q, want none (operator release must clear the scoped drain)", got)
		}

		// The destination the operator released must now be admitted.
		status, reason := doFetchWithAgent(t, "http://"+proxyAddr, "http://"+host+"/", agent)
		if status != http.StatusOK {
			t.Fatalf("fetch after operator release: status=%d reason=%q, want 200 (released destination must be admitted)", status, reason)
		}
	})

	t.Run("force_drain_quarantines_every_scope", func(t *testing.T) {
		proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, airlockDrainProxyConfig)
		defer cleanup()
		airlockTestUpstream(t, p)

		sm := p.sessionMgrPtr.Load()
		sess := sm.GetOrCreate(key)
		// Instantiate the destination scope at none, as a prior clean request to
		// that destination would have.
		if got := sess.AirlockForScope(scope).Tier(); got != config.AirlockTierNone {
			t.Fatalf("precondition: fresh scope tier = %q, want none", got)
		}

		found, changed, from, to := sm.ForceSetAirlockTier(key, config.AirlockTierDrain)
		if !found || !changed || from != config.AirlockTierNone || to != config.AirlockTierDrain {
			t.Fatalf("ForceSetAirlockTier(drain) = found:%v changed:%v from:%q to:%q, want found:true changed:true from:none to:drain", found, changed, from, to)
		}
		if got := sess.Airlock().Tier(); got != config.AirlockTierDrain {
			t.Fatalf("session-wide tier after force drain = %q, want drain", got)
		}
		if got := sess.AirlockForScope(scope).Tier(); got != config.AirlockTierDrain {
			t.Fatalf("scoped tier after force drain = %q, want drain (operator drain must quarantine every existing scope)", got)
		}
		futureScope := adaptiveScopeForHost("future.example")
		if got := sess.AirlockForScope(futureScope).Tier(); got != config.AirlockTierDrain {
			t.Fatalf("scope created after force drain = %q, want drain (operator override must govern future destinations)", got)
		}

		// The destination the operator drained must now be refused.
		status, reason := doFetchWithAgent(t, "http://"+proxyAddr, "http://"+host+"/", agent)
		if status != http.StatusForbidden || reason != airlockActiveReason {
			t.Fatalf("fetch after operator drain: status=%d reason=%q, want 403 %q (drained destination must be refused)", status, reason, airlockActiveReason)
		}
	})
}

func TestForceSetAirlockTier_WaitsForSessionTransactionLock(t *testing.T) {
	sess := &SessionState{
		key:    "atomic-override",
		scopes: make(map[string]*adaptiveScopeState),
	}
	sess.airlock = *NewAirlockState()
	sess.mu.Lock()
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		sess.ForceSetAirlockTierAllScopes(config.AirlockTierDrain, airlockTriggerManual, airlockSourceAdminAPI)
	}()
	<-started

	// While the session transaction lock is held, neither the global nor any
	// scoped portion of the override may become visible.
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := sess.airlock.Tier(); got != config.AirlockTierNone {
			sess.mu.Unlock()
			<-done
			t.Fatalf("global tier changed before session transaction lock was acquired: %q", got)
		}
		runtime.Gosched()
	}
	sess.mu.Unlock()
	<-done
	if got := sess.airlock.Tier(); got != config.AirlockTierDrain {
		t.Fatalf("global tier after completed override = %q, want drain", got)
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

// doConnectWithAgent dials the proxy and issues a raw opaque CONNECT to target
// (host:port) with the self-declared agent header, returning the tunnel-setup
// HTTP status and block-reason header. It never completes a tunnel: the airlock
// admission path answers before the proxy dials or hijacks the connection.
func doConnectWithAgent(t *testing.T, proxyAddr, target, agent string) (int, string) {
	t.Helper()
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s: %s\r\n\r\n",
		target, target, AgentHeader, agent); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
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
