// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func redirectPolicyTestProxy(t *testing.T, opts ...Option) (*Proxy, *config.Config, *scanner.Scanner) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SessionProfiling.Enabled = true
	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New(), opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(p.Close)
	return p, cfg, sc
}

func redirectPolicyRequests(t *testing.T, cfg *config.Config, sc *scanner.Scanner) (*http.Request, *http.Request) {
	t.Helper()
	ctx := context.WithValue(t.Context(), ctxKeyClientIP, "127.0.0.1")
	ctx = context.WithValue(ctx, ctxKeyRequestID, "req-redirect-policy")
	ctx = context.WithValue(ctx, ctxKeyAgent, agentAnonymous)
	ctx = context.WithValue(ctx, ctxKeyAgentConfig, cfg)
	ctx = context.WithValue(ctx, ctxKeyAgentScanner, sc)
	ctx = context.WithValue(ctx, ctxKeyRedirectTransport, TransportForward)
	redirectReq := httptest.NewRequestWithContext(ctx, http.MethodPost, "https://api.vendor.example/auth/update", nil)
	originalReq := httptest.NewRequestWithContext(ctx, http.MethodPost, "https://source.vendor.example/start", nil)
	return redirectReq, originalReq
}

func TestCheckRedirect_TaintedProtectedActionBlocks(t *testing.T) {
	p, cfg, sc := redirectPolicyTestProxy(t)
	cfg.Taint.TrustOverrides = []config.TaintTrustOverride{{
		Scope:       taintScopeAction,
		ActionMatch: "publish:post:https://source.vendor.example/start",
	}}
	rec := p.sessionMgrPtr.Load().GetOrCreate(sessionKeyFor(agentAnonymous, "127.0.0.1"))
	redirectReq, originalReq := redirectPolicyRequests(t, cfg, sc)
	redirectReq = redirectReq.WithContext(context.WithValue(redirectReq.Context(), ctxKeyRedirectSessionRecorder, rec))
	originalReq = originalReq.WithContext(context.WithValue(originalReq.Context(), ctxKeyRedirectSessionRecorder, rec))
	// The recorder is snapshotted at admission, but its live state may change
	// before a later redirect hop.
	observeHTTPResponseTaint(rec, cfg, "https://untrusted.vendor.example/page", "text/html", "forward_response", false)
	if decision := evaluateHTTPTaint(cfg, rec, originalReq.Method, originalReq.URL); decision.Result.Decision.String() != "allow" {
		t.Fatalf("precondition: action-scoped override did not admit original request: %+v", decision.Result)
	}
	if decision := evaluateHTTPTaint(cfg, rec, redirectReq.Method, redirectReq.URL); decision.Result.Decision.String() == "allow" {
		t.Fatalf("precondition: taint policy unexpectedly allowed protected redirect: %+v", decision.Result)
	}
	err := p.client.CheckRedirect(redirectReq, []*http.Request{originalReq})
	blockedErr, ok := blockedRequestErrorFrom(err)
	if !ok {
		t.Fatal("taint policy allowed protected redirect")
	}
	if blockedErr.layer != "taint_policy" {
		t.Fatalf("block layer = %q, want taint_policy", blockedErr.layer)
	}
	if blockedErr.taint == nil || blockedErr.taint.Result.Decision.String() != "ask" {
		t.Fatalf("redirect taint decision = %+v, want ask", blockedErr.taint)
	}
}

func TestCheckRedirect_TaintedProtectedActionExplicitApprovalAllows(t *testing.T) {
	approver := hitl.New(5,
		hitl.WithTerminal(true),
		hitl.WithInput(strings.NewReader("yes\n")),
		hitl.WithOutput(io.Discard),
	)
	t.Cleanup(approver.Close)
	p, cfg, sc := redirectPolicyTestProxy(t, WithApprover(approver))
	cfg.Taint.TrustOverrides = []config.TaintTrustOverride{{
		Scope:       taintScopeAction,
		ActionMatch: "publish:post:https://source.vendor.example/start",
	}}
	rec := p.sessionMgrPtr.Load().GetOrCreate(sessionKeyFor(agentAnonymous, "127.0.0.1"))
	observeHTTPResponseTaint(rec, cfg, "https://untrusted.vendor.example/page", "text/html", "forward_response", false)
	redirectReq, originalReq := redirectPolicyRequests(t, cfg, sc)
	redirectReq = redirectReq.WithContext(context.WithValue(redirectReq.Context(), ctxKeyRedirectSessionRecorder, rec))
	if decision := evaluateHTTPTaint(cfg, rec, originalReq.Method, originalReq.URL); decision.Result.Decision.String() != "allow" {
		t.Fatalf("precondition: action-scoped override did not admit original request: %+v", decision.Result)
	}
	// Pin the arm under test. Without this the test passes whenever the
	// redirect decision is allow, which proves nothing about the approver:
	// a matrix change that stopped gating this redirect would leave the
	// test green while the HITL branch went unexercised.
	if decision := evaluateHTTPTaint(cfg, rec, redirectReq.Method, redirectReq.URL); decision.Result.Decision.String() != "ask" {
		t.Fatalf("precondition: redirect decision = %q, want ask", decision.Result.Decision.String())
	}
	if err := p.client.CheckRedirect(redirectReq, []*http.Request{originalReq}); err != nil {
		t.Fatalf("explicitly approved redirect blocked: %v", err)
	}
}

// TestCheckRedirect_TaintedProtectedActionPolicyBlockIgnoresApprover pins the
// separation between the PolicyBlock and PolicyAsk arms of the redirect taint
// switch. PolicyBlock is terminal: a hostile-source session must never be
// offered an approval prompt, because prompting would let an operator approve
// away a decision the matrix already refused outright. Nothing else in this
// file reaches PolicyBlock - the sibling "Blocks" test exercises
// PolicyAsk-with-no-approver - so collapsing the two arms into one prompt
// would leave every other redirect test green.
func TestCheckRedirect_TaintedProtectedActionPolicyBlockIgnoresApprover(t *testing.T) {
	approver := hitl.New(5,
		hitl.WithTerminal(true),
		hitl.WithInput(strings.NewReader("yes\n")),
		hitl.WithOutput(io.Discard),
	)
	t.Cleanup(approver.Close)
	p, cfg, sc := redirectPolicyTestProxy(t, WithApprover(approver))
	cfg.Taint.TrustOverrides = []config.TaintTrustOverride{{
		Scope:       taintScopeAction,
		ActionMatch: "publish:post:https://source.vendor.example/start",
	}}
	rec := p.sessionMgrPtr.Load().GetOrCreate(sessionKeyFor(agentAnonymous, "127.0.0.1"))
	// promptHit escalates the source to hostile, which is the level the
	// matrix answers with block rather than ask.
	observeHTTPResponseTaint(rec, cfg, "https://untrusted.vendor.example/page", "text/html", "forward_response", true)
	redirectReq, originalReq := redirectPolicyRequests(t, cfg, sc)
	redirectReq = redirectReq.WithContext(context.WithValue(redirectReq.Context(), ctxKeyRedirectSessionRecorder, rec))
	if decision := evaluateHTTPTaint(cfg, rec, originalReq.Method, originalReq.URL); decision.Result.Decision.String() != "allow" {
		t.Fatalf("precondition: action-scoped override did not admit original request: %+v", decision.Result)
	}
	if decision := evaluateHTTPTaint(cfg, rec, redirectReq.Method, redirectReq.URL); decision.Result.Decision.String() != "block" {
		t.Fatalf("precondition: redirect decision = %q, want block", decision.Result.Decision.String())
	}
	err := p.client.CheckRedirect(redirectReq, []*http.Request{originalReq})
	blockedErr, ok := blockedRequestErrorFrom(err)
	if !ok {
		t.Fatal("approver allowed a redirect the taint matrix blocked outright")
	}
	if blockedErr.layer != "taint_policy" {
		t.Fatalf("block layer = %q, want taint_policy", blockedErr.layer)
	}
	if blockedErr.taint == nil || blockedErr.taint.Result.Decision.String() != "block" {
		t.Fatalf("redirect taint decision = %+v, want block", blockedErr.taint)
	}
}

func TestCheckRedirect_ScopedAirlockBlocks(t *testing.T) {
	p, cfg, sc := redirectPolicyTestProxy(t)
	sess := p.sessionMgrPtr.Load().GetOrCreate(sessionKeyFor(agentAnonymous, "127.0.0.1"))
	redirectReq, originalReq := redirectPolicyRequests(t, cfg, sc)
	redirectReq = redirectReq.WithContext(context.WithValue(redirectReq.Context(), ctxKeyRedirectSessionRecorder, sess))
	originalReq = originalReq.WithContext(context.WithValue(originalReq.Context(), ctxKeyRedirectSessionRecorder, sess))
	// A scope can enter drain after request admission but before the redirect.
	if changed, _, _ := sess.AirlockForScope(adaptiveScopeForHost("api.vendor.example")).ForceSetTier(config.AirlockTierDrain); !changed {
		t.Fatal("precondition: scoped airlock did not enter drain tier")
	}
	if allowed, _ := ClassifyAction(config.AirlockTierDrain, redirectReq.Method, TransportForward, false); allowed {
		t.Fatal("precondition: drain airlock unexpectedly allowed redirected POST")
	}
	err := p.client.CheckRedirect(redirectReq, []*http.Request{originalReq})
	blockedErr, ok := blockedRequestErrorFrom(err)
	if !ok {
		t.Fatal("scoped airlock allowed redirected action")
	}
	if blockedErr.layer != "airlock" {
		t.Fatalf("block layer = %q, want airlock", blockedErr.layer)
	}
}

func TestCheckRedirect_SessionPoliciesAllowHarmlessRedirect(t *testing.T) {
	p, cfg, sc := redirectPolicyTestProxy(t)
	redirectReq, originalReq := redirectPolicyRequests(t, cfg, sc)
	sess := p.sessionMgrPtr.Load().GetOrCreate(sessionKeyFor(agentAnonymous, "127.0.0.1"))
	redirectReq = redirectReq.WithContext(context.WithValue(redirectReq.Context(), ctxKeyRedirectSessionRecorder, sess))
	if err := p.client.CheckRedirect(redirectReq, []*http.Request{originalReq}); err != nil {
		t.Fatalf("clean session redirect blocked: %v", err)
	}

	redirectReq, originalReq = redirectPolicyRequests(t, cfg, sc)
	if err := p.client.CheckRedirect(redirectReq, []*http.Request{originalReq}); err != nil {
		t.Fatalf("redirect without session recorder blocked: %v", err)
	}
}

func TestForwardRedirect_SessionPoliciesBlockBeforeRedirectedEgress(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *Proxy)
	}{
		{
			name: "taint reauthorization",
			setup: func(t *testing.T, p *Proxy) {
				t.Helper()
				cfg := p.CurrentConfig()
				sess := p.sessionMgrPtr.Load().GetOrCreate(sessionKeyFor(agentAnonymous, "127.0.0.1"))
				observeHTTPResponseTaint(sess, cfg, "https://untrusted.vendor.example/page", "text/html", "forward_response", false)
			},
		},
		{
			name: "scoped airlock",
			setup: func(t *testing.T, p *Proxy) {
				t.Helper()
				sess := p.sessionMgrPtr.Load().GetOrCreate(sessionKeyFor(agentAnonymous, "127.0.0.1"))
				if changed, _, _ := sess.AirlockForScope(adaptiveScopeForHost("api.vendor.example")).ForceSetTier(config.AirlockTierDrain); !changed {
					t.Fatal("target scope did not enter drain tier")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var initialHits, redirectedHits atomic.Int32
			backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host == "source.vendor.example" {
					initialHits.Add(1)
					http.Redirect(w, r, "http://api.vendor.example/auth/update", http.StatusTemporaryRedirect)
					return
				}
				redirectedHits.Add(1)
				_, _ = io.WriteString(w, "unexpected redirected egress")
			}))
			defer backend.Close()

			proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
				cfg.SessionProfiling.Enabled = true
				cfg.Taint.TrustOverrides = []config.TaintTrustOverride{{
					Scope:       taintScopeAction,
					ActionMatch: "publish:post:http://source.vendor.example/start",
				}}
			})
			defer cleanup()
			tt.setup(t, p)
			p.client.Transport = &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					switch addr {
					case "source.vendor.example:80", "api.vendor.example:80":
						return (&net.Dialer{}).DialContext(ctx, network, backend.Listener.Addr().String())
					default:
						return (&net.Dialer{}).DialContext(ctx, network, addr)
					}
				},
				DisableCompression: true,
			}

			proxyURL, err := url.Parse("http://" + proxyAddr)
			if err != nil {
				t.Fatalf("parse proxy URL: %v", err)
			}
			client := &http.Client{
				Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
				Timeout:   2 * time.Second,
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://source.vendor.example/start", strings.NewReader("payload"))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("forward request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusForbidden {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want 403; body=%s", resp.StatusCode, body)
			}
			if initialHits.Load() != 1 {
				t.Fatalf("initial upstream hits = %d, want 1", initialHits.Load())
			}
			if redirectedHits.Load() != 0 {
				t.Fatalf("redirected upstream hits = %d, want 0", redirectedHits.Load())
			}
		})
	}
}

func TestFetchRedirect_ScopedAirlockBlocksBeforeRedirectedEgress(t *testing.T) {
	var initialHits, redirectedHits atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "source.vendor.example" {
			initialHits.Add(1)
			http.Redirect(w, r, "http://api.vendor.example/final", http.StatusFound)
			return
		}
		redirectedHits.Add(1)
		_, _ = io.WriteString(w, "unexpected redirected egress")
	}))
	defer backend.Close()

	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.SessionProfiling.Enabled = true
	})
	defer cleanup()
	sess := p.sessionMgrPtr.Load().GetOrCreate(sessionKeyFor(agentAnonymous, "127.0.0.1"))
	if changed, _, _ := sess.AirlockForScope(adaptiveScopeForHost("api.vendor.example")).ForceSetTier(config.AirlockTierDrain); !changed {
		t.Fatal("target scope did not enter drain tier")
	}
	p.client.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			switch addr {
			case "source.vendor.example:80", "api.vendor.example:80":
				return (&net.Dialer{}).DialContext(ctx, network, backend.Listener.Addr().String())
			default:
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}
		},
		DisableCompression: true,
	}

	requestURL := "http://" + proxyAddr + "/fetch?url=" + url.QueryEscape("http://source.vendor.example/start")
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, requestURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("fetch request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 403; body=%s", resp.StatusCode, body)
	}
	if initialHits.Load() != 1 {
		t.Fatalf("initial upstream hits = %d, want 1", initialHits.Load())
	}
	if redirectedHits.Load() != 0 {
		t.Fatalf("redirected upstream hits = %d, want 0", redirectedHits.Load())
	}
}
