// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Issuer-cookie and issuer-query allows follow flight_recorder.require_receipts
// exactly like credential-audience allows: ON means the allow receipt must be
// durably emitted before the request is forwarded, else the request is blocked
// before any upstream write. OFF keeps best-effort behavior.

type issuerAllowRequireCase struct {
	name         string
	require      bool
	emitFails    bool
	wantStatus   int
	wantUpstream int32 // hits on the allowed request only (issuance step excluded)
}

var issuerAllowRequireCases = []issuerAllowRequireCase{
	{name: "on and emit fails blocks before egress", require: true, emitFails: true, wantStatus: http.StatusForbidden, wantUpstream: 0},
	{name: "on and emit succeeds forwards", require: true, emitFails: false, wantStatus: http.StatusOK, wantUpstream: 1},
	{name: "off and emit fails still forwards", require: false, emitFails: true, wantStatus: http.StatusOK, wantUpstream: 1},
}

// runIssuerAllowIntercept issues a value (healthy recorder), optionally breaks
// the recorder, then sends the request that earns the issuer allow. The proxy's
// live config differs from the request snapshot so the receipt hash is checkable.
func runIssuerAllowIntercept(t *testing.T, tc issuerAllowRequireCase, issuePath string, issueHandler http.HandlerFunc, allowReq func(base string) *http.Request, allowPath string) {
	t.Helper()
	var allowHits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == issuePath {
			issueHandler(w, r)
			return
		}
		if r.URL.Path == allowPath {
			allowHits.Add(1)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	issuerCookieTestConfig(t, cfg)
	cfg.FlightRecorder.RequireReceipts = tc.require
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	live := config.Defaults()
	live.Internal = nil
	live.FetchProxy.Monitoring.Blocklist = append(live.FetchProxy.Monitoring.Blocklist, "live-only.vendor.example")
	if live.CanonicalPolicyHash() == cfg.CanonicalPolicyHash() {
		t.Fatal("test setup: live and snapshot policy hashes must differ")
	}
	p.cfgPtr.Store(live)
	rph := newReceiptProxyHelperWithMetrics(t, m)
	p.receiptEmitterPtr.Store(rph.emitter)

	do := func(req *http.Request) *http.Response {
		return interceptAndRequestWithRecorder(t, interceptRequestOptions{
			Upstream: upstream, Cache: cache, Pool: pool, Config: cfg, Scanner: sc,
			Logger: logger, Metrics: m, Request: req, Proxy: p,
			Agent: "agent-one", ActorAuth: envelope.ActorAuthBound,
		})
	}
	issueReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL+issuePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	issueResp := do(issueReq)
	_, _ = io.Copy(io.Discard, issueResp.Body)
	_ = issueResp.Body.Close()
	if issueResp.StatusCode != http.StatusOK {
		t.Fatalf("issuance status = %d, want 200", issueResp.StatusCode)
	}
	if tc.emitFails {
		if err := rph.rec.Close(); err != nil {
			t.Fatalf("recorder.Close: %v", err)
		}
	}

	resp := do(allowReq(upstream.URL))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != tc.wantStatus {
		t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
	}
	if got := allowHits.Load(); got != tc.wantUpstream {
		t.Fatalf("upstream allowed-request hits = %d, want %d", got, tc.wantUpstream)
	}
	if tc.require && tc.emitFails {
		if got := resp.Header.Get(blockreason.HeaderReason); got != string(blockreason.ReceiptEmissionFailed) {
			t.Fatalf("block reason header = %q, want %s", got, blockreason.ReceiptEmissionFailed)
		}
		if got := resp.Header.Get(blockreason.HeaderLayer); got != blockLayerIssuerAllowReceipt {
			t.Fatalf("block layer header = %q, want %q", got, blockLayerIssuerAllowReceipt)
		}
	}
	if tc.require && !tc.emitFails {
		layer := issuerCookieReceiptExtensionKey
		if allowPath == "/page" {
			layer = issuerQueryReceiptExtensionKey
		}
		r := rph.requireReceipt(t, layer)
		if got, want := r.ActionRecord.PolicyHash, cfg.CanonicalPolicyHash(); got != want {
			t.Fatalf("receipt policy_hash = %q, want request snapshot %q (live %q)", got, want, live.CanonicalPolicyHash())
		}
	}
}

func TestInterceptIssuerCookieAllow_RequireReceipts(t *testing.T) {
	aws := issuerAWSShapedValue()
	for _, tc := range issuerAllowRequireCases {
		t.Run(tc.name, func(t *testing.T) {
			runIssuerAllowIntercept(t, tc, "/login",
				func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Add("Set-Cookie", "AWSALB="+aws+"; Path=/; Secure; HttpOnly; Max-Age=600")
					_, _ = io.WriteString(w, "ok")
				},
				func(base string) *http.Request {
					req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/account", nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Cookie", "AWSALB="+aws)
					return req
				}, "/account")
		})
	}
}

func TestInterceptIssuerQueryAllow_RequireReceipts(t *testing.T) {
	value := issuedTestToken()
	for _, tc := range issuerAllowRequireCases {
		t.Run(tc.name, func(t *testing.T) {
			runIssuerAllowIntercept(t, tc, "/list",
				func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"next":"/page?%24skiptoken=`+value+`"}`)
				},
				func(base string) *http.Request {
					req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/page?%24skiptoken="+value, nil)
					if err != nil {
						t.Fatal(err)
					}
					return req
				}, "/page")
		})
	}
}

// Every path after the exemption was applied must return an error under
// require_receipts (else the gate is vacuous) and nil when it is off.
func TestRecordIssuerAllow_EarlyReturnsFollowRequireReceipts(t *testing.T) {
	on := config.Defaults()
	on.FlightRecorder.RequireReceipts = true
	off := config.Defaults()
	off.FlightRecorder.RequireReceipts = false

	newProxy := func(t *testing.T, emitFails bool) *Proxy {
		t.Helper()
		p := &Proxy{logger: audit.NewNop(), metrics: metrics.New()}
		rph := newReceiptProxyHelper(t)
		if emitFails {
			if err := rph.rec.Close(); err != nil {
				t.Fatal(err)
			}
		}
		p.receiptEmitterPtr.Store(rph.emitter)
		return p
	}

	type recorder func(p *Proxy, cfg *config.Config) error
	cookie := func(target string) recorder {
		return func(p *Proxy, cfg *config.Config) error {
			return p.recordIssuerCookieAllow(cfg, audit.LogContext{}, "AWS Access ID", "AWSALB", target, "req", "agent-one", http.MethodGet)
		}
	}
	query := func(target string) recorder {
		return func(p *Proxy, cfg *config.Config) error {
			return p.recordIssuerQueryAllow(cfg, audit.LogContext{}, target, "req", "agent-one", http.MethodGet, issuerQueryObserved)
		}
	}
	cases := []struct {
		name      string
		nilProxy  bool
		emitFails bool
		rec       recorder
	}{
		{"cookie unparseable target", false, false, cookie("%zz")},
		{"cookie non-https target", false, false, cookie("http://app.vendor.example/x")},
		{"cookie empty host", false, false, cookie("https:///x")},
		{"cookie nil proxy", true, false, cookie("https://app.vendor.example/x")},
		{"cookie emit failure", false, true, cookie("https://app.vendor.example/x")},
		{"query unparseable target", false, false, query("%zz")},
		{"query nil proxy", true, false, query("https://app.vendor.example/x")},
		{"query emit failure", false, true, query("https://app.vendor.example/x")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p *Proxy
			if !tc.nilProxy {
				p = newProxy(t, tc.emitFails)
			}
			if err := tc.rec(p, on); err == nil {
				t.Fatal("require_receipts on: want error, got nil")
			}
			if !tc.nilProxy {
				p = newProxy(t, tc.emitFails)
			}
			if err := tc.rec(p, off); err != nil {
				t.Fatalf("require_receipts off: want nil, got %v", err)
			}
			if err := tc.rec(p, nil); err != nil {
				t.Fatalf("nil snapshot: want nil, got %v", err)
			}
		})
	}

	t.Run("success returns nil under require", func(t *testing.T) {
		p := newProxy(t, false)
		if err := cookie("https://app.vendor.example/x")(p, on); err != nil {
			t.Fatalf("cookie: %v", err)
		}
		if err := query("https://app.vendor.example/x")(p, on); err != nil {
			t.Fatalf("query: %v", err)
		}
	})

	t.Run("missing emitter returns the unavailable error", func(t *testing.T) {
		p := &Proxy{logger: audit.NewNop()}
		if err := cookie("https://app.vendor.example/x")(p, on); !errors.Is(err, errCredentialAudienceReceiptEmitterUnavailable) {
			t.Fatalf("err = %v, want emitter unavailable", err)
		}
	})
}
