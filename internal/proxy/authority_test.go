// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/authority"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

type proxyAuthorityVerifierFunc func(context.Context, authority.Request) authority.Result

func (f proxyAuthorityVerifierFunc) Verify(ctx context.Context, request authority.Request) authority.Result {
	return f(ctx, request)
}

func denyProxyAuthorityVerifier(calls *atomic.Int32) authority.Verifier {
	return proxyAuthorityVerifierFunc(func(context.Context, authority.Request) authority.Result {
		calls.Add(1)
		return authority.Result{Decision: authority.DecisionDeny, Reason: authority.ReasonActionMismatch}
	})
}

func TestProxyAuthorityHelperFailClosedPaths(t *testing.T) {
	t.Parallel()
	if _, err := consumeAuthorityHeader(nil); !errors.Is(err, authority.ErrMissingReference) {
		t.Fatalf("nil request error = %v, want missing reference", err)
	}
	if err := (&Proxy{}).authorizeForward(t.Context(), "", authority.ErrMissingReference, authority.Request{}, audit.LogContext{}, TransportFetch); err != nil {
		t.Fatalf("nil verifier changed behavior: %v", err)
	}
	p := &Proxy{authorityVerifier: proxyAuthorityVerifierFunc(func(context.Context, authority.Request) authority.Result {
		return authority.Result{Decision: authority.Decision(99)}
	})}
	if err := p.authorizeForward(t.Context(), "grant", nil, authority.Request{
		Actor:       "agent-a",
		Action:      "read",
		Destination: "https://service.example",
	}, audit.LogContext{}, TransportFetch); err == nil {
		t.Fatal("invalid verifier decision did not fail closed")
	}
}

func TestFetchAndForwardAuthorityFailuresBeforeUpstream(t *testing.T) {
	t.Parallel()
	for _, transport := range []string{TransportFetch, TransportForward} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			for _, tc := range []struct {
				name              string
				values            []string
				connection        string
				decision          authority.Decision
				wantVerifierCalls int32
			}{
				{name: "deny", values: []string{"grant"}, decision: authority.DecisionDeny, wantVerifierCalls: 1},
				{name: "indeterminate", values: []string{"grant"}, decision: authority.DecisionIndeterminate, wantVerifierCalls: 1},
				{name: "invalid decision", values: []string{"grant"}, decision: authority.Decision(99), wantVerifierCalls: 1},
				{name: "missing", decision: authority.DecisionAllow},
				{name: "duplicate", values: []string{"one", "two"}, decision: authority.DecisionAllow},
				{name: "comma joined", values: []string{"one,two"}, decision: authority.DecisionAllow},
				{name: "connection nominated", values: []string{"grant"}, connection: authority.HTTPHeader, decision: authority.DecisionAllow},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var upstreamCalls, verifierCalls atomic.Int32
					upstream := newIPv4Server(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
						upstreamCalls.Add(1)
					}))
					defer upstream.Close()
					p, unusedBackend := setupTestProxy(t)
					defer unusedBackend.Close()
					defer p.Close()
					receiptHelper := newReceiptProxyHelperWithMetrics(t, p.metrics)
					p.receiptEmitterPtr.Store(receiptHelper.emitter)
					p.authorityVerifier = proxyAuthorityVerifierFunc(func(context.Context, authority.Request) authority.Result {
						verifierCalls.Add(1)
						return authority.Result{Decision: tc.decision, Reason: authority.ReasonActionMismatch}
					})

					var req *http.Request
					if transport == TransportFetch {
						req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.URL), nil)
					} else {
						req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
					}
					for _, value := range tc.values {
						req.Header.Add(authority.HTTPHeader, value)
					}
					if tc.connection != "" {
						req.Header.Set("Connection", tc.connection)
					}
					rec := httptest.NewRecorder()
					if transport == TransportFetch {
						p.handleFetch(rec, req)
					} else {
						p.handleForwardHTTP(rec, req)
					}
					if rec.Code != http.StatusForbidden {
						t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
					}
					if got := rec.Header().Get(blockreason.HeaderReason); got != string(blockreason.AuthorityMismatch) {
						t.Fatalf("block reason = %q, want %q", got, blockreason.AuthorityMismatch)
					}
					if verifierCalls.Load() != tc.wantVerifierCalls || upstreamCalls.Load() != 0 {
						t.Fatalf("verifier calls=%d upstream calls=%d, want %d/0", verifierCalls.Load(), upstreamCalls.Load(), tc.wantVerifierCalls)
					}
					receipts := receiptHelper.findReceipts(t)
					if len(receipts) != 1 {
						t.Fatalf("receipt count = %d, want exactly one authority denial", len(receipts))
					}
					record := receipts[0].ActionRecord
					if record.Verdict != config.ActionBlock || record.Layer != blockLayerAuthority {
						t.Fatalf("receipt verdict/layer = %q/%q, want %q/%q", record.Verdict, record.Layer, config.ActionBlock, blockLayerAuthority)
					}
				})
			}
		})
	}
}

func TestFetchAndForwardAuthorityHeaderConsumedOnAllow(t *testing.T) {
	t.Parallel()
	for _, transport := range []string{TransportFetch, TransportForward} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			seen := make(chan string, 1)
			verified := make(chan authority.Request, 1)
			upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Get(authority.HTTPHeader)
				_, _ = fmt.Fprint(w, "ok")
			}))
			defer upstream.Close()
			p, unusedBackend := setupTestProxy(t)
			defer unusedBackend.Close()
			defer p.Close()
			p.authorityVerifier = proxyAuthorityVerifierFunc(func(_ context.Context, request authority.Request) authority.Result {
				verified <- request
				return authority.Result{Decision: authority.DecisionAllow, Reason: authority.ReasonMatched}
			})
			var req *http.Request
			if transport == TransportFetch {
				req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.URL), nil)
			} else {
				req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
			}
			req.Header.Set(authority.HTTPHeader, "grant")
			rec := httptest.NewRecorder()
			if transport == TransportFetch {
				p.handleFetch(rec, req)
			} else {
				p.handleForwardHTTP(rec, req)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			if got := <-seen; got != "" {
				t.Fatalf("reserved header leaked upstream: %q", got)
			}
			verificationRequest := <-verified
			if verificationRequest.Actor == "" || verificationRequest.Action != "read" || verificationRequest.Destination != upstream.URL || verificationRequest.AuthorityRef != "grant" {
				t.Fatalf("verification request = %+v", verificationRequest)
			}
		})
	}
}

func TestConnectAuthorityDenyMakesNoDial(t *testing.T) {
	t.Parallel()
	var verifierCalls atomic.Int32
	proxyAddr, p, dialCalls, _, cleanup := setupConnectIdentityProxyWithInstance(t, nil, WithAuthorityVerifier(denyProxyAuthorityVerifier(&verifierCalls)))
	defer cleanup()
	receiptHelper := newReceiptProxyHelperWithMetrics(t, p.metrics)
	p.receiptEmitterPtr.Store(receiptHelper.emitter)

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "CONNECT 127.0.0.1:6443 HTTP/1.1\r\nHost: 127.0.0.1:6443\r\n%s: grant\r\n\r\n", authority.HTTPHeader); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden || dialCalls.Load() != 0 || verifierCalls.Load() != 1 {
		t.Fatalf("status=%d dial calls=%d verifier calls=%d, want 403/0/1", resp.StatusCode, dialCalls.Load(), verifierCalls.Load())
	}
	assertSingleProxyAuthorityBlockReceipt(t, receiptHelper.findReceipts(t))
}

func TestConnectAuthorityAllowReachesDialWithoutForwardingRequestHeaders(t *testing.T) {
	t.Parallel()
	verified := make(chan authority.Request, 1)
	proxyAddr, dialCalls, _, cleanup := setupConnectIdentityProxy(t, nil, WithAuthorityVerifier(
		proxyAuthorityVerifierFunc(func(_ context.Context, request authority.Request) authority.Result {
			verified <- request
			return authority.Result{Decision: authority.DecisionAllow, Reason: authority.ReasonMatched}
		}),
	))
	defer cleanup()

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "CONNECT 127.0.0.1:6443 HTTP/1.1\r\nHost: 127.0.0.1:6443\r\n%s: grant\r\n\r\n", authority.HTTPHeader); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway || dialCalls.Load() != 1 {
		t.Fatalf("status=%d dial calls=%d, want 502/1", resp.StatusCode, dialCalls.Load())
	}
	request := <-verified
	if request.Actor == "" || request.AuthorityRef != "grant" || request.Action != "read" || request.Destination != "127.0.0.1:6443" {
		t.Fatalf("verification request = %+v", request)
	}
}

func TestWebSocketAuthorityDenyMakesNoUpstreamHandshake(t *testing.T) {
	t.Parallel()
	backend, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer func() { _ = backend.Close() }()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := backend.Accept()
		if acceptErr == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	proxyAddr, p, cleanup := setupWSProxyDefaultWithProxy(t, nil)
	defer cleanup()
	receiptHelper := newReceiptProxyHelperWithMetrics(t, p.metrics)
	p.receiptEmitterPtr.Store(receiptHelper.emitter)
	var verifierCalls atomic.Int32
	p.authorityVerifier = denyProxyAuthorityVerifier(&verifierCalls)
	conn, err := dialWSConnWithHeader(proxyAddr, backend.Addr().String(), http.Header{authority.HTTPHeader: {"grant"}})
	if err != nil {
		t.Fatalf("WebSocket client handshake: %v", err)
	}
	defer func() { _ = conn.Close() }()
	frame, op, err := wsutil.ReadServerData(conn)
	if err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), string(blockreason.AuthorityMismatch)) {
		t.Fatalf("read policy close: %v", err)
	}
	if err == nil && (op != ws.OpClose || !strings.Contains(string(frame), string(blockreason.AuthorityMismatch))) {
		t.Fatalf("close opcode=%v payload=%q", op, frame)
	}
	if verifierCalls.Load() != 1 {
		t.Fatalf("verifier calls = %d, want 1", verifierCalls.Load())
	}
	select {
	case <-accepted:
		t.Fatal("authority-denied WebSocket reached upstream listener")
	case <-time.After(100 * time.Millisecond):
	}
	assertSingleProxyAuthorityBlockReceipt(t, receiptHelper.findReceipts(t))
}

func TestWebSocketAuthorityDenyBeforeUpgradeWithRequiredReceipts(t *testing.T) {
	t.Parallel()
	backend, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	defer func() { _ = backend.Close() }()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := backend.Accept()
		if acceptErr == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	proxyAddr, p, cleanup := setupWSProxyDefaultWithProxy(t, func(cfg *config.Config) {
		cfg.FlightRecorder.RequireReceipts = true
	})
	defer cleanup()
	receiptHelper := newReceiptProxyHelperWithMetrics(t, p.metrics)
	p.receiptEmitterPtr.Store(receiptHelper.emitter)
	var verifierCalls atomic.Int32
	p.authorityVerifier = denyProxyAuthorityVerifier(&verifierCalls)
	resp := requestWSHandshake(t, proxyAddr, backend.Addr().String(), http.Header{authority.HTTPHeader: {"grant"}})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get(blockreason.HeaderReason); got != string(blockreason.AuthorityMismatch) {
		t.Fatalf("block reason = %q, want %q", got, blockreason.AuthorityMismatch)
	}
	if verifierCalls.Load() != 1 {
		t.Fatalf("verifier calls = %d, want 1", verifierCalls.Load())
	}
	select {
	case <-accepted:
		t.Fatal("authority-denied WebSocket reached upstream listener")
	case <-time.After(100 * time.Millisecond):
	}
	assertSingleProxyAuthorityBlockReceipt(t, receiptHelper.findReceipts(t))
}

func assertSingleProxyAuthorityBlockReceipt(t *testing.T, receipts []receipt.Receipt) {
	t.Helper()
	if len(receipts) != 1 {
		t.Fatalf("receipt count = %d, want exactly one authority denial", len(receipts))
	}
	record := receipts[0].ActionRecord
	if record.Verdict != config.ActionBlock || record.Layer != blockLayerAuthority {
		t.Fatalf("receipt verdict/layer = %q/%q, want %q/%q", record.Verdict, record.Layer, config.ActionBlock, blockLayerAuthority)
	}
}

func TestWebSocketAuthorityHeaderConsumedOnAllow(t *testing.T) {
	t.Parallel()
	seen := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(authority.HTTPHeader)
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer backend.Close()

	proxyAddr, p, cleanup := setupWSProxyDefaultWithProxy(t, nil)
	defer cleanup()
	verified := make(chan authority.Request, 1)
	p.authorityVerifier = proxyAuthorityVerifierFunc(func(_ context.Context, request authority.Request) authority.Result {
		verified <- request
		return authority.Result{Decision: authority.DecisionAllow, Reason: authority.ReasonMatched}
	})
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	conn, err := dialWSConnWithHeader(proxyAddr, backendURL.Host, http.Header{authority.HTTPHeader: {"grant"}})
	if err != nil {
		t.Fatalf("WebSocket client handshake: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if got := <-seen; got != "" {
		t.Fatalf("reserved header leaked in upstream WebSocket handshake: %q", got)
	}
	verificationRequest := <-verified
	if verificationRequest.Actor == "" || verificationRequest.AuthorityRef != "grant" || verificationRequest.Action != "delegate" || verificationRequest.Destination != "ws://"+backendURL.Host {
		t.Fatalf("verification request = %+v", verificationRequest)
	}
}
