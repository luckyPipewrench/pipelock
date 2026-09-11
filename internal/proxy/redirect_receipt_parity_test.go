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
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const redirectReceiptRuleName = "block-redirect-target"

// redirectReceiptParityProxy builds a proxy handler that dials the given backend
// for both the source and redirect-target hostnames, with request_policy set to
// block method to api.vendor.example. When rph is non-nil the proxy records
// receipts; when nil, receipt emission is unavailable so the request_policy
// block records no receipt. It returns the handler for in-process serving.
func redirectReceiptParityProxy(t *testing.T, rph *receiptProxyHelper, backend *httptest.Server, method string) http.Handler {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = true
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.RequestPolicy.Enabled = true
	cfg.RequestPolicy.Rules = []config.RequestPolicyRule{{
		Name:   redirectReceiptRuleName,
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{"api.vendor.example"}, Methods: []string{method}},
		Reason: "redirect target requires operator approval",
	}}

	logger := audit.NewNop()
	sc := scanner.MustNew(cfg)
	var opts []Option
	if rph != nil {
		rph.cfg = cfg
		opts = append(opts, WithRecorder(rph.rec), WithReceiptEmitter(rph.emitter))
	}
	p, err := New(cfg, logger, sc, metrics.New(), opts...)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	// Replace only the transport so p.client's CheckRedirect closure (the
	// production redirect enforcement path under test) still runs, while the
	// two test hostnames resolve to the loopback backend.
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
	return p.buildHandler(p.buildMux())
}

// redirectReceiptBackend serves a redirect from source.vendor.example to
// api.vendor.example. redirectedHits counts any request that reached the
// redirect target, which must stay zero because the redirect is blocked in
// CheckRedirect before the redirected request is dispatched.
//
// sourceHits counts requests that reached the redirect SOURCE, and callers
// require exactly one. Without it, redirectedHits == 0 is satisfied just as
// well by a proxy that blocked the initial request and never followed a
// redirect at all, so the test would pass while proving nothing about
// redirect-hop enforcement.
func redirectReceiptBackend(t *testing.T, status int, redirectedHits, sourceHits *atomic.Int32) *httptest.Server {
	t.Helper()
	return newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "source.vendor.example" {
			if sourceHits != nil {
				sourceHits.Add(1)
			}
			http.Redirect(w, r, "http://api.vendor.example/auth/update", status)
			return
		}
		redirectedHits.Add(1)
		_, _ = io.WriteString(w, "unexpected redirected egress")
	}))
}

// requireRedirectRecordedReceipt pins the truthfulness invariant: when a
// redirect request_policy block advertises a recorded-receipt id, that id names
// a receipt that actually recorded, at the request_policy layer with a block
// verdict. It does NOT assert WHICH request_policy receipt (the decision receipt
// vs the transport block receipt) - both are recorded and truthful on this SHA,
// and which one a redirect block should advertise is an open decision recorded
// in BUILD-OUT.md. The header must never be empty when the emitter works or the
// caller loses its correlation handle to the recorded evidence.
func requireRedirectRecordedReceipt(t *testing.T, receipts []receipt.Receipt, headerID string) {
	t.Helper()
	if headerID == "" {
		t.Fatalf("%s is empty; the redirect block did not advertise any recorded receipt", blockreason.HeaderRecordedReceipt)
	}
	for _, r := range receipts {
		if r.ActionRecord.ActionID != headerID {
			continue
		}
		if r.ActionRecord.Layer != blockLayerRequestPolicy {
			t.Fatalf("advertised receipt layer = %q, want %q", r.ActionRecord.Layer, blockLayerRequestPolicy)
		}
		if got := receipt.NormalizeVerdict(r.ActionRecord.Verdict); got != receipt.NormalizeVerdict(config.ActionBlock) {
			t.Fatalf("advertised receipt verdict = %q, want block", got)
		}
		return
	}
	var ids []string
	for _, r := range receipts {
		ids = append(ids, r.ActionRecord.ActionID+"("+r.ActionRecord.Layer+"/"+r.ActionRecord.Pattern+")")
	}
	t.Fatalf("%s = %q names no recorded receipt; recorded: %v", blockreason.HeaderRecordedReceipt, headerID, ids)
}

// TestForwardRedirect_RequestPolicyBlockAdvertisesRecordedReceipt proves the
// forward-proxy redirect request_policy block advertises a truthful recorded
// receipt id (currently the transport block receipt; see BUILD-OUT.md for the
// open which-receipt parity decision).
func TestForwardRedirect_RequestPolicyBlockAdvertisesRecordedReceipt(t *testing.T) {
	var redirectedHits, sourceHits atomic.Int32
	// 307 preserves the POST method so the POST-scoped rule matches on hop 2.
	// A bodyless POST avoids the redirect-body-replay guard, which would block
	// earlier as body_dlp rather than exercising the request_policy path.
	backend := redirectReceiptBackend(t, http.StatusTemporaryRedirect, &redirectedHits, &sourceHits)
	defer backend.Close()

	rph := newReceiptProxyHelper(t)
	h := redirectReceiptParityProxy(t, rph, backend, http.MethodPost)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://source.vendor.example/start", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := rec.Header().Get(blockreason.HeaderReason); got != string(blockreason.RequestPolicyDeny) {
		t.Fatalf("%s = %q, want %q", blockreason.HeaderReason, got, blockreason.RequestPolicyDeny)
	}
	if redirectedHits.Load() != 0 {
		t.Fatalf("redirected egress hits = %d, want 0", redirectedHits.Load())
	}
	if sourceHits.Load() != 1 {
		t.Fatalf("redirect source hits = %d, want exactly 1; the request must reach the source and be blocked on the redirect hop, not before it", sourceHits.Load())
	}
	headerID := rec.Header().Get(blockreason.HeaderRecordedReceipt)
	requireRedirectRecordedReceipt(t, rph.findReceipts(t), headerID)
}

// TestFetchRedirect_RequestPolicyBlockAdvertisesRecordedReceipt proves the same
// for the fetch-mode redirect chain.
func TestFetchRedirect_RequestPolicyBlockAdvertisesRecordedReceipt(t *testing.T) {
	var redirectedHits, sourceHits atomic.Int32
	// Fetch is always GET; 302 preserves GET so the GET-scoped rule matches on
	// hop 2.
	backend := redirectReceiptBackend(t, http.StatusFound, &redirectedHits, &sourceHits)
	defer backend.Close()

	rph := newReceiptProxyHelper(t)
	h := redirectReceiptParityProxy(t, rph, backend, http.MethodGet)

	requestURL := "/fetch?url=" + url.QueryEscape("http://source.vendor.example/start")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, requestURL, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := rec.Header().Get(blockreason.HeaderReason); got != string(blockreason.RequestPolicyDeny) {
		t.Fatalf("%s = %q, want %q", blockreason.HeaderReason, got, blockreason.RequestPolicyDeny)
	}
	if redirectedHits.Load() != 0 {
		t.Fatalf("redirected egress hits = %d, want 0", redirectedHits.Load())
	}
	if sourceHits.Load() != 1 {
		t.Fatalf("redirect source hits = %d, want exactly 1; the request must reach the source and be blocked on the redirect hop, not before it", sourceHits.Load())
	}
	headerID := rec.Header().Get(blockreason.HeaderRecordedReceipt)
	requireRedirectRecordedReceipt(t, rph.findReceipts(t), headerID)
}

// TestRedirect_RequestPolicyBlockWithoutRecordedReceiptOmitsHeader proves the
// fail-closed direction: when receipt emission is unavailable on the redirect
// hop, the block still fires but advertises no receipt id (advertising an
// unrecorded id would be the #1151 defect in reverse). Covers both transports.
func TestRedirect_RequestPolicyBlockWithoutRecordedReceiptOmitsHeader(t *testing.T) {
	tests := []struct {
		name   string
		method string
		status int
		build  func(h http.Handler) (*httptest.ResponseRecorder, *http.Request)
	}{
		{
			name:   "forward",
			method: http.MethodPost,
			status: http.StatusTemporaryRedirect,
			build: func(http.Handler) (*httptest.ResponseRecorder, *http.Request) {
				return httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://source.vendor.example/start", nil)
			},
		},
		{
			name:   "fetch",
			method: http.MethodGet,
			status: http.StatusFound,
			build: func(http.Handler) (*httptest.ResponseRecorder, *http.Request) {
				requestURL := "/fetch?url=" + url.QueryEscape("http://source.vendor.example/start")
				return httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, requestURL, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var redirectedHits, sourceHits atomic.Int32
			backend := redirectReceiptBackend(t, tt.status, &redirectedHits, &sourceHits)
			defer backend.Close()

			// No receiptProxyHelper: emitter unavailable, so request_policy
			// records no receipt for the block.
			h := redirectReceiptParityProxy(t, nil, backend, tt.method)
			rec, req := tt.build(h)
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
			if got := rec.Header().Get(blockreason.HeaderReason); got != string(blockreason.RequestPolicyDeny) {
				t.Fatalf("%s = %q, want %q (block must still fire)", blockreason.HeaderReason, got, blockreason.RequestPolicyDeny)
			}
			if got := rec.Header().Get(blockreason.HeaderRecordedReceipt); got != "" {
				t.Fatalf("%s = %q, want empty when no receipt recorded", blockreason.HeaderRecordedReceipt, got)
			}
			if redirectedHits.Load() != 0 {
				t.Fatalf("redirected egress hits = %d, want 0", redirectedHits.Load())
			}
			if sourceHits.Load() != 1 {
				t.Fatalf("redirect source hits = %d, want exactly 1; the request must reach the source and be blocked on the redirect hop, not before it", sourceHits.Load())
			}
		})
	}
}
