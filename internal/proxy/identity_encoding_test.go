// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// browserAcceptEncoding is what a current desktop browser sends.
const browserAcceptEncoding = "gzip, deflate, br, zstd"

const identityCleanBody = "<html><body>ordinary browser page</body></html>"

// negotiatingUpstream behaves like a CDN that honours content negotiation: when
// the request advertises br or zstd it answers with that coding, which Pipelock
// cannot decode and must refuse; it serves identity bytes only when the request
// does not advertise one of them. A proxy that forwards the browser's
// Accept-Encoding therefore gets a 403 compressed_response, which is the
// defect this file guards. The upstream records every Accept-Encoding it saw.
type negotiatingUpstream struct {
	body string

	mu   sync.Mutex
	seen []string
}

func (u *negotiatingUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ae := r.Header.Get("Accept-Encoding")
	u.mu.Lock()
	u.seen = append(u.seen, ae)
	u.mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	for _, coding := range strings.Split(ae, ",") {
		coding = strings.ToLower(strings.TrimSpace(coding))
		if coding == "br" || coding == "zstd" {
			w.Header().Set("Content-Encoding", coding)
			// Opaque bytes: Pipelock has no decoder for these codings.
			_, _ = w.Write([]byte{0x1b, 0x2c, 0x00, 0xf8, 0x25, 0x83})
			return
		}
	}
	_, _ = io.WriteString(w, u.body)
}

func (u *negotiatingUpstream) requireIdentityOnly(t *testing.T) {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.seen) == 0 {
		t.Fatal("upstream was never reached")
	}
	for _, got := range u.seen {
		if got != "identity" {
			t.Errorf("upstream Accept-Encoding = %q, want identity", got)
		}
	}
}

type identityEncodingCase struct {
	name       string
	body       string
	wantStatus int
}

func identityEncodingCases() []identityEncodingCase {
	return []identityEncodingCase{
		{name: "clean page delivered", body: identityCleanBody, wantStatus: http.StatusOK},
		{name: "injection still blocked", body: "<html><body>" + testInjectionPayload + "</body></html>", wantStatus: http.StatusForbidden},
	}
}

func TestForwardProxy_BrowserAcceptEncodingRequestsIdentity(t *testing.T) {
	for _, tc := range identityEncodingCases() {
		t.Run(tc.name, func(t *testing.T) {
			up := &negotiatingUpstream{body: tc.body}
			backend := newIPv4Server(t, up)
			defer backend.Close()

			proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.Action = config.ActionBlock
			})
			defer cleanup()

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, backend.URL+"/page", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Accept-Encoding", browserAcceptEncoding)
			// The client transport must not decode on our behalf: a
			// browser-faithful client sees exactly what Pipelock returned.
			proxyURL, err := url.Parse("http://" + proxyAddr)
			if err != nil {
				t.Fatalf("parse proxy address: %v", err)
			}
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableCompression: true}}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			got, _ := io.ReadAll(resp.Body)

			up.requireIdentityOnly(t)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, tc.wantStatus, got)
			}
			if tc.wantStatus == http.StatusOK && string(got) != tc.body {
				t.Fatalf("body = %q, want %q", got, tc.body)
			}
		})
	}
}

func TestFetchProxy_BrowserAcceptEncodingRequestsIdentity(t *testing.T) {
	for _, tc := range identityEncodingCases() {
		t.Run(tc.name, func(t *testing.T) {
			up := &negotiatingUpstream{body: tc.body}
			backend := newIPv4Server(t, up)
			defer backend.Close()

			cfg := config.Defaults()
			cfg.FetchProxy.TimeoutSeconds = 5
			cfg.Internal = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
			cfg.APIAllowlist = nil
			cfg.ResponseScanning.Enabled = true
			cfg.ResponseScanning.Action = config.ActionBlock
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				t.Fatalf("proxy.New: %v", err)
			}
			t.Cleanup(p.Close)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(backend.URL+"/page"), nil)
			req.Header.Set("Accept-Encoding", browserAcceptEncoding)
			w := httptest.NewRecorder()
			p.handleFetch(w, req)

			up.requireIdentityOnly(t)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			var fr FetchResponse
			if err := json.Unmarshal(w.Body.Bytes(), &fr); err != nil {
				t.Fatalf("decode fetch response: %v", err)
			}
			if tc.wantStatus == http.StatusOK && !strings.Contains(fr.Content, "ordinary browser page") {
				t.Fatalf("content = %q, want the page text", fr.Content)
			}
			if tc.wantStatus == http.StatusForbidden && !fr.Blocked {
				t.Fatal("expected blocked=true")
			}
		})
	}
}

func TestReverseProxy_BrowserAcceptEncodingRequestsIdentity(t *testing.T) {
	for _, tc := range identityEncodingCases() {
		t.Run(tc.name, func(t *testing.T) {
			up := &negotiatingUpstream{body: tc.body}
			proxy := reverseTestSetup(t, reverseTestConfig(), up.ServeHTTP)

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, proxy.URL+"/page", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Accept-Encoding", browserAcceptEncoding)
			client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			got, _ := io.ReadAll(resp.Body)

			up.requireIdentityOnly(t)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, tc.wantStatus, got)
			}
			if tc.wantStatus == http.StatusOK && string(got) != tc.body {
				t.Fatalf("body = %q, want %q", got, tc.body)
			}
		})
	}
}

// TestTLSIntercept_BrowserAcceptEncodingRequestsIdentity is the control: the
// intercept path already requested identity before the other transports did.
func TestTLSIntercept_BrowserAcceptEncodingRequestsIdentity(t *testing.T) {
	for _, tc := range identityEncodingCases() {
		t.Run(tc.name, func(t *testing.T) {
			up := &negotiatingUpstream{body: tc.body}
			upstream := httptest.NewTLSServer(up)
			defer upstream.Close()

			cache, pool, cfg, _, logger, m := testInterceptSetup(t)
			cfg.ResponseScanning.Enabled = true
			cfg.ResponseScanning.Action = config.ActionBlock
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+upstream.Listener.Addr().String()+"/page", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Accept-Encoding", browserAcceptEncoding)
			resp := interceptAndRequest(t, upstream, cache, pool, cfg, sc, logger, m, req)
			defer func() { _ = resp.Body.Close() }()
			got, _ := io.ReadAll(resp.Body)

			up.requireIdentityOnly(t)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, tc.wantStatus, got)
			}
			if tc.wantStatus == http.StatusOK && string(got) != tc.body {
				t.Fatalf("body = %q, want %q", got, tc.body)
			}
		})
	}
}
