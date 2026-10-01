// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestRedirect_RateLimitCountsActualRequests(t *testing.T) {
	for _, mode := range []string{TransportForward, TransportFetch} {
		t.Run(mode, func(t *testing.T) {
			var initial, final atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					initial.Add(1)
					http.Redirect(w, r, "/final", http.StatusSeeOther)
					return
				}
				final.Add(1)
				_, _ = io.WriteString(w, "Synthetic final")
			}))
			t.Cleanup(origin.Close)
			client, base, _, p := newBrowserContractProxyClient(t, origin.URL, func(cfg *config.Config) {
				cfg.FetchProxy.Monitoring.MaxReqPerMinute = 2
			})
			if mode == TransportForward {
				resp, body, err := browserContractRequest(t, client, http.MethodGet, base+"/start", "")
				assertBrowserContractRedirect(t, resp, body, err, "/start", "/final")
				resp, body, err = browserContractRequest(t, client, http.MethodGet, base+"/final", "")
				assertBrowserContractResponse(t, resp, body, err, "/final", "Synthetic final")
				resp, body, err = browserContractRequest(t, client, http.MethodGet, base+"/final", "")
				if err != nil || resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get(blockreason.HeaderReason) != string(blockreason.RateLimit) {
					t.Fatalf("third request: status=%d headers=%v body=%q error=%v", resp.StatusCode, resp.Header, body, err)
				}
			} else {
				for _, path := range []string{"/start", "/final"} {
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(base+path), nil)
					rec := httptest.NewRecorder()
					p.handleFetch(rec, req)
					if path == "/start" {
						if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Synthetic final") {
							t.Fatalf("fetch chain: status=%d body=%q", rec.Code, rec.Body.String())
						}
					} else if rec.Code != http.StatusTooManyRequests || rec.Header().Get(blockreason.HeaderReason) != string(blockreason.RateLimit) {
						t.Fatalf("third fetch request: status=%d headers=%v body=%q", rec.Code, rec.Header(), rec.Body.String())
					}
				}
			}
			if initial.Load() != 1 || final.Load() != 1 {
				t.Fatalf("upstream requests: initial=%d final=%d, want 1 each", initial.Load(), final.Load())
			}
		})
	}
}

func TestForwardRedirect_RatePreflightDoesNotConsumeTarget(t *testing.T) {
	const targetHost = "target.other.example"
	for _, exhausted := range []bool{false, true} {
		name := "unfollowed"
		if exhausted {
			name = "exhausted_target"
		}
		t.Run(name, func(t *testing.T) {
			var initial, final atomic.Int32
			var targetURL string
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					initial.Add(1)
					http.Redirect(w, r, targetURL+"/final", http.StatusSeeOther)
					return
				}
				final.Add(1)
				_, _ = io.WriteString(w, "Synthetic final")
			}))
			targetURL = browserRedirectOrigin(t, "http://"+origin.Listener.Addr().String(), targetHost)
			origin.Start()
			t.Cleanup(origin.Close)
			client, base, _, _ := newBrowserContractProxyClient(t, origin.URL, func(cfg *config.Config) {
				cfg.FetchProxy.Monitoring.MaxReqPerMinute = 1
				cfg.APIAllowlist = append(cfg.APIAllowlist, targetHost)
				cfg.TrustedDomains = append(cfg.TrustedDomains, targetHost)
				cfg.DNS.HostOverrides[targetHost] = []string{"127.0.0.1"}
			})
			if exhausted {
				resp, body, err := browserContractRequest(t, client, http.MethodGet, targetURL+"/final", "")
				assertBrowserContractResponse(t, resp, body, err, "/final", "Synthetic final")
			}
			resp, body, err := browserContractRequest(t, client, http.MethodGet, base+"/start", "")
			if exhausted {
				if err != nil || resp.StatusCode != http.StatusForbidden || resp.Header.Get(blockreason.HeaderReason) != string(blockreason.RedirectScanDenied) || resp.Header.Get(blockreason.HeaderLayer) != scanner.ScannerRateLimit {
					t.Fatalf("exhausted target preflight: status=%d headers=%v body=%q error=%v", resp.StatusCode, resp.Header, body, err)
				}
			} else {
				assertBrowserContractRedirect(t, resp, body, err, "/start", targetURL+"/final")
				if final.Load() != 0 {
					t.Fatal("unfollowed redirect dispatched a target request")
				}
				resp, body, err = browserContractRequest(t, client, http.MethodGet, targetURL+"/final", "")
				assertBrowserContractResponse(t, resp, body, err, "/final", "Synthetic final")
			}
			resp, body, err = browserContractRequest(t, client, http.MethodGet, targetURL+"/final", "")
			if err != nil || resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get(blockreason.HeaderReason) != string(blockreason.RateLimit) || initial.Load() != 1 || final.Load() != 1 {
				t.Fatalf("target boundary: status=%d initial=%d final=%d body=%q error=%v", resp.StatusCode, initial.Load(), final.Load(), body, err)
			}
		})
	}
}

func TestForwardRedirect_RateLimitConcurrentActualRequests(t *testing.T) {
	var initial, final atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			initial.Add(1)
			http.Redirect(w, r, "/final", http.StatusSeeOther)
			return
		}
		final.Add(1)
		_, _ = io.WriteString(w, "Synthetic final")
	}))
	t.Cleanup(origin.Close)
	client, base, _, _ := newBrowserContractProxyClient(t, origin.URL, func(cfg *config.Config) {
		cfg.FetchProxy.Monitoring.MaxReqPerMinute = 2
	})
	resp, body, err := browserContractRequest(t, client, http.MethodGet, base+"/start", "")
	assertBrowserContractRedirect(t, resp, body, err, "/start", "/final")

	const requests = 8
	type outcome struct {
		status int
		reason string
		err    error
	}
	outcomes := make(chan outcome, requests)
	start := make(chan struct{})
	for range requests {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/final", nil)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			<-start
			resp, err := client.Do(req)
			if err != nil {
				outcomes <- outcome{err: err}
				return
			}
			_, readErr := io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			outcomes <- outcome{status: resp.StatusCode, reason: resp.Header.Get(blockreason.HeaderReason), err: readErr}
		}()
	}
	close(start)
	allowed, denied := 0, 0
	for range requests {
		got := <-outcomes
		switch {
		case got.err != nil:
			t.Errorf("concurrent request: %v", got.err)
		case got.status == http.StatusOK:
			allowed++
		case got.status == http.StatusTooManyRequests && got.reason == string(blockreason.RateLimit):
			denied++
		default:
			t.Errorf("unexpected concurrent response: %+v", got)
		}
	}
	if allowed != 1 || denied != requests-1 || initial.Load() != 1 || final.Load() != 1 {
		t.Fatalf("admission bound: allowed=%d denied=%d initial=%d final=%d", allowed, denied, initial.Load(), final.Load())
	}
}
