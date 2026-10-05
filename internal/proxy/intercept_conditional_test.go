// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestInterceptConditionalPolicyReload(t *testing.T) {
	body := []byte("const ordinary_constant = 1;")
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("ETag", "\"origin\"")
		if r.Header.Get("If-None-Match") == "\"origin\"" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(body)
	}))
	defer upstream.Close()
	cache, pool, cfg, sc, logger, m := testInterceptSetup(t)
	request := func(tag string) *http.Request {
		r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+upstream.Listener.Addr().String()+"/asset.js", nil)
		if tag != "" {
			r.Header.Set("If-None-Match", tag)
		}
		return r
	}
	first := interceptAndRequest(t, upstream, cache, pool, cfg, sc, logger, m, request(""))
	_, _ = io.Copy(io.Discard, first.Body)
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatal("clean positive control failed")
	}
	tag := first.Header.Get("ETag")
	if tag != "\"origin\"" {
		t.Fatal("positive binding control missing")
	}
	updated := cfg.Clone()
	updated.ResponseScanning.Action = config.ActionBlock
	updated.ResponseScanning.Patterns = append(updated.ResponseScanning.Patterns, config.ResponseScanPattern{Name: "new generation", Regex: "ordinary_constant"})
	reloaded := scanner.MustNew(updated)
	defer reloaded.Close()
	if result := reloaded.ScanResponseBodyWithSuppress(t.Context(), body, "", nil); result.Clean {
		t.Fatal("new rule positive detection control failed")
	}
	next := interceptAndRequest(t, upstream, cache, pool, updated, reloaded, logger, m, request(tag))
	defer func() { _ = next.Body.Close() }()
	if next.StatusCode != http.StatusForbidden {
		t.Fatalf("policy reload status=%d, want full-body scan block", next.StatusCode)
	}
}

func TestInterceptConditionalFullScan(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, name := range []string{"If-None-Match", "If-Modified-Since", "If-Range"} {
					if r.Header.Get(name) != "" {
						t.Errorf("conditional reached upstream: %s", name)
						w.WriteHeader(http.StatusNotModified)
						return
					}
				}
				w.Header().Set("Content-Type", "application/javascript")
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				w.Header().Set("ETag", "\"origin\"")
				w.Header().Set("Last-Modified", "Wed, 01 Oct 2025 12:00:00 GMT")
				_, _ = w.Write([]byte("var clean=1;"))
			}))
			defer upstream.Close()
			cache, pool, cfg, sc, logger, m := testInterceptSetup(t)
			for _, name := range []string{"If-None-Match", "If-Modified-Since", "If-Range"} {
				req, _ := http.NewRequestWithContext(t.Context(), method, upstream.URL+"/asset.js", nil)
				req.Header.Set(name, "arbitrary-unapproved-validator")
				resp := interceptAndRequest(t, upstream, cache, pool, cfg, sc, logger, m, req)
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status=%d", resp.StatusCode)
				}
				for key, want := range map[string]string{"Cache-Control": "public, max-age=31536000, immutable", "ETag": "\"origin\"", "Last-Modified": "Wed, 01 Oct 2025 12:00:00 GMT"} {
					if got := resp.Header.Get(key); got != want {
						t.Fatalf("%s=%q want%q", key, got, want)
					}
				}
			}
		})
	}
}

func TestInterceptUnexpectedNotModified(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("ETag", "\"never-approved\"")
				w.WriteHeader(http.StatusNotModified)
			}))
			defer upstream.Close()
			cache, pool, cfg, sc, logger, m := testInterceptSetup(t)
			cfg.FlightRecorder.RequireReceipts = true
			p, err := New(cfg, logger, sc, m)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
			p.receiptEmitterPtr.Store(rph.emitter)
			req, err := http.NewRequestWithContext(t.Context(), method, upstream.URL+"/asset.js", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, p)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("status=%d want502", resp.StatusCode)
			}
			if resp.Header.Get("ETag") != "" {
				t.Fatal("unapproved validator released")
			}
			receipts := rph.findReceipts(t)
			var blocks int
			for _, r := range receipts {
				if r.ActionRecord.Verdict == config.ActionBlock {
					blocks++
				}
			}
			if blocks < 2 {
				t.Fatalf("block and outcome evidence missing: blocks=%d", blocks)
			}
		})
	}
}
