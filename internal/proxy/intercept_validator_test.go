// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestInterceptChangedBodyValidators(t *testing.T) {
	for _, kind := range []string{"shield", "injection", "media", "clean"} {
		t.Run(kind, func(t *testing.T) {
			body := []byte("var ordinary=1;")
			contentType := "application/javascript"
			switch kind {
			case "shield":
				body = []byte(`<html><head></head><body><a href="chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/page.html">extension</a></body></html>`)
				contentType = "text/html"
			case "injection":
				body = []byte("safe text " + testInjectionPayload + " more text")
				contentType = "text/plain"
			case "media":
				body = buildValidPNG([]byte("Comment\x00ordinary metadata"))
				contentType = "image/png"
			}
			headers := map[string]string{"Content-Type": contentType, "ETag": "\"origin\"", "Last-Modified": "Wed, 01 Oct 2025 12:00:00 GMT", "Cache-Control": "public, max-age=31536000, immutable", "Expires": "Wed, 01 Oct 2031 12:00:00 GMT", "Digest": "fixture-digest", "Content-MD5": "fixture-md5"}
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for key, value := range headers {
					w.Header().Set(key, value)
				}
				_, _ = w.Write(body)
			}))
			defer upstream.Close()
			cache, pool, cfg, _, logger, m := testInterceptSetup(t)
			cfg.BrowserShield.Enabled = kind == "shield"
			cfg.ResponseScanning.Action = config.ActionStrip
			sc := scanner.MustNew(cfg)
			defer sc.Close()
			p, err := New(cfg, logger, sc, m)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+"/asset", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, p)
			defer func() { _ = resp.Body.Close() }()
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d", resp.StatusCode)
			}
			changed := kind != "clean"
			if bytes.Equal(got, body) == changed {
				t.Fatalf("body change control failed: changed=%t", changed)
			}
			for _, key := range []string{"ETag", "Last-Modified", "Digest", "Content-MD5"} {
				want := headers[key]
				if changed {
					want = ""
				}
				if got := resp.Header.Get(key); got != want {
					t.Fatalf("%s=%q want%q", key, got, want)
				}
			}
			for _, key := range []string{"Cache-Control", "Expires"} {
				if got := resp.Header.Get(key); got != headers[key] {
					t.Fatalf("%s changed to %q", key, got)
				}
			}
		})
	}
}
