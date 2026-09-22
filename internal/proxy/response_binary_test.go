// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestOpaqueBinaryPatternBytesPassAcrossHTTPHandlers(t *testing.T) {
	body := opaqueBinaryResponseFixture()
	for _, transport := range []string{"fetch", "forward", "intercept"} {
		t.Run(transport, func(t *testing.T) {
			cfg := testScannerConfig()
			cfg.Internal = nil
			cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"93.184.216.34"}}
			cfg.DLP.ScanEnv = false
			cfg.ResponseScanning.Enabled = true
			cfg.ResponseScanning.Action = config.ActionBlock
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			m := metrics.New()
			p, err := New(cfg, audit.NewNop(), sc, m)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			rt := forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": {"application/octet-stream"}},
					Body:       io.NopCloser(bytes.NewReader(body)),
					Request:    r,
				}, nil
			})
			p.client = &http.Client{Transport: rt}
			target := "http://api.vendor.example/payload"
			requestURL := target
			if transport == "fetch" {
				requestURL = "/fetch?url=" + target
			}
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, requestURL, nil)
			w := httptest.NewRecorder()
			switch transport {
			case "fetch":
				p.handleFetch(w, r)
			case "forward":
				p.handleForwardHTTP(w, r)
			case "intercept":
				h := newInterceptHandler(&InterceptContext{
					TargetHost: "api.vendor.example",
					TargetPort: "443",
					Config:     cfg,
					Scanner:    sc,
					Logger:     audit.NewNop(),
					Metrics:    m,
					ClientIP:   "192.0.2.1",
					RequestID:  "binary-response",
					Proxy:      p,
				}, rt)
				h.ServeHTTP(w, r)
			}
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.Bytes())
			}
			if transport == "fetch" {
				var response FetchResponse
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatalf("decode fetch response: %v", err)
				}
				if response.Blocked || response.StatusCode != http.StatusOK {
					t.Fatalf("fetch response = %+v, want allowed upstream 200", response)
				}
			} else if !bytes.Equal(w.Body.Bytes(), body) {
				t.Fatal("opaque response body changed in transit")
			}
		})
	}
}

func TestOpaqueBinaryPatternBytesPassReverse(t *testing.T) {
	body := opaqueBinaryResponseFixture()
	cfg := testScannerConfig()
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = config.ActionBlock
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)
	target, err := url.Parse("http://api.vendor.example/payload")
	if err != nil {
		t.Fatal(err)
	}
	rp := NewReverseProxy(target, &cfgPtr, &scPtr, audit.NewNop(), metrics.New(), killswitch.New(cfg), nil, nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/octet-stream"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    httptest.NewRequestWithContext(t.Context(), http.MethodGet, target.String(), nil),
	}
	if err := rp.modifyResponse(resp); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", resp.StatusCode, got)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("opaque response body changed in transit")
	}
}

func opaqueBinaryResponseFixture() []byte {
	body := bytes.Repeat([]byte{0x00, 0xff, 0x01, 0x80}, 1024)
	copy(body[2048:], []byte{0x00, 'D', 'A', 'N', 0x00})
	return body
}
