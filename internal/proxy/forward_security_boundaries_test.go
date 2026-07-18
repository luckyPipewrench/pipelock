// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type forwardBoundaryRoundTripper func(*http.Request) (*http.Response, error)

func (f forwardBoundaryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type forwardBoundaryReadCloser struct {
	reader io.Reader
	closed atomic.Bool
}

func (r *forwardBoundaryReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *forwardBoundaryReadCloser) Close() error {
	r.closed.Store(true)
	return nil
}

func newForwardBoundaryProxy(t *testing.T, cfgMod func(*config.Config), rt http.RoundTripper) *Proxy {
	t.Helper()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = true
	if cfgMod != nil {
		cfgMod(cfg)
	}

	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		sc.Close()
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)
	p.client.Transport = rt
	return p
}

func disableForwardBoundaryResponseTransforms(cfg *config.Config) {
	disabled := false
	cfg.ResponseScanning.Enabled = false
	cfg.BrowserShield.Enabled = false
	cfg.MediaPolicy.Enabled = &disabled
}

func TestForwardSecurityBoundary_RequestBodyReadFailurePreventsEgress(t *testing.T) {
	var roundTrips atomic.Int32
	p := newForwardBoundaryProxy(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.MaxBodyBytes = 1024
	}, forwardBoundaryRoundTripper(func(*http.Request) (*http.Response, error) {
		roundTrips.Add(1)
		return nil, errors.New("outbound transport must not run")
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://api.vendor.example/upload", &errorReader{n: 4, err: io.ErrUnexpectedEOF})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	p.handleForwardHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", rec.Code, rec.Body.String())
	}
	if roundTrips.Load() != 0 {
		t.Fatalf("outbound round trips = %d, want 0 after an incomplete body scan", roundTrips.Load())
	}
	if !strings.Contains(rec.Body.String(), "error reading request body") {
		t.Fatalf("response does not identify the fail-closed body read: %q", rec.Body.String())
	}
}

func TestForwardSecurityBoundary_StripsConnectionNamedAndIdentityHeaders(t *testing.T) {
	var sawOutbound atomic.Bool
	p := newForwardBoundaryProxy(t, disableForwardBoundaryResponseTransforms,
		forwardBoundaryRoundTripper(func(req *http.Request) (*http.Response, error) {
			sawOutbound.Store(true)
			if req.RequestURI != "" {
				t.Errorf("outbound RequestURI = %q, want empty", req.RequestURI)
			}
			if got := req.URL.Query().Get(agentQueryParam); got != "" {
				t.Errorf("outbound agent query = %q, want stripped", got)
			}
			if got := req.URL.Query().Get("keep"); got != "yes" {
				t.Errorf("unrelated outbound query = %q, want yes", got)
			}
			for _, name := range []string{
				AgentHeader,
				"Connection",
				"X-Hop-Secret",
				"Proxy-Authorization",
				"Forwarded",
				"X-Forwarded-For",
				"Via",
			} {
				if got := req.Header.Get(name); got != "" {
					t.Errorf("outbound header %s leaked with value %q", name, got)
				}
			}
			if got := req.Header.Get("X-End-To-End"); got != "preserved" {
				t.Errorf("end-to-end header = %q, want preserved", got)
			}
			return &http.Response{
				StatusCode: http.StatusPartialContent,
				Header: http.Header{
					"Connection":         {"X-Upstream-Hop"},
					"X-Upstream-Hop":     {"must-not-leak"},
					"Proxy-Authenticate": {"Basic realm=upstream"},
					"Content-Length":     {"999"},
					"X-End-To-End":       {"response-preserved"},
				},
				Body:    io.NopCloser(strings.NewReader("bounded response")),
				Request: req,
			}, nil
		}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"http://api.vendor.example/resource?agent=spoofed&keep=yes", nil)
	req.Header.Set(AgentHeader, "spoofed-agent")
	req.Header.Set("Connection", "X-Hop-Secret")
	req.Header.Set("X-Hop-Secret", "must-not-leak")
	req.Header.Set("Proxy-Authorization", "Basic must-not-leak")
	req.Header.Set("Forwarded", "for=198.51.100.10")
	req.Header.Set("X-Forwarded-For", "198.51.100.10")
	req.Header.Set("Via", "attacker-controlled")
	req.Header.Set("X-End-To-End", "preserved")
	rec := httptest.NewRecorder()

	p.handleForwardHTTP(rec, req)

	if !sawOutbound.Load() {
		t.Fatal("outbound transport was not reached")
	}
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206; body=%q", rec.Code, rec.Body.String())
	}
	for _, name := range []string{"Connection", "X-Upstream-Hop", "Proxy-Authenticate", "Content-Length"} {
		if got := rec.Header().Get(name); got != "" {
			t.Errorf("client response header %s leaked with value %q", name, got)
		}
	}
	if got := rec.Header().Get("X-End-To-End"); got != "response-preserved" {
		t.Errorf("client response end-to-end header = %q, want response-preserved", got)
	}
	if got := rec.Body.String(); got != "bounded response" {
		t.Errorf("client response body = %q, want bounded response", got)
	}
}

func TestForwardSecurityBoundary_CancellationReachesOutboundTransport(t *testing.T) {
	entered := make(chan struct{})
	transportDone := make(chan error, 1)
	p := newForwardBoundaryProxy(t, disableForwardBoundaryResponseTransforms,
		forwardBoundaryRoundTripper(func(req *http.Request) (*http.Response, error) {
			close(entered)
			<-req.Context().Done()
			err := req.Context().Err()
			transportDone <- err
			return nil, err
		}))

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://api.vendor.example/slow", nil)
	rec := httptest.NewRecorder()
	handlerDone := make(chan struct{})
	go func() {
		p.handleForwardHTTP(rec, req)
		close(handlerDone)
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("outbound transport was not entered")
	}
	cancel()

	select {
	case err := <-transportDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("outbound context error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("outbound transport did not observe request cancellation")
	}
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("forward handler did not return after request cancellation")
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 after canceled outbound request; body=%q", rec.Code, rec.Body.String())
	}
}

func TestForwardSecurityBoundary_TransportFailuresReturnSanitizedBadGateway(t *testing.T) {
	tests := []struct {
		name string
		rt   forwardBoundaryRoundTripper
	}{
		{
			name: "transport error",
			rt: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("dial failed with secret-token-marker")
			},
		},
		{
			name: "nil response without error",
			rt: func(*http.Request) (*http.Response, error) {
				return nil, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newForwardBoundaryProxy(t, disableForwardBoundaryResponseTransforms, tt.rt)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
				"http://api.vendor.example/failure", nil)
			rec := httptest.NewRecorder()

			p.handleForwardHTTP(rec, req)

			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502; body=%q", rec.Code, rec.Body.String())
			}
			if got := rec.Body.String(); got != "forward proxy fetch failed\n" {
				t.Fatalf("client-visible error = %q, want sanitized proxy error", got)
			}
			if strings.Contains(rec.Body.String(), "secret-token-marker") {
				t.Fatal("transport error detail leaked to the client")
			}
		})
	}
}

func TestForwardSecurityBoundary_ResponseReadFailureClosesBodyWithoutLeak(t *testing.T) {
	body := &forwardBoundaryReadCloser{
		reader: io.MultiReader(strings.NewReader("upstream-prefix-must-not-leak"), &errorReader{
			err: io.ErrUnexpectedEOF,
		}),
	}
	p := newForwardBoundaryProxy(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = true
		cfg.ResponseScanning.Action = config.ActionBlock
	}, forwardBoundaryRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": {"text/plain"},
				"Set-Cookie":   {"session=must-not-leak"},
				"X-Upstream":   {"must-not-leak"},
			},
			Body:    body,
			Request: req,
		}, nil
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"http://api.vendor.example/broken-response", nil)
	rec := httptest.NewRecorder()

	p.handleForwardHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", rec.Code, rec.Body.String())
	}
	if !body.closed.Load() {
		t.Fatal("upstream response body was not closed after the read failure")
	}
	if got := rec.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("blocked response leaked Set-Cookie %q", got)
	}
	if got := rec.Header().Get("X-Upstream"); got != "" {
		t.Fatalf("blocked response leaked X-Upstream %q", got)
	}
	if strings.Contains(rec.Body.String(), "upstream-prefix-must-not-leak") {
		t.Fatalf("blocked response leaked partially read payload: %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "response read error") {
		t.Fatalf("block response = %q, want response read error", rec.Body.String())
	}
}

func TestForwardSecurityBoundary_CompressedResponseClosesBodyWithoutLeak(t *testing.T) {
	body := &forwardBoundaryReadCloser{reader: strings.NewReader("compressed-payload-must-not-leak")}
	p := newForwardBoundaryProxy(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = true
		cfg.ResponseScanning.Action = config.ActionBlock
	}, forwardBoundaryRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":     {"text/plain"},
				"Content-Encoding": {"gzip"},
				"Set-Cookie":       {"session=must-not-leak"},
				"X-Upstream":       {"must-not-leak"},
			},
			Body:    body,
			Request: req,
		}, nil
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"http://api.vendor.example/compressed-response", nil)
	rec := httptest.NewRecorder()

	p.handleForwardHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", rec.Code, rec.Body.String())
	}
	if !body.closed.Load() {
		t.Fatal("upstream compressed response body was not closed")
	}
	for _, name := range []string{"Content-Encoding", "Set-Cookie", "X-Upstream"} {
		if got := rec.Header().Get(name); got != "" {
			t.Errorf("blocked response header %s leaked with value %q", name, got)
		}
	}
	if strings.Contains(rec.Body.String(), "compressed-payload-must-not-leak") {
		t.Fatalf("blocked response leaked compressed payload: %q", rec.Body.String())
	}
}
