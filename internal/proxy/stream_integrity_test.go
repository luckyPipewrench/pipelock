// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const integritySSEBody = "data: integrity-event\n\n"

// Replay capture and other direct handler callers use a recorder rather than
// net/http's panic recovery. They must retain the incomplete outcome and return;
// a server must instead close the connection without completing the body.
func TestStreamAbortServerAndRecorder(t *testing.T) {
	for _, transport := range []string{"forward", "intercept"} {
		for _, caller := range []string{"recorder", "server"} {
			t.Run(transport+"/"+caller, func(t *testing.T) {
				payload := strings.Repeat("download prefix\n", 1024)
				upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/plain")
					_, _ = io.WriteString(w, payload)
					w.(http.Flusher).Flush()
					panic(http.ErrAbortHandler)
				}))
				t.Cleanup(upstream.Close)
				cfg := reverseTestConfig()
				cfg.ForwardProxy.Enabled = true
				cfg.TLSInterception.Enabled = true
				cfg.FetchProxy.TimeoutSeconds = 10
				cfg.FlightRecorder.RequireReceipts = true
				integrityExempt(cfg)
				rph := newReceiptProxyHelper(t)
				auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
				logger, err := audit.New("json", "file", auditPath, false, false)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(logger.Close)
				handler := integrityHandler(t, transport, cfg, upstream, logger, rph)
				if caller == "recorder" {
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.vendor.example/payload", nil))
					if w.Code != http.StatusOK || w.Body.String() != payload {
						t.Fatalf("recorded response: status=%d bytes=%d", w.Code, w.Body.Len())
					}
				} else {
					done := make(chan struct{})
					downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						defer close(done)
						handler.ServeHTTP(w, r)
					}))
					t.Cleanup(downstream.Close)
					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, downstream.URL+"/payload", nil)
					if err != nil {
						t.Fatal(err)
					}
					resp, err := downstream.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					_, readErr := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if readErr == nil {
						t.Fatal("server completed a truncated response without an error")
					}
					integrityWait(t, done)
				}
				outcomes := 0
				for _, rec := range rph.findReceipts(t) {
					if rec.ActionRecord.Layer == "outcome" {
						outcomes++
						if !strings.Contains(rec.ActionRecord.Pattern, "reason="+httpstream.Incomplete) {
							t.Fatalf("truncated stream outcome = %s", rec.ActionRecord.Pattern)
						}
					}
				}
				if outcomes != 1 {
					t.Fatalf("incomplete outcomes = %d, want 1", outcomes)
				}
				logger.Close()
				logBytes, err := os.ReadFile(filepath.Clean(auditPath))
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(logBytes), "response stream incomplete") {
					t.Fatalf("missing incomplete audit: %s", logBytes)
				}
			})
		}
	}
}

// Real upstream and downstream HTTP servers exercise the framing that a
// ResponseRecorder cannot: a normal handler return completes chunked bodies.
func TestResponseStreamIntegrity(t *testing.T) {
	branches := []struct {
		name, transport, contentType string
		configure                    func(*config.Config)
		large                        bool
	}{
		{"forward_exempt", "forward", "text/plain", integrityExempt, false},
		{"forward_passthrough", "forward", "application/octet-stream", integrityPassthrough, true},
		{"forward_sse", "forward", "text/event-stream", nil, false},
		{"forward_sse_disabled", "forward", "text/event-stream", integrityDisableSSE, false},
		{"forward_a2a_sse", "forward", "text/event-stream", integrityEnableA2A, false},
		{"intercept_exempt", "intercept", "text/plain", integrityExempt, false},
		{"intercept_passthrough", "intercept", "application/octet-stream", integrityPassthrough, true},
		{"intercept_sse", "intercept", "text/event-stream", nil, false},
		{"intercept_sse_disabled", "intercept", "text/event-stream", integrityDisableSSE, false},
		{"intercept_a2a_sse", "intercept", "text/event-stream", integrityEnableA2A, false},
		{"reverse_media", "reverse", "audio/mpeg", nil, false},
		{"reverse_passthrough", "reverse", "application/octet-stream", integrityPassthrough, true},
		{"reverse_sse", "reverse", "text/event-stream", nil, false},
		{"reverse_sse_disabled", "reverse", "text/event-stream", integrityDisableSSE, false},
	}
	for _, branch := range branches {
		for _, proto := range []int{1, 2} {
			for _, ending := range []string{"chunked_break", "short_length", "cancel", "handler_cancel", "complete"} {
				t.Run(fmt.Sprintf("%s/h%d/%s", branch.name, proto, ending), func(t *testing.T) {
					t.Parallel()
					if branch.large && ending == "chunked_break" {
						t.Skip("unscannable_passthrough requires a positive declared Content-Length; chunked bodies are buffered fail-closed")
					}
					payload := strings.Repeat("integrity download prefix\n", 512)
					if branch.large {
						payload = strings.Repeat("x", 1024*1024+4096)
					}
					if branch.contentType == "text/event-stream" {
						payload = integritySSEBody
					}
					if strings.Contains(branch.name, "a2a") {
						payload = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":{\"state\":\"working\"}}}\n\n"
					}
					release := make(chan struct{})
					var releaseOnce sync.Once
					releaseUpstream := func() { releaseOnce.Do(func() { close(release) }) }
					t.Cleanup(releaseUpstream)
					upstreamDone := make(chan struct{})
					upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						defer close(upstreamDone)
						w.Header().Set("Content-Type", branch.contentType)
						w.Header().Set("Content-Disposition", `attachment; filename="payload.bin"`)
						if ending == "short_length" {
							w.Header().Set("Content-Length", strconv.Itoa(len(payload)+1024))
						} else if branch.large {
							w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
						}
						prefix := payload
						if branch.large && (ending == "cancel" || ending == "handler_cancel") {
							// Keep the declared body incomplete. Sending every promised
							// byte lets the proxy finish before cancellation reaches it,
							// even while this upstream handler is still waiting.
							prefix = payload[:len(payload)-1]
						}
						_, _ = io.WriteString(w, prefix)
						w.(http.Flusher).Flush()
						select {
						case <-release:
						case <-r.Context().Done():
							return
						}
						if ending == "chunked_break" {
							panic(http.ErrAbortHandler)
						}
					}))
					t.Cleanup(upstream.Close)
					cfg := reverseTestConfig()
					cfg.ForwardProxy.Enabled = true
					cfg.TLSInterception.Enabled = true
					cfg.FetchProxy.MaxResponseMB = 1
					cfg.FetchProxy.TimeoutSeconds = 10
					cfg.TLSInterception.MaxResponseBytes = 1024
					cfg.ResponseScanning.SSEStreaming.Enabled = true
					cfg.FlightRecorder.RequireReceipts = true
					mediaOff := false
					cfg.MediaPolicy.Enabled = &mediaOff
					if branch.configure != nil {
						branch.configure(cfg)
					}
					rph := newReceiptProxyHelper(t)
					auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
					logger, err := audit.New("json", "file", auditPath, false, false)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(logger.Close)
					handler := integrityHandler(t, branch.transport, cfg, upstream, logger, rph)
					handlerDone := make(chan struct{})
					handlerCancel := make(chan context.CancelFunc, 1)
					downstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						defer close(handlerDone)
						ctx, cancelHandler := context.WithCancel(r.Context())
						defer cancelHandler()
						handlerCancel <- cancelHandler
						r = r.WithContext(ctx)
						handler.ServeHTTP(w, r)
					}))
					downstream.EnableHTTP2 = proto == 2
					downstream.StartTLS()
					t.Cleanup(downstream.Close)
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					method := http.MethodGet
					var requestBody io.Reader
					if strings.Contains(branch.name, "a2a") {
						method = http.MethodPost
						requestBody = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"message/stream","params":{"message":{"role":"user","parts":[{"kind":"text","text":"hello"}]}}}`)
					}
					req, err := http.NewRequestWithContext(ctx, method, downstream.URL+"/payload", requestBody)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(branch.name, "a2a") {
						req.Header.Set("Content-Type", "application/a2a+json")
					}
					resp, err := downstream.Client().Do(req)
					if err != nil {
						t.Fatalf("before upstream break: %v", err)
					}
					defer func() { _ = resp.Body.Close() }()
					if resp.StatusCode != http.StatusOK || resp.ProtoMajor != proto {
						t.Fatalf("status/protocol = %d/%s", resp.StatusCode, resp.Proto)
					}
					first := make([]byte, 1)
					if _, err := io.ReadFull(resp.Body, first); err != nil {
						t.Fatalf("first byte: %v", err)
					}
					switch ending {
					case "cancel":
						cancel()
					case "handler_cancel":
						// Leave the client context live: its own cancellation error
						// must not hide a server that completes the failed stream.
						cancelHandler := <-handlerCancel
						cancelHandler()
					default:
						releaseUpstream()
					}
					body, readErr := io.ReadAll(resp.Body)
					if ending == "complete" {
						if readErr != nil || string(first)+string(body) != payload {
							t.Fatalf("complete body: bytes=%d err=%v", len(body)+1, readErr)
						}
					} else if readErr == nil {
						t.Fatalf("truncated response ended cleanly: bytes=%d", len(body)+1)
					}
					if ending == "handler_cancel" && ctx.Err() != nil {
						t.Fatalf("client context ended before server abort: %v", ctx.Err())
					}
					integrityWait(t, handlerDone)
					integrityWait(t, upstreamDone)
					wantReason := httpstream.Incomplete
					if ending == "cancel" || ending == "handler_cancel" {
						wantReason = httpstream.Cancelled
						// SSE streams keep their established reason.
						if branch.contentType == "text/event-stream" {
							wantReason = receiptReasonSSEStreamCancelled
						}
					}
					receipts := rph.findReceipts(t)
					found := false
					for _, rec := range receipts {
						if rec.ActionRecord.Layer != "outcome" {
							continue
						}
						pattern := rec.ActionRecord.Pattern
						if ending == "complete" {
							if branch.name == "intercept_exempt" && !strings.Contains(pattern, "reason="+receiptReasonExemptOverCapUnscanned) {
								t.Errorf("completed exempt over-cap outcome = %s", pattern)
							}
							if strings.Contains(pattern, "reason="+httpstream.Incomplete) || strings.Contains(pattern, "reason="+httpstream.Cancelled) || strings.Contains(pattern, "reason="+receiptReasonSSEStreamCancelled) {
								t.Errorf("complete outcome = %s", pattern)
							}
							found = true
						} else if strings.Contains(pattern, "reason="+wantReason) {
							found = true
						}
					}
					if !found {
						t.Fatalf("missing %s outcome in %+v", wantReason, receipts)
					}
					logger.Close()
					logBytes, err := os.ReadFile(filepath.Clean(auditPath))
					if err != nil {
						t.Fatal(err)
					}
					gotIncompleteAudit := strings.Contains(string(logBytes), "response stream incomplete")
					wantIncompleteAudit := ending == "chunked_break" || ending == "short_length"
					if gotIncompleteAudit != wantIncompleteAudit {
						t.Fatalf("incomplete audit = %v, want %v: %s", gotIncompleteAudit, wantIncompleteAudit, logBytes)
					}
				})
			}
		}
	}
}

// Without require_receipts the forward proxy records its allow decision after
// the response. An aborted stream must still leave that receipt behind.
func TestForwardAbortedStreamKeepsAllowReceipt(t *testing.T) {
	for _, branch := range []struct {
		name, contentType string
		configure         func(*config.Config)
	}{
		{"exempt", "text/plain", integrityExempt},
		{"sse", "text/event-stream", nil},
	} {
		t.Run(branch.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", branch.contentType)
				_, _ = io.WriteString(w, integritySSEBody)
				w.(http.Flusher).Flush()
				panic(http.ErrAbortHandler)
			}))
			t.Cleanup(upstream.Close)
			cfg := reverseTestConfig()
			cfg.ForwardProxy.Enabled = true
			cfg.FetchProxy.TimeoutSeconds = 10
			cfg.ResponseScanning.SSEStreaming.Enabled = true
			cfg.FlightRecorder.RequireReceipts = false
			mediaOff := false
			cfg.MediaPolicy.Enabled = &mediaOff
			if branch.configure != nil {
				branch.configure(cfg)
			}
			rph := newReceiptProxyHelper(t)
			handler := integrityHandler(t, "forward", cfg, upstream, audit.NewNop(), rph)
			downstream := httptest.NewServer(handler)
			t.Cleanup(downstream.Close)
			// A small aborted response can end before its headers are flushed.
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, downstream.URL+"/payload", nil)
			if err != nil {
				t.Fatal(err)
			}
			if resp, err := downstream.Client().Do(req); err == nil {
				_, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if readErr == nil {
					t.Fatal("truncated response ended cleanly")
				}
			}
			for _, rec := range rph.findReceipts(t) {
				if rec.ActionRecord.Verdict == config.ActionAllow && rec.ActionRecord.Transport == "forward" {
					return
				}
			}
			t.Fatal("aborted stream left no allow receipt")
		})
	}
}

func integrityExempt(cfg *config.Config) {
	cfg.ResponseScanning.ExemptDomains = []string{"127.0.0.1"}
}

func integrityDisableSSE(cfg *config.Config) { cfg.ResponseScanning.SSEStreaming.Enabled = false }

func integrityEnableA2A(cfg *config.Config) { cfg.A2AScanning.Enabled = true }

func integrityPassthrough(cfg *config.Config) {
	cfg.ResponseScanning.SizeExemptDomains = []string{"127.0.0.1"}
	cfg.ResponseScanning.UnscannablePassthrough = []config.UnscannablePassthroughEntry{{
		Host: "127.0.0.1", Paths: []string{"/payload"}, ContentTypes: []string{"application/octet-stream"},
		Reason: "opaque test download", Expires: temporaryExpiryDate(config.MaxUnscannablePassthroughHorizon),
	}}
}

func integrityWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream goroutine did not end")
	}
}

func integrityHandler(t *testing.T, transport string, cfg *config.Config, upstream *httptest.Server, logger *audit.Logger, rph *receiptProxyHelper) http.Handler {
	t.Helper()
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m, WithReceiptEmitter(rph.emitter))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	p.client.Transport = upstream.Client().Transport
	switch transport {
	case "forward":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Scheme, r.URL.Host, r.Host = u.Scheme, u.Host, u.Host
			p.handleForwardHTTP(w, r)
		})
	case "intercept":
		ic := &InterceptContext{
			TargetHost: u.Hostname(), TargetPort: u.Port(), Config: cfg, Scanner: sc,
			Logger: logger, Metrics: m, Proxy: p, RequestID: "stream-integrity",
		}
		handler := newInterceptHandler(ic, upstream.Client().Transport)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Host = u.Host
			handler.ServeHTTP(w, r)
		})
	default:
		var cfgPtr atomic.Pointer[config.Config]
		var scPtr atomic.Pointer[scanner.Scanner]
		cfgPtr.Store(cfg)
		scPtr.Store(sc)
		rp := NewReverseProxy(u, &cfgPtr, &scPtr, logger, m, killswitch.New(cfg), nil, nil)
		rp.proxy.Transport = upstream.Client().Transport
		rp.SetReceiptEmitter(&p.receiptEmitterPtr)
		return rp
	}
}
