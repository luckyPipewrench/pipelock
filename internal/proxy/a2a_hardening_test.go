// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestProxyA2AResponseStricterAction(t *testing.T) {
	for _, transport := range []string{"forward", "intercept"} {
		for _, action := range []string{config.ActionWarn, config.ActionBlock} {
			for _, direction := range []string{"response", "stream"} {
				t.Run(transport+"/"+action+"/"+direction, func(t *testing.T) {
					cfg := config.Defaults()
					cfg.Internal = nil
					cfg.A2AScanning.Enabled = true
					cfg.A2AScanning.Action = config.ActionWarn
					cfg.RequestBodyScanning.Enabled = false
					cfg.ResponseScanning.Action = action
					cfg.ResponseScanning.SSEStreaming.Action = config.ActionWarn
					cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.example"}
					body := `{"url":"https://blocked.example/message"}`
					contentType := "application/a2a+json"
					if direction == "stream" {
						contentType = "text/event-stream"
						body = "data: " + body + "\n\n"
					}
					w, hits, met := driveProxyA2AHardening(t, transport, `{"text":"hello"}`, body, contentType, cfg)
					if hits != 1 {
						t.Fatalf("response scan must decide after reaching upstream: hits=%d", hits)
					}
					if direction == "stream" {
						if w.Body.Len() != 0 {
							t.Fatalf("single-event finding must be withheld: %.300s", w.Body.String())
						}
						families, err := met.Registry().Gather()
						if err != nil {
							t.Fatal(err)
						}
						metricName := "pipelock_scanner_hits_total"
						if transport == "intercept" {
							metricName = "pipelock_tls_response_blocked_total"
						}
						var blocks float64
						for _, family := range families {
							if family.GetName() == metricName {
								for _, metric := range family.GetMetric() {
									blocks += metric.GetCounter().GetValue()
								}
							}
						}
						want := float64(0)
						if action == config.ActionBlock {
							want = 1
						}
						if blocks != want {
							t.Fatalf("stream finding must retain stricter action: blocks=%g want=%g", blocks, want)
						}
					} else if action == config.ActionBlock && w.Code != http.StatusForbidden {
						t.Fatalf("stricter response action must win: status=%d body=%.300s", w.Code, w.Body.String())
					} else if action == config.ActionWarn && (w.Code != http.StatusOK || w.Body.String() != body) {
						t.Fatalf("warn finding must retain response: status=%d body=%.300s", w.Code, w.Body.String())
					}
				})
			}
		}
	}
}

func TestProxyA2ADepthIndependentOfNodeBudget(t *testing.T) {
	for _, transport := range []string{"forward", "intercept"} {
		for _, direction := range []string{"request", "response", "stream"} {
			t.Run(transport+"/"+direction, func(t *testing.T) {
				cfg := config.Defaults()
				cfg.Internal = nil
				cfg.A2AScanning.Enabled = true
				cfg.A2AScanning.Action = config.ActionWarn
				cfg.RequestBodyScanning.Enabled = false
				cfg.ResponseScanning.Enabled = false
				deep := `"hello"`
				for range extract.MaxExtractDepth {
					deep = `{"payload":` + deep + `}`
				}
				wide := `{"a":[` + strings.Repeat("0,", 10000) + `0],"z":` + deep + `}`
				if !json.Valid([]byte(wide)) {
					t.Fatal("fixture must be valid JSON")
				}
				request, response, contentType := `{"text":"hello"}`, wide, "application/a2a+json"
				switch direction {
				case "request":
					request, response = wide, `{"text":"hello"}`
				case "stream":
					contentType = "text/event-stream"
					response = "data: " + wide + "\n\n"
				}
				w, hits, _ := driveProxyA2AHardening(t, transport, request, response, contentType, cfg)
				if direction == "stream" {
					if w.Body.Len() != 0 {
						t.Fatalf("uninspectable event must be withheld: %.300s", w.Body.String())
					}
				} else if w.Code != http.StatusForbidden {
					t.Fatalf("depth bound must block independently of node budget: status=%d body=%.300s", w.Code, w.Body.String())
				}
				if direction == "request" && hits != 0 || direction != "request" && hits != 1 {
					t.Fatalf("unexpected upstream calls: %d", hits)
				}
			})
		}
	}
}

func driveProxyA2AHardening(t *testing.T, transport, request, response, contentType string, cfg *config.Config) (*httptest.ResponseRecorder, int32, *metrics.Metrics) {
	t.Helper()
	var hits atomic.Int32
	var met *metrics.Metrics
	w := httptest.NewRecorder()
	if transport == "forward" {
		upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.Header().Set("Content-Type", contentType)
			_, _ = io.WriteString(w, response)
		}))
		t.Cleanup(upstream.Close)
		_, p, cleanup := setupForwardProxyWithInstance(t, func(c *config.Config) {
			c.Internal = nil
			c.A2AScanning = cfg.A2AScanning
			c.RequestBodyScanning = cfg.RequestBodyScanning
			c.ResponseScanning = cfg.ResponseScanning
			c.FetchProxy.Monitoring.Blocklist = cfg.FetchProxy.Monitoring.Blocklist
		})
		t.Cleanup(cleanup)
		met = p.metrics
		p.handleForwardHTTP(w, newA2AForwardBodyRequest(t, upstream.URL+"/message:send", request))
	} else {
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		met = metrics.New()
		handler := newInterceptHandler(&InterceptContext{
			TargetHost: "peer.example", TargetPort: "443", Config: cfg, Scanner: sc,
			Logger: audit.NewNop(), Metrics: met, ClientIP: testLoopbackIP,
			RequestID: "a2a-policy", Agent: agentAnonymous,
		}, roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
			hits.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{contentType}},
				Body: io.NopCloser(strings.NewReader(response)), ContentLength: int64(len(response)),
			}, nil
		}))
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://peer.example/message:send", strings.NewReader(request))
		req.Header.Set("Content-Type", "application/a2a+json")
		handler.ServeHTTP(w, req)
	}
	return w, hits.Load(), met
}
