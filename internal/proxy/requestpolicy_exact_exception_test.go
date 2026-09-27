// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestRequestPolicy_ForwardExactException(t *testing.T) {
	forwarded := make(chan string, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		forwarded <- string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)

	cfg := reqPolicyConfig(config.RequestPolicyRule{
		Name:   "block-item-move",
		Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{
			Hosts: []string{rpTestHost}, Methods: []string{http.MethodPost},
			PathPatterns: []string{`/items/.+/move$`},
		},
		Except: &config.RequestPolicyException{Field: "destinationId", Values: []string{"archive"}},
	})
	cfg.RequestPolicy.OnParseError = config.ActionAllow
	cfg.RequestPolicy.OnOpaqueOperation = config.ActionWarn
	cfg.RequestBodyScanning.Enabled = false
	p := newTestProxyWithConfig(t, cfg)
	p.client.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != rpTestHost+":80" {
				return nil, fmt.Errorf("unexpected upstream %q", addr)
			}
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		},
	}
	handler := p.buildHandler(p.buildMux())
	for _, tc := range []struct {
		name, body string
		wantBlock  bool
	}{
		{"archive", `{"destinationId":"archive"}`, false},
		{"deleted items", `{"destinationId":"deleteditems"}`, true},
		{"duplicate target", `{"destinationId":"archive","destinationId":"archive"}`, true},
		{"duplicate target blocked first", `{"destinationId":"deleteditems","destinationId":"archive"}`, true},
		{"duplicate target blocked last", `{"destinationId":"archive","destinationId":"deleteditems"}`, true},
		{"invalid json", `{"destinationId":`, true},
		{"absent", `{"other":"archive"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
				"http://"+rpTestHost+"/items/1/move", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if tc.wantBlock {
				if w.Code != http.StatusForbidden {
					t.Fatalf("HTTP %d, want 403", w.Code)
				}
				if len(forwarded) != 0 {
					t.Fatal("blocked request reached upstream")
				}
				return
			}
			if w.Code != http.StatusNoContent {
				t.Fatalf("HTTP %d, want upstream 204", w.Code)
			}
			select {
			case got := <-forwarded:
				if got != tc.body {
					t.Fatalf("upstream body = %q, want %q", got, tc.body)
				}
			default:
				t.Fatal("allowed request did not reach upstream")
			}
		})
	}
}
