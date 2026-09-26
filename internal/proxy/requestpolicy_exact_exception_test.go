// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestRequestPolicy_ForwardExactException(t *testing.T) {
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
	handler := p.buildHandler(p.buildMux())
	for _, tc := range []struct {
		name, body string
		wantBlock  bool
	}{
		{"archive", `{"destinationId":"archive"}`, false},
		{"deleted items", `{"destinationId":"deleteditems"}`, true},
		{"duplicate target", `{"destinationId":"archive","destinationId":"archive"}`, true},
		{"invalid json", `{"destinationId":`, true},
		{"absent", `{"other":"archive"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
				"http://"+rpTestHost+"/items/1/move", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if got := w.Code == http.StatusForbidden; got != tc.wantBlock {
				t.Fatalf("HTTP %d, want blocked=%t", w.Code, tc.wantBlock)
			}
		})
	}
}
