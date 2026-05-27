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

// batchReqPolicyConfig returns a config whose request_policy blocks sendMail and
// declares /$batch as a JSON batch endpoint (envelope fields set explicitly,
// mirroring what config normalization applies on the real load path).
func batchReqPolicyConfig() *config.Config {
	cfg := reqPolicyConfig(config.RequestPolicyRule{
		Name:   "block-sendmail",
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{PathPatterns: []string{`/sendMail$`}},
		Reason: "sendMail is blocked for the agent runtime",
	})
	cfg.ForwardProxy.Enabled = true
	cfg.RequestPolicy.Batch = []config.RequestPolicyBatch{{
		Route:          config.RequestPolicyRoute{PathPatterns: []string{`/\$batch$`}},
		RequestsField:  "requests",
		MethodField:    "method",
		URLField:       "url",
		BodyField:      "body",
		MaxSubRequests: 64,
	}}
	return cfg
}

func TestRequestPolicy_ForwardBatch_BlocksWrappedOperation(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, batchReqPolicyConfig())
	handler := p.buildHandler(p.buildMux())

	// A sendMail call wrapped in a $batch envelope must be unwrapped and blocked.
	body := `{"requests":[{"id":"1","method":"POST","url":"/v1.0/me/sendMail","body":{"message":{}}}]}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://"+rpTestHost+"/v1.0/$batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assertRequestPolicyBlock(t, w)
}

func TestRequestPolicy_ForwardBatch_BenignForwards(t *testing.T) {
	t.Parallel()
	cfg := batchReqPolicyConfig()
	// Point the upstream at a real server so a non-blocked batch can complete.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	p := newTestProxyWithConfig(t, cfg)
	handler := p.buildHandler(p.buildMux())

	body := `{"requests":[{"id":"1","method":"GET","url":"/v1.0/me/messages"}]}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://"+rpTestHost+"/v1.0/$batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// The benign batch is not a request_policy block (it will fail to dial the
	// non-existent host, but must not carry the request_policy_deny reason).
	if got := w.Header().Get("X-Pipelock-Block-Reason"); got == "request_policy_deny" {
		t.Fatal("a benign batch must not be blocked by request_policy")
	}
}
