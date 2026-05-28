// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// discriminatorBlockRule blocks a JSON POST to rpTestHost whose top-level
// "action" field is a string matching ^delete.
func discriminatorBlockRule() config.RequestPolicyRule {
	return config.RequestPolicyRule{
		Name:   rpRuleName,
		Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{
			Hosts:        []string{rpTestHost},
			Methods:      []string{http.MethodPost},
			ContentTypes: []string{"application/json"},
		},
		Discriminator: &config.RequestPolicyDiscriminator{
			Field:         "action",
			ValuePatterns: []string{`^delete`},
		},
		Reason: "dangerous operation requires operator approval",
	}
}

func discriminatorInput(body string, bodyRead bool) requestPolicyInput {
	in := requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodPost,
		Path:        "/v1/ops",
		ContentType: "application/json",
		BodyRead:    bodyRead,
		Transport:   TransportForward,
		AuditCtx:    audit.LogContext{},
	}
	if body != "" {
		in.Body = []byte(body)
	}
	return in
}

func TestApplyRequestPolicy_Discriminator(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		onOpaque  string
		body      string
		wantBlock bool
	}{
		{name: "string value matches", body: `{"action":"deleteAll"}`, wantBlock: true},
		{name: "string value no match", body: `{"action":"list"}`, wantBlock: false},
		{name: "field absent forwards", body: `{"other":"deleteAll"}`, wantBlock: false},
		{name: "array value opaque blocks", body: `{"action":["delete","all"]}`, wantBlock: true},
		{name: "object value opaque blocks", body: `{"action":{"op":"deleteAll"}}`, wantBlock: true},
		{name: "number value opaque blocks", body: `{"action":7}`, wantBlock: true},
		{name: "null value opaque blocks", body: `{"action":null}`, wantBlock: true},
		{name: "non-object top level opaque blocks", body: `["action","deleteAll"]`, wantBlock: true},
		{name: "invalid json parse error blocks", body: `{"action":"delete`, wantBlock: true},
		{name: "trailing garbage parse error blocks", body: `{"action":"list"} evil`, wantBlock: true},
		{name: "second json value parse error blocks", body: `{"action":"list"} {"action":"list"}`, wantBlock: true},
		{name: "duplicate target field dangerous-first opaque blocks", body: `{"action":"deleteAll","action":"list"}`, wantBlock: true},
		{name: "duplicate target field benign-first opaque blocks", body: `{"action":"list","action":"deleteAll"}`, wantBlock: true},
		{name: "duplicate unrelated field still evaluates target", body: `{"foo":1,"foo":2,"action":"list"}`, wantBlock: false},
		{name: "opaque warn forwards", onOpaque: config.ActionWarn, body: `{"action":["delete"]}`, wantBlock: false},
		{name: "opaque allow forwards", onOpaque: config.ActionAllow, body: `{"action":["delete"]}`, wantBlock: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := reqPolicyConfig(discriminatorBlockRule())
			if tt.onOpaque != "" {
				cfg.RequestPolicy.OnOpaqueOperation = tt.onOpaque
			}
			p := newTestProxyWithConfig(t, cfg)
			res := p.applyRequestPolicy(discriminatorInput(tt.body, true))
			if res.Block != tt.wantBlock {
				t.Fatalf("Block = %v, want %v (body %q)", res.Block, tt.wantBlock, tt.body)
			}
		})
	}
}

// A discriminator rule with the body unavailable must fail closed: the rule's
// route matched but no body could be inspected.
func TestApplyRequestPolicy_DiscriminatorBodyUnavailableFailsClosed(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(discriminatorBlockRule()))
	res := p.applyRequestPolicy(discriminatorInput("", false))
	if !res.Block {
		t.Fatal("route-matched discriminator request with unavailable body should fail closed")
	}
}

// Cross-surface independence: a body that is valid JSON (so the discriminator
// can classify it) but carries no inline GraphQL operation must be judged by
// the discriminator predicate, not fail-closed by the GraphQL opaque path. The
// GraphQL opaque signal applies only to GraphQL rules, of which there are none.
func TestApplyRequestPolicy_DiscriminatorIndependentOfGraphQLOpaque(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(discriminatorBlockRule()))

	// No "query" key -> GraphQL extraction reports opaque -> but only the
	// discriminator (string "list", no match) governs this disc-only rule.
	if res := p.applyRequestPolicy(discriminatorInput(`{"action":"list"}`, true)); res.Block {
		t.Fatal("disc-only rule must not inherit GraphQL opaque fail-closed on a benign value")
	}
	// Same body shape, dangerous value -> discriminator blocks.
	if res := p.applyRequestPolicy(discriminatorInput(`{"action":"deleteEverything"}`, true)); !res.Block {
		t.Fatal("discriminator should block a matching string value")
	}
}

// End-to-end through the forward absolute-URI transport with request body
// scanning disabled: request_policy must still read the body and block on a
// matching discriminator.
func TestRequestPolicy_ForwardDiscriminator_BlocksWithBodyScanningDisabled(t *testing.T) {
	t.Parallel()
	cfg := reqPolicyConfig(discriminatorBlockRule())
	cfg.RequestBodyScanning.Enabled = false
	p := newTestProxyWithConfig(t, cfg)
	handler := p.buildHandler(p.buildMux())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://"+rpTestHost+"/v1/ops", strings.NewReader(`{"action":"deleteAll"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assertRequestPolicyBlock(t, w)
}
