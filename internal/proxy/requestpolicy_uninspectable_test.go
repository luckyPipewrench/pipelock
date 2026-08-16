// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, errors.New("body stream failed") }
func (errBody) Close() error             { return nil }

func overrideGETHeaders() http.Header {
	h := http.Header{}
	h.Set("X-HTTP-Method-Override", http.MethodGet)
	h.Set("Content-Type", "application/json")
	return h
}

func TestRequestPolicyNeedsBodyPredicateUsesBaseMethodWhenOverrideMisses(t *testing.T) {
	t.Parallel()

	p := newTestProxyWithConfig(t, reqPolicyConfig(graphqlBlockRule()))
	in := requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodPost,
		Path:        "/graphql",
		ContentType: "application/json",
		Headers:     overrideGETHeaders(),
	}
	if !p.requestPolicyNeedsBodyPredicate(in) {
		t.Fatal("POST GraphQL rule ignored when override is GET")
	}

	getOnly := requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodGet,
		Path:        "/graphql",
		ContentType: "application/json",
		Headers:     http.Header{"Content-Type": []string{"application/json"}},
	}
	if p.requestPolicyNeedsBodyPredicate(getOnly) {
		t.Fatal("GET without a matching rule still required a body")
	}
}

func TestApplyRequestPolicy_UnreadGraphQLOverrideFailsClosed(t *testing.T) {
	t.Parallel()

	cfg := reqPolicyConfig(graphqlBlockRule())
	cfg.RequestPolicy.OnOpaqueOperation = config.ActionBlock
	p := newTestProxyWithConfig(t, cfg)
	got := p.applyRequestPolicy(requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodPost,
		Path:        "/graphql",
		ContentType: "application/json",
		Headers:     overrideGETHeaders(),
		BodyRead:    false,
	})
	if !got.Block {
		t.Fatal("unread GraphQL POST with GET override was allowed")
	}
}

func TestApplyRequestPolicy_DeferBodyPredicateSkipsUnreadOpaque(t *testing.T) {
	t.Parallel()

	cfg := reqPolicyConfig(graphqlBlockRule())
	cfg.RequestPolicy.OnOpaqueOperation = config.ActionBlock
	p := newTestProxyWithConfig(t, cfg)
	got := p.applyRequestPolicy(requestPolicyInput{
		Host:               rpTestHost,
		Method:             http.MethodPost,
		Path:               "/graphql",
		ContentType:        "application/json",
		BodyRead:           false,
		DeferBodyPredicate: true,
	})
	if got.Block {
		t.Fatalf("deferred body predicate still blocked: %+v", got)
	}
}

func TestPrepareRequestPolicyBodyReadErrorFailsClosed(t *testing.T) {
	t.Parallel()

	cfg := reqPolicyConfig(graphqlBlockRule())
	cfg.RequestPolicy.OnParseError = config.ActionAllow
	p := newTestProxyWithConfig(t, cfg)
	req := httptestRequest(t, http.MethodPost, "")
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(errBody{})
	in := requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodPost,
		Path:        "/graphql",
		ContentType: "application/json",
		Headers:     req.Header,
	}
	got := p.prepareRequestPolicyBody(req, &in)
	if !got.Block {
		t.Fatal("unreadable operation body was allowed")
	}
	if got.Reason == "" {
		t.Fatal("unreadable body block had no reason")
	}
}
