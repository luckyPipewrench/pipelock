// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestRequestPolicyReadBlockedNilMatcherAllows(t *testing.T) {
	t.Parallel()

	p := &Proxy{}
	in := requestPolicyInput{
		Host:     "api.vendor.example",
		Method:   http.MethodPost,
		Path:     "/graphql",
		BodyRead: false,
	}
	got := p.requestPolicyReadBlocked(in, "body unreadable")
	if got.Block {
		t.Fatalf("nil matcher read-block = %+v, want allow", got)
	}
	if got.Reason != "" || got.Info.Reason != "" {
		t.Fatalf("nil matcher still surfaced a block reason: %+v", got)
	}
}

func TestRequestPolicyBodyLimitDefaultAndConfigured(t *testing.T) {
	t.Parallel()

	p := &Proxy{}
	if got := p.requestPolicyBodyLimit(); got != defaultRequestPolicyMaxBodyBytes {
		t.Fatalf("unset config limit = %d, want default %d", got, defaultRequestPolicyMaxBodyBytes)
	}

	cfg := config.Defaults()
	cfg.RequestBodyScanning.MaxBodyBytes = 4096
	p.cfgPtr.Store(cfg)
	if got := p.requestPolicyBodyLimit(); got != 4096 {
		t.Fatalf("configured limit = %d, want 4096", got)
	}

	cfg.RequestBodyScanning.MaxBodyBytes = 0
	p.cfgPtr.Store(cfg)
	if got := p.requestPolicyBodyLimit(); got != defaultRequestPolicyMaxBodyBytes {
		t.Fatalf("non-positive limit = %d, want default %d", got, defaultRequestPolicyMaxBodyBytes)
	}
}

func TestPrepareRequestPolicyBodyAlreadyReadOrEmpty(t *testing.T) {
	t.Parallel()

	p := &Proxy{}
	cfg := reqPolicyConfig(graphqlBlockRule())
	if err := p.setupRequestPolicy(cfg); err != nil {
		t.Fatalf("setupRequestPolicy: %v", err)
	}

	in := requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodPost,
		Path:        "/graphql",
		ContentType: "application/json",
		BodyRead:    true,
		Body:        []byte(`{"already":true}`),
	}
	req := httptestRequest(t, http.MethodPost, `{"from-request":true}`)
	if got := p.prepareRequestPolicyBody(req, &in); got.Block {
		t.Fatalf("already-read body blocked: %+v", got)
	}
	if string(in.Body) != `{"already":true}` {
		t.Fatalf("already-read body was replaced: %s", in.Body)
	}

	in = requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodPost,
		Path:        "/graphql",
		ContentType: "application/json",
	}
	empty := httptestRequest(t, http.MethodPost, "")
	empty.Body = nil
	if got := p.prepareRequestPolicyBody(empty, &in); got.Block {
		t.Fatalf("nil body blocked: %+v", got)
	}
	if !in.BodyRead {
		t.Fatal("nil body was not marked read")
	}
}

func TestParseRequestPolicyJSONBodyRejectsEmptyAndTrailing(t *testing.T) {
	t.Parallel()

	if _, _, ok := parseRequestPolicyJSONBody(requestPolicyInput{}); ok {
		t.Fatal("empty body parsed as JSON")
	}
	if _, _, ok := parseRequestPolicyJSONBody(requestPolicyInput{Body: []byte(`{"a":1} trailing`)}); ok {
		t.Fatal("trailing garbage parsed as a single JSON value")
	}
	doc, dups, ok := parseRequestPolicyJSONBody(requestPolicyInput{Body: []byte(`{"a":1,"a":2}`)})
	if !ok {
		t.Fatal("valid object rejected")
	}
	if _, isObj := doc.(map[string]any); !isObj {
		t.Fatalf("doc = %#v, want object", doc)
	}
	if _, found := dups["a"]; !found {
		t.Fatalf("duplicate key missing from %v", dups)
	}
}

func httptestRequest(t *testing.T, method, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, "https://api.vendor.example/x", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}
