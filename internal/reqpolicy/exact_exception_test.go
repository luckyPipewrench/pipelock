// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import (
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func exactExceptionRule() config.RequestPolicyRule {
	return config.RequestPolicyRule{
		Name:   "block-move-except-archive",
		Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{
			Hosts:        []string{"api.service.example.com"},
			Methods:      []string{http.MethodPost},
			PathPatterns: []string{`/messages/.+/move$`},
		},
		Except: &config.RequestPolicyException{Field: "destinationId", Values: []string{"archive"}},
	}
}

func TestEvaluate_ExactException(t *testing.T) {
	m, err := NewMatcher(&config.RequestPolicy{
		Enabled:           true,
		OnParseError:      config.ActionWarn,
		OnOpaqueOperation: config.ActionAllow,
		Rules:             []config.RequestPolicyRule{exactExceptionRule()},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := RequestMeta{Host: "api.service.example.com", Method: http.MethodPost, Path: "/messages/1/move"}
	if !m.NeedsBodyPredicate(base) {
		t.Fatal("exact exception must cause body inspection")
	}
	if got := m.Evaluate(base); got.Matched() {
		t.Fatalf("route-only pass decided before body inspection: %+v", got)
	}
	for _, tc := range []struct {
		name string
		body string
		dup  bool
		want string
	}{
		{"archive exact", `{"destinationId":"archive"}`, false, ""},
		{"deleted items", `{"destinationId":"deleteditems"}`, false, config.ActionBlock},
		{"other folder", `{"destinationId":"inbox"}`, false, config.ActionBlock},
		{"case variant", `{"destinationId":"Archive"}`, false, config.ActionBlock},
		{"suffix", `{"destinationId":"archive-trash"}`, false, config.ActionBlock},
		{"absent", `{"other":"archive"}`, false, config.ActionBlock},
		{"null", `{"destinationId":null}`, false, config.ActionBlock},
		{"array", `{"destinationId":["archive"]}`, false, config.ActionBlock},
		{"non-object", `["archive"]`, false, config.ActionBlock},
		{"duplicate target", `{"destinationId":"archive"}`, true, config.ActionBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			meta := base
			meta.JSONBodyParsed = true
			meta.JSONBody = jsonBody(t, tc.body)
			if tc.dup {
				meta.JSONDupKeys = map[string]struct{}{"destinationId": {}}
			}
			if got := m.Evaluate(meta).Action; got != tc.want {
				t.Fatalf("Evaluate action = %q, want %q", got, tc.want)
			}
		})
	}
	for _, action := range []string{config.ActionWarn, config.ActionAllow} {
		if got := m.EvaluateUninspectable(base, action, PredDiscriminator).Action; got != config.ActionBlock {
			t.Fatalf("uninspectable body with %s global action = %q, want block", action, got)
		}
	}
	other := base
	other.Path = "/messages/1/reply"
	if got := m.EvaluateUninspectable(other, config.ActionWarn, PredDiscriminator); got.Matched() {
		t.Fatalf("exception affected unrelated path: %+v", got)
	}
}

func TestNewMatcher_RejectsUnsafeExactException(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config.RequestPolicyRule)
	}{
		{"shadow", func(r *config.RequestPolicyRule) { r.Shadow = true }},
		{"bodyless method", func(r *config.RequestPolicyRule) { r.Route.Methods = []string{http.MethodGet} }},
		{"missing host", func(r *config.RequestPolicyRule) { r.Route.Hosts = nil }},
		{"combined predicate", func(r *config.RequestPolicyRule) {
			r.Discriminator = &config.RequestPolicyDiscriminator{Field: "action", ValuePatterns: []string{"^delete$"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := exactExceptionRule()
			tc.edit(&r)
			if _, err := NewMatcher(&config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{r}}); err == nil {
				t.Fatal("unsafe exception compiled")
			}
		})
	}
}

func TestEvaluateBatch_ExactException(t *testing.T) {
	cfg := &config.RequestPolicy{
		Enabled:           true,
		OnParseError:      config.ActionAllow,
		OnOpaqueOperation: config.ActionWarn,
		Rules:             []config.RequestPolicyRule{exactExceptionRule()},
		Batch: []config.RequestPolicyBatch{{
			Route:         config.RequestPolicyRoute{PathPatterns: []string{`/\$batch$`}},
			RequestsField: "requests", MethodField: "method", URLField: "url", BodyField: "body", MaxSubRequests: 4,
		}},
	}
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	meta := RequestMeta{Host: "api.service.example.com", Method: http.MethodPost, Path: "/$batch"}
	for _, tc := range []struct{ name, body, want string }{
		{"exact archive", `{"destinationId":"archive"}`, ""},
		{"other folder", `{"destinationId":"deleteditems"}`, config.ActionBlock},
		{"duplicate target", `{"destinationId":"archive","destinationId":"archive"}`, config.ActionBlock},
		{"invalid body", `{"destinationId":`, config.ActionBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"requests":[{"method":"POST","url":"/messages/1/move","body":` + tc.body + `}]}`)
			if tc.name == "invalid body" {
				body = []byte(`{"requests":[{"method":"POST","url":"/messages/1/move","body":"invalid"}]}`)
			}
			got, ok := m.EvaluateBatch(meta, body)
			if !ok || got.Action != tc.want {
				t.Fatalf("EvaluateBatch = %+v, parseOK=%t; want %q", got, ok, tc.want)
			}
		})
	}
}
