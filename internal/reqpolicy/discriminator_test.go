// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// discRule blocks a POST to the host when the JSON body's top-level "action"
// field is a string matching ^delete.
func discRule() config.RequestPolicyRule {
	return config.RequestPolicyRule{
		Name:   "json-destructive-op",
		Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{
			Hosts:   []string{"api.service.example.com"},
			Methods: []string{http.MethodPost},
		},
		Discriminator: &config.RequestPolicyDiscriminator{
			Field:         "action",
			ValuePatterns: []string{"^delete"},
		},
		Reason: "destructive JSON operation",
	}
}

// jsonBody parses a JSON literal into the generic value the discriminator
// predicate walks, asserting it parses so a test typo surfaces immediately.
func jsonBody(t *testing.T, raw string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("jsonBody: %v", err)
	}
	return v
}

func TestEvaluate_Discriminator(t *testing.T) {
	host, method := "api.service.example.com", http.MethodPost

	tests := []struct {
		name       string
		onOpaque   string // matcher OnOpaqueOperation; "" => default block
		body       string
		wantAction string // "" => allow
	}{
		{
			name:       "field present string matches pattern",
			body:       `{"action":"deleteAll"}`,
			wantAction: config.ActionBlock,
		},
		{
			name:       "field present string no pattern match",
			body:       `{"action":"list"}`,
			wantAction: "",
		},
		{
			name:       "field absent",
			body:       `{"other":"deleteAll"}`,
			wantAction: "",
		},
		{
			name:       "field present as array is opaque",
			body:       `{"action":["delete","All"]}`,
			wantAction: config.ActionBlock,
		},
		{
			name:       "field present as object is opaque",
			body:       `{"action":{"op":"deleteAll"}}`,
			wantAction: config.ActionBlock,
		},
		{
			name:       "field present as number is opaque",
			body:       `{"action":7}`,
			wantAction: config.ActionBlock,
		},
		{
			name:       "field present as bool is opaque",
			body:       `{"action":true}`,
			wantAction: config.ActionBlock,
		},
		{
			name:       "field present as null is opaque",
			body:       `{"action":null}`,
			wantAction: config.ActionBlock,
		},
		{
			name:       "non-object top level is opaque",
			body:       `["action","deleteAll"]`,
			wantAction: config.ActionBlock,
		},
		{
			name:       "opaque honors on_opaque_operation warn",
			onOpaque:   config.ActionWarn,
			body:       `{"action":["delete"]}`,
			wantAction: config.ActionWarn,
		},
		{
			name:       "opaque honors on_opaque_operation allow",
			onOpaque:   config.ActionAllow,
			body:       `{"action":["delete"]}`,
			wantAction: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewMatcher(&config.RequestPolicy{
				Enabled:           true,
				OnOpaqueOperation: tt.onOpaque,
				Rules:             []config.RequestPolicyRule{discRule()},
			})
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			meta := RequestMeta{
				Host: host, Method: method,
				JSONBody:       jsonBody(t, tt.body),
				JSONBodyParsed: true,
			}
			got := m.Evaluate(meta)
			if got.Action != tt.wantAction {
				t.Fatalf("Evaluate action = %q, want %q", got.Action, tt.wantAction)
			}
		})
	}
}

func TestHasBodyPredicate(t *testing.T) {
	graphqlOnly := compiledRule{graphql: &gqlPredicate{}}
	discOnly := compiledRule{disc: &discPredicate{}}
	both := compiledRule{graphql: &gqlPredicate{}, disc: &discPredicate{}}
	routeOnly := compiledRule{}

	tests := []struct {
		name string
		rule compiledRule
		kind BodyPredicateKind
		want bool
	}{
		{"any matches graphql", graphqlOnly, PredAnyBody, true},
		{"any matches disc", discOnly, PredAnyBody, true},
		{"any matches none", routeOnly, PredAnyBody, false},
		{"graphql kind on graphql rule", graphqlOnly, PredGraphQL, true},
		{"graphql kind on disc rule", discOnly, PredGraphQL, false},
		{"disc kind on disc rule", discOnly, PredDiscriminator, true},
		{"disc kind on graphql rule", graphqlOnly, PredDiscriminator, false},
		{"any matches both", both, PredAnyBody, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.hasBodyPredicate(tt.kind); got != tt.want {
				t.Fatalf("hasBodyPredicate(%v) = %v, want %v", tt.kind, got, tt.want)
			}
		})
	}
}

// A duplicated targeted field is unclassifiable (parsers disagree on which
// value wins), so it is opaque regardless of the collapsed value; an unrelated
// duplicated key does not affect the targeted field.
func TestEvaluate_DiscriminatorDuplicateKey(t *testing.T) {
	m, err := NewMatcher(&config.RequestPolicy{
		Enabled: true,
		Rules:   []config.RequestPolicyRule{discRule()},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	base := RequestMeta{Host: "api.service.example.com", Method: http.MethodPost, JSONBodyParsed: true}

	// Targeted field "action" duplicated; collapsed value is benign "list".
	dup := base
	dup.JSONBody = map[string]any{"action": "list"}
	dup.JSONDupKeys = map[string]struct{}{"action": {}}
	if got := m.Evaluate(dup).Action; got != config.ActionBlock {
		t.Fatalf("duplicate targeted field should be opaque (block), got %q", got)
	}

	// Unrelated key duplicated; targeted field is a benign string.
	unrelated := base
	unrelated.JSONBody = map[string]any{"action": "list"}
	unrelated.JSONDupKeys = map[string]struct{}{"foo": {}}
	if got := m.Evaluate(unrelated); got.Matched() {
		t.Fatalf("unrelated duplicate key must not block, got %+v", got)
	}
}

// A discriminator rule must not fire until the body has been parsed: the
// route-only first pass (JSONBodyParsed=false) must never match, or a body
// predicate would block before the body is inspected.
func TestEvaluate_DiscriminatorRouteOnlyPassDoesNotMatch(t *testing.T) {
	m, err := NewMatcher(&config.RequestPolicy{
		Enabled: true,
		Rules:   []config.RequestPolicyRule{discRule()},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	got := m.Evaluate(RequestMeta{Host: "api.service.example.com", Method: http.MethodPost})
	if got.Matched() {
		t.Fatalf("route-only pass matched a discriminator rule: %+v", got)
	}
}

// NeedsBodyPredicate must be true for a route-matched discriminator rule so the
// transport reads the body, and false when the route does not match.
func TestNeedsBodyPredicate_Discriminator(t *testing.T) {
	m, err := NewMatcher(&config.RequestPolicy{
		Enabled: true,
		Rules:   []config.RequestPolicyRule{discRule()},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if !m.NeedsBodyPredicate(RequestMeta{Host: "api.service.example.com", Method: http.MethodPost}) {
		t.Fatalf("NeedsBodyPredicate = false for route-matched discriminator rule")
	}
	if m.NeedsBodyPredicate(RequestMeta{Host: "other.example.com", Method: http.MethodPost}) {
		t.Fatalf("NeedsBodyPredicate = true for non-matching route")
	}
}

// A rule with both GraphQL and discriminator predicates fires only when BOTH
// match (route AND graphql AND discriminator).
func TestEvaluate_CompositeGraphQLAndDiscriminator(t *testing.T) {
	rule := config.RequestPolicyRule{
		Name:   "composite",
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{"api.service.example.com"}},
		GraphQL: &config.RequestPolicyGraphQL{
			OperationTypes: []string{gqlMutation},
		},
		Discriminator: &config.RequestPolicyDiscriminator{
			Field:         "action",
			ValuePatterns: []string{"^delete"},
		},
	}
	m, err := NewMatcher(&config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule}})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	mutationOp := []RequestOperation{{Kind: gqlMutation, RootFields: []string{"x"}}}
	queryOp := []RequestOperation{{Kind: gqlQuery, RootFields: []string{"x"}}}

	cases := []struct {
		name       string
		ops        []RequestOperation
		body       string
		wantAction string
	}{
		{"both match", mutationOp, `{"action":"deleteAll"}`, config.ActionBlock},
		{"graphql matches discriminator does not", mutationOp, `{"action":"list"}`, ""},
		{"discriminator matches graphql does not", queryOp, `{"action":"deleteAll"}`, ""},
		{"neither matches", queryOp, `{"action":"list"}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta := RequestMeta{
				Host:           "api.service.example.com",
				Method:         http.MethodPost,
				Operations:     tc.ops,
				JSONBody:       jsonBody(t, tc.body),
				JSONBodyParsed: true,
			}
			if got := m.Evaluate(meta).Action; got != tc.wantAction {
				t.Fatalf("Evaluate action = %q, want %q", got, tc.wantAction)
			}
		})
	}
}
