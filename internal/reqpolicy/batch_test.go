// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy_test

import (
	"net/url"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/reqpolicy"
)

const batchHost = "graph.example.com"

// batchMatcher builds a matcher with a batch endpoint at /$batch plus the given
// rules. The envelope field names + cap mirror what config normalization sets.
func batchMatcher(t *testing.T, rules ...config.RequestPolicyRule) *reqpolicy.Matcher {
	t.Helper()
	cfg := &config.RequestPolicy{
		Enabled:           true,
		OnParseError:      config.ActionBlock,
		OnOpaqueOperation: config.ActionBlock,
		Rules:             rules,
		Batch: []config.RequestPolicyBatch{{
			Route:          config.RequestPolicyRoute{PathPatterns: []string{`/\$batch$`}},
			RequestsField:  "requests",
			MethodField:    "method",
			URLField:       "url",
			BodyField:      "body",
			MaxSubRequests: 64,
		}},
	}
	m, err := reqpolicy.NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	return m
}

func deleteRule() config.RequestPolicyRule {
	return config.RequestPolicyRule{
		Name:   "block-sendmail",
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{PathPatterns: []string{`/sendMail$`}},
		Reason: "sendMail is blocked for the agent runtime",
	}
}

func batchMeta() reqpolicy.RequestMeta {
	return reqpolicy.RequestMeta{Host: batchHost, Method: "POST", Path: "/v1.0/$batch"}
}

func TestEvaluateBatch_WrappedDangerousSubRequestBlocks(t *testing.T) {
	t.Parallel()
	m := batchMatcher(t, deleteRule())
	body := []byte(`{"requests":[{"id":"1","method":"POST","url":"/v1.0/me/sendMail","body":{"message":{}}}]}`)
	d, parseOK := m.EvaluateBatch(batchMeta(), body)
	if !parseOK {
		t.Fatal("well-formed envelope should parse")
	}
	if d.Action != config.ActionBlock {
		t.Fatalf("a sendMail sub-request wrapped in $batch must block; got action=%q", d.Action)
	}
}

func TestEvaluateBatch_MixedSafeAndUnsafeBlocks(t *testing.T) {
	t.Parallel()
	m := batchMatcher(t, deleteRule())
	body := []byte(`{"requests":[
		{"id":"1","method":"GET","url":"/v1.0/me/messages"},
		{"id":"2","method":"POST","url":"/v1.0/me/sendMail","body":{}}
	]}`)
	if d, _ := m.EvaluateBatch(batchMeta(), body); d.Action != config.ActionBlock {
		t.Fatalf("a batch with one dangerous sub-request must block; got %q", d.Action)
	}
}

func TestEvaluateBatch_AllBenignAllows(t *testing.T) {
	t.Parallel()
	m := batchMatcher(t, deleteRule())
	body := []byte(`{"requests":[{"id":"1","method":"GET","url":"/v1.0/me/messages"}]}`)
	if d, parseOK := m.EvaluateBatch(batchMeta(), body); !parseOK || d.Matched() {
		t.Fatalf("a benign batch must not match; got matched=%v parseOK=%v", d.Matched(), parseOK)
	}
}

func TestEvaluateBatch_GraphQLSubRequestBlocks(t *testing.T) {
	t.Parallel()
	gqlRule := config.RequestPolicyRule{
		Name:   "block-mutation",
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{PathPatterns: []string{`/graphql$`}},
		GraphQL: &config.RequestPolicyGraphQL{
			OperationTypes:    []string{"mutation"},
			RootFieldPatterns: []string{`^deleteRecord$`},
		},
	}
	m := batchMatcher(t, gqlRule)
	body := []byte(`{"requests":[{"method":"POST","url":"/graphql","body":{"query":"mutation { deleteRecord { id } }"}}]}`)
	if d, _ := m.EvaluateBatch(batchMeta(), body); d.Action != config.ActionBlock {
		t.Fatalf("a GraphQL mutation in a batch sub-request must block; got %q", d.Action)
	}
}

func TestEvaluateBatch_GraphQLOverGETSubRequestBlocks(t *testing.T) {
	t.Parallel()
	gqlRule := config.RequestPolicyRule{
		Name:   "block-mutation",
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Methods: []string{"GET"}, PathPatterns: []string{`/graphql$`}},
		GraphQL: &config.RequestPolicyGraphQL{
			OperationTypes:    []string{"mutation"},
			RootFieldPatterns: []string{`^deleteRecord$`},
		},
	}
	m := batchMatcher(t, gqlRule)
	query := url.QueryEscape(`mutation { deleteRecord { id } }`)
	body := []byte(`{"requests":[{"method":"GET","url":"/graphql?query=` + query + `"}]}`)
	if d, parseOK := m.EvaluateBatch(batchMeta(), body); !parseOK || d.Action != config.ActionBlock {
		t.Fatalf("a GraphQL-over-GET mutation in a batch must block; got action=%q parseOK=%v", d.Action, parseOK)
	}
}

func TestEvaluateBatch_GraphQLOverGETBenignAllows(t *testing.T) {
	t.Parallel()
	gqlRule := config.RequestPolicyRule{
		Name:   "block-mutation",
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Methods: []string{"GET"}, PathPatterns: []string{`/graphql$`}},
		GraphQL: &config.RequestPolicyGraphQL{
			OperationTypes:    []string{"mutation"},
			RootFieldPatterns: []string{`^deleteRecord$`},
		},
	}
	m := batchMatcher(t, gqlRule)
	query := url.QueryEscape(`query { viewer { id } }`)
	body := []byte(`{"requests":[{"method":"GET","url":"/graphql?query=` + query + `"}]}`)
	if d, parseOK := m.EvaluateBatch(batchMeta(), body); !parseOK || d.Matched() {
		t.Fatalf("a benign GraphQL-over-GET query in a batch must allow; got matched=%v parseOK=%v", d.Matched(), parseOK)
	}
}

func TestEvaluateBatch_GETNullBodyEvaluatesQuery(t *testing.T) {
	t.Parallel()
	gqlRule := config.RequestPolicyRule{
		Name:   "block-mutation",
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Methods: []string{"GET"}, PathPatterns: []string{`/graphql$`}},
		GraphQL: &config.RequestPolicyGraphQL{
			OperationTypes:    []string{"mutation"},
			RootFieldPatterns: []string{`^deleteRecord$`},
		},
	}
	m := batchMatcher(t, gqlRule)

	// An explicit JSON null body must be treated as no body so the GraphQL-over-GET
	// query string is still evaluated, not failed closed as an unparseable body.
	benign := url.QueryEscape(`query { viewer { id } }`)
	body := []byte(`{"requests":[{"method":"GET","url":"/graphql?query=` + benign + `","body":null}]}`)
	if d, parseOK := m.EvaluateBatch(batchMeta(), body); !parseOK || d.Matched() {
		t.Fatalf("GET sub-request with null body and benign query must allow; got matched=%v parseOK=%v", d.Matched(), parseOK)
	}

	// The query string is still inspected: a dangerous mutation with a null body blocks.
	mutation := url.QueryEscape(`mutation { deleteRecord { id } }`)
	body = []byte(`{"requests":[{"method":"GET","url":"/graphql?query=` + mutation + `","body":null}]}`)
	if d, parseOK := m.EvaluateBatch(batchMeta(), body); !parseOK || d.Action != config.ActionBlock {
		t.Fatalf("GET sub-request with null body and mutation query must block; got action=%q parseOK=%v", d.Action, parseOK)
	}
}

func TestEvaluateBatch_ContentTypeScopedRuleMatchesSubRequest(t *testing.T) {
	t.Parallel()
	rule := config.RequestPolicyRule{
		Name:   "block-sendmail-json",
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{PathPatterns: []string{`/sendMail$`}, ContentTypes: []string{"application/json"}},
		Reason: "sendMail is blocked for the agent runtime",
	}
	m := batchMatcher(t, rule)

	// A sub-request body is JSON by envelope definition, so a content-type-scoped
	// rule must still match an operation wrapped in a batch.
	body := []byte(`{"requests":[{"method":"POST","url":"/v1.0/me/sendMail","body":{"message":{}}}]}`)
	if d, parseOK := m.EvaluateBatch(batchMeta(), body); !parseOK || d.Action != config.ActionBlock {
		t.Fatalf("content-type-scoped rule must match a JSON-body batch sub-request; got action=%q parseOK=%v", d.Action, parseOK)
	}

	// The inferred content-type is body-gated: a bodyless sub-request carries no
	// content-type, matching a real bodyless request, so the JSON-scoped rule
	// does not fire (consistent with a direct bodyless request).
	bodyless := []byte(`{"requests":[{"method":"GET","url":"/v1.0/me/sendMail"}]}`)
	if d, parseOK := m.EvaluateBatch(batchMeta(), bodyless); !parseOK || d.Matched() {
		t.Fatalf("content-type-scoped rule must not match a bodyless sub-request; got matched=%v parseOK=%v", d.Matched(), parseOK)
	}
}

func TestEvaluateBatch_UnparseableEnvelopeFailsClosed(t *testing.T) {
	t.Parallel()
	m := batchMatcher(t, deleteRule())
	for _, body := range [][]byte{
		[]byte(`{"requests": not json`),                                       // malformed
		[]byte(`{"items":[]}`),                                                // wrong requests field
		[]byte(`{"requests":"not-array"}`),                                    // requests not an array
		[]byte(`{"requests":[{"url":"/v1.0/me/sendMail"}]}`),                  // missing method
		[]byte(`{"requests":[{"method":"POST"}]}`),                            // missing url
		[]byte(`{"requests":[{"method":123,"url":"/v1.0/me/sendMail"}]}`),     // method not a string
		[]byte(`{"requests":[{"method":"POST","url":"/v1.0/me/sendMail%"}]}`), // invalid url escape
		nil, // empty
	} {
		if _, parseOK := m.EvaluateBatch(batchMeta(), body); parseOK {
			t.Fatalf("envelope %q should not parse (fail closed)", body)
		}
	}
}

func TestEvaluateBatch_OverCapFailsClosed(t *testing.T) {
	t.Parallel()
	cfg := &config.RequestPolicy{
		Enabled:           true,
		OnParseError:      config.ActionBlock,
		OnOpaqueOperation: config.ActionBlock,
		Rules:             []config.RequestPolicyRule{deleteRule()},
		Batch: []config.RequestPolicyBatch{{
			Route:          config.RequestPolicyRoute{PathPatterns: []string{`/\$batch$`}},
			RequestsField:  "requests",
			MethodField:    "method",
			URLField:       "url",
			BodyField:      "body",
			MaxSubRequests: 2,
		}},
	}
	m, err := reqpolicy.NewMatcher(cfg)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	// 3 sub-requests exceeds the cap of 2 -> fail closed rather than inspect a prefix.
	body := []byte(`{"requests":[{"method":"GET","url":"/a"},{"method":"GET","url":"/b"},{"method":"GET","url":"/c"}]}`)
	if _, parseOK := m.EvaluateBatch(batchMeta(), body); parseOK {
		t.Fatal("over-cap batch must fail closed (parseOK=false)")
	}
}

func TestEvaluateBatch_NestedBatchBlocksInnerDangerousOp(t *testing.T) {
	t.Parallel()
	m := batchMatcher(t, deleteRule())
	// Outer $batch wraps a sub-request that is itself a $batch wrapping sendMail.
	inner := `{"requests":[{"method":"POST","url":"/v1.0/me/sendMail","body":{}}]}`
	body := []byte(`{"requests":[{"method":"POST","url":"/v1.0/$batch","body":` + inner + `}]}`)
	if d, _ := m.EvaluateBatch(batchMeta(), body); d.Action != config.ActionBlock {
		t.Fatalf("a sendMail nested one level deep in $batch must block; got %q", d.Action)
	}
}

func TestEvaluateBatch_NestedUnparseableBatchFailsClosed(t *testing.T) {
	t.Parallel()
	m := batchMatcher(t, deleteRule())
	body := []byte(`{"requests":[{"method":"POST","url":"/v1.0/$batch","body":{"notRequests":[]}}]}`)
	if d, parseOK := m.EvaluateBatch(batchMeta(), body); !parseOK || d.Action != config.ActionBlock || d.RuleName != "batch" {
		t.Fatalf("an unparseable nested batch must fail closed as batch; got action=%q rule=%q parseOK=%v", d.Action, d.RuleName, parseOK)
	}
}

func TestEvaluateBatch_AbsoluteSubRequestURLUsesPath(t *testing.T) {
	t.Parallel()
	rule := config.RequestPolicyRule{
		Name:   "block-sendmail-prefix",
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{PathPrefixes: []string{`/v1.0/me/sendMail`}},
		Reason: "sendMail is blocked for the agent runtime",
	}
	m := batchMatcher(t, rule)
	body := []byte(`{"requests":[{"method":"POST","url":"https://graph.example.com/v1.0/me/sendMail?ignored=true","body":{}}]}`)
	if d, parseOK := m.EvaluateBatch(batchMeta(), body); !parseOK || d.Action != config.ActionBlock {
		t.Fatalf("an absolute sub-request URL must route-match by path; got action=%q parseOK=%v", d.Action, parseOK)
	}
}

func TestEvaluateBatch_NoBatchRouteIsNoOp(t *testing.T) {
	t.Parallel()
	m := batchMatcher(t, deleteRule())
	// A request that does not match the batch route yields no batch decision.
	meta := reqpolicy.RequestMeta{Host: batchHost, Method: "POST", Path: "/v1.0/me/messages"}
	if d, parseOK := m.EvaluateBatch(meta, []byte(`{"requests":[]}`)); d.Matched() || !parseOK {
		t.Fatalf("non-batch route must be a no-op; got matched=%v parseOK=%v", d.Matched(), parseOK)
	}
}

func TestMatchesBatch(t *testing.T) {
	t.Parallel()
	m := batchMatcher(t, deleteRule())
	if !m.MatchesBatch(batchMeta()) {
		t.Error("the $batch path should match the batch route")
	}
	if m.MatchesBatch(reqpolicy.RequestMeta{Host: batchHost, Method: "POST", Path: "/v1.0/me/sendMail"}) {
		t.Error("a non-batch path should not match the batch route")
	}
}

func TestUninspectableBatch(t *testing.T) {
	t.Parallel()
	m := batchMatcher(t, deleteRule())
	if d := m.UninspectableBatch(batchMeta(), config.ActionBlock); d.Action != config.ActionBlock {
		t.Errorf("uninspectable batch with block action should block; got %q", d.Action)
	}
	if d := m.UninspectableBatch(batchMeta(), config.ActionAllow); d.Matched() {
		t.Error("uninspectable batch with allow action should not match")
	}
	if d := m.UninspectableBatch(reqpolicy.RequestMeta{Host: batchHost, Path: "/not-batch"}, config.ActionBlock); d.Matched() {
		t.Error("uninspectable batch off-route should not match")
	}
}
