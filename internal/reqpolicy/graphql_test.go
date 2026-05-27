// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// gqlBody wraps a query string in the GraphQL-over-HTTP JSON envelope.
func gqlBody(t *testing.T, query string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func extractQuery(t *testing.T, query string) []RequestOperation {
	t.Helper()
	ops, parseOK, opaque := ExtractGraphQL(gqlBody(t, query))
	if !parseOK {
		t.Fatalf("query %q: expected parseOK, got parse error", query)
	}
	if opaque {
		t.Fatalf("query %q: unexpected opaque", query)
	}
	return ops
}

func hasField(ops []RequestOperation, field string) bool {
	for _, op := range ops {
		for _, f := range op.RootFields {
			if f == field {
				return true
			}
		}
	}
	return false
}

func TestExtractGraphQL_RootFields(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantKind   string
		wantFields []string
		wantAlias  bool
	}{
		{"simple mutation", `mutation { deleteRecord(id: 1) { id } }`, gqlMutation, []string{"deleteRecord"}, false},
		{"alias resolves to real field", `mutation { x: deleteRecord(id: 1) { id } }`, gqlMutation, []string{"deleteRecord"}, true},
		{"shorthand query", `{ viewer { id } }`, gqlQuery, []string{"viewer"}, false},
		{"named query", `query Me { viewer { id } }`, gqlQuery, []string{"viewer"}, false},
		{"subscription", `subscription { recordUpdated { id } }`, gqlSubscription, []string{"recordUpdated"}, false},
		{"multiple root fields", `mutation { a b c }`, gqlMutation, []string{"a", "b", "c"}, false},
		{"args with nested object braces", `mutation { createNote(input: {body: "x", tags: ["a"]}) { id } }`, gqlMutation, []string{"createNote"}, false},
		{"variables and directives skipped", `mutation Op($id: ID!) @dir(x: 1) { deleteRecord(id: $id) @include(if: true) { id } }`, gqlMutation, []string{"deleteRecord"}, false},
		{"keyword-shaped field name stays a query", `query { mutationLog { id } }`, gqlQuery, []string{"mutationLog"}, false},
		{"comma whitespace tolerant", `mutation{,a,,b,}`, gqlMutation, []string{"a", "b"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ops := extractQuery(t, tc.query)
			if len(ops) != 1 {
				t.Fatalf("want 1 op, got %d (%+v)", len(ops), ops)
			}
			op := ops[0]
			if op.Kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", op.Kind, tc.wantKind)
			}
			if strings.Join(op.RootFields, ",") != strings.Join(tc.wantFields, ",") {
				t.Errorf("root fields = %v, want %v", op.RootFields, tc.wantFields)
			}
			if op.Aliased != tc.wantAlias {
				t.Errorf("aliased = %v, want %v", op.Aliased, tc.wantAlias)
			}
		})
	}
}

// The core evasion cases: a dangerous root field must be discoverable no matter
// how it is wrapped, while a keyword that only appears inside a string, comment,
// or argument value must NOT be reported as a root field.
func TestExtractGraphQL_Evasions(t *testing.T) {
	t.Run("fragment spread hides root field", func(t *testing.T) {
		ops := extractQuery(t, `mutation { ...f } fragment f on Mutation { deleteRecord(id: 1) { id } }`)
		if !hasField(ops, "deleteRecord") {
			t.Fatalf("deleteRecord hidden in fragment not surfaced: %+v", ops)
		}
	})
	t.Run("inline fragment at root", func(t *testing.T) {
		ops := extractQuery(t, `mutation { ... on Mutation { deleteRecord } }`)
		if !hasField(ops, "deleteRecord") {
			t.Fatalf("deleteRecord in inline fragment not surfaced: %+v", ops)
		}
	})
	t.Run("nested fragment chain", func(t *testing.T) {
		ops := extractQuery(t, `mutation { ...a } fragment a on M { ...b } fragment b on M { deleteRecord }`)
		if !hasField(ops, "deleteRecord") {
			t.Fatalf("deleteRecord in nested fragment not surfaced: %+v", ops)
		}
	})
	t.Run("multi-op dangerous sibling surfaced", func(t *testing.T) {
		ops := extractQuery(t, `query Safe { viewer { id } } mutation Bad { deleteRecord }`)
		if len(ops) != 2 || !hasField(ops, "deleteRecord") {
			t.Fatalf("dangerous sibling op not surfaced: %+v", ops)
		}
	})
	t.Run("keyword in block string is not a field", func(t *testing.T) {
		ops := extractQuery(t, `mutation { createNote(body: """please deleteRecord everything""") { id } }`)
		if hasField(ops, "deleteRecord") {
			t.Fatalf("block-string content leaked as field: %+v", ops)
		}
		if !hasField(ops, "createNote") {
			t.Fatalf("createNote field missing: %+v", ops)
		}
	})
	t.Run("keyword in line comment is not a field", func(t *testing.T) {
		ops := extractQuery(t, "mutation {\n  # deleteRecord here\n  createNote { id }\n}")
		if hasField(ops, "deleteRecord") {
			t.Fatalf("comment content leaked as field: %+v", ops)
		}
	})
	t.Run("keyword in argument string is not a field", func(t *testing.T) {
		ops := extractQuery(t, `mutation { createNote(text: "deleteRecord") { id } }`)
		if hasField(ops, "deleteRecord") {
			t.Fatalf("argument string leaked as field: %+v", ops)
		}
	})
	t.Run("brace inside string does not break selection", func(t *testing.T) {
		ops := extractQuery(t, `mutation { createNote(body: "}{ deleteRecord }{") { id } }`)
		if hasField(ops, "deleteRecord") || !hasField(ops, "createNote") {
			t.Fatalf("string-embedded braces broke parsing: %+v", ops)
		}
	})
	t.Run("BOM prefix tolerated", func(t *testing.T) {
		ops := extractQuery(t, "\ufeffmutation { deleteRecord }")
		if !hasField(ops, "deleteRecord") {
			t.Fatalf("BOM-prefixed query not parsed: %+v", ops)
		}
	})
	t.Run("json unicode-escaped field name decodes and is caught", func(t *testing.T) {
		// The JSON layer decodes d -> 'd' before the GraphQL lexer sees it,
		// so the real field name surfaces.
		body := []byte(`{"query":"mutation { \u0064eleteRecord }"}`)
		ops, ok, opaque := ExtractGraphQL(body)
		if !ok || opaque {
			t.Fatalf("expected parseOK non-opaque, got ok=%v opaque=%v", ok, opaque)
		}
		if !hasField(ops, "deleteRecord") {
			t.Fatalf("json-unicode-escaped field not surfaced: %+v", ops)
		}
	})
}

func TestExtractGraphQL_Batch(t *testing.T) {
	body := []byte(`[{"query":"query { viewer { id } }"},{"query":"mutation { deleteRecord }"}]`)
	ops, ok, opaque := ExtractGraphQL(body)
	if !ok || opaque {
		t.Fatalf("batch: ok=%v opaque=%v", ok, opaque)
	}
	if len(ops) != 2 || !hasField(ops, "deleteRecord") {
		t.Fatalf("batch did not surface all operations: %+v", ops)
	}
}

func TestExtractGraphQL_OpaqueAndParseError(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantParseOK bool
		wantOpaque  bool
	}{
		{"apq hash only", `{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}`, true, true},
		{"empty query string", `{"query":""}`, true, true},
		{"whitespace query", `{"query":"   "}`, true, true},
		{"unterminated selection", `{"query":"mutation { deleteRecord "}`, false, false},
		{"unterminated string", `{"query":"mutation { x(a: \"oops) { id } }"}`, false, false},
		{"graphql-level backslash escape fails closed", `{"query":"mutation { \\u0064eleteJob }"}`, false, false},
		{"invalid json", `not json at all`, false, false},
		{"empty body", ``, false, false},
		{"json number top level", `42`, false, false},
		{"stray top-level token", `{"query":"mutation deleteRecord"}`, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, parseOK, opaque := ExtractGraphQL([]byte(tc.body))
			if parseOK != tc.wantParseOK || opaque != tc.wantOpaque {
				t.Fatalf("ExtractGraphQL(%s) = parseOK %v, opaque %v; want %v, %v",
					tc.body, parseOK, opaque, tc.wantParseOK, tc.wantOpaque)
			}
		})
	}
}

// Regression: a duplicate fragment name must fail closed. A "last-wins" map
// would let a benign shadow fragment hide a dangerous first definition that a
// first-wins server (e.g. graphql-js) executes.
func TestExtractGraphQL_DuplicateFragmentFailsClosed(t *testing.T) {
	q := `mutation { ...f } fragment f on M { deleteRecord } fragment f on M { safeField }`
	if _, parseOK, _ := ExtractGraphQL(gqlBody(t, q)); parseOK {
		t.Fatal("duplicate fragment names must fail closed, not resolve last-wins")
	}
}

// Regression: exhausting the fragment-expansion budget with benign fields must
// fail closed, not silently truncate and drop a trailing dangerous field.
func TestExtractGraphQL_ExpansionCapFailsClosed(t *testing.T) {
	var b strings.Builder
	b.WriteString("mutation {")
	for i := 0; i < maxFragmentExpansion+10; i++ {
		b.WriteString(" f")
	}
	b.WriteString(" deleteRecord }")
	if _, parseOK, _ := ExtractGraphQL(gqlBody(t, b.String())); parseOK {
		t.Fatal("expansion-cap exhaustion must fail closed")
	}
}

func TestExtractGraphQL_CyclicFragmentFailsClosed(t *testing.T) {
	// Fragment cycles are spec-invalid. Fail closed rather than partially
	// classifying a graph whose execution semantics depend on server behavior.
	if _, parseOK, _ := ExtractGraphQL(gqlBody(t, `mutation { ...a } fragment a on M { ...b } fragment b on M { ...a deleteRecord }`)); parseOK {
		t.Fatal("cyclic fragments must fail closed")
	}
}

func TestExtractGraphQL_DeepNestingFailsClosed(t *testing.T) {
	// Nested inline fragments recurse the selection-set parser, so exceeding
	// the depth cap must fail closed. (Nested field selection sets are skipped
	// by brace-balancing and are bounded by the token cap instead.)
	n := maxSelectionDepth + 5
	q := "mutation {" + strings.Repeat(" ... on T {", n) + " deleteRecord" + strings.Repeat(" }", n) + " }"
	_, parseOK, _ := ExtractGraphQL(gqlBody(t, q))
	if parseOK {
		t.Fatal("excessively nested inline fragments should fail closed")
	}
}

// End-to-end: a rule with a GraphQL predicate blocks a dangerous mutation and
// allows a benign query, matching every operation in a multi-op document.
func TestExtractGraphQL_ParserCoverage(t *testing.T) {
	ok := []struct{ name, query, field string }{
		{"escaped quote in arg string", `mutation { createNote(t: "a\"b") { id } }`, "createNote"},
		{"escaped triple quote in block string", `mutation { createNote(t: """a\"""b""") { id } }`, "createNote"},
		{"bare directives on op and field", `mutation @auth { deleteRecord @foo }`, "deleteRecord"},
		{"fragment with directive", `mutation { ...f } fragment f on M @dir { deleteRecord }`, "deleteRecord"},
		{"inline fragment without type condition", `query { ... { viewer } }`, "viewer"},
		{"list argument balanced", `mutation { setTags(ids: [1, 2, 3]) { id } }`, "setTags"},
		{"spread with directive", `query { ...f @include(if: true) } fragment f on Q { viewer }`, "viewer"},
		{"multiple directives on op", `mutation @a @b { deleteRecord }`, "deleteRecord"},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			if ops := extractQuery(t, tc.query); !hasField(ops, tc.field) {
				t.Fatalf("expected field %q in %+v", tc.field, ops)
			}
		})
	}

	bad := []struct{ name, query string }{
		{"unterminated block string", `mutation { x(a: """oops) }`},
		{"unclosed arguments to EOF", `mutation { x(a: 1`},
		{"alias without field name", `mutation { x: }`},
		{"directive without name", `mutation { x @ }`},
		{"string with raw newline", "mutation { x(a: \"line\nmore\") }"},
		{"unknown top-level keyword", `frag x on Y { a }`},
		{"lone dot not ellipsis", `query { a.b }`},
		{"fragment missing name", `query { a } fragment { b }`},
		{"fragment missing on keyword", `query { a } fragment f X { b }`},
		{"fragment missing type condition", `query { a } fragment f on { b }`},
		{"empty operation selection", `query { }`},
		{"empty inline fragment selection", `query { ... on T { } }`},
		{"mismatched argument brackets", `mutation { safe(arg: [1, 2}) deleteRecord }`},
		{"document is only a comment", `# nothing here`},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, parseOK, _ := ExtractGraphQL(gqlBody(t, tc.query)); parseOK {
				t.Fatalf("expected parse error for %q", tc.query)
			}
		})
	}

	t.Run("batch with parse-error element fails closed", func(t *testing.T) {
		body := []byte(`[{"query":"query { a }"},{"query":"mutation { "}]`)
		if _, parseOK, _ := ExtractGraphQL(body); parseOK {
			t.Fatal("batch with a malformed element must fail closed")
		}
	})
	t.Run("batch with opaque element marks opaque but surfaces the rest", func(t *testing.T) {
		body := []byte(`[{"query":"mutation { deleteRecord }"},{"operationName":"x"}]`)
		ops, parseOK, opaque := ExtractGraphQL(body)
		if !parseOK || !opaque {
			t.Fatalf("batch opaque element: parseOK=%v opaque=%v", parseOK, opaque)
		}
		if !hasField(ops, "deleteRecord") {
			t.Fatalf("good element ops missing: %+v", ops)
		}
	})
	t.Run("empty batch fails closed", func(t *testing.T) {
		if _, parseOK, _ := ExtractGraphQL([]byte(`[]`)); parseOK {
			t.Fatal("empty batch should fail closed")
		}
	})
	t.Run("malformed batch element type fails closed", func(t *testing.T) {
		if _, parseOK, _ := ExtractGraphQL([]byte(`[{"query":123}]`)); parseOK {
			t.Fatal("non-string query should fail closed")
		}
	})
	t.Run("unknown fragment spread fails closed", func(t *testing.T) {
		if _, parseOK, _ := ExtractGraphQL(gqlBody(t, `query { ...doesNotExist }`)); parseOK {
			t.Fatal("unknown spread should fail closed")
		}
	})
}

func TestNewMatcher_BadGraphQLPattern(t *testing.T) {
	// Defense in depth: NewMatcher recompiles the predicate even though config
	// validation already rejects a bad pattern upstream.
	_, err := NewMatcher(&config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{{
		Name:    "bad",
		Action:  config.ActionBlock,
		Route:   config.RequestPolicyRoute{Hosts: []string{"api.example.com"}},
		GraphQL: &config.RequestPolicyGraphQL{RootFieldPatterns: []string{"("}},
	}}})
	if err == nil {
		t.Fatal("expected error for invalid graphql root_field_pattern")
	}
}

func TestMatcher_GraphQLPredicate(t *testing.T) {
	m, err := NewMatcher(&config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{{
		Name:   "block-destructive-mutations",
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{"api.example.com"}},
		GraphQL: &config.RequestPolicyGraphQL{
			OperationTypes:    []string{gqlMutation},
			RootFieldPatterns: []string{`(?i)(delete|destroy|archive)`},
		},
	}}})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	block := func(q string) Decision {
		return m.Evaluate(RequestMeta{Host: "api.example.com", Method: "POST", Operations: extractQuery(t, q)})
	}

	if d := block(`mutation { deleteRecord(id: 1) { id } }`); !d.Enforced() || d.Action != config.ActionBlock {
		t.Fatalf("destructive mutation not blocked: %+v", d)
	}
	if d := block(`mutation { x: archiveAccount { id } }`); !d.Enforced() {
		t.Fatalf("aliased destructive mutation not blocked: %+v", d)
	}
	if d := block(`query { viewer { id } }`); d.Matched() {
		t.Fatalf("benign query should not match: %+v", d)
	}
	if d := block(`mutation { updateProfile(name: "x") { id } }`); d.Matched() {
		t.Fatalf("non-destructive mutation should not match: %+v", d)
	}
	// Multi-op: a benign query alongside a destructive mutation must still block.
	if d := block(`query Safe { viewer } mutation Bad { deleteRecord }`); !d.Enforced() {
		t.Fatalf("destructive op in multi-op document not blocked: %+v", d)
	}
	// No operations (e.g. opaque/non-GraphQL) => predicate does not match.
	if d := m.Evaluate(RequestMeta{Host: "api.example.com", Method: "POST"}); d.Matched() {
		t.Fatalf("empty operations should not match graphql predicate: %+v", d)
	}
}

func TestMatcher_GraphQLOperationTypeOnly(t *testing.T) {
	m, err := NewMatcher(&config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{{
		Name:    "warn-all-mutations",
		Action:  config.ActionWarn,
		Route:   config.RequestPolicyRoute{Hosts: []string{"api.example.com"}},
		GraphQL: &config.RequestPolicyGraphQL{OperationTypes: []string{gqlMutation}},
	}}})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	d := m.Evaluate(RequestMeta{Host: "api.example.com", Operations: extractQuery(t, `mutation { anything }`)})
	if d.Action != config.ActionWarn {
		t.Fatalf("operation-type-only predicate should warn on any mutation: %+v", d)
	}
	d = m.Evaluate(RequestMeta{Host: "api.example.com", Operations: extractQuery(t, `query { viewer }`)})
	if d.Matched() {
		t.Fatalf("query should not match a mutation-only predicate: %+v", d)
	}
}
