// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import (
	"strings"
	"testing"
)

func TestGraphQLKeyAliases(t *testing.T) {
	for _, raw := range []string{
		`{"query":"query{viewer}","Query":"mutation{update}"}`,
		`{"query":"mutation{update}","query":"query{viewer}"}`,
		`{"query":"query{viewer}","operationName":"Read","OperationName":"Write"}`,
		`{"query":"query{viewer}","operationName":"Read","operationName":"Write"}`,
		`[{"query":"query{viewer}"},{"query":"query{viewer}","QUERY":"mutation{update}"}]`,
		`[{"query":"query{viewer}","operationName":"Read","operationName":"Write"}]`,
	} {
		if ops, ok, opaque := ExtractGraphQL([]byte(raw)); ok || opaque || len(ops) != 0 {
			t.Errorf("ambiguous GraphQL accepted: %s", raw)
		}
	}
	for _, raw := range []string{`{"query":"query{viewer}","variables":{"id":"sample","ID":"other"},"extensions":{"a":1,"A":2}}`, `[{"query":"query{viewer}"},{"query":"mutation{update}"}]`} {
		if ops, ok, opaque := ExtractGraphQL([]byte(raw)); !ok || opaque || len(ops) == 0 {
			t.Errorf("canonical control rejected: %s", raw)
		}
	}
}

func TestGraphQLFreeFormDepthCompatibility(t *testing.T) {
	raw := `{"query":"query{viewer{id}}","variables":{"nested":` + strings.Repeat("[", 200) + `0` + strings.Repeat("]", 200) + `},"extensions":{"id":1,"ID":2}}`
	if ops, ok, opaque := ExtractGraphQL([]byte(raw)); !ok || opaque || len(ops) != 1 {
		t.Fatalf("free-form depth rejected: ops=%v parsed=%v opaque=%v", ops, ok, opaque)
	}
}
