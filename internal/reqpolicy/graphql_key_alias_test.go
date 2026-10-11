// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import "testing"

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
	for _, raw := range []string{`{"query":"query{viewer}","variables":{"id":"sample"},"extensions":{}}`, `[{"query":"query{viewer}"},{"query":"mutation{update}"}]`} {
		if ops, ok, opaque := ExtractGraphQL([]byte(raw)); !ok || opaque || len(ops) == 0 {
			t.Errorf("canonical control rejected: %s", raw)
		}
	}
}
