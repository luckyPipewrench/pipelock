// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonrpc

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestExtractTextOnlyParityAndRequestIsolation(t *testing.T) {
	inputs := []string{
		"", "null", "{", `"plain text"`, "42", `{"value":[1,2,3]}`,
		`{"content":[{"type":"text","text":"first body"}]}`,
		`{"content":[{"type":"text","text":"second body"}],"structuredContent":{"count":42,"label":"text"}}`,
		`{"content":[{"type":"resource","resource":{"text":"resource text"}}]}`,
		`{"content":[{"type":"image","text":"caption","data":"visible text"}]}`,
		`{"content":[{"type":"resource_link","name":"name","title":"title","description":"description"}]}`,
		`{"content":[],"structuredContent":{"number":1.25,"nested":["one","two"]}}`,
		`{"alpha":"first","beta":["second",3,true,null]}`,
		deepJSONRPCObject(maxExtractDepth),
		deepJSONRPCObject(maxExtractDepth + 2),
		fmt.Sprintf(`{"content":[{"type":"text","text":"visible"}],"hidden":%s}`, deepJSONRPCObject(maxExtractDepth+2)),
	}
	for pass := 0; pass < 2; pass++ {
		for i := range inputs {
			index := i
			if pass != 0 {
				index = len(inputs) - 1 - i
			}
			t.Run(fmt.Sprintf("pass_%d_input_%d", pass, index), func(t *testing.T) {
				raw := json.RawMessage(inputs[index])
				full := ExtractTextResult(raw)
				textOnly := ExtractTextOnlyResult(raw)
				if textOnly.Text != full.Text || textOnly.Truncated != full.Truncated || textOnly.Numeric != "" {
					t.Fatalf("text-only result differs: got %+v, full %+v", textOnly, full)
				}
				if got := ExtractText(raw); got != full.Text {
					t.Fatalf("text wrapper differs: got %q, want %q", got, full.Text)
				}
			})
		}
	}
}
