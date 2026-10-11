// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonrpc

import (
	"strings"
	"testing"
)

func TestValidateMessageKeys(t *testing.T) {
	for _, tc := range []struct {
		name  string
		raw   string
		valid bool
	}{
		{"canonical response", `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`, true},
		{"custom fields", `{"jsonrpc":"2.0","custom":1,"Custom":2}`, true},
		{"case sensitive arguments", `{"method":"tools/call","params":{"name":"read","arguments":{"PATH":1,"Path":2}}}`, true},
		{"case sensitive schema properties", `{"result":{"tools":[{"name":"read","inputSchema":{"properties":{"Name":{},"name":{}}}}]}}`, true},
		{"canonical error", `{"error":{"code":1,"message":"ordinary","data":{"Name":1,"name":2}}}`, true},
		{"canonical resource", `{"method":"resources/read","params":{"uri":"file:///record"}}`, true},
		{"scalar shape owned by consumer", `1`, true},
		{"nested array shape owned by consumer", `[[{"Result":{}}]]`, true},
		{"null result", `{"result":null}`, true},
		{"field type owned by consumer", `{"method":123,"result":false}`, true},
		{"empty batch", `[]`, true},
		{"canonical batch", `[{"result":{}},{"method":"tools/call"}]`, true},
		{"empty input", ``, false},
		{"malformed", `{"result":`, false},
		{"invalid encoding", "{\"result\":\"\xff\"}", false},
		{"trailing value", `{} {}`, false},
		{"exact duplicate", `{"id":1,"id":2}`, false},
		{"escaped duplicate", `{"id":1,"\u0069d":2}`, false},
		{"envelope alias", `{"Result":{}}`, false},
		{"batch alias", `[{"result":{}},{"Result":{}}]`, false},
		{"nested error alias", `{"error":{"Message":"ordinary"}}`, false},
		{"tool routing alias", `{"method":"tools/call","params":{"Name":"read"}}`, false},
		{"resource routing alias", `{"method":"resources/read","params":{"URI":"file:///record"}}`, false},
		{"result alias", `{"result":{"Tools":[]}}`, false},
		{"tool field alias", `{"result":{"tools":[{"Name":"read"}]}}`, false},
		{"content alias", `{"result":{"content":[{"Text":"ordinary"}]}}`, false},
		{"type error cannot hide alias", `{"method":123,"params":false,"result":{"Tools":[]}}`, false},
		{"nested free form duplicate", `{"method":"tools/call","params":{"arguments":{"PATH":1,"PATH":2}}}`, false},
		{"batch syntax", `[{},`, false},
		{"excessive depth", strings.Repeat("[", 10001) + strings.Repeat("]", 10001), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateMessageKeys([]byte(tc.raw))
			if (err == nil) != tc.valid {
				t.Fatalf("ValidateMessageKeys() error=%v, valid=%v", err, tc.valid)
			}
		})
	}
}
