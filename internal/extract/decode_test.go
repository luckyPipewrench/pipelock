// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"encoding/json"
	"testing"
)

func TestDecodeJSONPreservesCompleteDocument(t *testing.T) {
	for _, raw := range []string{`{"n":1e999}`, `{"n":-1e999}`, `{"n":9007199254740993}`, ` {"n":1.50E+3} `} {
		t.Run(raw, func(t *testing.T) {
			var value map[string]any
			if err := DecodeJSON([]byte(raw), &value); err != nil {
				t.Fatal(err)
			}
			if _, ok := value["n"].(json.Number); !ok {
				t.Fatalf("lost number type: %T", value["n"])
			}
			for _, tail := range []string{` trailing`, ` {}`, ` 1`} {
				if err := DecodeJSON([]byte(raw+tail), &value); err == nil {
					t.Error("accepted partial document")
				}
			}
		})
	}
	for _, raw := range []string{"", `{"n":}`, `[`, `NaN`, `1e+`} {
		var value any
		if err := DecodeJSON([]byte(raw), &value); err == nil {
			t.Errorf("accepted malformed %q", raw)
		}
	}
	var value any
	if err := DecodeJSON([]byte(`null`), &value); err != nil || value != nil {
		t.Fatalf("null: %v, %v", value, err)
	}
	var target int
	if err := DecodeJSON([]byte(`"wrong type"`), &target); err == nil {
		t.Fatal("lost destination type error")
	}
}
