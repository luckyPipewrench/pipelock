// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonrpc

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestExtremeNumbersPreserveStringAndKeyExtraction(t *testing.T) {
	for _, number := range []string{"1.5", "-1e999", "1e999", "[1e999]"} {
		raw := json.RawMessage(`{"a":"first","b":"second","n":` + number + `}`)
		values := ExtractStringsFromJSONResult(raw)
		keys := ExtractKeysFromJSONResult(raw)
		if values.Truncated || !slices.Equal(values.Strings, []string{"first", "second"}) {
			t.Fatalf("number %s disabled value extraction: %+v", number, values)
		}
		if keys.Truncated || !slices.Equal(keys.Keys, []string{"a", "b", "n"}) {
			t.Fatalf("number %s disabled key extraction: %+v", number, keys)
		}
	}
	for _, raw := range []json.RawMessage{[]byte(`{"a":"first"} {}`), []byte(`{"a":"first","n":1e}`)} {
		if got := ExtractStringsFromJSONResult(raw); len(got.Strings) != 0 {
			t.Fatalf("invalid JSON extracted strings: %+v", got)
		}
		if got := ExtractKeysFromJSONResult(raw); len(got.Keys) != 0 {
			t.Fatalf("invalid JSON extracted keys: %+v", got)
		}
	}
}
