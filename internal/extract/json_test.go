// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAllStringsFromJSON_NestedObjects(t *testing.T) {
	raw := json.RawMessage(`{"a": {"b": "value1", "c": "value2"}, "d": "value3"}`)
	result := AllStringsFromJSON(raw)
	if len(result) == 0 {
		t.Fatal("expected non-empty result")
	}
	got := make(map[string]struct{}, len(result))
	for _, s := range result {
		got[s] = struct{}{}
	}
	for _, want := range []string{"a", "b", "value1", "c", "value2", "d", "value3"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing exact token %q in result: %v", want, result)
		}
	}
}

func TestAllStringsFromJSON_Arrays(t *testing.T) {
	raw := json.RawMessage(`["hello", "world", 42, true]`)
	result := AllStringsFromJSON(raw)
	got := make(map[string]struct{}, len(result))
	for _, s := range result {
		got[s] = struct{}{}
	}
	for _, want := range []string{"hello", "world", "42", "true"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing exact token %q in result: %v", want, result)
		}
	}
}

func TestAllStringsFromJSONOrdered_PreservesSourceOrder(t *testing.T) {
	raw := json.RawMessage(`{"z":"ignore previous","a":"instructions","nested":{"b":"ignora","a":"las instrucciones anteriores"}}`)
	result := AllStringsFromJSONOrdered(raw)
	want := []string{"z", "ignore previous", "a", "instructions", "nested", "b", "ignora", "a", "las instrucciones anteriores"}
	if len(result) != len(want) {
		t.Fatalf("len(result) = %d, want %d: %#v", len(result), len(want), result)
	}
	for i := range want {
		if result[i] != want[i] {
			t.Fatalf("result[%d] = %q, want %q; all=%#v", i, result[i], want[i], result)
		}
	}
}

func TestAllStringsFromJSON_DepthLimit(t *testing.T) {
	// Build deeply nested JSON: {"a":{"a":{"a":...}}} at 70 levels
	var b strings.Builder
	const depth = 70
	for i := 0; i < depth; i++ {
		b.WriteString(`{"a":`)
	}
	b.WriteString(`"deep"`)
	for i := 0; i < depth; i++ {
		b.WriteString(`}`)
	}
	raw := json.RawMessage(b.String())
	result := AllStringsFromJSON(raw)
	// Should not panic or stack overflow. Some strings extracted, but "deep"
	// is beyond maxExtractDepth (64) so it should be truncated.
	if len(result) == 0 {
		t.Fatal("expected some strings extracted from outer levels")
	}
	// Verify we got keys from the outer levels.
	got := make(map[string]struct{}, len(result))
	for _, s := range result {
		got[s] = struct{}{}
	}
	if _, ok := got["a"]; !ok {
		t.Error("expected at least the key 'a' from outer levels")
	}
	// "deep" is nested at depth 70, beyond maxExtractDepth (64).
	if _, present := got["deep"]; present {
		t.Error("did not expect \"deep\" beyond maxExtractDepth")
	}
}

func TestAllStringsFromJSON_EmptyInput(t *testing.T) {
	result := AllStringsFromJSON(nil)
	if len(result) != 0 {
		t.Errorf("expected empty result for nil input, got %d", len(result))
	}

	result = AllStringsFromJSON(json.RawMessage(""))
	if len(result) != 0 {
		t.Errorf("expected empty result for empty input, got %d", len(result))
	}
}

func TestJSONLeafPayloads(t *testing.T) {
	limits := JSONLeafLimits{MaxDepth: 2, MaxStreams: 2, MaxPathBytes: 32}
	tests := []struct {
		name     string
		raw      string
		limits   JSONLeafLimits
		complete bool
		want     map[string]string
	}{
		{
			name:     "partition values by escaped path",
			raw:      `{"messages":[{"content":"first","count":2}],"enabled":true}`,
			limits:   JSONLeafLimits{MaxDepth: 3, MaxStreams: 3, MaxPathBytes: 64},
			complete: true,
			want:     map[string]string{"$/messages/0/content": "first", "$/messages/0/count": "2", "$/enabled": "true"},
		},
		{name: "malformed input fails closed", raw: `{"unterminated"`, limits: limits},
		{name: "depth limit fails closed", raw: `[[["deep"]]]`, limits: limits},
		{name: "stream limit fails closed", raw: `{"one":"1","two":"2","three":"3"}`, limits: limits},
		{name: "path limit fails closed", raw: `{"this-path-is-too-long":"value"}`, limits: JSONLeafLimits{MaxDepth: 2, MaxStreams: 2, MaxPathBytes: 16}},
		{name: "invalid limits fail closed", raw: `"value"`, limits: JSONLeafLimits{}},
		{name: "trailing content fails closed", raw: `{"value":"ok"} trailing`, limits: limits},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, complete := JSONLeafPayloads(json.RawMessage(tt.raw), tt.limits)
			if complete != tt.complete {
				t.Fatalf("complete = %t, want %t; payloads=%#v", complete, tt.complete, got)
			}
			if !complete {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("payload count = %d, want %d: %#v", len(got), len(tt.want), got)
			}
			for path, want := range tt.want {
				if value := string(got[path]); value != want {
					t.Errorf("payload %q = %q, want %q", path, value, want)
				}
			}
		})
	}
}

func TestJSONLeafPayloadsPartial(t *testing.T) {
	t.Run("retains newest representable leaves", func(t *testing.T) {
		got, valid := JSONLeafPayloadsPartial(json.RawMessage(`{"one":"1","two":2,"three":true,"four":null}`), JSONLeafLimits{
			MaxDepth: 4, MaxStreams: 2, MaxPathBytes: 64,
		})
		if !valid {
			t.Fatal("partial extraction rejected valid JSON")
		}
		if len(got) != 2 || string(got["$/two"]) != "2" || string(got["$/three"]) != "true" {
			t.Fatalf("partial payloads = %#v, want newest scalar leaves", got)
		}
	})

	t.Run("long paths receive stable opaque keys", func(t *testing.T) {
		limits := JSONLeafLimits{MaxDepth: 4, MaxStreams: 2, MaxPathBytes: 8}
		first, valid := JSONLeafPayloadsPartial(json.RawMessage(`{"this-key-is-long":"first"}`), limits)
		if !valid || len(first) != 1 {
			t.Fatalf("first payloads = %#v, valid=%t", first, valid)
		}
		second, valid := JSONLeafPayloadsPartial(json.RawMessage(`{"this-key-is-long":"second"}`), limits)
		if !valid || len(second) != 1 {
			t.Fatalf("second payloads = %#v, valid=%t", second, valid)
		}
		for path := range first {
			if string(second[path]) != "second" {
				t.Fatalf("opaque path %q was not stable: %#v", path, second)
			}
		}
	})

	t.Run("depth limit omits only deep leaves", func(t *testing.T) {
		got, valid := JSONLeafPayloadsPartial(json.RawMessage(`{"shallow":"kept","deep":{"nested":{"value":"omitted"}}}`), JSONLeafLimits{
			MaxDepth: 1, MaxStreams: 2, MaxPathBytes: 64,
		})
		if !valid || string(got["$/shallow"]) != "kept" {
			t.Fatalf("depth-limited payloads = %#v, valid=%t", got, valid)
		}
		if _, ok := got["$/deep/nested/value"]; ok {
			t.Fatalf("depth-limited payloads retained deep leaf: %#v", got)
		}
	})

	t.Run("arrays nulls and escaped keys remain representable", func(t *testing.T) {
		got, valid := JSONLeafPayloadsPartial(json.RawMessage(`{"a/b~c":[null,2,true,"text"]}`), JSONLeafLimits{
			MaxDepth: 4, MaxStreams: 8, MaxPathBytes: 64,
		})
		if !valid || string(got["$/a~1b~0c/1"]) != "2" || string(got["$/a~1b~0c/2"]) != "true" || string(got["$/a~1b~0c/3"]) != "text" {
			t.Fatalf("array payloads = %#v, valid=%t", got, valid)
		}
	})

	t.Run("depth skip consumes nested arrays", func(t *testing.T) {
		got, valid := JSONLeafPayloadsPartial(json.RawMessage(`{"keep":"yes","drop":[{"nested":"no"}]}`), JSONLeafLimits{
			MaxDepth: 1, MaxStreams: 4, MaxPathBytes: 64,
		})
		if !valid || string(got["$/keep"]) != "yes" || len(got) != 1 {
			t.Fatalf("array depth-skip payloads = %#v, valid=%t", got, valid)
		}
	})

	for _, limits := range []JSONLeafLimits{{}, {MaxDepth: -1, MaxStreams: 1, MaxPathBytes: 1}} {
		if got, valid := JSONLeafPayloadsPartial(json.RawMessage(`"value"`), limits); valid || got != nil {
			t.Fatalf("invalid limits payload = %#v, valid=%t", got, valid)
		}
	}
	if got, valid := JSONLeafPayloadsPartial(json.RawMessage(`{"value":"ok"} trailing`), JSONLeafLimits{MaxDepth: 2, MaxStreams: 2, MaxPathBytes: 16}); valid || got != nil {
		t.Fatalf("trailing payload = %#v, valid=%t", got, valid)
	}

	for _, raw := range []json.RawMessage{nil, json.RawMessage(`{"unterminated"`)} {
		if got, valid := JSONLeafPayloadsPartial(raw, JSONLeafLimits{MaxDepth: 2, MaxStreams: 2, MaxPathBytes: 16}); valid || got != nil {
			t.Fatalf("invalid partial payload = %#v, valid=%t", got, valid)
		}
	}
}

func TestAllStringsFromJSON_InvalidJSON(t *testing.T) {
	result := AllStringsFromJSON(json.RawMessage(`{invalid json`))
	if len(result) != 0 {
		t.Errorf("expected empty result for invalid JSON, got %d", len(result))
	}
}

func TestAllStringsFromJSON_NumericAndBool(t *testing.T) {
	raw := json.RawMessage(`{"count": 123, "active": false, "rate": 3.14}`)
	result := AllStringsFromJSON(raw)
	got := make(map[string]struct{}, len(result))
	for _, s := range result {
		got[s] = struct{}{}
	}
	if _, ok := got["123"]; !ok {
		t.Error("missing numeric value 123")
	}
	if _, ok := got["false"]; !ok {
		t.Error("missing boolean value false")
	}
	if _, ok := got["3.14"]; !ok {
		t.Error("missing float value 3.14")
	}
}

func TestAllStringsFromJSONResult_ReportsTruncation(t *testing.T) {
	raw := nestedJSON(maxExtractDepth + 6)
	got := AllStringsFromJSONResult(raw)
	if !got.Truncated {
		t.Fatal("expected Truncated when nesting exceeds maxExtractDepth")
	}
	if len(got.Strings) == 0 {
		t.Fatal("expected outer keys before the depth cap")
	}
	for _, s := range got.Strings {
		if s == "deep" {
			t.Fatal(`extracted "deep" past maxExtractDepth`)
		}
	}

	shallow := AllStringsFromJSONResult(json.RawMessage(`{"a":"ok"}`))
	if shallow.Truncated {
		t.Fatal("did not expect Truncated on shallow JSON")
	}
}

func TestAllStringsFromJSONOrderedResult_NumbersAndBools(t *testing.T) {
	got := AllStringsFromJSONOrderedResult(json.RawMessage(`[true,false,42,3.5]`))
	want := []string{"true", "false", "42", "3.5"}
	if len(got.Strings) != len(want) {
		t.Fatalf("strings = %#v, want %#v", got.Strings, want)
	}
	for i := range want {
		if got.Strings[i] != want[i] {
			t.Fatalf("strings[%d] = %q, want %q", i, got.Strings[i], want[i])
		}
	}
	if got.Truncated {
		t.Fatal("did not expect Truncated on a flat array")
	}
}

func TestAllStringsFromJSONOrderedResult_DepthCapOmitsInnerTokens(t *testing.T) {
	raw := nestedJSON(maxExtractDepth + 2)
	got := AllStringsFromJSONOrderedResult(raw)
	if !got.Truncated {
		t.Fatal("expected Truncated when ordered extraction exceeds maxExtractDepth")
	}
	for _, s := range got.Strings {
		if s == "deep" {
			t.Fatal(`ordered extraction kept "deep" past maxExtractDepth`)
		}
	}
	if len(got.Strings) == 0 {
		t.Fatal("expected keys from levels inside the depth cap")
	}
}

func nestedJSON(depth int) json.RawMessage {
	var b strings.Builder
	for i := 0; i < depth; i++ {
		b.WriteString(`{"a":`)
	}
	b.WriteString(`"deep"`)
	for i := 0; i < depth; i++ {
		b.WriteString(`}`)
	}
	return json.RawMessage(b.String())
}
