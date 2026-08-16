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
