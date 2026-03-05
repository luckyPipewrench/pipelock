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
