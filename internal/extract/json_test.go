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
	joined := strings.Join(result, "|")
	for _, want := range []string{"a", "b", "value1", "c", "value2", "d", "value3"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in result: %s", want, joined)
		}
	}
}

func TestAllStringsFromJSON_Arrays(t *testing.T) {
	raw := json.RawMessage(`["hello", "world", 42, true]`)
	result := AllStringsFromJSON(raw)
	joined := strings.Join(result, "|")
	for _, want := range []string{"hello", "world", "42", "true"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in result: %s", want, joined)
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
	// Verify we got keys from the outer levels
	joined := strings.Join(result, "|")
	if !strings.Contains(joined, "a") {
		t.Error("expected at least the key 'a' from outer levels")
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
	joined := strings.Join(result, "|")
	if !strings.Contains(joined, "123") {
		t.Error("missing numeric value 123")
	}
	if !strings.Contains(joined, "false") {
		t.Error("missing boolean value false")
	}
	if !strings.Contains(joined, "3.14") {
		t.Error("missing float value 3.14")
	}
}
