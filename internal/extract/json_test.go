// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"encoding/json"
	"strconv"
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

var testJSONLeafBucketKey = []byte("pipelock-test-json-leaf-bucket-key")

func TestJSONLeafBucketPayloadsKeepsEveryLeafWithinFixedBuckets(t *testing.T) {
	limits := JSONLeafLimits{MaxDepth: 2, MaxPathBytes: 32}

	t.Run("arrays and scalar kinds remain represented", func(t *testing.T) {
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(`[null,2,true,"text"]`), limits, 8, testJSONLeafBucketKey)
		if !valid {
			t.Fatal("valid scalar array was rejected")
		}
		var all strings.Builder
		for _, value := range buckets {
			all.Write(value)
		}
		for _, want := range []string{"2", "true", "text"} {
			if !strings.Contains(all.String(), want) {
				t.Fatalf("bucket output omitted %q: %#v", want, buckets)
			}
		}
	})

	t.Run("invalid limits and empty key decline to partition", func(t *testing.T) {
		for _, tt := range []struct {
			raw     json.RawMessage
			limits  JSONLeafLimits
			buckets int
			key     []byte
		}{
			{raw: json.RawMessage(`{"unterminated"`), limits: limits, buckets: 8, key: testJSONLeafBucketKey},
			{raw: json.RawMessage(`{"value":"ok"}`), limits: JSONLeafLimits{}, buckets: 8, key: testJSONLeafBucketKey},
			{raw: json.RawMessage(`{"value":"ok"}`), limits: limits, buckets: 0, key: testJSONLeafBucketKey},
			{raw: json.RawMessage(`{"value":"ok"}`), limits: limits, buckets: maxJSONLeafBuckets + 1, key: testJSONLeafBucketKey},
			{raw: json.RawMessage(`{"value":"ok"}`), limits: limits, buckets: 8, key: nil},
			{raw: nil, limits: limits, buckets: 8, key: testJSONLeafBucketKey},
		} {
			if buckets, valid := JSONLeafBucketPayloads(tt.raw, tt.limits, tt.buckets, tt.key); valid || buckets != nil {
				t.Fatalf("invalid bucket extraction = %#v, valid=%t", buckets, valid)
			}
		}
	})

	if got := jsonLeafBucketIndex(nil, 0, 0, maxJSONLeafBuckets+1, testJSONLeafBucketKey); got != 0 {
		t.Fatalf("out-of-range bucket count index = %d, want 0", got)
	}
	if got := jsonLeafBucketIndex([]byte("$/a"), 0, 2, 8, nil); got != 0 {
		t.Fatalf("empty-key bucket index = %d, want 0", got)
	}

	t.Run("deep leaf uses a stable bucket", func(t *testing.T) {
		first, valid := JSONLeafBucketPayloads(nestedJSON(66), limits, 8, testJSONLeafBucketKey)
		if !valid || len(first) != 1 {
			t.Fatalf("first buckets = %#v, valid=%t", first, valid)
		}
		second, valid := JSONLeafBucketPayloads(nestedJSON(66), limits, 8, testJSONLeafBucketKey)
		if !valid || len(second) != 1 {
			t.Fatalf("second buckets = %#v, valid=%t", second, valid)
		}
		for bucket, value := range first {
			if string(value) != "deep" || string(second[bucket]) != "deep" {
				t.Fatalf("deep value was not retained in stable bucket %q: first=%q second=%q", bucket, value, second[bucket])
			}
		}
	})

	t.Run("more paths than buckets retain first and last leaves", func(t *testing.T) {
		var raw strings.Builder
		raw.WriteByte('{')
		for index := range 20 {
			if index > 0 {
				raw.WriteByte(',')
			}
			raw.WriteString(`"field_`)
			raw.WriteString(strconv.Itoa(index))
			raw.WriteString(`":"value_`)
			raw.WriteString(strconv.Itoa(index))
			raw.WriteByte('"')
		}
		raw.WriteByte('}')
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(raw.String()), limits, 4, testJSONLeafBucketKey)
		if !valid || len(buckets) > 4 {
			t.Fatalf("buckets = %#v, valid=%t", buckets, valid)
		}
		var all strings.Builder
		for _, value := range buckets {
			all.Write(value)
		}
		for _, want := range []string{"value_0", "value_19"} {
			if !strings.Contains(all.String(), want) {
				t.Fatalf("bucket output omitted %q: %#v", want, buckets)
			}
		}
	})
}

func TestJSONLeafBucketPayloadsKeepsLeavesParsedBeforeError(t *testing.T) {
	limits := JSONLeafLimits{MaxDepth: 4, MaxPathBytes: 64}
	secret := "AKI" + "AIOSFODNN7EXAMPLE"

	t.Run("trailing byte keeps the parsed leaf", func(t *testing.T) {
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(`{"a":"`+secret+`"} x`), limits, 8, testJSONLeafBucketKey)
		if valid {
			t.Fatal("trailing non-JSON must not report a complete document")
		}
		if !jsonLeafBucketsContain(buckets, secret) {
			t.Fatalf("parsed leaf was omitted after trailing byte: %#v", buckets)
		}
	})

	t.Run("second top-level value keeps the first object's leaves", func(t *testing.T) {
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(`{"a":"`+secret+`"}{}`), limits, 8, testJSONLeafBucketKey)
		if valid {
			t.Fatal("second top-level value must not report a complete document")
		}
		if !jsonLeafBucketsContain(buckets, secret) {
			t.Fatalf("parsed leaf was omitted after second value: %#v", buckets)
		}
	})

	t.Run("truncated after a complete sibling keeps that sibling", func(t *testing.T) {
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(`{"keep":"yes","drop":"`), limits, 8, testJSONLeafBucketKey)
		if valid {
			t.Fatal("truncated object must not report a complete document")
		}
		if !jsonLeafBucketsContain(buckets, "yes") {
			t.Fatalf("complete sibling was omitted: %#v", buckets)
		}
	})

	t.Run("truncated before any scalar yields no buckets", func(t *testing.T) {
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(`{"a":"`+secret), limits, 8, testJSONLeafBucketKey)
		if valid || buckets != nil {
			t.Fatalf("unterminated first leaf = %#v, valid=%t", buckets, valid)
		}
	})
}

func TestJSONLeafBucketPayloadsWalkerErrorReturns(t *testing.T) {
	limits := JSONLeafLimits{MaxDepth: 4, MaxPathBytes: 64}

	t.Run("unexpected closing delimiter", func(t *testing.T) {
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(`}`), limits, 8, testJSONLeafBucketKey)
		if valid || buckets != nil {
			t.Fatalf("unexpected delim = %#v, valid=%t", buckets, valid)
		}
	})

	t.Run("unexpected array closer", func(t *testing.T) {
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(`]`), limits, 8, testJSONLeafBucketKey)
		if valid || buckets != nil {
			t.Fatalf("unexpected array delim = %#v, valid=%t", buckets, valid)
		}
	})

	t.Run("non-string object key", func(t *testing.T) {
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(`{1:true}`), limits, 8, testJSONLeafBucketKey)
		if valid || buckets != nil {
			t.Fatalf("numeric key = %#v, valid=%t", buckets, valid)
		}
	})

	t.Run("truncated object key", func(t *testing.T) {
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(`{"`), limits, 8, testJSONLeafBucketKey)
		if valid || buckets != nil {
			t.Fatalf("truncated key = %#v, valid=%t", buckets, valid)
		}
	})

	t.Run("truncated after object key", func(t *testing.T) {
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(`{"a":`), limits, 8, testJSONLeafBucketKey)
		if valid || buckets != nil {
			t.Fatalf("truncated after key = %#v, valid=%t", buckets, valid)
		}
	})

	t.Run("truncated array after a scalar keeps that scalar", func(t *testing.T) {
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(`[1,`), limits, 8, testJSONLeafBucketKey)
		if valid {
			t.Fatal("truncated array must not report a complete document")
		}
		if !jsonLeafBucketsContain(buckets, "1") {
			t.Fatalf("array scalar was omitted: %#v", buckets)
		}
	})

	t.Run("mismatched object closer", func(t *testing.T) {
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(`{"a":1]`), limits, 8, testJSONLeafBucketKey)
		if valid {
			t.Fatal("mismatched closer must not report a complete document")
		}
		if !jsonLeafBucketsContain(buckets, "1") {
			t.Fatalf("leaf before mismatched closer was omitted: %#v", buckets)
		}
	})

	t.Run("mismatched array closer", func(t *testing.T) {
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(`[true}`), limits, 8, testJSONLeafBucketKey)
		if valid {
			t.Fatal("mismatched array closer must not report a complete document")
		}
		if !jsonLeafBucketsContain(buckets, "true") {
			t.Fatalf("array leaf before mismatched closer was omitted: %#v", buckets)
		}
	})

	t.Run("truncated nested object after sibling", func(t *testing.T) {
		buckets, valid := JSONLeafBucketPayloads(json.RawMessage(`{"keep":false,"child":{`), limits, 8, testJSONLeafBucketKey)
		if valid {
			t.Fatal("truncated nested object must not report a complete document")
		}
		if !jsonLeafBucketsContain(buckets, "false") {
			t.Fatalf("sibling before truncated nested object was omitted: %#v", buckets)
		}
	})
}

func TestJSONLeafBucketIndexIsKeyedPerSecret(t *testing.T) {
	path := []byte("$/messages/0/content")
	first := jsonLeafBucketIndex(path, 1, 8, 4096, testJSONLeafBucketKey)
	second := jsonLeafBucketIndex(path, 1, 8, 4096, testJSONLeafBucketKey)
	if first != second {
		t.Fatalf("same key mapped %q to %d then %d", path, first, second)
	}
	otherKey := append([]byte(nil), testJSONLeafBucketKey...)
	otherKey[len(otherKey)-1] ^= 0x01
	other := jsonLeafBucketIndex(path, 1, 8, 4096, otherKey)
	if first == other {
		t.Fatalf("distinct keys mapped %q to the same bucket %d", path, first)
	}

	target := jsonLeafBucketIndex(path, 1, 8, 4096, testJSONLeafBucketKey)
	wrongKey := []byte("attacker-guessed-json-leaf-bucket")
	hits := 0
	for index := 1; index <= 20000; index++ {
		candidate := []byte("$/n" + strconv.Itoa(index))
		if jsonLeafBucketIndex(candidate, 1, 8, 4096, wrongKey) == target {
			hits++
		}
	}
	if hits > 20 {
		t.Fatalf("grinding with the wrong key hit the secret bucket %d/20000 times; keyed mapping leaked", hits)
	}
	found := 0
	for index := 1; index <= 20000; index++ {
		candidate := []byte("$/n" + strconv.Itoa(index))
		if jsonLeafBucketIndex(candidate, 1, 8, 4096, testJSONLeafBucketKey) == target {
			found = index
			break
		}
	}
	if found == 0 {
		t.Fatal("keyed oracle did not find a colliding path in 20000 candidates")
	}
}

func jsonLeafBucketsContain(buckets map[string][]byte, want string) bool {
	for _, value := range buckets {
		if strings.Contains(string(value), want) {
			return true
		}
	}
	return false
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
