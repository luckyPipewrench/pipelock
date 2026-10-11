// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonscan

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

type aliasLeaf struct {
	Key string `json:"key"`
}
type aliasRecursive struct {
	*aliasRecursive
	Value string `json:"value"`
}
type aliasEmbedded struct{ aliasLeaf }

func TestDecodeStrictKeys(t *testing.T) {
	type document struct {
		Item   *aliasLeaf           `json:"item"`
		Items  []aliasLeaf          `json:"items"`
		Array  [1]aliasLeaf         `json:"array"`
		Map    map[string]aliasLeaf `json:"map"`
		Raw    json.RawMessage      `json:"raw"`
		Bytes  []byte               `json:"bytes"`
		Number any                  `json:"number"`
	}
	for _, raw := range []string{
		`{"Item":{}}`, `{"item":{"Key":"x"}}`, `{"items":[{"KEY":"x"}]}`,
		`{"array":[{"\u212aey":"x"}]}`, `{"map":{"arbitrary":{"KEY":"x"}}}`,
		`{"item":{},"ITEM":{}}`, `{"raw":{"a":1,"A":2}}`, `{"unknown":1}`,
	} {
		var target document
		if err := DecodeStrict([]byte(raw), &target); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	var target document
	if err := DecodeStrict([]byte(`{"item":{"key":"ok"},"items":[{"key":"ok"}],"array":[{"key":"ok"}],"map":{"KEY":{"key":"ok"}},"raw":{"Custom":1},"bytes":"YQ==","number":9007199254740993}`), &target); err != nil {
		t.Fatal(err)
	}
	if target.Number != json.Number("9007199254740993") {
		t.Fatalf("lost number spelling: %v", target.Number)
	}
	for _, raw := range []string{"", "{", "{}{}", "[]", "{\"bad\":\"\xff\"}"} {
		if err := DecodeStrict([]byte(raw), &target); err == nil {
			t.Errorf("accepted malformed/schema input %q", raw)
		}
	}
	for _, target := range []any{nil, document{}, (*document)(nil)} {
		var invalid *json.InvalidUnmarshalError
		if err := DecodeStrict([]byte(`{}`), target); !errors.As(err, &invalid) {
			t.Errorf("invalid target error: %v", err)
		}
	}
}

func TestRejectStructAliasesPromotion(t *testing.T) {
	type first struct{ Key string }
	type other struct{ Key string }
	type ambiguous struct {
		first
		other
	}
	type shadow struct {
		aliasLeaf
		Key string `json:"key"`
	}
	recursive := &aliasRecursive{}
	recursive.aliasRecursive = recursive
	type caseDistinct struct {
		Lower string `json:"key"`
		Upper string `json:"KEY"`
	}
	for _, tc := range []struct {
		name, raw string
		target    any
		reject    bool
	}{
		{"embedded alias", `{"KEY":"x"}`, &aliasEmbedded{}, true},
		{"embedded canonical", `{"key":"x"}`, &aliasEmbedded{}, false},
		{"recursive alias", `{"VALUE":"x"}`, recursive, true},
		{"recursive canonical", `{"value":"x"}`, recursive, false},
		{"ambiguous ignored", `{"KEY":"x"}`, &ambiguous{}, false},
		{"shadow alias", `{"KEY":"x"}`, &shadow{}, true},
		{"exact before folded", `{"KEY":"x"}`, &caseDistinct{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := RejectStructAliases([]byte(tc.raw), reflect.TypeOf(tc.target))
			if (err != nil) != tc.reject {
				t.Fatalf("reject=%v, got %v", tc.reject, err)
			}
		})
	}
	if err := RejectStructAliases([]byte(`{}`), nil); err != nil {
		t.Fatal(err)
	}
}

func TestStrictKeyValidationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		depth int
		valid bool
	}{
		{`{"a":[{}]}`, 3, true},
		{`{"a":[{}]}`, 2, false},
		{`0`, 0, true},
		{`{}`, 0, false},
		{`{} trailing`, 3, false},
		{`[] []`, 3, false},
		{`{"a":`, 3, false},
		{`{"`, 3, false},
		{`[`, 3, false},
		{`{"a":1`, 3, false},
	} {
		if err := ValidateKeys([]byte(tc.raw), tc.depth); (err == nil) != tc.valid {
			t.Errorf("%s at %d: %v", tc.raw, tc.depth, err)
		}
	}
	for _, raw := range []string{"", "[1]", `{`, `{"a":`, `{"a":1,`, `{"a":{"x":1,"X":2}}`} {
		if got := TopLevelDuplicateKeys([]byte(raw)); len(got) != 0 {
			t.Errorf("unexpected inventory for %q: %v", raw, got)
		}
	}
	got := TopLevelDuplicateKeys([]byte(`{"key":{},"\u212aey":[],"KEY":null,"key":4}`))
	for _, name := range []string{"key", "Key", "KEY"} {
		if _, ok := got[name]; !ok {
			t.Errorf("missing duplicate spelling %q: %v", name, got)
		}
	}
	if HasKeyAlias(map[string]int{"key": 1, "other": 2}, "key") {
		t.Fatal("canonical key reported as alias")
	}
	if !HasKeyAlias(map[string]int{"Key": 1}, "key") {
		t.Fatal("Unicode alias missed")
	}
}

func TestRejectStructAliasesNestedShapes(t *testing.T) {
	type plain struct {
		Name    string
		Skip    string `json:"-"`
		private string
	}
	type hidden int
	type hiddenEmbedded struct{ hidden }
	type named struct {
		aliasLeaf `json:"item"`
	}
	ignored := plain{private: "retained"}
	if err := DecodeStrict([]byte(`{"Name":"ok"}`), &ignored); err != nil || ignored.private != "retained" {
		t.Fatalf("unexported field changed: %+v, %v", ignored, err)
	}
	embedded := hiddenEmbedded{hidden: 7}
	if err := DecodeStrict([]byte(`{}`), &embedded); err != nil || embedded.hidden != 7 {
		t.Fatalf("unexported embedded scalar changed: %+v, %v", embedded, err)
	}
	for _, tc := range []struct {
		raw    string
		target any
		reject bool
	}{
		{`{"name":"x"}`, &plain{}, true},
		{`{"Name":"x"}`, &plain{}, false},
		{`{"SKIP":"x","PRIVATE":"x"}`, &plain{}, false},
		{`{}`, &hiddenEmbedded{}, false},
		{`{"ITEM":{"key":"x"}}`, &named{}, true},
		{`null`, &aliasLeaf{}, false},
		{`[]`, &aliasLeaf{}, true},
		{`{}`, &[]aliasLeaf{}, true},
		{`[]`, &map[string]aliasLeaf{}, true},
		{`[{"KEY":"x"}]`, &[]*aliasLeaf{}, true},
	} {
		if err := RejectStructAliases([]byte(tc.raw), reflect.TypeOf(tc.target)); (err != nil) != tc.reject {
			t.Errorf("%s into %T: %v", tc.raw, tc.target, err)
		}
	}
}
