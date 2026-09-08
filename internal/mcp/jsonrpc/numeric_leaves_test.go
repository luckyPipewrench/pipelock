// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonrpc

import (
	"encoding/json"
	"testing"
)

func TestExtractNumericLeaves(t *testing.T) {
	for _, tt := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty", raw: "", want: ""},
		{name: "null", raw: "null", want: ""},
		{name: "invalid json", raw: "{", want: ""},
		{name: "strings only", raw: `{"a":"1","b":["2"]}`, want: ""},
		{name: "array of ints in order", raw: `[57,52,50,48]`, want: "57,52,50,48"},
		{name: "sorted object keys", raw: `{"b":2,"a":1,"c":[3,{"z":5,"y":4}]}`, want: "1,2,3,4,5"},
		{name: "large integer keeps its digits", raw: `{"v":12345678901234567890}`, want: "12345678901234567890"},
		{name: "floats keep their spelling", raw: `[3.14,1e3,-2]`, want: "3.14,1e3,-2"},
		{name: "booleans are not numbers", raw: `[true,false,7]`, want: "7"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractNumericLeaves(json.RawMessage(tt.raw)); got != tt.want {
				t.Fatalf("ExtractNumericLeaves(%s) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestExtractTextResult_NumericChannel(t *testing.T) {
	for _, tt := range []struct {
		name        string
		raw         string
		wantText    string
		wantNumeric string
	}{
		{
			name:        "tool result with structuredContent numbers",
			raw:         `{"content":[{"type":"text","text":"ok"}],"structuredContent":{"codes":[57,52,50]}}`,
			wantText:    "ok",
			wantNumeric: "57,52,50",
		},
		{
			name:        "tool result with only numbers",
			raw:         `{"content":[],"structuredContent":{"value":12345678901234567890}}`,
			wantText:    "",
			wantNumeric: "12345678901234567890",
		},
		{
			name:        "non-standard shape",
			raw:         `{"payload":[1,2,3],"note":"n"}`,
			wantText:    "n",
			wantNumeric: "1,2,3",
		},
		{
			name:        "non-standard shape with only numbers",
			raw:         `{"payload":[1,2,3]}`,
			wantText:    "",
			wantNumeric: "1,2,3",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractTextResult(json.RawMessage(tt.raw))
			if got.Truncated {
				t.Fatal("unexpected truncation")
			}
			if got.Text != tt.wantText || got.Numeric != tt.wantNumeric {
				t.Fatalf("ExtractTextResult = (text %q, numeric %q), want (%q, %q)", got.Text, got.Numeric, tt.wantText, tt.wantNumeric)
			}
		})
	}
}
