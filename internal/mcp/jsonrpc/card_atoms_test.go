// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonrpc

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestCardJSONExtractionRetainsDiscardedScalarPositions(t *testing.T) {
	raw := json.RawMessage(`["left",0,false,true,null,"right"]`)
	result := ExtractStringsFromJSONResult(raw)
	if !slices.Equal(result.Strings, []string{"left", "right"}) || !slices.Equal(result.StringPositions, []int{0, 5}) || len(result.CardAtoms) != 6 {
		t.Fatal("string extraction lost scalar positions")
	}
	for i, want := range []string{"left", "0", "false", "true", "null", "right"} {
		if result.CardAtoms[i].Card != want || result.CardAtoms[i].Number != (i == 1) {
			t.Fatalf("scalar %d lost type or spelling", i)
		}
	}
}

func TestCardVisibleExtractionRetainsScalarPositions(t *testing.T) {
	raw := json.RawMessage(`["left",0,false,true,null,"","right"]`)
	result := ExtractVisibleStringsFromJSONResult(raw)
	if !slices.Equal(result.Strings, []string{"left", "", "right"}) || !slices.Equal(result.StringPositions, []int{0, 5, 6}) {
		t.Fatal("visible extraction lost scalar positions")
	}
	if got, want := ResponseCardText(result.CardAtoms), "left \nnull \nfalse \ntrue \nnull \n \nright"; got != want {
		t.Fatalf("card view = %q, want %q", got, want)
	}
}
