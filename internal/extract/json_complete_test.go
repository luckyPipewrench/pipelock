// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"encoding/json"
	"testing"
)

func TestAllStringsRequiresCompleteJSON(t *testing.T) {
	for _, raw := range []string{
		`{"value":"ordinary"} trailing`,
		`{"value":"ordinary"} {"second":"document"}`,
		`{"value":"ordinary",}`,
	} {
		t.Run(raw, func(t *testing.T) {
			got := AllStringsFromJSONResult(json.RawMessage(raw))
			if len(got.Strings) != 0 || len(got.CardStrings) != 0 {
				t.Fatalf("incomplete JSON received typed extraction: %+v", got)
			}
		})
	}
	got := AllStringsFromJSONResult(json.RawMessage(`{"value":"ordinary"}`))
	if len(got.Strings) != 2 || len(got.CardStrings) != 2 || got.Truncated {
		t.Fatalf("complete JSON was not extracted: %+v", got)
	}
}
