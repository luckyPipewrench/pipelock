// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestIsDuplicateKeyBlock(t *testing.T) {
	err := NoDuplicateJSONKeys([]byte(`{"a":1,"a":2}`))
	if !IsDuplicateKeyBlock(err) {
		t.Fatalf("IsDuplicateKeyBlock(%v) = false, want true", err)
	}
	if IsDuplicateKeyBlock(&BlockError{Reason: ReasonBodyUnparseable}) {
		t.Fatal("body-unparseable block must not be classified as duplicate-key block")
	}
	if IsDuplicateKeyBlock(errors.New("boom")) {
		t.Fatal("non-BlockError must not be classified as duplicate-key block")
	}
}

func TestIsJSONObject(t *testing.T) {
	tests := map[string]struct {
		raw  json.RawMessage
		want bool
	}{
		"object":          {raw: json.RawMessage(`{"a":1}`), want: true},
		"spaced object":   {raw: json.RawMessage(" \n\t{}"), want: true},
		"array":           {raw: json.RawMessage(`[]`), want: false},
		"null":            {raw: json.RawMessage(`null`), want: false},
		"empty":           {raw: nil, want: false},
		"malformed shape": {raw: json.RawMessage(`{`), want: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := IsJSONObject(tt.raw); got != tt.want {
				t.Fatalf("IsJSONObject(%q) = %v, want %v", string(tt.raw), got, tt.want)
			}
		})
	}
}
