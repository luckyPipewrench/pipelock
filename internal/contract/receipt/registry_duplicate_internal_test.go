// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeStrictRejectsDuplicateMembers(t *testing.T) {
	var target map[string]any
	err := decodeStrict(json.RawMessage(`{"verdict":"allow","verdict":"block"}`), &target)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("decodeStrict duplicate error = %v, want rejection", err)
	}
}
