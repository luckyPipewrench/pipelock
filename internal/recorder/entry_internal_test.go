// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"encoding/json"
	"testing"
)

func TestDecodeEntryDetailRejectsMalformedRawJSON(t *testing.T) {
	t.Parallel()

	if _, err := decodeEntryDetail(json.RawMessage(`{"unterminated":`)); err == nil {
		t.Fatal("decodeEntryDetail accepted malformed raw detail")
	}
}
