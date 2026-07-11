// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"bytes"
	"encoding/json"
	"errors"
)

// IsDuplicateKeyBlock reports whether err is the specific NoDuplicateJSONKeys
// outcome for an actual duplicate object member name.
func IsDuplicateKeyBlock(err error) bool {
	var be *BlockError
	if !errors.As(err, &be) {
		return false
	}
	return be.Reason == ReasonDuplicateKey
}

// IsJSONObject reports whether raw is shaped like a JSON object.
func IsJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) != 0 && trimmed[0] == '{'
}
