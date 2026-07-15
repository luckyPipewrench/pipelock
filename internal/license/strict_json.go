// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"encoding/json"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// decodeLicenseJSON preserves forward-compatible unknown fields while rejecting
// the cross-parser ambiguity of duplicate object members before typed decoding.
func decodeLicenseJSON(data []byte, out any) error {
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}
