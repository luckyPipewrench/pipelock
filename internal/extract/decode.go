// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"bytes"
	"encoding/json"
	"errors"
)

// DecodeJSON decodes one complete JSON document while preserving numeric
// tokens as json.Number. RFC 8259 section 6 permits numbers outside float64's
// range; Decoder.UseNumber keeps those numbers from disabling string, key,
// depth, or media inspection. This does not impose signed-artifact schema or
// duplicate-key rules on arbitrary tool content.
func DecodeJSON(raw []byte, target any) error {
	if !json.Valid(raw) {
		return errors.New("invalid JSON document")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode(target)
}
