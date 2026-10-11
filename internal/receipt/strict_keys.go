// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"reflect"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

func rejectReceiptAliases(data []byte) error {
	return rejectStructAliases(data, reflect.TypeFor[Receipt]())
}

func rejectStructAliases(data []byte, typ reflect.Type) error {
	if err := jsonscan.ValidateKeys(data, jsonscan.MaxNestingDepth); err != nil {
		// Keep the consuming decoder's syntax diagnostics while retaining key
		// and encoding validation for otherwise parseable JSON.
		if !json.Valid(data) {
			var value json.RawMessage
			if syntaxErr := json.Unmarshal(data, &value); syntaxErr != nil {
				return syntaxErr
			}
		}
		return err
	}
	return jsonscan.RejectStructAliases(data, typ)
}
