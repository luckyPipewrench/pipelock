// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonscan

import (
	"errors"
	"testing"
)

func TestJSONKeyErrorPrecedence(t *testing.T) {
	bad := string([]byte{0xff})
	for _, raw := range []string{
		`{"value":"` + bad + `","result":1,"result":2}`,
		`{"result":1,"result":2,"value":"` + bad + `"}`,
	} {
		if err := ValidateKeys([]byte(raw), MaxNestingDepth); !errors.Is(err, ErrDuplicateKey) {
			t.Errorf("duplicate must retain precedence over invalid UTF-8: %v", err)
		}
	}
}
