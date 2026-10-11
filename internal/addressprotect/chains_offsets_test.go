// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package addressprotect

import (
	"strings"
	"testing"
)

func TestBTCDetectOriginalOffsets(t *testing.T) {
	t.Parallel()
	const address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	for _, prefix := range []string{"plain ", "\u023a ", "\u212a ", "\u0130 "} {
		for _, addr := range []string{address, strings.ToUpper(address)} {
			t.Run(prefix+addr, func(t *testing.T) {
				matches := (btcValidator{}).Detect(prefix + addr)
				if len(matches) != 1 {
					t.Fatalf("matches = %v", matches)
				}
				if matches[0].offset != len(prefix) || matches[0].text != addr {
					t.Fatalf("wrong original span: %+v", matches[0])
				}
			})
		}
	}
}
