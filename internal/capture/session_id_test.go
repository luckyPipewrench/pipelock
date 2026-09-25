// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture

import "testing"

// TestSanitizeSessionIDRefusesInvalidUTF8 pins that a capture session id the
// recorder would refuse is rejected here, where the directory is named.
func TestSanitizeSessionIDRefusesInvalidUTF8(t *testing.T) {
	t.Parallel()

	if _, err := sanitizeSessionID("agent" + string([]byte{0xff})); err == nil {
		t.Fatal("sanitizeSessionID accepted invalid UTF-8")
	}
}
