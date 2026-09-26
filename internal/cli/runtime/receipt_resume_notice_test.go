// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"strings"
	"testing"
)

// The startup notice names the cause, says emission is disabled, and gives a
// remedy that works: restarting begins a new recorder session.
func TestReceiptResumeFailureNotice(t *testing.T) {
	got := receiptResumeFailureNotice(errors.New("refusing to resume session \"s\""))
	for _, want := range []string{
		"chain could not be resumed: refusing to resume session",
		"Receipt emission is DISABLED",
		"signing_key_path",
		"restart to begin a new session",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("notice missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "rotated") {
		t.Errorf("notice still attributes the failure to a key rotation:\n%s", got)
	}
}
