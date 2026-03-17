// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package seedprotect

import "testing"

func FuzzDetect(f *testing.F) {
	f.Add("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	f.Add("The quick brown fox jumps over the lazy dog and never looks back at the world")
	f.Add("")
	f.Add("abandon")
	f.Fuzz(func(t *testing.T, text string) {
		// Must not panic on any input.
		Detect(text, 12, true)
		Detect(text, 12, false)
	})
}
