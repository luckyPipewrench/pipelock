// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package processexec

import "errors"

// Replace fails closed on platforms without Unix process replacement.
func Replace(string, []string, []string) error {
	return errors.New("process replacement is unavailable on this platform")
}
