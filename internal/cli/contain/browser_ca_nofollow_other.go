// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package contain

import (
	"errors"
	"os"
)

// applyAgentOwnershipNoFollow is unsupported on Windows. Contained browser CA
// trust is a Linux host-containment path, so this fails closed rather than
// falling back to a path-resolving chmod that the platform cannot make safe.
func applyAgentOwnershipNoFollow(path string, _ os.FileMode, _, _ int) error {
	return errors.New("browser CA ownership requires a Unix host: " + path)
}
