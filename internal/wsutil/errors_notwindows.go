// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package wsutil

// isPlatformClosedErr has no extra platform-specific cases off Windows: the
// Unix teardown errnos already surface as error strings matched by
// IsExpectedCloseErr, so there is nothing additional to recognize here.
func isPlatformClosedErr(error) bool {
	return false
}
