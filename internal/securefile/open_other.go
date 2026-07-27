//go:build !unix && !windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package securefile

import "os"

// openRegularNonblocking fails closed where equivalent nonblocking, no-follow
// open primitives are unavailable.
func openRegularNonblocking(path string) (*os.File, error) {
	return nil, ErrUnsupportedSecureOpen
}
