// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package audit

import (
	"errors"
	"os"
)

// openDurableAuditFile fails closed where the platform cannot bind the final
// path component to an O_NOFOLLOW, non-blocking descriptor.
func openDurableAuditFile(string) (*os.File, bool, error) {
	return nil, false, errors.New("durable audit sink requires Unix no-follow descriptor binding")
}
