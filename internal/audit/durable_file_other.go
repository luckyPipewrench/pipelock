// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package audit

import (
	"errors"
	"io/fs"
	"os"
)

// DurableAuditFileSupported reports whether this target can bind the final
// lifecycle audit path to a no-follow file descriptor.
func DurableAuditFileSupported() bool { return false }

// openDurableAuditFile fails closed where the platform cannot bind the final
// path component to an O_NOFOLLOW, non-blocking descriptor. Commitment-key
// lifecycle mutations are therefore unavailable on these platforms.
func openDurableAuditFile(string) (*os.File, bool, error) {
	return nil, false, errors.New("durable audit sink is unsupported on this platform; commitment-key lifecycle mutations require Unix no-follow descriptor binding")
}

func validateDurableAuditPath(fs.FileInfo, string) error { return nil }
