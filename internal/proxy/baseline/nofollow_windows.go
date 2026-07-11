// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package baseline

import (
	"errors"
	"os"
)

var (
	errELOOP               = errors.New("ELOOP-not-supported-on-windows")
	errNoFollowUnsupported = errors.New("secure nofollow baseline reads are unsupported on windows")
)

func openRegularFileNoSymlinkBelowRoot(_, _, displayPath string) (*os.File, error) {
	return nil, errNoFollowUnsupported
}
