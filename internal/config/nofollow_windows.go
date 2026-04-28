// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package config

import "errors"

// noFollowFlag is zero on Windows: O_NOFOLLOW is not part of the Win32
// open API, and the symlink semantics differ (Windows resolves reparse
// points at a different layer). The Lstat-level rejection in
// validateLearnSaltSource still runs and is the primary defense; we
// accept the loss of the post-open re-check here.
const noFollowFlag = 0

// errELOOP is an unreachable sentinel on Windows. The Lstat path rejects
// reparse points before Open is called, so this errors.Is branch never
// fires. Defined so the Unix and Windows files share an identifier set.
var errELOOP = errors.New("ELOOP-not-supported-on-windows")
