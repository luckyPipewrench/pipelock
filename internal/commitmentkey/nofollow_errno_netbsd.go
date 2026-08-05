// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build netbsd

package commitmentkey

import "golang.org/x/sys/unix"

// NetBSD reports EFTYPE when O_NOFOLLOW refuses a final-component symlink.
var noFollowSymlinkErrors = noFollowSymlinkErrorsFor(noFollowErrnos{loop: unix.ELOOP, fileType: unix.EFTYPE})
