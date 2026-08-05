// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build freebsd

package commitmentkey

import "golang.org/x/sys/unix"

// FreeBSD reports EMLINK when O_NOFOLLOW refuses a final-component symlink.
var noFollowSymlinkErrors = noFollowSymlinkErrorsFor("freebsd", noFollowErrnos{loop: unix.ELOOP, link: unix.EMLINK})
