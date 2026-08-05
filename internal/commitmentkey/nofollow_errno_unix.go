// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix && !freebsd && !dragonfly && !netbsd

package commitmentkey

import "golang.org/x/sys/unix"

var noFollowSymlinkErrors = noFollowSymlinkErrorsFor("other", noFollowErrnos{loop: unix.ELOOP})
