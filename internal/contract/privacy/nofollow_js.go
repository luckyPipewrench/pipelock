// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build js

package privacy

import "errors"

// The browser target has no O_NOFOLLOW and no host filesystem permissions to
// check, so a file: source is refused rather than opened without the guards
// it depends on. An environment source still works.
const noFollowFlag = 0

var errELOOP = errors.New("ELOOP-not-supported-on-js")

const fileSourceSupported = false
