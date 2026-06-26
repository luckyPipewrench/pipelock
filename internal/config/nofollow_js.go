// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build js

package config

import "errors"

const noFollowFlag = 0

var errELOOP = errors.New("ELOOP-not-supported-on-js")
