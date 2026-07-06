// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package emitformat defines shared event export wire formats.
package emitformat

const (
	JSON = "json"
	CEF  = "cef"
)

func Supported(format string) bool {
	return format == JSON || format == CEF
}
