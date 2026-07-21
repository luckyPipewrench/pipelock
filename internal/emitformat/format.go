// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package emitformat defines shared event export wire formats.
package emitformat

import "strings"

const (
	JSON = "json"
	CEF  = "cef"
	OCSF = "ocsf"
)

var supportedFormats = []string{JSON, CEF, OCSF}

// SupportedFormats returns the canonical ordered list of event export wire formats.
func SupportedFormats() []string {
	return append([]string(nil), supportedFormats...)
}

func Supported(format string) bool {
	for _, supported := range supportedFormats {
		if format == supported {
			return true
		}
	}
	return false
}

// AllowedSet returns the supported formats as human-readable validation text.
func AllowedSet() string {
	switch len(supportedFormats) {
	case 0:
		return ""
	case 1:
		return supportedFormats[0]
	default:
		return strings.Join(supportedFormats[:len(supportedFormats)-1], ", ") + " or " + supportedFormats[len(supportedFormats)-1]
	}
}
