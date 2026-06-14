// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package wsutil

import (
	"errors"
	"io"
	"strings"
)

// IsExpectedCloseErr returns true for errors that are normal during connection teardown.
func IsExpectedCloseErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	s := err.Error()
	// Platform-specific teardown errnos (e.g. the Windows Winsock equivalents
	// of the Unix strings below) are matched via errors.Is in a build-tagged
	// helper so detection does not depend on locale-sensitive error text.
	return isPlatformClosedErr(err) ||
		strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "broken pipe")
}
