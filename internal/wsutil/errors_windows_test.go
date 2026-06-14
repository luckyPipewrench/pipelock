// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package wsutil

import (
	"fmt"
	"syscall"
	"testing"
)

// TestIsExpectedCloseErr_Windows verifies the Winsock teardown errnos are
// treated as a clean close, including when wrapped the way the ws header
// read path wraps them (fmt.Errorf %w / net.OpError chains). These are the
// Windows equivalents of "connection reset by peer" / "broken pipe".
func TestIsExpectedCloseErr_Windows(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"WSAECONNABORTED", syscall.WSAECONNABORTED},
		{"WSAECONNRESET", syscall.WSAECONNRESET},
		{"wrapped WSAECONNABORTED", fmt.Errorf("reading ws header: %w", syscall.WSAECONNABORTED)},
		{"wrapped WSAECONNRESET", fmt.Errorf("reading ws header: %w", syscall.WSAECONNRESET)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !IsExpectedCloseErr(tt.err) {
				t.Errorf("IsExpectedCloseErr(%v) = false, want true", tt.err)
			}
		})
	}
}
