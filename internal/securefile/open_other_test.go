//go:build !unix && !windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package securefile

import (
	"errors"
	"testing"
)

func TestOpenRegularNonblockingFailsClosedOnUnsupportedPlatform(t *testing.T) {
	file, err := openRegularNonblocking("unused")
	if file != nil {
		t.Fatalf("open result = %v, want nil", file)
	}
	if !errors.Is(err, ErrUnsupportedSecureOpen) {
		t.Fatalf("open error = %v, want %v", err, ErrUnsupportedSecureOpen)
	}
}
