// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package evidence

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCompactExchangeErrorReportsUnsupportedFilesystem(t *testing.T) {
	t.Parallel()
	for _, errno := range []error{unix.EINVAL, unix.ENOSYS, unix.ENOTSUP} {
		err := compactExchangeError(errno)
		if !errors.Is(err, errno) || !strings.Contains(err.Error(), "atomic directory exchange is unavailable") {
			t.Fatalf("compactExchangeError(%v) = %v", errno, err)
		}
	}
	other := errors.New("other")
	if err := compactExchangeError(other); !errors.Is(err, other) || strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("other error changed: %v", err)
	}
}
