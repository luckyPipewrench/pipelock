// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package directorysync

import (
	"errors"
	"syscall"
	"testing"
)

func TestDarwinDirectoryFullSyncFallback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fullErr  error
		wantSync bool
		wantErr  error
	}{
		{"full flush", nil, false, nil},
		{"unsupported", syscall.ENOTSUP, true, nil},
		{"invalid for descriptor", syscall.EINVAL, true, nil},
		{"not a tty", syscall.ENOTTY, true, nil},
		{"fallback I/O error", syscall.ENOTSUP, true, syscall.EIO},
		{"I/O error", syscall.EIO, false, syscall.EIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			err := syncDarwinDirectory(1, func(int) error { return tc.fullErr }, func(int) error {
				called = true
				return tc.wantErr
			})
			if called != tc.wantSync || !errors.Is(err, tc.wantErr) {
				t.Fatalf("fallback called = %t, error = %v; want %t, %v", called, err, tc.wantSync, tc.wantErr)
			}
		})
	}
}
