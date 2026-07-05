// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !js

package baseline

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestRetryableIntegrityHighWaterLockError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "would block", err: syscall.EWOULDBLOCK, want: true},
		{name: "again", err: syscall.EAGAIN, want: true},
		{name: "interrupted", err: syscall.EINTR, want: true},
		{name: "wrapped interrupted", err: fmt.Errorf("lock interrupted: %w", syscall.EINTR), want: true},
		{name: "permission", err: syscall.EPERM, want: false},
		{name: "unrelated", err: errors.New("interrupted"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := retryableIntegrityHighWaterLockError(tt.err); got != tt.want {
				t.Fatalf("retryableIntegrityHighWaterLockError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
