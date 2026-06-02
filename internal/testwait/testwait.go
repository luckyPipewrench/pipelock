// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package testwait

import (
	"context"
	"fmt"
	"testing"
	"time"
)

const defaultInterval = 5 * time.Millisecond

// For polls cond until it returns true or timeout elapses.
func For(t testing.TB, timeout time.Duration, cond func() bool, format string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ForContext(t, ctx, cond, format, args...)
}

// ForContext polls cond until it returns true or ctx is done.
func ForContext(t testing.TB, ctx context.Context, cond func() bool, format string, args ...any) {
	t.Helper()
	if cond() {
		return
	}
	ticker := time.NewTicker(defaultInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if cond() {
				return
			}
			t.Fatalf("timed out waiting for %s: %v", fmt.Sprintf(format, args...), ctx.Err())
		case <-ticker.C:
			if cond() {
				return
			}
		}
	}
}
