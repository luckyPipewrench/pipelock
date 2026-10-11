//go:build (unix && !aix) || windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"testing"
	"time"
)

func TestAppendLockContentionIsBounded(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	unlock, err := acquireAppendLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		release, err := acquireAppendLock(dir)
		if release != nil {
			release()
		}
		done <- err
	}()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		unlock()
		if !errors.Is(err, ErrAppendLockTimeout) {
			t.Fatalf("expected bounded lock timeout, got %v", err)
		}
	case <-timer.C:
		unlock()
		<-done
		t.Fatal("append lock waited without a bounded failure")
	}
	release, err := acquireAppendLock(dir)
	if err != nil {
		t.Fatalf("lock did not recover: %v", err)
	}
	release()
}
