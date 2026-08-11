// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestApply_IsOneShot proves a second application is refused.
//
// Landlock restrictions stack and cannot be lifted, so applying the same
// manifest twice intersects the policy with itself and narrows it permanently.
// The refusal happens before any syscall, which is what lets this run in
// process: the manifest here is incomplete, so even the first call stops short
// of the kernel.
func TestApply_IsOneShot(t *testing.T) {
	p := &PreparedManifest{complete: false}
	p.applied = true

	record, err := p.apply(func() (int, error) { return SocketMediationABI, nil })

	if !errors.Is(err, ErrAlreadyApplied) {
		t.Fatalf("err = %v, want ErrAlreadyApplied", err)
	}
	if record.Enforced() {
		t.Error("a repeat application must not report enforced")
	}
}

// TestPreparedManifest_CloseWaitsForApply proves the lock actually serializes.
//
// The previous version of this test ran Apply with an ABI below the in-process
// floor, so it returned before ever reading the rule slice. Close and Apply
// never overlapped on the data the lock protects, and the test would have kept
// passing if the lock were deleted. It proved nothing.
//
// This version blocks INSIDE the locked region, using the injected ABI lookup as
// the block point because apply calls it while holding the mutex. Close is then
// started and must not finish until Apply lets go. The manifest is incomplete so
// that Apply still returns before any syscall: the point is the lock, not the
// kernel.
func TestPreparedManifest_CloseWaitsForApply(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareGrants(
		[]grant{{declared: dir, access: AccessWriteDirectory}},
		os.Getuid(),
		mockFloorAllows,
	)
	if err != nil {
		t.Fatalf("prepareGrants: %v", err)
	}
	defer func() { _ = prepared.Close() }()
	// Force the incomplete path so apply returns without touching the kernel.
	prepared.complete = false

	inside := make(chan struct{})
	release := make(chan struct{})
	applyDone := make(chan struct{})
	go func() {
		defer close(applyDone)
		_, _ = prepared.apply(func() (int, error) {
			close(inside)
			<-release
			return SocketMediationABI, nil
		})
	}()

	select {
	case <-inside:
	case <-time.After(5 * time.Second):
		t.Fatal("apply never reached the locked region")
	}

	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		_ = prepared.Close()
	}()

	// Close must be blocked while Apply holds the mutex.
	select {
	case <-closeDone:
		t.Fatal("Close completed while Apply held the lock; rule descriptors are not serialized")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	select {
	case <-applyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("apply did not finish after release")
	}
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish after apply released the lock")
	}
}

// TestPreparedManifest_ConcurrentCloseIsRaceFree runs Close against Apply
// under the race detector.
//
// Close writes -1 over each descriptor while Apply reads the same fields to
// build rules. Unserialized, Apply could hand a stale descriptor number to the
// kernel, and a number freed by Close can be reused by any other open in the
// process, so the ruleset would grant an unrelated object. The assertion is
// that neither call panics and the race detector stays quiet; the outcome of
// the race is deliberately not asserted, since either order is legitimate.
func TestPreparedManifest_ConcurrentCloseIsRaceFree(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	for range 20 {
		prepared, err := prepareGrants(
			[]grant{{declared: dir, access: AccessWriteDirectory}},
			os.Getuid(),
			mockFloorAllows,
		)
		if err != nil {
			t.Fatalf("prepareGrants: %v", err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			// Below the in-process floor, so this returns before touching the
			// kernel while still exercising the locked path.
			_, _ = prepared.apply(func() (int, error) { return MinimumABI, nil })
		}()
		go func() {
			defer wg.Done()
			_ = prepared.Close()
		}()
		wg.Wait()

		if err := prepared.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
	}
}
