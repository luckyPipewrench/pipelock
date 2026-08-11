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

// TestPreparedManifest_ConcurrentCloseIsSerialized runs Close against Apply
// under the race detector.
//
// Close writes -1 over each descriptor while Apply reads the same fields to
// build rules. Unserialized, Apply could hand a stale descriptor number to the
// kernel, and a number freed by Close can be reused by any other open in the
// process, so the ruleset would grant an unrelated object. The assertion is
// that neither call panics and the race detector stays quiet; the outcome of
// the race is deliberately not asserted, since either order is legitimate.
func TestPreparedManifest_ConcurrentCloseIsSerialized(t *testing.T) {
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
