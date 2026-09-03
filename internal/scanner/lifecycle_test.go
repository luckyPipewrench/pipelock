// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// TestScanner_BeginUse_OkBeforeClose verifies the happy path: BeginUse
// succeeds and returns a release func; calling release decrements the
// in-flight counter so a subsequent Close does not block.
func TestScanner_BeginUse_OkBeforeClose(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)

	release, ok := sc.BeginUse()
	if !ok {
		t.Fatal("BeginUse on fresh scanner returned ok=false")
	}
	if sc.Closed() {
		t.Fatal("Closed() returned true on fresh scanner")
	}
	release()

	// Close should return immediately because the WaitGroup is balanced.
	doneCh := make(chan struct{})
	go func() {
		sc.Close()
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked despite balanced BeginUse/release")
	}
	if !sc.Closed() {
		t.Fatal("Closed() returned false after Close completed")
	}
}

// TestScanner_BeginUse_FailsAfterClose verifies that once Close has been
// initiated, no new caller can register in-flight use. This is the gate
// that prevents an unbounded drain when reload has already swapped in a
// successor scanner.
func TestScanner_BeginUse_FailsAfterClose(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	sc.Close()

	if release, ok := sc.BeginUse(); ok {
		t.Error("BeginUse on closed scanner returned ok=true")
		release()
	}
	if !sc.Closed() {
		t.Fatal("Closed() returned false after Close")
	}
}

// TestScanner_Close_BlocksUntilDrain verifies the core drain invariant:
// Close does not return until every outstanding BeginUse caller has
// invoked its release func. Without the WaitGroup drain, a future
// destructive Close would race with mid-scan callers.
func TestScanner_Close_BlocksUntilDrain(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)

	// Two in-flight users, so the drain can be exercised in two steps. Releasing
	// one is a real drain event that a correct Close must observe and keep
	// waiting through; a single user cannot distinguish "still draining" from
	// "never drained".
	releaseFirst, ok := sc.BeginUse()
	if !ok {
		t.Fatal("BeginUse on fresh scanner returned ok=false")
	}
	releaseSecond, ok := sc.BeginUse()
	if !ok {
		t.Fatal("second BeginUse on fresh scanner returned ok=false")
	}

	closeReturned := make(chan struct{})
	go func() {
		sc.Close()
		close(closeReturned)
	}()

	// Wait for closed=true rather than sleeping: under load a fixed window
	// expires before the goroutine is scheduled, which fails the test for a
	// scheduling artifact. The timeout is a hang backstop, not the assertion.
	//
	// This is also what makes the two negative checks below sound rather than
	// timing guesses. Close publishes closed=true BEFORE it starts draining, so
	// once publication is observable, a Close that does not drain has already
	// reached its return path. Waiting on publication therefore gives a broken
	// implementation its full opportunity to return early.
	testwait.For(t, 5*time.Second, sc.Closed, "Close goroutine did not publish closed=true")

	if release3, ok3 := sc.BeginUse(); ok3 {
		t.Error("BeginUse succeeded while Close was draining")
		release3()
	}

	select {
	case <-closeReturned:
		t.Fatal("Close returned with two users still in flight")
	default:
	}

	// Partial drain: the in-flight count drops but does not reach zero, so Close
	// must still be blocked. This catches a Close that waits for the first
	// release rather than for all of them.
	releaseFirst()
	select {
	case <-closeReturned:
		t.Fatal("Close returned after a partial drain, with one user still in flight")
	default:
	}

	releaseSecond()
	select {
	case <-closeReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after the final in-flight release")
	}
}

// TestScanner_Close_DrainTimeoutDefersTeardown verifies that a hung
// in-flight caller does NOT cause forced teardown of internal resources.
// After the configured timeout fires, Close returns but Drained stays
// false; teardown happens only after the hung user finally releases.
// This prevents the fail-open path where a hung scan continues using a
// scanner whose ticker resources have been torn down underneath it.
func TestScanner_Close_DrainTimeoutDefersTeardown(t *testing.T) {
	restore := scanner.SetCloseDrainTimeoutForTest(50 * time.Millisecond)
	defer restore()

	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)

	release, ok := sc.BeginUse()
	if !ok {
		t.Fatal("BeginUse returned ok=false")
	}

	start := time.Now()
	sc.Close()
	elapsed := time.Since(start)

	if elapsed < 50*time.Millisecond {
		t.Errorf("Close returned in %v, expected at least 50ms drain timeout", elapsed)
	}
	if elapsed > 1*time.Second {
		t.Errorf("Close took %v, expected ~50ms drain timeout", elapsed)
	}
	if !sc.Closed() {
		t.Fatal("Closed() returned false after drain-timeout Close")
	}
	// Drained must NOT be true yet: the hung user still holds the
	// pinned scanner, so teardown is parked in the detached goroutine.
	if sc.Drained() {
		t.Fatal("Drained() returned true while hung user still pinned the scanner; resources torn down mid-scan")
	}

	// Releasing the hung user lets the detached goroutine finish drain
	// and run teardown; Drained flips shortly afterwards.
	release()
	testwait.For(t, 2*time.Second, sc.Drained, "scanner drained after hung user release")
}

// TestScanner_Close_Idempotent verifies repeated Close calls are safe
// no-ops. Reload may invoke Close again on a scanner that has already
// been closed (e.g., shutdown after reload).
func TestScanner_Close_Idempotent(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)

	for i := 0; i < 5; i++ {
		sc.Close()
	}
	if !sc.Closed() {
		t.Fatal("Closed() returned false after repeated Close")
	}
}

// TestScanner_BeginUse_RaceFree verifies BeginUse / release / Close
// compose without data races under concurrent load. Run with -race.
func TestScanner_BeginUse_RaceFree(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)

	var wg sync.WaitGroup
	wg.Add(50)
	for i := 0; i < 50; i++ {
		go func() {
			defer wg.Done()
			if release, ok := sc.BeginUse(); ok {
				runtime.Gosched()
				release()
			}
		}()
	}
	// Race Close against in-flight callers.
	closeDone := make(chan struct{})
	go func() {
		sc.Close()
		close(closeDone)
	}()
	wg.Wait()
	<-closeDone
	if !sc.Closed() {
		t.Fatal("Closed() returned false after concurrent close")
	}
}
