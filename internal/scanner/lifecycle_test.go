// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestScanner_BeginUse_OkBeforeClose verifies the happy path: BeginUse
// succeeds and returns a release func; calling release decrements the
// in-flight counter so a subsequent Close does not block.
func TestScanner_BeginUse_OkBeforeClose(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)

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
	sc := scanner.New(cfg)
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
	sc := scanner.New(cfg)

	release, ok := sc.BeginUse()
	if !ok {
		t.Fatal("BeginUse on fresh scanner returned ok=false")
	}

	// Start Close in a goroutine. It must block on the in-flight user.
	closeReturned := make(chan struct{})
	go func() {
		sc.Close()
		close(closeReturned)
	}()

	// Allow the goroutine to publish closed=true and start the drain.
	select {
	case <-closeReturned:
		t.Fatal("Close returned before in-flight release was invoked")
	case <-time.After(50 * time.Millisecond):
	}

	// Once closed=true is published, BeginUse must reject newcomers.
	if !sc.Closed() {
		t.Fatal("Close goroutine did not publish closed=true within 50ms")
	}
	if release2, ok2 := sc.BeginUse(); ok2 {
		t.Error("BeginUse succeeded while Close was draining")
		release2()
	}

	release()
	select {
	case <-closeReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after in-flight release was invoked")
	}
}

// TestScanner_Close_DrainTimeout verifies the fail-safe: if an in-flight
// caller never invokes release, Close still completes after the configured
// drain timeout so a hung scan cannot leak the scanner indefinitely.
func TestScanner_Close_DrainTimeout(t *testing.T) {
	restore := scanner.SetCloseDrainTimeoutForTest(50 * time.Millisecond)
	defer restore()

	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)

	release, ok := sc.BeginUse()
	if !ok {
		t.Fatal("BeginUse returned ok=false")
	}
	defer release() // intentionally deferred to test runtime: never released during Close

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
}

// TestScanner_Close_Idempotent verifies repeated Close calls are safe
// no-ops. Reload may invoke Close again on a scanner that has already
// been closed (e.g., shutdown after reload).
func TestScanner_Close_Idempotent(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)

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
	sc := scanner.New(cfg)

	var wg sync.WaitGroup
	wg.Add(50)
	for i := 0; i < 50; i++ {
		go func() {
			defer wg.Done()
			if release, ok := sc.BeginUse(); ok {
				time.Sleep(time.Microsecond)
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
