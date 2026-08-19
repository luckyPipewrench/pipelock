// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package testwait

import (
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const defaultInterval = 5 * time.Millisecond

// ciDeadlineScale multiplies every For deadline when running under CI.
//
// These deadlines are sized for a development host. A CI runner is slower and
// far more contended: internal/proxy takes around 500s there with heavy
// parallelism, so a wait sized for a laptop becomes a coin flip and the harness
// itself decides the result. Three separate tests failed that way in one day, in
// three different packages, each time on a deadline rather than on the behavior
// under test.
//
// Scaling here rather than at the call sites is deliberate. There are more than
// ninety of them and most have deadlines of ten seconds or less, so raising them
// one at a time is a treadmill that keeps reporting timing noise as product
// failure. This weakens no assertion: cond and the failure message are
// unchanged, only the patience is, and a genuine hang still fails the package
// -timeout, which is the real backstop.
const ciDeadlineScale = 4

// scaleDeadline returns the deadline to actually use.
//
// PIPELOCK_TEST_DEADLINE_SCALE overrides the factor, so a loaded development
// host can opt in and a bisect can pin it to 1 to reproduce the original timing.
// Local runs are left alone by default to keep the feedback loop fast.
func scaleDeadline(d time.Duration) time.Duration {
	if raw := strings.TrimSpace(os.Getenv("PIPELOCK_TEST_DEADLINE_SCALE")); raw != "" {
		if f, err := strconv.ParseFloat(raw, 64); err == nil && f > 0 {
			// An absurd factor must saturate, not wrap. A float64 product past
			// the int64 range converts to a negative Duration, which would make
			// every wait expire immediately: the failure direction is a false
			// test failure, so clamp rather than trust the input.
			scaled := float64(d) * f
			if scaled >= float64(math.MaxInt64) {
				return time.Duration(math.MaxInt64)
			}
			// Both ends of the range fail the same way, so both are rejected
			// here. Overflow wraps to a negative Duration; a factor small enough
			// to put the product under one nanosecond truncates to zero. Either
			// makes every wait expire before it polls, reporting a passing
			// condition as a failure. Anything unrepresentable falls through to
			// the unscaled default rather than producing a useless deadline.
			if scaled >= 1 {
				return time.Duration(scaled)
			}
		}
	}
	if strings.TrimSpace(os.Getenv("CI")) != "" {
		return d * ciDeadlineScale
	}
	return d
}

// For polls cond until it returns true or timeout elapses. The deadline is
// scaled per scaleDeadline; the condition is not affected.
func For(t testing.TB, timeout time.Duration, cond func() bool, format string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), scaleDeadline(timeout))
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
