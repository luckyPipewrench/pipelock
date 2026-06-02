// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package testwait

import (
	"context"
	"testing"
	"time"
)

func TestForReturnsWhenConditionAlreadyTrue(t *testing.T) {
	calls := 0
	For(t, time.Second, func() bool {
		calls++
		return true
	}, "already true")
	if calls != 1 {
		t.Fatalf("condition calls = %d, want 1", calls)
	}
}

func TestForContextPollsUntilConditionTrue(t *testing.T) {
	calls := 0
	ForContext(t, context.Background(), func() bool {
		calls++
		return calls >= 2
	}, "eventual true")
	if calls < 2 {
		t.Fatalf("condition calls = %d, want at least 2", calls)
	}
}

func TestForContextChecksConditionAfterContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := 0
	ForContext(t, ctx, func() bool {
		calls++
		return calls >= 2
	}, "true on final check")
	if calls != 2 {
		t.Fatalf("condition calls = %d, want 2", calls)
	}
}
