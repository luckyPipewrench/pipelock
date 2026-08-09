// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"testing"
	"time"
)

func TestEntropyTrackerUpdateConfig_PreservesCurrentState(t *testing.T) {
	tracker := NewEntropyTracker(100, 300)
	tracker.Record("session", []byte("abc"))
	before := tracker.CurrentUsage("session")
	if before == 0 {
		t.Fatal("test setup did not record entropy")
	}

	tracker.UpdateConfig(1, 300)
	if got := tracker.Budget(); got != 1 {
		t.Fatalf("budget = %v, want 1", got)
	}
	if !tracker.BudgetExceeded("session") {
		t.Fatal("config update cleared in-window entropy state")
	}

	tracker.UpdateConfig(100, 1)
	tracker.mu.Lock()
	tracker.sessions["session"].entries[0].timestamp = time.Now().Add(-2 * time.Second)
	tracker.mu.Unlock()
	tracker.UpdateConfig(100, 1)
	if got := tracker.CurrentUsage("session"); got != 0 {
		t.Fatalf("shorter window retained expired usage %v", got)
	}
}

func TestFragmentBufferUpdateConfig_PreservesNewestSuffix(t *testing.T) {
	buffer := NewFragmentBuffer(32, 100, 300)
	buffer.Append("session", []byte("first-second"))

	buffer.UpdateConfig(8, 300)
	if got := buffer.TotalBufferBytes(); got != 8 {
		t.Fatalf("total bytes = %d, want 8", got)
	}
	buffer.mu.Lock()
	got := string(buffer.sessions["session"].fragments[0].data)
	buffer.mu.Unlock()
	if got != "t-second" {
		t.Fatalf("retained suffix = %q, want %q", got, "t-second")
	}
}
