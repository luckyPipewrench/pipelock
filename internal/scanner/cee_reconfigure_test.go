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

func TestCEEUpdateConfig_ClampsNonPositiveLimits(t *testing.T) {
	tracker := NewEntropyTracker(100, 300)
	tracker.UpdateConfig(0, 0)
	tracker.mu.Lock()
	if tracker.budget != 1 || tracker.windowSecs != 1 {
		t.Fatalf("tracker limits = %.0f/%d, want 1/1", tracker.budget, tracker.windowSecs)
	}
	tracker.mu.Unlock()

	buffer := NewFragmentBuffer(32, 100, 300)
	buffer.Append("session", []byte("first-second"))
	buffer.UpdateConfig(-1, -1)
	buffer.mu.Lock()
	if buffer.maxBytes != 1 || buffer.windowSecs != 1 {
		t.Fatalf("buffer limits = %d/%d, want 1/1", buffer.maxBytes, buffer.windowSecs)
	}
	buffer.mu.Unlock()
	if got := buffer.TotalBufferBytes(); got != 1 {
		t.Fatalf("buffer bytes = %d, want 1", got)
	}
}

func TestFragmentBufferUpdateConfig_DropsOldestFragments(t *testing.T) {
	buffer := NewFragmentBuffer(64, 100, 300)
	buffer.Append("session", []byte("aaaaaaaa"))
	buffer.Append("session", []byte("bbbbbbbb"))
	buffer.Append("session", []byte("cccccccc"))

	buffer.UpdateConfig(16, 300)
	buffer.mu.Lock()
	fragments := buffer.sessions["session"].fragments
	got := make([]string, len(fragments))
	for i := range fragments {
		got[i] = string(fragments[i].data)
	}
	buffer.mu.Unlock()
	if len(got) != 2 || got[0] != "bbbbbbbb" || got[1] != "cccccccc" {
		t.Fatalf("retained fragments = %q, want [bbbbbbbb cccccccc]", got)
	}
	if total := buffer.TotalBufferBytes(); total != 16 {
		t.Fatalf("buffer bytes = %d, want 16", total)
	}
}
