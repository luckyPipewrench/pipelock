// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestVerifierClockRollbackReportsUnavailableState(t *testing.T) {
	t.Parallel()
	pub, priv := testSignerKey(t)
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	now := start
	v := newTestVerifier(t, pub, start)
	v.nowFn = func() time.Time { return now }
	v.replayCache.nowFn = v.nowFn
	if err := v.replayCache.CheckAndStore("old", start.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	now = start.Add(7 * time.Minute)
	if err := v.replayCache.CheckAndStore("prune", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	now = start.Add(-2 * time.Minute)
	_, err := v.VerifyRequest(signedVerifierRequest(t, priv, now, ""), nil)
	if code, ok := VerificationFailureCodeOf(err); !ok || code != "replay_state" {
		t.Fatalf("failure code = %q (%v), want replay_state", code, err)
	}
	if !errors.Is(err, ErrReplayStateUnavailable) {
		t.Fatalf("clock refusal lost sentinel: %v", err)
	}
	if strings.Contains(err.Error(), "fresh signature") || !strings.Contains(err.Error(), "clock") {
		t.Fatalf("incorrect remedy: %v", err)
	}
	now = start.Add(7 * time.Minute)
	if _, err := v.VerifyRequest(signedVerifierRequest(t, priv, now, ""), nil); err != nil {
		t.Fatalf("clock recovery: %v", err)
	}
}

func TestVerifierMissingReplayCacheFailsClosed(t *testing.T) {
	t.Parallel()
	pub, priv := testSignerKey(t)
	now := time.Now()
	v := newTestVerifier(t, pub, now)
	v.replayCache = nil
	_, err := v.VerifyRequest(signedVerifierRequest(t, priv, now, ""), nil)
	if code, ok := VerificationFailureCodeOf(err); !ok || code != "replay_state" {
		t.Fatalf("missing cache: code=%q err=%v", code, err)
	}
	if !errors.Is(err, ErrReplayCacheRequired) {
		t.Fatalf("missing cache lost sentinel: %v", err)
	}
}
