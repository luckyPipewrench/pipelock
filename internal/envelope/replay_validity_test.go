// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"errors"
	"testing"
	"time"
)

func TestReplayCacheRetainsFullValidity(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	now := start
	cache := newReplayCache(time.Minute, 1, func() time.Time { return now })
	expires := start.Add(90 * time.Second)
	if err := cache.CheckAndStoreWithSkew("first", expires, time.Minute); err != nil {
		t.Fatal(err)
	}
	now = start.Add(121 * time.Second)
	if err := cache.CheckAndStoreWithSkew("second", now.Add(time.Minute), time.Minute); !errors.Is(err, ErrReplayCacheCapacity) {
		t.Errorf("capacity before expiry: %v", err)
	}
	if err := cache.CheckAndStoreWithSkew("first", expires, time.Minute); err == nil {
		t.Error("accepted still-valid replay")
	}
	now = expires.Add(time.Minute)
	if err := cache.CheckAndStoreWithSkew("first", expires, time.Minute); err == nil {
		t.Error("accepted expired signature")
	}
	if err := cache.CheckAndStore("second", now.Add(time.Minute)); err != nil {
		t.Fatalf("capacity did not recover: %v", err)
	}
}

func TestVerifierRetainsFutureClockNonce(t *testing.T) {
	t.Parallel()
	pub, priv := testSignerKey(t)
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	now := start
	req := signedVerifierRequest(t, priv, start.Add(30*time.Second), "")
	v := newTestVerifier(t, pub, start)
	v.nowFn = func() time.Time { return now }
	v.replayCache.nowFn = v.nowFn
	if _, err := v.VerifyRequest(req, nil); err != nil {
		t.Fatal(err)
	}
	now = start.Add(6*time.Minute + time.Second)
	if _, err := v.VerifyRequest(req, nil); err != nil {
		if code, ok := VerificationFailureCodeOf(err); !ok || code != VerificationFailureReplay {
			t.Fatalf("want replay failure, got %v", err)
		}
	} else {
		t.Fatal("accepted still-valid replay after retention window")
	}
}

func TestVerifierReloadLargerSkewRetainsNonces(t *testing.T) {
	t.Parallel()
	for _, timing := range []string{"retained", "old-in-flight", "already-pruned"} {
		t.Run(timing, func(t *testing.T) {
			pub, priv := testSignerKey(t)
			start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
			now := start
			old := newTestVerifier(t, pub, start)
			old.nowFn = func() time.Time { return now }
			old.replayCache.nowFn = old.nowFn
			req := signedVerifierRequest(t, priv, start, "")
			if timing != "old-in-flight" {
				if _, err := old.VerifyRequest(req, nil); err != nil {
					t.Fatal(err)
				}
			}
			if timing == "already-pruned" {
				now = start.Add(6*time.Minute + time.Second)
				if err := old.replayCache.CheckAndStoreWithSkew("prune-trigger", now.Add(time.Minute), old.skew); err != nil {
					t.Fatal(err)
				}
			}
			next := newTestVerifier(t, pub, start)
			next.skew = 2 * time.Minute
			next.nowFn = old.nowFn
			next.replayCache.nowFn = old.nowFn
			next.PreserveReplayState(old)
			if timing == "old-in-flight" {
				if _, err := old.VerifyRequest(req, nil); err != nil {
					t.Fatal(err)
				}
			}
			now = start.Add(6*time.Minute + time.Second)
			_, err := next.VerifyRequest(req, nil)
			if code, ok := VerificationFailureCodeOf(err); !ok || code != VerificationFailureReplay {
				t.Fatalf("want replay failure after larger-skew reload, got %v", err)
			}
			if err := next.replayCache.CheckAndStoreWithSkew("fresh", now.Add(time.Minute), next.skew); err != nil {
				t.Fatalf("fresh signature rejected: %v", err)
			}
		})
	}
}
