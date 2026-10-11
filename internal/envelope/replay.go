// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrReplayCacheCapacity reports that accepting a new nonce would evict
// still-valid replay state and make a prior request replayable.
var ErrReplayCacheCapacity = errors.New("signature replay cache capacity exhausted; cannot safely verify nonce")

// ReplayCache is a bounded, nonce-keyed in-process cache for inbound envelope
// verification. It is safe for concurrent use.
type ReplayCache struct {
	*replayState
	window time.Duration
	max    int
	nowFn  func() time.Time
}

type replayState struct {
	mu           sync.Mutex
	entries      map[string]time.Time // signed expiration, before skew
	maxSkew      time.Duration
	prunedExpiry time.Time
}

func NewReplayCache(window time.Duration, maxEntries int) *ReplayCache {
	return newReplayCache(window, maxEntries, time.Now)
}

func newReplayCache(window time.Duration, maxEntries int, nowFn func() time.Time) *ReplayCache {
	if window <= 0 {
		window = 5 * time.Minute
	}
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	if nowFn == nil {
		nowFn = time.Now
	}
	return &ReplayCache{
		replayState: &replayState{entries: make(map[string]time.Time)},
		window:      window,
		max:         maxEntries,
		nowFn:       nowFn,
	}
}

func (c *ReplayCache) CheckAndStore(nonce string, expires time.Time) error {
	return c.CheckAndStoreWithSkew(nonce, expires, 0)
}

func (c *ReplayCache) CheckAndStoreWithSkew(nonce string, expires time.Time, skew time.Duration) error {
	if c == nil {
		return nil
	}
	if nonce == "" {
		return fmt.Errorf("signature nonce is required")
	}
	if skew < 0 {
		skew = 0
	}

	now := c.nowFn().UTC()
	if expires.IsZero() {
		expires = now.Add(c.window)
	}
	if !expires.After(now.Add(-skew)) {
		return fmt.Errorf("signature expired")
	}
	// Retain through the full accepted validity interval, including signer
	// clock lead. Capacity exhaustion rejects new nonces instead of shortening
	// protection for signatures that can still verify.
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxSkew = max(c.maxSkew, skew)

	for n, exp := range c.entries {
		if !exp.Add(c.maxSkew).After(now) {
			delete(c.entries, n)
			if exp.After(c.prunedExpiry) {
				c.prunedExpiry = exp
			}
		}
	}
	// A relaxed skew or a clock rollback must not revive signatures whose
	// nonce may already have been forgotten. Retain one conservative boundary
	// instead of an unbounded set of expired nonces.
	if !expires.After(c.prunedExpiry) {
		return fmt.Errorf("signature replay state unavailable; a fresh signature is required")
	}
	if _, ok := c.entries[nonce]; ok {
		return fmt.Errorf("signature replay detected")
	}
	if len(c.entries) >= c.max {
		return ErrReplayCacheCapacity
	}

	c.entries[nonce] = expires
	return nil
}
