// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"fmt"
	"sync"
	"time"
)

// ReplayCache is a bounded, nonce-keyed in-process cache for inbound envelope
// verification. It is safe for concurrent use.
type ReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	window  time.Duration
	max     int
	nowFn   func() time.Time
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
		entries: make(map[string]time.Time),
		window:  window,
		max:     maxEntries,
		nowFn:   nowFn,
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
	storedUntil := expires.Add(skew)
	maxStoredUntil := now.Add(c.window).Add(skew)
	if storedUntil.After(maxStoredUntil) {
		storedUntil = maxStoredUntil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for n, exp := range c.entries {
		if !exp.After(now) {
			delete(c.entries, n)
		}
	}
	if _, ok := c.entries[nonce]; ok {
		return fmt.Errorf("signature replay detected")
	}
	for len(c.entries) >= c.max {
		var oldestNonce string
		var oldestExpiry time.Time
		for n, exp := range c.entries {
			if oldestNonce == "" || exp.Before(oldestExpiry) {
				oldestNonce = n
				oldestExpiry = exp
			}
		}
		delete(c.entries, oldestNonce)
	}

	c.entries[nonce] = storedUntil
	return nil
}
