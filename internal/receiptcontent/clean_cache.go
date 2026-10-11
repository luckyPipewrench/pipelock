// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// The four receipts of one request share most of their fragment candidates,
// and the candidates built only from fixed labels repeat on every request.
// A detector bound to one immutable scanner generation returns the same
// result for the same text, so a text it already judged clean needs no
// second call.
const (
	cleanCacheShards = 16
	// DefaultCleanCacheEntries bounds one cache. Each shard keeps at most two
	// generations of this share, so the cache holds at most twice this many
	// 16-byte digests.
	DefaultCleanCacheEntries = 1 << 16
)

type cleanDigest [16]byte

type cleanShard struct {
	mu        sync.Mutex
	cur, prev map[cleanDigest]struct{}
}

type cleanCache struct {
	key      [32]byte
	perShard int
	shards   [cleanCacheShards]cleanShard
}

// CachedDetector is a detector with a bounded memory of the texts it judged
// clean. It is exact only for a deterministic detector: callers must wrap a
// detector bound to one immutable scanner generation, never an arbitrary
// callback.
//
// Only a result with no match of any kind is remembered, and a remembered
// text returns that same empty clean result, so Detect returns exactly what
// the wrapped detector would. A dirty or warn-carrying result is returned as
// is and not remembered. Texts are keyed by a keyed SHA-256 digest truncated
// to 128 bits; the key is random per cache, so text is never retained and no
// one outside the process can choose a colliding pair.
type CachedDetector struct {
	det   Detector
	cache cleanCache
}

// NewCachedDetector wraps det with a clean-result cache of about entries
// texts.
func NewCachedDetector(det Detector, entries int) (*CachedDetector, error) {
	if det == nil {
		return nil, fmt.Errorf("receiptcontent: cached detector requires a detector")
	}
	if entries < cleanCacheShards {
		return nil, fmt.Errorf("receiptcontent: clean cache needs at least %d entries, got %d", cleanCacheShards, entries)
	}
	d := &CachedDetector{det: det, cache: cleanCache{perShard: entries / cleanCacheShards}}
	if _, err := io.ReadFull(rand.Reader, d.cache.key[:]); err != nil {
		return nil, fmt.Errorf("receiptcontent: clean cache key: %w", err)
	}
	return d, nil
}

// Detect is the cached Detector.
func (d *CachedDetector) Detect(ctx context.Context, text string) scanner.TextDLPResult {
	c := &d.cache
	key := c.digest(text)
	if c.has(key) {
		return scanner.TextDLPResult{Clean: true}
	}
	res := d.det(ctx, text)
	if res.Clean && len(res.Matches) == 0 && len(res.InformationalMatches) == 0 {
		c.add(key)
	}
	return res
}

// Len reports how many clean texts the cache currently remembers.
func (d *CachedDetector) Len() int {
	n := 0
	for i := range d.cache.shards {
		s := &d.cache.shards[i]
		s.mu.Lock()
		n += len(s.cur) + len(s.prev)
		s.mu.Unlock()
	}
	return n
}

func (c *cleanCache) digest(text string) cleanDigest {
	h := sha256.New()
	_, _ = h.Write(c.key[:])
	_, _ = io.WriteString(h, text)
	var sum [sha256.Size]byte
	var d cleanDigest
	copy(d[:], h.Sum(sum[:0]))
	return d
}

func (c *cleanCache) shard(d cleanDigest) *cleanShard {
	return &c.shards[int(d[0])%cleanCacheShards]
}

func (c *cleanCache) has(d cleanDigest) bool {
	s := c.shard(d)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cur[d]; ok {
		return true
	}
	if _, ok := s.prev[d]; ok {
		s.insertLocked(c.perShard, d) // keep a text in use across a rollover
		return true
	}
	return false
}

func (c *cleanCache) add(d cleanDigest) {
	s := c.shard(d)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.insertLocked(c.perShard, d)
}

// insertLocked adds d to the current generation. A full generation becomes
// the previous one and the oldest is dropped, which bounds memory without
// tracking recency per entry.
func (s *cleanShard) insertLocked(limit int, d cleanDigest) {
	if s.cur == nil {
		s.cur = make(map[cleanDigest]struct{}, limit)
	}
	if len(s.cur) >= limit {
		s.prev, s.cur = s.cur, make(map[cleanDigest]struct{}, limit)
	}
	s.cur[d] = struct{}{}
}
