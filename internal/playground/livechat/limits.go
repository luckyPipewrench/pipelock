// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"errors"
	"sync"
	"time"
)

// Safety-control errors. All are fail-closed outcomes: the caller refuses the
// action rather than proceeding.
var (
	// ErrRateLimited is returned when a key has exhausted its token bucket.
	ErrRateLimited = errors.New("livechat: rate limit exceeded")
	// ErrAtCapacity is returned when the global concurrency cap is reached.
	ErrAtCapacity = errors.New("livechat: at session capacity")
	// ErrInputTooLarge is returned when a visitor message exceeds the size cap.
	ErrInputTooLarge = errors.New("livechat: message too large")
	// ErrInputEmpty is returned for an empty visitor message.
	ErrInputEmpty = errors.New("livechat: empty message")
)

// defaultRateMaxKeys bounds the number of distinct keys (IPs/codes) a rate
// limiter will track, so an attacker spraying unique keys (e.g. spoofed source
// addresses) cannot exhaust memory. When the cap is hit and no idle bucket can
// be reclaimed, NEW keys are refused (fail-closed).
const defaultRateMaxKeys = 4096

// RateLimiter is a per-key token-bucket limiter with bounded memory and an
// injectable clock. It is safe for concurrent use. Construct one per dimension
// (e.g. one keyed by client IP, one keyed by invite-code id).
type RateLimiter struct {
	refillPerSec float64
	burst        float64
	idleTTL      time.Duration
	maxKeys      int
	now          func() time.Time

	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// RateConfig configures a RateLimiter.
type RateConfig struct {
	// RefillPerSec is the sustained allowed rate (tokens added per second).
	RefillPerSec float64
	// Burst is the bucket capacity (max tokens, i.e. max instantaneous burst).
	Burst float64
	// IdleTTL is how long a fully-recovered bucket may sit unused before it is
	// eligible for eviction. Defaults to 10 minutes.
	IdleTTL time.Duration
	// MaxKeys bounds tracked keys. Defaults to defaultRateMaxKeys.
	MaxKeys int
	// Now overrides the clock for tests. Defaults to time.Now.
	Now func() time.Time
}

// NewRateLimiter builds a RateLimiter. Non-positive rate or burst is clamped to
// a minimal allow-one-then-throttle policy so a misconfiguration cannot
// accidentally disable limiting.
func NewRateLimiter(cfg RateConfig) *RateLimiter {
	if cfg.RefillPerSec <= 0 {
		cfg.RefillPerSec = 1
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 1
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 10 * time.Minute
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = defaultRateMaxKeys
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{
		refillPerSec: cfg.RefillPerSec,
		burst:        cfg.Burst,
		idleTTL:      cfg.IdleTTL,
		maxKeys:      cfg.MaxKeys,
		now:          now,
		buckets:      make(map[string]*tokenBucket),
	}
}

// Allow consumes one token for key and reports whether the action is permitted.
// A nil limiter denies (fail-closed): an unconfigured limiter must not allow
// unbounded traffic.
func (r *RateLimiter) Allow(key string) bool {
	if r == nil {
		return false
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[key]
	if !ok {
		if len(r.buckets) >= r.maxKeys {
			r.evictIdleLocked(now)
		}
		if len(r.buckets) >= r.maxKeys {
			// Saturated with active keys: refuse the new key rather than grow
			// unbounded. Fail-closed under a unique-key spray.
			return false
		}
		b = &tokenBucket{tokens: r.burst, last: now}
		r.buckets[key] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * r.refillPerSec
			if b.tokens > r.burst {
				b.tokens = r.burst
			}
			b.last = now
		}
	}

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Sweep removes fully-recovered, idle buckets. Safe to call periodically. It is
// also invoked opportunistically by Allow when the key cap is hit.
func (r *RateLimiter) Sweep() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evictIdleLocked(r.now())
}

func (r *RateLimiter) evictIdleLocked(now time.Time) {
	for k, b := range r.buckets {
		// Refill to "now" so a bucket that has recovered is recognized as full.
		elapsed := now.Sub(b.last).Seconds()
		tokens := b.tokens
		if elapsed > 0 {
			tokens += elapsed * r.refillPerSec
		}
		if tokens >= r.burst && now.Sub(b.last) >= r.idleTTL {
			delete(r.buckets, k)
		}
	}
}

// Len returns the number of tracked keys (for diagnostics/tests).
func (r *RateLimiter) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}

// ConcurrencyLimiter is a counting semaphore enforcing a global cap on
// simultaneous sessions. Over the cap, Acquire refuses (the server queues or
// returns busy) — never unbounded compute.
type ConcurrencyLimiter struct {
	mu  sync.Mutex
	max int
	cur int
}

// NewConcurrencyLimiter builds a limiter with the given cap. A limit <= 0 is
// treated as 1 (at least serialize), never as unlimited.
func NewConcurrencyLimiter(limit int) *ConcurrencyLimiter {
	if limit <= 0 {
		limit = 1
	}
	return &ConcurrencyLimiter{max: limit}
}

// Acquire reserves one slot. It returns a release function and ok=true on
// success; ok=false (with a no-op release) when at capacity. release is
// idempotent. A nil limiter fails closed (ok=false).
func (c *ConcurrencyLimiter) Acquire() (release func(), ok bool) {
	if c == nil {
		return func() {}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur >= c.max {
		return func() {}, false
	}
	c.cur++
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			if c.cur > 0 {
				c.cur--
			}
			c.mu.Unlock()
		})
	}, true
}

// InUse returns the number of currently held slots.
func (c *ConcurrencyLimiter) InUse() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur
}

// Cap returns the configured maximum.
func (c *ConcurrencyLimiter) Cap() int {
	if c == nil {
		return 0
	}
	return c.max
}

// Session-cap defaults and bounds.
const (
	defaultMaxInputBytes = 2048
	maxMaxInputBytes     = 16384
	defaultSessionTTL    = 90 * time.Second
	minSessionTTL        = 10 * time.Second
	maxSessionTTL        = 10 * time.Minute
)

// Limits holds the per-session value caps (input size and wall-clock). It is a
// plain policy value; the session enforces SessionTTL via a context deadline.
type Limits struct {
	MaxInputBytes int
	SessionTTL    time.Duration
}

// DefaultLimits returns the conservative defaults used for public exposure.
func DefaultLimits() Limits {
	return Limits{MaxInputBytes: defaultMaxInputBytes, SessionTTL: defaultSessionTTL}
}

// Clamp returns a copy with each field forced into its safe range. Used at
// construction so an operator cannot set an absurd cap.
func (l Limits) Clamp() Limits {
	out := l
	if out.MaxInputBytes <= 0 {
		out.MaxInputBytes = defaultMaxInputBytes
	}
	if out.MaxInputBytes > maxMaxInputBytes {
		out.MaxInputBytes = maxMaxInputBytes
	}
	if out.SessionTTL <= 0 {
		out.SessionTTL = defaultSessionTTL
	}
	if out.SessionTTL < minSessionTTL {
		out.SessionTTL = minSessionTTL
	}
	if out.SessionTTL > maxSessionTTL {
		out.SessionTTL = maxSessionTTL
	}
	return out
}

// CheckInput validates a visitor message against the size cap. Empty and
// oversized messages are rejected (fail-closed).
func (l Limits) CheckInput(msg string) error {
	if len(msg) == 0 {
		return ErrInputEmpty
	}
	if len(msg) > l.MaxInputBytes {
		return ErrInputTooLarge
	}
	return nil
}
