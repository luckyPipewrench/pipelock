// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package authlimit bounds failed bearer-credential attempts per client
// address on Pipelock's opt-in administrative listeners.
//
// Every one of those listeners authenticates before it rate-limits, so a
// wrong guess costs the caller nothing: it returns 401 without consuming the
// authenticated request budget. That is an unbounded online guessing window.
// This package closes it by counting presented-but-invalid credentials per
// client address and refusing to evaluate further credentials from that
// address once the window is spent.
//
// Failure directions, stated so they are reviewed rather than assumed:
//
//   - Over budget => 429 before the credential is compared. The guesser gets
//     no oracle. A legitimate operator sharing the same source address as an
//     attacker waits at most one window; an operator on any other address is
//     unaffected. Requests that present a VALID credential while under budget
//     clear the address's failures, so a single mistyped token never locks an
//     operator out.
//   - Requests that present NO credential are not counted. They are not
//     guesses, and a challenge-then-retry client would otherwise spend its
//     budget on the challenge.
//   - The key is the transport peer address only. Forwarded-for headers are
//     attacker-controlled and would let a guesser pick a fresh key per
//     attempt, which is a bypass of the whole mechanism.
//   - The table is bounded. When it is full the least recently active address
//     is evicted; an attacker who can present many source addresses can age
//     out its own earlier keys but cannot grow memory without bound.
package authlimit

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	// DefaultMaxFailures is the number of invalid credentials one client
	// address may present per window before further attempts are refused
	// unevaluated. It matches the authenticated request budget the kill switch
	// API already applies per minute.
	DefaultMaxFailures = 10
	// DefaultWindow is the sliding window over which failures are counted.
	DefaultWindow = time.Minute
	// DefaultMaxKeys bounds the number of client addresses tracked at once.
	DefaultMaxKeys = 4096
)

// Limiter tracks presented-credential reservations per client key. Every
// admitted evaluation holds a slot until the window passes or the credential
// verifies and the caller resets the key.
type Limiter struct {
	maxFailures int
	window      time.Duration
	maxKeys     int
	now         func() time.Time

	mu      sync.Mutex
	entries map[string]*entry
	nextID  uint64
}

type entry struct {
	// failures holds the admitted evaluations inside the window, oldest
	// first. It never grows past maxFailures entries.
	failures []slot
}

// slot is one admitted evaluation: when it was admitted and an id that lets
// the request that took it give back exactly that slot.
type slot struct {
	id uint64
	at time.Time
}

// Reservation identifies one admitted evaluation so the caller can release
// exactly the slot it took, never a slot another request is holding. The zero
// Reservation releases nothing.
type Reservation struct {
	key string
	id  uint64
}

// New returns a limiter allowing maxFailures presented-but-invalid credentials
// per client key per window. Non-positive arguments fall back to the package
// defaults so a misconfigured caller gets the protective setting rather than
// an unlimited one.
func New(maxFailures int, window time.Duration) *Limiter {
	if maxFailures <= 0 {
		maxFailures = DefaultMaxFailures
	}
	if window <= 0 {
		window = DefaultWindow
	}
	return &Limiter{
		maxFailures: maxFailures,
		window:      window,
		maxKeys:     DefaultMaxKeys,
		now:         time.Now,
		entries:     make(map[string]*entry),
	}
}

// NewDefault returns a limiter with the package defaults.
func NewDefault() *Limiter {
	return New(DefaultMaxFailures, DefaultWindow)
}

// SetClock replaces the time source. Tests use it to move through windows
// without sleeping.
func (l *Limiter) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now != nil {
		l.now = now
	}
}

// Admit atomically reserves one credential-evaluation slot for key. It
// returns true when the caller may compare the presented credential, and
// false with the time until the oldest reservation leaves the window when the
// budget is spent. Reservation and check are one locked step on purpose: a
// separate check-then-record pair lets a burst of parallel guesses all observe
// "not blocked" before any of them is recorded, which is a fail-open. A slot
// reserved for a credential that then verifies is released by Reset. A nil
// limiter admits everything. Callers that may need to give a slot back use
// Reserve, which also returns the handle.
func (l *Limiter) Admit(key string) (bool, time.Duration) {
	_, allowed, retry := l.Reserve(key)
	return allowed, retry
}

// Reserve is Admit with a handle: on success the returned Reservation names
// exactly the slot this call took, for a later Release.
func (l *Limiter) Reserve(key string) (Reservation, bool, time.Duration) {
	if l == nil {
		return Reservation{}, true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.entries[key]
	if e == nil {
		if len(l.entries) >= l.maxKeys {
			l.evictOne(now)
		}
		e = &entry{}
		l.entries[key] = e
	}
	l.prune(e, now)
	if len(e.failures) >= l.maxFailures {
		// The window stays anchored on the oldest reservation inside it; a
		// spent budget does not extend itself on every further attempt, which
		// would let an attacker lock an operator out indefinitely from a
		// shared address. It simply stays spent until the window passes.
		retry := e.failures[0].at.Add(l.window).Sub(now)
		if retry <= 0 {
			retry = time.Second
		}
		return Reservation{}, false, retry
	}
	l.nextID++
	e.failures = append(e.failures, slot{id: l.nextID, at: now})
	return Reservation{key: key, id: l.nextID}, true, 0
}

// Blocked reports whether key has spent its budget without reserving a slot.
// Use it only for diagnostics; admission decisions go through Admit.
func (l *Limiter) Blocked(key string) (bool, time.Duration) {
	if l == nil {
		return false, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.entries[key]
	if e == nil {
		return false, 0
	}
	l.prune(e, now)
	if len(e.failures) < l.maxFailures {
		return false, 0
	}
	retry := e.failures[0].at.Add(l.window).Sub(now)
	if retry <= 0 {
		retry = time.Second
	}
	return true, retry
}

// Release gives back exactly the slot res names, leaving every other
// reservation on that key untouched. Callers use it when an admitted
// evaluation turned out not to be a guess at all, for example a request that
// a separate verifier authenticated while carrying a bearer value meant for
// something else, or a request that failed for a reason unrelated to the
// credential. A nil limiter, the zero Reservation, or a slot that has already
// expired or been reset is a no-op.
func (l *Limiter) Release(res Reservation) {
	if l == nil || res.id == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[res.key]
	if e == nil {
		return
	}
	for i, s := range e.failures {
		if s.id == res.id {
			e.failures = append(e.failures[:i], e.failures[i+1:]...)
			break
		}
	}
	if len(e.failures) == 0 {
		delete(l.entries, res.key)
	}
}

// Reset forgets key's reservations. Callers invoke it after a credential
// verifies, so an operator who mistyped a token once is not carried toward
// the limit by their own earlier mistake.
func (l *Limiter) Reset(key string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// Len reports how many client keys are currently tracked.
func (l *Limiter) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// prune drops failures that have left the window. Caller holds l.mu.
func (l *Limiter) prune(e *entry, now time.Time) {
	cutoff := now.Add(-l.window)
	i := 0
	for i < len(e.failures) && !e.failures[i].at.After(cutoff) {
		i++
	}
	if i > 0 {
		e.failures = append(e.failures[:0], e.failures[i:]...)
	}
}

// evictOne removes expired entries, and if none expired, the least recently
// active entry (the one whose NEWEST failure is oldest). Caller holds l.mu.
func (l *Limiter) evictOne(now time.Time) {
	var (
		victim    string
		victimAge time.Time
		found     bool
	)
	for k, e := range l.entries {
		l.prune(e, now)
		if len(e.failures) == 0 {
			delete(l.entries, k)
			found = true
			continue
		}
		newest := e.failures[len(e.failures)-1].at
		if victim == "" || newest.Before(victimAge) {
			victim, victimAge = k, newest
		}
	}
	if found {
		return
	}
	if victim != "" {
		delete(l.entries, victim)
	}
}

// ClientKey derives the limiter key from the request's transport peer
// address. It deliberately ignores X-Forwarded-For and similar headers: they
// are attacker-controlled on a directly exposed listener and would let a
// guesser choose a fresh key for every attempt.
func ClientKey(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// Refuse writes the 429 response for a client whose failure budget is spent.
// It sets Retry-After in whole seconds, rounded up, so a client that honors
// it does not return still blocked.
func Refuse(w http.ResponseWriter, retry time.Duration) {
	secs := int64(retry / time.Second)
	if retry%time.Second != 0 {
		secs++
	}
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
	http.Error(w, "too many failed authentication attempts", http.StatusTooManyRequests)
}
