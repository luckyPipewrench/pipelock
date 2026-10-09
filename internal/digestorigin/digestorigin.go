// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package digestorigin records SHA-256 digests that this process computed
// itself, so the receipt content boundary can tell a digest Pipelock derived
// (a policy, contract, manifest, or execution hash) from a caller-chosen value
// with the same spelling. A digest is a one-way function of its input, so
// excluding a computed digest from detector input exposes nothing; a
// caller-chosen value is never recorded and stays content.
//
// Recording is a capability: NewIssuer returns it once per name, so only the
// package that computes a digest holds the means to record it, and only by
// hashing a preimage.
//
// An origin lives as long as its holders. Sum returns a Digest whose hidden
// anchor keeps the digest computed while any copy of that Digest is reachable,
// so a producer that keeps the digests it stamps (a Config, an active contract
// set, a receipt emitter, a Guard run) keeps their origin for its own lifetime.
// After the last holder is collected the digest stays computed for a grace
// period, so a value already handed to an emitter across a reload is not
// refused. Nothing is evicted by count: digests computed and dropped
// elsewhere can never displace an origin that is still held.
//
// The package depends only on the standard library so the lowest layers can
// import it.
package digestorigin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// grace is how long a digest stays computed after its last holder is
// collected. It covers a value in flight between the producer that computed
// it and the emitter that retains it.
const grace = 10 * time.Minute

var (
	mu        sync.Mutex
	issuers   = map[string]struct{}{}
	origins   = map[string]*origin{}
	lastPrune time.Time
	now       = time.Now
)

// origin counts the live holders of one digest and when the last one went.
type origin struct {
	held     int
	released time.Time
}

// anchor is the heap object whose reachability is the origin's lifetime.
type anchor struct{ hex string }

// Digest is a digest an Issuer computed. While any copy is reachable,
// Computed reports its hex as computed. The zero Digest holds nothing.
type Digest struct {
	hex    string
	anchor *anchor
}

// String returns the lowercase hex digest.
func (d Digest) String() string { return d.hex }

// Held reports whether d holds an origin.
func (d Digest) Held() bool { return d.anchor != nil }

// Issuer is the capability to record digests computed by one package.
type Issuer struct{ name string }

// NewIssuer returns the recording capability for name. It panics on an empty
// or duplicate name; both are programming errors caught at initialization.
func NewIssuer(name string) *Issuer {
	if name == "" {
		panic("digestorigin: issuer name is required")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := issuers[name]; dup {
		panic(fmt.Sprintf("digestorigin: issuer %q created twice", name))
	}
	issuers[name] = struct{}{}
	return &Issuer{name: name}
}

// Sum computes SHA-256 over preimage and returns it as a Digest holding its
// origin. No API accepts a caller-chosen digest: possessing an issuer can
// establish origin only by computing the preimage. A nil or zero issuer still
// computes the digest but holds no origin.
func (i *Issuer) Sum(preimage []byte) Digest {
	sum := sha256.Sum256(preimage)
	digest := hex.EncodeToString(sum[:])
	if i == nil || i.name == "" {
		return Digest{hex: digest}
	}
	mu.Lock()
	defer mu.Unlock()
	return holdLocked(digest)
}

// Retain returns a Digest holding the origin of s when s is computed now,
// so a producer that receives a computed digest as a string keeps its origin
// for as long as it keeps the Digest. It never records a new origin: for any
// other value it returns the zero Digest and false.
func Retain(s string) (Digest, bool) {
	if !isSHA256Hex(s) {
		return Digest{}, false
	}
	mu.Lock()
	defer mu.Unlock()
	if !computedLocked(s) {
		return Digest{}, false
	}
	return holdLocked(s), true
}

// Computed reports whether s is a digest this process computed and still
// holds, or released less than the grace period ago.
func Computed(s string) bool {
	if !isSHA256Hex(s) {
		return false
	}
	mu.Lock()
	defer mu.Unlock()
	return computedLocked(s)
}

func computedLocked(s string) bool {
	o := origins[s]
	return o != nil && (o.held > 0 || now().Sub(o.released) < grace)
}

func holdLocked(digest string) Digest {
	pruneLocked()
	o := origins[digest]
	if o == nil {
		o = &origin{}
		origins[digest] = o
	}
	o.held++
	a := &anchor{hex: digest}
	runtime.AddCleanup(a, release, digest)
	return Digest{hex: digest, anchor: a}
}

// release runs after a holder's anchor is collected.
func release(digest string) {
	mu.Lock()
	defer mu.Unlock()
	if o := origins[digest]; o != nil && o.held > 0 {
		o.held--
		if o.held == 0 {
			o.released = now()
		}
	}
}

// pruneLocked forgets released origins whose grace has passed. It runs at
// most twice per grace period, so recording stays amortized O(1).
func pruneLocked() {
	t := now()
	if t.Sub(lastPrune) < grace/2 {
		return
	}
	lastPrune = t
	for digest, o := range origins {
		if o.held == 0 && t.Sub(o.released) >= grace {
			delete(origins, digest)
		}
	}
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
