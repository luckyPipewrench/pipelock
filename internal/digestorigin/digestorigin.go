// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package digestorigin records SHA-256 digests that this process computed
// itself, so the receipt content boundary can tell a digest Pipelock derived
// (a configuration policy hash) from a caller-chosen value with the same
// spelling. A digest is a one-way function of its input, so excluding a
// computed digest from detector input exposes nothing; a caller-chosen value
// is never recorded and stays content.
//
// Recording is a capability: NewIssuer returns it once per name, so only the
// package that computes a digest holds the means to record it. The package
// has no dependencies so the lowest layers (config) can import it.
package digestorigin

import (
	"fmt"
	"sync"
)

// maxRecorded bounds the record. Digests past the bound are not recorded,
// which only means they are scanned as content: the bound can never turn a
// value into a trusted one.
const maxRecorded = 4096

var (
	mu       sync.Mutex
	issuers  = map[string]struct{}{}
	recorded = map[string]struct{}{}
)

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

// Record notes digest as computed by this process and returns it unchanged.
// Only a lowercase 64-character hex string is recorded, so even a misuse
// cannot mark arbitrary text as computed.
func (i *Issuer) Record(digest string) string {
	if i == nil || !isSHA256Hex(digest) {
		return digest
	}
	mu.Lock()
	defer mu.Unlock()
	if len(recorded) < maxRecorded {
		recorded[digest] = struct{}{}
	}
	return digest
}

// Computed reports whether s is a digest this process recorded.
func Computed(s string) bool {
	if !isSHA256Hex(s) {
		return false
	}
	mu.Lock()
	defer mu.Unlock()
	_, ok := recorded[s]
	return ok
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
