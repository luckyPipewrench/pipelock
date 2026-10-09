// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package digestorigin records SHA-256 digests that this process computed
// itself, so the receipt content boundary can tell a digest Pipelock derived
// (a policy, contract, manifest, or execution hash) from a caller-chosen value with the same
// spelling. A digest is a one-way function of its input, so excluding a
// computed digest from detector input exposes nothing; a caller-chosen value
// is never recorded and stays content.
//
// Recording is a capability: NewIssuer returns it once per name, so only the
// package that computes a digest holds the means to record it. The package
// depends only on the standard library so the lowest layers can import it.
package digestorigin

import (
	"crypto/sha256"
	"encoding/hex"
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

// Sum computes SHA-256 over preimage, records its generated origin, and
// returns the lowercase hex digest. No API accepts a caller-chosen digest:
// possessing an issuer can establish origin only by computing the preimage.
// A nil or zero issuer still computes the digest but cannot record origin.
func (i *Issuer) Sum(preimage []byte) string {
	sum := sha256.Sum256(preimage)
	digest := hex.EncodeToString(sum[:])
	if i == nil || i.name == "" {
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
