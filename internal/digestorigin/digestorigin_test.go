// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package digestorigin

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestRecordAndComputed(t *testing.T) {
	iss := NewIssuer("test.record")
	d := digestOf("config bytes")
	if Computed(d) {
		t.Fatal("digest computed before it was recorded")
	}
	if got := iss.Sum([]byte("config bytes")); got != d || !Computed(d) {
		t.Fatalf("recorded digest not computed: %q", got)
	}
	for name, s := range map[string]string{
		"chosen hex":   strings.Repeat("ab12", 16),
		"uppercase":    strings.ToUpper(d),
		"short":        d[:63],
		"non-hex":      d[:63] + "z",
		"prefixed":     "sha256:" + d,
		"arbitrary":    "a caller chose this",
		"empty string": "",
	} {
		if Computed(s) {
			t.Errorf("%s: %q reported computed", name, s)
		}
	}
	// Non-digests are never recorded, even through the capability.
	if iss.Sum([]byte("not a digest")) == "not a digest" || Computed("not a digest") {
		t.Fatal("non-digest recorded")
	}
	mu.Lock()
	_, stored := recorded["not a digest"]
	mu.Unlock()
	if stored {
		t.Fatal("non-digest stored in the record")
	}
	var nilIssuer *Issuer
	other := digestOf("other")
	if nilIssuer.Sum([]byte("other")) != other || Computed(other) {
		t.Fatal("nil issuer recorded a digest")
	}
}

func TestRecordIsBounded(t *testing.T) {
	iss := NewIssuer("test.bound")
	mu.Lock()
	saved := recorded
	recorded = map[string]struct{}{}
	for i := 0; i < maxRecorded; i++ {
		recorded[digestOf(strings.Repeat("x", i))] = struct{}{}
	}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		recorded = saved
		mu.Unlock()
	})
	over := digestOf("over the bound")
	if iss.Sum([]byte("over the bound")); Computed(over) {
		t.Fatal("digest recorded past the bound")
	}
}

func TestNewIssuerRefusesDuplicatesAndEmpty(t *testing.T) {
	NewIssuer("test.dup")
	for name, issuer := range map[string]string{"duplicate": "test.dup", "empty": ""} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s issuer did not panic", name)
				}
			}()
			NewIssuer(issuer)
		}()
	}
}

func TestChosenDigestCannotAcquireOrigin(t *testing.T) {
	chosen := strings.Repeat("ab57", 16)
	iss := NewIssuer("test.chosen")
	computed := iss.Sum([]byte(chosen))
	if computed == chosen || Computed(chosen) || !Computed(computed) {
		t.Fatal("a chosen digest acquired origin instead of its computed hash")
	}
	var zero Issuer
	other := zero.Sum([]byte("zero issuer input"))
	if Computed(other) {
		t.Fatal("zero issuer recorded origin")
	}
}
