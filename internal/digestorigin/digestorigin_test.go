// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package digestorigin

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// advanceClock moves the package clock forward by d for the rest of the test.
func advanceClock(t *testing.T, d time.Duration) {
	t.Helper()
	mu.Lock()
	saved := now
	base := now()
	now = func() time.Time { return base.Add(d) }
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		now = saved
		mu.Unlock()
	})
}

// waitReleased collects garbage until no holder of any digest remains.
func waitReleased(t *testing.T, digests ...string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		runtime.GC()
		mu.Lock()
		held := 0
		for _, d := range digests {
			if o := origins[d]; o != nil && o.held > 0 {
				held++
			}
		}
		mu.Unlock()
		if held == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d digests still held after collection", held)
		}
		runtime.Gosched()
	}
}

func TestSumAndComputed(t *testing.T) {
	iss := NewIssuer("test.record")
	d := digestOf("config bytes")
	if Computed(d) {
		t.Fatal("digest computed before it was recorded")
	}
	got := iss.Sum([]byte("config bytes"))
	if got.String() != d || !got.Held() || !Computed(d) {
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
	runtime.KeepAlive(got)
}

func TestChosenDigestCannotAcquireOrigin(t *testing.T) {
	chosen := strings.Repeat("ab57", 16)
	iss := NewIssuer("test.chosen")
	computed := iss.Sum([]byte(chosen))
	if computed.String() == chosen || Computed(chosen) || !Computed(computed.String()) {
		t.Fatal("a chosen digest acquired origin instead of its computed hash")
	}
	if d, ok := Retain(chosen); ok || d.Held() || Computed(chosen) {
		t.Fatal("Retain recorded a chosen digest")
	}
	if d, ok := Retain("not a digest"); ok || d.Held() {
		t.Fatal("Retain accepted a non-digest")
	}
	var zero Issuer
	var nilIssuer *Issuer
	for name, d := range map[string]Digest{
		"zero": zero.Sum([]byte("zero issuer input")),
		"nil":  nilIssuer.Sum([]byte("nil issuer input")),
	} {
		if d.Held() || Computed(d.String()) {
			t.Errorf("%s issuer recorded origin", name)
		}
	}
	if (Digest{}).Held() {
		t.Fatal("zero Digest holds an origin")
	}
	runtime.KeepAlive(computed)
}

// TestHeldOriginSurvivesUnrelatedDigests is the regression for a bounded
// global record: once it filled, every later origin was discarded and a
// long-running process refused its own digests again. A held origin now
// survives any number of unrelated digests, their collection, and the
// grace period, and the dropped ones are forgotten so memory stays bounded.
func TestHeldOriginSurvivesUnrelatedDigests(t *testing.T) {
	iss := NewIssuer("test.flood")
	held := iss.Sum([]byte("long-lived policy"))
	const flood = 2 * 4096
	dropped := make([]string, 0, flood)
	for i := 0; i < flood; i++ {
		dropped = append(dropped, iss.Sum([]byte("unrelated-"+strconv.Itoa(i))).String())
	}
	late := iss.Sum([]byte("computed after the flood"))
	if !Computed(late.String()) {
		t.Fatal("a digest computed after many others was not recorded")
	}
	waitReleased(t, dropped...)
	advanceClock(t, grace)
	// The next recording prunes released origins past their grace.
	extra := iss.Sum([]byte("prune trigger"))
	if !Computed(held.String()) || !Computed(late.String()) {
		t.Fatal("a held origin was lost")
	}
	if Computed(dropped[0]) || Computed(dropped[flood-1]) {
		t.Fatal("a released origin outlived its grace")
	}
	mu.Lock()
	remaining := 0
	for _, d := range dropped {
		if _, ok := origins[d]; ok {
			remaining++
		}
	}
	mu.Unlock()
	if remaining != 0 {
		t.Fatalf("%d released origins were not forgotten", remaining)
	}
	runtime.KeepAlive(held)
	runtime.KeepAlive(late)
	runtime.KeepAlive(extra)
}

func TestReleasedOriginHasGraceAndRetainExtendsIt(t *testing.T) {
	iss := NewIssuer("test.grace")
	s := iss.Sum([]byte("handed to an emitter")).String()
	other := iss.Sum([]byte("never retained")).String()
	waitReleased(t, s, other)
	if !Computed(s) || !Computed(other) {
		t.Fatal("a just-released origin lost its grace")
	}
	// A producer receiving the string within grace keeps the origin.
	kept, ok := Retain(s)
	if !ok || !kept.Held() || kept.String() != s {
		t.Fatal("Retain refused a computed digest")
	}
	advanceClock(t, grace)
	if !Computed(s) {
		t.Fatal("a retained origin expired")
	}
	if Computed(other) {
		t.Fatal("an unretained origin outlived its grace")
	}
	if _, ok := Retain(other); ok {
		t.Fatal("Retain revived an expired origin")
	}
	runtime.KeepAlive(kept)
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
