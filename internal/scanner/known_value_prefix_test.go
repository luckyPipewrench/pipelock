// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"
)

func TestKnownValueWindowPrefixFilterCoversEveryWindow(t *testing.T) {
	values := []string{
		"rcpt" + "Zq7vK2mX9pL4wR8tN3bY6cH1jD5fG0sA",
		"\x00\xff" + strings.Repeat("\x80binary", 4),
		"shared-stem-" + "AAAABBBBCCCCDDDD" + "-left",
		"shared-stem-" + "AAAABBBBCCCCDDDD" + "-right",
	}
	set, err := buildKnownValueWindows(newKnownValueWindowBudget(maxKnownValueWindowEntries), values)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		index := set[value]
		if index.count > 0 && index.prefixes == nil {
			t.Fatalf("index for %q has windows but no prefix set", value)
		}
		for _, candidate := range index.windows {
			if !index.prefixes.mayContain(string(candidate.window.value[:])) {
				t.Fatalf("prefix set omits stored window %q", candidate.window.value[:])
			}
		}
		// Every retained window of a value must still be found through the
		// public lookup, which consults the prefix set first.
		for start := 0; start+minKnownSecretSubstringLen <= len(value); start++ {
			window := value[start : start+minKnownSecretSubstringLen]
			want := false
			for _, candidate := range index.windows {
				if candidate.valueIndex == index.valueIndex && string(candidate.window.value[:]) == window {
					want = true
					break
				}
			}
			if got := len(index.offsets(window)) > 0; got != want {
				t.Fatalf("offsets(%q) found = %t, want %t", window, got, want)
			}
		}
	}

	var nilSet *knownValueWindowPrefixes
	if !nilSet.mayContain("abcdefghijklmnop") {
		t.Fatal("nil prefix filter must report every prefix as present")
	}
	// The filter must exclude most absent prefixes, or it buys nothing.
	index := set[values[0]]
	absent := 0
	for i := range 256 {
		probe := string([]byte{'~', byte(i), '~', '~'}) + "............"
		if !index.prefixes.mayContain(probe) {
			absent++
		}
	}
	if absent < 200 {
		t.Fatalf("prefix filter excluded only %d of 256 absent prefixes", absent)
	}
}

func TestKnownValueSubstringStillFindsPartialRuns(t *testing.T) {
	secret := "rcpt" + "Zq7vK2mX9pL4wR8tN3bY6cH1jD5fG0sA"
	set, err := buildKnownValueWindows(newKnownValueWindowBudget(maxKnownValueWindowEntries), []string{secret})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		text string
		want int
	}{
		{name: "whole value", text: `{"a":"` + secret + `"}`, want: len(secret)},
		{name: "minimum run at end", text: `{"a":"x` + secret[len(secret)-minKnownSecretSubstringLen:], want: minKnownSecretSubstringLen},
		{name: "minimum run at start of text", text: secret[3 : 3+minKnownSecretSubstringLen], want: minKnownSecretSubstringLen},
		{name: "one byte short", text: "zz" + secret[2:2+minKnownSecretSubstringLen-1] + "zz", want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, length, _, ok := indexKnownValueSubstring(secret, set[secret], []spanTextView{{text: tc.text, viewLabel: "v"}})
			if tc.want == 0 {
				if ok {
					t.Fatalf("unexpected partial match of length %d", length)
				}
				return
			}
			if !ok || length != tc.want {
				t.Fatalf("partial match = %t length %d, want length %d", ok, length, tc.want)
			}
		})
	}
}
