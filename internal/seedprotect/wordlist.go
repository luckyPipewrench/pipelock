// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package seedprotect

import (
	_ "embed"
	"strings"
)

//go:embed english.txt
var rawWordlist string

// wordIndex maps each BIP-39 English word to its index (0-2047).
// Built once at init; the wordlist is frozen and never changes.
var wordIndex map[string]int

func init() {
	lines := strings.Split(strings.TrimSpace(rawWordlist), "\n")
	wordIndex = make(map[string]int, len(lines))
	for i, w := range lines {
		wordIndex[strings.TrimSpace(w)] = i
	}
}

// IsWord returns true if w is a BIP-39 English word.
func IsWord(w string) bool {
	_, ok := wordIndex[w]
	return ok
}

// IndexOf returns the BIP-39 index (0-2047) for a word. Returns -1 if not found.
func IndexOf(w string) int {
	idx, ok := wordIndex[w]
	if !ok {
		return -1
	}
	return idx
}

// WordCount returns the number of words in the embedded wordlist.
func WordCount() int {
	return len(wordIndex)
}
