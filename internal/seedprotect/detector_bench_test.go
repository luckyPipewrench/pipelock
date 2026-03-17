// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package seedprotect

import (
	"strings"
	"testing"
)

func BenchmarkSeedDetect_CleanText(b *testing.B) {
	text := "This is a normal sentence with no BIP-39 words that should bail immediately."
	for b.Loop() {
		Detect(text, 12, true)
	}
}

func BenchmarkSeedDetect_ValidPhrase(b *testing.B) {
	for b.Loop() {
		Detect(valid12, 12, true)
	}
}

func BenchmarkSeedDetect_LongText(b *testing.B) {
	// 1000 words, many are BIP-39 words (worst case for sliding window).
	var words []string
	bip39Words := []string{"abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse"}
	for i := 0; i < 1000; i++ {
		words = append(words, bip39Words[i%len(bip39Words)])
	}
	text := strings.Join(words, " ")
	b.ResetTimer()
	for b.Loop() {
		Detect(text, 12, true)
	}
}

func BenchmarkSeedChecksum(b *testing.B) {
	// Benchmark just checksum validation on a known-valid 12-word phrase.
	words := strings.Fields(valid12)
	indices := wordIndices(words)
	for b.Loop() {
		validateChecksum(indices)
	}
}
