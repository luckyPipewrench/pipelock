// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package seedprotect

import (
	"strings"
	"testing"
)

// Known-valid BIP-39 test vectors (from the BIP-39 reference implementation).
const (
	// 12-word: "abandon" x11 + "about" — valid checksum.
	valid12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	// 24-word: "abandon" x23 + "art" — valid checksum.
	valid24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
)

func TestDetect_Valid12Word(t *testing.T) {
	matches := Detect(valid12, 12, true)
	if len(matches) == 0 {
		t.Fatal("expected 12-word valid phrase to be detected")
	}
	if matches[0].WordCount != 12 {
		t.Errorf("word count = %d, want 12", matches[0].WordCount)
	}
	if !matches[0].ChecksumValid {
		t.Error("expected checksum valid")
	}
}

func TestDetect_Valid24Word(t *testing.T) {
	matches := Detect(valid24, 12, true)
	if len(matches) == 0 {
		t.Fatal("expected 24-word valid phrase to be detected")
	}
	// Should find both a 12-word and 24-word match (the first 12 words of the
	// 24-word phrase form a valid 12-word phrase due to the all-abandon pattern).
	found24 := false
	for _, m := range matches {
		if m.WordCount == 24 {
			found24 = true
		}
	}
	if !found24 {
		t.Error("expected a 24-word match")
	}
}

func TestDetect_BelowMinWords(t *testing.T) {
	// 11 BIP-39 words — below the 12-word minimum.
	words := strings.Repeat("abandon ", 11)
	matches := Detect(strings.TrimSpace(words), 12, false)
	if len(matches) != 0 {
		t.Errorf("expected no matches for 11 words, got %d", len(matches))
	}
}

func TestDetect_NonBIP39WordBreaksRun(t *testing.T) {
	// 12 words but one is not BIP-39.
	phrase := "abandon abandon abandon abandon abandon xyznotaword abandon abandon abandon abandon abandon about"
	matches := Detect(phrase, 12, true)
	if len(matches) != 0 {
		t.Errorf("expected no matches with non-BIP-39 word, got %d", len(matches))
	}
}

func TestDetect_ChecksumFail_VerifyTrue(t *testing.T) {
	// 12 BIP-39 words but invalid checksum.
	phrase := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	matches := Detect(phrase, 12, true)
	if len(matches) != 0 {
		t.Errorf("expected no matches with invalid checksum, got %d", len(matches))
	}
}

func TestDetect_ChecksumFail_VerifyFalse(t *testing.T) {
	// Same invalid checksum phrase, but verification disabled.
	phrase := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	matches := Detect(phrase, 12, false)
	if len(matches) == 0 {
		t.Fatal("expected match with verify_checksum=false")
	}
}

func TestDetect_CommaSeparated(t *testing.T) {
	phrase := strings.ReplaceAll(valid12, " ", ", ")
	matches := Detect(phrase, 12, true)
	if len(matches) == 0 {
		t.Fatal("expected comma-separated phrase to be detected")
	}
}

func TestDetect_NewlineSeparated(t *testing.T) {
	phrase := strings.ReplaceAll(valid12, " ", "\n")
	matches := Detect(phrase, 12, true)
	if len(matches) == 0 {
		t.Fatal("expected newline-separated phrase to be detected")
	}
}

func TestDetect_DashSeparated(t *testing.T) {
	phrase := strings.ReplaceAll(valid12, " ", "-")
	matches := Detect(phrase, 12, true)
	if len(matches) == 0 {
		t.Fatal("expected dash-separated phrase to be detected")
	}
}

func TestDetect_TabSeparated(t *testing.T) {
	phrase := strings.ReplaceAll(valid12, " ", "\t")
	matches := Detect(phrase, 12, true)
	if len(matches) == 0 {
		t.Fatal("expected tab-separated phrase to be detected")
	}
}

func TestDetect_PipeSeparated(t *testing.T) {
	phrase := strings.ReplaceAll(valid12, " ", "|")
	matches := Detect(phrase, 12, true)
	if len(matches) == 0 {
		t.Fatal("expected pipe-separated phrase to be detected")
	}
}

func TestDetect_MixedSeparators(t *testing.T) {
	// Mix of spaces, commas, and newlines.
	phrase := "abandon, abandon\nabandon abandon,abandon\nabandon abandon abandon\nabandon abandon abandon about"
	matches := Detect(phrase, 12, true)
	if len(matches) == 0 {
		t.Fatal("expected mixed-separator phrase to be detected")
	}
}

func TestDetect_CaseInsensitive(t *testing.T) {
	phrase := strings.ToUpper(valid12)
	matches := Detect(phrase, 12, true)
	if len(matches) == 0 {
		t.Fatal("expected uppercase phrase to be detected")
	}
}

func TestDetect_EmptyString(t *testing.T) {
	matches := Detect("", 12, true)
	if len(matches) != 0 {
		t.Errorf("expected no matches for empty string, got %d", len(matches))
	}
}

func TestDetect_SingleWord(t *testing.T) {
	matches := Detect("abandon", 12, true)
	if len(matches) != 0 {
		t.Errorf("expected no matches for single word, got %d", len(matches))
	}
}

func TestDetect_NormalEnglishParagraph(t *testing.T) {
	// A paragraph using some BIP-39 words but never 12 consecutive.
	text := "I want to change the world and make it a better place for people. " +
		"The first thing we need to do is find a good solution that will work. " +
		"Above all, we must keep our focus on what really matters in life."
	matches := Detect(text, 12, true)
	if len(matches) != 0 {
		t.Errorf("expected no matches in normal text, got %d", len(matches))
	}
}

func TestDetect_LeadingTrailingWhitespace(t *testing.T) {
	phrase := "  \t " + valid12 + "  \n "
	matches := Detect(phrase, 12, true)
	if len(matches) == 0 {
		t.Fatal("expected phrase with leading/trailing whitespace to be detected")
	}
}

func TestDetect_15Word(t *testing.T) {
	// 15-word: "abandon" x14 + "aisle" is one known valid vector.
	// Use verify_checksum=false for word count validation since we may not have
	// all valid 15-word test vectors. The key test is that 15 is accepted.
	words := strings.Repeat("abandon ", 15)
	matches := Detect(strings.TrimSpace(words), 12, false)
	found15 := false
	for _, m := range matches {
		if m.WordCount == 15 {
			found15 = true
		}
	}
	if !found15 {
		t.Error("expected a 15-word match with verify_checksum=false")
	}
}

func TestDetect_NonBIP39WordsOnly(t *testing.T) {
	// All non-BIP39 words — should not match.
	words := make([]string, 20)
	for i := range words {
		words[i] = "xyznotaword"
	}
	matches := Detect(strings.Join(words, " "), 12, false)
	if len(matches) != 0 {
		t.Errorf("expected no matches for all non-BIP-39 words, got %d", len(matches))
	}
}

func TestWordCount(t *testing.T) {
	if n := WordCount(); n != 2048 {
		t.Errorf("WordCount() = %d, want 2048", n)
	}
}

func TestIsWord(t *testing.T) {
	if !IsWord("abandon") {
		t.Error("expected 'abandon' to be a BIP-39 word")
	}
	if !IsWord("zoo") {
		t.Error("expected 'zoo' to be a BIP-39 word")
	}
	if IsWord("xyznotaword") {
		t.Error("expected 'xyznotaword' to NOT be a BIP-39 word")
	}
}
